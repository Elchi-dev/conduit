// Package vault stores secrets encrypted at rest.
//
// Design: a random 256-bit data key encrypts every secret with
// XChaCha20-Poly1305 (the secret's name is bound as associated data). The
// data key itself is stored only encrypted by a key derived from the owner's
// passphrase with Argon2id. Unlocking derives that key, unwraps the data key
// and keeps it in memory until Lock. Optionally the data key is also kept in
// the operating system's keychain so the vault unlocks on start.
package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/elchi-dev/conduit/internal/core"
)

// Errors.
var (
	ErrLocked        = errors.New("the vault is locked")
	ErrNotSetUp      = errors.New("the vault has not been set up")
	ErrAlreadySetUp  = errors.New("the vault is already set up")
	ErrBadPassphrase = errors.New("wrong passphrase")
	ErrNoSecret      = errors.New("no such secret")
)

// Kind of secret, used for display and generators.
type Kind string

const (
	KindPassword Kind = "password"
	KindToken    Kind = "token"
	KindNote     Kind = "note"
	KindTOTP     Kind = "totp"
	KindSSHKey   Kind = "ssh-key"
)

// Meta is everything about a secret except its value.
type Meta struct {
	Name        string     `json:"name"`
	Kind        Kind       `json:"kind"`
	Description string     `json:"description"`
	Tags        []string   `json:"tags"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
}

// Keychain stores the data key so the vault can unlock without a passphrase.
type Keychain interface {
	Get() ([]byte, error)
	Set(key []byte) error
	Delete() error
}

// Vault is the encrypted secret store.
type Vault struct {
	db       *sql.DB
	keychain Keychain

	mu  sync.RWMutex
	key []byte // nil while locked
}

// New returns a vault backed by the daemon database. keychain may be nil.
func New(store *core.Store, keychain Keychain) *Vault {
	return &Vault{db: store.DB, keychain: keychain}
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// ValidName reports whether s is a valid secret name (lowercase letters,
// digits and . _ / -, up to 128 characters).
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Status describes the vault.
type Status struct {
	SetUp      bool `json:"setUp"`
	Unlocked   bool `json:"unlocked"`
	Secrets    int  `json:"secrets"`
	Remembered bool `json:"remembered"`
}

// Status reports whether the vault is set up and unlocked.
func (v *Vault) Status(ctx context.Context) (Status, error) {
	var st Status
	var n int
	if err := v.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_meta`).Scan(&n); err != nil {
		return st, err
	}
	st.SetUp = n > 0
	if err := v.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_secrets`).Scan(&st.Secrets); err != nil {
		return st, err
	}
	v.mu.RLock()
	st.Unlocked = v.key != nil
	v.mu.RUnlock()
	if v.keychain != nil {
		if k, err := v.keychain.Get(); err == nil && len(k) == chacha20poly1305.KeySize {
			st.Remembered = true
		}
	}
	return st, nil
}

// KDF parameters for new vaults.
const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 2
)

// Setup creates the vault with a passphrase and leaves it unlocked.
func (v *Vault) Setup(ctx context.Context, passphrase string) error {
	if len(passphrase) < 12 {
		return errors.New("the vault passphrase must be at least 12 characters")
	}
	st, err := v.Status(ctx)
	if err != nil {
		return err
	}
	if st.SetUp {
		return ErrAlreadySetUp
	}
	dataKey := random(chacha20poly1305.KeySize)
	salt := random(16)
	kek := argon2.IDKey([]byte(passphrase), salt, kdfTime, kdfMemory, kdfThreads, chacha20poly1305.KeySize)
	wrapped, err := seal(kek, dataKey, []byte("conduit-vault-key"))
	if err != nil {
		return err
	}
	_, err = v.db.ExecContext(ctx, `INSERT INTO vault_meta (id, kdf_salt, kdf_time, kdf_memory, kdf_threads, wrapped_key, created_at) VALUES (1,?,?,?,?,?,?)`,
		salt, kdfTime, kdfMemory, kdfThreads, wrapped, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.key = dataKey
	v.mu.Unlock()
	return nil
}

// Unlock derives the key from the passphrase. remember also stores the data
// key in the OS keychain so future starts unlock automatically.
func (v *Vault) Unlock(ctx context.Context, passphrase string, remember bool) error {
	var salt, wrapped []byte
	var t, m, p uint32
	err := v.db.QueryRowContext(ctx, `SELECT kdf_salt, kdf_time, kdf_memory, kdf_threads, wrapped_key FROM vault_meta WHERE id = 1`).Scan(&salt, &t, &m, &p, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotSetUp
	}
	if err != nil {
		return err
	}
	kek := argon2.IDKey([]byte(passphrase), salt, t, m, uint8(p), chacha20poly1305.KeySize)
	key, err := open(kek, wrapped, []byte("conduit-vault-key"))
	if err != nil {
		return ErrBadPassphrase
	}
	v.mu.Lock()
	v.key = key
	v.mu.Unlock()
	if remember && v.keychain != nil {
		if err := v.keychain.Set(key); err != nil {
			return fmt.Errorf("unlocked, but could not save to the keychain: %w", err)
		}
	}
	return nil
}

// UnlockFromKeychain unlocks with a remembered key, if there is one.
func (v *Vault) UnlockFromKeychain(ctx context.Context) bool {
	if v.keychain == nil {
		return false
	}
	key, err := v.keychain.Get()
	if err != nil || len(key) != chacha20poly1305.KeySize {
		return false
	}
	// Verify the key against any stored secret before trusting it.
	var name string
	var ct []byte
	err = v.db.QueryRowContext(ctx, `SELECT name, ciphertext FROM vault_secrets LIMIT 1`).Scan(&name, &ct)
	if err == nil {
		if _, err := open(key, ct, []byte(name)); err != nil {
			return false
		}
	}
	v.mu.Lock()
	v.key = key
	v.mu.Unlock()
	return true
}

// Lock forgets the key. forget also removes it from the keychain.
func (v *Vault) Lock(forget bool) error {
	v.mu.Lock()
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = nil
	v.mu.Unlock()
	if forget && v.keychain != nil {
		return v.keychain.Delete()
	}
	return nil
}

func (v *Vault) dataKey() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return nil, ErrLocked
	}
	return v.key, nil
}

// Put creates or replaces a secret.
func (v *Vault) Put(ctx context.Context, m Meta, value string) error {
	if !ValidName(m.Name) {
		return fmt.Errorf("invalid secret name %q: use lowercase letters, digits and . _ / -", m.Name)
	}
	key, err := v.dataKey()
	if err != nil {
		return err
	}
	if m.Kind == "" {
		m.Kind = KindPassword
	}
	if m.Tags == nil {
		m.Tags = []string{}
	}
	ct, err := seal(key, []byte(value), []byte(m.Name))
	if err != nil {
		return err
	}
	tags, _ := json.Marshal(m.Tags)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = v.db.ExecContext(ctx, `INSERT INTO vault_secrets (name, kind, ciphertext, description, tags, created_at, updated_at) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, ciphertext = excluded.ciphertext, description = excluded.description, tags = excluded.tags, updated_at = excluded.updated_at`,
		m.Name, m.Kind, ct, m.Description, string(tags), now, now)
	return err
}

// Get decrypts a secret's value.
func (v *Vault) Get(ctx context.Context, name string) (string, error) {
	key, err := v.dataKey()
	if err != nil {
		return "", err
	}
	var ct []byte
	err = v.db.QueryRowContext(ctx, `SELECT ciphertext FROM vault_secrets WHERE name = ?`, name).Scan(&ct)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoSecret
	}
	if err != nil {
		return "", err
	}
	pt, err := open(key, ct, []byte(name))
	if err != nil {
		return "", fmt.Errorf("secret %q could not be decrypted (corrupted or tampered)", name)
	}
	_, _ = v.db.ExecContext(ctx, `UPDATE vault_secrets SET last_used_at = ? WHERE name = ?`, time.Now().UTC().Format(time.RFC3339Nano), name)
	return string(pt), nil
}

// Delete removes a secret.
func (v *Vault) Delete(ctx context.Context, name string) error {
	if _, err := v.dataKey(); err != nil {
		return err
	}
	res, err := v.db.ExecContext(ctx, `DELETE FROM vault_secrets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSecret
	}
	return nil
}

// List returns the metadata of every secret, sorted by name. It works while
// locked: names are not secret, values are.
func (v *Vault) List(ctx context.Context) ([]Meta, error) {
	rows, err := v.db.QueryContext(ctx, `SELECT name, kind, description, tags, created_at, updated_at, last_used_at FROM vault_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Meta{}
	for rows.Next() {
		var m Meta
		var tags, c, u string
		var used sql.NullString
		if err := rows.Scan(&m.Name, &m.Kind, &m.Description, &tags, &c, &u, &used); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &m.Tags)
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
		if used.Valid {
			t, _ := time.Parse(time.RFC3339Nano, used.String)
			m.LastUsedAt = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Resolve implements core.SecretResolver for "secret://name" references.
func (v *Vault) Resolve(ctx context.Context, ref string) (string, error) {
	name, ok := strings.CutPrefix(ref, "secret://")
	if !ok {
		return "", fmt.Errorf("not a vault reference: %q", ref)
	}
	return v.Get(ctx, name)
}

// values decrypts every secret, for leak scanning. The caller must not keep
// the map longer than needed.
func (v *Vault) values(ctx context.Context) (map[string]string, error) {
	key, err := v.dataKey()
	if err != nil {
		return nil, err
	}
	rows, err := v.db.QueryContext(ctx, `SELECT name, ciphertext FROM vault_secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name string
		var ct []byte
		if err := rows.Scan(&name, &ct); err != nil {
			return nil, err
		}
		if pt, err := open(key, ct, []byte(name)); err == nil {
			out[name] = string(pt)
		}
	}
	return out, rows.Err()
}

// Names returns all secret names, sorted.
func (v *Vault) Names(ctx context.Context) ([]string, error) {
	list, err := v.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(list))
	for i, m := range list {
		out[i] = m.Name
	}
	sort.Strings(out)
	return out, nil
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// seal encrypts with XChaCha20-Poly1305; the 24-byte nonce is prepended.
func seal(key, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := random(aead.NonceSize())
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

func open(key, ct, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], ad)
}
