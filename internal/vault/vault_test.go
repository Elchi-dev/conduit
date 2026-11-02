package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

type memKeychain struct{ key []byte }

func (m *memKeychain) Get() ([]byte, error) {
	if m.key == nil {
		return nil, errors.New("none")
	}
	return m.key, nil
}
func (m *memKeychain) Set(k []byte) error { m.key = append([]byte(nil), k...); return nil }
func (m *memKeychain) Delete() error      { m.key = nil; return nil }

func newVault(t *testing.T) (*Vault, *core.Store, *memKeychain) {
	t.Helper()
	st, err := core.OpenStore(context.Background(), t.TempDir()+"/v.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kc := &memKeychain{}
	return New(st, kc), st, kc
}

func TestVaultLifecycle(t *testing.T) {
	ctx := context.Background()
	v, st, kc := newVault(t)
	if err := v.Put(ctx, Meta{Name: "x"}, "y"); !errors.Is(err, ErrLocked) {
		t.Fatalf("put before setup: %v", err)
	}
	if err := v.Setup(ctx, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := v.Setup(ctx, "a long vault passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, Meta{Name: "mail/work", Kind: KindPassword}, "s3cret-value!"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, Meta{Name: "Bad Name"}, "x"); err == nil {
		t.Fatal("invalid name accepted")
	}

	// Nothing readable on disk.
	var ct []byte
	_ = st.DB.QueryRow(`SELECT ciphertext FROM vault_secrets`).Scan(&ct)
	if strings.Contains(string(ct), "s3cret") {
		t.Fatal("plaintext on disk")
	}

	_ = v.Lock(false)
	if _, err := v.Get(ctx, "mail/work"); !errors.Is(err, ErrLocked) {
		t.Fatalf("get while locked: %v", err)
	}
	if list, _ := v.List(ctx); len(list) != 1 {
		t.Fatal("names should be listable while locked")
	}
	if err := v.Unlock(ctx, "wrong passphrase!!", false); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := v.Unlock(ctx, "a long vault passphrase", true); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, "mail/work")
	if err != nil || got != "s3cret-value!" {
		t.Fatalf("get = %q, %v", got, err)
	}
	ref, err := v.Resolve(ctx, "secret://mail/work")
	if err != nil || ref != got {
		t.Fatalf("resolve = %q, %v", ref, err)
	}

	// Remembered key unlocks after a restart.
	_ = v.Lock(false)
	v2 := New(st, kc)
	if !v2.UnlockFromKeychain(ctx) {
		t.Fatal("keychain unlock failed")
	}
	if _, err := v2.Get(ctx, "mail/work"); err != nil {
		t.Fatal(err)
	}
	_ = v2.Lock(true)
	if New(st, kc).UnlockFromKeychain(ctx) {
		t.Fatal("forgotten key should not unlock")
	}
}

func TestCiphertextBoundToName(t *testing.T) {
	ctx := context.Background()
	v, st, _ := newVault(t)
	_ = v.Setup(ctx, "a long vault passphrase")
	_ = v.Put(ctx, Meta{Name: "a"}, "value-of-a")
	_ = v.Put(ctx, Meta{Name: "b"}, "value-of-b")
	// Swap ciphertexts: decryption must fail rather than return the wrong secret.
	_, _ = st.DB.Exec(`UPDATE vault_secrets SET ciphertext = (SELECT ciphertext FROM vault_secrets WHERE name = 'a') WHERE name = 'b'`)
	if _, err := v.Get(ctx, "b"); err == nil {
		t.Fatal("moved ciphertext decrypted")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 test vector (SHA-1): secret "12345678901234567890", T=59 → 94287082 (8 digits) → last 6 = 287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, left, err := TOTP(secret, time.Unix(59, 0))
	if err != nil || code != "287082" || left != 1 {
		t.Fatalf("totp = %s, %d, %v", code, left, err)
	}
	code2, _, _ := TOTP("otpauth://totp/x?secret="+secret+"&period=30", time.Unix(59, 0))
	if code2 != code {
		t.Fatal("otpauth URI not handled")
	}
}

func TestGenerate(t *testing.T) {
	p, err := Generate(24, true)
	if err != nil || len(p) != 24 || !strings.ContainsAny(p, symbols) || !strings.ContainsAny(p, digits) {
		t.Fatalf("generate = %q, %v", p, err)
	}
	if _, err := Generate(8, false); err == nil {
		t.Fatal("too short accepted")
	}
}

func TestEnvImportAndLeakScan(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newVault(t)
	_ = v.Setup(ctx, "a long vault passphrase")
	env, _ := ParseEnv(strings.NewReader("# comment\nexport API_KEY=\"abcd1234efgh\"\nSHORT=x\n"))
	if env["API_KEY"] != "abcd1234efgh" || EnvName("app", "API_KEY") != "app/api-key" {
		t.Fatalf("env parse: %v", env)
	}
	for k, val := range env {
		_ = v.Put(ctx, Meta{Name: EnvName("app", k)}, val)
	}
	leaks, _ := v.ScanText(ctx, "line one\nusing key abcd1234efgh here\nx")
	if len(leaks) != 1 || leaks[0].Secret != "app/api-key" || leaks[0].Line != 2 {
		t.Fatalf("scan text: %+v", leaks)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.yml"), []byte("token: abcd1234efgh\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "node_modules"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "node_modules", "x.js"), []byte("abcd1234efgh"), 0o600)
	found, scanned, err := v.ScanPath(ctx, dir, 0)
	if err != nil || len(found) != 1 || found[0].File != "config.yml" || scanned != 1 {
		t.Fatalf("scan path: %+v %d %v", found, scanned, err)
	}
}
