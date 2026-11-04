package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/elchi-dev/conduit/internal/core"
)

// Passkeys (WebAuthn) stored for people accounts. The ceremonies themselves
// (challenges, the relying party) are in internal/daemon/passkeys.go; this
// file only keeps the credentials.

// MaxPasskeys is how many passkeys one account can have.
const MaxPasskeys = 20

// ErrNoPasskey means the passkey doesn't exist or isn't the caller's.
var ErrNoPasskey = errors.New("no such passkey")

// Passkey is a stored passkey as listed to its owner.
type Passkey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// RPID is the host name the passkey works at.
	RPID       string     `json:"rpId"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// CredentialKey is how a credential ID is stored (base64url, no padding).
func CredentialKey(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// ListPasskeys returns an account's passkeys, oldest first.
func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, rp_id, created_at, last_used_at FROM user_passkeys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var created string
		var used sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &p.RPID, &created, &used); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		p.LastUsedAt = parseTS(used)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PasskeyCount returns how many passkeys an account has.
func (s *Service) PasskeyCount(ctx context.Context, userID string) int {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?`, userID).Scan(&n)
	return n
}

// PasskeyCredentials returns an account's credentials for the WebAuthn
// library. The sign count and transports come from their own columns.
func (s *Service) PasskeyCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT public_key, sign_count, transports, credential FROM user_passkeys WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var pub []byte
		var count int64
		var transports, raw string
		if err := rows.Scan(&pub, &count, &transports, &raw); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if json.Unmarshal([]byte(raw), &c) != nil {
			continue
		}
		c.PublicKey = pub
		c.Authenticator.SignCount = uint32(count)
		c.Transport = nil
		for _, t := range strings.Split(transports, ",") {
			if t != "" {
				c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PasskeyOwner returns the account a credential ID belongs to.
func (s *Service) PasskeyOwner(ctx context.Context, credentialID []byte) (string, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM user_passkeys WHERE credential_id = ?`, CredentialKey(credentialID)).Scan(&owner)
	return owner, err
}

func joinTransports(ts []protocol.AuthenticatorTransport) string {
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ",")
}

// AddPasskey stores a new, verified credential.
func (s *Service) AddPasskey(ctx context.Context, userID, rpID, name string, c *webauthn.Credential) (Passkey, error) {
	p := Passkey{ID: core.NewID("pk"), Name: name, RPID: rpID, CreatedAt: s.now().UTC()}
	raw, err := json.Marshal(c)
	if err != nil {
		return Passkey{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO user_passkeys (id, user_id, rp_id, credential_id, public_key, sign_count, transports, credential, name, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		p.ID, userID, rpID, CredentialKey(c.ID), c.PublicKey, int64(c.Authenticator.SignCount), joinTransports(c.Transport), string(raw), p.Name, ts(p.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return Passkey{}, errors.New("this passkey is already registered")
	}
	return p, err
}

// PasskeyUsed records a successful sign-in: the new sign count and flags.
func (s *Service) PasskeyUsed(ctx context.Context, userID string, c *webauthn.Credential) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE user_passkeys SET sign_count = ?, credential = ?, last_used_at = ? WHERE credential_id = ? AND user_id = ?`,
		int64(c.Authenticator.SignCount), string(raw), ts(s.now()), CredentialKey(c.ID), userID)
	return err
}

// RenamePasskey changes the name of one of the account's passkeys.
func (s *Service) RenamePasskey(ctx context.Context, userID, id, name string) (Passkey, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE user_passkeys SET name = ? WHERE id = ? AND user_id = ?`, name, id, userID)
	if err != nil {
		return Passkey{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Passkey{}, ErrNoPasskey
	}
	list, err := s.ListPasskeys(ctx, userID)
	for _, p := range list {
		if p.ID == id {
			return p, nil
		}
	}
	if err == nil {
		err = ErrNoPasskey
	}
	return Passkey{}, err
}

// DeletePasskey removes one of the account's passkeys and returns its name.
func (s *Service) DeletePasskey(ctx context.Context, userID, id string) (string, error) {
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM user_passkeys WHERE id = ? AND user_id = ?`, id, userID).Scan(&name); err != nil {
		return "", ErrNoPasskey
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_passkeys WHERE id = ? AND user_id = ?`, id, userID)
	return name, err
}

// deletePasskeys removes every passkey of an account. A password reset or
// change calls it, so whoever sets the new password takes the account back
// from anyone who planted a passkey.
func (s *Service) deletePasskeys(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_passkeys WHERE user_id = ?`, userID)
	return err
}
