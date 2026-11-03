// Package auth owns local accounts, sessions and API keys for the daemon.
//
// Secrets are never stored: passwords are hashed with Argon2id, and session
// tokens and API-key secrets (both 160 bits of randomness) with SHA-256.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/elchi-dev/conduit/internal/core"
)

// Errors.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrSetupDone          = errors.New("setup already completed")
)

// Role of a local user.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// User is a local account.
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	Disabled  bool      `json:"disabled"`
	// TwoFactor is true when the account signs in with an authenticator
	// code after its password.
	TwoFactor bool `json:"twoFactor"`
}

// Session is a signed-in client.
type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"userId"`
	Device     string    `json:"device"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Service implements accounts, sessions and keys on the daemon database.
type Service struct {
	db         *sql.DB
	SessionTTL time.Duration
	limiter    *limiter
	now        func() time.Time
}

// New returns the auth service.
func New(store *core.Store) *Service {
	return &Service{db: store.DB, SessionTTL: 30 * 24 * time.Hour, limiter: newLimiter(), now: time.Now}
}

var tokenEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func randomToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return tokenEncoding.EncodeToString(b)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil
	}
	return &t
}

// --- passwords ---------------------------------------------------------

// Argon2id parameters (OWASP 2024 recommendation: m=19 MiB, t=2, p=1 minimum;
// we use 64 MiB, t=3).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// argonSlots bounds concurrent Argon2id runs (64 MiB each), so a burst of
// sign-in attempts queues instead of exhausting memory.
var argonSlots = make(chan struct{}, max(2, min(runtime.NumCPU(), 8)))

func argonKey(pw, salt []byte, t, m uint32, p uint8, n uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(pw, salt, t, m, p, n)
}

// HashPassword returns an encoded Argon2id hash.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argonKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword checks pw against an encoded Argon2id hash in constant time.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	if m > 256*1024 || t > 10 || p == 0 || len(want) == 0 || len(want) > 64 {
		return false // not a hash this code wrote
	}
	got := argonKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- users -------------------------------------------------------------

// UserCount returns how many accounts exist.
func (s *Service) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser adds an account. The password must be at least 10 characters.
func (s *Service) CreateUser(ctx context.Context, name, email, password string, role Role) (User, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return User{}, fmt.Errorf("invalid email: %w", err)
	}
	if len(password) < 10 {
		return User{}, errors.New("password must be at least 10 characters")
	}
	switch role {
	case RoleOwner, RoleAdmin, RoleMember, RoleViewer:
	default:
		return User{}, fmt.Errorf("invalid role %q", role)
	}
	u := User{ID: core.NewID("user"), Name: strings.TrimSpace(name), Email: strings.ToLower(addr.Address), Role: role, CreatedAt: s.now().UTC()}
	if u.Name == "" {
		u.Name = u.Email
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?)`,
		u.ID, u.Name, u.Email, HashPassword(password), u.Role, ts(u.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return User{}, errors.New("an account with this email already exists")
	}
	return u, err
}

// Setup creates the owner account; it only works while no account exists.
func (s *Service) Setup(ctx context.Context, name, email, password string) (User, error) {
	n, err := s.UserCount(ctx)
	if err != nil {
		return User{}, err
	}
	if n > 0 {
		return User{}, ErrSetupDone
	}
	return s.CreateUser(ctx, name, email, password, RoleOwner)
}

// GetUser returns one user.
func (s *Service) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, email, role, created_at, disabled, `+twoFactorCol+` FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Name, &u.Email, &u.Role, &created, &u.Disabled, &u.TwoFactor)
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return u, err
}

// UserByEmail returns the account with this email address.
func (s *Service) UserByEmail(ctx context.Context, email string) (User, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, strings.ToLower(strings.TrimSpace(email))).Scan(&id)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// SetRole changes an account's role. The owner's role can't change, and no
// one else can become owner.
func (s *Service) SetRole(ctx context.Context, id string, role Role) error {
	switch role {
	case RoleAdmin, RoleMember, RoleViewer:
	default:
		return fmt.Errorf("the role must be admin, member or viewer")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ? AND role != ?`, role, id, RoleOwner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such account, or it's the owner")
	}
	return nil
}

// SetDisabled switches an account off or on. Switching it off ends its
// sessions; its keys stop working while it is off. The owner can't be
// switched off.
func (s *Service) SetDisabled(ctx context.Context, id string, off bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ? AND role != ?`, off, id, RoleOwner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such account, or it's the owner")
	}
	if off {
		_, err = s.RevokeSessions(ctx, id, "")
	}
	return err
}

// ResetPassword sets a new password for someone else and ends their
// sessions. The owner's password can only be changed by the owner.
func (s *Service) ResetPassword(ctx context.Context, id, password string) error {
	if len(password) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ? AND role != ?`, HashPassword(password), id, RoleOwner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such account, or it's the owner")
	}
	_, err = s.RevokeSessions(ctx, id, "")
	return err
}

// ListUsers returns all accounts.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, email, role, created_at, disabled, `+twoFactorCol+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created string
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &created, &u.Disabled, &u.TwoFactor); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// Authenticate checks an email and password.
func (s *Service) Authenticate(ctx context.Context, email, password string) (User, error) {
	var id, hash string
	var disabled bool
	err := s.db.QueryRowContext(ctx, `SELECT id, password_hash, disabled FROM users WHERE email = ?`, strings.ToLower(strings.TrimSpace(email))).Scan(&id, &hash, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		// Spend the same time as a real check so emails can't be probed by timing.
		VerifyPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g", password)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, err
	}
	if !VerifyPassword(hash, password) || disabled {
		return User{}, ErrInvalidCredentials
	}
	return s.GetUser(ctx, id)
}

// ChangePassword sets a new password and signs out every other session.
func (s *Service) ChangePassword(ctx context.Context, userID, oldPw, newPw, keepSession string) error {
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash); err != nil {
		return err
	}
	if !VerifyPassword(hash, oldPw) {
		return ErrInvalidCredentials
	}
	if len(newPw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, HashPassword(newPw), userID); err != nil {
		return err
	}
	_, err := s.RevokeSessions(ctx, userID, keepSession)
	return err
}

// --- sessions ------------------------------------------------------------

// SessionPrefix starts every session token.
const SessionPrefix = "cds_"

// CreateSession signs a user in and returns the session and its token.
func (s *Service) CreateSession(ctx context.Context, userID, device string) (Session, string, error) {
	tok := SessionPrefix + randomToken(20)
	now := s.now().UTC()
	se := Session{ID: core.NewID("sess"), UserID: userID, Device: device, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.SessionTTL)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, token_hash, user_id, device, created_at, last_seen_at, expires_at) VALUES (?,?,?,?,?,?,?)`,
		se.ID, sha(tok), se.UserID, se.Device, ts(now), ts(now), ts(se.ExpiresAt))
	return se, tok, err
}

// SessionUser resolves a session token to its user, sliding last-seen.
func (s *Service) SessionUser(ctx context.Context, token string) (User, Session, error) {
	var se Session
	var created, seen, exp string
	var revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, device, created_at, last_seen_at, expires_at, revoked_at FROM sessions WHERE token_hash = ?`, sha(token)).
		Scan(&se.ID, &se.UserID, &se.Device, &created, &seen, &exp, &revoked)
	if err != nil {
		return User{}, se, ErrUnauthenticated
	}
	se.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	se.LastSeenAt, _ = time.Parse(time.RFC3339Nano, seen)
	se.ExpiresAt, _ = time.Parse(time.RFC3339Nano, exp)
	now := s.now()
	if revoked.Valid || now.After(se.ExpiresAt) {
		return User{}, se, ErrUnauthenticated
	}
	if now.Sub(se.LastSeenAt) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, ts(now), se.ID)
	}
	u, err := s.GetUser(ctx, se.UserID)
	if err != nil || u.Disabled {
		return User{}, se, ErrUnauthenticated
	}
	return u, se, nil
}

// ListSessions returns a user's active sessions.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, device, created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen_at DESC`, userID, ts(s.now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var se Session
		var c, l, e string
		if err := rows.Scan(&se.ID, &se.UserID, &se.Device, &c, &l, &e); err != nil {
			return nil, err
		}
		se.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		se.LastSeenAt, _ = time.Parse(time.RFC3339Nano, l)
		se.ExpiresAt, _ = time.Parse(time.RFC3339Nano, e)
		out = append(out, se)
	}
	return out, rows.Err()
}

// RevokeSession signs one session out.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, ts(s.now()), sessionID, userID)
	return err
}

// RevokeSessions signs out every session of userID ("" for all users) except
// keep. Returns how many were revoked.
func (s *Service) RevokeSessions(ctx context.Context, userID, keep string) (int64, error) {
	q := `UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND id != ?`
	args := []any{ts(s.now()), keep}
	if userID != "" {
		q += ` AND user_id = ?`
		args = append(args, userID)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
