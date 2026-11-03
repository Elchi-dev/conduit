package hub

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
)

// Account is a hub account. Accounts belong to one hub; they are not shared
// between hubs.
type Account struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Verified  bool      `json:"verified"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"createdAt"`
}

// caller is the authenticated subject of a request.
type caller struct {
	Account Account
	// Device is set when a paired device (not a person) is calling.
	DeviceID string
	// Scopes is set for hub API keys; nil means a full session.
	Scopes []string
	token  string
}

type ctxKey struct{}

func callerOf(r *http.Request) caller { c, _ := r.Context().Value(ctxKey{}).(caller); return c }

func (c caller) can(scope string) bool {
	if c.Scopes == nil {
		return true
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

const (
	sessionPrefix = "chs_"
	devicePrefix  = "chd_"
	keyPrefix     = "chk_"
)

func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// authenticate resolves a session, device or API key token.
func (s *Server) authenticate(ctx context.Context, tok string) (caller, error) {
	var accountID string
	var c caller
	switch {
	case strings.HasPrefix(tok, sessionPrefix):
		var exp string
		var revoked int
		err := s.db.Row(ctx, `SELECT account_id, expires_at, revoked FROM hub_sessions WHERE token_hash = ?`, hash(tok)).Scan(&accountID, &exp, &revoked)
		if err != nil || revoked == 1 || s.now().After(parseTS(exp)) {
			return c, errors.New("unauthenticated")
		}
	case strings.HasPrefix(tok, devicePrefix):
		var revoked int
		err := s.db.Row(ctx, `SELECT id, account_id, revoked FROM devices WHERE token_hash = ?`, hash(tok)).Scan(&c.DeviceID, &accountID, &revoked)
		if err != nil || revoked == 1 {
			return c, errors.New("unauthenticated")
		}
		_, _ = s.db.Exec(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, ts(s.now()), c.DeviceID)
		// Devices may use the relay, sync and the registry, nothing else.
		c.Scopes = []string{"relay", "sync", "registry:read", "updates"}
	case strings.HasPrefix(tok, keyPrefix):
		var scopes string
		var revoked int
		err := s.db.Row(ctx, `SELECT account_id, scopes, revoked FROM hub_keys WHERE secret_hash = ?`, hash(tok)).Scan(&accountID, &scopes, &revoked)
		if err != nil || revoked == 1 {
			return c, errors.New("unauthenticated")
		}
		_ = json.Unmarshal([]byte(scopes), &c.Scopes)
		if c.Scopes == nil {
			c.Scopes = []string{}
		}
	default:
		return c, errors.New("unauthenticated")
	}
	a, err := s.account(ctx, accountID)
	if err != nil {
		return c, errors.New("unauthenticated")
	}
	c.Account, c.token = a, tok
	return c, nil
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.authenticate(r.Context(), bearer(r))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "sign in, or present a device token or hub API key")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	}
}

func (s *Server) account(ctx context.Context, id string) (Account, error) {
	var a Account
	var v, adm int
	var cr string
	err := s.db.Row(ctx, `SELECT id, email, name, verified, is_admin, created_at FROM accounts WHERE id = ?`, id).Scan(&a.ID, &a.Email, &a.Name, &v, &adm, &cr)
	a.Verified, a.Admin, a.CreatedAt = v == 1, adm == 1, parseTS(cr)
	return a, err
}

// sendToken stores a one-time token and emails a link containing it.
func (s *Server) sendToken(ctx context.Context, accountID, email, kind string, data any, ttl time.Duration, subject, intro, path string) error {
	tok := token(24)
	d, _ := json.Marshal(data)
	if _, err := s.db.Exec(ctx, `INSERT INTO email_tokens (token_hash, account_id, kind, data, expires_at) VALUES (?,?,?,?,?)`,
		hash(tok), accountID, kind, string(d), ts(s.now().Add(ttl))); err != nil {
		return err
	}
	link := s.cfg.PublicURL + path + "?token=" + tok
	text := fmt.Sprintf("%s\n\n%s\n\nThis link works once and expires in %s. If you didn't ask for this, ignore this email.\n\n%s", intro, link, human(ttl), s.cfg.Name)
	return s.mail.Send(ctx, email, subject, text)
}

func human(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	if d >= time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

// useToken consumes a one-time token of a kind and returns its row.
func (s *Server) useToken(ctx context.Context, tok, kind string) (accountID string, data json.RawMessage, err error) {
	var exp string
	var used int
	var d string
	err = s.db.Row(ctx, `SELECT account_id, data, expires_at, used FROM email_tokens WHERE token_hash = ? AND kind = ?`, hash(tok), kind).Scan(&accountID, &d, &exp, &used)
	if err != nil || used == 1 || s.now().After(parseTS(exp)) {
		return "", nil, errors.New("this link is invalid or has expired")
	}
	res, err := s.db.Exec(ctx, `UPDATE email_tokens SET used = 1 WHERE token_hash = ? AND used = 0`, hash(tok))
	if err != nil {
		return "", nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", nil, errors.New("this link was already used")
	}
	return accountID, json.RawMessage(d), nil
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Name        string `json:"name"`
		Password    string `json:"password"`
		InviteToken string `json:"inviteToken"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	addr, err := mail.ParseAddress(req.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "enter a valid email address")
		return
	}
	email := strings.ToLower(addr.Address)
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "the password must be at least 10 characters")
		return
	}
	ctx := r.Context()
	if !s.cfg.OpenRegistration && email != s.cfg.AdminEmail && !s.validInvite(ctx, req.InviteToken, email) {
		writeErr(w, http.StatusForbidden, "this hub only accepts invited people; open the invitation link from your email and sign up with the address it was sent to")
		return
	}
	// Admin rights come with a confirmed address (see verifyEmail), so
	// whoever signs up first with the admin address can't take the hub.
	a := Account{ID: newID("acct"), Email: email, Name: strings.TrimSpace(req.Name), CreatedAt: s.now().UTC()}
	if a.Name == "" {
		a.Name = strings.Split(email, "@")[0]
	}
	_, err = s.db.Exec(ctx, `INSERT INTO accounts (id, email, name, password_hash, verified, is_admin, created_at) VALUES (?,?,?,?,0,?,?)`,
		a.ID, a.Email, a.Name, auth.HashPassword(req.Password), b2i(a.Admin), ts(a.CreatedAt))
	if err != nil {
		// Same answer whether or not the address exists, so accounts can't be
		// enumerated; the owner of the address gets a notice by email.
		var existing string
		if s.db.Row(ctx, `SELECT id FROM accounts WHERE email = ?`, email).Scan(&existing) == nil {
			_ = s.mail.Send(ctx, email, "Someone tried to create an account with your address",
				"Someone tried to sign up at "+s.cfg.Name+" with this email address, which already has an account. If it was you, sign in or reset your password at "+s.cfg.PublicURL+".")
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "check your email"})
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not create the account")
		return
	}
	if err := s.sendToken(ctx, a.ID, a.Email, "verify", nil, 48*time.Hour, "Confirm your email for "+s.cfg.Name,
		"Confirm your email address to finish setting up your account:", "/verify"); err != nil {
		s.log.Error("verification email failed", "err", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "check your email"})
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	_ = readJSON(r, &req)
	id, _, err := s.useToken(r.Context(), req.Token, "verify")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE accounts SET verified = 1 WHERE id = ?`, id)
	s.grantConfiguredAdmin(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

// grantConfiguredAdmin makes the account an admin if its (now confirmed)
// address is CONDUIT_HUB_ADMIN_EMAIL.
func (s *Server) grantConfiguredAdmin(ctx context.Context, id string) {
	if s.cfg.AdminEmail == "" {
		return
	}
	_, _ = s.db.Exec(ctx, `UPDATE accounts SET is_admin = 1 WHERE id = ? AND email = ? AND verified = 1`, id, s.cfg.AdminEmail)
}

// validInvite reports whether tok is an unused, unexpired invitation sent
// to email. It doesn't consume it; accepting the invitation does.
func (s *Server) validInvite(ctx context.Context, tok, email string) bool {
	if tok == "" {
		return false
	}
	var data, exp string
	var used int
	if s.db.Row(ctx, `SELECT data, expires_at, used FROM email_tokens WHERE token_hash = ? AND kind = 'invite'`, hash(tok)).Scan(&data, &exp, &used) != nil {
		return false
	}
	var inv struct{ Email string }
	_ = json.Unmarshal([]byte(data), &inv)
	return used == 0 && !s.now().After(parseTS(exp)) && inv.Email == email
}

func (s *Server) resendVerification(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if c.Account.Verified {
		writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
		return
	}
	_ = s.sendToken(r.Context(), c.Account.ID, c.Account.Email, "verify", nil, 48*time.Hour, "Confirm your email for "+s.cfg.Name,
		"Confirm your email address to finish setting up your account:", "/verify")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !s.logins.Allow(email) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.logins.RetryAfter(email).Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins for this account; try again in a few minutes or reset your password")
		return
	}
	var id, h string
	err := s.db.Row(ctx, `SELECT id, password_hash FROM accounts WHERE email = ?`, email).Scan(&id, &h)
	if errors.Is(err, sql.ErrNoRows) {
		auth.VerifyPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g", req.Password)
		s.logins.Add(email)
		writeErr(w, http.StatusUnauthorized, "wrong email or password")
		return
	}
	if err != nil || !auth.VerifyPassword(h, req.Password) {
		s.logins.Add(email)
		writeErr(w, http.StatusUnauthorized, "wrong email or password")
		return
	}
	s.logins.Reset(email)
	s.issueSession(w, r, id, req.Device)
}

// issueSession signs an account in on a new hub session, answers like a
// password sign-in ({token, account}) and sends the new-sign-in email.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, id, device string) {
	ctx := r.Context()
	tok := sessionPrefix + token(20)
	if device == "" {
		device = r.UserAgent()
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO hub_sessions (token_hash, account_id, device, created_at, expires_at) VALUES (?,?,?,?,?)`,
		hash(tok), id, truncate(device, 200), ts(s.now()), ts(s.now().Add(30*24*time.Hour))); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not sign in")
		return
	}
	a, _ := s.account(ctx, id)
	go func() {
		_ = s.mail.Send(context.Background(), a.Email, "New sign-in to "+s.cfg.Name,
			fmt.Sprintf("Your account was just signed in to from %s (%s) at %s.\n\nIf this wasn't you, reset your password at %s.", truncate(device, 80), s.clientIP(r), s.now().UTC().Format("2 Jan 2006 15:04 MST"), s.cfg.PublicURL))
	}()
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "account": a})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_, _ = s.db.Exec(r.Context(), `UPDATE hub_sessions SET revoked = 1 WHERE token_hash = ?`, hash(callerOf(r).token))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	writeJSON(w, http.StatusOK, map[string]any{"account": c.Account, "device": c.DeviceID, "scopes": c.Scopes})
}

func (s *Server) requestReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	_ = readJSON(r, &req)
	ctx := r.Context()
	var id, email string
	if s.db.Row(ctx, `SELECT id, email FROM accounts WHERE email = ?`, strings.ToLower(strings.TrimSpace(req.Email))).Scan(&id, &email) == nil {
		_ = s.sendToken(ctx, id, email, "reset", nil, time.Hour, "Reset your password for "+s.cfg.Name, "Choose a new password:", "/reset")
	}
	// Same answer either way, so addresses can't be probed.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "if that address has an account, a reset link is on its way"})
}

func (s *Server) confirmReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	_ = readJSON(r, &req)
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "the password must be at least 10 characters")
		return
	}
	id, _, err := s.useToken(r.Context(), req.Token, "reset")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	_, _ = s.db.Exec(ctx, `UPDATE accounts SET password_hash = ?, verified = 1 WHERE id = ?`, auth.HashPassword(req.Password), id)
	s.grantConfiguredAdmin(ctx, id)
	_, _ = s.db.Exec(ctx, `UPDATE hub_sessions SET revoked = 1 WHERE account_id = ?`, id)
	// Passkeys too: a reset is how people take their account back.
	_, _ = s.db.Exec(ctx, `DELETE FROM passkeys WHERE account_id = ?`, id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed; every other sign-in and every passkey was removed"})
}
