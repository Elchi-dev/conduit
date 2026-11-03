package hub

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/totp"
)

// Two-factor sign-in with authenticator apps for hub accounts. A password
// sign-in then needs a code (or a recovery code) as a second step. Passkey
// sign-in already proves two factors (the device and its unlock), so it
// doesn't ask. A password reset by email keeps two-factor sign-in on: email
// access alone shouldn't be enough to take an account.

var errTwoFactorCode = errors.New("that code didn't work; check your authenticator app's clock, or use a recovery code")

func (s *Server) totpKey(ctx context.Context) (string, error) {
	var k string
	err := s.db.Row(ctx, `SELECT value FROM hub_settings WHERE key = 'totp_key'`).Scan(&k)
	if err == nil && k != "" {
		return k, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO hub_settings (key, value) VALUES ('totp_key', ?) ON CONFLICT (key) DO NOTHING`, totp.NewKey()); err != nil {
		return "", err
	}
	err = s.db.Row(ctx, `SELECT value FROM hub_settings WHERE key = 'totp_key'`).Scan(&k)
	return k, err
}

func (s *Server) twoFactorOn(ctx context.Context, account string) bool {
	var n int
	_ = s.db.Row(ctx, `SELECT COUNT(*) FROM account_totp WHERE account_id = ? AND enabled = 1`, account).Scan(&n)
	return n > 0
}

func (s *Server) totpSecret(ctx context.Context, account string) (secret []byte, enabled bool, last int64, err error) {
	var sealed string
	var en int
	if err = s.db.Row(ctx, `SELECT secret, enabled, last_step FROM account_totp WHERE account_id = ?`, account).Scan(&sealed, &en, &last); err != nil {
		return nil, false, 0, err
	}
	key, err := s.totpKey(ctx)
	if err != nil {
		return nil, false, 0, err
	}
	secret, err = totp.Open(key, sealed, account)
	return secret, en == 1, last, err
}

// checkCode accepts a code from the app (each time step once) or an unused
// recovery code, for an account with two-factor sign-in on.
func (s *Server) checkCode(ctx context.Context, account, code string, needEnabled bool) error {
	if totp.LooksLikeRecoveryCode(code) {
		if !s.twoFactorOn(ctx, account) {
			return errTwoFactorCode
		}
		res, err := s.db.Exec(ctx, `UPDATE account_recovery_codes SET used_at = ? WHERE account_id = ? AND code_hash = ? AND used_at IS NULL`,
			ts(s.now()), account, totp.HashRecoveryCode(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errTwoFactorCode
		}
		return nil
	}
	secret, enabled, last, err := s.totpSecret(ctx, account)
	if err != nil || (needEnabled && !enabled) {
		return errTwoFactorCode
	}
	step, ok := totp.Verify(secret, code, s.now(), last)
	if !ok {
		return errTwoFactorCode
	}
	res, err := s.db.Exec(ctx, `UPDATE account_totp SET last_step = ? WHERE account_id = ? AND last_step < ?`, step, account, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errTwoFactorCode
	}
	return nil
}

func (s *Server) newRecoveryCodes(ctx context.Context, account string) ([]string, error) {
	codes, hashes := totp.NewRecoveryCodes(totp.RecoveryCodes)
	if _, err := s.db.Exec(ctx, `DELETE FROM account_recovery_codes WHERE account_id = ?`, account); err != nil {
		return nil, err
	}
	for _, h := range hashes {
		if _, err := s.db.Exec(ctx, `INSERT INTO account_recovery_codes (account_id, code_hash) VALUES (?, ?)`, account, h); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// passwordOK checks the signed-in person's password, counting failures.
func (s *Server) passwordOK(ctx context.Context, w http.ResponseWriter, c caller, password string) bool {
	if !s.logins.Allow(c.Account.Email) {
		writeErr(w, http.StatusTooManyRequests, "too many wrong passwords or codes; try again in a few minutes")
		return false
	}
	var h string
	if s.db.Row(ctx, `SELECT password_hash FROM accounts WHERE id = ?`, c.Account.ID).Scan(&h) != nil || !auth.VerifyPassword(h, password) {
		s.logins.Add(c.Account.Email)
		writeErr(w, http.StatusForbidden, "your password didn't match")
		return false
	}
	return true
}

type twoFactorBody struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) twoFactorStatus(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	ctx := r.Context()
	on := s.twoFactorOn(ctx, c.Account.ID)
	left := 0
	if on {
		_ = s.db.Row(ctx, `SELECT COUNT(*) FROM account_recovery_codes WHERE account_id = ? AND used_at IS NULL`, c.Account.ID).Scan(&left)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": on, "recoveryCodesLeft": left})
}

func (s *Server) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var req twoFactorBody
	_ = readJSON(r, &req)
	ctx := r.Context()
	if !s.passwordOK(ctx, w, c, req.Password) {
		return
	}
	if s.twoFactorOn(ctx, c.Account.ID) {
		writeErr(w, http.StatusConflict, "two-factor sign-in is already on; turn it off first to set it up again")
		return
	}
	key, err := s.totpKey(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not set up")
		return
	}
	raw := totp.NewSecret()
	sealed, err := totp.Seal(key, raw, c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not set up")
		return
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO account_totp (account_id, secret, enabled, last_step, created_at) VALUES (?,?,0,0,?)
		ON CONFLICT (account_id) DO UPDATE SET secret = excluded.secret, enabled = 0, last_step = 0, created_at = excluded.created_at`,
		c.Account.ID, sealed, ts(s.now())); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not set up")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": totp.Encode(raw), "uri": totp.URI(s.cfg.Name, c.Account.Email, raw)})
}

func (s *Server) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var req twoFactorBody
	_ = readJSON(r, &req)
	ctx := r.Context()
	if s.twoFactorOn(ctx, c.Account.ID) {
		writeErr(w, http.StatusConflict, "two-factor sign-in is already on")
		return
	}
	if err := s.checkCode(ctx, c.Account.ID, req.Code, false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.db.Exec(ctx, `UPDATE account_totp SET enabled = 1 WHERE account_id = ?`, c.Account.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not turn it on")
		return
	}
	codes, err := s.newRecoveryCodes(ctx, c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	s.notifySecurity(c.Account.Email, "Two-factor sign-in is on", "Two-factor sign-in was turned on for your account. Keep your recovery codes somewhere safe.")
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// confirmed checks password and a code for the signed-in person.
func (s *Server) confirmed(w http.ResponseWriter, r *http.Request) (caller, bool) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return c, false
	}
	var req twoFactorBody
	_ = readJSON(r, &req)
	ctx := r.Context()
	if !s.passwordOK(ctx, w, c, req.Password) {
		return c, false
	}
	if err := s.checkCode(ctx, c.Account.ID, req.Code, true); err != nil {
		s.logins.Add(c.Account.Email)
		writeErr(w, http.StatusForbidden, err.Error())
		return c, false
	}
	return c, true
}

func (s *Server) twoFactorDisable(w http.ResponseWriter, r *http.Request) {
	c, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	_, _ = s.db.Exec(ctx, `DELETE FROM account_recovery_codes WHERE account_id = ?`, c.Account.ID)
	if _, err := s.db.Exec(ctx, `DELETE FROM account_totp WHERE account_id = ?`, c.Account.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not turn it off")
		return
	}
	s.notifySecurity(c.Account.Email, "Two-factor sign-in is off", "Two-factor sign-in was turned off for your account. If this wasn't you, reset your password now.")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) twoFactorRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	c, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	codes, err := s.newRecoveryCodes(r.Context(), c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// sessionTwoFactor finishes a password sign-in with a code.
func (s *Server) sessionTwoFactor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	account, device, ok := s.twoFactor.Peek(req.Challenge)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "the sign-in expired; enter your password again")
		return
	}
	ctx := r.Context()
	a, err := s.account(ctx, account)
	if err != nil {
		s.twoFactor.Done(req.Challenge)
		writeErr(w, http.StatusUnauthorized, "wrong email or password")
		return
	}
	if !s.logins.Allow(a.Email) {
		writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins for this account; try again in a few minutes")
		return
	}
	if err := s.checkCode(ctx, account, req.Code, true); err != nil {
		s.logins.Add(a.Email)
		s.twoFactor.Failed(req.Challenge)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.twoFactor.Done(req.Challenge)
	s.logins.Reset(a.Email)
	s.issueSession(w, r, account, device)
}

func (s *Server) notifySecurity(to, subject, body string) {
	go func() {
		_ = s.mail.Send(context.Background(), to, subject+" on "+s.cfg.Name, body+"\n\n"+s.cfg.PublicURL)
	}()
}
