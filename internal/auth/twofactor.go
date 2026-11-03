package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/elchi-dev/conduit/internal/totp"
)

// twoFactorCol is the users-query column that says whether 2FA is on.
const twoFactorCol = `EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.enabled = 1)`

const settingTOTPKey = "auth.totp_key"

// Two-factor errors.
var (
	ErrTwoFactorCode = errors.New("that code didn't work; check your authenticator app's clock, or use a recovery code")
	ErrTwoFactorOff  = errors.New("two-factor sign-in isn't on for this account")
	ErrTwoFactorOn   = errors.New("two-factor sign-in is already on; turn it off first to set it up again")
	ErrNoEnrollment  = errors.New("start the setup first")
)

// totpKey is the key that encrypts authenticator secrets at rest, made on
// first use.
func (s *Service) totpKey(ctx context.Context) (string, error) {
	var k string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, settingTOTPKey).Scan(&k)
	if err == nil && k != "" {
		return k, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	k = totp.NewKey()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, settingTOTPKey, k); err != nil {
		return "", err
	}
	// Another request may have won the race; use whatever is stored.
	err = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, settingTOTPKey).Scan(&k)
	return k, err
}

// TwoFactorEnabled reports whether the account uses two-factor sign-in.
func (s *Service) TwoFactorEnabled(ctx context.Context, userID string) bool {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND enabled = 1`, userID).Scan(&n)
	return n > 0
}

// BeginTwoFactor makes a new secret for an account that doesn't use 2FA
// yet, and returns it as text and as an otpauth:// URI for a QR code.
// It takes effect only after EnableTwoFactor confirms a code from the app.
func (s *Service) BeginTwoFactor(ctx context.Context, userID, account string) (secret, uri string, err error) {
	if s.TwoFactorEnabled(ctx, userID) {
		return "", "", ErrTwoFactorOn
	}
	key, err := s.totpKey(ctx)
	if err != nil {
		return "", "", err
	}
	raw := totp.NewSecret()
	sealed, err := totp.Seal(key, raw, userID)
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO user_totp (user_id, secret, enabled, last_step, created_at) VALUES (?,?,0,0,?)
		ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, enabled = 0, last_step = 0, created_at = excluded.created_at, enabled_at = NULL`,
		userID, sealed, ts(s.now().UTC())); err != nil {
		return "", "", err
	}
	return totp.Encode(raw), totp.URI("Conduit", account, raw), nil
}

func (s *Service) totpSecret(ctx context.Context, userID string) (secret []byte, enabled bool, last int64, err error) {
	var sealed string
	var en int
	err = s.db.QueryRowContext(ctx, `SELECT secret, enabled, last_step FROM user_totp WHERE user_id = ?`, userID).Scan(&sealed, &en, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, 0, ErrNoEnrollment
	}
	if err != nil {
		return nil, false, 0, err
	}
	key, err := s.totpKey(ctx)
	if err != nil {
		return nil, false, 0, err
	}
	secret, err = totp.Open(key, sealed, userID)
	return secret, en == 1, last, err
}

// useStep records a time step as used, atomically, so one code works once
// even when two requests race.
func (s *Service) useStep(ctx context.Context, userID string, step int64) bool {
	res, err := s.db.ExecContext(ctx, `UPDATE user_totp SET last_step = ? WHERE user_id = ? AND last_step < ?`, step, userID, step)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// EnableTwoFactor confirms the setup with a code from the app and returns
// the recovery codes, shown once.
func (s *Service) EnableTwoFactor(ctx context.Context, userID, code string) ([]string, error) {
	secret, enabled, last, err := s.totpSecret(ctx, userID)
	if err != nil {
		return nil, err
	}
	if enabled {
		return nil, ErrTwoFactorOn
	}
	step, ok := totp.Verify(secret, code, s.now(), last)
	if !ok || !s.useStep(ctx, userID, step) {
		return nil, ErrTwoFactorCode
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE user_totp SET enabled = 1, enabled_at = ? WHERE user_id = ?`, ts(s.now().UTC()), userID); err != nil {
		return nil, err
	}
	return s.newRecoveryCodes(ctx, userID)
}

func (s *Service) newRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes, hashes := totp.NewRecoveryCodes(totp.RecoveryCodes)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// CheckTwoFactor accepts a code from the app, or a recovery code (which
// then stops working). It's for accounts with 2FA on.
func (s *Service) CheckTwoFactor(ctx context.Context, userID, code string) error {
	if totp.LooksLikeRecoveryCode(code) {
		if !s.TwoFactorEnabled(ctx, userID) {
			return ErrTwoFactorOff
		}
		res, err := s.db.ExecContext(ctx, `UPDATE user_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
			ts(s.now().UTC()), userID, totp.HashRecoveryCode(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrTwoFactorCode
		}
		return nil
	}
	secret, enabled, last, err := s.totpSecret(ctx, userID)
	if err != nil || !enabled {
		return ErrTwoFactorOff
	}
	step, ok := totp.Verify(secret, code, s.now(), last)
	if !ok || !s.useStep(ctx, userID, step) {
		return ErrTwoFactorCode
	}
	return nil
}

// RegenerateRecoveryCodes replaces the recovery codes.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if !s.TwoFactorEnabled(ctx, userID) {
		return nil, ErrTwoFactorOff
	}
	return s.newRecoveryCodes(ctx, userID)
}

// RecoveryCodesLeft counts unused recovery codes.
func (s *Service) RecoveryCodesLeft(ctx context.Context, userID string) int {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n
}

// DisableTwoFactor turns 2FA off and forgets the secret and recovery codes.
// Callers check the password and a code first (or that an admin may reset).
func (s *Service) DisableTwoFactor(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id = ?`, userID)
	return err
}

// CheckPassword verifies an account's current password.
func (s *Service) CheckPassword(ctx context.Context, userID, password string) bool {
	var hash string
	if s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash) != nil {
		VerifyPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g", password)
		return false
	}
	return VerifyPassword(hash, password)
}
