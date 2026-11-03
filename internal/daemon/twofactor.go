package daemon

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/totp"
)

// Two-factor sign-in with authenticator apps (internal/totp). Everything
// here is for signed-in people only; API keys and agents never sign in, so
// they have nothing to protect with a second factor. Single sign-on
// (oidc.go) leaves the second factor to the identity provider.

var twoFactorChallenges = totp.NewChallenges()

func (s *Server) twoFactorRoutes() []route {
	return []route{
		{"POST /api/v1/auth/login/2fa", s.loginTwoFactor},
		{"GET /api/v1/me/2fa", s.need("", s.twoFactorStatus)},
		{"POST /api/v1/me/2fa/setup", s.need("", s.twoFactorSetup)},
		{"POST /api/v1/me/2fa/enable", s.need("", s.twoFactorEnable)},
		{"POST /api/v1/me/2fa/disable", s.need("", s.twoFactorDisable)},
		{"POST /api/v1/me/2fa/recovery-codes", s.need("", s.twoFactorRecoveryCodes)},
		{"POST /api/v1/users/{id}/2fa/reset", s.need("admin:*:*", s.twoFactorReset)},
	}
}

// startTwoFactor answers a correct password for an account with 2FA on:
// no session yet, a challenge for the second step.
func (s *Server) startTwoFactor(w http.ResponseWriter, u auth.User, device string) {
	id := twoFactorChallenges.Put(u.ID, device)
	if id == "" {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-ins in progress; try again in a minute")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"twoFactor": true, "challenge": id})
}

func (s *Server) loginTwoFactor(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, device, ok := twoFactorChallenges.Peek(req.Challenge)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "the sign-in expired; enter your password again")
		return
	}
	u, err := s.Auth.GetUser(r.Context(), userID)
	if err != nil || u.Disabled {
		twoFactorChallenges.Done(req.Challenge)
		writeErr(w, http.StatusUnauthorized, auth.ErrInvalidCredentials.Error())
		return
	}
	src := requestSource(r)
	acct := strings.ToLower(u.Email)
	if !loginFailsBySource.Allow(src) || !loginFailsByAccount.Allow(acct) {
		wait := max(loginFailsBySource.RetryAfter(src), loginFailsByAccount.RetryAfter(acct))
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins; try again in a few minutes")
		return
	}
	if err := s.Auth.CheckTwoFactor(r.Context(), u.ID, req.Code); err != nil {
		loginFailsBySource.Add(src)
		loginFailsByAccount.Add(acct)
		twoFactorChallenges.Failed(req.Challenge)
		writeErr(w, http.StatusUnauthorized, auth.ErrTwoFactorCode.Error())
		return
	}
	twoFactorChallenges.Done(req.Challenge)
	loginFailsByAccount.Reset(acct)
	s.startSession(w, r, u, device, http.StatusOK)
}

type twoFactorState struct {
	Enabled           bool `json:"enabled"`
	RecoveryCodesLeft int  `json:"recoveryCodesLeft"`
}

func (s *Server) twoFactorStatus(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	st := twoFactorState{Enabled: s.Auth.TwoFactorEnabled(r.Context(), p.User.ID)}
	if st.Enabled {
		st.RecoveryCodesLeft = s.Auth.RecoveryCodesLeft(r.Context(), p.User.ID)
	}
	writeJSON(w, http.StatusOK, st)
}

type twoFactorReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// readTwoFactor reads the body, and checks the password (and, when asked,
// a code) of the signed-in person.
func (s *Server) readTwoFactor(w http.ResponseWriter, r *http.Request, needCode bool) (twoFactorReq, auth.User, bool) {
	var req twoFactorReq
	if !s.humanOnly(w, r) {
		return req, auth.User{}, false
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return req, auth.User{}, false
	}
	p, _ := principal(r)
	acct := strings.ToLower(p.User.Email)
	if !loginFailsByAccount.Allow(acct) {
		writeErr(w, http.StatusTooManyRequests, "too many wrong passwords or codes; try again in a few minutes")
		return req, auth.User{}, false
	}
	if !s.Auth.CheckPassword(r.Context(), p.User.ID, req.Password) {
		loginFailsByAccount.Add(acct)
		writeErr(w, http.StatusForbidden, "your password didn't match")
		return req, auth.User{}, false
	}
	if needCode {
		if err := s.Auth.CheckTwoFactor(r.Context(), p.User.ID, req.Code); err != nil {
			loginFailsByAccount.Add(acct)
			writeErr(w, http.StatusForbidden, err.Error())
			return req, auth.User{}, false
		}
	}
	return req, p.User, true
}

func (s *Server) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.readTwoFactor(w, r, false)
	if !ok {
		return
	}
	secret, uri, err := s.Auth.BeginTwoFactor(r.Context(), u.ID, u.Email)
	if errors.Is(err, auth.ErrTwoFactorOn) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
}

func (s *Server) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req twoFactorReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principal(r)
	codes, err := s.Auth.EnableTwoFactor(r.Context(), p.User.ID, req.Code)
	switch {
	case errors.Is(err, auth.ErrNoEnrollment), errors.Is(err, auth.ErrTwoFactorOn):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, auth.ErrTwoFactorCode):
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "two_factor_enabled", "", nil)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

func (s *Server) twoFactorDisable(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.readTwoFactor(w, r, true)
	if !ok {
		return
	}
	if err := s.Auth.DisableTwoFactor(r.Context(), u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "two_factor_disabled", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) twoFactorRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.readTwoFactor(w, r, true)
	if !ok {
		return
	}
	codes, err := s.Auth.RegenerateRecoveryCodes(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.auditConfig(r, "recovery_codes_replaced", "", nil)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// twoFactorReset turns off someone else's 2FA (a lost phone), with the same
// rules as setting their password: not yourself, never the owner, and only
// the owner for admins. They sign in with their password and set it up again.
func (s *Server) twoFactorReset(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	id := r.PathValue("id")
	p, _ := principal(r)
	target, err := s.Auth.GetUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such account")
		return
	}
	switch {
	case id == p.User.ID:
		writeErr(w, http.StatusBadRequest, "turn your own two-factor sign-in off in Settings")
		return
	case target.Role == auth.RoleOwner:
		writeErr(w, http.StatusForbidden, "the owner's two-factor sign-in can only be changed by the owner")
		return
	case target.Role == auth.RoleAdmin && p.User.Role != auth.RoleOwner:
		writeErr(w, http.StatusForbidden, "only the owner can reset an admin's two-factor sign-in")
		return
	}
	if err := s.Auth.DisableTwoFactor(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.Auth.RevokeSessions(r.Context(), id, "")
	s.auditConfig(r, "two_factor_reset", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
