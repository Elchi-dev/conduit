package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/ratelimit"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Single sign-on with any OpenID Connect provider (Google Workspace,
// Microsoft Entra ID, Okta, Keycloak, Authentik, GitLab…): authorization
// code flow with PKCE (S256), state and nonce. See docs/api/sso.md.

const oidcSetting = "auth.oidc"

// OIDCSettings is the single sign-on configuration.
type OIDCSettings struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // a secret:// vault reference, never a value
	Label        string `json:"label"`
	// AllowedDomains limits which email domains may sign in; empty allows
	// any verified address that already has an account here.
	AllowedDomains []string `json:"allowedDomains"`
	// AutoCreate makes an account for a verified address in an allowed
	// domain on its first sign-in, with NewUserRole (member or viewer).
	AutoCreate  bool      `json:"autoCreate"`
	NewUserRole auth.Role `json:"newUserRole"`
	// RedirectBase is the daemon's address as the provider knows it, e.g.
	// https://conduit.example.com; empty uses the request's origin.
	RedirectBase string `json:"redirectBase"`
}

const oidcCallbackPath = "/api/v1/auth/oidc/callback"

func (s *Server) oidcSettings(ctx context.Context) OIDCSettings {
	var raw string
	var cfg OIDCSettings
	if err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, oidcSetting).Scan(&raw); err == nil {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	if cfg.Label == "" {
		cfg.Label = "single sign-on"
	}
	if cfg.NewUserRole == "" {
		cfg.NewUserRole = auth.RoleMember
	}
	if cfg.AllowedDomains == nil {
		cfg.AllowedDomains = []string{}
	}
	return cfg
}

func (c OIDCSettings) validate() error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return errors.New("the issuer is the provider's https:// address, e.g. https://accounts.google.com")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("enter the client ID from your provider")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	switch c.NewUserRole {
	case auth.RoleMember, auth.RoleViewer:
	default:
		return errors.New("new accounts can be members or viewers; promote people afterwards")
	}
	if c.RedirectBase != "" {
		r, err := url.Parse(c.RedirectBase)
		if err != nil || (r.Scheme != "https" && r.Scheme != "http") || r.Host == "" || (r.Path != "" && r.Path != "/") {
			return errors.New("the address of this daemon is like https://conduit.example.com, without a path")
		}
	}
	if len(c.AllowedDomains) == 0 {
		return errors.New("add at least one allowed email domain, such as your company's; without one, anyone your provider lets set an address could try it")
	}
	for _, d := range c.AllowedDomains {
		if strings.ContainsAny(d, "@/ ") || !strings.Contains(d, ".") {
			return errors.New("allowed domains are like example.com")
		}
	}
	return nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// redirectURL is where the provider sends people back.
func (s *Server) oidcRedirect(r *http.Request, c OIDCSettings) string {
	if c.RedirectBase != "" {
		return strings.TrimRight(c.RedirectBase, "/") + oidcCallbackPath
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + oidcCallbackPath
}

// --- provider and ceremonies ----------------------------------------------------------

type oidcCeremony struct {
	verifier, nonce, redirect string
	// linkUser is set when a signed-in person links their account to their
	// identity at the provider, instead of signing in.
	linkUser string
	expires  time.Time
}

var (
	oidcMu         sync.Mutex
	oidcCeremonies = map[string]oidcCeremony{}
	oidcProviders  = map[string]*oidc.Provider{} // by issuer
	oidcLimit      = ratelimit.New(30, time.Minute, 10000)
)

const (
	oidcCeremonyTTL = 10 * time.Minute
	oidcMaxPending  = 5000
	oidcStateCookie = "conduit_oidc"
)

func oidcHTTP(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, &http.Client{Timeout: 15 * time.Second})
}

func provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	oidcMu.Lock()
	p := oidcProviders[issuer]
	oidcMu.Unlock()
	if p != nil {
		return p, nil
	}
	p, err := oidc.NewProvider(oidcHTTP(ctx), issuer)
	if err != nil {
		return nil, err
	}
	oidcMu.Lock()
	oidcProviders[issuer] = p
	oidcMu.Unlock()
	return p, nil
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func putCeremony(state string, c oidcCeremony) bool {
	oidcMu.Lock()
	defer oidcMu.Unlock()
	now := time.Now()
	if len(oidcCeremonies) >= oidcMaxPending {
		for k, v := range oidcCeremonies {
			if now.After(v.expires) {
				delete(oidcCeremonies, k)
			}
		}
		if len(oidcCeremonies) >= oidcMaxPending {
			return false
		}
	}
	oidcCeremonies[state] = c
	return true
}

// takeCeremony returns and forgets a ceremony; each state works once.
func takeCeremony(state string) (oidcCeremony, bool) {
	oidcMu.Lock()
	defer oidcMu.Unlock()
	c, ok := oidcCeremonies[state]
	delete(oidcCeremonies, state)
	if !ok || time.Now().After(c.expires) {
		return oidcCeremony{}, false
	}
	return c, true
}

func (s *Server) oauthConfig(ctx context.Context, r *http.Request, c OIDCSettings, p *oidc.Provider) (*oauth2.Config, error) {
	if s.Vault == nil {
		return nil, errors.New("no vault")
	}
	secret, err := s.Vault.Resolve(ctx, c.ClientSecret)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: p.Endpoint(),
		RedirectURL: s.oidcRedirect(r, c), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}, nil
}

// --- handlers ------------------------------------------------------------------

func (s *Server) oidcRoutes() []route {
	return []route{
		{"GET /api/v1/auth/oidc", s.oidcPublic},
		{"GET /api/v1/auth/oidc/settings", s.need("admin:*:*", s.oidcGetSettings)},
		{"PUT /api/v1/auth/oidc", s.need("admin:*:*", s.oidcPutSettings)},
		{"GET /api/v1/auth/oidc/start", s.oidcStart},
		{"GET /api/v1/auth/oidc/link", s.need("", s.oidcLink)},
		{"GET /api/v1/auth/oidc/me", s.need("", s.oidcMine)},
		{"DELETE /api/v1/auth/oidc/link", s.need("", s.oidcUnlink)},
		{"GET " + oidcCallbackPath, s.oidcCallback},
	}
}

func (s *Server) oidcPublic(w http.ResponseWriter, r *http.Request) {
	c := s.oidcSettings(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"enabled": c.Enabled, "label": c.Label})
}

type oidcSettingsResp struct {
	OIDCSettings
	RedirectURI string `json:"redirectUri"`
}

func (s *Server) oidcGetSettings(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	c := s.oidcSettings(r.Context())
	// The setting holds only a vault reference; it is still the name of a
	// credential, so it's shown as stored and never resolved here.
	writeJSON(w, http.StatusOK, oidcSettingsResp{OIDCSettings: c, RedirectURI: s.oidcRedirect(r, c)})
}

func (s *Server) oidcPutSettings(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var c OIDCSettings
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	if err := s.mayUse(r.Context(), principalActor(r), strings.TrimPrefix(c.ClientSecret, "secret://")); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	c.Label = strings.TrimSpace(c.Label)
	if c.NewUserRole == "" {
		c.NewUserRole = auth.RoleMember
	}
	doms := []string{}
	for _, d := range c.AllowedDomains {
		if d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@")); d != "" {
			doms = append(doms, d)
		}
	}
	c.AllowedDomains = doms
	if c.ClientSecret != "" && !strings.HasPrefix(c.ClientSecret, "secret://") {
		writeErr(w, http.StatusBadRequest, "store the client secret in the vault and enter its secret:// reference, not the secret itself")
		return
	}
	if err := c.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	b, _ := json.Marshal(c)
	if _, err := s.DB.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, oidcSetting, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	oidcMu.Lock()
	delete(oidcProviders, c.Issuer) // pick up provider changes
	oidcMu.Unlock()
	s.auditConfig(r, "oidc_settings_changed", "", map[string]any{"enabled": c.Enabled, "issuer": c.Issuer, "clientId": c.ClientID,
		"allowedDomains": c.AllowedDomains, "autoCreate": c.AutoCreate, "newUserRole": c.NewUserRole})
	s.oidcGetSettings(w, r)
}

func (s *Server) oidcFail(w http.ResponseWriter, r *http.Request, code, detail string) {
	s.Log.Warn("single sign-on refused", "reason", code, "detail", detail, "source", requestSource(r))
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/?signin_error="+url.QueryEscape(code), http.StatusFound)
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	s.oidcBegin(w, r, "")
}

// oidcLink starts the same ceremony for the signed-in person, to link their
// account to their identity at the provider. Owners and admins must do this
// before they can use single sign-on.
func (s *Server) oidcLink(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	s.oidcBegin(w, r, p.User.ID)
}

// oidcUnlink removes the signed-in person's links.
func (s *Server) oidcUnlink(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	_, _ = s.DB.ExecContext(r.Context(), `DELETE FROM oidc_links WHERE user_id = ?`, p.User.ID)
	s.auditConfig(r, "oidc_unlinked", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// oidcMine reports whether the signed-in person has a linked identity.
func (s *Server) oidcMine(w http.ResponseWriter, r *http.Request) {
	p, _ := principal(r)
	var n int
	_ = s.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM oidc_links WHERE user_id = ?`, p.User.ID).Scan(&n)
	writeJSON(w, http.StatusOK, map[string]bool{"linked": n > 0})
}

func (s *Server) oidcBegin(w http.ResponseWriter, r *http.Request, linkUser string) {
	if !oidcLimit.Add(requestSource(r)) {
		s.oidcFail(w, r, "busy", "rate limited")
		return
	}
	ctx := r.Context()
	c := s.oidcSettings(ctx)
	if !c.Enabled {
		s.oidcFail(w, r, "sso_off", "not enabled")
		return
	}
	p, err := provider(ctx, c.Issuer)
	if err != nil {
		s.oidcFail(w, r, "provider", err.Error())
		return
	}
	cfg, err := s.oauthConfig(ctx, r, c, p)
	if err != nil {
		s.oidcFail(w, r, "config", err.Error())
		return
	}
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	if !putCeremony(state, oidcCeremony{verifier: verifier, nonce: nonce, redirect: cfg.RedirectURL, linkUser: linkUser, expires: time.Now().Add(oidcCeremonyTTL)}) {
		s.oidcFail(w, r, "busy", "too many pending sign-ins")
		return
	}
	// The state is also bound to this browser, so a sign-in someone else
	// started can't be completed in your browser (login CSRF).
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: state, Path: "/api/v1/auth/oidc", MaxAge: int(oidcCeremonyTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if !oidcLimit.Add(requestSource(r)) {
		s.oidcFail(w, r, "busy", "rate limited")
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.oidcFail(w, r, "provider_refused", e)
		return
	}
	state := q.Get("state")
	ck, err := r.Cookie(oidcStateCookie)
	if state == "" || err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(state)) != 1 {
		s.oidcFail(w, r, "state", "state missing or not from this browser")
		return
	}
	cer, ok := takeCeremony(state)
	if !ok {
		s.oidcFail(w, r, "expired", "unknown or expired state")
		return
	}
	c := s.oidcSettings(ctx)
	if !c.Enabled {
		s.oidcFail(w, r, "sso_off", "not enabled")
		return
	}
	p, err := provider(ctx, c.Issuer)
	if err != nil {
		s.oidcFail(w, r, "provider", err.Error())
		return
	}
	cfg, err := s.oauthConfig(ctx, r, c, p)
	if err != nil {
		s.oidcFail(w, r, "config", err.Error())
		return
	}
	cfg.RedirectURL = cer.redirect
	tok, err := cfg.Exchange(oidcHTTP(ctx), q.Get("code"), oauth2.VerifierOption(cer.verifier))
	if err != nil {
		s.oidcFail(w, r, "exchange", err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		s.oidcFail(w, r, "no_id_token", "")
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(oidcHTTP(ctx), rawID)
	if err != nil {
		s.oidcFail(w, r, "token", err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(cer.nonce)) != 1 {
		s.oidcFail(w, r, "token", "nonce mismatch")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified any    `json:"email_verified"`
		Name     string `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		s.oidcFail(w, r, "token", err.Error())
		return
	}
	if idt.Subject == "" {
		s.oidcFail(w, r, "token", "no subject")
		return
	}

	// Linking: the signed-in person who started this ceremony.
	if cer.linkUser != "" {
		var other string
		err := s.DB.QueryRowContext(ctx, `SELECT user_id FROM oidc_links WHERE issuer = ? AND subject = ?`, c.Issuer, idt.Subject).Scan(&other)
		if err == nil && other != cer.linkUser {
			s.oidcFail(w, r, "linked_elsewhere", "identity already linked to another account")
			return
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_links (issuer, subject, user_id, created_at) VALUES (?,?,?,?) ON CONFLICT(issuer, subject) DO NOTHING`,
			c.Issuer, idt.Subject, cer.linkUser, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			s.oidcFail(w, r, "account", err.Error())
			return
		}
		u, _ := s.Auth.GetUser(ctx, cer.linkUser)
		in, _ := json.Marshal(map[string]any{"issuer": c.Issuer, "subject": shortHash(idt.Subject)})
		_, _ = s.Engine.Audit.Append(context.WithoutCancel(ctx), core.Entry{Actor: core.Actor{ID: u.ID, Kind: core.ActorUser, Name: u.Name}, Module: "core", Instance: "auth", Action: "oidc_linked", Risk: sdk.RiskWrite, Decision: core.Allow, Status: "ok", Input: in})
		http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true})
		http.Redirect(w, r, "/settings?sso=linked", http.StatusFound)
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	// Only a JSON true counts: a string could be anything a provider lets
	// people type.
	verified := claims.Verified == true
	var u auth.User
	created := false
	var linkedID string
	err = s.DB.QueryRowContext(ctx, `SELECT user_id FROM oidc_links WHERE issuer = ? AND subject = ?`, c.Issuer, idt.Subject).Scan(&linkedID)
	switch {
	case err == nil:
		// A linked identity: the subject decides, whatever the email says now.
		u, err = s.Auth.GetUser(ctx, linkedID)
		if err != nil {
			s.oidcFail(w, r, "account", "linked account is gone")
			return
		}
	default:
		if email == "" || !verified {
			s.oidcFail(w, r, "unverified", "no verified email")
			return
		}
		domain := email[strings.LastIndex(email, "@")+1:]
		allowed := false
		for _, d := range c.AllowedDomains {
			allowed = allowed || d == domain
		}
		if !allowed {
			s.oidcFail(w, r, "domain", domain)
			return
		}
		u, err = s.Auth.UserByEmail(ctx, email)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if !c.AutoCreate {
				s.oidcFail(w, r, "no_account", email)
				return
			}
			u, err = s.Auth.CreateUser(ctx, claims.Name, email, randomToken(), c.NewUserRole)
			if err != nil {
				s.oidcFail(w, r, "account", err.Error())
				return
			}
			created = true
		case err != nil:
			s.oidcFail(w, r, "account", err.Error())
			return
		case u.Role == auth.RoleOwner || u.Role == auth.RoleAdmin:
			// Never by email alone for accounts that can change everything.
			s.oidcFail(w, r, "link_required", email)
			return
		default:
			// A member or viewer whose account has a link to another
			// identity at this provider doesn't get a second one by email.
			var n int
			_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_links WHERE user_id = ? AND issuer = ?`, u.ID, c.Issuer).Scan(&n)
			if n > 0 {
				s.oidcFail(w, r, "linked_elsewhere", email)
				return
			}
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_links (issuer, subject, user_id, created_at) VALUES (?,?,?,?)`,
			c.Issuer, idt.Subject, u.ID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			s.oidcFail(w, r, "account", err.Error())
			return
		}
	}
	if u.Disabled {
		s.oidcFail(w, r, "disabled", u.Email)
		return
	}
	se, sessTok, err := s.Auth.CreateSession(ctx, u.ID, "Single sign-on, "+r.UserAgent())
	if err != nil {
		s.oidcFail(w, r, "session", err.Error())
		return
	}
	actor := core.Actor{ID: u.ID, Kind: core.ActorUser, Name: u.Name}
	in, _ := json.Marshal(map[string]any{"issuer": c.Issuer, "email": u.Email, "created": created, "subject": shortHash(idt.Subject)})
	_, _ = s.Engine.Audit.Append(context.WithoutCancel(ctx), core.Entry{Actor: actor, Module: "core", Instance: "auth", Action: "oidc_login", Risk: sdk.RiskWrite, Decision: core.Allow, Status: "ok", Input: in})
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: sessTok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil, Expires: se.ExpiresAt})
	http.Redirect(w, r, "/", http.StatusFound)
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:9])
}
