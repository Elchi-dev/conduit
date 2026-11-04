package daemon

// Passkeys (WebAuthn) for people accounts.
//
// The relying party is whatever address the daemon is opened at: the RP ID
// is the request's host name without the port, and the only accepted origin
// is the request's own origin. WebAuthn doesn't allow IP addresses as RP
// IDs, so passkeys are only offered when the host is a name: localhost (and
// *.localhost), an mDNS *.local name, or one in CONDUIT_ALLOWED_HOSTS. The
// desktop app, which opens the daemon at 127.0.0.1, doesn't offer them; GET
// /auth/passkeys/available tells the UI. A passkey only works at the name it
// was added at.
//
// Adding a passkey needs a signed-in person (not a key or an agent) and
// their password again: a passkey outlives sessions, so a stolen session
// alone can't plant a way back in. A password change or reset removes the
// account's passkeys.
//
// Sign-in is usernameless (discoverable credentials) and asks the
// authenticator to verify the person (PIN or biometrics), so a passkey
// counts as both factors: it skips the authenticator-app code of two-factor
// sign-in. Failed passkey sign-ins count against the same per-source limit
// as wrong passwords.
//
// Ceremony state (the challenge) is kept in memory for five minutes, used
// once, and bound to its ceremony type, the relying party it was started
// for and (for registration) the account. It doesn't survive a restart,
// which only means a ceremony in progress has to start again.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	passkeyCeremonyTTL = 5 * time.Minute
	maxPasskeyCeremony = 10000
	passkeyNameSize    = 60
)

func (s *Server) passkeyRoutes() []route {
	return []route{
		{"GET /api/v1/auth/passkeys/available", s.passkeysAvailable},
		{"POST /api/v1/auth/passkeys/login/begin", s.beginPasskeyLogin},
		{"POST /api/v1/auth/passkeys/login/finish", s.finishPasskeyLogin},
		{"GET /api/v1/me/passkeys", s.need("", s.listPasskeys)},
		{"POST /api/v1/me/passkeys/register/begin", s.need("", s.beginPasskeyRegistration)},
		{"POST /api/v1/me/passkeys/register/finish", s.need("", s.finishPasskeyRegistration)},
		{"PATCH /api/v1/me/passkeys/{id}", s.need("", s.renamePasskey)},
		{"DELETE /api/v1/me/passkeys/{id}", s.need("", s.deletePasskey)},
	}
}

// --- relying party ------------------------------------------------------

type relyingParty struct {
	id     string // host name without port
	origin string // scheme://host[:port]
}

// relyingPartyFor works out the relying party for a request, or why there
// is none.
func relyingPartyFor(r *http.Request) (relyingParty, string) {
	if r.RemoteAddr == "relay" {
		return relyingParty{}, "passkeys work only when the daemon is opened directly in a browser, not through remote access"
	}
	host := strings.ToLower(r.Host)
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if name == "" || net.ParseIP(name) != nil {
		return relyingParty{}, "passkeys need a host name, not an IP address; open the daemon at http://localhost or a name in CONDUIT_ALLOWED_HOSTS"
	}
	if !allowedHost(host, extraHosts()) {
		return relyingParty{}, "this host name isn't one the daemon is served under"
	}
	if err := protocol.ValidateRPID(name); err != nil {
		return relyingParty{}, "this host name can't be used for passkeys"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if o, err := url.Parse(r.Header.Get("Origin")); err == nil && o.Scheme == "https" && strings.EqualFold(o.Host, r.Host) {
		// Behind a reverse proxy that ends TLS, the browser's origin is
		// https at the same host.
		scheme = "https"
	}
	return relyingParty{id: name, origin: scheme + "://" + host}, ""
}

func (rp relyingParty) webauthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rp.id,
		RPDisplayName: "Conduit",
		RPOrigins:     []string{rp.origin},
	})
}

// --- ceremonies ---------------------------------------------------------

type passkeyCeremony struct {
	kind    string // "register" or "login"
	user    string // registration: the account adding the passkey
	rp      relyingParty
	data    webauthn.SessionData
	expires time.Time
}

type passkeyCeremonies struct {
	mu sync.Mutex
	m  map[string]passkeyCeremony
}

var ceremonies = &passkeyCeremonies{m: map[string]passkeyCeremony{}}

func (c *passkeyCeremonies) put(cer passkeyCeremony) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if len(c.m) >= maxPasskeyCeremony {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxPasskeyCeremony {
			return ""
		}
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	cer.expires = now.Add(passkeyCeremonyTTL)
	c.m[id] = cer
	return id
}

// take returns a ceremony once; a second take of the same id fails.
func (c *passkeyCeremonies) take(id string) (passkeyCeremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cer, ok := c.m[id]
	delete(c.m, id)
	if !ok || time.Now().After(cer.expires) {
		return passkeyCeremony{}, false
	}
	return cer, true
}

// waUser adapts an account and its passkeys to the library.
type waUser struct {
	u     auth.User
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.u.ID) }
func (u *waUser) WebAuthnName() string                       { return u.u.Email }
func (u *waUser) WebAuthnDisplayName() string                { return u.u.Name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) waUser(ctx context.Context, u auth.User) (*waUser, error) {
	creds, err := s.Auth.PasskeyCredentials(ctx, u.ID)
	return &waUser{u: u, creds: creds}, err
}

// --- availability -------------------------------------------------------

func (s *Server) passkeysAvailable(w http.ResponseWriter, r *http.Request) {
	rp, why := relyingPartyFor(r)
	out := map[string]any{"available": why == ""}
	if why == "" {
		out["rpId"] = rp.id
	} else {
		out["reason"] = why
	}
	writeJSON(w, http.StatusOK, out)
}

// --- managing your passkeys --------------------------------------------

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	list, err := s.Auth.ListPasskeys(r.Context(), p.User.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func passkeyName(n string) string {
	n = strings.Join(strings.Fields(n), " ")
	if n == "" {
		return "Passkey"
	}
	for utf8.RuneCountInString(n) > passkeyNameSize {
		_, size := utf8.DecodeLastRuneInString(n)
		n = n[:len(n)-size]
	}
	return n
}

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principal(r)
	acct := strings.ToLower(p.User.Email)
	if !loginFailsByAccount.Allow(acct) {
		writeErr(w, http.StatusTooManyRequests, "too many wrong passwords or codes; try again in a few minutes")
		return
	}
	if !s.Auth.CheckPassword(r.Context(), p.User.ID, req.Password) {
		loginFailsByAccount.Add(acct)
		writeErr(w, http.StatusForbidden, "enter your password to add a passkey")
		return
	}
	rp, why := relyingPartyFor(r)
	if why != "" {
		writeErr(w, http.StatusBadRequest, why)
		return
	}
	wa, err := rp.webauthn()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "passkeys can't be used at this address: "+err.Error())
		return
	}
	u, err := s.waUser(r.Context(), p.User)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load the account")
		return
	}
	if len(u.creds) >= auth.MaxPasskeys {
		writeErr(w, http.StatusConflict, "an account can have at most "+strconv.Itoa(auth.MaxPasskeys)+" passkeys; remove one first")
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start: "+err.Error())
		return
	}
	id := ceremonies.put(passkeyCeremony{kind: "register", user: p.User.ID, rp: rp, data: *data})
	if id == "" {
		writeErr(w, http.StatusServiceUnavailable, "too many passkey requests in progress; try again in a minute")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": opts})
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Ceremony string          `json:"ceremony"`
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principal(r)
	rp, why := relyingPartyFor(r)
	cer, ok := ceremonies.take(req.Ceremony)
	if !ok || cer.kind != "register" || cer.user != p.User.ID || why != "" || cer.rp != rp {
		writeErr(w, http.StatusBadRequest, "this passkey request expired or was already used; start again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Response))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the browser's answer couldn't be read")
		return
	}
	wa, err := rp.webauthn()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.waUser(r.Context(), p.User)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load the account")
		return
	}
	cred, err := wa.CreateCredential(u, cer.data, parsed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the passkey couldn't be verified")
		return
	}
	pk, err := s.Auth.AddPasskey(r.Context(), p.User.ID, rp.id, passkeyName(req.Name), cred)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.auditConfig(r, "passkey_added", "", map[string]any{"passkey": pk.ID, "name": pk.Name, "rpId": pk.RPID})
	writeJSON(w, http.StatusCreated, pk)
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principal(r)
	pk, err := s.Auth.RenamePasskey(r.Context(), p.User.ID, r.PathValue("id"), passkeyName(req.Name))
	if errors.Is(err, auth.ErrNoPasskey) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pk)
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	id := r.PathValue("id")
	name, err := s.Auth.DeletePasskey(r.Context(), p.User.ID, id)
	if errors.Is(err, auth.ErrNoPasskey) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "passkey_removed", "", map[string]any{"passkey": id, "name": name})
	w.WriteHeader(http.StatusNoContent)
}

// --- signing in ---------------------------------------------------------

// passkeyLimited answers 429 when the source has too many failed sign-ins.
func passkeyLimited(w http.ResponseWriter, src string) bool {
	if loginFailsBySource.Allow(src) {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(loginFailsBySource.RetryAfter(src).Seconds())+1))
	writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins; try again in a few minutes")
	return true
}

func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if passkeyLimited(w, requestSource(r)) {
		return
	}
	rp, why := relyingPartyFor(r)
	if why != "" {
		writeErr(w, http.StatusBadRequest, why)
		return
	}
	wa, err := rp.webauthn()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "passkeys can't be used at this address: "+err.Error())
		return
	}
	opts, data, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start: "+err.Error())
		return
	}
	id := ceremonies.put(passkeyCeremony{kind: "login", rp: rp, data: *data})
	if id == "" {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-ins in progress; try again in a minute")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": opts})
}

const passkeyLoginFailed = "this passkey isn't registered here, or it couldn't be verified"

func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ceremony string          `json:"ceremony"`
		Device   string          `json:"device"`
		Response json.RawMessage `json:"response"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	src := requestSource(r)
	if passkeyLimited(w, src) {
		return
	}
	rp, why := relyingPartyFor(r)
	cer, ok := ceremonies.take(req.Ceremony)
	if !ok || cer.kind != "login" || why != "" || cer.rp != rp {
		writeErr(w, http.StatusBadRequest, "this sign-in expired or was already used; start again")
		return
	}
	fail := func(msg string) {
		loginFailsBySource.Add(src)
		writeErr(w, http.StatusUnauthorized, msg)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Response))
	if err != nil {
		fail("the browser's answer couldn't be read")
		return
	}
	wa, err := rp.webauthn()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	var user auth.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		owner, err := s.Auth.PasskeyOwner(ctx, rawID)
		if err != nil {
			return nil, errors.New("unknown passkey")
		}
		if string(userHandle) != owner {
			return nil, errors.New("passkey and account don't match")
		}
		u, err := s.Auth.GetUser(ctx, owner)
		if err != nil {
			return nil, err
		}
		user = u
		return s.waUser(ctx, u)
	}
	cred, err := wa.ValidateDiscoverableLogin(handler, cer.data, parsed)
	if err != nil || user.ID == "" {
		fail(passkeyLoginFailed)
		return
	}
	// A signature counter that went backwards means the private key may
	// have been copied; refuse rather than guess.
	if cred.Authenticator.CloneWarning {
		fail("this passkey's signature counter went backwards, which can mean it was copied; sign in with your password and remove it")
		return
	}
	if user.Disabled {
		fail(auth.ErrInvalidCredentials.Error())
		return
	}
	if err := s.Auth.PasskeyUsed(ctx, user.ID, cred); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	loginFailsByAccount.Reset(strings.ToLower(user.Email))
	actor := core.Actor{ID: user.ID, Kind: core.ActorUser, Name: user.Name}
	in, _ := json.Marshal(map[string]any{"email": user.Email, "rpId": rp.id, "credential": auth.CredentialKey(cred.ID)})
	_, _ = s.Engine.Audit.Append(context.WithoutCancel(ctx), core.Entry{Actor: actor, Module: "core", Instance: "auth", Action: "passkey_login", Risk: sdk.RiskWrite, Decision: core.Allow, Status: "ok", Input: in})
	device := req.Device
	if device == "" {
		device = r.UserAgent()
	}
	if len(device) > 180 {
		device = strings.ToValidUTF8(device[:180], "")
	}
	s.startSession(w, r, user, device+" (passkey)", http.StatusOK)
}
