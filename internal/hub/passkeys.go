package hub

// Passkeys (WebAuthn) for hub accounts.
//
// A signed-in person adds passkeys to their account; anyone can then sign in
// with one without typing an email address (discoverable credentials). The
// relying party is the hub's public address (Config.PublicURL): its host name
// is the RP ID and its origin the only accepted origin, so passkeys only work
// when CONDUIT_HUB_URL is exactly the address people open.
//
// Ceremony state (the challenge) lives in memory for five minutes and is
// used once; it doesn't survive a restart, which only means a sign-in that
// was in progress has to start over.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elchi-dev/conduit/internal/auth"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyTTL     = 5 * time.Minute
	maxCeremonies   = 10000
	maxPasskeys     = 20
	passkeyNameSize = 60
)

type ceremony struct {
	data    webauthn.SessionData
	account string // registration: the account adding the passkey
	expires time.Time
}

type passkeyState struct {
	once sync.Once
	wa   *webauthn.WebAuthn
	err  error

	mu         sync.Mutex
	ceremonies map[string]ceremony
}

var passkeyStates sync.Map // *Server -> *passkeyState

func (s *Server) passkeys() (*passkeyState, error) {
	v, _ := passkeyStates.LoadOrStore(s, &passkeyState{ceremonies: map[string]ceremony{}})
	st := v.(*passkeyState)
	st.once.Do(func() {
		u, err := url.Parse(s.cfg.PublicURL)
		if err != nil || u.Host == "" {
			st.err = errors.New("passkeys need CONDUIT_HUB_URL set to this hub's public address")
			return
		}
		st.wa, st.err = webauthn.New(&webauthn.Config{
			RPID:          u.Hostname(),
			RPDisplayName: s.cfg.Name,
			RPOrigins:     []string{u.Scheme + "://" + u.Host},
		})
	})
	return st, st.err
}

func (st *passkeyState) put(c ceremony) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	if len(st.ceremonies) >= maxCeremonies {
		for k, v := range st.ceremonies {
			if now.After(v.expires) {
				delete(st.ceremonies, k)
			}
		}
		if len(st.ceremonies) >= maxCeremonies {
			return ""
		}
	}
	id := token(16)
	c.expires = now.Add(ceremonyTTL)
	st.ceremonies[id] = c
	return id
}

// take returns a ceremony once; a second take of the same id fails.
func (st *passkeyState) take(id string) (ceremony, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.ceremonies[id]
	delete(st.ceremonies, id)
	if !ok || time.Now().After(c.expires) {
		return ceremony{}, false
	}
	return c, true
}

// waUser adapts an account and its passkeys to the library.
type waUser struct {
	id, email, name string
	creds           []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.email }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) waUser(ctx context.Context, accountID string) (*waUser, error) {
	a, err := s.account(ctx, accountID)
	if err != nil {
		return nil, err
	}
	u := &waUser{id: a.ID, email: a.Email, name: a.Name}
	rows, err := s.db.Query(ctx, `SELECT credential FROM passkeys WHERE account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var c webauthn.Credential
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, rows.Err()
}

// Passkey is a stored passkey as listed to its owner.
type Passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, name, created_at, last_used_at FROM passkeys WHERE account_id = ? ORDER BY created_at`, c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list passkeys")
		return
	}
	defer rows.Close()
	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var created string
		var used sql.NullString
		if rows.Scan(&p.ID, &p.Name, &created, &used) != nil {
			continue
		}
		p.CreatedAt = parseTS(created)
		if used.Valid && used.String != "" {
			t := parseTS(used.String)
			p.LastUsedAt = &t
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	if !c.Account.Verified {
		writeErr(w, http.StatusForbidden, "confirm your email address before adding a passkey")
		return
	}
	// A passkey outlives sessions, so adding one needs the password too: a
	// stolen session alone can't plant a way back in.
	var req struct {
		Password string `json:"password"`
	}
	_ = readJSON(r, &req)
	var hash string
	if err := s.db.Row(r.Context(), `SELECT password_hash FROM accounts WHERE id = ?`, c.Account.ID).Scan(&hash); err != nil || !auth.VerifyPassword(hash, req.Password) {
		writeErr(w, http.StatusForbidden, "enter your password to add a passkey")
		return
	}
	st, err := s.passkeys()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	u, err := s.waUser(r.Context(), c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load the account")
		return
	}
	if len(u.creds) >= maxPasskeys {
		writeErr(w, http.StatusConflict, fmt.Sprintf("an account can have at most %d passkeys; remove one first", maxPasskeys))
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, cr := range u.creds {
		exclude = append(exclude, cr.Descriptor())
	}
	opts, data, err := st.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start: "+err.Error())
		return
	}
	id := st.put(ceremony{data: *data, account: c.Account.ID})
	if id == "" {
		writeErr(w, http.StatusServiceUnavailable, "too many passkey requests in progress; try again in a minute")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": opts})
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
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
	st, err := s.passkeys()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	cer, ok := st.take(req.Ceremony)
	if !ok || cer.account != c.Account.ID {
		writeErr(w, http.StatusBadRequest, "this passkey request expired or was already used; start again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Response))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the browser's answer couldn't be read")
		return
	}
	u, err := s.waUser(r.Context(), c.Account.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load the account")
		return
	}
	cred, err := st.wa.CreateCredential(u, cer.data, parsed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the passkey couldn't be verified")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}
	name = truncate(name, passkeyNameSize)
	raw, _ := json.Marshal(cred)
	p := Passkey{ID: newID("pk"), Name: name, CreatedAt: s.now().UTC()}
	if _, err := s.db.Exec(r.Context(), `INSERT INTO passkeys (id, account_id, credential_id, name, credential, created_at) VALUES (?,?,?,?,?,?)`,
		p.ID, c.Account.ID, base64.RawURLEncoding.EncodeToString(cred.ID), p.Name, string(raw), ts(p.CreatedAt)); err != nil {
		writeErr(w, http.StatusConflict, "this passkey is already registered")
		return
	}
	a := c.Account
	go func() {
		_ = s.mail.Send(context.Background(), a.Email, "Passkey added to your "+s.cfg.Name+" account",
			fmt.Sprintf("A passkey named %q was added to your account at %s.\n\nIf this wasn't you, reset your password at %s and remove the passkey.", p.Name, s.now().UTC().Format("2 Jan 2006 15:04 MST"), s.cfg.PublicURL))
	}()
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if !personOnly(w, c) {
		return
	}
	var name string
	if err := s.db.Row(r.Context(), `SELECT name FROM passkeys WHERE id = ? AND account_id = ?`, r.PathValue("id"), c.Account.ID).Scan(&name); err != nil {
		writeErr(w, http.StatusNotFound, "no such passkey")
		return
	}
	if _, err := s.db.Exec(r.Context(), `DELETE FROM passkeys WHERE id = ? AND account_id = ?`, r.PathValue("id"), c.Account.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not remove the passkey")
		return
	}
	a := c.Account
	go func() {
		_ = s.mail.Send(context.Background(), a.Email, "Passkey removed from your "+s.cfg.Name+" account",
			fmt.Sprintf("The passkey named %q was removed from your account at %s.\n\nIf this wasn't you, reset your password at %s.", name, s.now().UTC().Format("2 Jan 2006 15:04 MST"), s.cfg.PublicURL))
	}()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	st, err := s.passkeys()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	opts, data, err := st.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start: "+err.Error())
		return
	}
	id := st.put(ceremony{data: *data})
	if id == "" {
		writeErr(w, http.StatusServiceUnavailable, "too many sign-ins in progress; try again in a minute")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": opts})
}

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
	st, err := s.passkeys()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	cer, ok := st.take(req.Ceremony)
	if !ok || cer.account != "" {
		writeErr(w, http.StatusBadRequest, "this sign-in expired or was already used; start again")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Response))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the browser's answer couldn't be read")
		return
	}
	ctx := r.Context()
	var account string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var owner string
		if err := s.db.Row(ctx, `SELECT account_id FROM passkeys WHERE credential_id = ?`, base64.RawURLEncoding.EncodeToString(rawID)).Scan(&owner); err != nil {
			return nil, errors.New("unknown passkey")
		}
		if string(userHandle) != owner {
			return nil, errors.New("passkey and account don't match")
		}
		account = owner
		return s.waUser(ctx, owner)
	}
	cred, err := st.wa.ValidateDiscoverableLogin(handler, cer.data, parsed)
	if err != nil || account == "" {
		writeErr(w, http.StatusUnauthorized, "this passkey isn't registered on this hub, or it couldn't be verified")
		return
	}
	// A signature counter that went backwards means the private key may
	// have been copied; refuse rather than guess.
	if cred.Authenticator.CloneWarning {
		writeErr(w, http.StatusUnauthorized, "this passkey's signature counter went backwards, which can mean it was copied; sign in with your password and remove it")
		return
	}
	raw, _ := json.Marshal(cred)
	_, _ = s.db.Exec(ctx, `UPDATE passkeys SET credential = ?, last_used_at = ? WHERE credential_id = ? AND account_id = ?`,
		string(raw), ts(s.now()), base64.RawURLEncoding.EncodeToString(cred.ID), account)
	device := req.Device
	if device == "" {
		device = r.UserAgent()
	}
	s.issueSession(w, r, account, truncate(device, 180)+" (passkey)")
}
