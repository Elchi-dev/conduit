// Package keycloak works with a Keycloak server through its admin REST API,
// signed in as a confidential client with a service account (client
// credentials): realms, users and their counts, sessions, disabling and
// enabling a user, ending a user's sessions, and clients (never their
// secrets).
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Keycloak server and the client Conduit signs in as.
type Config struct {
	Address            string `json:"address"`      // e.g. https://sso.example.com (or …/auth on old versions)
	Realm              string `json:"realm"`        // realm to manage by default
	AuthRealm          string `json:"authRealm"`    // realm the client lives in; the realm when empty
	ClientID           string `json:"clientId"`     // confidential client with a service account
	ClientSecret       string `json:"clientSecret"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client // admin API, with the access token
	auth  *rest.Client // token endpoint, no auth
	realm string
	token tokenSource
}

type tokenSource struct {
	mu      sync.Mutex
	access  string
	expires time.Time
	fetch   func(ctx context.Context) (string, time.Duration, error)
	now     func() time.Time
}

func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.access != "" && t.now().Before(t.expires) {
		return t.access, nil
	}
	tok, ttl, err := t.fetch(ctx)
	if err != nil {
		t.access = ""
		return "", err
	}
	// Renew a little before Keycloak's expiry.
	if ttl > 60*time.Second {
		ttl -= 30 * time.Second
	}
	t.access, t.expires = tok, t.now().Add(ttl)
	return tok, nil
}

func (t *tokenSource) drop() {
	t.mu.Lock()
	t.access = ""
	t.mu.Unlock()
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Keycloak module.
func New() *Module { return &Module{} }

var (
	realmRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:/@-]{1,255}$`)
	idRe       = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	prefixRe   = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
)

func validRealm(s string) bool { return realmRe.MatchString(s) && s != "." && s != ".." }

// ErrToken is returned when Keycloak refuses the client credentials.
var ErrToken = errors.New("Keycloak refused the client credentials (check the client ID, its secret and that the client has service accounts enabled)")

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	realm := `"realm":{"type":"string","description":"Realm (the instance's when empty)"}`
	user := `"user":{"type":"string","description":"User ID or exact username"}`
	return sdk.Manifest{
		ID: "keycloak", Name: "Keycloak", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Keycloak: realms, users and counts, sessions, disabling or enabling a user, signing a user out everywhere, clients (never their secrets).",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","realm","clientId","clientSecret"],"properties":{
			"address":{"type":"string","description":"Keycloak's address, e.g. https://sso.example.com (add /auth for versions before 17)"},
			"realm":{"type":"string","description":"Realm to manage by default"},
			"authRealm":{"type":"string","description":"Realm the client is in, e.g. master; the realm above when empty"},
			"clientId":{"type":"string","description":"A confidential client with service accounts enabled, whose service account has realm-management roles (view-users, view-clients, view-realm; manage-users for disabling and signing out)"},
			"clientSecret":{"type":"string","x-secret":true,"description":"The client's secret (Credentials tab)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "realms", Title: "Realms", Description: "Realms the service account can see, with display name and whether they're enabled.", Risk: sdk.RiskRead},
			{Name: "users", Title: "Users", Description: "How many users a realm has (matching a search) and, unless countOnly, a page of them with username, email, name, enabled and verified.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + realm + `,"search":{"type":"string","description":"Matches username, email, first or last name"},"first":{"type":"integer","minimum":0,"default":0},"max":{"type":"integer","minimum":1,"maximum":100,"default":50},"countOnly":{"type":"boolean"}}}`)},
			{Name: "sessions", Title: "Sessions", Description: "Active and offline sessions per client in a realm, with totals; or the sessions of one user (start, last access, clients, never IP addresses).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + realm + `,` + user + `}}`)},
			{Name: "disable_user", Title: "Disable a user", Description: "Turns a user off so they can't sign in. The preview shows their sessions, which keep working until they expire or are ended with logout_user. Undo enables them again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + realm + `,` + user + `}}`)},
			{Name: "enable_user", Title: "Enable a user", Description: "Turns a disabled user back on, which lets them sign in again. Undo disables them.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + realm + `,` + user + `}}`)},
			{Name: "logout_user", Title: "Sign a user out everywhere", Description: "Ends every session of a user in the realm (their tokens can't be refreshed). The preview counts the sessions.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{` + realm + `,` + user + `}}`)},
			{Name: "clients", Title: "Clients", Description: "Clients of a realm: client ID, name, protocol, public or confidential, enabled, service account, redirect URIs. Never secrets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + realm + `,"search":{"type":"string","description":"Client IDs containing this"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is like https://sso.example.com")
	}
	realm := strings.TrimSpace(c.Realm)
	if !validRealm(realm) {
		return errors.New("the realm is its name, like master")
	}
	authRealm := strings.TrimSpace(c.AuthRealm)
	if authRealm == "" {
		authRealm = realm
	}
	if !validRealm(authRealm) {
		return errors.New("the client's realm is its name, like master")
	}
	clientID := strings.TrimSpace(c.ClientID)
	if !clientIDRe.MatchString(clientID) {
		return errors.New("enter the client ID")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + prefix
	cn := &conn{realm: realm, auth: rest.New(base, nil)}
	cn.auth.HTTP = client
	secretRef := c.ClientSecret
	cn.token = tokenSource{now: time.Now, fetch: func(ctx context.Context) (string, time.Duration, error) {
		sec, err := h.Secret(ctx, secretRef)
		if err != nil {
			return "", 0, err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {strings.TrimSpace(sec)}}
		res, err := cn.auth.Send(ctx, http.MethodPost, "/realms/"+url.PathEscape(authRealm)+"/protocol/openid-connect/token", nil, strings.NewReader(form.Encode()),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) {
			return "", 0, ErrToken
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", 0, fmt.Errorf("there's no realm %s at this address (Keycloak before 17 needs /auth in the address)", authRealm)
		}
		if err != nil {
			return "", 0, err
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			return "", 0, fmt.Errorf("Keycloak answered %s to the sign-in", res.Status)
		}
		var t struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if json.Unmarshal(b, &t) != nil || t.AccessToken == "" {
			return "", 0, errors.New("unexpected sign-in answer from Keycloak")
		}
		ttl := time.Duration(t.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = time.Minute
		}
		return t.AccessToken, ttl, nil
	}}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token.get(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case errors.Is(err, ErrToken):
		return err
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Keycloak refused: the service account lacks the role for this (realm-management roles such as view-users or manage-users)")
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Keycloak refused the access token")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

// do calls the admin API, signing in again once if the token was refused.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.token.drop()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var realms []struct {
		Realm string `json:"realm"`
	}
	if err := c.do(ctx, http.MethodGet, "/admin/realms", url.Values{"briefRepresentation": {"true"}}, nil, &realms); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "admin API").Error()}
	}
	for _, r := range realms {
		if r.Realm == c.realm {
			return sdk.Health{Status: "ok", Message: fmt.Sprintf("signed in · %d realm(s) visible", len(realms))}
		}
	}
	return sdk.Health{Status: "degraded", Message: "signed in, but the service account can't see realm " + c.realm}
}

type input struct {
	Realm     string `json:"realm"`
	Search    string `json:"search"`
	First     int    `json:"first"`
	Max       int    `json:"max"`
	CountOnly bool   `json:"countOnly"`
	User      string `json:"user"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func text(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

type user struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Enabled       bool   `json:"enabled"`
	EmailVerified bool   `json:"emailVerified"`
	Created       int64  `json:"createdTimestamp"`
	FederationURL string `json:"federationLink"`
}

func (u user) summary() map[string]any {
	e := map[string]any{"id": u.ID, "username": u.Username, "email": u.Email, "firstName": u.FirstName, "lastName": u.LastName, "enabled": u.Enabled, "emailVerified": u.EmailVerified, "created": when(u.Created)}
	if u.FederationURL != "" {
		e["federated"] = true
	}
	return e
}

func (c *conn) realmPath(s string) (string, string, error) {
	r := strings.TrimSpace(s)
	if r == "" {
		r = c.realm
	}
	if !validRealm(r) {
		return "", "", fmt.Errorf("%q isn't a realm name", r)
	}
	return r, "/admin/realms/" + url.PathEscape(r), nil
}

// findUser resolves a user ID or exact username to one user.
func (c *conn) findUser(ctx context.Context, base, raw string) (user, error) {
	var u user
	s := strings.TrimSpace(raw)
	if s == "" || !text(s, 255) {
		return u, errors.New("the user is their ID or exact username")
	}
	if uuidRe.MatchString(s) {
		err := c.do(ctx, http.MethodGet, base+"/users/"+strings.ToLower(s), nil, nil, &u)
		if err == nil {
			if !strings.EqualFold(u.ID, s) {
				return u, errors.New("unexpected user from Keycloak")
			}
			return u, nil
		}
		if !rest.IsStatus(err, http.StatusNotFound) {
			return u, friendly(err, "user")
		}
	}
	var us []user
	if err := c.do(ctx, http.MethodGet, base+"/users", url.Values{"username": {s}, "exact": {"true"}}, nil, &us); err != nil {
		return u, friendly(err, "user")
	}
	var match []user
	for _, x := range us {
		if strings.EqualFold(x.Username, s) {
			match = append(match, x)
		}
	}
	switch {
	case len(match) == 0:
		return u, fmt.Errorf("there's no user %s", s)
	case len(match) > 1:
		return u, fmt.Errorf("%d users are called %s; give the ID", len(match), s)
	}
	if !idRe.MatchString(match[0].ID) {
		return u, errors.New("unexpected user ID from Keycloak")
	}
	return match[0], nil
}

type session struct {
	ID         string            `json:"id"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	Clients    map[string]string `json:"clients"`
	RememberMe bool              `json:"rememberMe"`
}

func (c *conn) userSessions(ctx context.Context, base string, u user) ([]session, error) {
	var ss []session
	if err := c.do(ctx, http.MethodGet, base+"/users/"+u.ID+"/sessions", nil, nil, &ss); err != nil {
		return nil, friendly(err, "user")
	}
	return ss, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "realms" {
		var realms []struct {
			Realm       string `json:"realm"`
			DisplayName string `json:"displayName"`
			Enabled     bool   `json:"enabled"`
		}
		if err := c.do(ctx, http.MethodGet, "/admin/realms", url.Values{"briefRepresentation": {"true"}}, nil, &realms); err != nil {
			return sdk.Result{}, friendly(err, "realm")
		}
		out := []map[string]any{}
		for _, r := range realms {
			out = append(out, map[string]any{"realm": r.Realm, "displayName": r.DisplayName, "enabled": r.Enabled})
		}
		return sdk.JSON(out)
	}
	realm, base, err := c.realmPath(p.Realm)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "users":
		if !text(p.Search, 200) {
			return sdk.Result{}, errors.New("the search is up to 200 characters of text")
		}
		limit := p.Max
		if limit == 0 {
			limit = 50
		}
		if limit < 1 || limit > 100 || p.First < 0 {
			return sdk.Result{}, errors.New("max is between 1 and 100, first 0 or more")
		}
		q := url.Values{}
		if s := strings.TrimSpace(p.Search); s != "" {
			q.Set("search", s)
		}
		var count int
		if err := c.do(ctx, http.MethodGet, base+"/users/count", q, nil, &count); err != nil {
			return sdk.Result{}, friendly(err, "realm "+realm)
		}
		out := map[string]any{"realm": realm, "count": count}
		if !p.CountOnly {
			q.Set("first", fmt.Sprint(p.First))
			q.Set("max", fmt.Sprint(limit))
			q.Set("briefRepresentation", "true")
			var us []user
			if err := c.do(ctx, http.MethodGet, base+"/users", q, nil, &us); err != nil {
				return sdk.Result{}, friendly(err, "realm "+realm)
			}
			list := []map[string]any{}
			for _, u := range us {
				list = append(list, u.summary())
			}
			out["users"] = list
			out["first"] = p.First
		}
		return sdk.JSON(out)

	case "sessions":
		if strings.TrimSpace(p.User) != "" {
			u, err := c.findUser(ctx, base, p.User)
			if err != nil {
				return sdk.Result{}, err
			}
			ss, err := c.userSessions(ctx, base, u)
			if err != nil {
				return sdk.Result{}, err
			}
			list := []map[string]any{}
			for _, s := range ss {
				var clients []string
				for _, name := range s.Clients {
					clients = append(clients, name)
				}
				list = append(list, map[string]any{"started": when(s.Start), "lastAccess": when(s.LastAccess), "clients": clients, "rememberMe": s.RememberMe})
			}
			return sdk.JSON(map[string]any{"realm": realm, "user": u.Username, "sessions": len(ss), "list": list})
		}
		var stats []struct {
			ClientID string `json:"clientId"`
			Active   any    `json:"active"`
			Offline  any    `json:"offline"`
		}
		if err := c.do(ctx, http.MethodGet, base+"/client-session-stats", nil, nil, &stats); err != nil {
			return sdk.Result{}, friendly(err, "realm "+realm)
		}
		active, offline := 0, 0
		per := []map[string]any{}
		for _, s := range stats {
			a, o := num(s.Active), num(s.Offline)
			active += a
			offline += o
			per = append(per, map[string]any{"client": s.ClientID, "active": a, "offline": o})
		}
		return sdk.JSON(map[string]any{"realm": realm, "active": active, "offline": offline, "clients": per,
			"note": "client sessions: one person signed in to two clients counts twice"})

	case "disable_user":
		return c.setEnabled(ctx, call, realm, base, p.User, false)
	case "enable_user":
		return c.setEnabled(ctx, call, realm, base, p.User, true)

	case "logout_user":
		u, err := c.findUser(ctx, base, p.User)
		if err != nil {
			return sdk.Result{}, err
		}
		ss, err := c.userSessions(ctx, base, u)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("End all %d session(s) of %s in %s; they have to sign in again everywhere (access tokens already issued last until they expire)", len(ss), u.Username, realm),
				Changes: []sdk.Change{{Target: "user " + u.Username, Op: "logout", Before: mustJSON(map[string]any{"sessions": len(ss)}), After: mustJSON(map[string]any{"sessions": 0})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, base+"/users/"+u.ID+"/logout", nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "user")
		}
		return sdk.JSON(map[string]any{"realm": realm, "user": u.Username, "sessionsEnded": len(ss)})

	case "clients":
		s := strings.TrimSpace(p.Search)
		if s != "" && !clientIDRe.MatchString(s) {
			return sdk.Result{}, errors.New("the search is part of a client ID")
		}
		q := url.Values{"first": {"0"}, "max": {"200"}}
		if s != "" {
			q.Set("clientId", s)
			q.Set("search", "true")
		}
		var cs []struct {
			ID                     string   `json:"id"`
			ClientID               string   `json:"clientId"`
			Name                   string   `json:"name"`
			Protocol               string   `json:"protocol"`
			Enabled                bool     `json:"enabled"`
			PublicClient           bool     `json:"publicClient"`
			BearerOnly             bool     `json:"bearerOnly"`
			ServiceAccountsEnabled bool     `json:"serviceAccountsEnabled"`
			StandardFlowEnabled    bool     `json:"standardFlowEnabled"`
			RootURL                string   `json:"rootUrl"`
			RedirectURIs           []string `json:"redirectUris"`
			ClientAuthenticator    string   `json:"clientAuthenticatorType"`
		}
		if err := c.do(ctx, http.MethodGet, base+"/clients", q, nil, &cs); err != nil {
			return sdk.Result{}, friendly(err, "realm "+realm)
		}
		out := []map[string]any{}
		for _, cl := range cs {
			kind := "confidential"
			switch {
			case cl.PublicClient:
				kind = "public"
			case cl.BearerOnly:
				kind = "bearer-only"
			}
			out = append(out, map[string]any{"id": cl.ID, "clientId": cl.ClientID, "name": cl.Name, "protocol": cl.Protocol, "enabled": cl.Enabled, "type": kind,
				"serviceAccount": cl.ServiceAccountsEnabled, "standardFlow": cl.StandardFlowEnabled, "rootUrl": cl.RootURL, "redirectUris": cl.RedirectURIs, "authenticator": cl.ClientAuthenticator})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// num reads Keycloak's session counts, which come as strings or numbers.
func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		var n int
		fmt.Sscan(x, &n)
		return n
	}
	return 0
}

func (c *conn) setEnabled(ctx context.Context, call sdk.Call, realm, base, raw string, enabled bool) (sdk.Result, error) {
	u, err := c.findUser(ctx, base, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	verb, undo := "Disable", "enable_user"
	if enabled {
		verb, undo = "Enable", "disable_user"
	}
	if u.Enabled == enabled {
		return sdk.JSON(map[string]any{"realm": realm, "user": u.Username, "enabled": enabled, "note": "nothing to do; it already is"})
	}
	if call.DryRun {
		sum := fmt.Sprintf("%s %s (%s) in %s", verb, u.Username, u.Email, realm)
		if enabled {
			sum += "; they can sign in again"
		} else {
			ss, err := c.userSessions(ctx, base, u)
			if err != nil {
				return sdk.Result{}, err
			}
			sum += fmt.Sprintf("; they can't sign in. Their %d session(s) aren't ended (use logout_user)", len(ss))
		}
		if u.FederationURL != "" {
			sum += "; the user comes from a federated directory, which may set it back"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "user " + u.Username, Op: "update", Before: mustJSON(map[string]any{"enabled": u.Enabled}), After: mustJSON(map[string]any{"enabled": enabled})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPut, base+"/users/"+u.ID, nil, map[string]any{"enabled": enabled}, nil); err != nil {
		return sdk.Result{}, friendly(err, "user")
	}
	res, err := sdk.JSON(map[string]any{"realm": realm, "user": u.Username, "enabled": enabled})
	back := "Disable"
	if !enabled {
		back = "Enable"
	}
	res.Undo = sdk.UndoWith(undo, map[string]any{"realm": realm, "user": u.ID}, back+" "+u.Username+" again")
	return res, err
}
