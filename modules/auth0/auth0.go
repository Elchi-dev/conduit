// Package auth0 works with an Auth0 tenant through the Management API, with
// a machine-to-machine application's client credentials: users, applications
// (never their secrets or keys), the tenant's logs, and blocking and
// unblocking users.
package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Auth0 tenant.
type Config struct {
	Domain       string `json:"domain"`       // e.g. acme.eu.auth0.com
	ClientID     string `json:"clientId"`     // the machine-to-machine application's client id
	ClientSecret string `json:"clientSecret"` // secret:// its client secret
	AllowAdmins  bool   `json:"allowAdmins"`
}

type conn struct {
	api         *rest.Client
	domain      string
	allowAdmins bool
	cache       oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<domain> (tests).
	Base string
}

// New returns the Auth0 module.
func New() *Module { return &Module{} }

var (
	// tenant, tenant.eu, tenant.us, tenant.au, tenant.jp, tenant.uk, ...
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2}[0-9]?)?\.auth0\.com$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	userIDRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}\|[A-Za-z0-9_.@:+|=-]{1,200}$`)
	emailRe    = regexp.MustCompile(`^[^\s@"\\/]{1,128}@[^\s@"\\/]{1,125}$`)
	searchRe   = regexp.MustCompile(`^[\p{L}\p{N}@._+-]{1,100}$`)
	logTypeRe  = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	adminRole  = regexp.MustCompile(`(?i)admin|owner|super`)
	logTypes   = map[string]string{"s": "login", "f": "failed login", "fp": "wrong password", "fu": "wrong username", "slo": "logout", "flo": "failed logout",
		"ss": "signup", "fs": "failed signup", "scp": "password changed", "fcp": "failed password change", "limit_wc": "IP blocked", "limit_mu": "IP blocked (many users)",
		"seacft": "token exchange", "feacft": "failed token exchange", "sapi": "management API change", "fapi": "failed management API call", "du": "user deleted",
		"gd_auth_succeed": "MFA success", "gd_auth_failed": "MFA failed", "pwd_leak": "breached password", "sv": "email verified", "w": "warning"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","properties":{"user":{"type":"string","description":"User id like auth0|abc123 (from users)"},"email":{"type":"string","description":"Or the user's email, when exactly one user has it"}}}`
	return sdk.Manifest{
		ID: "auth0", Name: "Auth0", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Auth0: users, applications and the tenant's logs; block and unblock users.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["domain","clientId","clientSecret"],"properties":{
			"domain":{"type":"string","description":"The tenant's Auth0 domain, e.g. acme.eu.auth0.com (not a custom domain)"},
			"clientId":{"type":"string","description":"Client id of a machine-to-machine application authorized for the Auth0 Management API"},
			"clientSecret":{"type":"string","x-secret":true,"description":"That application's client secret. Grant it read:users, read:clients, read:logs, read:roles, and update:users to block and unblock"},
			"allowAdmins":{"type":"boolean","default":false,"description":"Let Conduit block users that hold an admin, owner or super role (off: refused)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "users", Title: "Users", Description: "Total and a list with id, name, nickname, blocked, logins, last login, created and connections. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Start of a name, nickname or email"},"blocked":{"type":"boolean","description":"Only blocked users"},
					"includeEmail":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":1,"maximum":1000}}}`)},
			{Name: "clients", Title: "Applications", Description: "Applications with client id, type, first party, grant types, auth method, callbacks and allowed origins. Never client secrets or signing keys.", Risk: sdk.RiskRead},
			{Name: "logs", Title: "Logs", Description: "The tenant's log, newest first: logins, failures, signups, API changes, with user, IP and application. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","description":"Only this event code, e.g. s (login), f (failed login), fp, fu, slo, sapi, limit_wc"},
					"user":{"type":"string","description":"Only this user's events (user id)"},"limit":{"type":"integer","default":30,"minimum":1,"maximum":100}}}`)},
			{Name: "block_user", Title: "Block a user", Description: "Stops a user signing in; the account stays. Refused for admins unless allowed. Undo unblocks.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "unblock_user", Title: "Unblock a user", Description: "Lets a blocked user sign in again. Undo blocks them.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
		},
	}
}

// tenantDomain checks an Auth0 domain and returns it lowercase.
func tenantDomain(s string) (string, error) {
	bad := errors.New("the domain is the tenant's Auth0 domain, like acme.eu.auth0.com")
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() != "" || (u.Path != "" && u.Path != "/" && u.Path != "/api/v2" && u.Path != "/api/v2/") {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if !domainRe.MatchString(host) {
		return "", bad
	}
	return host, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	domain, err := tenantDomain(c.Domain)
	if err != nil {
		return err
	}
	c.ClientID = strings.TrimSpace(c.ClientID)
	if !clientIDRe.MatchString(c.ClientID) {
		return errors.New("the client id is the application's Client ID (letters and digits)")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base := "https://" + domain
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	cn := &conn{domain: domain, allowAdmins: c.AllowAdmins}
	ref, clientID := c.ClientSecret, c.ClientID
	audience := "https://" + domain + "/api/v2/"
	fetch := func(ctx context.Context) (oauth.Grant, error) {
		sec, err := h.Secret(ctx, ref)
		if err != nil {
			return oauth.Grant{}, err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {strings.TrimSpace(sec)}, "audience": {audience}}
		return oauth.Exchange(ctx, client, base+"/oauth/token", form, "", "")
	}
	cn.api = rest.New(base+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := cn.cache.Get(ctx, fetch)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	var oe *oauth.Error
	switch {
	case errors.As(err, &oe):
		if oe.Code != "" {
			return fmt.Errorf("Auth0 refused the client credentials (%s)", oe.Code)
		}
		return fmt.Errorf("Auth0 refused the client credentials (HTTP %d)", oe.Status)
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Auth0 refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the application lacks the Management API scope for this (Applications, APIs, Auth0 Management API, Machine to Machine Applications)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Auth0's rate limit was reached; try again in a minute")
	}
	return err
}

// do calls the Management API, getting a new token once if it was refused.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.cache.Drop()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		FriendlyName string `json:"friendly_name"`
	}
	err = c.do(ctx, http.MethodGet, "/tenants/settings", url.Values{"fields": {"friendly_name"}, "include_fields": {"true"}}, nil, &s)
	switch {
	case err == nil:
		name := s.FriendlyName
		if name == "" {
			name = c.domain
		}
		return sdk.Health{Status: "ok", Message: "tenant " + name}
	case strings.HasPrefix(err.Error(), "the application lacks"):
		// Signed in, but may not read tenant settings: that's fine.
		return sdk.Health{Status: "ok", Message: "signed in to " + c.domain}
	case rest.IsStatus(err, http.StatusNotFound):
		return sdk.Health{Status: "down", Message: "no Auth0 Management API at this domain"}
	}
	return sdk.Health{Status: "down", Message: err.Error()}
}

type input struct {
	Search       string `json:"search"`
	Blocked      *bool  `json:"blocked"`
	IncludeEmail bool   `json:"includeEmail"`
	Limit        *int   `json:"limit"`
	Type         string `json:"type"`
	User         string `json:"user"`
	Email        string `json:"email"`
}

// lucene escapes a search term's reserved characters (the allowed set has
// only these three).
func lucene(s string) string {
	return strings.NewReplacer("+", `\+`, "-", `\-`, "=", `\=`).Replace(s)
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
	switch call.Action {
	case "users":
		return c.users(ctx, p)
	case "clients":
		return c.clients(ctx)
	case "logs":
		return c.logs(ctx, p)
	case "block_user", "unblock_user":
		return c.setBlocked(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type identity struct {
	Provider   string `json:"provider"`
	Connection string `json:"connection"`
	IsSocial   bool   `json:"isSocial"`
	// access_token and refresh_token (social connections) aren't decoded.
}

type user struct {
	UserID      string     `json:"user_id"`
	Name        string     `json:"name"`
	Nickname    string     `json:"nickname"`
	Email       string     `json:"email"`
	Verified    bool       `json:"email_verified"`
	Blocked     bool       `json:"blocked"`
	LastLogin   string     `json:"last_login"`
	LoginsCount int        `json:"logins_count"`
	CreatedAt   string     `json:"created_at"`
	Identities  []identity `json:"identities"`
}

const userFields = "user_id,name,nickname,email,email_verified,blocked,last_login,logins_count,created_at,identities"

func (u user) label() string {
	if u.Name != "" {
		return u.Name
	}
	return u.UserID
}

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	limit := 50
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 1000 {
		return sdk.Result{}, errors.New("limit is 1 to 1000 (Auth0 lists at most 1000)")
	}
	var terms []string
	if s := strings.TrimSpace(p.Search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("the search is one word of letters, digits and @ . _ + - (at most 100)")
		}
		e := lucene(s)
		terms = append(terms, "(name:"+e+"* OR nickname:"+e+"* OR email:"+e+"*)")
	}
	if p.Blocked != nil {
		terms = append(terms, "blocked:"+strconv.FormatBool(*p.Blocked))
	}
	q := url.Values{"fields": {userFields}, "include_fields": {"true"}, "include_totals": {"true"}, "search_engine": {"v3"}, "sort": {"created_at:1"}}
	if len(terms) > 0 {
		q.Set("q", strings.Join(terms, " AND "))
	}
	per := min(limit, 100)
	q.Set("per_page", strconv.Itoa(per))
	var all []user
	total := 0
	for pg := 0; len(all) < limit && pg*per < 1000; pg++ {
		q.Set("page", strconv.Itoa(pg))
		var res struct {
			Total int    `json:"total"`
			Users []user `json:"users"`
		}
		if err := c.do(ctx, http.MethodGet, "/users", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		total = res.Total
		all = append(all, res.Users...)
		if len(res.Users) < per {
			break
		}
	}
	if len(all) > limit {
		all = all[:limit]
	}
	out := []map[string]any{}
	for _, u := range all {
		row := map[string]any{"id": u.UserID, "name": u.Name, "nickname": u.Nickname, "blocked": u.Blocked, "logins": u.LoginsCount, "lastLogin": u.LastLogin, "created": u.CreatedAt}
		var conns []string
		for _, i := range u.Identities {
			conns = append(conns, i.Connection)
		}
		row["connections"] = conns
		if p.IncludeEmail {
			row["email"], row["emailVerified"] = u.Email, u.Verified
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": total, "users": out})
}

// clients lists applications, asking only for harmless fields and decoding
// them one by one: client secrets, signing keys and encryption keys are
// never requested or read.
func (c *conn) clients(ctx context.Context) (sdk.Result, error) {
	q := url.Values{"fields": {"client_id,name,description,app_type,is_first_party,callbacks,allowed_origins,grant_types,token_endpoint_auth_method"},
		"include_fields": {"true"}, "include_totals": {"true"}, "per_page": {"100"}}
	out := []map[string]any{}
	for pg := 0; pg < 20; pg++ {
		q.Set("page", strconv.Itoa(pg))
		var res struct {
			Total   int `json:"total"`
			Clients []struct {
				ClientID    string   `json:"client_id"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				AppType     string   `json:"app_type"`
				FirstParty  bool     `json:"is_first_party"`
				Callbacks   []string `json:"callbacks"`
				Origins     []string `json:"allowed_origins"`
				GrantTypes  []string `json:"grant_types"`
				AuthMethod  string   `json:"token_endpoint_auth_method"`
			} `json:"clients"`
		}
		if err := c.do(ctx, http.MethodGet, "/clients", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		for _, a := range res.Clients {
			row := map[string]any{"clientId": a.ClientID, "name": a.Name, "type": a.AppType, "firstParty": a.FirstParty, "grantTypes": a.GrantTypes, "authMethod": a.AuthMethod}
			if a.Description != "" {
				row["description"] = a.Description
			}
			if len(a.Callbacks) > 0 {
				row["callbacks"] = a.Callbacks
			}
			if len(a.Origins) > 0 {
				row["allowedOrigins"] = a.Origins
			}
			out = append(out, row)
		}
		if len(res.Clients) < 100 {
			break
		}
	}
	return sdk.JSON(map[string]any{"count": len(out), "clients": out})
}

func (c *conn) logs(ctx context.Context, p input) (sdk.Result, error) {
	limit := 30
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 100 {
		return sdk.Result{}, errors.New("limit is 1 to 100")
	}
	var terms []string
	if t := strings.TrimSpace(p.Type); t != "" {
		if !logTypeRe.MatchString(t) {
			return sdk.Result{}, errors.New("the type is an event code like s, f, fp or limit_wc")
		}
		terms = append(terms, "type:"+t)
	}
	if u := strings.TrimSpace(p.User); u != "" {
		if !userIDRe.MatchString(u) {
			return sdk.Result{}, errors.New("the user is a user id like auth0|abc123 (from users)")
		}
		terms = append(terms, `user_id:"`+u+`"`) // the pattern has no quotes or backslashes
	}
	q := url.Values{"per_page": {strconv.Itoa(limit)}, "page": {"0"}, "sort": {"date:-1"},
		"fields": {"date,type,description,client_name,user_name,user_id,ip,connection"}, "include_fields": {"true"}}
	if len(terms) > 0 {
		q.Set("q", strings.Join(terms, " AND "))
	}
	var res []struct {
		Date        string `json:"date"`
		Type        string `json:"type"`
		Description string `json:"description"`
		ClientName  string `json:"client_name"`
		UserName    string `json:"user_name"`
		UserID      string `json:"user_id"`
		IP          string `json:"ip"`
		Connection  string `json:"connection"`
		// details (request bodies, headers) isn't decoded.
	}
	if err := c.do(ctx, http.MethodGet, "/logs", q, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range res {
		row := map[string]any{"date": e.Date, "type": e.Type, "ip": e.IP}
		if k, ok := logTypes[e.Type]; ok {
			row["kind"] = k
		}
		for k, v := range map[string]string{"description": e.Description, "application": e.ClientName, "user": e.UserName, "userId": e.UserID, "connection": e.Connection} {
			if v != "" {
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"events": out})
}

// target checks the input, then finds the user and refuses admins unless
// allowed. The token's own identity is an application, never a user, so it
// can't be a target.
func (c *conn) target(ctx context.Context, p input) (user, error) {
	id, email := strings.TrimSpace(p.User), strings.TrimSpace(p.Email)
	q := url.Values{"fields": {userFields}, "include_fields": {"true"}}
	var u user
	switch {
	case id != "":
		if !userIDRe.MatchString(id) {
			return u, errors.New("the user is a user id like auth0|abc123 (from users)")
		}
		if err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), q, nil, &u); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return u, fmt.Errorf("there's no user %s", id)
			}
			return u, err
		}
	case email != "":
		if !emailRe.MatchString(email) {
			return u, errors.New("that isn't an email address")
		}
		q.Set("email", email)
		var us []user
		if err := c.do(ctx, http.MethodGet, "/users-by-email", q, nil, &us); err != nil {
			return u, err
		}
		switch len(us) {
		case 0:
			return u, fmt.Errorf("there's no user with the email %s", email)
		case 1:
			u = us[0]
		default:
			return u, fmt.Errorf("%d users have this email (one per connection); give the user id", len(us))
		}
	default:
		return u, errors.New("enter the user's id or email")
	}
	if !userIDRe.MatchString(u.UserID) {
		return u, errors.New("Auth0 answered with an unusable user id")
	}
	if !c.allowAdmins {
		var roles []struct {
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(u.UserID)+"/roles", url.Values{"per_page": {"100"}}, nil, &roles); err != nil {
			return u, fmt.Errorf("couldn't check whether %s is an admin (%v); refused", u.label(), err)
		}
		for _, r := range roles {
			if adminRole.MatchString(r.Name) {
				return u, fmt.Errorf("%s has the role %q; turn on allowAdmins in the settings to act on admins", u.label(), r.Name)
			}
		}
	}
	return u, nil
}

func (c *conn) setBlocked(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	blocking := call.Action == "block_user"
	u, err := c.target(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if u.Blocked == blocking {
		return sdk.JSON(map[string]any{"id": u.UserID, "name": u.Name, "blocked": u.Blocked, "note": "nothing to change"})
	}
	verb, back, undo := "Block", "unblock_user", "Unblock "+u.label()
	if !blocking {
		verb, back, undo = "Unblock", "block_user", "Block "+u.label()+" again"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]bool{"blocked": u.Blocked})
		a, _ := json.Marshal(map[string]bool{"blocked": blocking})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + u.label(), Changes: []sdk.Change{{Target: "user " + u.label() + " (" + u.UserID + ")", Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if err := c.do(ctx, http.MethodPatch, "/users/"+url.PathEscape(u.UserID), nil, map[string]bool{"blocked": blocking}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": u.UserID, "name": u.Name, "blocked": blocking})
	res.Undo = sdk.UndoWith(back, map[string]string{"user": u.UserID}, undo)
	return res, err
}
