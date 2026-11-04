// Package okta works with an Okta organization through an API token: users
// (counts and the list), groups, applications (never their credentials),
// suspending and unsuspending users, and ending a user's sessions.
package okta

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Okta organization.
type Config struct {
	OrgURL      string `json:"orgUrl"` // e.g. https://acme.okta.com
	Token       string `json:"token"`  // secret:// API token
	AllowAdmins bool   `json:"allowAdmins"`
}

type conn struct {
	api         *rest.Client
	org         string
	allowAdmins bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<org>.okta.com (tests).
	Base string
}

// New returns the Okta module.
func New() *Module { return &Module{} }

var (
	labelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9]{6,40}$`)
	loginRe  = regexp.MustCompile(`^[^\s/\\?#%]{1,200}$`)
	cursorRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,200}$`)
	statuses = map[string]bool{"STAGED": true, "PROVISIONED": true, "ACTIVE": true, "RECOVERY": true, "PASSWORD_EXPIRED": true, "LOCKED_OUT": true, "SUSPENDED": true, "DEPROVISIONED": true}
	// The vendor domains an Okta organization lives under.
	vendorDomains = []string{".okta.com", ".oktapreview.com", ".okta-emea.com"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","required":["user"],"properties":{"user":{"type":"string","description":"User id (from users) or exact login"}}}`
	return sdk.Manifest{
		ID: "okta", Name: "Okta", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Okta: users, groups and applications; suspend and unsuspend users and end their sessions.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["orgUrl","token"],"properties":{
			"orgUrl":{"type":"string","description":"Your Okta organization, e.g. https://acme.okta.com (okta.com, oktapreview.com or okta-emea.com)"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Security, API, Tokens). It acts with the permissions of the admin who created it"},
			"allowAdmins":{"type":"boolean","default":false,"description":"Let Conduit suspend users that hold an admin role or end their sessions (off: refused)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "users", Title: "Users", Description: "Users with id, login, name, status, created, last login and last status change. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Start of a first name, last name, login or email"},
					"status":{"type":"string","enum":["STAGED","PROVISIONED","ACTIVE","RECOVERY","PASSWORD_EXPIRED","LOCKED_OUT","SUSPENDED","DEPROVISIONED"]},
					"includeEmail":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with their type (Okta, app or built-in), description and member count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Start of the group name"}}}`)},
			{Name: "apps", Title: "Applications", Description: "Applications with their label, status, sign-on mode and dates. Never credentials or client secrets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Start of the app's name or label"}}}`)},
			{Name: "suspend_user", Title: "Suspend a user", Description: "Stops an active user signing in; the account, groups and apps stay. Refused for the token's own user, and for admins unless allowed. Undo unsuspends.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "unsuspend_user", Title: "Unsuspend a user", Description: "Lets a suspended user sign in again. Undo suspends them.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "reset_sessions", Title: "End a user's sessions", Description: "Signs a user out of Okta everywhere, and with revokeTokens also revokes the OAuth tokens apps hold. Refused for the token's own user, and for admins unless allowed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["user"],"properties":{"user":{"type":"string","description":"User id (from users) or exact login"},"revokeTokens":{"type":"boolean","default":false,"description":"Also revoke the user's OAuth and OIDC tokens"}}}`)},
		},
	}
}

// orgHost checks an Okta organization address and returns its host. Only
// one label under an Okta domain is accepted; acme-admin.okta.com (the admin
// console) becomes acme.okta.com.
func orgHost(s string) (string, error) {
	bad := errors.New("the organization address is like https://acme.okta.com")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", bad
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() != "" || (u.Path != "" && u.Path != "/") {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	for _, d := range vendorDomains {
		label, ok := strings.CutSuffix(host, d)
		if !ok || !labelRe.MatchString(label) {
			continue
		}
		if l := strings.TrimSuffix(label, "-admin"); l != "" && labelRe.MatchString(l) {
			label = l
		}
		return label + d, nil
	}
	return "", bad
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	host, err := orgHost(c.OrgURL)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	org := "https://" + host
	base := org
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	ref := c.Token
	api := rest.New(base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "SSWS "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org, allowAdmins: c.AllowAdmins})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Okta refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's admin isn't allowed to do this in Okta")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Okta's rate limit was reached; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	hdr, err := c.api.Do(ctx, method, path, q, body, out)
	return hdr, friendly(err)
}

// next reads the cursor of the Link header's next page, or "".
func next(h http.Header) string {
	for _, l := range h.Values("Link") {
		for _, part := range strings.Split(l, ",") {
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			i, j := strings.Index(part, "<"), strings.Index(part, ">")
			if i < 0 || j <= i {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(part[i+1 : j]))
			if err != nil {
				continue
			}
			if a := u.Query().Get("after"); cursorRe.MatchString(a) {
				return a
			}
		}
	}
	return ""
}

// list reads pages of up to 200 until limit items.
func (c *conn) list(ctx context.Context, path string, q url.Values, limit int, out func(json.RawMessage) bool) error {
	q.Set("limit", strconv.Itoa(min(limit, 200)))
	n := 0
	for range 50 {
		var page []json.RawMessage
		hdr, err := c.do(ctx, http.MethodGet, path, q, nil, &page)
		if err != nil {
			return err
		}
		for _, p := range page {
			if out(p) {
				n++
			}
			if n >= limit {
				return nil
			}
		}
		after := next(hdr)
		if after == "" || len(page) == 0 {
			return nil
		}
		q.Set("after", after)
	}
	return nil
}

type user struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	Created         string `json:"created"`
	LastLogin       string `json:"lastLogin"`
	StatusChanged   string `json:"statusChanged"`
	PasswordChanged string `json:"passwordChanged"`
	Profile         struct {
		Login     string `json:"login"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"email"`
	} `json:"profile"`
	// credentials (recovery question, password state) isn't decoded.
}

func (u user) name() string { return strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName) }

func (c *conn) me(ctx context.Context) (user, error) {
	var u user
	_, err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &u)
	return u, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	u, err := c.me(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Okta API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + u.Profile.Login + " · " + strings.TrimPrefix(c.org, "https://")}
}

type input struct {
	Search       string `json:"search"`
	Status       string `json:"status"`
	IncludeEmail bool   `json:"includeEmail"`
	Limit        *int   `json:"limit"`
	User         string `json:"user"`
	RevokeTokens bool   `json:"revokeTokens"`
}

func search(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("the search is one line of at most 200 characters")
	}
	return s, nil
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
	case "groups":
		return c.groups(ctx, p)
	case "apps":
		return c.apps(ctx, p)
	case "suspend_user", "unsuspend_user":
		return c.setSuspended(ctx, call, p)
	case "reset_sessions":
		return c.resetSessions(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status != "" && !statuses[p.Status] {
		return sdk.Result{}, errors.New("status is STAGED, PROVISIONED, ACTIVE, RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED or DEPROVISIONED")
	}
	limit := 50
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 500 {
		return sdk.Result{}, errors.New("limit is 1 to 500")
	}
	q := url.Values{}
	switch {
	case s != "":
		q.Set("q", s) // q can't be combined with filter: the status is checked here
	case p.Status != "":
		q.Set("filter", `status eq "`+p.Status+`"`) // from the fixed list above
	}
	out := []map[string]any{}
	err = c.list(ctx, "/users", q, limit, func(raw json.RawMessage) bool {
		var u user
		if json.Unmarshal(raw, &u) != nil || (p.Status != "" && u.Status != p.Status) {
			return false
		}
		row := map[string]any{"id": u.ID, "login": u.Profile.Login, "name": u.name(), "status": u.Status,
			"created": u.Created, "lastLogin": u.LastLogin, "statusChanged": u.StatusChanged}
		if p.IncludeEmail {
			row["email"] = u.Profile.Email
		}
		out = append(out, row)
		return true
	})
	if err != nil {
		return sdk.Result{}, err
	}
	counts := map[string]int{}
	for _, u := range out {
		counts[strings.ToLower(u["status"].(string))]++
	}
	return sdk.JSON(map[string]any{"count": len(out), "byStatus": counts, "users": out})
}

func (c *conn) groups(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"expand": {"stats"}}
	if s != "" {
		q.Set("q", s)
	}
	out := []map[string]any{}
	err = c.list(ctx, "/groups", q, 1000, func(raw json.RawMessage) bool {
		var g struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Profile struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"profile"`
			Embedded struct {
				Stats *struct {
					UsersCount int `json:"usersCount"`
				} `json:"stats"`
			} `json:"_embedded"`
		}
		if json.Unmarshal(raw, &g) != nil {
			return false
		}
		row := map[string]any{"id": g.ID, "name": g.Profile.Name, "type": strings.ToLower(strings.TrimSuffix(g.Type, "_GROUP"))}
		if g.Profile.Description != "" {
			row["description"] = g.Profile.Description
		}
		if g.Embedded.Stats != nil {
			row["members"] = g.Embedded.Stats.UsersCount
		}
		out = append(out, row)
		return true
	})
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"count": len(out), "groups": out})
}

// apps lists applications, decoded field by field: an app's credentials
// (OAuth client secrets, SAML signing keys, shared passwords) are never read.
func (c *conn) apps(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{}
	if s != "" {
		q.Set("q", s)
	}
	out := []map[string]any{}
	err = c.list(ctx, "/apps", q, 1000, func(raw json.RawMessage) bool {
		var a struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Label       string `json:"label"`
			Status      string `json:"status"`
			SignOnMode  string `json:"signOnMode"`
			Created     string `json:"created"`
			LastUpdated string `json:"lastUpdated"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return false
		}
		out = append(out, map[string]any{"id": a.ID, "name": a.Name, "label": a.Label, "status": a.Status, "signOnMode": a.SignOnMode, "created": a.Created, "updated": a.LastUpdated})
		return true
	})
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"count": len(out), "apps": out})
}

// target checks the user input, then looks the user up and refuses the
// token's own user and, unless allowed, admins.
func (c *conn) target(ctx context.Context, p input) (user, error) {
	who := strings.TrimSpace(p.User)
	if who == "" {
		return user{}, errors.New("enter the user's id or login")
	}
	if !idRe.MatchString(who) && !loginRe.MatchString(who) {
		return user{}, errors.New("the user is an id (from users) or a login, without spaces or slashes")
	}
	var u user
	if _, err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(who), nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return user{}, fmt.Errorf("there's no user %q", who)
		}
		return user{}, err
	}
	if !idRe.MatchString(u.ID) {
		return user{}, errors.New("Okta answered with an unusable user id")
	}
	me, err := c.me(ctx)
	if err != nil {
		return user{}, err
	}
	if !idRe.MatchString(me.ID) {
		return user{}, errors.New("couldn't tell which user the API token belongs to; refused")
	}
	if me.ID == u.ID {
		return user{}, errors.New("that's the API token's own user; acting on it would lock Conduit out")
	}
	if !c.allowAdmins {
		var roles []struct {
			Type  string `json:"type"`
			Label string `json:"label"`
		}
		if _, err := c.do(ctx, http.MethodGet, "/users/"+u.ID+"/roles", nil, nil, &roles); err != nil {
			return user{}, fmt.Errorf("couldn't check whether %s is an admin (%v); refused", u.Profile.Login, err)
		}
		if len(roles) > 0 {
			r := roles[0].Type
			if r == "" {
				r = roles[0].Label
			}
			return user{}, fmt.Errorf("%s holds an admin role (%s); turn on allowAdmins in the settings to act on admins", u.Profile.Login, r)
		}
	}
	return u, nil
}

func (c *conn) setSuspended(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	suspending := call.Action == "suspend_user"
	u, err := c.target(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	want, from := "SUSPENDED", "ACTIVE"
	verb, path, back := "Suspend", "suspend", "unsuspend_user"
	if !suspending {
		want, from = "ACTIVE", "SUSPENDED"
		verb, path, back = "Unsuspend", "unsuspend", "suspend_user"
	}
	switch u.Status {
	case want:
		return sdk.JSON(map[string]any{"id": u.ID, "login": u.Profile.Login, "status": u.Status, "note": "nothing to change"})
	case from:
	default:
		return sdk.Result{}, fmt.Errorf("%s is %s; only %s users can be %sed", u.Profile.Login, u.Status, strings.ToLower(from), strings.ToLower(verb))
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"status": u.Status})
		a, _ := json.Marshal(map[string]string{"status": want})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + u.Profile.Login, Changes: []sdk.Change{{Target: fmt.Sprintf("user %s (%s)", u.Profile.Login, u.ID), Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if _, err := c.do(ctx, http.MethodPost, "/users/"+u.ID+"/lifecycle/"+path, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": u.ID, "login": u.Profile.Login, "status": want})
	undo := "Unsuspend " + u.Profile.Login
	if !suspending {
		undo = "Suspend " + u.Profile.Login + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"user": u.ID}, undo)
	return res, err
}

func (c *conn) resetSessions(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	u, err := c.target(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	what := "Okta sessions"
	if p.RevokeTokens {
		what += " and OAuth tokens"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "End " + u.Profile.Login + "'s " + what, Changes: []sdk.Change{{Target: fmt.Sprintf("user %s (%s)", u.Profile.Login, u.ID), Op: "end " + what}}}}, nil
	}
	var q url.Values
	if p.RevokeTokens {
		q = url.Values{"oauthTokens": {"true"}}
	}
	if _, err := c.do(ctx, http.MethodDelete, "/users/"+u.ID+"/sessions", q, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"id": u.ID, "login": u.Profile.Login, "ended": what})
}
