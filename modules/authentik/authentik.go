// Package authentik works with an authentik identity provider through an
// API token: users (counts and the list), groups, applications, recent
// events and logins, deactivating and reactivating users, and the server's
// version and status.
package authentik

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one authentik server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://auth.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the authentik module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	actionRe = regexp.MustCompile(`^[a-z_]{1,40}$`)
	userTyps = map[string]bool{"internal": true, "external": true, "service_account": true, "internal_service_account": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","properties":{"id":{"type":"integer","minimum":1,"description":"User id (pk, from users)"},"username":{"type":"string","description":"Or the exact username"}}}`
	return sdk.Manifest{
		ID: "authentik", Name: "authentik", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "authentik: users, groups, applications, recent events and logins, deactivating users, and the server's version and status.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://auth.example.com"},
			"token":{"type":"string","x-secret":true,"description":"API token (Directory, Tokens and App passwords, intent API). It acts with its user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, to trust authentik's self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Version and status", Description: "Running and latest version (and whether an update is due), runtime, server time, workers, and outposts.", Risk: sdk.RiskRead},
			{Name: "users", Title: "Users", Description: "How many users there are (active, inactive, superusers), and a list with username, name, last login and groups. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"},"active":{"type":"boolean","description":"Only active (true) or inactive (false) users"},
					"type":{"type":"string","enum":["internal","external","service_account","internal_service_account"]},
					"includeEmail":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":0,"maximum":500,"description":"0 for counts only"}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with their parent, member count and whether they grant superuser.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"}}}`)},
			{Name: "applications", Title: "Applications", Description: "Applications with their slug, provider, launch URL and group.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"}}}`)},
			{Name: "events", Title: "Recent events", Description: "The audit log, newest first: logins, failed logins, changes, alerts. Holds usernames and IP addresses, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"action":{"type":"string","description":"Only this kind, e.g. login, login_failed, logout, user_write, model_updated, configuration_error, system_exception"},
					"username":{"type":"string","description":"Only events of this user"},"limit":{"type":"integer","default":30,"minimum":1,"maximum":200}}}`)},
			{Name: "deactivate_user", Title: "Deactivate a user", Description: "Stops a user from signing in (the account and its data stay). Undo activates it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "activate_user", Title: "Activate a user", Description: "Lets a deactivated user sign in again. Undo deactivates it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://auth.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	tok := c.Token
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/api/v3"), "/if/admin")
	origin := u.Scheme + "://" + u.Host + p
	api := rest.New(origin+"/api/v3", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

func friendly(err error) error {
	switch {
	// authentik answers 403 "Token invalid/expired" for a bad token, and
	// 403 too when the token's user lacks a permission.
	case rest.IsStatus(err, http.StatusUnauthorized),
		rest.IsStatus(err, http.StatusForbidden) && (strings.Contains(strings.ToLower(err.Error()), "token invalid") || strings.Contains(strings.ToLower(err.Error()), "expired")):
		return errors.New("authentik refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in authentik")
	}
	return err
}

type page struct {
	Pagination struct {
		Next  int `json:"next"`
		Count int `json:"count"`
	} `json:"pagination"`
	Results []map[string]any `json:"results"`
}

// list reads pages until limit results (at most 100 per page).
func (c *conn) list(ctx context.Context, path string, q url.Values, limit int) ([]map[string]any, int, error) {
	if q == nil {
		q = url.Values{}
	}
	size := limit
	if size > 100 || size <= 0 {
		size = 100
	}
	q.Set("page_size", strconv.Itoa(size))
	var all []map[string]any
	count := 0
	for pg := 1; pg <= 50; {
		q.Set("page", strconv.Itoa(pg))
		var p page
		if err := c.get(ctx, path, q, &p); err != nil {
			return nil, 0, err
		}
		count = p.Pagination.Count
		all = append(all, p.Results...)
		if (limit > 0 && len(all) >= limit) || p.Pagination.Next <= pg || len(p.Results) == 0 {
			break
		}
		pg = p.Pagination.Next
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, count, nil
}

func (c *conn) count(ctx context.Context, path string, q url.Values) (int, error) {
	q.Set("page_size", "1")
	var p page
	if err := c.get(ctx, path, q, &p); err != nil {
		return 0, err
	}
	return p.Pagination.Count, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := c.get(ctx, "/core/users/me/", nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no authentik API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + me.User.Username
	var v version
	if err := c.get(ctx, "/admin/version/", nil, &v); err == nil {
		msg += " · authentik " + v.Current
		if v.Outdated {
			msg += " (" + v.Latest + " is out)"
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type version struct {
	Current  string `json:"version_current"`
	Latest   string `json:"version_latest"`
	Outdated bool   `json:"outdated"`
	Build    string `json:"build_hash"`
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

type input struct {
	Search       string `json:"search"`
	Active       *bool  `json:"active"`
	Type         string `json:"type"`
	IncludeEmail bool   `json:"includeEmail"`
	Limit        *int   `json:"limit"`
	Action       string `json:"action"`
	Username     string `json:"username"`
	ID           any    `json:"id"`
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
	case "status":
		return c.status(ctx)
	case "users":
		return c.users(ctx, p)
	case "groups", "applications":
		s, err := search(p.Search)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{}
		if s != "" {
			q.Set("search", s)
		}
		path := "/core/groups/"
		if call.Action == "groups" {
			q.Set("include_users", "false")
		} else {
			path = "/core/applications/"
			q.Set("superuser_full_list", "true") // all of them, not only the ones the token's user can open
		}
		list, total, err := c.list(ctx, path, q, 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range list {
			if call.Action == "groups" {
				e := map[string]any{"id": x["pk"], "name": str(x, "name"), "superuser": x["is_superuser"] == true}
				if us, ok := x["users"].([]any); ok {
					e["members"] = len(us)
				}
				if pn := str(x, "parent_name"); pn != "" {
					e["parent"] = pn
				}
				out = append(out, e)
				continue
			}
			e := map[string]any{"name": str(x, "name"), "slug": str(x, "slug")}
			if po, ok := x["provider_obj"].(map[string]any); ok {
				e["provider"] = strings.TrimSpace(str(po, "name") + " (" + str(po, "verbose_name") + ")")
			}
			if l := str(x, "launch_url"); l != "" {
				e["launchUrl"] = l
			}
			if g := str(x, "group"); g != "" {
				e["group"] = g
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"total": total, call.Action: out})
	case "events":
		return c.events(ctx, p)
	case "deactivate_user", "activate_user":
		return c.setActive(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) status(ctx context.Context) (sdk.Result, error) {
	var v version
	if err := c.get(ctx, "/admin/version/", nil, &v); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"version": v.Current, "latest": v.Latest, "outdated": v.Outdated, "build": v.Build, "url": c.origin}
	// /admin/system/ also echoes the request's headers, our token among
	// them; only the runtime and time are passed on.
	var sys struct {
		Runtime    map[string]any `json:"runtime"`
		ServerTime string         `json:"server_time"`
		Embedded   bool           `json:"embedded_outpost_disabled"`
	}
	if err := c.get(ctx, "/admin/system/", nil, &sys); err == nil {
		rt := map[string]any{}
		for _, k := range []string{"python_version", "gunicorn_version", "environment", "architecture", "platform", "openssl_version", "openssl_fips_enabled", "authentik_latest_version"} {
			if v, ok := sys.Runtime[k]; ok {
				rt[k] = v
			}
		}
		out["runtime"], out["serverTime"], out["embeddedOutpostDisabled"] = rt, sys.ServerTime, sys.Embedded
	}
	// Workers: {"count": n} before 2024.x, a list of workers since.
	var raw json.RawMessage
	if err := c.get(ctx, "/admin/workers/", nil, &raw); err == nil {
		var n struct {
			Count *int `json:"count"`
		}
		var l []json.RawMessage
		if json.Unmarshal(raw, &n) == nil && n.Count != nil {
			out["workers"] = *n.Count
		} else if json.Unmarshal(raw, &l) == nil {
			out["workers"] = len(l)
		}
	}
	if outposts, _, err := c.list(ctx, "/outposts/instances/", nil, 100); err == nil {
		var ol []map[string]any
		for _, o := range outposts {
			ol = append(ol, map[string]any{"name": str(o, "name"), "type": str(o, "type")})
		}
		out["outposts"] = ol
	}
	return sdk.JSON(out)
}

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Type != "" && !userTyps[p.Type] {
		return sdk.Result{}, errors.New("type is internal, external, service_account or internal_service_account")
	}
	limit := 50
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 0 || limit > 500 {
		return sdk.Result{}, errors.New("limit is 0 to 500")
	}
	counts := map[string]int{}
	for k, q := range map[string]url.Values{"total": {}, "active": {"is_active": {"true"}}, "inactive": {"is_active": {"false"}}, "superusers": {"is_superuser": {"true"}}} {
		n, err := c.count(ctx, "/core/users/", q)
		if err != nil {
			return sdk.Result{}, err
		}
		counts[k] = n
	}
	out := map[string]any{"counts": counts}
	if limit == 0 {
		return sdk.JSON(out)
	}
	q := url.Values{"ordering": {"username"}, "include_groups": {"true"}}
	if s != "" {
		q.Set("search", s)
	}
	if p.Active != nil {
		q.Set("is_active", strconv.FormatBool(*p.Active))
	}
	if p.Type != "" {
		q.Set("type", p.Type)
	}
	list, matches, err := c.list(ctx, "/core/users/", q, limit)
	if err != nil {
		return sdk.Result{}, err
	}
	users := []map[string]any{}
	for _, u := range list {
		e := map[string]any{"id": u["pk"], "username": str(u, "username"), "name": str(u, "name"), "active": u["is_active"] == true,
			"superuser": u["is_superuser"] == true, "type": str(u, "type"), "lastLogin": u["last_login"]}
		var groups []string
		if gs, ok := u["groups_obj"].([]any); ok {
			for _, g := range gs {
				if g, ok := g.(map[string]any); ok {
					groups = append(groups, str(g, "name"))
				}
			}
		}
		if groups != nil {
			e["groups"] = groups
		}
		if p.IncludeEmail {
			e["email"] = str(u, "email")
		}
		users = append(users, e)
	}
	out["matches"], out["users"] = matches, users
	return sdk.JSON(out)
}

func (c *conn) events(ctx context.Context, p input) (sdk.Result, error) {
	limit := 30
	if p.Limit != nil && *p.Limit > 0 {
		limit = min(*p.Limit, 200)
	}
	q := url.Values{"ordering": {"-created"}}
	if a := strings.TrimSpace(p.Action); a != "" {
		if !actionRe.MatchString(a) {
			return sdk.Result{}, errors.New("the action is an event kind like login or login_failed")
		}
		q.Set("action", a)
	}
	if u := strings.TrimSpace(p.Username); u != "" {
		if _, err := search(u); err != nil {
			return sdk.Result{}, err
		}
		q.Set("username", u)
	}
	list, total, err := c.list(ctx, "/events/events/", q, limit)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, e := range list {
		user, _ := e["user"].(map[string]any)
		ctxm, _ := e["context"].(map[string]any)
		ev := map[string]any{"created": str(e, "created"), "action": str(e, "action"), "app": str(e, "app"), "clientIp": str(e, "client_ip")}
		if user != nil {
			ev["user"] = str(user, "username")
		}
		// A few context fields; the rest can be whole model dumps.
		if ctxm != nil {
			for _, k := range []string{"message", "username", "reason"} {
				if s := str(ctxm, k); s != "" {
					ev[k] = s
				}
			}
			if hr, ok := ctxm["http_request"].(map[string]any); ok {
				ev["path"] = str(hr, "path")
			}
			if geo, ok := ctxm["geo"].(map[string]any); ok {
				ev["country"] = str(geo, "country")
			}
			if a, ok := ctxm["authorized_application"].(map[string]any); ok {
				ev["application"] = str(a, "name")
			}
			if mdl, ok := ctxm["model"].(map[string]any); ok {
				ev["model"] = strings.TrimSpace(str(mdl, "model_name") + " " + str(mdl, "name"))
			}
		}
		out = append(out, ev)
	}
	return sdk.JSON(map[string]any{"total": total, "events": out})
}

type user struct {
	PK        int    `json:"pk"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	IsActive  bool   `json:"is_active"`
	Superuser bool   `json:"is_superuser"`
}

func (c *conn) findUser(ctx context.Context, p input) (user, error) {
	var u user
	if p.ID != nil {
		f, ok := p.ID.(float64)
		if !ok || f < 1 || f != float64(int(f)) || f > 1e12 {
			return u, errors.New("the user id is a positive number (from users)")
		}
		if err := c.get(ctx, "/core/users/"+strconv.Itoa(int(f))+"/", nil, &u); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return u, fmt.Errorf("there's no user %d", int(f))
			}
			return u, err
		}
		return u, nil
	}
	name := strings.TrimSpace(p.Username)
	if name == "" {
		return u, errors.New("enter the user's id or username")
	}
	if _, err := search(name); err != nil {
		return u, err
	}
	var pg struct {
		Results []user `json:"results"`
	}
	if err := c.get(ctx, "/core/users/", url.Values{"username": {name}, "page_size": {"5"}}, &pg); err != nil {
		return u, err
	}
	for _, x := range pg.Results {
		if x.Username == name {
			return x, nil
		}
	}
	return u, fmt.Errorf("there's no user %q", name)
}

func (c *conn) setActive(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	activating := call.Action == "activate_user"
	u, err := c.findUser(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if !activating {
		var me struct {
			User struct {
				PK int `json:"pk"`
			} `json:"user"`
		}
		if err := c.get(ctx, "/core/users/me/", nil, &me); err != nil {
			return sdk.Result{}, err
		}
		if me.User.PK == u.PK {
			return sdk.Result{}, errors.New("that's the token's own user; deactivating it would lock Conduit out")
		}
	}
	if u.IsActive == activating {
		return sdk.JSON(map[string]any{"id": u.PK, "username": u.Username, "active": activating, "note": "nothing to change"})
	}
	verb, back := "Deactivate", "activate_user"
	if activating {
		verb, back = "Activate", "deactivate_user"
	}
	target := fmt.Sprintf("user %s (%d)", u.Username, u.PK)
	if u.Superuser {
		target += ", a superuser"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]bool{"active": u.IsActive})
		a, _ := json.Marshal(map[string]bool{"active": activating})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + u.Username, Changes: []sdk.Change{{Target: target, Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPatch, "/core/users/"+strconv.Itoa(u.PK)+"/", nil, map[string]any{"is_active": activating}, nil); err != nil {
		return sdk.Result{}, friendly(err)
	}
	res, err := sdk.JSON(map[string]any{"id": u.PK, "username": u.Username, "active": activating})
	undo := "Deactivate " + u.Username + " again"
	if !activating {
		undo = "Activate " + u.Username + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]any{"id": u.PK}, undo)
	return res, err
}
