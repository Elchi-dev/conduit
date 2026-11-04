// Package lldap works with an LLDAP server through its GraphQL API, signing
// in as an admin user: users, groups, and adding users to groups and
// removing them.
package lldap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one LLDAP server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://ldap.example.com
	Username           string `json:"username"` // a member of lldap_admin
	Password           string `json:"password"` // secret:// its password
	AllowAdmins        bool   `json:"allowAdmins"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api         *rest.Client // GraphQL, with the session token
	login       *rest.Client // sign-in, no credentials attached
	username    string
	password    string // secret:// reference
	host        sdk.Host
	allowAdmins bool
	cache       oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the LLDAP module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe = regexp.MustCompile(`^[A-Za-z0-9_.@+-]{1,64}$`)
)

// adminGroup reports whether a group grants rights over the directory:
// lldap_admin, lldap_password_manager, lldap_strict_readonly.
func adminGroup(name string) bool { return strings.HasPrefix(strings.ToLower(name), "lldap_") }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	member := `{"type":"object","required":["user","group"],"properties":{"user":{"type":"string","description":"User id (from users)"},"group":{"type":["integer","string"],"description":"Group id (from groups) or exact name"}}}`
	return sdk.Manifest{
		ID: "lldap", Name: "LLDAP", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "LLDAP: users and groups; add users to groups and remove them.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The web interface's address, e.g. https://ldap.example.com or http://lldap.lan:17170"},
			"username":{"type":"string","description":"A user in lldap_admin (a dedicated one is best)"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"allowAdmins":{"type":"boolean","default":false,"description":"Let Conduit change lldap_* groups (admin, password manager, read-only) and the groups of their members (off: refused)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "users", Title: "Users", Description: "Users with id, display name, created and groups. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the id or display name"},"includeEmail":{"type":"boolean","default":false}}}`)},
			{Name: "groups", Title: "Groups", Description: "Groups with id, name, created, member count and whether they're a built-in admin group.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the name"}}}`)},
			{Name: "add_to_group", Title: "Add a user to a group", Description: "Gives a user a group, and with it whatever the group grants in the apps that use LLDAP. Refused for the signed-in user, and for admin groups unless allowed. Undo removes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(member)},
			{Name: "remove_from_group", Title: "Remove a user from a group", Description: "Takes a group away from a user, and its access with it. Refused for the signed-in user, and for admin groups unless allowed. Undo adds it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(member)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://ldap.example.com")
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("the user name is an LLDAP user id, like admin")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
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
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/api/graphql")
	origin := u.Scheme + "://" + u.Host + p
	cn := &conn{username: c.Username, password: c.Password, host: h, allowAdmins: c.AllowAdmins}
	cn.login = rest.New(origin, nil)
	cn.login.HTTP = rest.SameHostOnly(client)
	cn.api = rest.New(origin, func(ctx context.Context, r *http.Request) error {
		t, err := cn.cache.Get(ctx, cn.signIn)
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

var errLogin = errors.New("LLDAP refused the user name or password")

// signIn gets a session token (a JWT, valid a day by default; kept an hour).
func (c *conn) signIn(ctx context.Context) (oauth.Grant, error) {
	pw, err := c.host.Secret(ctx, c.password)
	if err != nil {
		return oauth.Grant{}, err
	}
	var res struct {
		Token string `json:"token"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/auth/simple/login", nil, map[string]string{"username": c.username, "password": pw}, &res)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusForbidden):
		return oauth.Grant{}, errLogin
	case rest.IsStatus(err, http.StatusNotFound):
		return oauth.Grant{}, errors.New("no LLDAP at this address")
	case err != nil:
		return oauth.Grant{}, err
	case res.Token == "":
		return oauth.Grant{}, errors.New("LLDAP answered without a token")
	}
	return oauth.Grant{Access: res.Token, ExpiresIn: 3600}, nil
}

// clip shortens a server's message, after redacting it.
func clip(s string) string {
	s = rest.Redact(strings.TrimSpace(s))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// gql runs a GraphQL operation. Values only ever travel in variables, never
// in the query text.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/api/graphql", nil, body, &res)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.cache.Drop()
		_, err = c.api.Do(ctx, http.MethodPost, "/api/graphql", nil, body, &res)
	}
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("LLDAP refused the session token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the user isn't allowed to do this in LLDAP (it must be in lldap_admin)")
	case err != nil:
		return err
	case len(res.Errors) > 0:
		return errors.New("LLDAP: " + clip(res.Errors[0].Message))
	}
	if out != nil {
		return json.Unmarshal(res.Data, out)
	}
	return nil
}

type groupRef struct {
	ID          int    `json:"id"`
	DisplayName string `json:"displayName"`
}

type user struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"displayName"`
	CreationDate string     `json:"creationDate"`
	Groups       []groupRef `json:"groups"`
}

func (u user) groupNames() []string {
	out := []string{}
	for _, g := range u.Groups {
		out = append(out, g.DisplayName)
	}
	sort.Strings(out)
	return out
}

type group struct {
	ID           int    `json:"id"`
	DisplayName  string `json:"displayName"`
	CreationDate string `json:"creationDate"`
	Users        []struct {
		ID string `json:"id"`
	} `json:"users"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var res struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
	}
	if err := c.gql(ctx, `query { users { id } }`, nil, &res); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("signed in as %s · %d users", c.username, len(res.Users))}
}

type input struct {
	Search       string `json:"search"`
	IncludeEmail bool   `json:"includeEmail"`
	User         string `json:"user"`
	Group        any    `json:"group"`
}

func search(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("the search is one line of at most 200 characters")
	}
	return strings.ToLower(s), nil
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
	case "add_to_group", "remove_from_group":
		return c.membership(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	var res struct {
		Users []user `json:"users"`
	}
	if err := c.gql(ctx, `query { users { id email displayName creationDate groups { id displayName } } }`, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	sort.Slice(res.Users, func(i, j int) bool { return res.Users[i].ID < res.Users[j].ID })
	out := []map[string]any{}
	for _, u := range res.Users {
		if s != "" && !strings.Contains(strings.ToLower(u.ID), s) && !strings.Contains(strings.ToLower(u.DisplayName), s) {
			continue
		}
		row := map[string]any{"id": u.ID, "displayName": u.DisplayName, "created": u.CreationDate, "groups": u.groupNames()}
		if p.IncludeEmail {
			row["email"] = u.Email
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"count": len(out), "users": out})
}

func (c *conn) allGroups(ctx context.Context) ([]group, error) {
	var res struct {
		Groups []group `json:"groups"`
	}
	err := c.gql(ctx, `query { groups { id displayName creationDate users { id } } }`, nil, &res)
	sort.Slice(res.Groups, func(i, j int) bool { return res.Groups[i].DisplayName < res.Groups[j].DisplayName })
	return res.Groups, err
}

func (c *conn) groups(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	gs, err := c.allGroups(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, g := range gs {
		if s != "" && !strings.Contains(strings.ToLower(g.DisplayName), s) {
			continue
		}
		out = append(out, map[string]any{"id": g.ID, "name": g.DisplayName, "created": g.CreationDate, "members": len(g.Users), "admin": adminGroup(g.DisplayName)})
	}
	return sdk.JSON(map[string]any{"count": len(out), "groups": out})
}

// groupArg checks the group input: a positive id or a name.
func groupArg(v any) (int, string, error) {
	switch g := v.(type) {
	case float64:
		if g >= 1 && g <= 1e9 && g == float64(int(g)) {
			return int(g), "", nil
		}
	case string:
		g = strings.TrimSpace(g)
		if g != "" && len(g) <= 200 && !strings.ContainsAny(g, "\r\n\x00") {
			return 0, g, nil
		}
	}
	return 0, "", errors.New("the group is its id (a number, from groups) or its exact name")
}

func (c *conn) membership(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	adding := call.Action == "add_to_group"
	uid := strings.TrimSpace(p.User)
	if !userRe.MatchString(uid) {
		return sdk.Result{}, errors.New("the user is a user id (from users)")
	}
	gid, gname, err := groupArg(p.Group)
	if err != nil {
		return sdk.Result{}, err
	}
	if strings.EqualFold(uid, c.username) {
		return sdk.Result{}, errors.New("that's the user Conduit signs in as; changing its groups could lock Conduit out")
	}
	gs, err := c.allGroups(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var g *group
	for i := range gs {
		if (gid != 0 && gs[i].ID == gid) || (gid == 0 && gs[i].DisplayName == gname) {
			g = &gs[i]
			break
		}
	}
	if g == nil {
		if gid != 0 {
			return sdk.Result{}, fmt.Errorf("there's no group %d", gid)
		}
		return sdk.Result{}, fmt.Errorf("there's no group %q", gname)
	}
	var res struct {
		User *user `json:"user"`
	}
	if err := c.gql(ctx, `query($id: String!) { user(userId: $id) { id email displayName groups { id displayName } } }`, map[string]any{"id": uid}, &res); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return sdk.Result{}, fmt.Errorf("there's no user %q", uid)
		}
		return sdk.Result{}, err
	}
	if res.User == nil || !userRe.MatchString(res.User.ID) {
		return sdk.Result{}, fmt.Errorf("there's no user %q", uid)
	}
	u := *res.User
	// LLDAP also signs users in by email, so the configured name may be
	// the user's email rather than its id.
	if strings.EqualFold(u.ID, c.username) || (u.Email != "" && strings.EqualFold(strings.TrimSpace(u.Email), c.username)) {
		return sdk.Result{}, errors.New("that's the user Conduit signs in as; changing its groups could lock Conduit out")
	}
	if !c.allowAdmins {
		if adminGroup(g.DisplayName) {
			return sdk.Result{}, fmt.Errorf("%s is a built-in admin group; turn on allowAdmins in the settings to change it", g.DisplayName)
		}
		for _, n := range u.groupNames() {
			if adminGroup(n) {
				return sdk.Result{}, fmt.Errorf("%s is in %s; turn on allowAdmins in the settings to change an admin's groups", u.ID, n)
			}
		}
	}
	member := false
	for _, x := range u.Groups {
		if x.ID == g.ID {
			member = true
		}
	}
	if member == adding {
		return sdk.JSON(map[string]any{"user": u.ID, "group": g.DisplayName, "member": member, "note": "nothing to change"})
	}
	verb, op, back, undo := "Add "+u.ID+" to "+g.DisplayName, "add", "remove_from_group", "Remove "+u.ID+" from "+g.DisplayName
	mutation := `mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }`
	if !adding {
		verb, op, back, undo = "Remove "+u.ID+" from "+g.DisplayName, "remove", "add_to_group", "Add "+u.ID+" back to "+g.DisplayName
		mutation = `mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }`
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"groups": u.groupNames()})
		after := []string{}
		for _, n := range u.groupNames() {
			if n != g.DisplayName {
				after = append(after, n)
			}
		}
		if adding {
			after = append(after, g.DisplayName)
			sort.Strings(after)
		}
		a, _ := json.Marshal(map[string]any{"groups": after})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb, Changes: []sdk.Change{{Target: "user " + u.ID, Op: op + " group " + g.DisplayName, Before: b, After: a}}}}, nil
	}
	if err := c.gql(ctx, mutation, map[string]any{"u": u.ID, "g": g.ID}, nil); err != nil {
		return sdk.Result{}, err
	}
	out, err := sdk.JSON(map[string]any{"user": u.ID, "group": g.DisplayName, "member": adding})
	out.Undo = sdk.UndoWith(back, map[string]any{"user": u.ID, "group": g.ID}, undo)
	return out, err
}
