// Package zitadel works with a Zitadel instance through a service user's
// personal access token: organizations, users, projects and their
// applications (never client secrets), and deactivating and reactivating
// users.
package zitadel

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

// Config is one Zitadel instance (and, optionally, one organization in it).
type Config struct {
	URL                string `json:"url"`   // e.g. https://auth.example.com or https://my-instance.zitadel.cloud
	Token              string `json:"token"` // secret:// service user PAT
	OrgID              string `json:"orgId"` // organization to act in; default the service user's own
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

// New returns the Zitadel module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	orgRe  = regexp.MustCompile(`^[0-9]{1,30}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	who := `{"type":"object","properties":{"id":{"type":"string","description":"User id (from users)"},"userName":{"type":"string","description":"Or the exact user name"}}}`
	return sdk.Manifest{
		ID: "zitadel", Name: "Zitadel", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Zitadel: organizations, users, projects and their applications; deactivate and reactivate users.",
		Presets:     []string{"team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The instance's address, e.g. https://auth.example.com or https://my-instance.zitadel.cloud"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token of a service user (Users, Service Users, Personal Access Tokens). Give it Org User Manager to read and change users, Org Owner Viewer to only read"},
			"orgId":{"type":"string","description":"The organization to work in (its id); empty for the service user's own"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "orgs", Title: "Organizations", Description: "The organizations the token can see, with state and primary domain (only its own one when it may not search).", Risk: sdk.RiskRead},
			{Name: "users", Title: "Users", Description: "The organization's users: id, user name, display name, human or machine, state and last change. Emails only when asked. Kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the user name"},
					"state":{"type":"string","enum":["active","inactive","locked","initial"]},"type":{"type":"string","enum":["human","machine"]},
					"includeEmail":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "projects", Title: "Projects and applications", Description: "Projects with their state and applications: type (OIDC, API, SAML), client id, auth method and redirect URIs. Never client secrets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Part of the project name"}}}`)},
			{Name: "deactivate_user", Title: "Deactivate a user", Description: "Stops a user signing in (the account stays). Refused for the token's own user. Undo reactivates it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
			{Name: "reactivate_user", Title: "Reactivate a user", Description: "Lets a deactivated user sign in again. Undo deactivates it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(who)},
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
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	c.OrgID = strings.TrimSpace(c.OrgID)
	if c.OrgID != "" && !orgRe.MatchString(c.OrgID) {
		return errors.New("the organization id is a number (Organization, its settings)")
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
	ref := c.Token
	p := strings.TrimRight(u.Path, "/")
	for _, s := range []string{"/management/v1", "/ui/console"} {
		p = strings.TrimSuffix(p, s)
	}
	origin := u.Scheme + "://" + u.Host + p
	api := rest.New(origin, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if c.OrgID != "" {
		api.Header.Set("x-zitadel-orgid", c.OrgID)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Zitadel refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the service user isn't allowed to do this in Zitadel")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return friendly(err)
}

type org struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"`
	PrimaryDomain string `json:"primaryDomain"`
}

func (c *conn) me(ctx context.Context) (org, error) {
	var res struct {
		Org org `json:"org"`
	}
	err := c.do(ctx, http.MethodGet, "/management/v1/orgs/me", nil, &res)
	return res.Org, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	o, err := c.me(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Zitadel API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if o.State != "" && o.State != "ORG_STATE_ACTIVE" {
		return sdk.Health{Status: "degraded", Message: "organization " + o.Name + " is " + state(o.State)}
	}
	return sdk.Health{Status: "ok", Message: "organization " + o.Name}
}

// state turns USER_STATE_ACTIVE and the like into "active".
func state(s string) string {
	for _, p := range []string{"USER_STATE_", "ORG_STATE_", "ORGANIZATION_STATE_", "PROJECT_STATE_", "APP_STATE_"} {
		s = strings.TrimPrefix(s, p)
	}
	return strings.ToLower(s)
}

type input struct {
	Search       string `json:"search"`
	State        string `json:"state"`
	Type         string `json:"type"`
	IncludeEmail bool   `json:"includeEmail"`
	Limit        *int   `json:"limit"`
	ID           string `json:"id"`
	UserName     string `json:"userName"`
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
	case "orgs":
		return c.orgs(ctx)
	case "users":
		return c.users(ctx, p)
	case "projects":
		return c.projects(ctx, p)
	case "deactivate_user", "reactivate_user":
		return c.setActive(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) orgs(ctx context.Context) (sdk.Result, error) {
	var res struct {
		Result []org `json:"result"`
	}
	body := map[string]any{"query": map[string]any{"limit": 100, "asc": true}}
	var err error
	// The v2 search (v2beta before Zitadel 2.63); a token that may not
	// search sees its own organization.
	for _, path := range []string{"/v2/organizations/_search", "/v2beta/organizations/_search"} {
		if err = c.do(ctx, http.MethodPost, path, body, &res); err == nil || !rest.IsStatus(err, http.StatusNotFound) {
			break
		}
	}
	if err != nil && rest.IsStatus(err, http.StatusUnauthorized) {
		return sdk.Result{}, err
	}
	if err != nil || len(res.Result) == 0 {
		o, err := c.me(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		res.Result = []org{o}
	}
	out := []map[string]any{}
	for _, o := range res.Result {
		out = append(out, map[string]any{"id": o.ID, "name": o.Name, "state": state(o.State), "primaryDomain": o.PrimaryDomain})
	}
	return sdk.JSON(out)
}

type zuser struct {
	ID                 string   `json:"id"`
	State              string   `json:"state"`
	UserName           string   `json:"userName"`
	PreferredLoginName string   `json:"preferredLoginName"`
	LoginNames         []string `json:"loginNames"`
	Details            struct {
		ChangeDate    string `json:"changeDate"`
		CreationDate  string `json:"creationDate"`
		ResourceOwner string `json:"resourceOwner"`
	} `json:"details"`
	Human *struct {
		Profile struct {
			DisplayName string `json:"displayName"`
			FirstName   string `json:"firstName"`
			LastName    string `json:"lastName"`
		} `json:"profile"`
		Email struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isEmailVerified"`
		} `json:"email"`
	} `json:"human"`
	Machine *struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"machine"`
}

func (u zuser) kind() string {
	if u.Machine != nil {
		return "machine"
	}
	return "human"
}

func (u zuser) display() string {
	if u.Human != nil {
		if d := u.Human.Profile.DisplayName; d != "" {
			return d
		}
		return strings.TrimSpace(u.Human.Profile.FirstName + " " + u.Human.Profile.LastName)
	}
	if u.Machine != nil {
		return u.Machine.Name
	}
	return ""
}

var userStates = map[string]string{"active": "USER_STATE_ACTIVE", "inactive": "USER_STATE_INACTIVE", "locked": "USER_STATE_LOCKED", "initial": "USER_STATE_INITIAL"}

func (c *conn) searchUsers(ctx context.Context, queries []map[string]any, limit int) ([]zuser, int, error) {
	var res struct {
		Details struct {
			TotalResult string `json:"totalResult"`
		} `json:"details"`
		Result []zuser `json:"result"`
	}
	body := map[string]any{"query": map[string]any{"limit": limit, "asc": true}, "sortingColumn": "USER_FIELD_NAME_USER_NAME", "queries": queries}
	if err := c.do(ctx, http.MethodPost, "/management/v1/users/_search", body, &res); err != nil {
		return nil, 0, err
	}
	total, _ := strconv.Atoi(res.Details.TotalResult)
	return res.Result, total, nil
}

func (c *conn) users(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	limit := 50
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 500 {
		return sdk.Result{}, errors.New("limit is 1 to 500")
	}
	queries := []map[string]any{}
	if s != "" {
		queries = append(queries, map[string]any{"userNameQuery": map[string]string{"userName": s, "method": "TEXT_QUERY_METHOD_CONTAINS_IGNORE_CASE"}})
	}
	if p.State != "" {
		st, ok := userStates[p.State]
		if !ok {
			return sdk.Result{}, errors.New("state is active, inactive, locked or initial")
		}
		queries = append(queries, map[string]any{"stateQuery": map[string]string{"state": st}})
	}
	switch p.Type {
	case "":
	case "human", "machine":
		queries = append(queries, map[string]any{"typeQuery": map[string]string{"type": "TYPE_" + strings.ToUpper(p.Type)}})
	default:
		return sdk.Result{}, errors.New("type is human or machine")
	}
	us, total, err := c.searchUsers(ctx, queries, limit)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, u := range us {
		row := map[string]any{"id": u.ID, "userName": u.UserName, "name": u.display(), "type": u.kind(), "state": state(u.State),
			"created": u.Details.CreationDate, "changed": u.Details.ChangeDate}
		if p.IncludeEmail && u.Human != nil {
			row["email"], row["emailVerified"] = u.Human.Email.Email, u.Human.Email.IsVerified
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": total, "users": out})
}

func (c *conn) projects(ctx context.Context, p input) (sdk.Result, error) {
	s, err := search(p.Search)
	if err != nil {
		return sdk.Result{}, err
	}
	body := map[string]any{"query": map[string]any{"limit": 100, "asc": true}}
	if s != "" {
		body["queries"] = []map[string]any{{"nameQuery": map[string]string{"name": s, "method": "TEXT_QUERY_METHOD_CONTAINS_IGNORE_CASE"}}}
	}
	var res struct {
		Result []struct {
			ID                   string `json:"id"`
			Name                 string `json:"name"`
			State                string `json:"state"`
			ProjectRoleAssertion bool   `json:"projectRoleAssertion"`
			ProjectRoleCheck     bool   `json:"projectRoleCheck"`
			HasProjectCheck      bool   `json:"hasProjectCheck"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/management/v1/projects/_search", body, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, pr := range res.Result {
		row := map[string]any{"id": pr.ID, "name": pr.Name, "state": state(pr.State), "roleAssertion": pr.ProjectRoleAssertion, "roleCheck": pr.ProjectRoleCheck}
		if idRe.MatchString(pr.ID) {
			apps, err := c.apps(ctx, pr.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			row["apps"] = apps
		}
		out = append(out, row)
	}
	return sdk.JSON(out)
}

// apps lists a project's applications. Each config is decoded field by
// field: nothing secret (a client secret, a SAML certificate) is read.
func (c *conn) apps(ctx context.Context, project string) ([]map[string]any, error) {
	var res struct {
		Result []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			State      string `json:"state"`
			OIDCConfig *struct {
				ClientID       string   `json:"clientId"`
				AppType        string   `json:"appType"`
				AuthMethodType string   `json:"authMethodType"`
				RedirectURIs   []string `json:"redirectUris"`
				GrantTypes     []string `json:"grantTypes"`
				DevMode        bool     `json:"devMode"`
			} `json:"oidcConfig"`
			APIConfig *struct {
				ClientID       string `json:"clientId"`
				AuthMethodType string `json:"authMethodType"`
			} `json:"apiConfig"`
			SAMLConfig *struct {
				MetadataURL string `json:"metadataUrl"`
			} `json:"samlConfig"`
		} `json:"result"`
	}
	body := map[string]any{"query": map[string]any{"limit": 100, "asc": true}}
	if err := c.do(ctx, http.MethodPost, "/management/v1/projects/"+url.PathEscape(project)+"/apps/_search", body, &res); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, a := range res.Result {
		row := map[string]any{"id": a.ID, "name": a.Name, "state": state(a.State)}
		switch {
		case a.OIDCConfig != nil:
			o := a.OIDCConfig
			row["type"], row["clientId"], row["appType"] = "oidc", o.ClientID, strings.ToLower(strings.TrimPrefix(o.AppType, "OIDC_APP_TYPE_"))
			row["authMethod"] = strings.ToLower(strings.TrimPrefix(o.AuthMethodType, "OIDC_AUTH_METHOD_TYPE_"))
			row["redirectUris"], row["devMode"] = o.RedirectURIs, o.DevMode
			var gs []string
			for _, g := range o.GrantTypes {
				gs = append(gs, strings.ToLower(strings.TrimPrefix(g, "OIDC_GRANT_TYPE_")))
			}
			row["grantTypes"] = gs
		case a.APIConfig != nil:
			row["type"], row["clientId"] = "api", a.APIConfig.ClientID
			row["authMethod"] = strings.ToLower(strings.TrimPrefix(a.APIConfig.AuthMethodType, "API_AUTH_METHOD_TYPE_"))
		case a.SAMLConfig != nil:
			row["type"] = "saml"
			if a.SAMLConfig.MetadataURL != "" {
				row["metadataUrl"] = rest.CleanURL(a.SAMLConfig.MetadataURL)
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (c *conn) findUser(ctx context.Context, p input) (zuser, error) {
	id := strings.TrimSpace(p.ID)
	if id != "" {
		if !idRe.MatchString(id) {
			return zuser{}, errors.New("the user id is letters, digits, dashes and underscores (from users)")
		}
		var res struct {
			User zuser `json:"user"`
		}
		if err := c.do(ctx, http.MethodGet, "/management/v1/users/"+id, nil, &res); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return zuser{}, fmt.Errorf("there's no user %s", id)
			}
			return zuser{}, err
		}
		if res.User.ID == "" {
			return zuser{}, fmt.Errorf("there's no user %s", id)
		}
		return res.User, nil
	}
	name, err := search(p.UserName)
	if err != nil {
		return zuser{}, err
	}
	if name == "" {
		return zuser{}, errors.New("enter the user's id or user name")
	}
	us, _, err := c.searchUsers(ctx, []map[string]any{{"userNameQuery": map[string]string{"userName": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}, 5)
	if err != nil {
		return zuser{}, err
	}
	for _, u := range us {
		if u.UserName == name {
			return u, nil
		}
	}
	return zuser{}, fmt.Errorf("there's no user %q", name)
}

func (c *conn) setActive(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	activating := call.Action == "reactivate_user"
	u, err := c.findUser(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if !activating {
		var me struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		}
		if err := c.do(ctx, http.MethodGet, "/auth/v1/users/me", nil, &me); err != nil {
			return sdk.Result{}, err
		}
		if me.User.ID == u.ID {
			return sdk.Result{}, errors.New("that's the token's own service user; deactivating it would lock Conduit out")
		}
	}
	inactive := u.State == "USER_STATE_INACTIVE"
	switch {
	case !activating && inactive, activating && u.State == "USER_STATE_ACTIVE":
		return sdk.JSON(map[string]any{"id": u.ID, "userName": u.UserName, "state": state(u.State), "note": "nothing to change"})
	case activating && !inactive:
		// A locked user is unlocked, not reactivated.
		return sdk.Result{}, fmt.Errorf("%s is %s, not deactivated", u.UserName, state(u.State))
	}
	verb, path, back := "Deactivate", "_deactivate", "reactivate_user"
	if activating {
		verb, path, back = "Reactivate", "_reactivate", "deactivate_user"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"state": state(u.State)})
		after := "inactive"
		if activating {
			after = "active"
		}
		a, _ := json.Marshal(map[string]string{"state": after})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + u.UserName, Changes: []sdk.Change{{Target: fmt.Sprintf("%s user %s (%s)", u.kind(), u.UserName, u.ID), Op: strings.ToLower(verb), Before: b, After: a}}}}, nil
	}
	if !idRe.MatchString(u.ID) {
		return sdk.Result{}, errors.New("Zitadel answered with an unusable user id")
	}
	if err := c.do(ctx, http.MethodPost, "/management/v1/users/"+u.ID+"/"+path, map[string]any{}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": u.ID, "userName": u.UserName, "active": activating})
	undo := "Reactivate " + u.UserName
	if activating {
		undo = "Deactivate " + u.UserName + " again"
	}
	res.Undo = sdk.UndoWith(back, map[string]string{"id": u.ID}, undo)
	return res, err
}
