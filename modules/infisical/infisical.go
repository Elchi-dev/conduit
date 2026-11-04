// Package infisical works with Infisical (cloud or self-hosted) as a machine
// identity with Universal Auth: projects and their environments, folders and
// secret keys under a path (never values or comments), a secret's version
// history (metadata only) and the values of named secrets only through the
// destructive reveal_secret. It never creates, edits or deletes secrets and
// never changes access (identities, client secrets, roles).
package infisical

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one machine identity on one Infisical server.
type Config struct {
	URL                string `json:"url"`          // default https://app.infisical.com
	ClientID           string `json:"clientId"`     // Universal Auth client id
	ClientSecret       string `json:"clientSecret"` // secret://
	Project            string `json:"project"`      // default project id or slug
	Environment        string `json:"environment"`  // default environment slug
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host       sdk.Host
	clientID   string
	secretRef  string
	defProject string
	env        string
	api        *rest.Client
	login      *rest.Client

	mu      sync.Mutex
	bearer  string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Infisical module.
func New() *Module { return &Module{} }

const (
	maxReveal   = 10
	maxSecrets  = 2000
	maxVersions = 100
)

var (
	idRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	slugRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	segRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	loc := `"project":{"type":"string","description":"Project id or slug (the instance's default when empty)"},"environment":{"type":"string","description":"Environment slug, e.g. dev or prod (the instance's default when empty)"},"path":{"type":"string","description":"Folder path, / when empty"}`
	return sdk.Manifest{
		ID: "infisical", Name: "Infisical", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "Infisical as a machine identity: projects, environments, folders and secret keys (never values or comments), version history, revealing named secrets (destructive).",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["clientId","clientSecret"],"properties":{
			"url":{"type":"string","default":"https://app.infisical.com","description":"Infisical: https://app.infisical.com, https://eu.infisical.com or your own server"},
			"clientId":{"type":"string","description":"The machine identity's Universal Auth client id"},
			"clientSecret":{"type":"string","x-secret":true,"description":"A Universal Auth client secret. Give the identity a read-only role on only the projects Conduit should see"},
			"project":{"type":"string","description":"Default project id or slug"},
			"environment":{"type":"string","description":"Default environment slug, e.g. prod"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Server status", Description: "Whether the server answers, its date and which optional services (email, Redis, secret scanning) it has.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "The projects the identity is in: name, id, slug, environments and dates.", Risk: sdk.RiskRead},
			{Name: "environments", Title: "Environments", Description: "A project's environments with name, slug and id.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project id or slug (the instance's default when empty)"}}}`)},
			{Name: "secrets", Title: "Secret keys", Description: "Folders and secret keys under a path of one environment, with version, type, tags and dates. Never values or comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + loc + `}}`)},
			{Name: "versions", Title: "Secret versions", Description: "A secret's versions with number, type and dates, newest first. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + loc + `,"key":{"type":"string","description":"Secret key"}}}`)},
			{Name: "reveal_secret", Title: "Reveal secret values", Description: "The values of the named secrets (up to 10) in one environment and path, and only those; never comments. Revealing a credential is destructive: it can't be taken back.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["keys"],"properties":{` + loc + `,"keys":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":10,"description":"Secret keys whose values to return"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "https://app.infisical.com"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the URL is like https://app.infisical.com or https://infisical.example.com")
	}
	cid := strings.TrimSpace(c.ClientID)
	if !idRe.MatchString(cid) {
		return errors.New("enter the identity's Universal Auth client id")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") {
		return errors.New("store the client secret in the vault and enter its secret:// reference")
	}
	proj, env := strings.TrimSpace(c.Project), strings.TrimSpace(c.Environment)
	if proj != "" && !slugRe.MatchString(proj) {
		return errors.New("the default project is its id or slug")
	}
	if env != "" && !slugRe.MatchString(env) {
		return errors.New("the default environment is its slug, like prod")
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
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	cn := &conn{host: h, clientID: cid, secretRef: c.ClientSecret, defProject: proj, env: env}
	cn.login = rest.New(base, nil)
	cn.login.HTTP = rest.SameHostOnly(client)
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx, false)
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

// token logs in with Universal Auth when there's no current access token.
func (c *conn) token(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.bearer != "" && time.Now().Before(c.expires) {
		return c.bearer, nil
	}
	c.bearer = ""
	sec, err := c.host.Secret(ctx, c.secretRef)
	if err != nil {
		return "", err
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	body := map[string]string{"clientId": c.clientID, "clientSecret": strings.TrimSpace(sec)}
	if _, err := c.login.Do(ctx, http.MethodPost, "/api/v1/auth/universal-auth/login", nil, body, &out); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("Infisical refused the client id and secret (revoked, expired, or not allowed from this address)")
		}
		return "", fmt.Errorf("logging in: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("the login returned no access token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if ttl > 2*time.Minute {
		ttl -= time.Minute
	}
	c.bearer, c.expires = out.AccessToken, time.Now().Add(ttl)
	return c.bearer, nil
}

func friendly(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Infisical refused the identity's session")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the identity has no access to %s", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		if _, lerr := c.token(ctx, true); lerr != nil {
			return lerr
		}
		_, err = c.api.Do(ctx, method, path, q, nil, out)
	}
	return err
}

type environment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type project struct {
	ID           string        `json:"id"`
	OldID        string        `json:"_id"`
	Name         string        `json:"name"`
	Slug         string        `json:"slug"`
	Type         string        `json:"type"`
	Environments []environment `json:"environments"`
	CreatedAt    string        `json:"createdAt"`
	UpdatedAt    string        `json:"updatedAt"`
}

func (p project) id() string {
	if p.ID != "" {
		return p.ID
	}
	return p.OldID
}

func (c *conn) projects(ctx context.Context) ([]project, error) {
	var out struct {
		Workspaces []project `json:"workspaces"`
		Projects   []project `json:"projects"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/workspace", nil, &out)
	if rest.IsStatus(err, http.StatusNotFound) {
		// Newer servers call workspaces projects.
		err = c.do(ctx, http.MethodGet, "/api/v1/projects", nil, &out)
	}
	if err != nil {
		return nil, friendly(err, "project list")
	}
	ps := append(out.Workspaces, out.Projects...)
	sort.Slice(ps, func(i, j int) bool { return strings.ToLower(ps[i].Name) < strings.ToLower(ps[j].Name) })
	return ps, nil
}

// project resolves a project id or slug (or the default).
func (c *conn) project(ctx context.Context, s string) (project, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = c.defProject
	}
	if s == "" {
		return project{}, errors.New("name the project (its id or slug; see projects), or set a default")
	}
	if !slugRe.MatchString(s) {
		return project{}, fmt.Errorf("%q isn't a project id or slug", s)
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return project{}, err
	}
	for _, p := range ps {
		if p.id() == s || p.Slug == s {
			return p, nil
		}
	}
	return project{}, fmt.Errorf("there's no project %q the identity is in", s)
}

// place is a validated project, environment and folder path.
type place struct {
	proj project
	env  string
	path string
}

func (c *conn) place(ctx context.Context, p input) (place, error) {
	env := strings.TrimSpace(p.Environment)
	if env == "" {
		env = c.env
	}
	if env == "" {
		return place{}, errors.New("name the environment (its slug, like prod), or set a default")
	}
	if !slugRe.MatchString(env) {
		return place{}, fmt.Errorf("%q isn't an environment slug", env)
	}
	path, err := folderPath(p.Path)
	if err != nil {
		return place{}, err
	}
	proj, err := c.project(ctx, p.Project)
	if err != nil {
		return place{}, err
	}
	known := len(proj.Environments) == 0
	for _, e := range proj.Environments {
		known = known || e.Slug == env
	}
	if !known {
		return place{}, fmt.Errorf("project %s has no environment %q", proj.Name, env)
	}
	return place{proj: proj, env: env, path: path}, nil
}

// folderPath checks a path like /app/db and returns it with a leading slash.
func folderPath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "/", nil
	}
	if len(s) > 1024 {
		return "", errors.New("the path is too long")
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." || !segRe.MatchString(seg) {
			return "", fmt.Errorf("%q isn't a folder path (letters, digits and _ . - between slashes)", s)
		}
	}
	return "/" + s, nil
}

func validKey(k string) bool {
	return k != "" && len(k) <= 256 && k != "." && k != ".." && !strings.ContainsAny(k, `/\?#%`) &&
		!strings.ContainsFunc(k, func(r rune) bool { return r <= 0x20 || r == 0x7f })
}

func (pl place) query() url.Values {
	return url.Values{"workspaceId": {pl.proj.id()}, "environment": {pl.env}, "secretPath": {pl.path}}
}

type secretMeta struct {
	ID        string `json:"id"`
	OldID     string `json:"_id"`
	Key       string `json:"secretKey"`
	Value     string `json:"secretValue"`   // only read by reveal_secret
	Comment   string `json:"secretComment"` // never returned
	Version   int    `json:"version"`
	Type      string `json:"type"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	Tags      []struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"tags"`
}

func (s secretMeta) id() string {
	if s.ID != "" {
		return s.ID
	}
	return s.OldID
}

func (c *conn) list(ctx context.Context, pl place) ([]secretMeta, error) {
	q := pl.query()
	// Ask the server to leave values out (servers that predate the flag
	// ignore it; the values are dropped here either way).
	q.Set("viewSecretValue", "false")
	q.Set("include_imports", "false")
	q.Set("expandSecretReferences", "false")
	var out struct {
		Secrets []secretMeta `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v3/secrets/raw", q, &out); err != nil {
		return nil, friendly(err, "folder "+pl.path+" in "+pl.env)
	}
	sort.Slice(out.Secrets, func(i, j int) bool { return out.Secrets[i].Key < out.Secrets[j].Key })
	return out.Secrets, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/status", nil, nil, nil); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d project(s)", len(ps))}
}

type input struct {
	Project     string   `json:"project"`
	Environment string   `json:"environment"`
	Path        string   `json:"path"`
	Key         string   `json:"key"`
	Keys        []string `json:"keys"`
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
		var st struct {
			Date             string `json:"date"`
			Message          string `json:"message"`
			Email            bool   `json:"emailConfigured"`
			Redis            bool   `json:"redisConfigured"`
			SecretScanning   bool   `json:"secretScanningConfigured"`
			InviteOnlySignup bool   `json:"inviteOnlySignup"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/status", nil, &st); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"message": st.Message, "date": st.Date, "emailConfigured": st.Email, "redisConfigured": st.Redis, "secretScanningConfigured": st.SecretScanning, "inviteOnlySignup": st.InviteOnlySignup})

	case "projects":
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, pr := range ps {
			envs := []string{}
			for _, e := range pr.Environments {
				envs = append(envs, e.Slug)
			}
			e := map[string]any{"id": pr.id(), "name": pr.Name, "slug": pr.Slug, "environments": envs, "created": pr.CreatedAt, "updated": pr.UpdatedAt}
			if pr.Type != "" {
				e["type"] = pr.Type
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"projects": list})

	case "environments":
		pr, err := c.project(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		envs := []map[string]any{}
		for _, e := range pr.Environments {
			envs = append(envs, map[string]any{"id": e.ID, "name": e.Name, "slug": e.Slug})
		}
		return sdk.JSON(map[string]any{"project": pr.Name, "environments": envs})

	case "secrets":
		pl, err := c.place(ctx, p)
		if err != nil {
			return sdk.Result{}, err
		}
		ss, err := c.list(ctx, pl)
		if err != nil {
			return sdk.Result{}, err
		}
		var folders struct {
			Folders []struct {
				Name string `json:"name"`
			} `json:"folders"`
		}
		fq := url.Values{"workspaceId": {pl.proj.id()}, "environment": {pl.env}, "path": {pl.path}}
		folderErr := c.do(ctx, http.MethodGet, "/api/v1/folders", fq, &folders)
		list := []map[string]any{}
		for i, s := range ss {
			if i == maxSecrets {
				break
			}
			e := map[string]any{"key": s.Key, "id": s.id(), "version": s.Version, "type": s.Type, "created": s.CreatedAt, "updated": s.UpdatedAt}
			if len(s.Tags) > 0 {
				tags := []string{}
				for _, t := range s.Tags {
					tags = append(tags, t.Slug)
				}
				e["tags"] = tags
			}
			list = append(list, e)
		}
		fl := []string{}
		for _, f := range folders.Folders {
			fl = append(fl, f.Name)
		}
		sort.Strings(fl)
		out := map[string]any{"project": pl.proj.Name, "environment": pl.env, "path": pl.path, "count": len(ss), "secrets": list, "folders": fl}
		if folderErr != nil {
			out["foldersError"] = friendly(folderErr, "folder list").Error()
		}
		if len(ss) > maxSecrets {
			out["truncated"] = true
		}
		return sdk.JSON(out)

	case "versions":
		if !validKey(p.Key) {
			return sdk.Result{}, errors.New("name the secret's key (secrets lists them)")
		}
		pl, err := c.place(ctx, p)
		if err != nil {
			return sdk.Result{}, err
		}
		ss, err := c.list(ctx, pl)
		if err != nil {
			return sdk.Result{}, err
		}
		sid := ""
		for _, s := range ss {
			if s.Key == p.Key && (s.Type == "" || s.Type == "shared") {
				sid = s.id()
			}
		}
		if sid == "" || !idRe.MatchString(sid) {
			return sdk.Result{}, fmt.Errorf("there's no secret %s in %s %s", p.Key, pl.env, pl.path)
		}
		var out struct {
			Versions []struct {
				Version   int    `json:"version"`
				Type      string `json:"type"`
				CreatedAt string `json:"createdAt"`
				UpdatedAt string `json:"updatedAt"`
				Actor     *struct {
					ActorType string `json:"actorType"`
					Name      string `json:"name"`
				} `json:"actor"`
			} `json:"secretVersions"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v1/secret/"+sid+"/secret-versions", url.Values{"offset": {"0"}, "limit": {fmt.Sprint(maxVersions)}}, &out); err != nil {
			return sdk.Result{}, friendly(err, "version history of "+p.Key)
		}
		vs := []map[string]any{}
		for _, v := range out.Versions {
			e := map[string]any{"version": v.Version, "created": v.CreatedAt, "updated": v.UpdatedAt}
			if v.Type != "" {
				e["type"] = v.Type
			}
			if v.Actor != nil && v.Actor.ActorType != "" {
				e["actor"] = strings.TrimSpace(v.Actor.ActorType + " " + v.Actor.Name)
			}
			vs = append(vs, e)
		}
		sort.Slice(vs, func(i, j int) bool { return vs[i]["version"].(int) > vs[j]["version"].(int) })
		return sdk.JSON(map[string]any{"key": p.Key, "environment": pl.env, "path": pl.path, "versions": vs})

	case "reveal_secret":
		if len(p.Keys) == 0 {
			return sdk.Result{}, errors.New("name the secrets whose values to reveal (secrets lists their keys)")
		}
		if len(p.Keys) > maxReveal {
			return sdk.Result{}, fmt.Errorf("reveal up to %d secrets at a time", maxReveal)
		}
		for _, k := range p.Keys {
			if !validKey(k) {
				return sdk.Result{}, fmt.Errorf("%q isn't a secret key", k)
			}
		}
		pl, err := c.place(ctx, p)
		if err != nil {
			return sdk.Result{}, err
		}
		vals := map[string]string{}
		var missing []string
		for _, k := range p.Keys {
			if _, ok := vals[k]; ok {
				continue
			}
			q := pl.query()
			q.Set("type", "shared")
			q.Set("include_imports", "false")
			var out struct {
				Secret secretMeta `json:"secret"`
			}
			err := c.do(ctx, http.MethodGet, "/api/v3/secrets/raw/"+url.PathEscape(k), q, &out)
			if rest.IsStatus(err, http.StatusNotFound) || (err == nil && out.Secret.Key != k) {
				missing = append(missing, k)
				continue
			}
			if err != nil {
				return sdk.Result{}, friendly(err, "secret "+k)
			}
			vals[k] = out.Secret.Value
		}
		out := map[string]any{"project": pl.proj.Name, "environment": pl.env, "path": pl.path, "values": vals}
		if len(missing) > 0 {
			out["missing"] = missing
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
