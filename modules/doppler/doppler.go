// Package doppler works with Doppler through its REST API: the token's own
// identity, projects, configs, secret names (never values or notes), the
// workplace activity log, and the values of named secrets only through the
// destructive reveal_secret. It never sets, deletes or rotates secrets and
// never changes access (tokens, service accounts, roles).
package doppler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Doppler token.
type Config struct {
	Token   string `json:"token"`   // secret:// service, service account or personal token
	Project string `json:"project"` // default project
	Config  string `json:"config"`  // default config, e.g. prd
}

type conn struct {
	api     *rest.Client
	project string
	config  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host, Base the API (tests).
	HTTP *http.Client
	Base string
}

// New returns the Doppler module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.doppler.com"
	maxReveal   = 10
	maxPages    = 20
)

var (
	slugRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,256}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	pc := `"project":{"type":"string","description":"Project slug (the instance's default when empty)"},"config":{"type":"string","description":"Config, e.g. dev or prd (the instance's default when empty)"}`
	return sdk.Manifest{
		ID: "doppler", Name: "Doppler", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "Doppler: the token's identity, projects, configs, secret names (never values), the activity log, revealing named secrets (destructive).",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A Doppler token: a service token (one config, read-only), a service account token or a personal token. Prefer a read-only one"},
			"project":{"type":"string","description":"Default project slug (a service token's own project when empty)"},
			"config":{"type":"string","description":"Default config, e.g. prd (a service token's own config when empty)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "me", Title: "This token", Description: "The token's type, name, workplace and when it was created and last used. Never the token.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "Projects with slug, name, description and creation time (needs a personal or service account token).", Risk: sdk.RiskRead},
			{Name: "configs", Title: "Configs", Description: "A project's configs with environment, root or branch, locked, and when they were last fetched.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project slug (the instance's default when empty)"}}}`)},
			{Name: "secret_names", Title: "Secret names", Description: "The names of a config's secrets. Never values or notes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + pc + `}}`)},
			{Name: "activity", Title: "Activity log", Description: "Recent workplace activity: what happened, who did it, the project, config and time (newest first).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Only entries for this project"},"page":{"type":"integer","minimum":1},"perPage":{"type":"integer","minimum":1,"maximum":100}}}`)},
			{Name: "reveal_secret", Title: "Reveal secret values", Description: "The values of the named secrets (up to 10) of one config, and only those; never notes. Revealing a credential is destructive: it can't be taken back.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["names"],"properties":{` + pc + `,"names":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":10,"description":"Secret names whose values to return"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the Doppler token in the vault and enter its secret:// reference")
	}
	proj, cfg := strings.TrimSpace(c.Project), strings.TrimSpace(c.Config)
	if proj != "" && !slugRe.MatchString(proj) {
		return errors.New("the default project is a project slug")
	}
	if cfg != "" && !slugRe.MatchString(cfg) {
		return errors.New("the default config is a config name, like prd")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, project: proj, config: cfg})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// dopplerMessage pulls Doppler's {"messages":["..."]} out of an API error.
func dopplerMessage(err error) string {
	var e *rest.Error
	if !errors.As(err, &e) {
		return ""
	}
	i := strings.Index(e.Message, "{")
	if i < 0 {
		return ""
	}
	var body struct {
		Messages []string `json:"messages"`
	}
	if json.Unmarshal([]byte(e.Message[i:]), &body) != nil || len(body.Messages) == 0 {
		return ""
	}
	return rest.Redact(strings.Join(body.Messages, "; "))
}

func friendly(err error, what string) error {
	if err == nil {
		return nil
	}
	msg := dopplerMessage(err)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Doppler refused the token (revoked or expired)")
	case rest.IsStatus(err, http.StatusForbidden):
		if msg != "" {
			return fmt.Errorf("the token has no access to %s: %s", what, msg)
		}
		return fmt.Errorf("the token has no access to %s", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case msg != "":
		return fmt.Errorf("Doppler: %s", msg)
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

type me struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
	Workplace  struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"workplace"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var who me
	if err := c.get(ctx, "/v3/me", nil, &who, "token info"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: strings.TrimSpace(strings.ReplaceAll(who.Type, "_", " ") + " " + who.Name + " · " + who.Workplace.Name)}
}

type input struct {
	Project string   `json:"project"`
	Config  string   `json:"config"`
	Names   []string `json:"names"`
	Page    int      `json:"page"`
	PerPage int      `json:"perPage"`
}

// scope returns the project and config query, falling back to the
// instance's defaults. Both may be empty for a service token, which is
// bound to one config.
func (c *conn) scope(p input, needConfig bool) (url.Values, string, string, error) {
	proj, cfg := strings.TrimSpace(p.Project), strings.TrimSpace(p.Config)
	if proj == "" {
		proj = c.project
	}
	if cfg == "" && needConfig {
		cfg = c.config
	}
	if proj != "" && !slugRe.MatchString(proj) {
		return nil, "", "", fmt.Errorf("%q isn't a project slug", proj)
	}
	if cfg != "" && !slugRe.MatchString(cfg) {
		return nil, "", "", fmt.Errorf("%q isn't a config name", cfg)
	}
	if (proj == "") != (cfg == "") && needConfig {
		return nil, "", "", errors.New("give both the project and the config (or neither, with a service token)")
	}
	q := url.Values{}
	if proj != "" {
		q.Set("project", proj)
	}
	if cfg != "" && needConfig {
		q.Set("config", cfg)
	}
	return q, proj, cfg, nil
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
	case "me":
		var who me
		if err := c.get(ctx, "/v3/me", nil, &who, "token info"); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"type": who.Type, "name": who.Name, "slug": who.Slug, "created": who.CreatedAt, "lastSeen": who.LastSeenAt, "workplace": who.Workplace.Name})

	case "projects":
		type proj struct {
			ID          string `json:"id"`
			Slug        string `json:"slug"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CreatedAt   string `json:"created_at"`
		}
		list := []map[string]any{}
		truncated := true
		for page := 1; page <= maxPages; page++ {
			var out struct {
				Projects []proj `json:"projects"`
			}
			if err := c.get(ctx, "/v3/projects", url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}, &out, "the project list"); err != nil {
				return sdk.Result{}, err
			}
			for _, pr := range out.Projects {
				list = append(list, map[string]any{"slug": pr.Slug, "name": pr.Name, "description": pr.Description, "created": pr.CreatedAt})
			}
			if len(out.Projects) < 100 {
				truncated = false
				break
			}
		}
		res := map[string]any{"projects": list}
		if truncated {
			res["truncated"] = true
		}
		return sdk.JSON(res)

	case "configs":
		q, proj, _, err := c.scope(p, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if proj == "" {
			return sdk.Result{}, errors.New("name the project (its slug; see projects), or set a default")
		}
		type cfg struct {
			Name        string `json:"name"`
			Environment string `json:"environment"`
			Root        bool   `json:"root"`
			Locked      bool   `json:"locked"`
			Inheritable bool   `json:"inheritable"`
			CreatedAt   string `json:"created_at"`
			InitialAt   string `json:"initial_fetch_at"`
			LastAt      string `json:"last_fetch_at"`
		}
		list := []map[string]any{}
		truncated := true
		for page := 1; page <= maxPages; page++ {
			q.Set("page", strconv.Itoa(page))
			q.Set("per_page", "100")
			var out struct {
				Configs []cfg `json:"configs"`
			}
			if err := c.get(ctx, "/v3/configs", q, &out, "project "+proj); err != nil {
				return sdk.Result{}, err
			}
			for _, cf := range out.Configs {
				e := map[string]any{"name": cf.Name, "environment": cf.Environment, "root": cf.Root, "locked": cf.Locked, "created": cf.CreatedAt, "lastFetched": cf.LastAt}
				if cf.Inheritable {
					e["inheritable"] = true
				}
				list = append(list, e)
			}
			if len(out.Configs) < 100 {
				truncated = false
				break
			}
		}
		res := map[string]any{"project": proj, "configs": list}
		if truncated {
			res["truncated"] = true
		}
		return sdk.JSON(res)

	case "secret_names":
		q, proj, cfg, err := c.scope(p, true)
		if err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Names []string `json:"names"`
		}
		if err := c.get(ctx, "/v3/configs/config/secrets/names", q, &out, "that config"); err != nil {
			return sdk.Result{}, err
		}
		sort.Strings(out.Names)
		if out.Names == nil {
			out.Names = []string{}
		}
		res := map[string]any{"names": out.Names}
		if proj != "" {
			res["project"], res["config"] = proj, cfg
		}
		return sdk.JSON(res)

	case "activity":
		if p.Page < 0 || p.PerPage < 0 || p.PerPage > 100 {
			return sdk.Result{}, errors.New("the page is 1 or more and perPage 1 to 100")
		}
		proj := strings.TrimSpace(p.Project)
		if proj != "" && !slugRe.MatchString(proj) {
			return sdk.Result{}, fmt.Errorf("%q isn't a project slug", proj)
		}
		page, per := max(p.Page, 1), p.PerPage
		if per == 0 {
			per = 20
		}
		var out struct {
			Logs []struct {
				ID        string `json:"id"`
				Text      string `json:"text"`
				CreatedAt string `json:"created_at"`
				Project   string `json:"enclave_project"`
				Config    string `json:"enclave_config"`
				Env       string `json:"enclave_environment"`
				User      *struct {
					Name     string `json:"name"`
					Username string `json:"username"`
				} `json:"user"`
			} `json:"logs"`
		}
		if err := c.get(ctx, "/v3/logs", url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(per)}}, &out, "the activity log"); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, l := range out.Logs {
			if proj != "" && l.Project != proj {
				continue
			}
			// The text is the server's ("Alice added a secret …"); redact
			// anything that looks like a credential, as for other free text.
			e := map[string]any{"id": l.ID, "text": rest.Redact(l.Text), "created": l.CreatedAt}
			if l.Project != "" {
				e["project"] = l.Project
			}
			if l.Config != "" {
				e["config"] = l.Config
			}
			if l.Env != "" {
				e["environment"] = l.Env
			}
			if l.User != nil {
				e["user"] = strings.TrimSpace(l.User.Name)
				if e["user"] == "" {
					e["user"] = l.User.Username
				}
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"page": page, "logs": list})

	case "reveal_secret":
		if len(p.Names) == 0 {
			return sdk.Result{}, errors.New("name the secrets whose values to reveal (secret_names lists them)")
		}
		if len(p.Names) > maxReveal {
			return sdk.Result{}, fmt.Errorf("reveal up to %d secrets at a time", maxReveal)
		}
		for _, n := range p.Names {
			if !nameRe.MatchString(n) {
				return sdk.Result{}, fmt.Errorf("%q isn't a secret name (letters, digits and underscores)", n)
			}
		}
		q, proj, cfg, err := c.scope(p, true)
		if err != nil {
			return sdk.Result{}, err
		}
		vals := map[string]string{}
		var missing []string
		for _, n := range p.Names {
			if _, ok := vals[n]; ok {
				continue
			}
			q.Set("name", n)
			var out struct {
				Name  string `json:"name"`
				Value struct {
					Raw      *string `json:"raw"`
					Computed *string `json:"computed"`
				} `json:"value"`
			}
			_, err := c.api.Do(ctx, http.MethodGet, "/v3/configs/config/secret", q, nil, &out)
			if rest.IsStatus(err, http.StatusNotFound) || (err == nil && out.Name != n) {
				missing = append(missing, n)
				continue
			}
			if err != nil {
				return sdk.Result{}, friendly(err, "secret "+n)
			}
			switch {
			case out.Value.Computed != nil:
				vals[n] = *out.Value.Computed
			case out.Value.Raw != nil:
				vals[n] = *out.Value.Raw
			default:
				missing = append(missing, n)
			}
		}
		res := map[string]any{"values": vals}
		if proj != "" {
			res["project"], res["config"] = proj, cfg
		}
		if len(missing) > 0 {
			res["missing"] = missing
		}
		return sdk.JSON(res)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
