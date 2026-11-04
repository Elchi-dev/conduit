// Package unleash works with an Unleash server (self-hosted or Unleash
// Cloud) through its admin API and an admin or personal access token:
// projects, features with their state in each environment, the activation
// strategies of a feature (kinds and counts, never the values its
// constraints match), and turning a feature on or off in one environment.
//
// Turning a feature on or off changes what users get right away, so both
// are destructive; each is the other's undo.
package unleash

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Unleash instance.
type Config struct {
	URL                string `json:"url"`   // e.g. https://unleash.example.com or https://eu.app.unleash-hosted.com/abc123
	Token              string `json:"token"` // secret:// admin or personal access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Unleash module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
	// Unleash requires URL-friendly names for projects, features and
	// environments.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","default":"default","description":"Project id (from projects)"}`
	feature := `"feature":{"type":"string","description":"The feature's name"}`
	env := `"environment":{"type":"string","description":"Environment name, e.g. production"}`
	toggle := sdk.Schema(`{"type":"object","required":["feature","environment"],"properties":{` + project + `,` + feature + `,` + env + `}}`)
	return sdk.Manifest{
		ID: "unleash", Name: "Unleash", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "Unleash feature flags: projects, features with their state per environment, strategies; turn a feature on or off in an environment.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your Unleash address, e.g. https://unleash.example.com, or your Unleash Cloud instance, e.g. https://eu.app.unleash-hosted.com/abc123"},
			"token":{"type":"string","x-secret":true,"description":"An admin API token or a personal access token (Admin, API access, or your profile); it acts with its role"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their feature and member counts and health.", Risk: sdk.RiskRead},
			{Name: "features", Title: "Features", Description: "A project's features: name, type, whether stale, and whether it's on in each environment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
			{Name: "strategies", Title: "Strategies", Description: "One feature's activation strategies per environment: kind, rollout, stickiness, and the kinds of constraints with how many values each matches (never the values).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["feature"],"properties":{` + project + `,` + feature + `,"environment":{"type":"string","description":"Only this environment"}}}`)},
			{Name: "turn_on", Title: "Turn a feature on", Description: "Turns a feature on in one environment; users get it right away. The preview names project, environment and feature with the state before and after. Undo turns it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
			{Name: "turn_off", Title: "Turn a feature off", Description: "Turns a feature off in one environment; users lose it right away. The preview names project, environment and feature with the state before and after. Undo turns it on again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "/..") {
		return errors.New("the address is like https://unleash.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/admin", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Unleash refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Unleash refused: %v (does the token's role allow this, or does the project need a change request?)", err)
	case rest.IsStatus(err, http.StatusNotFound) && what != "":
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Unleash's rate limit was hit; try again in a minute")
	}
	return err
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type project struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Health       *int   `json:"health"`
	FeatureCount int    `json:"featureCount"`
	MemberCount  int    `json:"memberCount"`
	Mode         string `json:"mode"`
}

func (c *conn) projects(ctx context.Context) ([]project, error) {
	var a struct {
		Projects []project `json:"projects"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/projects", nil, nil, &a); err != nil {
		return nil, friendly(err, "")
	}
	return a.Projects, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Unleash admin API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n := 0
	for _, p := range ps {
		n += p.FeatureCount
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d projects, %d features", len(ps), n)}
}

type strategy struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Disabled    bool           `json:"disabled"`
	Parameters  map[string]any `json:"parameters"`
	Constraints []struct {
		ContextName string   `json:"contextName"`
		Operator    string   `json:"operator"`
		Inverted    bool     `json:"inverted"`
		Values      []string `json:"values"`
		Value       string   `json:"value"`
	} `json:"constraints"`
	Segments []json.RawMessage `json:"segments"`
	Variants []json.RawMessage `json:"variants"`
}

type environment struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Enabled    bool       `json:"enabled"`
	Strategies []strategy `json:"strategies"`
}

type feature struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Project     string        `json:"project"`
	Stale       bool          `json:"stale"`
	Archived    bool          `json:"archived"`
	CreatedAt   string        `json:"createdAt"`
	LastSeenAt  string        `json:"lastSeenAt"`
	Environment []environment `json:"environments"`
}

// safeParams are the strategy parameters that say how a feature rolls out
// without naming users: user ids, IP addresses and host names are left out.
var safeParams = map[string]bool{"rollout": true, "stickiness": true, "groupId": true, "percentage": true}

func (s strategy) out() map[string]any {
	o := map[string]any{"kind": s.Name, "disabled": s.Disabled, "segments": len(s.Segments), "variants": len(s.Variants)}
	if s.Title != "" {
		o["title"] = clip(s.Title, 200)
	}
	params := map[string]any{}
	other := []string{}
	for k, v := range s.Parameters {
		if safeParams[k] {
			params[k] = v
		} else {
			other = append(other, k)
		}
	}
	if len(params) > 0 {
		o["parameters"] = params
	}
	if len(other) > 0 {
		sort.Strings(other)
		o["otherParameters"] = other // names only: their values can be user ids or addresses
	}
	cs := []map[string]any{}
	for _, x := range s.Constraints {
		n := len(x.Values)
		if n == 0 && x.Value != "" {
			n = 1
		}
		cs = append(cs, map[string]any{"context": clip(x.ContextName, 100), "operator": x.Operator, "inverted": x.Inverted, "values": n})
	}
	o["constraints"] = cs
	return o
}

func (c *conn) feature(ctx context.Context, proj, name string) (feature, error) {
	var f feature
	if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+url.PathEscape(proj)+"/features/"+url.PathEscape(name), nil, nil, &f); err != nil {
		return f, friendly(err, "feature "+name+" in project "+proj)
	}
	if f.Name != name {
		// The name goes into the update's path and the undo.
		return f, fmt.Errorf("Unleash answered with another feature for %s", name)
	}
	return f, nil
}

func envNames(es []environment) string {
	n := []string{}
	for _, e := range es {
		n = append(n, e.Name)
	}
	return strings.Join(n, ", ")
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project     string `json:"project"`
		Feature     string `json:"feature"`
		Environment string `json:"environment"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Project, p.Feature, p.Environment = strings.TrimSpace(p.Project), strings.TrimSpace(p.Feature), strings.TrimSpace(p.Environment)
	if p.Project == "" {
		p.Project = "default"
	}
	// Check everything the action takes before the first request.
	switch call.Action {
	case "projects":
	case "features", "strategies", "turn_on", "turn_off":
		if !nameRe.MatchString(p.Project) {
			return sdk.Result{}, errors.New("the project is its id (letters, digits, - _ . ~)")
		}
		if call.Action != "features" && !nameRe.MatchString(p.Feature) {
			return sdk.Result{}, errors.New("the feature is its name (letters, digits, - _ . ~)")
		}
		need := call.Action == "turn_on" || call.Action == "turn_off"
		if (need || p.Environment != "") && !nameRe.MatchString(p.Environment) {
			return sdk.Result{}, errors.New("the environment is its name, e.g. production")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}

	switch call.Action {
	case "projects":
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			row := map[string]any{"id": x.ID, "name": clip(x.Name, 200), "features": x.FeatureCount, "members": x.MemberCount}
			if x.Description != "" {
				row["description"] = clip(x.Description, 300)
			}
			if x.Health != nil {
				row["health"] = *x.Health
			}
			if x.Mode != "" {
				row["mode"] = x.Mode
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "features":
		var a struct {
			Features []feature `json:"features"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+url.PathEscape(p.Project)+"/features", nil, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "project "+p.Project)
		}
		out := []map[string]any{}
		for _, f := range a.Features {
			envs := map[string]bool{}
			for _, e := range f.Environment {
				envs[e.Name] = e.Enabled
			}
			row := map[string]any{"name": f.Name, "type": f.Type, "stale": f.Stale, "enabled": envs}
			if f.Description != "" {
				row["description"] = clip(f.Description, 300)
			}
			if f.LastSeenAt != "" {
				row["lastSeen"] = f.LastSeenAt
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"project": p.Project, "features": out})

	case "strategies":
		f, err := c.feature(ctx, p.Project, p.Feature)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range f.Environment {
			if p.Environment != "" && e.Name != p.Environment {
				continue
			}
			ss := []map[string]any{}
			for _, s := range e.Strategies {
				ss = append(ss, s.out())
			}
			out = append(out, map[string]any{"environment": e.Name, "type": e.Type, "enabled": e.Enabled, "strategies": ss})
		}
		if p.Environment != "" && len(out) == 0 {
			return sdk.Result{}, fmt.Errorf("feature %s has no environment %s (it has: %s)", f.Name, p.Environment, envNames(f.Environment))
		}
		return sdk.JSON(map[string]any{"project": p.Project, "feature": f.Name, "environments": out})
	}
	return c.toggle(ctx, call, p.Project, p.Feature, p.Environment)
}

func (c *conn) toggle(ctx context.Context, call sdk.Call, proj, name, env string) (sdk.Result, error) {
	on := call.Action == "turn_on"
	f, err := c.feature(ctx, proj, name)
	if err != nil {
		return sdk.Result{}, err
	}
	var e *environment
	for i := range f.Environment {
		if f.Environment[i].Name == env {
			e = &f.Environment[i]
		}
	}
	if e == nil {
		return sdk.Result{}, fmt.Errorf("feature %s has no environment %s (it has: %s)", f.Name, env, envNames(f.Environment))
	}
	if e.Enabled == on {
		return sdk.JSON(map[string]any{"project": proj, "feature": f.Name, "environment": env, "enabled": on, "note": "nothing to change"})
	}
	word, back := map[bool]string{true: "on", false: "off"}[on], map[bool]string{true: "turn_off", false: "turn_on"}[on]
	target := fmt.Sprintf("feature %s in project %s, environment %s", f.Name, proj, env)
	if e.Type != "" {
		target += " (" + e.Type + ")"
	}
	summary := fmt.Sprintf("Turn feature %s %s in %s (project %s); users get the change right away", f.Name, word, env, proj)
	if on {
		active := 0
		for _, s := range e.Strategies {
			if !s.Disabled {
				active++
			}
		}
		if active == 0 {
			// Unleash then adds the environment's default strategy (by
			// default a 100% rollout); turning it off again leaves that
			// strategy in place.
			summary += "; it has no active strategy, so Unleash adds its default strategy (usually everyone gets it)"
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary,
			Changes: []sdk.Change{{Target: target, Op: "turn " + word, Before: mustJSON(map[string]bool{"enabled": e.Enabled}), After: mustJSON(map[string]bool{"enabled": on})}}}}, nil
	}
	// The on and off endpoints change this environment's switch alone, so a
	// strategy or variant someone changed since the preview stays as it is.
	path := "/projects/" + url.PathEscape(proj) + "/features/" + url.PathEscape(f.Name) + "/environments/" + url.PathEscape(env) + "/" + word
	if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
		return sdk.Result{}, friendly(err, "feature "+f.Name+" in project "+proj)
	}
	// The endpoints answer with no body: read the feature back to be sure
	// the switch moved (a change request, for one, can leave it as it was).
	if g, err := c.feature(ctx, proj, f.Name); err == nil {
		for _, ge := range g.Environment {
			if ge.Name == env && ge.Enabled != on {
				return sdk.Result{}, fmt.Errorf("Unleash kept feature %s %s in %s", f.Name, map[bool]string{true: "off", false: "on"}[on], env)
			}
		}
	}
	res, err := sdk.JSON(map[string]any{"project": proj, "feature": f.Name, "environment": env, "enabled": on, "before": e.Enabled})
	res.Undo = sdk.UndoWith(back, map[string]string{"project": proj, "feature": f.Name, "environment": env},
		fmt.Sprintf("Turn %s %s again in %s", f.Name, map[bool]string{true: "off", false: "on"}[on], env))
	return res, err
}
