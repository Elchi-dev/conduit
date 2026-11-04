// Package launchdarkly works with LaunchDarkly through its REST API and an
// API access token: projects, environments (never their SDK, mobile or
// client-side keys), flags with their state in an environment (counts of
// targets and rules, never who they match), and turning a flag on or off in
// one environment with a JSON Patch that first tests the switch is still as
// it was read.
//
// Turning a flag on or off changes what users get right away, so both are
// destructive; each is the other's undo.
package launchdarkly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one LaunchDarkly account.
type Config struct {
	Token  string `json:"token"`  // secret:// API access token
	Region string `json:"region"` // "", "us", "eu" or "federal"
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host, and Base the API address
	// (tests).
	HTTP *http.Client
	Base string
}

// New returns the LaunchDarkly module.
func New() *Module { return &Module{} }

var regions = map[string]string{"": "https://app.launchdarkly.com", "us": "https://app.launchdarkly.com", "eu": "https://app.eu.launchdarkly.com", "federal": "https://app.launchdarkly.us"}

// keyRe matches LaunchDarkly project, environment and flag keys.
var keyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

// jsonPointer escapes a key for a JSON Pointer (RFC 6901). keyRe already
// leaves out both characters; this keeps the patch right if it ever doesn't.
var jsonPointer = strings.NewReplacer("~", "~0", "/", "~1")

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project key (from projects), e.g. default"}`
	env := `"environment":{"type":"string","description":"Environment key, e.g. production"}`
	flag := `"flag":{"type":"string","description":"The flag's key"}`
	toggle := sdk.Schema(`{"type":"object","required":["project","environment","flag"],"properties":{` + project + `,` + env + `,` + flag + `,"comment":{"type":"string","maxLength":500,"description":"Why, kept in the flag's history"}}}`)
	return sdk.Manifest{
		ID: "launchdarkly", Name: "LaunchDarkly", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "LaunchDarkly feature flags: projects, environments, flags with their state per environment; turn a flag on or off in an environment.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API access token (Organization settings, Authorization), with the Reader role to look, Writer to turn flags on and off"},
			"region":{"type":"string","enum":["us","eu","federal"],"default":"us","description":"us (app.launchdarkly.com), eu (app.eu.launchdarkly.com) or federal (app.launchdarkly.us)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their key, name and tags.", Risk: sdk.RiskRead},
			{Name: "environments", Title: "Environments", Description: "A project's environments: key, name, whether critical, and whether changes need a comment or confirmation. Never their SDK keys.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)},
			{Name: "flags", Title: "Flags", Description: "A project's flags with whether each is on in an environment, kind, temporary and tags.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project","environment"],"properties":{` + project + `,` + env + `}}`)},
			{Name: "flag", Title: "Flag", Description: "One flag in an environment: on or off, variations by name, and how many individual targets and rules it has (never who they match).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project","environment","flag"],"properties":{` + project + `,` + env + `,` + flag + `}}`)},
			{Name: "turn_on", Title: "Turn a flag on", Description: "Turns a flag's targeting on in one environment; users get it right away. The preview names project, environment and flag with the state before and after. Undo turns it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
			{Name: "turn_off", Title: "Turn a flag off", Description: "Turns a flag's targeting off in one environment, so everyone gets its off variation right away. The preview names project, environment and flag with the state before and after. Undo turns it on again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	site, ok := regions[strings.ToLower(strings.TrimSpace(c.Region))]
	if !ok {
		return errors.New("the region is us, eu or federal")
	}
	if m.Base != "" {
		site = m.Base
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API access token in the vault and enter its secret:// reference")
	}
	ref := c.Token
	api := rest.New(site+"/api/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("LaunchDarkly refused the API access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("LaunchDarkly refused: %v (does the token's role allow this?)", err)
	case rest.IsStatus(err, http.StatusNotFound) && what != "":
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusMethodNotAllowed):
		return errors.New("this environment needs an approval request for flag changes; ask for one in LaunchDarkly")
	case rest.IsStatus(err, http.StatusConflict):
		return errors.New("the flag changed in LaunchDarkly while this ran; look at it again and retry")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("LaunchDarkly's rate limit was hit; try again in a minute")
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

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Items      []json.RawMessage `json:"items"`
		TotalCount *int              `json:"totalCount"`
	}
	if err := c.get(ctx, "/projects", url.Values{"limit": {"1000"}}, &a, ""); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	n := len(a.Items)
	if a.TotalCount != nil {
		n = *a.TotalCount
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d projects", n)}
}

// flagEnv is a flag's configuration in one environment. Targets and rules
// are decoded only far enough to count them: their values are user and
// context keys, emails and the like.
type flagEnv struct {
	On           bool  `json:"on"`
	Archived     bool  `json:"archived"`
	LastModified int64 `json:"lastModified"`
	Version      int   `json:"_version"`
	OffVariation *int  `json:"offVariation"`
	Targets      []struct {
		Values []json.RawMessage `json:"values"`
	} `json:"targets"`
	ContextTargets []struct {
		Values []json.RawMessage `json:"values"`
	} `json:"contextTargets"`
	Rules []struct {
		Clauses []json.RawMessage `json:"clauses"`
		Rollout json.RawMessage   `json:"rollout"`
	} `json:"rules"`
	Fallthrough struct {
		Variation *int            `json:"variation"`
		Rollout   json.RawMessage `json:"rollout"`
	} `json:"fallthrough"`
	Prerequisites []json.RawMessage `json:"prerequisites"`
}

type flag struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Temporary  bool     `json:"temporary"`
	Archived   bool     `json:"archived"`
	Deprecated bool     `json:"deprecated"`
	Tags       []string `json:"tags"`
	Variations []struct {
		Name string `json:"name"`
		// The value isn't decoded: a JSON variation can carry configuration.
	} `json:"variations"`
	Environments map[string]flagEnv `json:"environments"`
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
		Flag        string `json:"flag"`
		Comment     string `json:"comment"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Project, p.Environment, p.Flag = strings.TrimSpace(p.Project), strings.TrimSpace(p.Environment), strings.TrimSpace(p.Flag)
	// Check everything the action takes before the first request.
	var needEnv, needFlag bool
	switch call.Action {
	case "projects":
	case "environments":
	case "flags":
		needEnv = true
	case "flag", "turn_on", "turn_off":
		needEnv, needFlag = true, true
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if call.Action != "projects" && !keyRe.MatchString(p.Project) {
		return sdk.Result{}, errors.New("the project is its key (letters, digits, . _ -), from projects")
	}
	if needEnv && !keyRe.MatchString(p.Environment) {
		return sdk.Result{}, errors.New("the environment is its key, e.g. production")
	}
	if needFlag && !keyRe.MatchString(p.Flag) {
		return sdk.Result{}, errors.New("the flag is its key (letters, digits, . _ -)")
	}
	if len([]rune(p.Comment)) > 500 || strings.ContainsAny(p.Comment, "\x00\r") {
		return sdk.Result{}, errors.New("the comment is one paragraph up to 500 characters")
	}
	proj := url.PathEscape(p.Project)

	switch call.Action {
	case "projects":
		var a struct {
			Items []struct {
				Key  string   `json:"key"`
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/projects", url.Values{"limit": {"1000"}}, &a, ""); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range a.Items {
			out = append(out, map[string]any{"key": x.Key, "name": clip(x.Name, 200), "tags": x.Tags})
		}
		return sdk.JSON(out)

	case "environments":
		// Field by field: the SDK key, mobile key and client-side id are
		// never read.
		var a struct {
			Items []struct {
				Key              string   `json:"key"`
				Name             string   `json:"name"`
				Color            string   `json:"color"`
				Critical         bool     `json:"critical"`
				RequireComments  bool     `json:"requireComments"`
				ConfirmChanges   bool     `json:"confirmChanges"`
				Tags             []string `json:"tags"`
				ApprovalSettings *struct {
					Required bool `json:"required"`
				} `json:"approvalSettings"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/projects/"+proj+"/environments", url.Values{"limit": {"200"}}, &a, "project "+p.Project); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range a.Items {
			row := map[string]any{"key": e.Key, "name": clip(e.Name, 200), "critical": e.Critical, "requireComments": e.RequireComments, "confirmChanges": e.ConfirmChanges, "tags": e.Tags}
			if e.ApprovalSettings != nil {
				row["approvalRequired"] = e.ApprovalSettings.Required
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"project": p.Project, "environments": out})

	case "flags":
		var a struct {
			Items []flag `json:"items"`
		}
		q := url.Values{"env": {p.Environment}, "summary": {"true"}, "limit": {"100"}}
		out := []map[string]any{}
		on := 0
		for offset := 0; offset < 2000; offset += 100 {
			a.Items = nil
			q.Set("offset", fmt.Sprint(offset))
			if err := c.get(ctx, "/flags/"+proj, q, &a, "project "+p.Project); err != nil {
				return sdk.Result{}, err
			}
			for _, f := range a.Items {
				e, ok := f.Environments[p.Environment]
				row := map[string]any{"key": f.Key, "name": clip(f.Name, 200), "kind": f.Kind, "temporary": f.Temporary, "tags": f.Tags}
				if ok {
					row["on"] = e.On
					if e.On {
						on++
					}
					if t := when(e.LastModified); t != "" {
						row["modified"] = t
					}
				}
				out = append(out, row)
			}
			if len(a.Items) < 100 {
				break
			}
		}
		return sdk.JSON(map[string]any{"project": p.Project, "environment": p.Environment, "flags": out, "on": on, "off": len(out) - on})

	case "flag":
		f, e, err := c.flag(ctx, p.Project, p.Environment, p.Flag)
		if err != nil {
			return sdk.Result{}, err
		}
		vars := []string{}
		for i, v := range f.Variations {
			if v.Name != "" {
				vars = append(vars, clip(v.Name, 100))
			} else {
				vars = append(vars, fmt.Sprintf("variation %d", i))
			}
		}
		targets := 0
		for _, t := range e.Targets {
			targets += len(t.Values)
		}
		for _, t := range e.ContextTargets {
			targets += len(t.Values)
		}
		rules := []map[string]any{}
		for _, r := range e.Rules {
			rules = append(rules, map[string]any{"clauses": len(r.Clauses), "rollout": len(r.Rollout) > 0 && string(r.Rollout) != "null"})
		}
		fall := "variation"
		if len(e.Fallthrough.Rollout) > 0 && string(e.Fallthrough.Rollout) != "null" {
			fall = "rollout"
		}
		o := map[string]any{"project": p.Project, "environment": p.Environment, "key": f.Key, "name": clip(f.Name, 200), "kind": f.Kind, "temporary": f.Temporary,
			"archived": f.Archived, "tags": f.Tags, "variations": vars, "on": e.On, "version": e.Version, "individualTargets": targets, "rules": rules,
			"defaultRule": fall, "prerequisites": len(e.Prerequisites)}
		if e.OffVariation != nil && *e.OffVariation >= 0 && *e.OffVariation < len(vars) {
			o["offVariation"] = vars[*e.OffVariation]
		}
		if e.Fallthrough.Variation != nil && *e.Fallthrough.Variation >= 0 && *e.Fallthrough.Variation < len(vars) {
			o["defaultVariation"] = vars[*e.Fallthrough.Variation]
		}
		if t := when(e.LastModified); t != "" {
			o["modified"] = t
		}
		return sdk.JSON(o)
	}
	return c.toggle(ctx, call, p.Project, p.Environment, p.Flag, p.Comment)
}

func (c *conn) flag(ctx context.Context, proj, env, key string) (flag, flagEnv, error) {
	var f flag
	if err := c.get(ctx, "/flags/"+url.PathEscape(proj)+"/"+url.PathEscape(key), url.Values{"env": {env}}, &f, "flag "+key+" in project "+proj); err != nil {
		return f, flagEnv{}, err
	}
	if f.Key != key {
		// The key goes into the update's path and the undo.
		return f, flagEnv{}, fmt.Errorf("LaunchDarkly answered with another flag for %s", key)
	}
	e, ok := f.Environments[env]
	if !ok {
		return f, e, fmt.Errorf("project %s has no environment %s", proj, env)
	}
	return f, e, nil
}

func (c *conn) toggle(ctx context.Context, call sdk.Call, proj, env, key, comment string) (sdk.Result, error) {
	on := call.Action == "turn_on"
	f, e, err := c.flag(ctx, proj, env, key)
	if err != nil {
		return sdk.Result{}, err
	}
	if e.On == on {
		return sdk.JSON(map[string]any{"project": proj, "environment": env, "flag": f.Key, "on": on, "note": "nothing to change"})
	}
	word, back := map[bool]string{true: "on", false: "off"}[on], map[bool]string{true: "turn_off", false: "turn_on"}[on]
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn flag %s %s in %s (project %s); users get the change right away", f.Key, word, env, proj),
			Changes: []sdk.Change{{Target: fmt.Sprintf("flag %s in project %s, environment %s", f.Key, proj, env), Op: "turn " + word,
				Before: mustJSON(map[string]any{"on": e.On, "version": e.Version}), After: mustJSON(map[string]any{"on": on})}}}}, nil
	}
	if comment == "" {
		comment = "Turned " + word + " through Conduit"
	}
	// A JSON Patch that touches only this environment's on switch, with a
	// test first: LaunchDarkly applies it only if the switch is still as it
	// was read, so a change someone made in the meantime isn't overwritten,
	// and rules, targets and variations stay as they are.
	ptr := "/environments/" + jsonPointer.Replace(env) + "/on"
	body := map[string]any{"comment": comment, "patch": []map[string]any{
		{"op": "test", "path": ptr, "value": e.On},
		{"op": "replace", "path": ptr, "value": on},
	}}
	var after flag
	if _, err := c.api.Do(ctx, http.MethodPatch, "/flags/"+url.PathEscape(proj)+"/"+url.PathEscape(f.Key), nil, body, &after); err != nil {
		// No retry: a 405 means the environment needs an approval request,
		// and a failed test means the flag changed since it was read.
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusConflict) {
			if _, now, rerr := c.flag(ctx, proj, env, key); rerr == nil && now.On != e.On {
				return sdk.Result{}, fmt.Errorf("flag %s was turned %s in %s by someone else since it was read; nothing was changed", f.Key, word, env)
			}
		}
		return sdk.Result{}, friendly(err, "flag "+f.Key+" in project "+proj)
	}
	if ae, ok := after.Environments[env]; ok && ae.On != on {
		return sdk.Result{}, fmt.Errorf("LaunchDarkly kept flag %s %s in %s", f.Key, map[bool]string{true: "off", false: "on"}[on], env)
	}
	out, err := sdk.JSON(map[string]any{"project": proj, "environment": env, "flag": f.Key, "on": on, "before": e.On})
	out.Undo = sdk.UndoWith(back, map[string]string{"project": proj, "environment": env, "flag": f.Key},
		fmt.Sprintf("Turn %s %s again in %s", f.Key, map[bool]string{true: "off", false: "on"}[on], env))
	return out, err
}
