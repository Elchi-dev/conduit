// Package growthbook works with GrowthBook (cloud or self-hosted) through
// its REST API and a secret API key: features with their state in each
// environment (rules counted by kind, never their conditions or values),
// turning a feature on or off in one environment, and experiments with
// their status and variations.
//
// Turning a feature on or off changes what users get right away, so both
// are destructive; each is the other's undo.
package growthbook

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GrowthBook organization.
type Config struct {
	URL                string `json:"url"`    // default https://api.growthbook.io; self-hosted: the API address (port 3100)
	APIKey             string `json:"apiKey"` // secret:// secret API key
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

// New returns the GrowthBook module.
func New() *Module { return &Module{} }

var (
	pathRe    = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
	featureRe = regexp.MustCompile(`^[A-Za-z0-9_.:|-]{1,200}$`)
	envRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	feature := `"feature":{"type":"string","description":"The feature's key (id)"}`
	env := `"environment":{"type":"string","description":"Environment id, e.g. production"}`
	project := `"project":{"type":"string","description":"Only this project (its id, prj_…)"}`
	toggle := sdk.Schema(`{"type":"object","required":["feature","environment"],"properties":{` + feature + `,` + env + `,"reason":{"type":"string","maxLength":300,"description":"Why, kept in the feature's audit log"}}}`)
	return sdk.Manifest{
		ID: "growthbook", Name: "GrowthBook", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "GrowthBook: features with their state per environment, turning a feature on or off in an environment, and experiments with status and variations.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"url":{"type":"string","default":"https://api.growthbook.io","description":"GrowthBook Cloud, or your GrowthBook API's address, e.g. https://growthbook-api.example.com (port 3100 by default)"},
			"apiKey":{"type":"string","x-secret":true,"description":"A secret API key (Settings, API Keys), read-only to look, admin to turn features on and off"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "features", Title: "Features", Description: "Features with value type, project, tags, whether archived, and in each environment whether it's on and how many rules of which kind it has.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
			{Name: "turn_on", Title: "Turn a feature on", Description: "Turns a feature on in one environment; users get its rules right away. The preview names project, environment and feature with the state before and after. Undo turns it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
			{Name: "turn_off", Title: "Turn a feature off", Description: "Turns a feature off in one environment, so users get no value from it right away. The preview names project, environment and feature with the state before and after. Undo turns it on again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
			{Name: "experiments", Title: "Experiments", Description: "Experiments: name, tracking key, status, project, variations, phases with coverage, and the result once decided.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
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
		c.URL = "https://api.growthbook.io"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "/..") {
		return errors.New("the address is like https://growthbook-api.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the secret API key in the vault and enter its secret:// reference")
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
	ref := c.APIKey
	base := strings.TrimRight(u.Path, "/")
	base = strings.TrimSuffix(strings.TrimSuffix(base, "/v1"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
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
		return errors.New("GrowthBook refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("GrowthBook refused: %v (is it an admin key, and does the feature need an approved draft?)", err)
	case rest.IsStatus(err, http.StatusNotFound) && what != "":
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("GrowthBook's rate limit was hit; try again in a minute")
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

// featureEnv is a feature in one environment. Rules are decoded only for
// their kind and whether they're on: conditions name users (emails, ids)
// and values can carry configuration.
type featureEnv struct {
	Enabled bool `json:"enabled"`
	Rules   []struct {
		Type    string `json:"type"`
		Enabled *bool  `json:"enabled"`
	} `json:"rules"`
}

type feature struct {
	ID           string                `json:"id"`
	Description  string                `json:"description"`
	Archived     bool                  `json:"archived"`
	ValueType    string                `json:"valueType"`
	Project      string                `json:"project"`
	Tags         []string              `json:"tags"`
	DateUpdated  string                `json:"dateUpdated"`
	Environments map[string]featureEnv `json:"environments"`
}

func (f feature) out() map[string]any {
	envs := map[string]any{}
	for name, e := range f.Environments {
		kinds := map[string]int{}
		for _, r := range e.Rules {
			if r.Enabled == nil || *r.Enabled {
				kinds[r.Type]++
			}
		}
		envs[name] = map[string]any{"enabled": e.Enabled, "rules": len(e.Rules), "activeRulesByKind": kinds}
	}
	o := map[string]any{"key": f.ID, "valueType": f.ValueType, "archived": f.Archived, "tags": f.Tags, "environments": envs}
	if f.Project != "" {
		o["project"] = f.Project
	}
	if f.Description != "" {
		o["description"] = clip(f.Description, 300)
	}
	if f.DateUpdated != "" {
		o["updated"] = f.DateUpdated
	}
	return o
}

// pages reads a GrowthBook list (limit/offset with hasMore) into key.
func pages[T any](ctx context.Context, c *conn, path, key string, q url.Values) ([]T, int, error) {
	var all []T
	total := 0
	for offset := 0; offset < 5000; {
		q.Set("limit", "100")
		q.Set("offset", strconv.Itoa(offset))
		var raw map[string]json.RawMessage
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &raw); err != nil {
			return nil, 0, friendly(err, "")
		}
		var items []T
		if err := json.Unmarshal(raw[key], &items); err != nil && len(raw[key]) > 0 {
			return nil, 0, fmt.Errorf("unexpected answer from GrowthBook: %w", err)
		}
		all = append(all, items...)
		var more bool
		var next *int
		json.Unmarshal(raw["hasMore"], &more)
		json.Unmarshal(raw["nextOffset"], &next)
		json.Unmarshal(raw["total"], &total)
		if !more || len(items) == 0 {
			break
		}
		if next != nil && *next > offset {
			offset = *next
		} else {
			offset += len(items)
		}
	}
	if total < len(all) {
		total = len(all)
	}
	return all, total, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Features []json.RawMessage `json:"features"`
		Total    *int              `json:"total"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/features", url.Values{"limit": {"1"}}, nil, &a); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no GrowthBook API at this address"}
		}
		return sdk.Health{Status: "down", Message: friendly(err, "").Error()}
	}
	if a.Total == nil {
		return sdk.Health{Status: "ok", Message: "GrowthBook answers"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d features", *a.Total)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Feature     string `json:"feature"`
		Environment string `json:"environment"`
		Project     string `json:"project"`
		Reason      string `json:"reason"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Feature, p.Environment, p.Project = strings.TrimSpace(p.Feature), strings.TrimSpace(p.Environment), strings.TrimSpace(p.Project)
	// Check everything the action takes before the first request.
	switch call.Action {
	case "features", "experiments":
		if p.Project != "" && !idRe.MatchString(p.Project) {
			return sdk.Result{}, errors.New("the project is its id, like prj_abc123")
		}
	case "turn_on", "turn_off":
		if !featureRe.MatchString(p.Feature) {
			return sdk.Result{}, errors.New("the feature is its key (letters, digits, _ - . : |)")
		}
		if !envRe.MatchString(p.Environment) {
			return sdk.Result{}, errors.New("the environment is its id, e.g. production")
		}
		if len([]rune(p.Reason)) > 300 || strings.ContainsAny(p.Reason, "\x00\r\n") {
			return sdk.Result{}, errors.New("the reason is one line up to 300 characters")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	q := url.Values{}
	if p.Project != "" {
		q.Set("projectId", p.Project)
	}

	switch call.Action {
	case "features":
		fs, total, err := pages[feature](ctx, c, "/features", "features", q)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, f := range fs {
			out = append(out, f.out())
		}
		return sdk.JSON(map[string]any{"features": out, "total": total})

	case "experiments":
		type experiment struct {
			ID          string   `json:"id"`
			TrackingKey string   `json:"trackingKey"`
			Name        string   `json:"name"`
			Type        string   `json:"type"`
			Project     string   `json:"project"`
			Hypothesis  string   `json:"hypothesis"`
			Tags        []string `json:"tags"`
			Archived    bool     `json:"archived"`
			Status      string   `json:"status"`
			DateUpdated string   `json:"dateUpdated"`
			Variations  []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"variations"`
			Phases []struct {
				Name          string   `json:"name"`
				DateStarted   string   `json:"dateStarted"`
				DateEnded     string   `json:"dateEnded"`
				Coverage      *float64 `json:"coverage"`
				ReasonStopped string   `json:"reasonForStopping"`
				// targetingCondition and namespaces aren't decoded: a
				// condition can name users.
			} `json:"phases"`
			ResultSummary *struct {
				Status   string `json:"status"`
				Winner   string `json:"winner"`
				Released string `json:"releasedVariationId"`
			} `json:"resultSummary"`
		}
		es, total, err := pages[experiment](ctx, c, "/experiments", "experiments", q)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range es {
			vars := []string{}
			for _, v := range x.Variations {
				n := v.Name
				if n == "" {
					n = v.Key
				}
				vars = append(vars, clip(n, 100))
			}
			phases := []map[string]any{}
			for _, ph := range x.Phases {
				row := map[string]any{"name": clip(ph.Name, 100), "started": ph.DateStarted}
				if ph.DateEnded != "" {
					row["ended"] = ph.DateEnded
				}
				if ph.Coverage != nil {
					row["coverage"] = *ph.Coverage
				}
				if ph.ReasonStopped != "" {
					row["reasonStopped"] = clip(ph.ReasonStopped, 300)
				}
				phases = append(phases, row)
			}
			row := map[string]any{"id": x.ID, "name": clip(x.Name, 200), "trackingKey": x.TrackingKey, "status": x.Status, "archived": x.Archived,
				"variations": vars, "phases": phases, "tags": x.Tags}
			for k, v := range map[string]string{"type": x.Type, "project": x.Project, "updated": x.DateUpdated} {
				if v != "" {
					row[k] = v
				}
			}
			if x.Hypothesis != "" {
				row["hypothesis"] = clip(x.Hypothesis, 300)
			}
			if x.ResultSummary != nil && x.ResultSummary.Status != "" {
				row["result"] = map[string]string{"status": x.ResultSummary.Status, "winner": x.ResultSummary.Winner, "released": x.ResultSummary.Released}
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"experiments": out, "total": total})
	}
	return c.toggle(ctx, call, p.Feature, p.Environment, p.Reason)
}

func (c *conn) feature(ctx context.Context, key string) (feature, error) {
	var a struct {
		Feature feature `json:"feature"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/features/"+url.PathEscape(key), nil, nil, &a); err != nil {
		return a.Feature, friendly(err, "feature "+key)
	}
	if a.Feature.ID != key {
		// The key goes into the update's path and the undo.
		return a.Feature, fmt.Errorf("GrowthBook answered with another feature for %s", key)
	}
	return a.Feature, nil
}

func (c *conn) toggle(ctx context.Context, call sdk.Call, key, env, reason string) (sdk.Result, error) {
	on := call.Action == "turn_on"
	f, err := c.feature(ctx, key)
	if err != nil {
		return sdk.Result{}, err
	}
	e, ok := f.Environments[env]
	if !ok {
		names := []string{}
		for n := range f.Environments {
			names = append(names, n)
		}
		sort.Strings(names)
		return sdk.Result{}, fmt.Errorf("feature %s has no environment %s (it has: %s)", f.ID, env, strings.Join(names, ", "))
	}
	if e.Enabled == on {
		return sdk.JSON(map[string]any{"feature": f.ID, "environment": env, "enabled": on, "note": "nothing to change"})
	}
	word, back := map[bool]string{true: "on", false: "off"}[on], map[bool]string{true: "turn_off", false: "turn_on"}[on]
	proj := f.Project
	if proj == "" {
		proj = "none"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn feature %s %s in %s (project %s); users get the change right away", f.ID, word, env, proj),
			Changes: []sdk.Change{{Target: fmt.Sprintf("feature %s in project %s, environment %s", f.ID, proj, env), Op: "turn " + word,
				Before: mustJSON(map[string]bool{"enabled": e.Enabled}), After: mustJSON(map[string]bool{"enabled": on})}}}}, nil
	}
	if reason == "" {
		reason = "Turned " + word + " through Conduit"
	}
	// The toggle endpoint changes only this environment's switch: rules
	// and values changed since the preview stay as they are.
	var after struct {
		Feature feature `json:"feature"`
	}
	body := map[string]any{"reason": reason, "environments": map[string]bool{env: on}}
	if _, err := c.api.Do(ctx, http.MethodPost, "/features/"+url.PathEscape(f.ID)+"/toggle", nil, body, &after); err != nil {
		return sdk.Result{}, friendly(err, "feature "+f.ID)
	}
	if ae, ok := after.Feature.Environments[env]; ok && ae.Enabled != on {
		return sdk.Result{}, fmt.Errorf("GrowthBook kept feature %s %s in %s", f.ID, map[bool]string{true: "off", false: "on"}[on], env)
	}
	res, err := sdk.JSON(map[string]any{"feature": f.ID, "project": f.Project, "environment": env, "enabled": on, "before": e.Enabled})
	res.Undo = sdk.UndoWith(back, map[string]string{"feature": f.ID, "environment": env},
		fmt.Sprintf("Turn %s %s again in %s", f.ID, map[bool]string{true: "off", false: "on"}[on], env))
	return res, err
}
