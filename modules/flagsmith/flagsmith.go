// Package flagsmith works with Flagsmith (cloud or self-hosted) through its
// admin API and an organisation API key: projects, environments (never
// their client-side or server-side keys), flags with their state in an
// environment (segment and identity overrides counted, never listed), and
// turning a flag on or off in one environment.
//
// Turning a flag on or off changes what users get right away, so both are
// destructive; each is the other's undo.
package flagsmith

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Flagsmith organisation.
type Config struct {
	URL                string `json:"url"`    // default https://api.flagsmith.com; self-hosted: the API address
	APIKey             string `json:"apiKey"` // secret:// organisation (admin) API key
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

// New returns the Flagsmith module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
	idRe   = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	flagRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,150}$`)
	// envKeyRe checks the environment key Flagsmith returns before it goes
	// into a request path.
	envKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":["integer","string"],"description":"Project id (from projects)"}`
	env := `"environment":{"type":["string","integer"],"description":"Environment name, e.g. Production, or its id (from environments)"}`
	flag := `"flag":{"type":["string","integer"],"description":"The flag's name, or its id"}`
	toggle := sdk.Schema(`{"type":"object","required":["project","environment","flag"],"properties":{` + project + `,` + env + `,` + flag + `}}`)
	return sdk.Manifest{
		ID: "flagsmith", Name: "Flagsmith", Version: "0.1.0", Category: "Development", Icon: "rocket",
		Description: "Flagsmith feature flags: projects, environments, flags with their state per environment; turn a flag on or off in an environment.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"url":{"type":"string","default":"https://api.flagsmith.com","description":"Flagsmith Cloud, or your Flagsmith API's address, e.g. https://flagsmith.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An organisation API key (Organisation settings, API Keys); an admin key can change flags"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their id, name and organisation.", Risk: sdk.RiskRead},
			{Name: "environments", Title: "Environments", Description: "A project's environments: id, name, description and whether feature versioning is on. Never their keys.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)},
			{Name: "flags", Title: "Flags", Description: "A project's flags: name, type, description, tags and default; with an environment, whether each is on there and how many segment overrides it has.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `,` + env + `}}`)},
			{Name: "turn_on", Title: "Turn a flag on", Description: "Turns a flag on in one environment; users get it right away. The preview names project, environment and flag with the state before and after. Undo turns it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
			{Name: "turn_off", Title: "Turn a flag off", Description: "Turns a flag off in one environment; users lose it right away. The preview names project, environment and flag with the state before and after. Undo turns it on again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: toggle},
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
		c.URL = "https://api.flagsmith.com"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "/..") {
		return errors.New("the address is like https://flagsmith.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the organisation API key in the vault and enter its secret:// reference")
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
		r.Header.Set("Authorization", "Api-Key "+strings.TrimSpace(k))
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
		return errors.New("Flagsmith refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Flagsmith refused: %v (is it an admin organisation key?)", err)
	case rest.IsStatus(err, http.StatusNotFound) && what != "":
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Flagsmith's rate limit was hit; try again in a minute")
	}
	return err
}

// hideKey takes an environment key out of an error. The key is part of the
// request path, and rest.TransportError keeps a URL's path ("Get
// \"https://host/api/v1/environments/<key>/featurestates/\": EOF"), as can
// a server's error text. The HTTP status is kept for friendly.
func hideKey(err error, key string) error {
	if err == nil || key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	var re *rest.Error
	if errors.As(err, &re) {
		return &rest.Error{Status: re.Status, Message: strings.ReplaceAll(re.Message, key, "[environment key]")}
	}
	return errors.New(strings.ReplaceAll(err.Error(), key, "[environment key]"))
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

func flexString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s), nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", errors.New("expected a name or an id")
	}
	return n.String(), nil
}

// list reads a list Flagsmith may answer plain or paginated
// ({"results": [...], "next": ...}), page by page.
func list[T any](ctx context.Context, c *conn, path string, q url.Values, what string) ([]T, error) {
	var all []T
	if q == nil {
		q = url.Values{}
	}
	q.Set("page_size", "100")
	for page := 1; page <= 50; page++ {
		q.Set("page", strconv.Itoa(page))
		var raw json.RawMessage
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &raw); err != nil {
			return nil, friendly(err, what)
		}
		var plain []T
		if json.Unmarshal(raw, &plain) == nil {
			return append(all, plain...), nil
		}
		var pg struct {
			Results []T     `json:"results"`
			Next    *string `json:"next"`
		}
		if err := json.Unmarshal(raw, &pg); err != nil {
			return nil, fmt.Errorf("unexpected answer from Flagsmith: %w", err)
		}
		all = append(all, pg.Results...)
		if pg.Next == nil || *pg.Next == "" || len(pg.Results) == 0 {
			break
		}
	}
	return all, nil
}

type project struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Organisation int64  `json:"organisation"`
}

// environment is decoded field by field: its api_key (the SDK key) is
// read only to build request paths and is never returned or put in an undo.
type environment struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Versioning  bool   `json:"use_v2_feature_versioning"`
	key         string
}

func (c *conn) environments(ctx context.Context, proj string) ([]environment, error) {
	type envRaw struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		APIKey      string `json:"api_key"`
		Versioning  bool   `json:"use_v2_feature_versioning"`
	}
	raw, err := list[envRaw](ctx, c, "/environments/", url.Values{"project": {proj}}, "project "+proj)
	if err != nil {
		return nil, err
	}
	out := []environment{}
	for _, e := range raw {
		out = append(out, environment{ID: e.ID, Name: e.Name, Description: e.Description, Versioning: e.Versioning, key: e.APIKey})
	}
	return out, nil
}

func (c *conn) environment(ctx context.Context, proj, want string) (environment, error) {
	es, err := c.environments(ctx, proj)
	if err != nil {
		return environment{}, err
	}
	var hit []environment
	for _, e := range es {
		if strconv.FormatInt(e.ID, 10) == want || e.Name == want {
			hit = append(hit, e)
		}
	}
	if len(hit) == 0 {
		for _, e := range es {
			if strings.EqualFold(e.Name, want) {
				hit = append(hit, e)
			}
		}
	}
	switch {
	case len(hit) == 0:
		names := []string{}
		for _, e := range es {
			names = append(names, e.Name)
		}
		return environment{}, fmt.Errorf("project %s has no environment %s (it has: %s)", proj, want, strings.Join(names, ", "))
	case len(hit) > 1:
		return environment{}, fmt.Errorf("project %s has several environments called %s; use its id", proj, want)
	}
	if !envKeyRe.MatchString(hit[0].key) {
		return environment{}, fmt.Errorf("Flagsmith answered with an unexpected key for environment %s", want)
	}
	return hit[0], nil
}

type feature struct {
	ID             int64             `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Description    string            `json:"description"`
	DefaultEnabled bool              `json:"default_enabled"`
	Tags           []json.RawMessage `json:"tags"`
	IsArchived     bool              `json:"is_archived"`
	ServerSideOnly bool              `json:"is_server_key_only"`
	// initial_value isn't decoded: a remote config value can hold
	// configuration that isn't meant for agents.
}

// featureState is decoded without its value, for the same reason.
type featureState struct {
	ID             int64  `json:"id"`
	Feature        int64  `json:"feature"`
	Enabled        bool   `json:"enabled"`
	Identity       *any   `json:"identity"`
	FeatureSegment *any   `json:"feature_segment"`
	Updated        string `json:"updated_at"`
}

func (s featureState) base() bool { return s.Identity == nil && s.FeatureSegment == nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := list[project](ctx, c, "/projects/", nil, "")
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Flagsmith API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d projects", len(ps))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project     json.RawMessage `json:"project"`
		Environment json.RawMessage `json:"environment"`
		Flag        json.RawMessage `json:"flag"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	// Check everything the action takes before the first request.
	var proj, env, fl string
	switch call.Action {
	case "projects":
	case "environments", "flags", "turn_on", "turn_off":
		if proj, err = flexString(p.Project); err != nil || !idRe.MatchString(proj) {
			return sdk.Result{}, errors.New("the project is its id, a number (from projects)")
		}
		env, err = flexString(p.Environment)
		toggle := call.Action == "turn_on" || call.Action == "turn_off"
		if err != nil || (env == "" && toggle) || utf8.RuneCountInString(env) > 200 || ctrlRe.MatchString(env) {
			return sdk.Result{}, errors.New("the environment is its name, e.g. Production, or its id")
		}
		if toggle {
			if fl, err = flexString(p.Flag); err != nil || !flagRe.MatchString(fl) {
				return sdk.Result{}, errors.New("the flag is its name (letters, digits, _ - . :) or its id")
			}
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}

	switch call.Action {
	case "projects":
		ps, err := list[project](ctx, c, "/projects/", nil, "")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "organisation": x.Organisation})
		}
		return sdk.JSON(out)

	case "environments":
		es, err := c.environments(ctx, proj)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range es {
			row := map[string]any{"id": e.ID, "name": clip(e.Name, 200), "featureVersioning": e.Versioning}
			if e.Description != "" {
				row["description"] = clip(e.Description, 300)
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"project": proj, "environments": out})

	case "flags":
		fs, err := list[feature](ctx, c, "/projects/"+proj+"/features/", nil, "project "+proj)
		if err != nil {
			return sdk.Result{}, err
		}
		var e environment
		states := map[int64]featureState{}
		overrides := map[int64]int{}
		if env != "" {
			if e, err = c.environment(ctx, proj, env); err != nil {
				return sdk.Result{}, err
			}
			ss, err := list[featureState](ctx, c, "/environments/"+url.PathEscape(e.key)+"/featurestates/", nil, "environment "+env)
			if err != nil {
				return sdk.Result{}, hideKey(err, e.key)
			}
			for _, s := range ss {
				switch {
				case s.base():
					states[s.Feature] = s
				case s.FeatureSegment != nil:
					overrides[s.Feature]++
				}
			}
		}
		out := []map[string]any{}
		on := 0
		for _, f := range fs {
			row := map[string]any{"id": f.ID, "name": f.Name, "type": f.Type, "defaultEnabled": f.DefaultEnabled, "tags": len(f.Tags), "archived": f.IsArchived}
			if f.Description != "" {
				row["description"] = clip(f.Description, 300)
			}
			if s, ok := states[f.ID]; ok {
				row["enabled"] = s.Enabled
				if s.Enabled {
					on++
				}
				if overrides[f.ID] > 0 {
					row["segmentOverrides"] = overrides[f.ID]
				}
			}
			out = append(out, row)
		}
		res := map[string]any{"project": proj, "flags": out}
		if env != "" {
			res["environment"], res["on"], res["off"] = e.Name, on, len(states)-on
		}
		return sdk.JSON(res)
	}
	return c.toggle(ctx, call, proj, env, fl)
}

func (c *conn) feature(ctx context.Context, proj, want string) (feature, error) {
	if idRe.MatchString(want) {
		var f feature
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+proj+"/features/"+want+"/", nil, nil, &f); err == nil && strconv.FormatInt(f.ID, 10) == want {
			return f, nil
		} else if err != nil && !rest.IsStatus(err, http.StatusNotFound) {
			return f, friendly(err, "")
		}
	}
	fs, err := list[feature](ctx, c, "/projects/"+proj+"/features/", url.Values{"search": {want}}, "project "+proj)
	if err != nil {
		return feature{}, err
	}
	for _, f := range fs {
		if f.Name == want {
			return f, nil
		}
	}
	return feature{}, fmt.Errorf("there's no flag %s in project %s", want, proj)
}

func (c *conn) toggle(ctx context.Context, call sdk.Call, proj, envName, want string) (sdk.Result, error) {
	on := call.Action == "turn_on"
	e, err := c.environment(ctx, proj, envName)
	if err != nil {
		return sdk.Result{}, err
	}
	f, err := c.feature(ctx, proj, want)
	if err != nil {
		return sdk.Result{}, err
	}
	ss, err := list[featureState](ctx, c, "/environments/"+url.PathEscape(e.key)+"/featurestates/", url.Values{"feature": {strconv.FormatInt(f.ID, 10)}}, "environment "+e.Name)
	if err != nil {
		return sdk.Result{}, hideKey(err, e.key)
	}
	var st *featureState
	for i := range ss {
		if ss[i].base() && ss[i].Feature == f.ID {
			st = &ss[i]
		}
	}
	if st == nil {
		return sdk.Result{}, fmt.Errorf("flag %s has no state in environment %s", f.Name, e.Name)
	}
	if st.Enabled == on {
		return sdk.JSON(map[string]any{"project": proj, "environment": e.Name, "flag": f.Name, "enabled": on, "note": "nothing to change"})
	}
	word, back := map[bool]string{true: "on", false: "off"}[on], map[bool]string{true: "turn_off", false: "turn_on"}[on]
	// Refused before the preview too, so a preview never shows a change the
	// action won't make.
	if e.Versioning {
		return sdk.Result{}, fmt.Errorf("environment %s uses feature versioning, where changes are published as versions; turn the flag %s in Flagsmith", e.Name, word)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn flag %s %s in %s (project %s); users get the change right away", f.Name, word, e.Name, proj),
			Changes: []sdk.Change{{Target: fmt.Sprintf("flag %s in project %s, environment %s", f.Name, proj, e.Name), Op: "turn " + word,
				Before: mustJSON(map[string]bool{"enabled": st.Enabled}), After: mustJSON(map[string]bool{"enabled": on})}}}}, nil
	}
	// Only enabled is sent: the flag's value and segment overrides stay as
	// they are, whatever changed since the preview.
	var after featureState
	path := "/environments/" + url.PathEscape(e.key) + "/featurestates/" + strconv.FormatInt(st.ID, 10) + "/"
	if _, err := c.api.Do(ctx, http.MethodPatch, path, nil, map[string]bool{"enabled": on}, &after); err != nil {
		return sdk.Result{}, friendly(hideKey(err, e.key), "flag "+f.Name+" in environment "+e.Name)
	}
	if after.ID != 0 && (after.ID != st.ID || after.Enabled != on) {
		return sdk.Result{}, fmt.Errorf("Flagsmith kept flag %s %s in %s", f.Name, map[bool]string{true: "off", false: "on"}[on], e.Name)
	}
	res, err := sdk.JSON(map[string]any{"project": proj, "environment": e.Name, "flag": f.Name, "enabled": on, "before": st.Enabled})
	res.Undo = sdk.UndoWith(back, map[string]string{"project": proj, "environment": strconv.FormatInt(e.ID, 10), "flag": strconv.FormatInt(f.ID, 10)},
		fmt.Sprintf("Turn %s %s again in %s", f.Name, map[bool]string{true: "off", false: "on"}[on], e.Name))
	return res, err
}
