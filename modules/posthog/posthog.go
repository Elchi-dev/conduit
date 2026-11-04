// Package posthog works with PostHog (US or EU cloud, or self-hosted)
// through its API with a personal API key: projects, saved insights, a daily
// summary of an event (pageviews by default), the top events, feature flags
// with their rollout, switching a flag or changing its rollout, and recent
// exceptions from error tracking.
//
// Changing a flag changes what users of the product get in production, so
// set_flag is destructive; its preview shows the old and the new state, and
// its undo puts the old one back (itself destructive, so approved again).
package posthog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one PostHog organization reached with a personal API key.
type Config struct {
	Host    string          `json:"host"`    // us, eu, or https://posthog.example.com
	APIKey  string          `json:"apiKey"`  // secret:// personal API key
	Project json.RawMessage `json:"project"` // default project id (optional)
}

type conn struct {
	api     *rest.Client
	site    string
	mu      sync.Mutex
	project string // default project, from the settings or the first one found
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the PostHog module.
func New() *Module { return &Module{} }

var (
	idRe     = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,400}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	ctrlRe   = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

var hosts = map[string]string{"": "https://us.posthog.com", "us": "https://us.posthog.com", "eu": "https://eu.posthog.com"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":["string","integer"],"description":"Project id (default: the one in the settings, or the first)"}`
	flag := `"flag":{"type":["string","integer"],"description":"The flag's key, e.g. new-checkout, or its id"}`
	days := func(def, max int) string {
		return fmt.Sprintf(`"days":{"type":"integer","minimum":1,"maximum":%d,"default":%d}`, max, def)
	}
	return sdk.Manifest{
		ID: "posthog", Name: "PostHog", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "PostHog: projects, insights, daily pageviews or any event, top events, feature flags (switching one or changing its rollout is destructive) and recent exceptions.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"host":{"type":"string","default":"us","description":"us (us.posthog.com), eu (eu.posthog.com), or your server, e.g. https://posthog.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"A personal API key (Settings, Personal API keys), with read scopes, and feature_flag:write to change flags"},
			"project":{"type":["string","integer"],"description":"Default project id (from the address: /project/<id>/)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "The projects the key can see, with id, name and time zone.", Risk: sdk.RiskRead},
			{Name: "insights", Title: "Insights", Description: "Saved insights, most recently changed first: name, whether favourited, when last refreshed and a link.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "trends", Title: "Event trend", Description: "One event per day over the last days, with distinct users: pageviews by default.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"event":{"type":"string","default":"$pageview","maxLength":200},` + days(7, 90) + `}}`)},
			{Name: "events", Title: "Top events", Description: "The most frequent events over the last days, with counts and distinct users.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,` + days(7, 90) + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "flags", Title: "Feature flags", Description: "Flags with key, name, whether on, and the rollout of each release condition.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
			{Name: "flag", Title: "Feature flag", Description: "One flag: on or off, release conditions with rollout, variants, and PostHog's status (active, stale, ...).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["flag"],"properties":{` + project + `,` + flag + `}}`)},
			{Name: "set_flag", Title: "Change a feature flag", Description: "Switches a flag on or off and/or sets the rollout percentage of one release condition. This changes production behaviour for users, so it's destructive. The preview shows old and new; undo puts the old state back.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["flag"],"properties":{` + project + `,` + flag + `,"active":{"type":"boolean","description":"On (true) or off (false)"},"rollout":{"type":"number","minimum":0,"maximum":100,"description":"Rollout percentage"},"group":{"type":"integer","minimum":1,"description":"Which release condition (1 is the first); needed when the flag has several"}}}`)},
			{Name: "errors", Title: "Recent exceptions", Description: "Exceptions captured by error tracking over the last days, grouped by type and message, most frequent first. Messages can hold user data, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,` + days(1, 30) + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
		},
	}
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
		return "", errors.New("an id is a number")
	}
	return n.String(), nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	host := strings.TrimSpace(c.Host)
	site, ok := hosts[strings.ToLower(host)]
	if !ok {
		u, err := url.Parse(host)
		prefix := ""
		if err == nil {
			prefix = strings.TrimRight(u.Path, "/")
		}
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
			return errors.New("the host is us, eu, or your PostHog server, like https://posthog.example.com")
		}
		if strings.HasSuffix(strings.ToLower(u.Hostname()), ".i.posthog.com") {
			return errors.New("that's PostHog's ingestion address; the API is at us or eu (us.posthog.com, eu.posthog.com)")
		}
		site = u.Scheme + "://" + u.Host + prefix
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the personal API key in the vault and enter its secret:// reference")
	}
	proj, err := flexString(c.Project)
	if err != nil || (proj != "" && !idRe.MatchString(proj)) {
		return errors.New("the project is its id, the number in /project/<id>/")
	}
	ref := c.APIKey
	api := rest.New(site+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, site: site, project: proj})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("PostHog refused the personal API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("PostHog refused: %v (does the key have the scope, and access to this project?)", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("PostHog refused the request: %v", err)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("PostHog's rate limit was hit; try again in a minute")
	}
	return err
}

type project struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Timezone string `json:"timezone"`
}

func (c *conn) projects(ctx context.Context) ([]project, error) {
	var a struct {
		Results []project `json:"results"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/projects/", nil, nil, &a); err != nil {
		return nil, friendly(err, "project list")
	}
	return a.Results, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	c.mu.Lock()
	want := c.project
	c.mu.Unlock()
	if want == "" {
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d projects", len(ps))}
	}
	for _, p := range ps {
		if strconv.FormatInt(p.ID, 10) == want {
			return sdk.Health{Status: "ok", Message: "Project " + clip(p.Name, 80)}
		}
	}
	return sdk.Health{Status: "degraded", Message: "the key can't see project " + want}
}

// projectID picks the project for a call.
func (c *conn) projectID(ctx context.Context, raw json.RawMessage) (string, error) {
	p, err := flexString(raw)
	if err != nil || (p != "" && !idRe.MatchString(p)) {
		return "", errors.New("the project is its id, the number in /project/<id>/")
	}
	if p != "" {
		return p, nil
	}
	c.mu.Lock()
	p = c.project
	c.mu.Unlock()
	if p != "" {
		return p, nil
	}
	ps, err := c.projects(ctx)
	if err != nil {
		return "", err
	}
	if len(ps) == 0 {
		return "", errors.New("the key can't see any project")
	}
	p = strconv.FormatInt(ps[0].ID, 10)
	c.mu.Lock()
	c.project = p
	c.mu.Unlock()
	return p, nil
}

type input struct {
	Project json.RawMessage `json:"project"`
	Flag    json.RawMessage `json:"flag"`
	Event   string          `json:"event"`
	Days    int             `json:"days"`
	Limit   int             `json:"limit"`
	Active  *bool           `json:"active"`
	Rollout *float64        `json:"rollout"`
	Group   *int            `json:"group"`
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

func bounded(v, def, lo, hi int, what string) (int, error) {
	if v == 0 {
		return def, nil
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("%s is %d to %d", what, lo, hi)
	}
	return v, nil
}

// hogql runs a HogQL query with its values passed as placeholders, never
// spliced into the text.
func (c *conn) hogql(ctx context.Context, proj, query string, values map[string]any) ([][]any, error) {
	q := map[string]any{"kind": "HogQLQuery", "query": query}
	if len(values) > 0 {
		q["values"] = values
	}
	var a struct {
		Results [][]any `json:"results"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/projects/"+proj+"/query/", nil, map[string]any{"query": q}, &a); err != nil {
		return nil, friendly(err, "project "+proj)
	}
	return a.Results, nil
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// flag is a feature flag with its filters kept raw, so a change sends back
// everything it doesn't touch as it was.
type flag struct {
	ID      int64          `json:"id"`
	Key     string         `json:"key"`
	Name    string         `json:"name"`
	Active  bool           `json:"active"`
	Deleted bool           `json:"deleted"`
	Filters map[string]any `json:"filters"`
}

func (f flag) groups() []map[string]any {
	gs, _ := f.Filters["groups"].([]any)
	var out []map[string]any
	for _, g := range gs {
		if m, ok := g.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// rollout of a release condition; none means everyone matching it.
func rollout(g map[string]any) float64 {
	if v, ok := g["rollout_percentage"].(float64); ok {
		return v
	}
	return 100
}

func (f flag) out(site, proj string) map[string]any {
	o := map[string]any{"id": f.ID, "key": f.Key, "name": clip(f.Name, 200), "active": f.Active, "url": site + "/project/" + proj + "/feature_flags/" + strconv.FormatInt(f.ID, 10)}
	var conds []map[string]any
	for i, g := range f.groups() {
		ps, _ := g["properties"].([]any)
		cd := map[string]any{"group": i + 1, "rollout": rollout(g), "conditions": len(ps)}
		if v, ok := g["variant"].(string); ok && v != "" {
			cd["variant"] = v
		}
		conds = append(conds, cd)
	}
	o["releaseConditions"] = conds
	if len(conds) == 1 && conds[0]["conditions"] == 0 {
		o["rollout"] = conds[0]["rollout"]
	}
	if mv, ok := f.Filters["multivariate"].(map[string]any); ok {
		if vs, ok := mv["variants"].([]any); ok {
			var names []string
			for _, v := range vs {
				if vm, ok := v.(map[string]any); ok {
					names = append(names, text(vm["key"]))
				}
			}
			o["variants"] = names
		}
	}
	return o
}

func (c *conn) flags(ctx context.Context, proj string) ([]flag, error) {
	var all []flag
	q := url.Values{"limit": {"100"}, "offset": {"0"}}
	for page := 0; page < 10; page++ {
		var a struct {
			Results []flag  `json:"results"`
			Next    *string `json:"next"`
		}
		q.Set("offset", strconv.Itoa(page*100))
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+proj+"/feature_flags/", q, nil, &a); err != nil {
			return nil, friendly(err, "project "+proj)
		}
		for _, f := range a.Results {
			if !f.Deleted {
				all = append(all, f)
			}
		}
		if a.Next == nil || len(a.Results) == 0 {
			break
		}
	}
	return all, nil
}

// findFlag looks a flag up by id, or by key through the list.
func (c *conn) findFlag(ctx context.Context, proj string, raw json.RawMessage) (flag, error) {
	s, err := flexString(raw)
	if err != nil || s == "" || !keyRe.MatchString(s) {
		return flag{}, errors.New("the flag is its key (letters, digits, - and _) or its id")
	}
	if idRe.MatchString(s) {
		var f flag
		_, err := c.api.Do(ctx, http.MethodGet, "/projects/"+proj+"/feature_flags/"+s+"/", nil, nil, &f)
		if err == nil && !f.Deleted {
			return f, nil
		}
		if err != nil && !rest.IsStatus(err, http.StatusNotFound) {
			return flag{}, friendly(err, "flag "+s)
		}
		// A key can be all digits too: fall through to the list.
	}
	fs, err := c.flags(ctx, proj)
	if err != nil {
		return flag{}, err
	}
	for _, f := range fs {
		if f.Key == s {
			return f, nil
		}
	}
	return flag{}, fmt.Errorf("there's no flag %s in project %s", s, proj)
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
	if call.Action == "projects" {
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range ps {
			list = append(list, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "timezone": x.Timezone})
		}
		return sdk.JSON(list)
	}
	// Check everything the action takes before the first request.
	var days, lim int
	switch call.Action {
	case "insights":
		lim, err = bounded(p.Limit, 25, 1, 100, "the limit")
	case "trends":
		days, err = bounded(p.Days, 7, 1, 90, "days")
		if p.Event == "" {
			p.Event = "$pageview"
		}
		if err == nil && (utf8.RuneCountInString(p.Event) > 200 || ctrlRe.MatchString(p.Event) || strings.TrimSpace(p.Event) == "") {
			err = errors.New("the event is its name, e.g. $pageview, up to 200 characters")
		}
	case "events":
		if days, err = bounded(p.Days, 7, 1, 90, "days"); err == nil {
			lim, err = bounded(p.Limit, 20, 1, 100, "the limit")
		}
	case "errors":
		if days, err = bounded(p.Days, 1, 1, 30, "days"); err == nil {
			lim, err = bounded(p.Limit, 25, 1, 100, "the limit")
		}
	case "flags":
	case "flag", "set_flag":
		s, ferr := flexString(p.Flag)
		if ferr != nil || s == "" || !keyRe.MatchString(s) {
			err = errors.New("the flag is its key (letters, digits, - and _) or its id")
		}
		if call.Action == "set_flag" && err == nil {
			switch {
			case p.Active == nil && p.Rollout == nil:
				err = errors.New("say what to change: active (on or off) and/or rollout (a percentage)")
			case p.Rollout != nil && (math.IsNaN(*p.Rollout) || *p.Rollout < 0 || *p.Rollout > 100):
				err = errors.New("the rollout is a percentage from 0 to 100")
			case p.Group != nil && (*p.Group < 1 || *p.Group > 1000):
				err = errors.New("the group is the release condition's number, 1 for the first")
			case p.Group != nil && p.Rollout == nil:
				err = errors.New("a group goes with a rollout")
			}
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	proj, err := c.projectID(ctx, p.Project)
	if err != nil {
		return sdk.Result{}, err
	}

	switch call.Action {
	case "insights":
		var a struct {
			Results []struct {
				ID           int64  `json:"id"`
				ShortID      string `json:"short_id"`
				Name         string `json:"name"`
				DerivedName  string `json:"derived_name"`
				Favorited    bool   `json:"favorited"`
				LastRefresh  string `json:"last_refresh"`
				LastModified string `json:"last_modified_at"`
			} `json:"results"`
		}
		q := url.Values{"limit": {strconv.Itoa(lim)}, "saved": {"true"}, "order": {"-last_modified_at"}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+proj+"/insights/", q, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "project "+proj)
		}
		list := []map[string]any{}
		for _, x := range a.Results {
			n := x.Name
			if n == "" {
				n = x.DerivedName
			}
			list = append(list, map[string]any{"id": x.ID, "name": clip(n, 200), "favorited": x.Favorited, "lastRefresh": x.LastRefresh, "modified": x.LastModified,
				"url": c.site + "/project/" + proj + "/insights/" + url.PathEscape(x.ShortID)})
		}
		return sdk.JSON(list)

	case "trends":
		rows, err := c.hogql(ctx, proj, fmt.Sprintf(`SELECT toDate(timestamp) AS day, count() AS events, count(DISTINCT person_id) AS users FROM events WHERE event = {event} AND timestamp >= now() - INTERVAL %d DAY GROUP BY day ORDER BY day`, days),
			map[string]any{"event": p.Event})
		if err != nil {
			return sdk.Result{}, err
		}
		series := []map[string]any{}
		var total float64
		for _, r := range rows {
			if len(r) < 3 {
				continue
			}
			total += num(r[1])
			series = append(series, map[string]any{"day": clip(text(r[0]), 10), "events": num(r[1]), "users": num(r[2])})
		}
		return sdk.JSON(map[string]any{"project": proj, "event": p.Event, "days": days, "total": total, "perDay": series})

	case "events":
		rows, err := c.hogql(ctx, proj, fmt.Sprintf(`SELECT event, count() AS events, count(DISTINCT person_id) AS users FROM events WHERE timestamp >= now() - INTERVAL %d DAY GROUP BY event ORDER BY events DESC LIMIT %d`, days, lim), nil)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, r := range rows {
			if len(r) < 3 {
				continue
			}
			list = append(list, map[string]any{"event": clip(text(r[0]), 200), "events": num(r[1]), "users": num(r[2])})
		}
		return sdk.JSON(map[string]any{"project": proj, "days": days, "events": list})

	case "errors":
		rows, err := c.hogql(ctx, proj, fmt.Sprintf(`SELECT coalesce(nullIf(toString(properties.$exception_type), ''), toString(properties.$exception_types)) AS type, coalesce(nullIf(toString(properties.$exception_message), ''), toString(properties.$exception_values)) AS message, count() AS occurrences, count(DISTINCT person_id) AS users, max(timestamp) AS last_seen FROM events WHERE event = '$exception' AND timestamp >= now() - INTERVAL %d DAY GROUP BY type, message ORDER BY occurrences DESC LIMIT %d`, days, lim), nil)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, r := range rows {
			if len(r) < 5 {
				continue
			}
			list = append(list, map[string]any{"type": clip(rest.Redact(text(r[0])), 200), "message": clip(rest.Redact(text(r[1])), 500), "occurrences": num(r[2]), "users": num(r[3]), "lastSeen": clip(text(r[4]), 40)})
		}
		out := map[string]any{"project": proj, "days": days, "exceptions": list}
		if len(list) == 0 {
			out["note"] = "no $exception events in this time; error tracking may be off for this project"
		}
		return sdk.JSON(out)

	case "flags":
		fs, err := c.flags(ctx, proj)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		on := 0
		for _, f := range fs {
			if f.Active {
				on++
			}
			list = append(list, f.out(c.site, proj))
		}
		return sdk.JSON(map[string]any{"project": proj, "flags": list, "on": on, "off": len(fs) - on})

	case "flag":
		f, err := c.findFlag(ctx, proj, p.Flag)
		if err != nil {
			return sdk.Result{}, err
		}
		o := f.out(c.site, proj)
		var st struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+proj+"/feature_flags/"+strconv.FormatInt(f.ID, 10)+"/status/", nil, nil, &st); err == nil && st.Status != "" {
			o["status"], o["statusReason"] = strings.ToLower(st.Status), clip(st.Reason, 300)
		}
		return sdk.JSON(o)

	case "set_flag":
		f, err := c.findFlag(ctx, proj, p.Flag)
		if err != nil {
			return sdk.Result{}, err
		}
		before := map[string]any{"active": f.Active}
		after := map[string]any{"active": f.Active}
		patch := map[string]any{}
		undo := map[string]any{"project": proj, "flag": strconv.FormatInt(f.ID, 10)}
		if p.Active != nil && *p.Active != f.Active {
			patch["active"] = *p.Active
			after["active"] = *p.Active
			undo["active"] = f.Active
		}
		if p.Rollout != nil {
			gs := f.groups()
			g := 1
			switch {
			case len(gs) == 0:
				return sdk.Result{}, fmt.Errorf("flag %s has no release conditions to roll out", f.Key)
			case p.Group != nil:
				g = *p.Group
			case len(gs) > 1:
				return sdk.Result{}, fmt.Errorf("flag %s has %d release conditions; say which with group (1 to %d)", f.Key, len(gs), len(gs))
			}
			if g > len(gs) {
				return sdk.Result{}, fmt.Errorf("flag %s has %d release conditions", f.Key, len(gs))
			}
			old := rollout(gs[g-1])
			before["group"], before["rollout"] = g, old
			after["group"], after["rollout"] = g, *p.Rollout
			if old != *p.Rollout {
				gs[g-1]["rollout_percentage"] = *p.Rollout
				filters := map[string]any{}
				for k, v := range f.Filters {
					filters[k] = v
				}
				all := make([]any, len(gs))
				for i := range gs {
					all[i] = gs[i]
				}
				filters["groups"] = all
				patch["filters"] = filters
				undo["rollout"], undo["group"] = old, g
			}
		}
		if len(patch) == 0 {
			return sdk.JSON(map[string]any{"flag": f.Key, "note": "the flag is already like that", "state": before})
		}
		label := f.Key
		sum := fmt.Sprintf("Change feature flag %s in production", label)
		if a, ok := patch["active"].(bool); ok {
			sum = fmt.Sprintf("Switch feature flag %s %s", label, map[bool]string{true: "on", false: "off"}[a])
		}
		if _, ok := patch["filters"]; ok {
			sum += fmt.Sprintf("; release condition %v from %v%% to %v%%", after["group"], before["rollout"], after["rollout"])
		}
		sum += "; users get the new behaviour right away"
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "flag " + label, Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
		}
		var got flag
		if _, err := c.api.Do(ctx, http.MethodPatch, "/projects/"+proj+"/feature_flags/"+strconv.FormatInt(f.ID, 10)+"/", nil, patch, &got); err != nil {
			return sdk.Result{}, friendly(err, "flag "+label)
		}
		r, err := sdk.JSON(map[string]any{"flag": f.Key, "before": before, "after": after})
		r.Undo = sdk.UndoWith("set_flag", undo, "Put feature flag "+label+" back as it was")
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
