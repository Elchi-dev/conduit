// Package datadog works with a Datadog organization through its API with an
// API key and an application key: monitors and their state, triggered
// monitors, muting one monitor for a while (a downtime) and unmuting it,
// incidents, posting events, dashboards and SLO status.
package datadog

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Datadog organization.
type Config struct {
	Site   string `json:"site"`   // datadoghq.com, datadoghq.eu, us3.datadoghq.com, …
	APIKey string `json:"apiKey"` // secret://
	AppKey string `json:"appKey"` // secret://
}

type conn struct {
	api  *rest.Client
	site string
	now  func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.<site> (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Datadog module.
func New() *Module { return &Module{} }

// Sites are Datadog's sites; the API is at api.<site>.
var Sites = []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com", "ddog-gov.com"}

var (
	scopeRe  = regexp.MustCompile(`^[A-Za-z0-9_.:/@ (),!-]{1,500}$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:/-]{0,199}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	searchRe = regexp.MustCompile(`^[A-Za-z0-9 _.:/@"()-]{1,200}$`)
	aggRe    = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := `"id":{"type":"integer","minimum":1,"description":"Monitor id"}`
	return sdk.Manifest{
		ID: "datadog", Name: "Datadog", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Datadog: monitors and what's alerting, mute one monitor for a while (whole monitor or over a day needs the destructive mute), incidents, events, dashboards, SLO status.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["site","apiKey","appKey"],"properties":{
			"site":{"type":"string","enum":["datadoghq.com","us3.datadoghq.com","us5.datadoghq.com","datadoghq.eu","ap1.datadoghq.com","ap2.datadoghq.com","ddog-gov.com"],"default":"datadoghq.com","description":"Your Datadog site, as in the address you sign in at (app.datadoghq.eu is datadoghq.eu)"},
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Organization settings, API keys)"},
			"appKey":{"type":"string","x-secret":true,"description":"Application key (Organization settings, Application keys), ideally scoped: monitors_read, monitors_downtime, incident_read, events_read, dashboards_read, slos_read"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "monitors", Title: "Monitors", Description: "Monitors with their state (OK, Alert, Warn, No Data), type, tags and whether they're muted.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"name":{"type":"string","description":"Only names containing this"},"tags":{"type":"array","items":{"type":"string"},"description":"Only monitors with these monitor tags"}}}`)},
			{Name: "monitor", Title: "Monitor state", Description: "One monitor: query, state of each group, when it last triggered, and active downtimes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "triggered_monitors", Title: "Triggered monitors", Description: "Monitors in Alert, Warn or No Data right now, with when they triggered.", Risk: sdk.RiskRead},
			{Name: "mute_monitor", Title: "Mute part of a monitor", Description: "Schedules a downtime that silences one scope of one monitor (named groups such as host:web-1, no wildcards) for up to 24 hours (1440 minutes). Muting a whole monitor or for longer is mute_monitor_long. Undo cancels the downtime.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","scope"],"properties":{` + id + `,"scope":{"type":"string","description":"Groups to mute, e.g. host:web-1 or env:prod (no wildcards)"},"minutes":{"type":"integer","minimum":1,"maximum":1440,"default":60},"message":{"type":"string","maxLength":1000}}}`)},
			{Name: "mute_monitor_long", Title: "Mute a whole monitor or for long", Description: "Schedules a downtime that silences one monitor (one scope of it, or all its groups when allGroups) for up to a week (10080 minutes). Destructive: it can blind alerting for a whole service. Muting every monitor or a wildcard scope is refused. Undo cancels the downtime.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"scope":{"type":"string","description":"Groups to mute, e.g. host:web-1 or env:prod (no wildcards)"},"allGroups":{"type":"boolean","description":"Mute every group of this one monitor"},"minutes":{"type":"integer","minimum":1,"maximum":10080,"default":60},"message":{"type":"string","maxLength":1000}}}`)},
			{Name: "unmute_monitor", Title: "Unmute a monitor", Description: "Cancels a downtime by id, or every active downtime that names this monitor.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `,"downtime":{"type":"string","description":"Downtime id"}}}`)},
			{Name: "incidents", Title: "Incidents", Description: "Recent incidents with severity, state and whether customers are affected.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":25,"maximum":100}}}`)},
			{Name: "post_event", Title: "Post an event", Description: "Posts an event to the event stream (deploy markers, notes). Events can't be deleted.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["title","text"],"properties":{"title":{"type":"string","maxLength":500},"text":{"type":"string","maxLength":4000},"alertType":{"type":"string","enum":["info","success","warning","error"],"default":"info"},"priority":{"type":"string","enum":["normal","low"]},"tags":{"type":"array","items":{"type":"string"},"maxItems":50},"aggregationKey":{"type":"string"}}}`)},
			{Name: "dashboards", Title: "Dashboards", Description: "Dashboards with title, link and when they changed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string"}}}`)},
			{Name: "slos", Title: "SLO status", Description: "Service level objectives with target, current value, error budget left and state per time window.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Search query, e.g. a name or service:api"},"limit":{"type":"integer","default":50,"maximum":100}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	site := strings.ToLower(strings.TrimSpace(c.Site))
	if site == "" {
		site = "datadoghq.com"
	}
	site = strings.TrimPrefix(strings.TrimPrefix(site, "https://"), "app.")
	ok := false
	for _, s := range Sites {
		ok = ok || s == site
	}
	if !ok {
		return fmt.Errorf("the site is one of %s", strings.Join(Sites, ", "))
	}
	if !strings.HasPrefix(c.APIKey, "secret://") || !strings.HasPrefix(c.AppKey, "secret://") {
		return errors.New("store the API key and the application key in the vault and enter their secret:// references")
	}
	base := "https://api." + site
	if m.Base != "" {
		base = m.Base
	}
	apiRef, appRef := c.APIKey, c.AppKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, apiRef)
		if err != nil {
			return err
		}
		a, err := h.Secret(ctx, appRef)
		if err != nil {
			return err
		}
		r.Header.Set("DD-API-KEY", strings.TrimSpace(k))
		r.Header.Set("DD-APPLICATION-KEY", strings.TrimSpace(a))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// The keys are custom headers, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, site: site, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Datadog refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Datadog refused: the application key is wrong or lacks the scope for this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Valid bool `json:"valid"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/validate", nil, nil, &v); err != nil || !v.Valid {
		if err == nil || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Datadog refused the API key (is the site right?)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var mons []json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/monitor", url.Values{"page": {"0"}, "page_size": {"1"}}, nil, &mons); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Datadog refused the application key (or it lacks monitors_read)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected to " + c.site}
}

type input struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Tags           []string `json:"tags"`
	Scope          string   `json:"scope"`
	AllGroups      bool     `json:"allGroups"`
	Minutes        int      `json:"minutes"`
	Message        string   `json:"message"`
	Downtime       string   `json:"downtime"`
	Limit          int      `json:"limit"`
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	AlertType      string   `json:"alertType"`
	Priority       string   `json:"priority"`
	AggregationKey string   `json:"aggregationKey"`
	Search         string   `json:"search"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func clip(s string, k int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > k {
		return string(r[:k]) + "…"
	}
	return string(r)
}

func ts(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

type monitor struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Query    string   `json:"query"`
	Message  string   `json:"message"`
	State    string   `json:"overall_state"`
	Tags     []string `json:"tags"`
	Priority *int     `json:"priority"`
	Modified string   `json:"modified"`
	Status   *struct {
		Groups map[string]struct {
			Status        string `json:"status"`
			LastTriggered int64  `json:"last_triggered_ts"`
		} `json:"groups"`
	} `json:"state"`
	Downtimes []struct {
		ID     any      `json:"id"`
		Active bool     `json:"active"`
		Scope  []string `json:"scope"`
		End    *int64   `json:"end"`
	} `json:"matching_downtimes"`
}

func (mo monitor) summary() map[string]any {
	out := map[string]any{"id": mo.ID, "name": mo.Name, "type": mo.Type, "state": mo.State, "tags": mo.Tags}
	if mo.Priority != nil {
		out["priority"] = *mo.Priority
	}
	for _, d := range mo.Downtimes {
		if d.Active {
			out["muted"] = true
		}
	}
	return out
}

func (c *conn) getMonitor(ctx context.Context, id int64) (monitor, error) {
	var mo monitor
	if id < 1 {
		return mo, errors.New("the monitor is its id, a number (see monitors)")
	}
	q := url.Values{"group_states": {"all"}, "with_downtimes": {"true"}}
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/monitor/"+strconv.FormatInt(id, 10), q, nil, &mo); err != nil {
		return mo, friendly(err, fmt.Sprintf("monitor %d", id))
	}
	return mo, nil
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
	case "monitors":
		q := url.Values{"page_size": {"200"}, "with_downtimes": {"true"}}
		if s := strings.TrimSpace(p.Name); s != "" {
			if len(s) > 200 || strings.ContainsAny(s, "\r\n") {
				return sdk.Result{}, errors.New("the name filter is one line of up to 200 characters")
			}
			q.Set("name", s)
		}
		if len(p.Tags) > 0 {
			for _, t := range p.Tags {
				if !tagRe.MatchString(t) {
					return sdk.Result{}, fmt.Errorf("%q isn't a tag", t)
				}
			}
			q.Set("monitor_tags", strings.Join(p.Tags, ","))
		}
		out := []map[string]any{}
		for pg := 0; pg < 5; pg++ {
			q.Set("page", strconv.Itoa(pg))
			var mons []monitor
			if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/monitor", q, nil, &mons); err != nil {
				return sdk.Result{}, friendly(err, "monitor")
			}
			for _, mo := range mons {
				out = append(out, mo.summary())
			}
			if len(mons) < 200 {
				break
			}
		}
		return sdk.JSON(out)

	case "monitor":
		mo, err := c.getMonitor(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := mo.summary()
		out["query"], out["message"], out["modified"] = clip(mo.Query, 2000), clip(mo.Message, 2000), mo.Modified
		groups := []map[string]any{}
		if mo.Status != nil {
			for name, g := range mo.Status.Groups {
				if len(groups) == 200 {
					break
				}
				groups = append(groups, map[string]any{"group": name, "status": g.Status, "lastTriggered": ts(g.LastTriggered)})
			}
		}
		out["groups"] = groups
		dts := []map[string]any{}
		for _, d := range mo.Downtimes {
			if d.Active {
				e := map[string]any{"id": d.ID, "scope": d.Scope}
				if d.End != nil {
					e["end"] = ts(*d.End)
				}
				dts = append(dts, e)
			}
		}
		out["downtimes"] = dts
		return sdk.JSON(out)

	case "triggered_monitors":
		q := url.Values{"query": {`status:(alert OR warn OR "no data")`}, "per_page": {"100"}, "sort": {"status,asc"}}
		var res struct {
			Monitors []struct {
				ID            int64    `json:"id"`
				Name          string   `json:"name"`
				Status        string   `json:"status"`
				Type          string   `json:"type"`
				Tags          []string `json:"tags"`
				LastTriggered int64    `json:"last_triggered_ts"`
				Priority      *int     `json:"priority"`
			} `json:"monitors"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/monitor/search", q, nil, &res); err != nil {
			return sdk.Result{}, friendly(err, "monitor")
		}
		out := []map[string]any{}
		for _, mo := range res.Monitors {
			e := map[string]any{"id": mo.ID, "name": mo.Name, "status": mo.Status, "type": mo.Type, "tags": mo.Tags, "lastTriggered": ts(mo.LastTriggered)}
			if mo.Priority != nil {
				e["priority"] = *mo.Priority
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "mute_monitor":
		return c.mute(ctx, call, p, false)
	case "mute_monitor_long":
		return c.mute(ctx, call, p, true)
	case "unmute_monitor":
		return c.unmute(ctx, call, p)

	case "incidents":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		var res struct {
			Data []struct {
				ID         string `json:"id"`
				Attributes struct {
					PublicID         int64  `json:"public_id"`
					Title            string `json:"title"`
					Severity         string `json:"severity"`
					State            string `json:"state"`
					Created          string `json:"created"`
					Resolved         string `json:"resolved"`
					CustomerImpacted bool   `json:"customer_impacted"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/v2/incidents", url.Values{"page[size]": {strconv.Itoa(limit)}}, nil, &res); err != nil {
			return sdk.Result{}, friendly(err, "incident")
		}
		out := []map[string]any{}
		for _, in := range res.Data {
			a := in.Attributes
			e := map[string]any{"id": in.ID, "number": a.PublicID, "title": clip(a.Title, 300), "severity": a.Severity, "state": a.State, "created": a.Created, "customerImpacted": a.CustomerImpacted}
			if a.Resolved != "" {
				e["resolved"] = a.Resolved
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "post_event":
		return c.event(ctx, call, p)

	case "dashboards":
		s := strings.ToLower(strings.TrimSpace(p.Search))
		if len(s) > 200 {
			return sdk.Result{}, errors.New("the search is up to 200 characters")
		}
		var res struct {
			Dashboards []struct {
				ID       string `json:"id"`
				Title    string `json:"title"`
				URL      string `json:"url"`
				Layout   string `json:"layout_type"`
				Modified string `json:"modified_at"`
			} `json:"dashboards"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/dashboard", url.Values{"filter[deleted]": {"false"}}, nil, &res); err != nil {
			return sdk.Result{}, friendly(err, "dashboard")
		}
		out := []map[string]any{}
		for _, d := range res.Dashboards {
			if s != "" && !strings.Contains(strings.ToLower(d.Title), s) {
				continue
			}
			link := d.URL
			if strings.HasPrefix(link, "/") {
				link = "https://app." + c.site + link
			}
			out = append(out, map[string]any{"id": d.ID, "title": d.Title, "url": link, "layout": d.Layout, "modified": d.Modified})
		}
		return sdk.JSON(out)

	case "slos":
		return c.slos(ctx, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// maxShortMute is the longest downtime mute_monitor (write) schedules;
// longer ones, and whole-monitor ones, are mute_monitor_long (destructive).
const maxShortMute = 1440

// mute schedules a downtime for one monitor. long is mute_monitor_long: it
// may cover every group of the monitor and last up to a week; the write
// action is held to named groups for at most a day.
func (c *conn) mute(ctx context.Context, call sdk.Call, p input, long bool) (sdk.Result, error) {
	if p.ID < 1 {
		return sdk.Result{}, errors.New("name the one monitor to mute by its id; muting every monitor isn't offered")
	}
	scope := strings.TrimSpace(p.Scope)
	switch {
	case strings.Contains(scope, "*"):
		return sdk.Result{}, errors.New("wildcard scopes are refused; name the groups (host:web-1) or set allGroups to mute this whole monitor")
	case !long && p.AllGroups:
		return sdk.Result{}, errors.New("muting every group of a monitor is mute_monitor_long; mute_monitor needs a scope like host:web-1")
	case !long && scope == "":
		return sdk.Result{}, errors.New("give a scope (like host:web-1); muting the whole monitor is mute_monitor_long")
	case scope == "" && !p.AllGroups:
		return sdk.Result{}, errors.New("give a scope (like host:web-1) or set allGroups to mute every group of this monitor")
	case scope != "" && p.AllGroups:
		return sdk.Result{}, errors.New("give a scope or allGroups, not both")
	case scope != "" && !scopeRe.MatchString(scope):
		return sdk.Result{}, errors.New("the scope is tags like host:web-1 or env:prod AND service:api")
	}
	mins := p.Minutes
	if mins == 0 {
		mins = 60
	}
	if !long && (mins < 1 || mins > maxShortMute) {
		return sdk.Result{}, errors.New("mute_monitor mutes for 1 to 1440 minutes (a day); longer mutes are mute_monitor_long")
	}
	if mins < 1 || mins > 10080 {
		return sdk.Result{}, errors.New("mute for 1 to 10080 minutes (a week); indefinite mutes aren't offered")
	}
	msg := strings.TrimSpace(p.Message)
	if len(msg) > 1000 {
		return sdk.Result{}, errors.New("the message is up to 1000 characters")
	}
	mo, err := c.getMonitor(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	end := c.now().UTC().Add(time.Duration(mins) * time.Minute).Truncate(time.Second)
	shown := scope
	if p.AllGroups {
		shown = "all groups"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Mute monitor %d %q (%s, now %s) for %s until %s; it won't notify meanwhile", mo.ID, clip(mo.Name, 80), shown, mo.State, (time.Duration(mins) * time.Minute).String(), end.Format(time.RFC3339)),
			Changes: []sdk.Change{{Target: fmt.Sprintf("monitor %d", mo.ID), Op: "mute", After: mustJSON(map[string]any{"scope": shown, "until": end.Format(time.RFC3339), "message": msg})}}}}, nil
	}
	apiScope := scope
	if p.AllGroups {
		apiScope = "*" // every group of this one monitor (monitor_identifier pins the monitor)
	}
	if msg == "" {
		msg = "Muted from Conduit"
	}
	body := map[string]any{"data": map[string]any{"type": "downtime", "attributes": map[string]any{
		"monitor_identifier": map[string]any{"monitor_id": mo.ID},
		"scope":              apiScope,
		"message":            msg,
		"schedule":           map[string]any{"end": end.Format(time.RFC3339)},
		"notify_end_states":  []string{"alert", "no data", "warn"},
		"notify_end_types":   []string{"expired", "canceled"},
	}}}
	var res struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/api/v2/downtime", nil, body, &res); err != nil {
		return sdk.Result{}, friendly(err, "monitor")
	}
	out, err := sdk.JSON(map[string]any{"monitor": mo.ID, "downtime": res.Data.ID, "scope": shown, "until": end.Format(time.RFC3339)})
	if uuidRe.MatchString(res.Data.ID) {
		out.Undo = sdk.UndoWith("unmute_monitor", map[string]any{"downtime": res.Data.ID}, fmt.Sprintf("Unmute monitor %d", mo.ID))
	}
	return out, err
}

type downtime struct {
	ID         string `json:"id"`
	Attributes struct {
		Scope     string `json:"scope"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		MonitorID *struct {
			MonitorID int64 `json:"monitor_id"`
		} `json:"monitor_identifier"`
		Schedule *struct {
			End string `json:"end"`
		} `json:"schedule"`
	} `json:"attributes"`
}

func (c *conn) unmute(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	var targets []downtime
	switch d := strings.TrimSpace(p.Downtime); {
	case d != "":
		if !uuidRe.MatchString(d) {
			return sdk.Result{}, errors.New("the downtime is its id (see monitor)")
		}
		var res struct {
			Data downtime `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/v2/downtime/"+d, nil, nil, &res); err != nil {
			return sdk.Result{}, friendly(err, "downtime "+d)
		}
		targets = append(targets, res.Data)
	case p.ID > 0:
		for pg := 0; pg < 10; pg++ {
			var res struct {
				Data []downtime `json:"data"`
			}
			q := url.Values{"current_only": {"true"}, "page[limit]": {"100"}, "page[offset]": {strconv.Itoa(pg * 100)}}
			if _, err := c.api.Do(ctx, http.MethodGet, "/api/v2/downtime", q, nil, &res); err != nil {
				return sdk.Result{}, friendly(err, "downtime")
			}
			for _, d := range res.Data {
				if mi := d.Attributes.MonitorID; mi != nil && mi.MonitorID == p.ID && d.Attributes.Status != "canceled" && d.Attributes.Status != "ended" {
					targets = append(targets, d)
				}
			}
			if len(res.Data) < 100 {
				break
			}
		}
		if len(targets) == 0 {
			return sdk.JSON(map[string]any{"monitor": p.ID, "note": "no active downtime names this monitor (it may be muted by a tag-based downtime; see monitor)"})
		}
	default:
		return sdk.Result{}, errors.New("give the downtime id or the monitor id")
	}
	for _, d := range targets {
		if !uuidRe.MatchString(d.ID) {
			return sdk.Result{}, errors.New("unexpected downtime id from Datadog")
		}
	}
	if call.DryRun {
		changes := []sdk.Change{}
		for _, d := range targets {
			before := map[string]any{"scope": d.Attributes.Scope, "status": d.Attributes.Status}
			if s := d.Attributes.Schedule; s != nil && s.End != "" {
				before["end"] = s.End
			}
			if mi := d.Attributes.MonitorID; mi != nil {
				before["monitor"] = mi.MonitorID
			}
			changes = append(changes, sdk.Change{Target: "downtime " + d.ID, Op: "cancel", Before: mustJSON(before)})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel %d downtime(s); the monitor notifies again", len(targets)), Changes: changes}}, nil
	}
	var done []string
	for _, d := range targets {
		if _, err := c.api.Do(ctx, http.MethodDelete, "/api/v2/downtime/"+d.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "downtime "+d.ID)
		}
		done = append(done, d.ID)
	}
	return sdk.JSON(map[string]any{"canceled": done})
}

func (c *conn) event(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	title, text := strings.TrimSpace(p.Title), strings.TrimSpace(p.Text)
	if title == "" || len([]rune(title)) > 500 || strings.ContainsAny(title, "\r\n") {
		return sdk.Result{}, errors.New("the title is one line of up to 500 characters")
	}
	if text == "" || len([]rune(text)) > 4000 {
		return sdk.Result{}, errors.New("the text is up to 4000 characters")
	}
	alert := p.AlertType
	if alert == "" {
		alert = "info"
	}
	switch alert {
	case "info", "success", "warning", "error":
	default:
		return sdk.Result{}, errors.New("alertType is info, success, warning or error")
	}
	if p.Priority != "" && p.Priority != "normal" && p.Priority != "low" {
		return sdk.Result{}, errors.New("priority is normal or low")
	}
	if len(p.Tags) > 50 {
		return sdk.Result{}, errors.New("up to 50 tags")
	}
	for _, t := range p.Tags {
		if !tagRe.MatchString(t) {
			return sdk.Result{}, fmt.Errorf("%q isn't a tag (like env:prod)", t)
		}
	}
	if p.AggregationKey != "" && !aggRe.MatchString(p.AggregationKey) {
		return sdk.Result{}, errors.New("the aggregation key is up to 100 letters, digits and _ . : / -")
	}
	body := map[string]any{"title": title, "text": text, "alert_type": alert}
	if p.Priority != "" {
		body["priority"] = p.Priority
	}
	if len(p.Tags) > 0 {
		body["tags"] = p.Tags
	}
	if p.AggregationKey != "" {
		body["aggregation_key"] = p.AggregationKey
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Post a %s event %q to the event stream (events can't be deleted)", alert, clip(title, 80)),
			Changes: []sdk.Change{{Target: "event stream", Op: "post", After: mustJSON(body)}}}}, nil
	}
	var res struct {
		Event struct {
			ID  int64  `json:"id"`
			URL string `json:"url"`
		} `json:"event"`
		Status string `json:"status"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/api/v1/events", nil, body, &res); err != nil {
		return sdk.Result{}, friendly(err, "event")
	}
	return sdk.JSON(map[string]any{"event": res.Event.ID, "url": res.Event.URL, "status": res.Status})
}

func (c *conn) slos(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	q := url.Values{"page[size]": {strconv.Itoa(limit)}, "page[number]": {"0"}}
	if s := strings.TrimSpace(p.Search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search with letters, digits, spaces and _ . : / @ \" ( ) -")
		}
		q.Set("query", s)
	}
	var res struct {
		Data struct {
			Attributes struct {
				SLOs []struct {
					Data struct {
						ID         string `json:"id"`
						Attributes struct {
							Name    string   `json:"name"`
							Type    string   `json:"slo_type"`
							Tags    []string `json:"all_tags"`
							Overall []struct {
								Timeframe      string   `json:"timeframe"`
								Target         float64  `json:"target"`
								Status         *float64 `json:"status"`
								ErrorBudgetLft *float64 `json:"error_budget_remaining"`
								State          string   `json:"state"`
							} `json:"overall_status"`
						} `json:"attributes"`
					} `json:"data"`
				} `json:"slos"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/slo/search", q, nil, &res); err != nil {
		return sdk.Result{}, friendly(err, "SLO")
	}
	out := []map[string]any{}
	for _, s := range res.Data.Attributes.SLOs {
		a := s.Data.Attributes
		windows := []map[string]any{}
		for _, o := range a.Overall {
			w := map[string]any{"timeframe": o.Timeframe, "target": o.Target, "state": o.State}
			if o.Status != nil {
				w["current"] = *o.Status
			}
			if o.ErrorBudgetLft != nil {
				w["errorBudgetRemaining"] = *o.ErrorBudgetLft
			}
			windows = append(windows, w)
		}
		out = append(out, map[string]any{"id": s.Data.ID, "name": a.Name, "type": a.Type, "tags": a.Tags, "status": windows})
	}
	return sdk.JSON(out)
}
