// Package betterstack works with Better Stack Uptime through its API with a
// team API token: monitors and their status, incidents (listing,
// acknowledging, resolving), who's on call and status pages.
package betterstack

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

// Config is one Better Stack team.
type Config struct {
	Token string `json:"token"` // secret:// Uptime API token
}

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://uptime.betterstack.com/api (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Better Stack module.
func New() *Module { return &Module{} }

const defaultBase = "https://uptime.betterstack.com/api"

var (
	idRe = regexp.MustCompile(`^[0-9]{1,20}$`)
	byRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	incident := `"incident":{"type":"string","description":"Incident ID (see incidents)"},"by":{"type":"string","maxLength":80,"description":"Who asked, recorded after Conduit, e.g. \"Conduit (for ops@example.com)\"; it's always recorded as Conduit"}`
	return sdk.Manifest{
		ID: "betterstack", Name: "Better Stack Uptime", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Better Stack Uptime: monitors and their status, incidents (acknowledging and resolving are destructive), who's on call, status pages.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An Uptime API token (Settings, API tokens; a team token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "monitors", Title: "Monitors", Description: "Monitors with type, status (up, down, paused, pending, maintenance, validating), check frequency and when they were last checked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["up","down","paused","pending","maintenance","validating"],"description":"Only monitors in this status"}}}`)},
			{Name: "incidents", Title: "Incidents", Description: "Incidents over the last days, newest first: name, cause, when it started, whether acknowledged and resolved. Unresolved only unless includeResolved.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":90,"default":7},"includeResolved":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "acknowledge_incident", Title: "Acknowledge an incident", Description: "Acknowledges an ongoing incident, which stops its escalation to further people (destructive: nobody else gets paged). It's recorded as acknowledged by Conduit. It can't be un-acknowledged.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident"],"properties":{` + incident + `}}`)},
			{Name: "resolve_incident", Title: "Resolve an incident", Description: "Resolves an incident: alerting and escalation for it stop even if the monitor is still failing (destructive). It can't be reopened.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident"],"properties":{` + incident + `}}`)},
			{Name: "on_call", Title: "On call now", Description: "Who's on call now in each on-call calendar, with name and email.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "status_pages", Title: "Status pages", Description: "Status pages with their address and overall state.", Risk: sdk.RiskRead},
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
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Better Stack refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Better Stack refused: the token can't do this (is it a team token with write access?)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Better Stack's rate limit was hit; try again in a minute")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a page[monitorAttrs]
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/monitors", url.Values{"per_page": {"1"}}, nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "API here").Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected"}
}

type resource[T any] struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes T      `json:"attributes"`
}

type page[T any] struct {
	Data       []resource[T] `json:"data"`
	Pagination struct {
		Next *string `json:"next"`
	} `json:"pagination"`
}

type monitorAttrs struct {
	URL           string  `json:"url"`
	Name          string  `json:"pronounceable_name"`
	Type          string  `json:"monitor_type"`
	Status        string  `json:"status"`
	LastCheckedAt *string `json:"last_checked_at"`
	Paused        bool    `json:"paused"`
	CheckFreq     int     `json:"check_frequency"`
}

type incidentAttrs struct {
	Name           string  `json:"name"`
	URL            *string `json:"url"`
	Cause          string  `json:"cause"`
	StartedAt      string  `json:"started_at"`
	AcknowledgedAt *string `json:"acknowledged_at"`
	ResolvedAt     *string `json:"resolved_at"`
	Status         string  `json:"status"`
	TeamName       string  `json:"team_name"`
}

type statusPageAttrs struct {
	Company   string  `json:"company_name"`
	Subdomain string  `json:"subdomain"`
	Custom    *string `json:"custom_domain"`
	State     string  `json:"aggregate_state"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// shownURL is an address cut to scheme://host and its first path segment
// (rest.ShortURL): a token in the path, the query or the user part would
// end up in the audit log.
func shownURL(s string) string {
	return clip(rest.ShortURL(s), 300)
}

func incidentOut(r resource[incidentAttrs]) map[string]any {
	a := r.Attributes
	out := map[string]any{"id": r.ID, "name": clip(a.Name, 200), "cause": rest.Redact(clip(a.Cause, 300)), "started": a.StartedAt,
		"acknowledged": a.AcknowledgedAt != nil, "resolved": a.ResolvedAt != nil}
	if a.Status != "" {
		out["status"] = a.Status
	}
	if u := shownURL(str(a.URL)); u != "" {
		out["url"] = u
	}
	if v := str(a.AcknowledgedAt); v != "" {
		out["acknowledgedAt"] = v
	}
	if v := str(a.ResolvedAt); v != "" {
		out["resolvedAt"] = v
	}
	if a.TeamName != "" {
		out["team"] = clip(a.TeamName, 100)
	}
	return out
}

type input struct {
	Status          string `json:"status"`
	Days            int    `json:"days"`
	IncludeResolved bool   `json:"includeResolved"`
	Limit           int    `json:"limit"`
	Incident        string `json:"incident"`
	By              string `json:"by"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// pages fetches up to max pages of a list.
func pages[T any](ctx context.Context, c *conn, path string, q url.Values, max int, keep func(resource[T]) bool) ([]resource[T], error) {
	var all []resource[T]
	for pg := 1; pg <= max; pg++ {
		q.Set("page", strconv.Itoa(pg))
		var a page[T]
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &a); err != nil {
			return nil, err
		}
		for _, r := range a.Data {
			if keep(r) {
				all = append(all, r)
			}
		}
		if a.Pagination.Next == nil || *a.Pagination.Next == "" || len(a.Data) == 0 {
			break
		}
	}
	return all, nil
}

func (c *conn) incident(ctx context.Context, raw string) (resource[incidentAttrs], error) {
	id := strings.TrimSpace(raw)
	if !idRe.MatchString(id) {
		return resource[incidentAttrs]{}, errors.New("the incident is its ID, a number (see incidents)")
	}
	var a struct {
		Data resource[incidentAttrs] `json:"data"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/v3/incidents/"+id, nil, nil, &a)
	if rest.IsStatus(err, http.StatusNotFound) {
		_, err = c.api.Do(ctx, http.MethodGet, "/v2/incidents/"+id, nil, nil, &a)
	}
	if err != nil {
		return resource[incidentAttrs]{}, friendly(err, "incident "+id)
	}
	if a.Data.ID != id {
		return resource[incidentAttrs]{}, errors.New("unexpected answer from Better Stack")
	}
	return a.Data, nil
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
		switch p.Status {
		case "", "up", "down", "paused", "pending", "maintenance", "validating":
		default:
			return sdk.Result{}, errors.New("the status is up, down, paused, pending, maintenance or validating")
		}
		ms, err := pages(ctx, c, "/v2/monitors", url.Values{"per_page": {"100"}}, 10, func(r resource[monitorAttrs]) bool {
			return p.Status == "" || r.Attributes.Status == p.Status
		})
		if err != nil {
			return sdk.Result{}, friendly(err, "monitor")
		}
		list := []map[string]any{}
		by := map[string]int{}
		for _, r := range ms {
			a := r.Attributes
			by[a.Status]++
			name := a.Name
			if name == "" {
				name = shownURL(a.URL)
			}
			e := map[string]any{"id": r.ID, "name": clip(name, 200), "type": a.Type, "status": a.Status, "checkEverySeconds": a.CheckFreq}
			if u := shownURL(a.URL); u != "" && a.Type != "heartbeat" {
				e["url"] = u
			}
			if v := str(a.LastCheckedAt); v != "" {
				e["lastChecked"] = v
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"monitors": list, "byStatus": by})

	case "incidents":
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 90 {
			return sdk.Result{}, errors.New("days is between 1 and 90")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		now := c.now().UTC()
		q := url.Values{"from": {now.AddDate(0, 0, -days).Format("2006-01-02")}, "to": {now.Format("2006-01-02")}, "per_page": {strconv.Itoa(limit)}}
		if !p.IncludeResolved {
			q.Set("resolved", "false")
		}
		var a page[incidentAttrs]
		_, err := c.api.Do(ctx, http.MethodGet, "/v3/incidents", q, nil, &a)
		if rest.IsStatus(err, http.StatusNotFound) {
			_, err = c.api.Do(ctx, http.MethodGet, "/v2/incidents", q, nil, &a)
		}
		if err != nil {
			return sdk.Result{}, friendly(err, "incidents API")
		}
		list := []map[string]any{}
		for _, r := range a.Data {
			if len(list) == limit {
				break
			}
			if !p.IncludeResolved && r.Attributes.ResolvedAt != nil {
				continue
			}
			list = append(list, incidentOut(r))
		}
		return sdk.JSON(map[string]any{"days": days, "incidents": list})

	case "acknowledge_incident", "resolve_incident":
		ack := call.Action == "acknowledge_incident"
		// Always recorded as Conduit: an agent mustn't put an incident's
		// acknowledgement on a person's name. who's asking goes after it.
		by := "Conduit"
		if who := strings.TrimSpace(p.By); who != "" {
			if !byRe.MatchString(who) || len([]rune(who)) > 80 {
				return sdk.Result{}, errors.New("by is up to 80 characters")
			}
			by = "Conduit (for " + who + ")"
		}
		r, err := c.incident(ctx, p.Incident)
		if err != nil {
			return sdk.Result{}, err
		}
		a := r.Attributes
		label := clip(a.Name, 100)
		if a.ResolvedAt != nil {
			return sdk.JSON(map[string]any{"id": r.ID, "name": label, "note": "the incident is already resolved"})
		}
		if ack && a.AcknowledgedAt != nil {
			return sdk.JSON(map[string]any{"id": r.ID, "name": label, "note": "the incident is already acknowledged"})
		}
		verb, field, op := "Acknowledge", "acknowledged_by", "acknowledge"
		if !ack {
			verb, field, op = "Resolve", "resolved_by", "resolve"
		}
		if call.DryRun {
			sum := fmt.Sprintf("%s incident %s (%s) as %s", verb, label, clip(a.Cause, 120), by)
			if ack {
				sum += "; escalation to further people stops"
			} else {
				sum += "; alerting stops even if the monitor is still failing"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "incident " + r.ID, Op: op,
				Before: mustJSON(map[string]any{"acknowledged": a.AcknowledgedAt != nil, "resolved": false}), After: mustJSON(map[string]any{"acknowledged": true, "resolved": !ack})}}}}, nil
		}
		var after struct {
			Data resource[incidentAttrs] `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/v2/incidents/"+r.ID+"/"+op, nil, map[string]string{field: by}, &after); err != nil {
			return sdk.Result{}, friendly(err, "incident "+r.ID)
		}
		out := map[string]any{"id": r.ID, "name": label}
		if ack {
			out["acknowledged"] = true
		} else {
			out["resolved"] = true
		}
		return sdk.JSON(out)

	case "on_call":
		var a struct {
			Data []struct {
				ID         string `json:"id"`
				Attributes struct {
					Name    *string `json:"name"`
					Default bool    `json:"default_calendar"`
				} `json:"attributes"`
				Relationships struct {
					Users struct {
						Data []struct {
							ID string `json:"id"`
						} `json:"data"`
					} `json:"on_call_users"`
				} `json:"relationships"`
			} `json:"data"`
			Included []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Attributes struct {
					First string `json:"first_name"`
					Last  string `json:"last_name"`
					Email string `json:"email"`
				} `json:"attributes"`
			} `json:"included"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/v2/on-calls", nil, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "on-call calendar")
		}
		users := map[string]map[string]any{}
		for _, inc := range a.Included {
			if inc.Type != "user" {
				continue
			}
			users[inc.ID] = map[string]any{"name": clip(strings.TrimSpace(inc.Attributes.First+" "+inc.Attributes.Last), 100), "email": clip(inc.Attributes.Email, 200)}
		}
		list := []map[string]any{}
		for _, cal := range a.Data {
			name := "Default"
			if cal.Attributes.Name != nil && *cal.Attributes.Name != "" {
				name = clip(*cal.Attributes.Name, 100)
			}
			on := []map[string]any{}
			for _, u := range cal.Relationships.Users.Data {
				if v, ok := users[u.ID]; ok {
					on = append(on, v)
				}
			}
			list = append(list, map[string]any{"id": cal.ID, "calendar": name, "default": cal.Attributes.Default, "onCall": on})
		}
		return sdk.JSON(map[string]any{"calendars": list})

	case "status_pages":
		ps, err := pages(ctx, c, "/v2/status-pages", url.Values{"per_page": {"100"}}, 5, func(resource[statusPageAttrs]) bool { return true })
		if err != nil {
			return sdk.Result{}, friendly(err, "status page")
		}
		list := []map[string]any{}
		for _, r := range ps {
			a := r.Attributes
			addr := ""
			if a.Subdomain != "" {
				addr = "https://" + clip(a.Subdomain, 63) + ".betteruptime.com"
			}
			if d := str(a.Custom); d != "" {
				addr = "https://" + clip(d, 253)
			}
			list = append(list, map[string]any{"id": r.ID, "name": clip(a.Company, 200), "address": addr, "state": a.State})
		}
		return sdk.JSON(map[string]any{"statusPages": list})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
