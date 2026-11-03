// Package pagerduty shows and handles PagerDuty incidents and on-call, and
// sends events that open or resolve incidents.
package pagerduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one PagerDuty account. Either part may be set.
type Config struct {
	Token      string `json:"token"`      // secret:// REST API key
	From       string `json:"from"`       // email of a PagerDuty user, required for changes
	RoutingKey string `json:"routingKey"` // secret:// Events API v2 integration key
	API        string `json:"api"`        // default https://api.pagerduty.com (tests)
	Events     string `json:"events"`     // default https://events.pagerduty.com (tests)
}

type conn struct {
	cfg    Config
	api    *rest.Client
	events *rest.Client
	host   sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the PagerDuty module.
func New() *Module { return &Module{} }

var (
	idRe    = regexp.MustCompile(`^[A-Z0-9]{5,20}$`)
	dedupRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Incident id, e.g. PT4KHLK"}}}`)
	return sdk.Manifest{
		ID: "pagerduty", Name: "PagerDuty", Version: "0.1.0", Category: "Operations", Icon: "bell",
		Description: "Open incidents and who's on call; acknowledge and resolve incidents, or open one from an automation.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"token":{"type":"string","x-secret":true,"description":"A REST API key (Integrations, API Access Keys); read-only is enough for viewing"},
			"from":{"type":"string","format":"email","description":"Email of the PagerDuty user changes are made as"},
			"routingKey":{"type":"string","x-secret":true,"description":"An Events API v2 integration key of a service, to open incidents"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "incidents", Title: "Open incidents", Description: "Triggered and acknowledged incidents.", Risk: sdk.RiskRead},
			{Name: "oncall", Title: "On call now", Risk: sdk.RiskRead},
			{Name: "acknowledge", Title: "Acknowledge an incident", Risk: sdk.RiskWrite, Input: id},
			{Name: "resolve", Title: "Resolve an incident", Risk: sdk.RiskWrite, Input: id},
			{Name: "trigger", Title: "Open an incident", Description: "Through the Events API of the service the routing key belongs to.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["summary"],"properties":{"summary":{"type":"string","maxLength":1024},"severity":{"type":"string","enum":["critical","error","warning","info"],"default":"error"},"source":{"type":"string","default":"conduit"},"dedupKey":{"type":"string"}}}`)},
			{Name: "resolve_event", Title: "Resolve an event", Description: "Resolves the incident an earlier event opened, by its dedup key.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["dedupKey"],"properties":{"dedupKey":{"type":"string"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Token == "" && c.RoutingKey == "" {
		return errors.New("add a REST API key, an Events routing key, or both (stored in the vault)")
	}
	if c.From != "" {
		if _, err := mail.ParseAddress(c.From); err != nil {
			return errors.New("the From address is a PagerDuty user's email")
		}
	}
	if c.API == "" {
		c.API = "https://api.pagerduty.com"
	}
	if c.Events == "" {
		c.Events = "https://events.pagerduty.com"
	}
	cn := &conn{cfg: c, host: h}
	if c.Token != "" {
		tok := c.Token
		cn.api = rest.New(c.API, func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Token token="+strings.TrimSpace(t))
			r.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
			if c.From != "" {
				r.Header.Set("From", c.From)
			}
			return nil
		})
		if m.HTTP != nil {
			cn.api.HTTP = m.HTTP
		}
	}
	cn.events = rest.New(c.Events, nil)
	if m.HTTP != nil {
		cn.events.HTTP = m.HTTP
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if c.api == nil {
		return sdk.Health{Status: "ok", Message: "Events only (no API key to check)"}
	}
	var res struct {
		Incidents []struct{} `json:"incidents"`
		More      bool       `json:"more"`
	}
	if _, err := c.api.Do(ctx, "GET", "/incidents", url.Values{"statuses[]": {"triggered"}, "limit": {"25"}}, nil, &res); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if n := len(res.Incidents); n > 0 {
		more := ""
		if res.More {
			more = "+"
		}
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d%s triggered incident(s)", n, more)}
	}
	return sdk.Health{Status: "ok", Message: "No triggered incidents"}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		Source   string `json:"source"`
		DedupKey string `json:"dedupKey"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needAPI := func() error {
		if c.api == nil {
			return errors.New("this needs a REST API key in the settings")
		}
		return nil
	}
	switch call.Action {
	case "incidents":
		if err := needAPI(); err != nil {
			return sdk.Result{}, err
		}
		var res struct {
			Incidents []struct {
				ID          string                   `json:"id"`
				Number      int                      `json:"incident_number"`
				Title       string                   `json:"title"`
				Status      string                   `json:"status"`
				Urgency     string                   `json:"urgency"`
				CreatedAt   string                   `json:"created_at"`
				HTMLURL     string                   `json:"html_url"`
				Service     struct{ Summary string } `json:"service"`
				Assignments []struct {
					Assignee struct{ Summary string } `json:"assignee"`
				} `json:"assignments"`
			} `json:"incidents"`
		}
		q := url.Values{"statuses[]": {"triggered", "acknowledged"}, "limit": {"50"}, "sort_by": {"created_at:desc"}}
		if _, err := c.api.Do(ctx, "GET", "/incidents", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range res.Incidents {
			who := []string{}
			for _, a := range i.Assignments {
				who = append(who, a.Assignee.Summary)
			}
			out = append(out, map[string]any{"id": i.ID, "number": i.Number, "title": i.Title, "status": i.Status, "urgency": i.Urgency,
				"service": i.Service.Summary, "assigned": who, "created": i.CreatedAt, "url": i.HTMLURL})
		}
		return sdk.JSON(out)

	case "oncall":
		if err := needAPI(); err != nil {
			return sdk.Result{}, err
		}
		var res struct {
			Oncalls []struct {
				User             struct{ Summary string }  `json:"user"`
				Schedule         *struct{ Summary string } `json:"schedule"`
				EscalationPolicy struct{ Summary string }  `json:"escalation_policy"`
				Level            int                       `json:"escalation_level"`
				End              string                    `json:"end"`
			} `json:"oncalls"`
		}
		if _, err := c.api.Do(ctx, "GET", "/oncalls", url.Values{"earliest": {"true"}, "limit": {"100"}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, o := range res.Oncalls {
			row := map[string]any{"person": o.User.Summary, "policy": o.EscalationPolicy.Summary, "level": o.Level, "until": o.End}
			if o.Schedule != nil {
				row["schedule"] = o.Schedule.Summary
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "acknowledge", "resolve":
		if err := needAPI(); err != nil {
			return sdk.Result{}, err
		}
		if c.cfg.From == "" {
			return sdk.Result{}, errors.New("set From in the settings: PagerDuty records changes as a user")
		}
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("an incident id looks like PT4KHLK")
		}
		status := map[string]string{"acknowledge": "acknowledged", "resolve": "resolved"}[call.Action]
		body := map[string]any{"incident": map[string]string{"type": "incident_reference", "status": status}}
		if _, err := c.api.Do(ctx, "PUT", "/incidents/"+p.ID, nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"id": p.ID, "status": status})

	case "trigger", "resolve_event":
		if c.cfg.RoutingKey == "" {
			return sdk.Result{}, errors.New("this needs an Events routing key in the settings")
		}
		key, err := c.host.Secret(ctx, c.cfg.RoutingKey)
		if err != nil {
			return sdk.Result{}, err
		}
		ev := map[string]any{"routing_key": strings.TrimSpace(key)}
		if call.Action == "resolve_event" {
			if !dedupRe.MatchString(p.DedupKey) {
				return sdk.Result{}, errors.New("the dedup key from the event that opened the incident is required")
			}
			ev["event_action"], ev["dedup_key"] = "resolve", p.DedupKey
		} else {
			if strings.TrimSpace(p.Summary) == "" || len(p.Summary) > 1024 {
				return sdk.Result{}, errors.New("a summary is 1 to 1024 characters")
			}
			sev := p.Severity
			if sev == "" {
				sev = "error"
			}
			switch sev {
			case "critical", "error", "warning", "info":
			default:
				return sdk.Result{}, errors.New("severity is critical, error, warning or info")
			}
			src := p.Source
			if src == "" {
				src = "conduit"
			}
			ev["event_action"] = "trigger"
			ev["payload"] = map[string]string{"summary": p.Summary, "severity": sev, "source": src}
			if p.DedupKey != "" {
				if !dedupRe.MatchString(p.DedupKey) {
					return sdk.Result{}, errors.New("a dedup key is letters, digits and . _ : -")
				}
				ev["dedup_key"] = p.DedupKey
			}
		}
		var res struct {
			Status   string `json:"status"`
			Message  string `json:"message"`
			DedupKey string `json:"dedup_key"`
		}
		if _, err := c.events.Do(ctx, "POST", "/v2/enqueue", nil, ev, &res); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"status": res.Status, "dedupKey": res.DedupKey})
		if call.Action == "trigger" && res.DedupKey != "" {
			r.Undo = sdk.UndoWith("resolve_event", map[string]string{"dedupKey": res.DedupKey}, "Resolve the incident it opened")
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
