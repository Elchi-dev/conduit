// Package opsgenie works with Opsgenie through its REST API and an API key:
// alerts (listing, details, acknowledging, closing, notes), on-call
// schedules and who is on call.
package opsgenie

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

// Config is one Opsgenie account.
type Config struct {
	Token  string `json:"token"`  // secret:// API key (an API integration's key)
	Region string `json:"region"` // us (default) or eu
}

// Hosts are Opsgenie's API hosts by region.
var Hosts = map[string]string{
	"us": "https://api.opsgenie.com",
	"eu": "https://api.eu.opsgenie.com",
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the region's host (tests).
	Base string
}

// New returns the Opsgenie module.
func New() *Module { return &Module{} }

var (
	alertRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
	tinyRe  = regexp.MustCompile(`^[0-9]{1,12}$`)
	schedRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	byRe    = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,80}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	alert := `"alert":{"type":"string","description":"Alert id or its short number (tinyId), see alerts"}`
	by := `"by":{"type":"string","maxLength":80,"description":"Who asked, recorded after Conduit, e.g. \"Conduit (for ops@example.com)\"; it's always recorded as Conduit"}`
	note := `"note":{"type":"string","maxLength":5000,"description":"A note recorded with it"}`
	return sdk.Manifest{
		ID: "opsgenie", Name: "Opsgenie", Version: "0.1.0", Category: "Monitoring", Icon: "bell",
		Description: "Opsgenie: alerts (acknowledging and closing are destructive, they stop notifications), notes, on-call schedules and who's on call.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"The API key of an API integration (Settings, Integrations, API); give it read access, and create and update access for changes"},
			"region":{"type":"string","enum":["us","eu"],"default":"us","description":"eu when you sign in at app.eu.opsgenie.com"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "alerts", Title: "Alerts", Description: "Alerts, newest first: short number, message, status, priority, acknowledged, snoozed, count, tags and when it was created and last occurred. Open ones unless status says otherwise.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["open","closed","all"],"default":"open"},"priority":{"type":"string","enum":["P1","P2","P3","P4","P5"]},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "alert", Title: "Alert details", Description: "One alert with its description, details, tags, integration and when it was acknowledged or closed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["alert"],"properties":{` + alert + `}}`)},
			{Name: "acknowledge_alert", Title: "Acknowledge an alert", Description: "Acknowledges an open alert, which stops its notifications and escalation to further people (destructive). Recorded as Conduit. Undo unacknowledges it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["alert"],"properties":{` + alert + `,` + note + `,` + by + `}}`)},
			{Name: "unacknowledge_alert", Title: "Unacknowledge an alert", Description: "Takes the acknowledgement off an open alert, so notifications and escalation go on. Undo acknowledges it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["alert"],"properties":{` + alert + `,` + note + `,` + by + `}}`)},
			{Name: "close_alert", Title: "Close an alert", Description: "Closes an alert: its notifications and escalation stop even if the problem goes on (destructive). It can't be reopened; a new occurrence opens a new alert.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["alert"],"properties":{` + alert + `,` + note + `,` + by + `}}`)},
			{Name: "add_note", Title: "Add a note", Description: "Adds a note to an alert, recorded as Conduit. Notes can't be removed through the API.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["alert","note"],"properties":{` + alert + `,` + note + `,` + by + `}}`)},
			{Name: "schedules", Title: "On-call schedules", Description: "Schedules with their team, time zone and whether they're on.", Risk: sdk.RiskRead},
			{Name: "on_call", Title: "Who's on call", Description: "Who's on call now in each schedule (or one), by Opsgenie user name, which is their email address.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"schedule":{"type":"string","description":"Schedule id (see schedules); all enabled schedules when left out"}}}`)},
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
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	region := strings.ToLower(strings.TrimSpace(c.Region))
	if region == "" {
		region = "us"
	}
	base, ok := Hosts[region]
	if !ok {
		return errors.New("the region is us or eu")
	}
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "GenieKey "+strings.TrimSpace(t))
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
		return errors.New("Opsgenie refused the API key (is the region right?)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Opsgenie refused: the API key's integration isn't allowed to do this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Opsgenie's rate limit was hit; try again in a minute")
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

// shown is free text from alerts, redacted before it's shortened (a
// credential cut in half would no longer be recognised).
func shown(s string, n int) string { return clip(rest.Redact(s), n) }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var res struct {
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/alerts/count", url.Values{"query": {"status:open AND acknowledged:false"}}, nil, &res); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Opsgenie API here").Error()}
	}
	if n := res.Data.Count; n > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d open unacknowledged alert(s)", n)}
	}
	return sdk.Health{Status: "ok", Message: "No open unacknowledged alerts"}
}

type alert struct {
	ID             string            `json:"id"`
	TinyID         string            `json:"tinyId"`
	Message        string            `json:"message"`
	Status         string            `json:"status"`
	Acknowledged   bool              `json:"acknowledged"`
	Snoozed        bool              `json:"snoozed"`
	Count          int               `json:"count"`
	Priority       string            `json:"priority"`
	Tags           []string          `json:"tags"`
	CreatedAt      string            `json:"createdAt"`
	UpdatedAt      string            `json:"updatedAt"`
	LastOccurredAt string            `json:"lastOccurredAt"`
	Description    string            `json:"description"`
	Details        map[string]string `json:"details"`
	Entity         string            `json:"entity"`
	Integration    struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"integration"`
	Report struct {
		AckTime   int64 `json:"ackTime"`
		CloseTime int64 `json:"closeTime"`
	} `json:"report"`
	// owner, source and who acknowledged or closed it aren't decoded:
	// they're people's names and addresses, kept out of the audit log.
}

func (a alert) label() string {
	if a.TinyID != "" {
		return "#" + a.TinyID + " " + shown(a.Message, 100)
	}
	return shown(a.Message, 100)
}

func alertRow(a alert) map[string]any {
	tags := []string{}
	for _, t := range a.Tags {
		tags = append(tags, shown(t, 100))
	}
	return map[string]any{"id": a.ID, "tinyId": a.TinyID, "message": shown(a.Message, 300), "status": a.Status, "priority": a.Priority,
		"acknowledged": a.Acknowledged, "snoozed": a.Snoozed, "count": a.Count, "tags": tags, "created": a.CreatedAt, "lastOccurred": a.LastOccurredAt}
}

type input struct {
	Status   string `json:"status"`
	Priority string `json:"priority"`
	Limit    int    `json:"limit"`
	Alert    string `json:"alert"`
	Note     string `json:"note"`
	By       string `json:"by"`
	Schedule string `json:"schedule"`
}

func (c *conn) alert(ctx context.Context, raw string) (alert, error) {
	id := strings.TrimSpace(raw)
	kind := "id"
	switch {
	case tinyRe.MatchString(id):
		kind = "tiny"
	case alertRe.MatchString(id):
	default:
		return alert{}, errors.New("the alert is its id or short number (see alerts)")
	}
	var res struct {
		Data alert `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/alerts/"+url.PathEscape(id), url.Values{"identifierType": {kind}}, nil, &res); err != nil {
		return alert{}, friendly(err, "alert "+id)
	}
	if (kind == "id" && res.Data.ID != id) || (kind == "tiny" && res.Data.TinyID != id) || !alertRe.MatchString(res.Data.ID) {
		return alert{}, errors.New("Opsgenie answered with another alert")
	}
	return res.Data, nil
}

// actor is the name an action is recorded under: always Conduit, so an
// agent can't put an acknowledgement on a person's name.
func actor(by string) (string, error) {
	who := strings.TrimSpace(by)
	if who == "" {
		return "Conduit", nil
	}
	if !byRe.MatchString(who) {
		return "", errors.New("by is up to 80 characters")
	}
	return "Conduit (for " + who + ")", nil
}

func checkNote(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 5000 {
		return "", errors.New("a note is up to 5000 characters")
	}
	for _, r := range s {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return "", errors.New("the note has a control character")
		}
	}
	return s, nil
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
	case "alerts":
		status := p.Status
		if status == "" {
			status = "open"
		}
		var q []string
		switch status {
		case "open", "closed":
			q = append(q, "status:"+status)
		case "all":
		default:
			return sdk.Result{}, errors.New("the status is open, closed or all")
		}
		if p.Priority != "" {
			switch p.Priority {
			case "P1", "P2", "P3", "P4", "P5":
				q = append(q, "priority:"+p.Priority)
			default:
				return sdk.Result{}, errors.New("the priority is P1 to P5")
			}
		}
		limit := p.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		v := url.Values{"limit": {strconv.Itoa(limit)}, "sort": {"createdAt"}, "order": {"desc"}}
		if len(q) > 0 {
			v.Set("query", strings.Join(q, " AND "))
		}
		var res struct {
			Data []alert `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/v2/alerts", v, nil, &res); err != nil {
			return sdk.Result{}, friendly(err, "alerts API")
		}
		out := []map[string]any{}
		for _, a := range res.Data {
			if len(out) == limit {
				break
			}
			out = append(out, alertRow(a))
		}
		return sdk.JSON(out)

	case "alert":
		a, err := c.alert(ctx, p.Alert)
		if err != nil {
			return sdk.Result{}, err
		}
		row := alertRow(a)
		if a.Description != "" {
			row["description"] = shown(a.Description, 2000)
		}
		if a.Entity != "" {
			row["entity"] = shown(a.Entity, 200)
		}
		if a.Integration.Name != "" {
			row["integration"] = clip(a.Integration.Name, 100) + " (" + clip(a.Integration.Type, 50) + ")"
		}
		if len(a.Details) > 0 {
			keys := make([]string, 0, len(a.Details))
			for k := range a.Details {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			d := map[string]string{}
			for i, k := range keys {
				if i == 30 {
					break
				}
				d[clip(k, 100)] = shown(a.Details[k], 300)
			}
			row["details"] = d
		}
		if a.Report.AckTime > 0 {
			row["msToAcknowledge"] = a.Report.AckTime
		}
		if a.Report.CloseTime > 0 {
			row["msToClose"] = a.Report.CloseTime
		}
		row["updated"] = a.UpdatedAt
		return sdk.JSON(row)

	case "acknowledge_alert", "unacknowledge_alert", "close_alert", "add_note":
		by, err := actor(p.By)
		if err != nil {
			return sdk.Result{}, err
		}
		note, err := checkNote(p.Note)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "add_note" && note == "" {
			return sdk.Result{}, errors.New("the note is empty")
		}
		a, err := c.alert(ctx, p.Alert)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.change(ctx, call, a, by, note)

	case "schedules":
		scheds, err := c.schedules(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range scheds {
			row := map[string]any{"id": s.ID, "name": clip(s.Name, 200), "timezone": s.Timezone, "enabled": s.Enabled}
			if s.OwnerTeam != nil && s.OwnerTeam.Name != "" {
				row["team"] = clip(s.OwnerTeam.Name, 200)
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "on_call":
		var ids []string
		names := map[string]string{}
		if s := strings.TrimSpace(p.Schedule); s != "" {
			if !schedRe.MatchString(s) {
				return sdk.Result{}, errors.New("the schedule is its id (see schedules)")
			}
			ids = []string{s}
		} else {
			scheds, err := c.schedules(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, s := range scheds {
				if s.Enabled && schedRe.MatchString(s.ID) && len(ids) < 25 {
					ids = append(ids, s.ID)
					names[s.ID] = s.Name
				}
			}
		}
		out := []map[string]any{}
		for _, id := range ids {
			var res struct {
				Data struct {
					Parent struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"_parent"`
					Recipients []string `json:"onCallRecipients"`
				} `json:"data"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/v2/schedules/"+url.PathEscape(id)+"/on-calls", url.Values{"scheduleIdentifierType": {"id"}, "flat": {"true"}}, nil, &res); err != nil {
				return sdk.Result{}, friendly(err, "schedule "+id)
			}
			name := res.Data.Parent.Name
			if name == "" {
				name = names[id]
			}
			who := []string{}
			for _, r := range res.Data.Recipients {
				who = append(who, clip(r, 200))
			}
			out = append(out, map[string]any{"schedule": clip(name, 200), "id": id, "onCall": who})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type schedule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Timezone  string `json:"timezone"`
	Enabled   bool   `json:"enabled"`
	OwnerTeam *struct {
		Name string `json:"name"`
	} `json:"ownerTeam"`
}

func (c *conn) schedules(ctx context.Context) ([]schedule, error) {
	var res struct {
		Data []schedule `json:"data"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/schedules", nil, nil, &res); err != nil {
		return nil, friendly(err, "schedules API")
	}
	return res.Data, nil
}

func (c *conn) change(ctx context.Context, call sdk.Call, a alert, by, note string) (sdk.Result, error) {
	label := a.label()
	closed := a.Status == "closed"
	switch call.Action {
	case "acknowledge_alert":
		if closed {
			return sdk.JSON(map[string]any{"id": a.ID, "alert": label, "note": "the alert is already closed"})
		}
		if a.Acknowledged {
			return sdk.JSON(map[string]any{"id": a.ID, "alert": label, "note": "nothing to change: the alert is already acknowledged"})
		}
	case "unacknowledge_alert":
		if closed {
			return sdk.JSON(map[string]any{"id": a.ID, "alert": label, "note": "the alert is closed"})
		}
		if !a.Acknowledged {
			return sdk.JSON(map[string]any{"id": a.ID, "alert": label, "note": "nothing to change: the alert isn't acknowledged"})
		}
	case "close_alert":
		if closed {
			return sdk.JSON(map[string]any{"id": a.ID, "alert": label, "note": "nothing to change: the alert is already closed"})
		}
	}
	op := map[string]string{"acknowledge_alert": "acknowledge", "unacknowledge_alert": "unacknowledge", "close_alert": "close", "add_note": "notes"}[call.Action]
	if call.DryRun {
		var sum string
		after := map[string]any{"acknowledged": a.Acknowledged, "status": a.Status}
		switch call.Action {
		case "acknowledge_alert":
			sum = "Acknowledge alert " + label + " as " + by + "; its notifications and escalation stop"
			after["acknowledged"] = true
		case "unacknowledge_alert":
			sum = "Unacknowledge alert " + label + " as " + by + "; notifications and escalation go on"
			after["acknowledged"] = false
		case "close_alert":
			sum = "Close alert " + label + " as " + by + "; notifications and escalation stop even if the problem goes on"
			after["status"] = "closed"
		}
		if note != "" {
			after["note"] = note
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "alert " + label, Op: op,
			Before: mustJSON(map[string]any{"acknowledged": a.Acknowledged, "status": a.Status}), After: mustJSON(after)}}}}, nil
	}
	body := map[string]string{"user": by, "source": "Conduit"}
	if note != "" {
		body["note"] = note
	}
	var res struct {
		Result    string `json:"result"`
		RequestID string `json:"requestId"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/v2/alerts/"+url.PathEscape(a.ID)+"/"+op, url.Values{"identifierType": {"id"}}, body, &res); err != nil {
		return sdk.Result{}, friendly(err, "alert "+a.ID)
	}
	out := map[string]any{"id": a.ID, "alert": label, "requested": op, "requestId": clip(res.RequestID, 100),
		"note": "Opsgenie carries requests out in the background, usually within seconds"}
	if call.Action == "add_note" {
		out["requested"] = "add note"
	}
	r, err := sdk.JSON(out)
	switch call.Action {
	case "acknowledge_alert":
		r.Undo = sdk.UndoWith("unacknowledge_alert", map[string]string{"alert": a.ID}, "Unacknowledge "+label)
	case "unacknowledge_alert":
		r.Undo = sdk.UndoWith("acknowledge_alert", map[string]string{"alert": a.ID}, "Acknowledge "+label+" again")
	}
	return r, err
}
