// Package incidentio works with incident.io through its API and an API key:
// incidents (listing and details), severities and statuses, declaring an
// incident and moving one to another status.
package incidentio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// Config is one incident.io organization.
type Config struct {
	Token string `json:"token"` // secret:// API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.incident.io (tests).
	Base string
}

// New returns the incident.io module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.incident.io"

var (
	idRe  = regexp.MustCompile(`^[0-9A-Za-z]{10,40}$`)
	refRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,80}$`)
)

// categories are the status filters incidents offers, mapped to
// incident.io's status categories.
var categories = map[string][]string{
	"live":          {"triage", "active"},
	"post-incident": {"post-incident"},
	"closed":        {"closed"},
	"all":           nil,
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "incidentio", Name: "incident.io", Version: "0.1.0", Category: "Monitoring", Icon: "bell",
		Description: "incident.io: incidents, severities and statuses; declare an incident and change its status (both destructive: they run your workflows, which can page people and open channels).",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API key (Settings, API keys) that can view incidents, and create and edit them for changes"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "incidents", Title: "Incidents", Description: "Incidents, newest first: reference, name, status and its category, severity, mode, visibility, when it was created and its link. Live ones (triage and active) unless status says otherwise.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["live","post-incident","closed","all"],"default":"live"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "incident", Title: "Incident details", Description: "One incident with its summary, status, severity, type, channel and timestamps.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["incident"],"properties":{"incident":{"type":"string","description":"Incident id (see incidents)"}}}`)},
			{Name: "severities", Title: "Severities", Description: "Severities with their rank and description.", Risk: sdk.RiskRead},
			{Name: "statuses", Title: "Incident statuses", Description: "The statuses incidents can have, with their category (triage, active, post-incident, closed and others).", Risk: sdk.RiskRead},
			{Name: "create_incident", Title: "Declare an incident", Description: "Declares an incident. incident.io opens its channel and runs your workflows, which can page people and announce it, so this is destructive. Incidents can't be deleted through the API; test makes a test incident.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":200},"summary":{"type":"string","maxLength":5000},"severity":{"type":"string","description":"Severity id or name (see severities)"},"status":{"type":"string","description":"Status id or name (see statuses); incident.io's default when left out"},"visibility":{"type":"string","enum":["public","private"],"default":"public","description":"public: everyone in your organization can see it"},"test":{"type":"boolean","default":false,"description":"Declare a test incident"}}}`)},
			{Name: "update_status", Title: "Change an incident's status", Description: "Moves an incident to another status, such as monitoring or closed. Status changes run your workflows (updates, announcements, paging), so this is destructive. The incident's channel is told only with notifyChannel. Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["incident","status"],"properties":{"incident":{"type":"string","description":"Incident id (see incidents)"},"status":{"type":"string","description":"Status id or name (see statuses)"},"notifyChannel":{"type":"boolean","default":false,"description":"Post the change in the incident's channel"}}}`)},
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
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("incident.io refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("incident.io refused: the API key doesn't have the permission for this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("incident.io's rate limit was hit; try again in a minute")
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

// shown is free text from incidents, redacted before it's shortened.
func shown(s string, n int) string { return clip(rest.Redact(s), n) }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type status struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Rank        int    `json:"rank"`
}

type severity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Rank        int    `json:"rank"`
}

type incident struct {
	ID               string    `json:"id"`
	Reference        string    `json:"reference"`
	Name             string    `json:"name"`
	Summary          *string   `json:"summary"`
	Status           status    `json:"incident_status"`
	Severity         *severity `json:"severity"`
	Mode             string    `json:"mode"`
	Visibility       string    `json:"visibility"`
	CreatedAt        string    `json:"created_at"`
	UpdatedAt        string    `json:"updated_at"`
	Permalink        string    `json:"permalink"`
	SlackChannelName string    `json:"slack_channel_name"`
	Type             *struct {
		Name string `json:"name"`
	} `json:"incident_type"`
	Timestamps []struct {
		Name  string  `json:"name"`
		Value *string `json:"value"`
	} `json:"incident_timestamp_values"`
	// The creator and role assignments aren't decoded: they're people's
	// names and addresses, kept out of the audit log.
}

func (i incident) label() string {
	if i.Reference != "" {
		return clip(i.Reference, 30) + " " + shown(i.Name, 100)
	}
	return shown(i.Name, 100)
}

func incidentRow(i incident) map[string]any {
	row := map[string]any{"id": i.ID, "reference": clip(i.Reference, 30), "name": shown(i.Name, 200), "status": clip(i.Status.Name, 100), "statusCategory": i.Status.Category,
		"mode": i.Mode, "visibility": i.Visibility, "created": i.CreatedAt, "updated": i.UpdatedAt}
	if i.Severity != nil {
		row["severity"] = clip(i.Severity.Name, 100)
	}
	if i.Permalink != "" {
		row["link"] = clip(rest.CleanURL(i.Permalink), 300)
	}
	return row
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	is, err := c.list(ctx, "live", 25)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if n := len(is); n > 0 {
		more := ""
		if n == 25 {
			more = "+"
		}
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d%s live incident(s)", n, more)}
	}
	return sdk.Health{Status: "ok", Message: "No live incidents"}
}

func (c *conn) list(ctx context.Context, cat string, limit int) ([]incident, error) {
	q := url.Values{"page_size": {strconv.Itoa(limit)}}
	for _, s := range categories[cat] {
		q.Add("status_category[one_of]", s)
	}
	var res struct {
		Incidents []incident `json:"incidents"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/incidents", q, nil, &res); err != nil {
		return nil, friendly(err, "incidents API here")
	}
	return res.Incidents, nil
}

func (c *conn) incident(ctx context.Context, raw string) (incident, error) {
	id := strings.TrimSpace(raw)
	if !idRe.MatchString(id) {
		return incident{}, errors.New("the incident is its id (see incidents)")
	}
	var res struct {
		Incident incident `json:"incident"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/incidents/"+url.PathEscape(id), nil, nil, &res); err != nil {
		return incident{}, friendly(err, "incident "+id)
	}
	if res.Incident.ID != id {
		return incident{}, errors.New("incident.io answered with another incident")
	}
	return res.Incident, nil
}

func (c *conn) statuses(ctx context.Context) ([]status, error) {
	var res struct {
		Statuses []status `json:"incident_statuses"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/incident_statuses", nil, nil, &res); err != nil {
		return nil, friendly(err, "statuses API here")
	}
	sort.SliceStable(res.Statuses, func(a, b int) bool { return res.Statuses[a].Rank < res.Statuses[b].Rank })
	return res.Statuses, nil
}

func (c *conn) severities(ctx context.Context) ([]severity, error) {
	var res struct {
		Severities []severity `json:"severities"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/v1/severities", nil, nil, &res); err != nil {
		return nil, friendly(err, "severities API here")
	}
	sort.SliceStable(res.Severities, func(a, b int) bool { return res.Severities[a].Rank < res.Severities[b].Rank })
	return res.Severities, nil
}

// find matches an id, or a name ignoring case.
func find[T any](list []T, want string, id, name func(T) string) (T, bool) {
	for _, x := range list {
		if id(x) == want {
			return x, true
		}
	}
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(name(x)), want) {
			return x, true
		}
	}
	var zero T
	return zero, false
}

func (c *conn) findStatus(ctx context.Context, want string) (status, error) {
	ss, err := c.statuses(ctx)
	if err != nil {
		return status{}, err
	}
	s, ok := find(ss, want, func(s status) string { return s.ID }, func(s status) string { return s.Name })
	if !ok || !idRe.MatchString(s.ID) {
		return status{}, fmt.Errorf("there's no status %q (see statuses)", clip(want, 80))
	}
	return s, nil
}

type input struct {
	Status        string `json:"status"`
	Limit         int    `json:"limit"`
	Incident      string `json:"incident"`
	Name          string `json:"name"`
	Summary       string `json:"summary"`
	Severity      string `json:"severity"`
	Visibility    string `json:"visibility"`
	Test          bool   `json:"test"`
	NotifyChannel bool   `json:"notifyChannel"`
}

func text(s string, max int, multiline bool, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > max {
		return "", fmt.Errorf("%s is up to %d characters", what, max)
	}
	for _, r := range s {
		if (r < 0x20 && !(multiline && (r == '\n' || r == '\t'))) || r == 0x7f {
			return "", fmt.Errorf("%s has a control character", what)
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
	case "incidents":
		cat := p.Status
		if cat == "" {
			cat = "live"
		}
		if _, ok := categories[cat]; !ok {
			return sdk.Result{}, errors.New("the status is live, post-incident, closed or all")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		is, err := c.list(ctx, cat, limit)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			if len(out) == limit {
				break
			}
			out = append(out, incidentRow(i))
		}
		return sdk.JSON(out)

	case "incident":
		i, err := c.incident(ctx, p.Incident)
		if err != nil {
			return sdk.Result{}, err
		}
		row := incidentRow(i)
		if i.Summary != nil && *i.Summary != "" {
			row["summary"] = shown(*i.Summary, 2000)
		}
		if i.Type != nil && i.Type.Name != "" {
			row["type"] = clip(i.Type.Name, 100)
		}
		if i.SlackChannelName != "" {
			row["channel"] = "#" + clip(i.SlackChannelName, 100)
		}
		ts := map[string]string{}
		for _, t := range i.Timestamps {
			if t.Value != nil && *t.Value != "" && len(ts) < 20 {
				ts[clip(t.Name, 60)] = *t.Value
			}
		}
		if len(ts) > 0 {
			row["timestamps"] = ts
		}
		return sdk.JSON(row)

	case "severities":
		ss, err := c.severities(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, map[string]any{"id": s.ID, "name": clip(s.Name, 100), "rank": s.Rank, "description": clip(s.Description, 300)})
		}
		return sdk.JSON(out)

	case "statuses":
		ss, err := c.statuses(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			out = append(out, map[string]any{"id": s.ID, "name": clip(s.Name, 100), "category": s.Category, "description": clip(s.Description, 300)})
		}
		return sdk.JSON(out)

	case "create_incident":
		return c.create(ctx, call, p)

	case "update_status":
		want := strings.TrimSpace(p.Status)
		if !refRe.MatchString(want) {
			return sdk.Result{}, errors.New("the status is its id or name (see statuses)")
		}
		cur, err := c.incident(ctx, p.Incident)
		if err != nil {
			return sdk.Result{}, err
		}
		st, err := c.findStatus(ctx, want)
		if err != nil {
			return sdk.Result{}, err
		}
		label := cur.label()
		if st.ID == cur.Status.ID {
			return sdk.JSON(map[string]any{"id": cur.ID, "incident": label, "status": clip(st.Name, 100), "note": "nothing to change"})
		}
		if !idRe.MatchString(cur.Status.ID) {
			return sdk.Result{}, errors.New("unexpected answer from incident.io")
		}
		channel := "the incident's channel isn't told (notifyChannel is off)"
		if p.NotifyChannel {
			channel = "the change is posted in the incident's channel"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{
				Summary: fmt.Sprintf("Move %s from %s to %s; workflows that react to status changes run, and %s", label, clip(cur.Status.Name, 100), clip(st.Name, 100), channel),
				Changes: []sdk.Change{{Target: "incident " + label, Op: "update",
					Before: mustJSON(map[string]string{"status": cur.Status.Name, "category": cur.Status.Category}), After: mustJSON(map[string]string{"status": st.Name, "category": st.Category})}}}}, nil
		}
		body := map[string]any{"incident": map[string]string{"incident_status_id": st.ID}, "notify_incident_channel": p.NotifyChannel}
		var res struct {
			Incident incident `json:"incident"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/v2/incidents/"+url.PathEscape(cur.ID)+"/actions/edit", nil, body, &res); err != nil {
			return sdk.Result{}, friendly(err, "incident "+cur.ID)
		}
		if res.Incident.ID != "" && res.Incident.Status.ID != st.ID {
			return sdk.Result{}, fmt.Errorf("incident.io kept %s as %s", label, clip(res.Incident.Status.Name, 100))
		}
		r, err := sdk.JSON(map[string]any{"id": cur.ID, "incident": label, "status": clip(st.Name, 100), "was": clip(cur.Status.Name, 100), "channelNotified": p.NotifyChannel})
		r.Undo = sdk.UndoWith("update_status", map[string]string{"incident": cur.ID, "status": cur.Status.ID}, "Move "+label+" back to "+clip(cur.Status.Name, 60))
		return r, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	name, err := text(p.Name, 200, false, "the name")
	if err != nil {
		return sdk.Result{}, err
	}
	if name == "" {
		return sdk.Result{}, errors.New("an incident needs a name")
	}
	summary, err := text(p.Summary, 5000, true, "the summary")
	if err != nil {
		return sdk.Result{}, err
	}
	vis := p.Visibility
	if vis == "" {
		vis = "public"
	}
	if vis != "public" && vis != "private" {
		return sdk.Result{}, errors.New("the visibility is public or private")
	}
	sevIn, stIn := strings.TrimSpace(p.Severity), strings.TrimSpace(p.Status)
	if (sevIn != "" && !refRe.MatchString(sevIn)) || (stIn != "" && !refRe.MatchString(stIn)) {
		return sdk.Result{}, errors.New("a severity or status is its id or name (see severities and statuses)")
	}
	body := map[string]any{"name": name, "visibility": vis, "mode": "standard"}
	if p.Test {
		body["mode"] = "test"
	}
	if summary != "" {
		body["summary"] = summary
	}
	after := map[string]any{"name": name, "visibility": vis, "mode": body["mode"]}
	if summary != "" {
		after["summary"] = summary
	}
	if sevIn != "" {
		ss, err := c.severities(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		s, ok := find(ss, sevIn, func(s severity) string { return s.ID }, func(s severity) string { return s.Name })
		if !ok || !idRe.MatchString(s.ID) {
			return sdk.Result{}, fmt.Errorf("there's no severity %q (see severities)", clip(sevIn, 80))
		}
		body["severity_id"], after["severity"] = s.ID, s.Name
	}
	if stIn != "" {
		s, err := c.findStatus(ctx, stIn)
		if err != nil {
			return sdk.Result{}, err
		}
		body["incident_status_id"], after["status"] = s.ID, s.Name
	}
	if call.DryRun {
		kind := "an incident"
		if p.Test {
			kind = "a test incident"
		}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Declare %s %q (%s) in incident.io; it opens the incident's channel and runs your workflows, which can page people and announce it", kind, name, vis),
			Changes: []sdk.Change{{Target: "incident.io", Op: "create", After: mustJSON(after)}}}}, nil
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return sdk.Result{}, err
	}
	body["idempotency_key"] = "conduit-" + hex.EncodeToString(key)
	var res struct {
		Incident incident `json:"incident"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/v2/incidents", nil, body, &res); err != nil {
		return sdk.Result{}, friendly(err, "incidents API here")
	}
	return sdk.JSON(incidentRow(res.Incident))
}
