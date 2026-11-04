// Package kimai works with a Kimai time tracker through its REST API and an
// API token: projects, activities, timesheets, and starting or stopping a
// timer.
//
// Starting and stopping a timer are writes with an undo: stopping undoes a
// start, and a stop is undone by starting a new timer on the same project
// and activity. Rates and budgets are never read.
package kimai

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Kimai user.
type Config struct {
	URL                string `json:"url"`   // e.g. https://time.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
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
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Kimai module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	tagRe  = regexp.MustCompile(`^[^,]{1,100}$`)
)

const (
	maxDesc = 2000
	maxTags = 20
	maxDays = 366
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	timer := `"project":{"type":"integer","minimum":1,"description":"Project id (see projects)"},"activity":{"type":"integer","minimum":1,"description":"Activity id (see activities)"},"description":{"type":"string"},"tags":{"type":"array","maxItems":20,"items":{"type":"string"}}`
	return sdk.Manifest{
		ID: "kimai", Name: "Kimai", Version: "0.1.0", Category: "Productivity", Icon: "calendar",
		Description: "Kimai time tracking: projects, activities and timesheets; start and stop a timer.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Kimai's address, e.g. https://time.example.com (or your Kimai Cloud address)"},
			"token":{"type":"string","x-secret":true,"description":"An API token (your avatar, API access, Create token); it acts as your user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Visible projects with their customer, order number and whether they're billable. Names customers, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Only projects whose name or customer contains this"}}}`)},
			{Name: "activities", Title: "Activities", Description: "Visible activities, global or of one project.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"integer","minimum":1,"description":"Only this project's activities (and global ones)"}}}`)},
			{Name: "timesheets", Title: "Timesheets", Description: "Your time entries between two dates (the last 7 days by default), or only the running timers: project, activity, start, end, duration, description and tags. No rates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"start":{"type":"string","format":"date","description":"YYYY-MM-DD, 6 days ago by default"},"end":{"type":"string","format":"date","description":"YYYY-MM-DD, today by default"},"running":{"type":"boolean","description":"Only the running timers"},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}}}`)},
			{Name: "start_timer", Title: "Start a timer", Description: "Starts tracking time now on a project and activity. Kimai may stop a timer already running if it allows only one. Undo stops it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","activity"],"properties":{` + timer + `}}`)},
			{Name: "stop_timer", Title: "Stop a timer", Description: "Stops a running timer (the only one running when no id is given), recording the time so far. Undo starts a new timer on the same project and activity.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"id":{"type":"integer","minimum":1,"description":"Timesheet id of the running timer (see timesheets)"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://time.example.com")
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
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
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

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Kimai refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("your Kimai user isn't allowed to do this")
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
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Kimai API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in"
	if v.Version != "" {
		msg += " · Kimai " + v.Version
	}
	var active []timesheet
	if c.do(ctx, http.MethodGet, "/timesheets/active", nil, nil, &active) == nil && len(active) > 0 {
		msg += fmt.Sprintf(" · %d timer(s) running", len(active))
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type named struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ref is a project or activity, which Kimai sends as an id or (with
// full=true) as an object.
type ref struct {
	ID   int
	Name string
}

func (r *ref) UnmarshalJSON(b []byte) error {
	var id int
	if json.Unmarshal(b, &id) == nil {
		r.ID = id
		return nil
	}
	var n named
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	r.ID, r.Name = n.ID, n.Name
	return nil
}

type timesheet struct {
	ID          int      `json:"id"`
	Begin       string   `json:"begin"`
	End         *string  `json:"end"`
	Duration    int      `json:"duration"`
	Description *string  `json:"description"`
	Project     ref      `json:"project"`
	Activity    ref      `json:"activity"`
	Tags        []string `json:"tags"`
	// Rates and the user aren't decoded.
}

func (t timesheet) row() map[string]any {
	r := map[string]any{"id": t.ID, "project": t.Project.ID, "activity": t.Activity.ID, "begin": t.Begin, "running": t.End == nil}
	if t.Project.Name != "" {
		r["projectName"] = t.Project.Name
	}
	if t.Activity.Name != "" {
		r["activityName"] = t.Activity.Name
	}
	if t.End != nil {
		r["end"] = *t.End
		r["durationSeconds"] = t.Duration
	}
	if t.Description != nil && *t.Description != "" {
		r["description"] = *t.Description
	}
	if len(t.Tags) > 0 {
		r["tags"] = t.Tags
	}
	return r
}

func (t timesheet) label() string {
	p, a := t.Project.Name, t.Activity.Name
	if p == "" {
		p = "project " + strconv.Itoa(t.Project.ID)
	}
	if a == "" {
		a = "activity " + strconv.Itoa(t.Activity.ID)
	}
	return p + " / " + a
}

func parseDate(s string) (time.Time, error) {
	if !dateRe.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q isn't a date like 2026-11-04", s)
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q isn't a date", s)
	}
	return t, nil
}

type input struct {
	Query       string   `json:"query"`
	Project     int      `json:"project"`
	Activity    int      `json:"activity"`
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Running     bool     `json:"running"`
	Limit       int      `json:"limit"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	ID          int      `json:"id"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "projects":
		q := strings.ToLower(strings.TrimSpace(p.Query))
		if len(q) > 200 {
			return sdk.Result{}, errors.New("the query is at most 200 characters")
		}
		var ps []struct {
			ID          int     `json:"id"`
			Name        string  `json:"name"`
			Customer    string  `json:"parentTitle"`
			OrderNumber *string `json:"orderNumber"`
			Visible     bool    `json:"visible"`
			Billable    *bool   `json:"billable"`
		}
		if err := c.do(ctx, http.MethodGet, "/projects", url.Values{"visible": {"1"}}, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			if q != "" && !strings.Contains(strings.ToLower(x.Name), q) && !strings.Contains(strings.ToLower(x.Customer), q) {
				continue
			}
			r := map[string]any{"id": x.ID, "name": x.Name, "customer": x.Customer}
			if x.OrderNumber != nil && *x.OrderNumber != "" {
				r["orderNumber"] = *x.OrderNumber
			}
			if x.Billable != nil {
				r["billable"] = *x.Billable
			}
			out = append(out, r)
		}
		return sdk.JSON(out)
	case "activities":
		if p.Project < 0 {
			return sdk.Result{}, errors.New("the project is a project id (see projects)")
		}
		q := url.Values{"visible": {"1"}}
		if p.Project > 0 {
			q.Set("project", strconv.Itoa(p.Project))
		}
		var as []struct {
			ID      int     `json:"id"`
			Name    string  `json:"name"`
			Project *int    `json:"project"`
			Parent  *string `json:"parentTitle"`
		}
		if err := c.do(ctx, http.MethodGet, "/activities", q, nil, &as); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range as {
			r := map[string]any{"id": a.ID, "name": a.Name, "global": a.Project == nil}
			if a.Project != nil {
				r["project"] = *a.Project
				if a.Parent != nil {
					r["projectName"] = *a.Parent
				}
			}
			out = append(out, r)
		}
		return sdk.JSON(out)
	case "timesheets":
		return c.timesheets(ctx, p)
	case "start_timer":
		return c.start(ctx, call, p)
	case "stop_timer":
		if p.ID < 0 {
			return sdk.Result{}, errors.New("the id is a timesheet id (see timesheets)")
		}
		return c.stop(ctx, call, p.ID)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) timesheets(ctx context.Context, p input) (sdk.Result, error) {
	n := p.Limit
	if n < 0 || n > 500 {
		return sdk.Result{}, errors.New("limit is 1 to 500")
	}
	if n == 0 {
		n = 50
	}
	if p.Running {
		var ts []timesheet
		if err := c.do(ctx, http.MethodGet, "/timesheets/active", nil, nil, &ts); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			out = append(out, t.row())
		}
		return sdk.JSON(out)
	}
	today := c.now()
	e := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	if p.End != "" {
		t, err := parseDate(p.End)
		if err != nil {
			return sdk.Result{}, err
		}
		e = t
	}
	s := e.AddDate(0, 0, -6)
	if p.Start != "" {
		t, err := parseDate(p.Start)
		if err != nil {
			return sdk.Result{}, err
		}
		s = t
	}
	if s.After(e) {
		return sdk.Result{}, errors.New("the start is after the end")
	}
	if e.Sub(s) > maxDays*24*time.Hour {
		return sdk.Result{}, fmt.Errorf("at most %d days at once", maxDays)
	}
	q := url.Values{"begin": {s.Format("2006-01-02") + "T00:00:00"}, "end": {e.Format("2006-01-02") + "T23:59:59"},
		"full": {"true"}, "size": {strconv.Itoa(n)}, "page": {"1"}, "orderBy": {"begin"}, "order": {"DESC"}}
	var ts []timesheet
	if err := c.do(ctx, http.MethodGet, "/timesheets", q, nil, &ts); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	total := 0
	for _, t := range ts {
		total += t.Duration
		out = append(out, t.row())
	}
	return sdk.JSON(map[string]any{"start": s.Format("2006-01-02"), "end": e.Format("2006-01-02"), "timesheets": out, "totalSeconds": total})
}

func (c *conn) active(ctx context.Context) ([]timesheet, error) {
	var ts []timesheet
	err := c.do(ctx, http.MethodGet, "/timesheets/active", nil, nil, &ts)
	return ts, err
}

func (c *conn) start(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Project <= 0 || p.Activity <= 0 {
		return sdk.Result{}, errors.New("give the project and activity ids (see projects and activities)")
	}
	desc := strings.TrimSpace(p.Description)
	if len([]rune(desc)) > maxDesc {
		return sdk.Result{}, fmt.Errorf("the description is at most %d characters", maxDesc)
	}
	if len(p.Tags) > maxTags {
		return sdk.Result{}, fmt.Errorf("at most %d tags", maxTags)
	}
	tags := []string{}
	for _, t := range p.Tags {
		t = strings.TrimSpace(t)
		if !tagRe.MatchString(t) {
			return sdk.Result{}, errors.New("tags are 1 to 100 characters, without commas")
		}
		tags = append(tags, t)
	}
	running, err := c.active(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	for _, t := range running {
		if t.Project.ID == p.Project && t.Activity.ID == p.Activity {
			return sdk.JSON(map[string]any{"id": t.ID, "running": true, "project": p.Project, "activity": p.Activity, "note": "nothing to change: a timer is already running on this project and activity"})
		}
	}
	body := map[string]any{"project": p.Project, "activity": p.Activity}
	if desc != "" {
		body["description"] = desc
	}
	if len(tags) > 0 {
		body["tags"] = strings.Join(tags, ",")
	}
	if call.DryRun {
		summary := fmt.Sprintf("Start a timer on project %d, activity %d", p.Project, p.Activity)
		if len(running) > 0 {
			summary += fmt.Sprintf(" (%d already running; Kimai may stop them if it allows only one)", len(running))
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "timesheet", Op: "create", After: mustJSON(body)}}}}, nil
	}
	// No begin: Kimai starts it now, in the user's time zone.
	var t timesheet
	if err := c.do(ctx, http.MethodPost, "/timesheets", url.Values{"full": {"true"}}, body, &t); err != nil {
		return sdk.Result{}, err
	}
	if t.ID <= 0 {
		return sdk.Result{}, errors.New("Kimai answered without the new timesheet")
	}
	res, err := sdk.JSON(t.row())
	res.Undo = sdk.UndoWith("stop_timer", map[string]int{"id": t.ID}, "Stop the timer on "+t.label())
	return res, err
}

func (c *conn) stop(ctx context.Context, call sdk.Call, id int) (sdk.Result, error) {
	var t timesheet
	if id == 0 {
		running, err := c.active(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		switch len(running) {
		case 0:
			return sdk.JSON(map[string]any{"running": false, "note": "nothing to change: no timer is running"})
		case 1:
			t = running[0]
		default:
			return sdk.Result{}, fmt.Errorf("%d timers are running; give the id of the one to stop (see timesheets with running)", len(running))
		}
	} else {
		if err := c.do(ctx, http.MethodGet, "/timesheets/"+strconv.Itoa(id), url.Values{"full": {"true"}}, nil, &t); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no timesheet %d", id)
			}
			return sdk.Result{}, err
		}
		if t.ID != id {
			// The id goes into the stop's path and the undo.
			return sdk.Result{}, fmt.Errorf("Kimai answered with another timesheet for %d", id)
		}
		if t.End != nil {
			return sdk.JSON(map[string]any{"id": t.ID, "running": false, "end": *t.End, "note": "nothing to change: this timer isn't running"})
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop the timer on %s, running since %s", t.label(), t.Begin),
			Changes: []sdk.Change{{Target: "timesheet " + strconv.Itoa(t.ID), Op: "stop", Before: mustJSON(map[string]any{"running": true}), After: mustJSON(map[string]any{"running": false})}}}}, nil
	}
	var after timesheet
	if err := c.do(ctx, http.MethodPatch, "/timesheets/"+strconv.Itoa(t.ID)+"/stop", nil, nil, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID == 0 {
		after = t
	}
	if after.Project.Name == "" {
		after.Project, after.Activity = t.Project, t.Activity
	}
	res, err := sdk.JSON(after.row())
	undo := map[string]any{"project": t.Project.ID, "activity": t.Activity.ID}
	if t.Description != nil && *t.Description != "" {
		undo["description"] = *t.Description
	}
	if len(t.Tags) > 0 {
		undo["tags"] = t.Tags
	}
	res.Undo = sdk.UndoWith("start_timer", undo, "Start a new timer on "+t.label())
	return res, err
}
