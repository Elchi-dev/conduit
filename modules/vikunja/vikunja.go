// Package vikunja works with a Vikunja task server through its REST API and
// an API token: projects, tasks due today, overdue or matching a filter, and
// creating, completing, reopening, updating and deleting tasks.
package vikunja

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Vikunja server.
type Config struct {
	URL                string `json:"url"`      // e.g. https://tasks.example.com
	Token              string `json:"token"`    // secret:// API token
	Timezone           string `json:"timezone"` // IANA zone for "today"; the user's Vikunja setting by default
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string

	mu sync.Mutex
	tz string // configured, or read from the user's settings
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Vikunja module.
func New() *Module { return &Module{} }

const (
	maxTitle = 250
	maxDesc  = 64 << 10
	maxLimit = 200
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// zero is how Vikunja writes "no date".
const zero = "0001-01-01T00:00:00Z"

var priorities = []string{"unset", "low", "medium", "high", "urgent", "do now"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}`
	task := `"id":{"type":"integer","minimum":1,"description":"Task id"}`
	fields := `"title":{"type":"string"},"description":{"type":"string"},"due":{"type":"string","description":"YYYY-MM-DD (midnight in your time zone) or an RFC 3339 time; empty to clear"},"priority":{"type":"integer","minimum":0,"maximum":5,"description":"0 unset, 1 low, 2 medium, 3 high, 4 urgent, 5 do now"}`
	return sdk.Manifest{
		ID: "vikunja", Name: "Vikunja", Version: "0.1.0", Category: "Productivity", Icon: "check",
		Description: "Vikunja projects and tasks: what's due today or overdue, any filter, and adding, completing, editing and deleting tasks.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Vikunja's address, e.g. https://tasks.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token from Settings → API Tokens, with the tasks and projects permissions you want to allow"},
			"timezone":{"type":"string","description":"Time zone for today and overdue, e.g. Europe/Berlin. Defaults to your Vikunja setting"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Every project, archived ones marked.", Risk: sdk.RiskRead},
			{Name: "today", Title: "Due today", Description: "Open tasks due today (not overdue ones; see overdue).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "overdue", Title: "Overdue", Description: "Open tasks whose due date has passed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Tasks matching a Vikunja filter (done = false && priority >= 3, due_date < now+7d, labels in 4), in a project, or matching words.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"filter":{"type":"string"},"project":{"type":"integer","minimum":1},"search":{"type":"string","description":"Words in the title or description (not with filter)"},"includeDone":{"type":"boolean","default":false},` + limit + `}}`)},
			{Name: "task", Title: "Task details", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + task + `}}`)},
			{Name: "create_task", Title: "Add a task", Description: "Adds a task to a project. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","title"],"properties":{"project":{"type":"integer","minimum":1},` + fields + `}}`)},
			{Name: "mark_done", Title: "Mark a task done", Description: "Checks a task off; a repeating task moves to its next date instead. Undo reopens it (or puts the date back).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + task + `}}`)},
			{Name: "mark_undone", Title: "Reopen a task", Description: "Unchecks a done task. Undo marks it done again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + task + `}}`)},
			{Name: "update_task", Title: "Update a task", Description: "Changes the fields given and keeps the rest. Undo puts the old values back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + task + `,` + fields + `}}`)},
			{Name: "delete_task", Title: "Delete a task", Description: "Deletes a task with its comments and attachments. Vikunja can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + task + `}}`)},
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
		return errors.New("the address is like https://tasks.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	if c.Timezone != "" {
		if _, err := time.LoadLocation(c.Timezone); err != nil || c.Timezone == "Local" {
			return fmt.Errorf("unknown time zone %q (use a name like Europe/Berlin)", c.Timezone)
		}
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.Token
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(origin+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin, tz: c.Timezone})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	hdr, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return hdr, errors.New("Vikunja refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return hdr, fmt.Errorf("Vikunja refused the request: %v (the token lacks the permission, or you can't access this)", err)
	}
	return hdr, err
}

type user struct {
	Username string `json:"username"`
	Settings struct {
		Timezone string `json:"timezone"`
	} `json:"settings"`
}

// zone returns the time zone for "today": the configured one, else the
// user's Vikunja setting, else UTC.
func (c *conn) zone(ctx context.Context) *time.Location {
	c.mu.Lock()
	tz := c.tz
	c.mu.Unlock()
	if tz == "" {
		var u user
		if _, err := c.do(ctx, http.MethodGet, "/user", nil, nil, &u); err == nil {
			tz = u.Settings.Timezone
			if _, err := time.LoadLocation(tz); err != nil || tz == "" || tz == "Local" {
				tz = "UTC"
			}
			c.mu.Lock()
			c.tz = tz
			c.mu.Unlock()
		}
	}
	if loc, err := time.LoadLocation(tz); err == nil && tz != "" && tz != "Local" {
		return loc
	}
	return time.UTC
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u user
	if _, err := c.do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Vikunja API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + u.Username
	var info struct {
		Version string `json:"version"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/info", nil, nil, &info); err == nil && info.Version != "" {
		msg += " · Vikunja " + info.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type label struct {
	Title string `json:"title"`
}

type task struct {
	ID          int     `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Done        bool    `json:"done"`
	DoneAt      string  `json:"done_at"`
	DueDate     string  `json:"due_date"`
	Priority    int     `json:"priority"`
	ProjectID   int     `json:"project_id"`
	Identifier  string  `json:"identifier"`
	RepeatAfter int     `json:"repeat_after"`
	RepeatMode  int     `json:"repeat_mode"`
	Labels      []label `json:"labels"`
	Created     string  `json:"created"`
	Updated     string  `json:"updated"`
}

func (t task) repeating() bool { return t.RepeatAfter > 0 || t.RepeatMode == 1 }

func dateOrNil(s string) any {
	if s == "" || s == zero || strings.HasPrefix(s, "0001-01-01") {
		return nil
	}
	return s
}

func (c *conn) summary(t task, projects map[int]string) map[string]any {
	out := map[string]any{"id": t.ID, "title": t.Title, "done": t.Done, "projectId": t.ProjectID,
		"url": c.origin + "/tasks/" + strconv.Itoa(t.ID)}
	if n, ok := projects[t.ProjectID]; ok {
		out["project"] = n
	}
	if d := dateOrNil(t.DueDate); d != nil {
		out["due"] = d
	}
	if t.Priority > 0 && t.Priority < len(priorities) {
		out["priority"] = priorities[t.Priority]
	}
	if t.Identifier != "" {
		out["identifier"] = t.Identifier
	}
	if t.repeating() {
		out["repeats"] = true
	}
	ls := []string{}
	for _, l := range t.Labels {
		ls = append(ls, l.Title)
	}
	out["labels"] = ls
	return out
}

type project struct {
	ID         int    `json:"id"`
	Title      string `json:"title"`
	ParentID   int    `json:"parent_project_id"`
	IsArchived bool   `json:"is_archived"`
	IsFavorite bool   `json:"is_favorite"`
}

func (c *conn) projects(ctx context.Context) ([]project, error) {
	var all []project
	for pg := 1; pg <= 10; pg++ {
		var page []project
		hdr, err := c.do(ctx, http.MethodGet, "/projects", url.Values{"page": {strconv.Itoa(pg)}, "per_page": {"100"}, "is_archived": {"true"}}, nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		total, _ := strconv.Atoi(hdr.Get("X-Pagination-Total-Pages"))
		if len(page) == 0 || pg >= total {
			break
		}
	}
	return all, nil
}

func (c *conn) projectNames(ctx context.Context) map[int]string {
	out := map[int]string{}
	ps, err := c.projects(ctx)
	if err != nil {
		return out
	}
	for _, p := range ps {
		out[p.ID] = p.Title
	}
	return out
}

// list reads tasks across projects with a filter expression.
func (c *conn) list(ctx context.Context, q url.Values, limit int) (sdk.Result, error) {
	if limit <= 0 || limit > maxLimit {
		limit = 50
	}
	q.Set("per_page", strconv.Itoa(limit))
	q.Set("page", "1")
	if q.Get("sort_by") == "" {
		q["sort_by"] = []string{"due_date", "id"}
		q["order_by"] = []string{"asc", "desc"}
	}
	if q.Get("filter") != "" {
		q.Set("filter_timezone", c.zone(ctx).String())
	}
	var ts []task
	_, err := c.do(ctx, http.MethodGet, "/tasks/all", q, nil, &ts)
	if rest.IsStatus(err, http.StatusNotFound) {
		// Newer releases list them at /tasks.
		_, err = c.do(ctx, http.MethodGet, "/tasks", q, nil, &ts)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	names := c.projectNames(ctx)
	out := []map[string]any{}
	for _, t := range ts {
		out = append(out, c.summary(t, names))
	}
	return sdk.JSON(out)
}

// get reads a task twice over: typed, and as the raw object Vikunja wants
// back on update (it replaces the whole task, so every field must be sent).
func (c *conn) get(ctx context.Context, id int) (task, map[string]any, error) {
	if id <= 0 {
		return task{}, nil, errors.New("enter the task id")
	}
	var raw json.RawMessage
	if _, err := c.do(ctx, http.MethodGet, "/tasks/"+strconv.Itoa(id), nil, nil, &raw); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return task{}, nil, fmt.Errorf("there's no task %d (or the token can't see it)", id)
		}
		return task{}, nil, err
	}
	var t task
	var full map[string]any
	if err := json.Unmarshal(raw, &t); err != nil {
		return task{}, nil, err
	}
	if err := json.Unmarshal(raw, &full); err != nil {
		return task{}, nil, err
	}
	return t, full, nil
}

type input struct {
	ID          int     `json:"id"`
	Project     int     `json:"project"`
	Filter      string  `json:"filter"`
	Search      string  `json:"search"`
	IncludeDone bool    `json:"includeDone"`
	Limit       int     `json:"limit"`
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Due         *string `json:"due"`
	Priority    *int    `json:"priority"`
}

// fields checks the task fields given and returns them in Vikunja's names.
func (p input) fields(loc *time.Location) (map[string]any, error) {
	b := map[string]any{}
	if p.Title != nil {
		t := strings.TrimSpace(*p.Title)
		if t == "" || len([]rune(t)) > maxTitle {
			return nil, fmt.Errorf("the title is 1 to %d characters", maxTitle)
		}
		b["title"] = t
	}
	if p.Description != nil {
		if len(*p.Description) > maxDesc {
			return nil, errors.New("the description is too long")
		}
		b["description"] = *p.Description
	}
	if p.Priority != nil {
		if *p.Priority < 0 || *p.Priority > 5 {
			return nil, errors.New("priority is 0 (unset) to 5 (do now)")
		}
		b["priority"] = *p.Priority
	}
	if p.Due != nil {
		d := strings.TrimSpace(*p.Due)
		switch {
		case d == "":
			b["due_date"] = zero
		case dateRe.MatchString(d):
			t, err := time.ParseInLocation("2006-01-02", d, loc)
			if err != nil {
				return nil, fmt.Errorf("%q isn't a date", d)
			}
			b["due_date"] = t.Format(time.RFC3339)
		default:
			t, err := time.Parse(time.RFC3339, d)
			if err != nil {
				return nil, errors.New("due is YYYY-MM-DD or an RFC 3339 time like 2026-11-04T17:00:00+01:00")
			}
			b["due_date"] = t.Format(time.RFC3339)
		}
	}
	return b, nil
}

// needsZone says whether fields() needs the time zone (a date-only due).
func (p input) needsZone() bool { return p.Due != nil && dateRe.MatchString(strings.TrimSpace(*p.Due)) }

func (c *conn) fieldsFor(ctx context.Context, p input) (map[string]any, error) {
	// Check everything once without a network round trip, then for real.
	if _, err := p.fields(time.UTC); err != nil {
		return nil, err
	}
	loc := time.UTC
	if p.needsZone() {
		loc = c.zone(ctx)
	}
	return p.fields(loc)
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
		ps, err := c.projects(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].IsArchived != ps[j].IsArchived && !ps[i].IsArchived })
		out := []map[string]any{}
		for _, x := range ps {
			r := map[string]any{"id": x.ID, "title": x.Title, "url": c.origin + "/projects/" + strconv.Itoa(x.ID)}
			if x.ParentID > 0 {
				r["parentId"] = x.ParentID
			}
			if x.IsArchived {
				r["archived"] = true
			}
			if x.IsFavorite {
				r["favorite"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "today":
		return c.list(ctx, url.Values{"filter": {"done = false && due_date >= now/d && due_date < now/d+1d"}}, p.Limit)
	case "overdue":
		return c.list(ctx, url.Values{"filter": {"done = false && due_date < now/d"}}, p.Limit)

	case "tasks":
		f := strings.TrimSpace(p.Filter)
		s := strings.TrimSpace(p.Search)
		if len(f) > 1024 || len(s) > 256 {
			return sdk.Result{}, errors.New("the filter or search is too long")
		}
		if f != "" && s != "" {
			return sdk.Result{}, errors.New("give a filter or search words, not both")
		}
		if p.Project < 0 {
			return sdk.Result{}, errors.New("the project is a project id (see projects)")
		}
		var parts []string
		if f != "" {
			parts = append(parts, "("+f+")")
		} else if !p.IncludeDone {
			parts = append(parts, "done = false")
		}
		if p.Project > 0 {
			parts = append(parts, "project = "+strconv.Itoa(p.Project))
		}
		q := url.Values{}
		if len(parts) > 0 {
			q.Set("filter", strings.Join(parts, " && "))
		}
		if s != "" {
			q.Set("s", s)
		}
		return c.list(ctx, q, p.Limit)

	case "task":
		t, _, err := c.get(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(t, c.projectNames(ctx))
		out["description"], out["created"], out["updated"] = t.Description, t.Created, t.Updated
		if d := dateOrNil(t.DoneAt); d != nil {
			out["doneAt"] = d
		}
		return sdk.JSON(out)

	case "create_task":
		return c.create(ctx, call, p)
	case "mark_done", "mark_undone":
		return c.check(ctx, call, p.ID)
	case "update_task":
		return c.update(ctx, call, p)

	case "delete_task":
		t, _, err := c.get(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete task %q", t.Title),
				Changes: []sdk.Change{{Target: fmt.Sprintf("task %d %q", t.ID, t.Title), Op: "delete", Before: mustJSON(c.summary(t, nil))}}}}, nil
		}
		if _, err := c.do(ctx, http.MethodDelete, "/tasks/"+strconv.Itoa(t.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": t.ID, "title": t.Title})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Title == nil {
		return sdk.Result{}, errors.New("the task needs a title")
	}
	if p.Project <= 0 {
		return sdk.Result{}, errors.New("give the project (an id, see projects)")
	}
	b, err := c.fieldsFor(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	var pr project
	if _, err := c.do(ctx, http.MethodGet, "/projects/"+strconv.Itoa(p.Project), nil, nil, &pr); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no project %d", p.Project)
		}
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q to %s", b["title"], pr.Title),
			Changes: []sdk.Change{{Target: "task in " + pr.Title, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var t task
	// Vikunja creates with PUT.
	if _, err := c.do(ctx, http.MethodPut, "/projects/"+strconv.Itoa(p.Project)+"/tasks", nil, b, &t); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(c.summary(t, map[int]string{p.Project: pr.Title}))
	if t.ID > 0 {
		res.Undo = sdk.UndoWith("delete_task", map[string]any{"id": t.ID}, fmt.Sprintf("Delete task %q", t.Title))
	}
	return res, err
}

func (c *conn) check(ctx context.Context, call sdk.Call, id int) (sdk.Result, error) {
	t, full, err := c.get(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	done := call.Action == "mark_done"
	if t.Done == done {
		state := "open"
		if t.Done {
			state = "done"
		}
		return sdk.JSON(map[string]any{"id": t.ID, "note": "the task is already " + state})
	}
	repeating := done && t.repeating() && dateOrNil(t.DueDate) != nil
	summary, op := fmt.Sprintf("Mark %q done", t.Title), "done"
	if repeating {
		summary = fmt.Sprintf("Mark this occurrence of %q done (it repeats; the due date moves to the next one)", t.Title)
	}
	if !done {
		summary, op = fmt.Sprintf("Reopen %q", t.Title), "reopen"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: fmt.Sprintf("task %d %q", t.ID, t.Title), Op: op}}}}, nil
	}
	full["done"] = done
	var after task
	if _, err := c.do(ctx, http.MethodPost, "/tasks/"+strconv.Itoa(t.ID), nil, full, &after); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": t.ID, "title": t.Title, "done": after.Done || (done && !repeating), "repeating": repeating, "due": dateOrNil(after.DueDate)})
	switch {
	case repeating:
		res.Undo = sdk.UndoWith("update_task", map[string]any{"id": t.ID, "due": t.DueDate}, fmt.Sprintf("Put %q back on %s", t.Title, t.DueDate))
	case done:
		res.Undo = sdk.UndoWith("mark_undone", map[string]any{"id": t.ID}, fmt.Sprintf("Reopen %q", t.Title))
	default:
		res.Undo = sdk.UndoWith("mark_done", map[string]any{"id": t.ID}, fmt.Sprintf("Mark %q done again", t.Title))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if _, err := p.fields(time.UTC); err != nil {
		return sdk.Result{}, err
	}
	if p.ID <= 0 {
		return sdk.Result{}, errors.New("enter the task id")
	}
	if p.Title == nil && p.Description == nil && p.Due == nil && p.Priority == nil {
		return sdk.Result{}, errors.New("say what to change: title, description, due or priority")
	}
	b, err := c.fieldsFor(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	t, full, err := c.get(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	before, back := map[string]any{}, map[string]any{"id": t.ID}
	for k := range b {
		switch k {
		case "title":
			before[k], back["title"] = t.Title, t.Title
		case "description":
			before[k], back["description"] = t.Description, t.Description
		case "priority":
			before[k], back["priority"] = t.Priority, t.Priority
		case "due_date":
			before["due"] = dateOrNil(t.DueDate)
			if d := dateOrNil(t.DueDate); d != nil {
				back["due"] = d
			} else {
				back["due"] = ""
			}
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update %q", t.Title),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %d %q", t.ID, t.Title), Op: "update", Before: mustJSON(before), After: mustJSON(b)}}}}, nil
	}
	for k, v := range b {
		full[k] = v
	}
	var after task
	if _, err := c.do(ctx, http.MethodPost, "/tasks/"+strconv.Itoa(t.ID), nil, full, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID == 0 {
		after = t
	}
	res, err := sdk.JSON(c.summary(after, nil))
	res.Undo = sdk.UndoWith("update_task", back, fmt.Sprintf("Restore %q", t.Title))
	return res, err
}
