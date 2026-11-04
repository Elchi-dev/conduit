// Package todoist works with Todoist through its unified API (v1) and a
// personal API token: projects, labels and tasks (today, overdue, any filter),
// and adding, completing, updating and deleting tasks.
package todoist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Todoist account.
type Config struct {
	Token string `json:"token"` // secret:// API token
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.todoist.com/api/v1 (tests).
	Base string
}

// New returns the Todoist module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.todoist.com/api/v1"
	maxList     = 200
)

// Todoist v1 ids are short opaque strings ("6X7rM8997g3RQmvh"); older
// accounts still have numeric ones. Nothing else goes into a path.
var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","default":50,"maximum":200}`
	task := `"task":{"type":"string","description":"Task id (from the task lists)"}`
	fields := `"content":{"type":"string","description":"The task name (Markdown allowed)"},
		"description":{"type":"string"},
		"labels":{"type":"array","items":{"type":"string"},"maxItems":50,"description":"Label names"},
		"priority":{"type":"integer","minimum":1,"maximum":4,"description":"1 is urgent (p1), 4 is normal (p4)"},
		"due":{"type":"string","description":"When, in Todoist's words: 'tomorrow 5pm', 'every monday', '2026-12-01'; 'no date' clears it"}`
	return sdk.Manifest{
		ID: "todoist", Name: "Todoist", Version: "0.1.0", Category: "Productivity", Icon: "check",
		Description: "Your Todoist projects and tasks: today, overdue, any filter; add, complete, update and delete tasks.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"API token (Todoist settings, Integrations, Developer). It has full access to your account"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Every project, with the inbox marked.", Risk: sdk.RiskRead},
			{Name: "labels", Title: "Labels", Description: "Your personal labels.", Risk: sdk.RiskRead},
			{Name: "today", Title: "Due today", Description: "Tasks due today (not overdue ones; see overdue).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "overdue", Title: "Overdue", Description: "Tasks whose due date has passed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Open tasks matching a Todoist filter ('today | overdue', '#Work & p1', '@waiting'), or in a project or with a label.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"filter":{"type":"string","description":"Todoist filter query"},"project":{"type":"string","description":"Project id"},"label":{"type":"string","description":"Label name"},` + limit + `}}`)},
			{Name: "task", Title: "Task details", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "add_task", Title: "Add a task", Description: "Adds a task (to the inbox unless a project is given). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["content"],"properties":{` + fields + `,"project":{"type":"string","description":"Project id; the inbox when empty"}}}`)},
			{Name: "complete_task", Title: "Complete a task", Description: "Checks a task off. A recurring task moves to its next date instead. Undo reopens it (or puts the date back).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "reopen_task", Title: "Reopen a task", Description: "Unchecks a completed task. Undo completes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "update_task", Title: "Update a task", Description: "Changes the fields given. Undo puts the old values back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `,` + fields + `}}`)},
			{Name: "delete_task", Title: "Delete a task", Description: "Deletes a task with its subtasks and comments. Todoist can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
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
	tok := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
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
	var u struct {
		FullName string `json:"full_name"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Todoist refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + u.FullName}
}

type due struct {
	Date      string `json:"date"`
	String    string `json:"string"`
	Lang      string `json:"lang"`
	Recurring bool   `json:"is_recurring"`
	Timezone  string `json:"timezone"`
}

type task struct {
	ID          string   `json:"id"`
	Content     string   `json:"content"`
	Description string   `json:"description"`
	ProjectID   string   `json:"project_id"`
	ParentID    *string  `json:"parent_id"`
	Labels      []string `json:"labels"`
	Priority    int      `json:"priority"` // 4 is urgent in the API
	Due         *due     `json:"due"`
	Checked     bool     `json:"checked"`
	AddedAt     string   `json:"added_at"`
}

type project struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	ParentID   *string `json:"parent_id"`
	Inbox      bool    `json:"inbox_project"`
	IsFavorite bool    `json:"is_favorite"`
	IsArchived bool    `json:"is_archived"`
	Color      string  `json:"color"`
}

type label struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Color      string `json:"color"`
	IsFavorite bool   `json:"is_favorite"`
}

type page[T any] struct {
	Results    []T     `json:"results"`
	NextCursor *string `json:"next_cursor"`
}

// all follows cursors until max items (or 20 pages).
func all[T any](ctx context.Context, c *conn, path string, q url.Values, max int) ([]T, error) {
	if q == nil {
		q = url.Values{}
	}
	var out []T
	for i := 0; i < 20 && len(out) < max; i++ {
		q.Set("limit", fmt.Sprint(min(200, max-len(out))))
		var p page[T]
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Results...)
		if p.NextCursor == nil || *p.NextCursor == "" || len(p.Results) == 0 {
			break
		}
		q.Set("cursor", *p.NextCursor)
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

func (c *conn) projectNames(ctx context.Context) (map[string]string, error) {
	ps, err := all[project](ctx, c, "/projects", nil, 1000)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, p := range ps {
		names[p.ID] = p.Name
	}
	return names, nil
}

// pLabel turns the API's priority (4 urgent) into the app's (p1 urgent).
func pLabel(api int) string {
	if api < 1 || api > 4 {
		api = 1
	}
	return fmt.Sprintf("p%d", 5-api)
}

func summary(t task, projects map[string]string) map[string]any {
	out := map[string]any{"id": t.ID, "content": t.Content, "priority": pLabel(t.Priority), "labels": nonNil(t.Labels),
		"project": projects[t.ProjectID], "projectId": t.ProjectID, "url": "https://app.todoist.com/app/task/" + url.PathEscape(t.ID)}
	if t.Description != "" {
		d := []rune(t.Description)
		if len(d) > 500 {
			d = append(d[:500], '…')
		}
		out["description"] = string(d)
	}
	if t.Due != nil {
		out["due"] = map[string]any{"date": t.Due.Date, "string": t.Due.String, "recurring": t.Due.Recurring}
	}
	if t.ParentID != nil && *t.ParentID != "" {
		out["parentId"] = *t.ParentID
	}
	if t.Checked {
		out["completed"] = true
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *conn) listTasks(ctx context.Context, path string, q url.Values, limit int) (sdk.Result, error) {
	if limit <= 0 || limit > maxList {
		limit = 50
	}
	ts, err := all[task](ctx, c, path, q, limit)
	if err != nil {
		return sdk.Result{}, err
	}
	names, err := c.projectNames(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, t := range ts {
		out = append(out, summary(t, names))
	}
	return sdk.JSON(map[string]any{"count": len(out), "tasks": out})
}

func (c *conn) get(ctx context.Context, id string) (task, error) {
	var t task
	if !idRe.MatchString(id) {
		return t, errors.New("enter the task id")
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/tasks/"+id, nil, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return t, fmt.Errorf("there's no task %s (or it was deleted)", id)
		}
		return t, err
	}
	return t, nil
}

type input struct {
	Task        string    `json:"task"`
	Project     string    `json:"project"`
	Label       string    `json:"label"`
	Filter      string    `json:"filter"`
	Limit       int       `json:"limit"`
	Content     *string   `json:"content"`
	Description *string   `json:"description"`
	Labels      *[]string `json:"labels"`
	Priority    *int      `json:"priority"`
	Due         *string   `json:"due"`
	// DueDate, DueDatetime and DueLang are what undo uses to put an exact
	// date back (a "due" phrase would be read relative to now).
	DueDate     string `json:"dueDate,omitempty"`
	DueDatetime string `json:"dueDatetime,omitempty"`
	DueLang     string `json:"dueLang,omitempty"`
}

// body builds the create/update fields shared by add_task and update_task,
// with priority mapped from the app's p1..p4 to the API's 4..1.
func (p input) body() (map[string]any, error) {
	b := map[string]any{}
	if p.Content != nil {
		s := strings.TrimSpace(*p.Content)
		if s == "" || len(s) > 2000 {
			return nil, errors.New("the task needs a name of up to 2000 characters")
		}
		b["content"] = s
	}
	if p.Description != nil {
		if len(*p.Description) > 16000 {
			return nil, errors.New("the description is too long")
		}
		b["description"] = *p.Description
	}
	if p.Labels != nil {
		ls := []string{}
		for _, l := range *p.Labels {
			l = strings.TrimSpace(l)
			if l == "" || len(l) > 128 {
				return nil, errors.New("label names are 1 to 128 characters")
			}
			ls = append(ls, l)
		}
		if len(ls) > 50 {
			return nil, errors.New("up to 50 labels")
		}
		b["labels"] = ls
	}
	if p.Priority != nil {
		if *p.Priority < 1 || *p.Priority > 4 {
			return nil, errors.New("priority is 1 (urgent) to 4 (normal)")
		}
		b["priority"] = 5 - *p.Priority
	}
	switch {
	case p.DueDatetime != "":
		b["due_datetime"] = p.DueDatetime
	case p.DueDate != "":
		b["due_date"] = p.DueDate
	case p.Due != nil:
		d := strings.TrimSpace(*p.Due)
		if d == "" || len(d) > 200 {
			return nil, errors.New("say when it's due, or 'no date' to clear it")
		}
		b["due_string"] = d
	}
	if p.DueLang != "" {
		b["due_lang"] = p.DueLang
	}
	return b, nil
}

// restoreDue returns the undo fields that put a task's due date back exactly.
func restoreDue(d *due) map[string]any {
	if d == nil {
		return map[string]any{"due": "no date"}
	}
	switch {
	case d.Recurring:
		out := map[string]any{"due": d.String}
		if d.Lang != "" {
			out["dueLang"] = d.Lang
		}
		return out
	case !strings.Contains(d.Date, "T"):
		return map[string]any{"dueDate": d.Date}
	case strings.HasSuffix(d.Date, "Z"):
		return map[string]any{"dueDatetime": d.Date}
	default:
		// A floating time ("2026-11-04T17:00:00"): no zone to give
		// due_datetime, so spell it out for the parser.
		if t, err := time.Parse("2006-01-02T15:04:05", d.Date); err == nil {
			return map[string]any{"due": t.Format("Jan 2 2006 15:04"), "dueLang": "en"}
		}
		return map[string]any{"due": d.String}
	}
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
		ps, err := all[project](ctx, c, "/projects", nil, 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			r := map[string]any{"id": x.ID, "name": x.Name, "favorite": x.IsFavorite, "url": "https://app.todoist.com/app/project/" + url.PathEscape(x.ID)}
			if x.Inbox {
				r["inbox"] = true
			}
			if x.ParentID != nil && *x.ParentID != "" {
				r["parentId"] = *x.ParentID
			}
			if x.IsArchived {
				r["archived"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "labels":
		ls, err := all[label](ctx, c, "/labels", nil, 1000)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, map[string]any{"id": l.ID, "name": l.Name, "color": l.Color, "favorite": l.IsFavorite})
		}
		return sdk.JSON(out)

	case "today", "overdue":
		return c.listTasks(ctx, "/tasks/filter", url.Values{"query": {call.Action}}, p.Limit)

	case "tasks":
		f := strings.TrimSpace(p.Filter)
		if f != "" {
			if p.Project != "" || p.Label != "" {
				return sdk.Result{}, errors.New("give a filter, or a project and label, not both (put them in the filter: #Project & @label)")
			}
			if len(f) > 1024 {
				return sdk.Result{}, errors.New("the filter is too long")
			}
			return c.listTasks(ctx, "/tasks/filter", url.Values{"query": {f}}, p.Limit)
		}
		q := url.Values{}
		if p.Project != "" {
			if !idRe.MatchString(p.Project) {
				return sdk.Result{}, errors.New("the project is a project id (see projects)")
			}
			q.Set("project_id", p.Project)
		}
		if l := strings.TrimSpace(p.Label); l != "" {
			q.Set("label", l)
		}
		return c.listTasks(ctx, "/tasks", q, p.Limit)

	case "task":
		t, err := c.get(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		names, err := c.projectNames(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(t, names)
		out["description"] = t.Description
		out["added"] = t.AddedAt
		return sdk.JSON(out)

	case "add_task":
		return c.add(ctx, call, p)
	case "complete_task", "reopen_task":
		return c.check(ctx, call, p.Task)
	case "update_task":
		return c.update(ctx, call, p)
	case "delete_task":
		t, err := c.get(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete task %q", t.Content),
				Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.ID, t.Content), Op: "delete", Before: mustJSON(summary(t, nil))}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/tasks/"+t.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": t.ID, "content": t.Content})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) add(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Content == nil {
		return sdk.Result{}, errors.New("the task needs a name")
	}
	b, err := p.body()
	if err != nil {
		return sdk.Result{}, err
	}
	where := "the inbox"
	if p.Project != "" {
		if !idRe.MatchString(p.Project) {
			return sdk.Result{}, errors.New("the project is a project id (see projects)")
		}
		var pr project
		if _, err := c.api.Do(ctx, http.MethodGet, "/projects/"+p.Project, nil, nil, &pr); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no project %s", p.Project)
			}
			return sdk.Result{}, err
		}
		b["project_id"] = p.Project
		where = pr.Name
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q to %s", b["content"], where),
			Changes: []sdk.Change{{Target: "task in " + where, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var t task
	if _, err := c.api.Do(ctx, http.MethodPost, "/tasks", nil, b, &t); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(summary(t, map[string]string{t.ProjectID: where}))
	if t.ID != "" {
		res.Undo = sdk.UndoWith("delete_task", map[string]any{"task": t.ID}, fmt.Sprintf("Delete task %q", t.Content))
	}
	return res, err
}

func (c *conn) check(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	t, err := c.get(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	completing := call.Action == "complete_task"
	if t.Checked == completing {
		state := "open"
		if t.Checked {
			state = "completed"
		}
		return sdk.JSON(map[string]any{"task": t.ID, "note": "the task is already " + state})
	}
	recurring := completing && t.Due != nil && t.Due.Recurring
	summaryText, op, path := fmt.Sprintf("Complete %q", t.Content), "complete", "/tasks/"+t.ID+"/close"
	if recurring {
		summaryText = fmt.Sprintf("Complete this occurrence of %q (it repeats %s; the date moves to the next one)", t.Content, t.Due.String)
	}
	if !completing {
		summaryText, op, path = fmt.Sprintf("Reopen %q", t.Content), "reopen", "/tasks/"+t.ID+"/reopen"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summaryText, Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.ID, t.Content), Op: op}}}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"task": t.ID, "content": t.Content, "completed": completing, "recurring": recurring})
	switch {
	case recurring:
		in := restoreDue(t.Due)
		in["task"] = t.ID
		res.Undo = sdk.UndoWith("update_task", in, fmt.Sprintf("Put %q back on %s", t.Content, t.Due.Date))
	case completing:
		res.Undo = sdk.UndoWith("reopen_task", map[string]any{"task": t.ID}, fmt.Sprintf("Reopen %q", t.Content))
	default:
		res.Undo = sdk.UndoWith("complete_task", map[string]any{"task": t.ID}, fmt.Sprintf("Complete %q again", t.Content))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	b, err := p.body()
	if err != nil {
		return sdk.Result{}, err
	}
	if len(b) == 0 || (len(b) == 1 && b["due_lang"] != nil) {
		return sdk.Result{}, errors.New("say what to change: content, description, labels, priority or due")
	}
	t, err := c.get(ctx, p.Task)
	if err != nil {
		return sdk.Result{}, err
	}
	before, back := map[string]any{}, map[string]any{"task": t.ID}
	for k := range b {
		switch k {
		case "content":
			before[k], back["content"] = t.Content, t.Content
		case "description":
			before[k], back["description"] = t.Description, t.Description
		case "labels":
			before[k], back["labels"] = nonNil(t.Labels), nonNil(t.Labels)
		case "priority":
			before[k], back["priority"] = 5-t.Priority, 5-t.Priority
		case "due_string", "due_date", "due_datetime":
			before["due"] = nil
			if t.Due != nil {
				before["due"] = t.Due.Date
			}
			for k, v := range restoreDue(t.Due) {
				back[k] = v
			}
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update %q", t.Content),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.ID, t.Content), Op: "update", Before: mustJSON(before), After: mustJSON(b)}}}}, nil
	}
	var after task
	if _, err := c.api.Do(ctx, http.MethodPost, "/tasks/"+t.ID, nil, b, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID == "" {
		after = t
	}
	res, err := sdk.JSON(summary(after, nil))
	res.Undo = sdk.UndoWith("update_task", back, fmt.Sprintf("Restore %q", t.Content))
	return res, err
}
