// Package asana works with Asana through its REST API and a personal access
// token: workspaces, projects and tasks, creating, updating, completing and
// deleting tasks, and commenting on them.
package asana

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
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Asana account.
type Config struct {
	Token string `json:"token"` // secret:// personal access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://app.asana.com/api/1.0 (tests).
	Base string
}

// New returns the Asana module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://app.asana.com/api/1.0"
	maxName     = 1024
	maxNotes    = 65000
	maxComment  = 10000
)

// Asana ids (gids) are numeric strings. Nothing else goes into a path.
var gidRe = regexp.MustCompile(`^\d{1,20}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	task := `"task":{"type":"string","description":"Task id (gid, from tasks)"}`
	fields := `"name":{"type":"string","maxLength":1024},
		"notes":{"type":"string","x-multiline":true,"description":"The task's description"},
		"due":{"type":"string","description":"Due date, YYYY-MM-DD; empty clears it"},
		"assignee":{"type":"string","description":"'me' or a user id; empty unassigns"}`
	return sdk.Manifest{
		ID: "asana", Name: "Asana", Version: "0.1.0", Category: "Productivity", Icon: "check",
		Description: "Asana: workspaces, projects and tasks; create, update, complete and comment on tasks.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal access token (My settings, Apps, Developer apps, Personal access tokens). It acts as you"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "workspaces", Title: "Workspaces", Description: "The workspaces and organizations you belong to.", Risk: sdk.RiskRead},
			{Name: "projects", Title: "Projects", Description: "Projects in a workspace (the only one when you have one).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"workspace":{"type":"string","description":"Workspace id"},"archived":{"type":"boolean","default":false}}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Open tasks in a project, or the tasks assigned to you in a workspace.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project id"},"workspace":{"type":"string","description":"Workspace id, for your own tasks"},"completed":{"type":"boolean","default":false,"description":"Include completed tasks"},"limit":{"type":"integer","default":50,"maximum":100}}}`)},
			{Name: "task", Title: "Task details", Description: "Name, notes, due date, assignee, projects, tags and recent comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "create_task", Title: "Create a task", Description: "In a project, or in a workspace's My Tasks. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"project":{"type":"string","description":"Project id"},"workspace":{"type":"string","description":"Workspace id, when there's no project"},` + fields + `}}`)},
			{Name: "update_task", Title: "Update a task", Description: "Changes the fields given. Undo puts the old values back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `,` + fields + `}}`)},
			{Name: "complete_task", Title: "Complete a task", Description: "Marks a task complete. Undo reopens it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "reopen_task", Title: "Reopen a task", Description: "Marks a completed task incomplete. Undo completes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "comment", Title: "Comment on a task", Description: "Adds a plain-text comment; the task's collaborators are notified as usual. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task","text"],"properties":{` + task + `,"text":{"type":"string","x-multiline":true}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["comment"],"properties":{"comment":{"type":"string","description":"Comment (story) id"}}}`)},
			{Name: "delete_task", Title: "Delete a task", Description: "Moves the task to Asana's trash, with its subtasks.", Risk: sdk.RiskDestructive, DryRun: true,
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
		return errors.New("store the access token in the vault and enter its secret:// reference")
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

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Asana refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("your Asana account isn't allowed to do this")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Asana's rate limit was reached; try again in a minute")
	}
	return err
}

// do sends a request, wrapping the body in {"data": …} and unwrapping the
// answer's data into out.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var in any
	if body != nil {
		in = map[string]any{"data": body}
	}
	var res struct {
		Data json.RawMessage `json:"data"`
	}
	if _, err := c.api.Do(ctx, method, path, q, in, &res); err != nil {
		return friendly(err)
	}
	if out != nil && len(res.Data) > 0 && string(res.Data) != "null" {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return errors.New("unexpected answer from Asana")
		}
	}
	return nil
}

type named struct {
	GID  string `json:"gid"`
	Name string `json:"name"`
}

type task struct {
	GID         string  `json:"gid"`
	Name        string  `json:"name"`
	Notes       string  `json:"notes"`
	Completed   bool    `json:"completed"`
	DueOn       *string `json:"due_on"`
	DueAt       *string `json:"due_at"`
	Assignee    *named  `json:"assignee"`
	Projects    []named `json:"projects"`
	Tags        []named `json:"tags"`
	URL         string  `json:"permalink_url"`
	CreatedAt   string  `json:"created_at"`
	ModifiedAt  string  `json:"modified_at"`
	CompletedAt *string `json:"completed_at"`
}

const taskFields = "name,completed,due_on,due_at,assignee.name,projects.name,permalink_url,modified_at"

func names(ns []named) []string {
	out := []string{}
	for _, n := range ns {
		out = append(out, n.Name)
	}
	return out
}

func summary(t task) map[string]any {
	out := map[string]any{"id": t.GID, "name": t.Name, "completed": t.Completed, "projects": names(t.Projects), "url": t.URL}
	if t.DueAt != nil && *t.DueAt != "" {
		out["due"] = *t.DueAt
	} else if t.DueOn != nil && *t.DueOn != "" {
		out["due"] = *t.DueOn
	}
	if t.Assignee != nil {
		out["assignee"] = t.Assignee.Name
	}
	if t.ModifiedAt != "" {
		out["modified"] = t.ModifiedAt
	}
	return out
}

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
	var me struct {
		Name       string  `json:"name"`
		Workspaces []named `json:"workspaces"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", url.Values{"opt_fields": {"name,workspaces.name"}}, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("signed in as %s, %d workspaces", me.Name, len(me.Workspaces))}
}

type input struct {
	Workspace string  `json:"workspace"`
	Project   string  `json:"project"`
	Archived  bool    `json:"archived"`
	Completed bool    `json:"completed"`
	Limit     int     `json:"limit"`
	Task      string  `json:"task"`
	Comment   string  `json:"comment"`
	Text      string  `json:"text"`
	Name      *string `json:"name"`
	Notes     *string `json:"notes"`
	Due       *string `json:"due"`
	Assignee  *string `json:"assignee"`
}

// fields checks the task fields given and returns them as Asana's body.
func (p input) fields() (map[string]any, error) {
	b := map[string]any{}
	if p.Name != nil {
		s := strings.TrimSpace(*p.Name)
		if s == "" || len(s) > maxName {
			return nil, fmt.Errorf("a task name is 1 to %d characters", maxName)
		}
		b["name"] = s
	}
	if p.Notes != nil {
		if len(*p.Notes) > maxNotes {
			return nil, errors.New("the notes are too long")
		}
		b["notes"] = *p.Notes
	}
	if p.Due != nil {
		d := strings.TrimSpace(*p.Due)
		if d == "" {
			b["due_on"] = nil
		} else if _, err := time.Parse("2006-01-02", d); err != nil {
			return nil, errors.New("the due date is like 2026-12-01")
		} else {
			b["due_on"] = d
		}
	}
	if p.Assignee != nil {
		a := strings.TrimSpace(*p.Assignee)
		switch {
		case a == "":
			b["assignee"] = nil
		case a == "me" || gidRe.MatchString(a):
			b["assignee"] = a
		default:
			return nil, errors.New("the assignee is 'me' or a user id")
		}
	}
	return b, nil
}

func need(id, what string) error {
	if !gidRe.MatchString(id) {
		return fmt.Errorf("the %s is its numeric id", what)
	}
	return nil
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
	p.Task, p.Project, p.Workspace, p.Comment = strings.TrimSpace(p.Task), strings.TrimSpace(p.Project), strings.TrimSpace(p.Workspace), strings.TrimSpace(p.Comment)
	switch call.Action {
	case "workspaces":
		var ws []struct {
			named
			IsOrganization bool `json:"is_organization"`
		}
		if err := c.do(ctx, http.MethodGet, "/workspaces", url.Values{"opt_fields": {"name,is_organization"}, "limit": {"100"}}, nil, &ws); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, w := range ws {
			out = append(out, map[string]any{"id": w.GID, "name": w.Name, "organization": w.IsOrganization})
		}
		return sdk.JSON(out)

	case "projects":
		ws, err := c.workspace(ctx, p.Workspace)
		if err != nil {
			return sdk.Result{}, err
		}
		var ps []struct {
			named
			Archived   bool   `json:"archived"`
			Color      string `json:"color"`
			URL        string `json:"permalink_url"`
			ModifiedAt string `json:"modified_at"`
			Team       *named `json:"team"`
		}
		q := url.Values{"workspace": {ws}, "archived": {strconv.FormatBool(p.Archived)}, "limit": {"100"}, "opt_fields": {"name,archived,color,permalink_url,modified_at,team.name"}}
		if err := c.do(ctx, http.MethodGet, "/projects", q, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			r := map[string]any{"id": x.GID, "name": x.Name, "archived": x.Archived, "url": x.URL, "modified": x.ModifiedAt}
			if x.Team != nil {
				r["team"] = x.Team.Name
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "tasks":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 50
		}
		q := url.Values{"limit": {strconv.Itoa(limit)}, "opt_fields": {taskFields}}
		if p.Project != "" {
			if err := need(p.Project, "project"); err != nil {
				return sdk.Result{}, err
			}
			q.Set("project", p.Project)
		} else {
			ws, err := c.workspace(ctx, p.Workspace)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("workspace", ws)
			q.Set("assignee", "me")
		}
		if !p.Completed {
			q.Set("completed_since", "now") // only incomplete tasks
		}
		var ts []task
		if err := c.do(ctx, http.MethodGet, "/tasks", q, nil, &ts); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			out = append(out, summary(t))
		}
		return sdk.JSON(map[string]any{"count": len(out), "tasks": out})

	case "task":
		t, err := c.task(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(t)
		out["notes"] = t.Notes
		out["tags"] = names(t.Tags)
		out["created"] = t.CreatedAt
		var st []struct {
			GID       string `json:"gid"`
			Type      string `json:"type"`
			Text      string `json:"text"`
			CreatedAt string `json:"created_at"`
			CreatedBy *named `json:"created_by"`
		}
		comments := []map[string]any{}
		if c.do(ctx, http.MethodGet, "/tasks/"+t.GID+"/stories", url.Values{"opt_fields": {"type,text,created_at,created_by.name"}, "limit": {"100"}}, nil, &st) == nil {
			for _, s := range st {
				if s.Type != "comment" {
					continue
				}
				r := map[string]any{"id": s.GID, "at": s.CreatedAt, "text": s.Text}
				if s.CreatedBy != nil {
					r["by"] = s.CreatedBy.Name
				}
				comments = append(comments, r)
			}
		}
		if len(comments) > 20 {
			comments = comments[len(comments)-20:]
		}
		out["comments"] = comments
		return sdk.JSON(out)

	case "create_task":
		return c.create(ctx, call, p)
	case "update_task":
		return c.update(ctx, call, p)
	case "complete_task", "reopen_task":
		return c.setCompleted(ctx, call, p.Task)
	case "comment":
		return c.comment(ctx, call, p)

	case "delete_comment":
		if err := need(p.Comment, "comment"); err != nil {
			return sdk.Result{}, err
		}
		var s struct {
			GID       string `json:"gid"`
			Type      string `json:"type"`
			Text      string `json:"text"`
			CreatedBy *named `json:"created_by"`
		}
		if err := c.do(ctx, http.MethodGet, "/stories/"+p.Comment, url.Values{"opt_fields": {"type,text,created_by.name"}}, nil, &s); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no comment %s", p.Comment)
			}
			return sdk.Result{}, err
		}
		if s.GID != p.Comment || s.Type != "comment" {
			return sdk.Result{}, fmt.Errorf("%s isn't a comment", p.Comment)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete comment " + s.GID,
				Changes: []sdk.Change{{Target: "comment " + s.GID, Op: "delete", Before: mustJSON(map[string]string{"text": s.Text})}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/stories/"+s.GID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": s.GID})

	case "delete_task":
		t, err := c.task(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete task %q", t.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.GID, t.Name), Op: "delete", Before: mustJSON(summary(t))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/tasks/"+t.GID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": t.GID, "name": t.Name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// workspace returns the workspace given, or the only one there is.
func (c *conn) workspace(ctx context.Context, id string) (string, error) {
	if id != "" {
		return id, need(id, "workspace")
	}
	var ws []named
	if err := c.do(ctx, http.MethodGet, "/workspaces", url.Values{"limit": {"100"}}, nil, &ws); err != nil {
		return "", err
	}
	if len(ws) != 1 {
		return "", fmt.Errorf("you're in %d workspaces; say which (see workspaces)", len(ws))
	}
	return ws[0].GID, nil
}

func (c *conn) task(ctx context.Context, id string) (task, error) {
	var t task
	if err := need(id, "task"); err != nil {
		return t, err
	}
	q := url.Values{"opt_fields": {taskFields + ",notes,tags.name,created_at,assignee.gid"}}
	if err := c.do(ctx, http.MethodGet, "/tasks/"+id, q, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return t, fmt.Errorf("there's no task %s", id)
		}
		return t, err
	}
	if t.GID != id {
		// The id goes into the change's path and its undo.
		return t, fmt.Errorf("Asana answered with another task for %s", id)
	}
	return t, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Name == nil {
		return sdk.Result{}, errors.New("the task needs a name")
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	where := ""
	switch {
	case p.Project != "":
		if err := need(p.Project, "project"); err != nil {
			return sdk.Result{}, err
		}
		var pr named
		if err := c.do(ctx, http.MethodGet, "/projects/"+p.Project, url.Values{"opt_fields": {"name"}}, nil, &pr); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no project %s", p.Project)
			}
			return sdk.Result{}, err
		}
		b["projects"] = []string{p.Project}
		where = "project " + pr.Name
	case p.Workspace != "":
		if err := need(p.Workspace, "workspace"); err != nil {
			return sdk.Result{}, err
		}
		b["workspace"] = p.Workspace
		if _, ok := b["assignee"]; !ok {
			b["assignee"] = "me"
		}
		where = "My Tasks in workspace " + p.Workspace
	default:
		return sdk.Result{}, errors.New("say which project (or workspace) the task goes in")
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create task %q in %s", b["name"], where),
			Changes: []sdk.Change{{Target: "task in " + where, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var t task
	if err := c.do(ctx, http.MethodPost, "/tasks", url.Values{"opt_fields": {taskFields}}, b, &t); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(summary(t))
	if gidRe.MatchString(t.GID) {
		res.Undo = sdk.UndoWith("delete_task", map[string]string{"task": t.GID}, fmt.Sprintf("Delete task %q", t.Name))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(p.Task, "task"); err != nil {
		return sdk.Result{}, err
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	if len(b) == 0 {
		return sdk.Result{}, errors.New("say what to change: name, notes, due or assignee")
	}
	t, err := c.task(ctx, p.Task)
	if err != nil {
		return sdk.Result{}, err
	}
	due, assignee, assigneeName := "", "", ""
	if t.DueOn != nil {
		due = *t.DueOn
	}
	if t.Assignee != nil {
		assignee, assigneeName = t.Assignee.GID, t.Assignee.Name
	}
	before, after, back := map[string]any{}, map[string]any{}, map[string]any{"task": t.GID}
	for k, v := range b {
		switch k {
		case "name":
			if v != t.Name {
				before["name"], after["name"], back["name"] = t.Name, v, t.Name
			}
		case "notes":
			if v != t.Notes {
				before["notes"], after["notes"], back["notes"] = t.Notes, v, t.Notes
			}
		case "due_on":
			if s, _ := v.(string); s != due {
				before["due"], after["due"], back["due"] = due, s, due
			}
		case "assignee":
			s, _ := v.(string)
			if s == "me" {
				var me named
				if err := c.do(ctx, http.MethodGet, "/users/me", url.Values{"opt_fields": {"name"}}, nil, &me); err != nil {
					return sdk.Result{}, err
				}
				s = me.GID
			}
			if s != assignee {
				before["assignee"], after["assignee"], back["assignee"] = assigneeName, s, assignee
			}
		}
	}
	if len(after) == 0 {
		return sdk.JSON(map[string]any{"task": t.GID, "name": t.Name, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update task %q", t.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.GID, t.Name), Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var out task
	if err := c.do(ctx, http.MethodPut, "/tasks/"+t.GID, url.Values{"opt_fields": {taskFields}}, b, &out); err != nil {
		return sdk.Result{}, err
	}
	if out.GID == "" {
		out = t
	}
	res, err := sdk.JSON(summary(out))
	res.Undo = sdk.UndoWith("update_task", back, fmt.Sprintf("Restore task %q", t.Name))
	return res, err
}

func (c *conn) setCompleted(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	t, err := c.task(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	done := call.Action == "complete_task"
	if t.Completed == done {
		return sdk.JSON(map[string]any{"task": t.GID, "name": t.Name, "completed": done, "note": "nothing to change"})
	}
	verb, back, undo := "Complete", "reopen_task", "Reopen"
	if !done {
		verb, back, undo = "Reopen", "complete_task", "Complete"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s task %q", verb, t.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.GID, t.Name), Op: strings.ToLower(verb),
				Before: mustJSON(map[string]bool{"completed": t.Completed}), After: mustJSON(map[string]bool{"completed": done})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPut, "/tasks/"+t.GID, nil, map[string]any{"completed": done}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"task": t.GID, "name": t.Name, "completed": done})
	res.Undo = sdk.UndoWith(back, map[string]string{"task": t.GID}, fmt.Sprintf("%s task %q", undo, t.Name))
	return res, err
}

func (c *conn) comment(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(p.Task, "task"); err != nil {
		return sdk.Result{}, err
	}
	text := strings.TrimSpace(p.Text)
	if text == "" || len(text) > maxComment {
		return sdk.Result{}, fmt.Errorf("a comment is 1 to %d characters", maxComment)
	}
	if f := mention.Find(text); f.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", f.Wildcard)
	}
	t, err := c.task(ctx, p.Task)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Comment on task %q", t.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.GID, t.Name), Op: "create", After: mustJSON(map[string]string{"text": text})}}}}, nil
	}
	var s struct {
		GID string `json:"gid"`
	}
	if err := c.do(ctx, http.MethodPost, "/tasks/"+t.GID+"/stories", nil, map[string]any{"text": text}, &s); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"task": t.GID, "comment": s.GID})
	if gidRe.MatchString(s.GID) {
		res.Undo = sdk.UndoWith("delete_comment", map[string]string{"comment": s.GID}, "Delete the comment")
	}
	return res, err
}
