// Package clickup works with ClickUp through its REST API (v2) and a personal
// API token: workspaces, spaces, lists and tasks, creating, updating and
// deleting tasks, and commenting on them.
package clickup

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

// Config is one ClickUp account.
type Config struct {
	Token string `json:"token"` // secret:// personal API token (pk_…)
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.clickup.com/api/v2 (tests).
	Base string
}

// New returns the ClickUp module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.clickup.com/api/v2"
	maxName     = 1024
	maxText     = 50000
)

var (
	// Workspace, space, folder and list ids are numbers; task ids are
	// short alphanumeric strings ("86a1b2c3d"); comment ids are numbers.
	numRe  = regexp.MustCompile(`^\d{1,20}$`)
	taskRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	task := `"task":{"type":"string","description":"Task id (from tasks)"}`
	fields := `"name":{"type":"string","maxLength":1024},
		"description":{"type":"string","x-multiline":true,"description":"Markdown"},
		"status":{"type":"string","description":"A status of the list, e.g. 'in progress' or 'complete'"},
		"priority":{"type":"integer","minimum":0,"maximum":4,"description":"1 urgent, 2 high, 3 normal, 4 low; 0 clears it"},
		"due":{"type":"string","description":"Due date, YYYY-MM-DD; empty clears it"}`
	return sdk.Manifest{
		ID: "clickup", Name: "ClickUp", Version: "0.1.0", Category: "Productivity", Icon: "check",
		Description: "ClickUp: spaces, lists and tasks; create and update tasks (status, priority, due date) and comment on them.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal API token, pk_… (Settings, Apps, API Token). It acts as you"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "workspaces", Title: "Workspaces", Description: "The workspaces (teams) the token can reach.", Risk: sdk.RiskRead},
			{Name: "spaces", Title: "Spaces", Description: "Spaces in a workspace (the only one when you have one), with their statuses.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"workspace":{"type":"string","description":"Workspace id"}}}`)},
			{Name: "lists", Title: "Lists", Description: "Lists in a space, in folders or on their own, with task counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["space"],"properties":{"space":{"type":"string","description":"Space id"}}}`)},
			{Name: "tasks", Title: "Tasks", Description: "Tasks in a list, open ones unless closed is set.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["list"],"properties":{"list":{"type":"string","description":"List id"},"closed":{"type":"boolean","default":false,"description":"Include closed tasks"},"page":{"type":"integer","default":0}}}`)},
			{Name: "task", Title: "Task details", Description: "Name, description, status, priority, due date, assignees, tags and recent comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `}}`)},
			{Name: "create_task", Title: "Create a task", Description: "Adds a task to a list. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["list","name"],"properties":{"list":{"type":"string","description":"List id"},` + fields + `}}`)},
			{Name: "update_task", Title: "Update a task", Description: "Changes the fields given; set status to close or reopen it. Undo puts the old values back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task"],"properties":{` + task + `,` + fields + `}}`)},
			{Name: "comment", Title: "Comment on a task", Description: "Adds a comment, without notifying everyone on the task (the assignees and watchers ClickUp always tells still hear). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["task","text"],"properties":{` + task + `,"text":{"type":"string","x-multiline":true}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["comment"],"properties":{"comment":{"type":"string","description":"Comment id"}}}`)},
			{Name: "delete_task", Title: "Delete a task", Description: "Deletes a task with its subtasks and comments.", Risk: sdk.RiskDestructive, DryRun: true,
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
		r.Header.Set("Authorization", strings.TrimSpace(t))
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
		return errors.New("ClickUp refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("your ClickUp account isn't allowed to do this")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("ClickUp's rate limit was reached; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type task struct {
	ID          string `json:"id"`
	CustomID    string `json:"custom_id"`
	Name        string `json:"name"`
	TextContent string `json:"text_content"`
	Status      struct {
		Status string `json:"status"`
		Type   string `json:"type"`
	} `json:"status"`
	Priority *struct {
		ID       string `json:"id"`
		Priority string `json:"priority"`
	} `json:"priority"`
	DueDate   *string `json:"due_date"`
	Assignees []struct {
		Username string `json:"username"`
		// Email isn't decoded: it'd end up in the audit log.
	} `json:"assignees"`
	Tags []struct {
		Name string `json:"name"`
	} `json:"tags"`
	List        named  `json:"list"`
	URL         string `json:"url"`
	DateCreated string `json:"date_created"`
	DateUpdated string `json:"date_updated"`
	DateClosed  string `json:"date_closed"`
}

// day turns ClickUp's milliseconds into YYYY-MM-DD (UTC).
func day(ms *string) string {
	if ms == nil || *ms == "" {
		return ""
	}
	n, err := strconv.ParseInt(*ms, 10, 64)
	if err != nil {
		return ""
	}
	return time.UnixMilli(n).UTC().Format("2006-01-02")
}

func stamp(ms string) string {
	if d := day(&ms); d != "" {
		n, _ := strconv.ParseInt(ms, 10, 64)
		return time.UnixMilli(n).UTC().Format(time.RFC3339)
	}
	return ""
}

func priority(t task) int {
	if t.Priority == nil {
		return 0
	}
	n, _ := strconv.Atoi(t.Priority.ID)
	return n
}

func summary(t task) map[string]any {
	who := []string{}
	for _, a := range t.Assignees {
		who = append(who, a.Username)
	}
	out := map[string]any{"id": t.ID, "name": t.Name, "status": t.Status.Status, "closed": t.Status.Type == "closed" || t.Status.Type == "done",
		"assignees": who, "list": t.List.Name, "url": t.URL}
	if t.CustomID != "" {
		out["customId"] = t.CustomID
	}
	if t.Priority != nil {
		out["priority"] = t.Priority.Priority
	}
	if d := day(t.DueDate); d != "" {
		out["due"] = d
	}
	if s := stamp(t.DateUpdated); s != "" {
		out["updated"] = s
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
	var u struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ws, err := c.workspaces(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("signed in as %s, %d workspaces", u.User.Username, len(ws))}
}

func (c *conn) workspaces(ctx context.Context) ([]named, error) {
	// Members (with their emails) aren't decoded.
	var t struct {
		Teams []named `json:"teams"`
	}
	err := c.do(ctx, http.MethodGet, "/team", nil, nil, &t)
	return t.Teams, err
}

type input struct {
	Workspace   string  `json:"workspace"`
	Space       string  `json:"space"`
	List        string  `json:"list"`
	Closed      bool    `json:"closed"`
	Page        int     `json:"page"`
	Task        string  `json:"task"`
	Comment     string  `json:"comment"`
	Text        string  `json:"text"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
	Priority    *int    `json:"priority"`
	Due         *string `json:"due"`
}

// fields checks the task fields given and returns them as ClickUp's body.
func (p input) fields() (map[string]any, error) {
	b := map[string]any{}
	if p.Name != nil {
		s := strings.TrimSpace(*p.Name)
		if s == "" || len(s) > maxName {
			return nil, fmt.Errorf("a task name is 1 to %d characters", maxName)
		}
		b["name"] = s
	}
	if p.Description != nil {
		if len(*p.Description) > maxText {
			return nil, errors.New("the description is too long")
		}
		b["markdown_description"] = *p.Description
	}
	if p.Status != nil {
		s := strings.TrimSpace(*p.Status)
		if s == "" || len(s) > 100 {
			return nil, errors.New("a status is a name of up to 100 characters")
		}
		b["status"] = s
	}
	if p.Priority != nil {
		if *p.Priority < 0 || *p.Priority > 4 {
			return nil, errors.New("priority is 1 (urgent) to 4 (low), or 0 to clear it")
		}
		if *p.Priority == 0 {
			b["priority"] = nil
		} else {
			b["priority"] = *p.Priority
		}
	}
	if p.Due != nil {
		d := strings.TrimSpace(*p.Due)
		if d == "" {
			b["due_date"] = nil
		} else if t, err := time.Parse("2006-01-02", d); err != nil {
			return nil, errors.New("the due date is like 2026-12-01")
		} else {
			b["due_date"] = t.UnixMilli()
			b["due_date_time"] = false
		}
	}
	return b, nil
}

func need(re *regexp.Regexp, id, what string) error {
	if !re.MatchString(id) {
		return fmt.Errorf("the %s is its id (see %ss)", what, what)
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
	p.Workspace, p.Space, p.List, p.Task, p.Comment = strings.TrimSpace(p.Workspace), strings.TrimSpace(p.Space), strings.TrimSpace(p.List), strings.TrimSpace(p.Task), strings.TrimSpace(p.Comment)
	switch call.Action {
	case "workspaces":
		ws, err := c.workspaces(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, w := range ws {
			out = append(out, map[string]any{"id": w.ID, "name": w.Name})
		}
		return sdk.JSON(out)

	case "spaces":
		ws := p.Workspace
		if ws == "" {
			all, err := c.workspaces(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			if len(all) != 1 {
				return sdk.Result{}, fmt.Errorf("the token reaches %d workspaces; say which (see workspaces)", len(all))
			}
			ws = all[0].ID
		} else if err := need(numRe, ws, "workspace"); err != nil {
			return sdk.Result{}, err
		}
		var s struct {
			Spaces []struct {
				named
				Private  bool `json:"private"`
				Statuses []struct {
					Status string `json:"status"`
					Type   string `json:"type"`
				} `json:"statuses"`
			} `json:"spaces"`
		}
		if err := c.do(ctx, http.MethodGet, "/team/"+ws+"/space", url.Values{"archived": {"false"}}, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range s.Spaces {
			st := []string{}
			for _, v := range x.Statuses {
				st = append(st, v.Status)
			}
			out = append(out, map[string]any{"id": x.ID, "name": x.Name, "private": x.Private, "statuses": st})
		}
		return sdk.JSON(out)

	case "lists":
		if err := need(numRe, p.Space, "space"); err != nil {
			return sdk.Result{}, err
		}
		type list struct {
			named
			TaskCount any  `json:"task_count"`
			Archived  bool `json:"archived"`
		}
		var free struct {
			Lists []list `json:"lists"`
		}
		var folders struct {
			Folders []struct {
				named
				Lists []list `json:"lists"`
			} `json:"folders"`
		}
		q := url.Values{"archived": {"false"}}
		if err := c.do(ctx, http.MethodGet, "/space/"+p.Space+"/folder", q, nil, &folders); err != nil {
			return sdk.Result{}, err
		}
		if err := c.do(ctx, http.MethodGet, "/space/"+p.Space+"/list", q, nil, &free); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		row := func(l list, folder string) {
			r := map[string]any{"id": l.ID, "name": l.Name, "tasks": l.TaskCount}
			if folder != "" {
				r["folder"] = folder
			}
			out = append(out, r)
		}
		for _, f := range folders.Folders {
			for _, l := range f.Lists {
				row(l, f.Name)
			}
		}
		for _, l := range free.Lists {
			row(l, "")
		}
		return sdk.JSON(out)

	case "tasks":
		if err := need(numRe, p.List, "list"); err != nil {
			return sdk.Result{}, err
		}
		if p.Page < 0 || p.Page > 1000 {
			return sdk.Result{}, errors.New("the page is 0 or more")
		}
		q := url.Values{"page": {strconv.Itoa(p.Page)}, "include_closed": {strconv.FormatBool(p.Closed)}, "subtasks": {"true"}, "archived": {"false"}}
		var r struct {
			Tasks    []task `json:"tasks"`
			LastPage bool   `json:"last_page"`
		}
		if err := c.do(ctx, http.MethodGet, "/list/"+p.List+"/task", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range r.Tasks {
			out = append(out, summary(t))
		}
		res := map[string]any{"count": len(out), "tasks": out}
		if !r.LastPage && len(r.Tasks) > 0 {
			res["nextPage"] = p.Page + 1
		}
		return sdk.JSON(res)

	case "task":
		t, err := c.task(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(t)
		out["description"] = t.TextContent
		tags := []string{}
		for _, x := range t.Tags {
			tags = append(tags, x.Name)
		}
		out["tags"] = tags
		if s := stamp(t.DateCreated); s != "" {
			out["created"] = s
		}
		var cs struct {
			Comments []struct {
				ID          string `json:"id"`
				CommentText string `json:"comment_text"`
				Date        string `json:"date"`
				User        struct {
					Username string `json:"username"`
				} `json:"user"`
			} `json:"comments"`
		}
		comments := []map[string]any{}
		if c.do(ctx, http.MethodGet, "/task/"+t.ID+"/comment", nil, nil, &cs) == nil {
			for _, x := range cs.Comments {
				comments = append(comments, map[string]any{"id": x.ID, "by": x.User.Username, "at": stamp(x.Date), "text": x.CommentText})
			}
		}
		if len(comments) > 20 {
			comments = comments[:20] // newest first
		}
		out["comments"] = comments
		return sdk.JSON(out)

	case "create_task":
		return c.create(ctx, call, p)
	case "update_task":
		return c.update(ctx, call, p)
	case "comment":
		return c.comment(ctx, call, p)

	case "delete_comment":
		if err := need(numRe, p.Comment, "comment"); err != nil {
			return sdk.Result{}, err
		}
		if err := c.do(ctx, http.MethodDelete, "/comment/"+p.Comment, nil, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no comment %s", p.Comment)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Comment})

	case "delete_task":
		t, err := c.task(ctx, p.Task)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete task %q", t.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q in %s", t.ID, t.Name, t.List.Name), Op: "delete", Before: mustJSON(summary(t))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/task/"+t.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": t.ID, "name": t.Name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) task(ctx context.Context, id string) (task, error) {
	var t task
	if err := need(taskRe, id, "task"); err != nil {
		return t, err
	}
	if err := c.do(ctx, http.MethodGet, "/task/"+id, url.Values{"include_markdown_description": {"false"}}, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return t, fmt.Errorf("there's no task %s", id)
		}
		return t, err
	}
	if t.ID != id {
		// The id goes into the change's path and its undo.
		return t, fmt.Errorf("ClickUp answered with another task for %s", id)
	}
	return t, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(numRe, p.List, "list"); err != nil {
		return sdk.Result{}, err
	}
	if p.Name == nil {
		return sdk.Result{}, errors.New("the task needs a name")
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	var l named
	if err := c.do(ctx, http.MethodGet, "/list/"+p.List, nil, nil, &l); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no list %s", p.List)
		}
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create task %q in %s", b["name"], l.Name),
			Changes: []sdk.Change{{Target: "task in list " + l.Name, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var t task
	if err := c.do(ctx, http.MethodPost, "/list/"+p.List+"/task", nil, b, &t); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(summary(t))
	if taskRe.MatchString(t.ID) {
		res.Undo = sdk.UndoWith("delete_task", map[string]string{"task": t.ID}, fmt.Sprintf("Delete task %q", t.Name))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(taskRe, p.Task, "task"); err != nil {
		return sdk.Result{}, err
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	if len(b) == 0 {
		return sdk.Result{}, errors.New("say what to change: name, description, status, priority or due")
	}
	t, err := c.task(ctx, p.Task)
	if err != nil {
		return sdk.Result{}, err
	}
	before, after, back, send := map[string]any{}, map[string]any{}, map[string]any{"task": t.ID}, map[string]any{}
	for k, v := range b {
		switch k {
		case "name":
			if v != t.Name {
				before[k], after[k], back[k], send[k] = t.Name, v, t.Name, v
			}
		case "markdown_description":
			if v != t.TextContent {
				before["description"], after["description"], back["description"], send[k] = t.TextContent, v, t.TextContent, v
			}
		case "status":
			if !strings.EqualFold(v.(string), t.Status.Status) {
				before[k], after[k], back[k], send[k] = t.Status.Status, v, t.Status.Status, v
			}
		case "priority":
			n, _ := v.(int)
			if n != priority(t) {
				before[k], after[k], back[k], send[k] = priority(t), n, priority(t), v
			}
		case "due_date":
			d := ""
			if ms, ok := v.(int64); ok {
				d = time.UnixMilli(ms).UTC().Format("2006-01-02")
			}
			if d != day(t.DueDate) {
				before["due"], after["due"], back["due"], send[k] = day(t.DueDate), d, day(t.DueDate), v
				if d != "" {
					send["due_date_time"] = false
				}
			}
		}
	}
	if len(send) == 0 {
		return sdk.JSON(map[string]any{"task": t.ID, "name": t.Name, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update task %q", t.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.ID, t.Name), Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var out task
	if err := c.do(ctx, http.MethodPut, "/task/"+t.ID, nil, send, &out); err != nil {
		return sdk.Result{}, err
	}
	if out.ID == "" {
		out = t
	}
	res, err := sdk.JSON(summary(out))
	res.Undo = sdk.UndoWith("update_task", back, fmt.Sprintf("Restore task %q", t.Name))
	return res, err
}

func (c *conn) comment(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if err := need(taskRe, p.Task, "task"); err != nil {
		return sdk.Result{}, err
	}
	text := strings.TrimSpace(p.Text)
	if text == "" || len(text) > maxText {
		return sdk.Result{}, fmt.Errorf("a comment is 1 to %d characters", maxText)
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
			Changes: []sdk.Change{{Target: fmt.Sprintf("task %s %q", t.ID, t.Name), Op: "create", After: mustJSON(map[string]string{"text": text})}}}}, nil
	}
	var r struct {
		ID json.RawMessage `json:"id"` // a number, or a string on some accounts
	}
	if err := c.do(ctx, http.MethodPost, "/task/"+t.ID+"/comment", nil, map[string]any{"comment_text": text, "notify_all": false}, &r); err != nil {
		return sdk.Result{}, err
	}
	id := strings.Trim(string(r.ID), `"`)
	res, err := sdk.JSON(map[string]string{"task": t.ID, "comment": id})
	if numRe.MatchString(id) {
		res.Undo = sdk.UndoWith("delete_comment", map[string]string{"comment": id}, "Delete the comment")
	}
	return res, err
}
