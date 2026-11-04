// Package plane works with Plane (plane.so, cloud or self-hosted) through its
// REST API and an API key: projects, states and work items (issues),
// creating, updating and deleting them, and commenting on them.
package plane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Plane workspace.
type Config struct {
	URL                string `json:"url"`       // default https://api.plane.so; self-hosted: the instance's address
	Workspace          string `json:"workspace"` // workspace slug, from the address bar
	Token              string `json:"token"`     // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	ws  string // workspace path, /workspaces/<slug>

	mu  sync.Mutex
	seg string // "work-items", or "issues" on older servers
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Plane module.
func New() *Module { return &Module{} }

const (
	maxName    = 255
	maxText    = 50000
	maxComment = 20000
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// Plane's cursors are "per_page:page:is_prev".
	cursorRe   = regexp.MustCompile(`^\d{1,3}:\d{1,6}:[01]$`)
	priorities = map[string]bool{"urgent": true, "high": true, "medium": true, "low": true, "none": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project id (from projects)"}`
	issue := project + `,"issue":{"type":"string","description":"Work item id (from issues)"}`
	fields := `"name":{"type":"string","maxLength":255},
		"description":{"type":"string","x-multiline":true,"description":"Plain text"},
		"state":{"type":"string","description":"State name, e.g. In Progress or Done (see states)"},
		"priority":{"type":"string","enum":["urgent","high","medium","low","none"]},
		"due":{"type":"string","description":"Target date, YYYY-MM-DD; empty clears it"}`
	return sdk.Manifest{
		ID: "plane", Name: "Plane", Version: "0.1.0", Category: "Productivity", Icon: "list",
		Description: "Plane (cloud or self-hosted): projects, states and work items; create, update and comment on issues.",
		Presets:     []string{"developer", "team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["workspace","token"],"properties":{
			"url":{"type":"string","default":"https://api.plane.so","description":"Plane Cloud, or your instance's address, e.g. https://plane.example.com"},
			"workspace":{"type":"string","description":"The workspace slug, as in the address: app.plane.so/<slug>/"},
			"token":{"type":"string","x-secret":true,"description":"An API key (Profile settings, Personal access tokens, or Workspace settings, API tokens). It acts as its user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects in the workspace with their identifiers.", Risk: sdk.RiskRead},
			{Name: "states", Title: "States", Description: "A project's workflow states and their groups (backlog, unstarted, started, completed, cancelled).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `}}`)},
			{Name: "issues", Title: "Work items", Description: "A project's work items, newest first; pass the cursor from one page to get the next.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `,"limit":{"type":"integer","default":50,"maximum":100},"cursor":{"type":"string"}}}`)},
			{Name: "issue", Title: "Work item details", Description: "Name, description, state, priority, dates and comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project","issue"],"properties":{` + issue + `}}`)},
			{Name: "create_issue", Title: "Create a work item", Description: "Adds a work item to a project. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","name"],"properties":{` + project + `,` + fields + `}}`)},
			{Name: "update_issue", Title: "Update a work item", Description: "Changes the fields given; set state to move it. Undo puts the old values back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","issue"],"properties":{` + issue + `,` + fields + `}}`)},
			{Name: "comment", Title: "Comment on a work item", Description: "Adds a plain-text comment. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","issue","text"],"properties":{` + issue + `,"text":{"type":"string","x-multiline":true}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["project","issue","comment"],"properties":{` + issue + `,"comment":{"type":"string","description":"Comment id"}}}`)},
			{Name: "delete_issue", Title: "Delete a work item", Description: "Deletes a work item with its comments.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","issue"],"properties":{` + issue + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "https://api.plane.so"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://plane.example.com")
	}
	c.Workspace = strings.ToLower(strings.TrimSpace(c.Workspace))
	if !slugRe.MatchString(c.Workspace) {
		return errors.New("the workspace is its slug, as in app.plane.so/<slug>/")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	base := strings.TrimRight(u.Path, "/")
	base = strings.TrimSuffix(strings.TrimSuffix(base, "/v1"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-Key", strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, ws: "/workspaces/" + c.Workspace})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Plane refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the key's user isn't allowed to do this in Plane")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Plane's rate limit was reached; try again in a minute")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// list reads an answer that is a plain array or a page with results.
func list[T any](ctx context.Context, c *conn, path string, q url.Values) ([]T, *string, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, path, q, nil, &raw); err != nil {
		return nil, nil, err
	}
	var arr []T
	if json.Unmarshal(raw, &arr) == nil {
		return arr, nil, nil
	}
	var pg struct {
		Results     []T     `json:"results"`
		NextCursor  *string `json:"next_cursor"`
		NextResults bool    `json:"next_page_results"`
	}
	if err := json.Unmarshal(raw, &pg); err != nil {
		return nil, nil, errors.New("unexpected answer from Plane")
	}
	if !pg.NextResults {
		pg.NextCursor = nil
	}
	return pg.Results, pg.NextCursor, nil
}

// items returns the path of a project's work items. Plane renamed issues to
// work items; older servers only know /issues/.
func (c *conn) items(ctx context.Context, project string) (string, error) {
	c.mu.Lock()
	seg := c.seg
	c.mu.Unlock()
	base := c.ws + "/projects/" + project + "/"
	if seg != "" {
		return base + seg + "/", nil
	}
	q := url.Values{"per_page": {"1"}}
	err := c.do(ctx, http.MethodGet, base+"work-items/", q, nil, nil)
	seg = "work-items"
	if rest.IsStatus(err, http.StatusNotFound) {
		if err2 := c.do(ctx, http.MethodGet, base+"issues/", q, nil, nil); err2 == nil {
			seg, err = "issues", nil
		}
	}
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", fmt.Errorf("there's no project %s in this workspace", project)
		}
		return "", err
	}
	c.mu.Lock()
	c.seg = seg
	c.mu.Unlock()
	return base + seg + "/", nil
}

type project struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Identifier  string  `json:"identifier"`
	Description string  `json:"description"`
	ArchivedAt  *string `json:"archived_at"`
	Members     *int    `json:"total_members"`
}

type state struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

type issue struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SequenceID  int      `json:"sequence_id"`
	State       string   `json:"state"`
	Priority    string   `json:"priority"`
	StartDate   *string  `json:"start_date"`
	TargetDate  *string  `json:"target_date"`
	Description string   `json:"description_stripped"`
	Assignees   []string `json:"assignees"`
	Labels      []string `json:"labels"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	CompletedAt *string  `json:"completed_at"`
	Project     string   `json:"project"`
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type ctxProject struct {
	p      project
	states map[string]state
	order  []state // as Plane lists them
}

func (cp ctxProject) summary(i issue) map[string]any {
	out := map[string]any{"id": i.ID, "name": i.Name, "priority": i.Priority, "assignees": len(i.Assignees)}
	if cp.p.Identifier != "" && i.SequenceID > 0 {
		out["key"] = cp.p.Identifier + "-" + strconv.Itoa(i.SequenceID)
	}
	if s, ok := cp.states[i.State]; ok {
		out["state"], out["stateGroup"] = s.Name, s.Group
	}
	if d := str(i.TargetDate); d != "" {
		out["due"] = d
	}
	if d := str(i.StartDate); d != "" {
		out["start"] = d
	}
	if i.UpdatedAt != "" {
		out["updated"] = i.UpdatedAt
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
		DisplayName string `json:"display_name"`
		// Email isn't decoded: it'd end up in the audit log.
	}
	if err := c.do(ctx, http.MethodGet, "/users/me/", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Plane API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ps, _, err := list[project](ctx, c, c.ws+"/projects/", nil)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "there's no such workspace, or the key can't see it"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("signed in as %s, %d projects", me.DisplayName, len(ps))}
}

type input struct {
	Project     string  `json:"project"`
	Issue       string  `json:"issue"`
	Comment     string  `json:"comment"`
	Limit       int     `json:"limit"`
	Cursor      string  `json:"cursor"`
	Text        string  `json:"text"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	State       *string `json:"state"`
	Priority    *string `json:"priority"`
	Due         *string `json:"due"`
}

func need(id, what string) error {
	if !uuidRe.MatchString(id) {
		return fmt.Errorf("the %s is its id (a UUID)", what)
	}
	return nil
}

// paragraphs turns plain text into escaped HTML paragraphs.
func paragraphs(text string) string {
	var b strings.Builder
	for _, p := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		b.WriteString("<p>" + strings.ReplaceAll(html.EscapeString(p), "\n", "<br>") + "</p>")
	}
	if b.Len() == 0 {
		return "<p></p>"
	}
	return b.String()
}

// fields checks the work item fields given; a state is still a name here.
func (p input) fields() (map[string]any, error) {
	b := map[string]any{}
	if p.Name != nil {
		s := strings.TrimSpace(*p.Name)
		if s == "" || len(s) > maxName {
			return nil, fmt.Errorf("a name is 1 to %d characters", maxName)
		}
		b["name"] = s
	}
	if p.Description != nil {
		if len(*p.Description) > maxText {
			return nil, errors.New("the description is too long")
		}
		b["description"] = strings.TrimSpace(*p.Description)
	}
	if p.State != nil {
		s := strings.TrimSpace(*p.State)
		if s == "" || len(s) > 255 {
			return nil, errors.New("the state is a state name (see states)")
		}
		b["state"] = s
	}
	if p.Priority != nil {
		s := strings.ToLower(strings.TrimSpace(*p.Priority))
		if !priorities[s] {
			return nil, errors.New("priority is urgent, high, medium, low or none")
		}
		b["priority"] = s
	}
	if p.Due != nil {
		d := strings.TrimSpace(*p.Due)
		if d == "" {
			b["target_date"] = nil
		} else if _, err := time.Parse("2006-01-02", d); err != nil {
			return nil, errors.New("the due date is like 2026-12-01")
		} else {
			b["target_date"] = d
		}
	}
	return b, nil
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
	p.Project, p.Issue, p.Comment, p.Cursor = strings.TrimSpace(p.Project), strings.TrimSpace(p.Issue), strings.TrimSpace(p.Comment), strings.TrimSpace(p.Cursor)
	if call.Action == "projects" {
		ps, _, err := list[project](ctx, c, c.ws+"/projects/", nil)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			r := map[string]any{"id": x.ID, "name": x.Name, "identifier": x.Identifier}
			if x.Description != "" {
				r["description"] = x.Description
			}
			if x.ArchivedAt != nil {
				r["archived"] = true
			}
			if x.Members != nil {
				r["members"] = *x.Members
			}
			out = append(out, r)
		}
		return sdk.JSON(out)
	}
	// Everything else is in a project; check every id before any request.
	if err := need(p.Project, "project"); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "issue", "update_issue", "comment", "delete_comment", "delete_issue":
		if err := need(p.Issue, "work item"); err != nil {
			return sdk.Result{}, err
		}
	}
	switch call.Action {
	case "states":
		cp, err := c.project(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, s := range cp.order {
			out = append(out, map[string]string{"id": s.ID, "name": s.Name, "group": s.Group})
		}
		return sdk.JSON(out)

	case "issues":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 50
		}
		q := url.Values{"per_page": {strconv.Itoa(limit)}, "order_by": {"-created_at"}}
		if p.Cursor != "" {
			if !cursorRe.MatchString(p.Cursor) {
				return sdk.Result{}, errors.New("the cursor is the one the previous page returned")
			}
			q.Set("cursor", p.Cursor)
		}
		cp, err := c.project(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		path, err := c.items(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		is, next, err := list[issue](ctx, c, path, q)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			out = append(out, cp.summary(i))
		}
		res := map[string]any{"project": cp.p.Name, "count": len(out), "issues": out}
		if next != nil && *next != "" {
			res["cursor"] = *next
		}
		return sdk.JSON(res)

	case "issue":
		cp, i, path, err := c.issue(ctx, p.Project, p.Issue)
		if err != nil {
			return sdk.Result{}, err
		}
		out := cp.summary(i)
		out["description"] = i.Description
		out["created"] = i.CreatedAt
		if d := str(i.CompletedAt); d != "" {
			out["completed"] = d
		}
		comments := []map[string]any{}
		cs, _, err := list[struct {
			ID          string `json:"id"`
			CommentHTML string `json:"comment_html"`
			Stripped    string `json:"comment_stripped"`
			CreatedAt   string `json:"created_at"`
		}](ctx, c, path+i.ID+"/comments/", nil)
		if err == nil {
			for _, x := range cs {
				comments = append(comments, map[string]any{"id": x.ID, "at": x.CreatedAt, "text": x.Stripped})
			}
		}
		out["comments"] = comments
		return sdk.JSON(out)

	case "create_issue":
		return c.create(ctx, call, p)
	case "update_issue":
		return c.update(ctx, call, p)
	case "comment":
		return c.comment(ctx, call, p)

	case "delete_comment":
		if err := need(p.Comment, "comment"); err != nil {
			return sdk.Result{}, err
		}
		path, err := c.items(ctx, p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := c.do(ctx, http.MethodDelete, path+p.Issue+"/comments/"+p.Comment+"/", nil, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no comment %s on that work item", p.Comment)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Comment})

	case "delete_issue":
		cp, i, path, err := c.issue(ctx, p.Project, p.Issue)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete work item %q", i.Name),
				Changes: []sdk.Change{{Target: target(cp, i), Op: "delete", Before: mustJSON(cp.summary(i))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, path+i.ID+"/", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": i.ID, "name": i.Name})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func target(cp ctxProject, i issue) string {
	return fmt.Sprintf("work item %s-%d %q in %s", cp.p.Identifier, i.SequenceID, i.Name, cp.p.Name)
}

func (c *conn) project(ctx context.Context, id string) (ctxProject, error) {
	var cp ctxProject
	if err := c.do(ctx, http.MethodGet, c.ws+"/projects/"+id+"/", nil, nil, &cp.p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return cp, fmt.Errorf("there's no project %s in this workspace", id)
		}
		return cp, err
	}
	ss, _, err := list[state](ctx, c, c.ws+"/projects/"+id+"/states/", nil)
	if err != nil {
		return cp, err
	}
	cp.states, cp.order = map[string]state{}, ss
	for _, s := range ss {
		cp.states[s.ID] = s
	}
	return cp, nil
}

// stateID finds a state by name.
func (cp ctxProject) stateID(name string) (string, error) {
	var names []string
	for _, s := range cp.order {
		if strings.EqualFold(s.Name, name) {
			return s.ID, nil
		}
		names = append(names, s.Name)
	}
	return "", fmt.Errorf("%s has no state %q; it has: %s", cp.p.Name, name, strings.Join(names, ", "))
}

func (c *conn) issue(ctx context.Context, project, id string) (ctxProject, issue, string, error) {
	var i issue
	cp, err := c.project(ctx, project)
	if err != nil {
		return cp, i, "", err
	}
	path, err := c.items(ctx, project)
	if err != nil {
		return cp, i, "", err
	}
	if err := c.do(ctx, http.MethodGet, path+id+"/", nil, nil, &i); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return cp, i, "", fmt.Errorf("there's no work item %s in %s", id, cp.p.Name)
		}
		return cp, i, "", err
	}
	if !strings.EqualFold(i.ID, id) {
		// The id goes into the change's path and its undo.
		return cp, i, "", fmt.Errorf("Plane answered with another work item for %s", id)
	}
	return cp, i, path, nil
}

// body turns checked fields into Plane's: the description as HTML and the
// state as its id.
func (cp ctxProject) body(b map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range b {
		switch k {
		case "description":
			out["description_html"] = paragraphs(v.(string))
		case "state":
			id, err := cp.stateID(v.(string))
			if err != nil {
				return nil, err
			}
			out["state"] = id
		default:
			out[k] = v
		}
	}
	return out, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Name == nil {
		return sdk.Result{}, errors.New("the work item needs a name")
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	cp, err := c.project(ctx, p.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	send, err := cp.body(b)
	if err != nil {
		return sdk.Result{}, err
	}
	path, err := c.items(ctx, p.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create work item %q in %s", b["name"], cp.p.Name),
			Changes: []sdk.Change{{Target: "work item in " + cp.p.Name, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var i issue
	if err := c.do(ctx, http.MethodPost, path, nil, send, &i); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(cp.summary(i))
	if uuidRe.MatchString(i.ID) {
		res.Undo = sdk.UndoWith("delete_issue", map[string]string{"project": p.Project, "issue": i.ID}, fmt.Sprintf("Delete work item %q", i.Name))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	if len(b) == 0 {
		return sdk.Result{}, errors.New("say what to change: name, description, state, priority or due")
	}
	cp, i, path, err := c.issue(ctx, p.Project, p.Issue)
	if err != nil {
		return sdk.Result{}, err
	}
	stateName := cp.states[i.State].Name
	before, after, back, changed := map[string]any{}, map[string]any{}, map[string]any{"project": p.Project, "issue": i.ID}, map[string]any{}
	for k, v := range b {
		s, _ := v.(string)
		switch k {
		case "name":
			if s != i.Name {
				before[k], after[k], back[k], changed[k] = i.Name, s, i.Name, s
			}
		case "description":
			if s != strings.TrimSpace(i.Description) {
				before[k], after[k], back[k], changed[k] = i.Description, s, i.Description, s
			}
		case "state":
			if !strings.EqualFold(s, stateName) {
				before[k], after[k], back[k], changed[k] = stateName, s, stateName, s
			}
		case "priority":
			if s != i.Priority {
				before[k], after[k], back[k], changed[k] = i.Priority, s, i.Priority, s
			}
		case "target_date":
			if s != str(i.TargetDate) {
				before["due"], after["due"], back["due"], changed[k] = str(i.TargetDate), s, str(i.TargetDate), v
			}
		}
	}
	if len(changed) == 0 {
		return sdk.JSON(map[string]any{"issue": i.ID, "name": i.Name, "note": "nothing to change"})
	}
	send, err := cp.body(changed)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Update work item %q", i.Name),
			Changes: []sdk.Change{{Target: target(cp, i), Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var out issue
	if err := c.do(ctx, http.MethodPatch, path+i.ID+"/", nil, send, &out); err != nil {
		return sdk.Result{}, err
	}
	if out.ID == "" {
		out = i
	}
	res, err := sdk.JSON(cp.summary(out))
	res.Undo = sdk.UndoWith("update_issue", back, fmt.Sprintf("Restore work item %q", i.Name))
	return res, err
}

func (c *conn) comment(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	text := strings.TrimSpace(p.Text)
	if text == "" || len(text) > maxComment {
		return sdk.Result{}, fmt.Errorf("a comment is 1 to %d characters", maxComment)
	}
	if f := mention.Find(text); f.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", f.Wildcard)
	}
	cp, i, path, err := c.issue(ctx, p.Project, p.Issue)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Comment on work item %q", i.Name),
			Changes: []sdk.Change{{Target: target(cp, i), Op: "create", After: mustJSON(map[string]string{"text": text})}}}}, nil
	}
	// Escaped, so the comment can't carry markup or mention tags.
	var r struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, path+i.ID+"/comments/", nil, map[string]any{"comment_html": paragraphs(text)}, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"issue": i.ID, "comment": r.ID})
	if uuidRe.MatchString(r.ID) {
		res.Undo = sdk.UndoWith("delete_comment", map[string]string{"project": p.Project, "issue": i.ID, "comment": r.ID}, "Delete the comment")
	}
	return res, err
}
