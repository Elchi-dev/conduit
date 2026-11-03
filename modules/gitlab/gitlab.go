// Package gitlab manages GitLab (gitlab.com or self-managed): projects,
// merge requests, issues and pipelines.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GitLab account's settings.
type Config struct {
	Token    string   `json:"token"` // secret:// personal access token
	URL      string   `json:"url"`   // default https://gitlab.com
	Projects []string `json:"projects"`
}

type account struct {
	cfg Config
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[account]
	HTTP *http.Client
}

// New returns the GitLab module.
func New() *Module { return &Module{} }

const projProp = `"project":{"type":"string","description":"group/project; defaults to your watched projects"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "gitlab", Name: "GitLab", Version: "0.1.0", Category: "Development", Icon: "git",
		Description: "Projects, merge requests, issues and pipelines on gitlab.com or your own GitLab.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"Personal access token with read_api (api for writes)"},
			"url":{"type":"string","description":"Your GitLab's address; default https://gitlab.com"},
			"projects":{"type":"array","items":{"type":"string"},"description":"Projects to watch, as group/project"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects you're a member of, most recently active first.", Risk: sdk.RiskRead},
			{Name: "merge_requests", Title: "Merge requests", Description: "Open merge requests in a project, or assigned to you.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + projProp + `}}`)},
			{Name: "issues", Title: "Issues", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","properties":{` + projProp + `}}`)},
			{Name: "pipelines", Title: "Pipelines", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + projProp + `,"failedOnly":{"type":"boolean","title":"Only failed pipelines"}}}`)},
			{Name: "retry_pipeline", Title: "Retry a pipeline", Description: "Retries its failed jobs.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["project","pipelineId"],"properties":{"project":{"type":"string"},"pipelineId":{"type":"integer"}}}`)},
			{Name: "create_issue", Title: "Open an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["project","title"],"properties":{"project":{"type":"string"},"title":{"type":"string"},"description":{"type":"string","format":"textarea"}}}`)},
			{Name: "close_issue", Title: "Close an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["project","iid"],"properties":{"project":{"type":"string"},"iid":{"type":"integer"}}}`)},
			{Name: "reopen_issue", Title: "Reopen an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["project","iid"],"properties":{"project":{"type":"string"},"iid":{"type":"integer"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Token == "" {
		return errors.New("add a token (stored in the vault)")
	}
	if c.URL == "" {
		c.URL = "https://gitlab.com"
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if err := rest.ValidBase(c.URL); err != nil {
		return err
	}
	tok := c.Token
	api := rest.New(c.URL+"/api/v4", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("PRIVATE-TOKEN", t)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	// The token travels in PRIVATE-TOKEN, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &account{cfg: c, api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	a, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Username string `json:"username"`
	}
	if _, err := a.api.Do(ctx, "GET", "/user", nil, nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + u.Username}
}

// Item is a merge request or issue row.
type Item struct {
	Project string `json:"project"`
	IID     int    `json:"iid"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Author  string `json:"author"`
	Updated string `json:"updated"`
	URL     string `json:"url"`
}

// Pipeline is a pipeline row.
type Pipeline struct {
	Project string `json:"project"`
	ID      int64  `json:"id"`
	Ref     string `json:"ref"`
	Status  string `json:"status"`
	Source  string `json:"source"`
	Created string `json:"created"`
	URL     string `json:"url"`
}

type glItem struct {
	IID       int    `json:"iid"`
	Title     string `json:"title"`
	State     string `json:"state"`
	UpdatedAt string `json:"updated_at"`
	WebURL    string `json:"web_url"`
	Author    struct {
		Username string `json:"username"`
	} `json:"author"`
	References struct {
		Full string `json:"full"`
	} `json:"references"`
}

func row(project string, i glItem) Item {
	if project == "" {
		project = i.References.Full
		if k := strings.LastIndexAny(project, "!#"); k > 0 {
			project = project[:k]
		}
	}
	return Item{Project: project, IID: i.IID, Title: i.Title, State: i.State, Author: i.Author.Username, Updated: i.UpdatedAt, URL: i.WebURL}
}

func (a *account) projects(p string) ([]string, error) {
	if p != "" {
		return []string{p}, nil
	}
	if len(a.cfg.Projects) == 0 {
		return nil, errors.New("name a project, or add projects to watch in this account's settings")
	}
	return a.cfg.Projects, nil
}

func pid(p string) string { return url.PathEscape(p) }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.set.Get(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project     string `json:"project"`
		FailedOnly  bool   `json:"failedOnly"`
		PipelineID  int64  `json:"pipelineId"`
		Title       string `json:"title"`
		Description string `json:"description"`
		IID         int    `json:"iid"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "projects":
		var ps []struct {
			Path         string `json:"path_with_namespace"`
			Visibility   string `json:"visibility"`
			Stars        int    `json:"star_count"`
			OpenIssues   int    `json:"open_issues_count"`
			LastActivity string `json:"last_activity_at"`
			WebURL       string `json:"web_url"`
		}
		if _, err := a.api.Do(ctx, "GET", "/projects", url.Values{"membership": {"true"}, "order_by": {"last_activity_at"}, "per_page": {"50"}}, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ps)

	case "merge_requests", "issues":
		kind := c.Action
		out := []Item{}
		if p.Project == "" && len(a.cfg.Projects) == 0 {
			var is []glItem
			if _, err := a.api.Do(ctx, "GET", "/"+kind, url.Values{"state": {"opened"}, "scope": {"assigned_to_me"}, "per_page": {"50"}}, nil, &is); err != nil {
				return sdk.Result{}, err
			}
			for _, i := range is {
				out = append(out, row("", i))
			}
			return sdk.JSON(out)
		}
		ps, _ := a.projects(p.Project)
		for _, pr := range ps {
			var is []glItem
			if _, err := a.api.Do(ctx, "GET", "/projects/"+pid(pr)+"/"+kind, url.Values{"state": {"opened"}, "per_page": {"50"}}, nil, &is); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", pr, err)
			}
			for _, i := range is {
				out = append(out, row(pr, i))
			}
		}
		return sdk.JSON(out)

	case "pipelines":
		ps, err := a.projects(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []Pipeline{}
		for _, pr := range ps {
			var ls []struct {
				ID        int64  `json:"id"`
				Ref       string `json:"ref"`
				Status    string `json:"status"`
				Source    string `json:"source"`
				CreatedAt string `json:"created_at"`
				WebURL    string `json:"web_url"`
			}
			q := url.Values{"per_page": {"20"}}
			if p.FailedOnly {
				q.Set("status", "failed")
			}
			if _, err := a.api.Do(ctx, "GET", "/projects/"+pid(pr)+"/pipelines", q, nil, &ls); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", pr, err)
			}
			for _, l := range ls {
				out = append(out, Pipeline{Project: pr, ID: l.ID, Ref: l.Ref, Status: l.Status, Source: l.Source, Created: l.CreatedAt, URL: l.WebURL})
			}
		}
		return sdk.JSON(out)

	case "retry_pipeline":
		if p.Project == "" || p.PipelineID == 0 {
			return sdk.Result{}, errors.New("project and pipelineId are required")
		}
		var r struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
		if _, err := a.api.Do(ctx, "POST", fmt.Sprintf("/projects/%s/pipelines/%d/retry", pid(p.Project), p.PipelineID), nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(r)

	case "create_issue":
		if p.Project == "" || strings.TrimSpace(p.Title) == "" {
			return sdk.Result{}, errors.New("project and title are required")
		}
		var i glItem
		if _, err := a.api.Do(ctx, "POST", "/projects/"+pid(p.Project)+"/issues", nil, map[string]string{"title": p.Title, "description": p.Description}, &i); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(row(p.Project, i))
		r.Undo = sdk.UndoWith("close_issue", map[string]any{"project": p.Project, "iid": i.IID}, fmt.Sprintf("Close issue #%d", i.IID))
		return r, nil

	case "close_issue", "reopen_issue":
		if p.Project == "" || p.IID == 0 {
			return sdk.Result{}, errors.New("project and iid are required")
		}
		ev, undo, verb := "close", "reopen_issue", "Reopen"
		if c.Action == "reopen_issue" {
			ev, undo, verb = "reopen", "close_issue", "Close"
		}
		var i glItem
		if _, err := a.api.Do(ctx, "PUT", fmt.Sprintf("/projects/%s/issues/%d", pid(p.Project), p.IID), nil, map[string]string{"state_event": ev}, &i); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(row(p.Project, i))
		r.Undo = sdk.UndoWith(undo, map[string]any{"project": p.Project, "iid": p.IID}, fmt.Sprintf("%s #%d", verb, p.IID))
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
