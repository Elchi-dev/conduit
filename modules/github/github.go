// Package github manages GitHub (or GitHub Enterprise): repositories, pull
// requests, issues and Actions runs.
package github

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GitHub account's settings.
type Config struct {
	Token string `json:"token"` // secret:// fine-grained or classic token
	API   string `json:"api"`   // default https://api.github.com
	// Repos are the repositories to watch by default (owner/name).
	Repos []string `json:"repos"`
}

type account struct {
	cfg Config
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[account]
	// HTTP overrides the client (tests).
	HTTP *http.Client
}

// New returns the GitHub module.
func New() *Module { return &Module{} }

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

const repoProp = `"repo":{"type":"string","description":"owner/name; defaults to your watched repositories"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "github", Name: "GitHub", Version: "0.1.0", Category: "Development", Icon: "git",
		Description: "Repositories, pull requests, issues and Actions runs on GitHub or GitHub Enterprise.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A fine-grained token with read access (add write for issues, comments, re-runs and merges)"},
			"api":{"type":"string","description":"API URL for GitHub Enterprise, e.g. https://github.example.com/api/v3"},
			"repos":{"type":"array","items":{"type":"string"},"description":"Repositories to watch, as owner/name"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repos", Title: "Repositories", Description: "Your repositories, most recently pushed first.", Risk: sdk.RiskRead},
			{Name: "pull_requests", Title: "Pull requests", Description: "Open pull requests in a repository, or everywhere you're involved.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + repoProp + `}}`)},
			{Name: "issues", Title: "Issues", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + repoProp + `,"state":{"type":"string","enum":["open","closed","all"],"default":"open"}}}`)},
			{Name: "runs", Title: "Actions runs", Description: "Recent workflow runs and how they ended.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + repoProp + `,"failedOnly":{"type":"boolean","title":"Only failed runs"}}}`)},
			{Name: "rerun", Title: "Re-run failed jobs", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["repo","runId"],"properties":{"repo":{"type":"string"},"runId":{"type":"integer"}}}`)},
			{Name: "create_issue", Title: "Open an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","title"],"properties":{"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string","format":"textarea"},"labels":{"type":"array","items":{"type":"string"}}}}`)},
			{Name: "close_issue", Title: "Close an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{"repo":{"type":"string"},"number":{"type":"integer"}}}`)},
			{Name: "reopen_issue", Title: "Reopen an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{"repo":{"type":"string"},"number":{"type":"integer"}}}`)},
			{Name: "comment", Title: "Comment", Description: "Comment on an issue or pull request.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number","body"],"properties":{"repo":{"type":"string"},"number":{"type":"integer"},"body":{"type":"string","format":"textarea"}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["repo","commentId"],"properties":{"repo":{"type":"string"},"commentId":{"type":"integer"}}}`)},
			{Name: "merge", Title: "Merge a pull request", Description: "Merges if GitHub says it can be merged.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{"repo":{"type":"string"},"number":{"type":"integer"},"method":{"type":"string","enum":["merge","squash","rebase"],"default":"squash"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "pull_request", Title: "Pull requests", ListAction: "pull_requests", ViewHint: "table"}},
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
	if c.API == "" {
		c.API = "https://api.github.com"
	}
	if err := rest.ValidBase(c.API); err != nil {
		return err
	}
	for _, r := range c.Repos {
		if !repoRe.MatchString(r) {
			return fmt.Errorf("%q isn't owner/name", r)
		}
	}
	tok := c.Token
	api := rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	api.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	api.Header.Set("Accept", "application/vnd.github+json")
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
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
		Login string `json:"login"`
	}
	hd, err := a.api.Do(ctx, "GET", "/user", nil, nil, &u)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Signed in as " + u.Login
	if left, _ := strconv.Atoi(hd.Get("X-RateLimit-Remaining")); hd.Get("X-RateLimit-Remaining") != "" && left < 100 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%s; only %d API calls left this hour", msg, left)}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Repo is a repository row.
type Repo struct {
	Name     string `json:"name"`
	Private  bool   `json:"private"`
	Stars    int    `json:"stars"`
	Issues   int    `json:"openIssues"`
	Language string `json:"language,omitempty"`
	Pushed   string `json:"pushed"`
	URL      string `json:"url"`
}

// PR is a pull request row.
type PR struct {
	Repo    string `json:"repo"`
	Number  int    `json:"number"`
	Title   string `json:"title"`
	Author  string `json:"author"`
	Draft   bool   `json:"draft"`
	Updated string `json:"updated"`
	URL     string `json:"url"`
}

// Issue is an issue row.
type Issue struct {
	Repo    string `json:"repo"`
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Author  string `json:"author"`
	Labels  string `json:"labels,omitempty"`
	Updated string `json:"updated"`
	URL     string `json:"url"`
}

// Run is a workflow run row.
type Run struct {
	Repo       string `json:"repo"`
	ID         int64  `json:"id"`
	Workflow   string `json:"workflow"`
	Branch     string `json:"branch"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
	Started    string `json:"started"`
	URL        string `json:"url"`
}

type user struct {
	Login string `json:"login"`
}

type ghIssue struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	State       string    `json:"state"`
	User        user      `json:"user"`
	UpdatedAt   string    `json:"updated_at"`
	HTMLURL     string    `json:"html_url"`
	RepoURL     string    `json:"repository_url"`
	Draft       bool      `json:"draft"`
	PullRequest *struct{} `json:"pull_request"`
	Labels      []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

func repoFromURL(u string) string {
	i := strings.Index(u, "/repos/")
	if i < 0 {
		return ""
	}
	return u[i+len("/repos/"):]
}

type in struct {
	Repo       string   `json:"repo"`
	State      string   `json:"state"`
	FailedOnly bool     `json:"failedOnly"`
	RunID      int64    `json:"runId"`
	Number     int      `json:"number"`
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Labels     []string `json:"labels"`
	CommentID  int64    `json:"commentId"`
	Method     string   `json:"method"`
}

func (a *account) repos(r string) ([]string, error) {
	if r != "" {
		if !repoRe.MatchString(r) {
			return nil, fmt.Errorf("%q isn't owner/name", r)
		}
		return []string{r}, nil
	}
	if len(a.cfg.Repos) == 0 {
		return nil, errors.New("name a repository, or add repositories to watch in this account's settings")
	}
	return a.cfg.Repos, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.set.Get(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p in
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "repos":
		var rs []struct {
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
			Stars    int    `json:"stargazers_count"`
			Issues   int    `json:"open_issues_count"`
			Language string `json:"language"`
			PushedAt string `json:"pushed_at"`
			HTMLURL  string `json:"html_url"`
		}
		if _, err := a.api.Do(ctx, "GET", "/user/repos", url.Values{"sort": {"pushed"}, "per_page": {"50"}}, nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := []Repo{}
		for _, r := range rs {
			out = append(out, Repo{Name: r.FullName, Private: r.Private, Stars: r.Stars, Issues: r.Issues, Language: r.Language, Pushed: r.PushedAt, URL: r.HTMLURL})
		}
		return sdk.JSON(out)

	case "pull_requests":
		var items []ghIssue
		if p.Repo == "" && len(a.cfg.Repos) == 0 {
			var s struct {
				Items []ghIssue `json:"items"`
			}
			if _, err := a.api.Do(ctx, "GET", "/search/issues", url.Values{"q": {"is:pr is:open involves:@me archived:false"}, "per_page": {"50"}}, nil, &s); err != nil {
				return sdk.Result{}, err
			}
			items = s.Items
		} else {
			repos, err := a.repos(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, r := range repos {
				var prs []struct {
					ghIssue
					Head struct {
						Repo struct {
							FullName string `json:"full_name"`
						} `json:"repo"`
					} `json:"head"`
				}
				if _, err := a.api.Do(ctx, "GET", "/repos/"+r+"/pulls", url.Values{"state": {"open"}, "per_page": {"50"}}, nil, &prs); err != nil {
					return sdk.Result{}, fmt.Errorf("%s: %w", r, err)
				}
				for _, pr := range prs {
					pr.ghIssue.RepoURL = "/repos/" + r
					items = append(items, pr.ghIssue)
				}
			}
		}
		out := []PR{}
		for _, i := range items {
			out = append(out, PR{Repo: repoFromURL(i.RepoURL), Number: i.Number, Title: i.Title, Author: i.User.Login, Draft: i.Draft, Updated: i.UpdatedAt, URL: i.HTMLURL})
		}
		return sdk.JSON(out)

	case "issues":
		repos, err := a.repos(p.Repo)
		if err != nil {
			return sdk.Result{}, err
		}
		state := p.State
		if state == "" {
			state = "open"
		}
		out := []Issue{}
		for _, r := range repos {
			var is []ghIssue
			if _, err := a.api.Do(ctx, "GET", "/repos/"+r+"/issues", url.Values{"state": {state}, "per_page": {"50"}}, nil, &is); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", r, err)
			}
			for _, i := range is {
				if i.PullRequest != nil {
					continue // the issues API also lists pull requests
				}
				var lbl []string
				for _, l := range i.Labels {
					lbl = append(lbl, l.Name)
				}
				out = append(out, Issue{Repo: r, Number: i.Number, Title: i.Title, State: i.State, Author: i.User.Login, Labels: strings.Join(lbl, ", "), Updated: i.UpdatedAt, URL: i.HTMLURL})
			}
		}
		return sdk.JSON(out)

	case "runs":
		repos, err := a.repos(p.Repo)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []Run{}
		for _, r := range repos {
			var d struct {
				Runs []struct {
					ID         int64  `json:"id"`
					Name       string `json:"name"`
					HeadBranch string `json:"head_branch"`
					Event      string `json:"event"`
					Status     string `json:"status"`
					Conclusion string `json:"conclusion"`
					RunStarted string `json:"run_started_at"`
					HTMLURL    string `json:"html_url"`
				} `json:"workflow_runs"`
			}
			q := url.Values{"per_page": {"20"}}
			if p.FailedOnly {
				q.Set("status", "failure")
			}
			if _, err := a.api.Do(ctx, "GET", "/repos/"+r+"/actions/runs", q, nil, &d); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", r, err)
			}
			for _, x := range d.Runs {
				out = append(out, Run{Repo: r, ID: x.ID, Workflow: x.Name, Branch: x.HeadBranch, Event: x.Event, Status: x.Status, Conclusion: x.Conclusion, Started: x.RunStarted, URL: x.HTMLURL})
			}
		}
		return sdk.JSON(out)

	case "rerun":
		if !repoRe.MatchString(p.Repo) || p.RunID == 0 {
			return sdk.Result{}, errors.New("repo and runId are required")
		}
		if _, err := a.api.Do(ctx, "POST", fmt.Sprintf("/repos/%s/actions/runs/%d/rerun-failed-jobs", p.Repo, p.RunID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"rerun": p.RunID})

	case "create_issue":
		if !repoRe.MatchString(p.Repo) || strings.TrimSpace(p.Title) == "" {
			return sdk.Result{}, errors.New("repo and title are required")
		}
		body := map[string]any{"title": p.Title, "body": p.Body}
		if len(p.Labels) > 0 {
			body["labels"] = p.Labels
		}
		var i ghIssue
		if _, err := a.api.Do(ctx, "POST", "/repos/"+p.Repo+"/issues", nil, body, &i); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(Issue{Repo: p.Repo, Number: i.Number, Title: i.Title, State: i.State, URL: i.HTMLURL})
		r.Undo = sdk.UndoWith("close_issue", map[string]any{"repo": p.Repo, "number": i.Number}, fmt.Sprintf("Close issue #%d", i.Number))
		return r, nil

	case "close_issue", "reopen_issue":
		if !repoRe.MatchString(p.Repo) || p.Number == 0 {
			return sdk.Result{}, errors.New("repo and number are required")
		}
		state, undo, verb := "closed", "reopen_issue", "Reopen"
		if c.Action == "reopen_issue" {
			state, undo, verb = "open", "close_issue", "Close"
		}
		var i ghIssue
		if _, err := a.api.Do(ctx, "PATCH", fmt.Sprintf("/repos/%s/issues/%d", p.Repo, p.Number), nil, map[string]string{"state": state}, &i); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(Issue{Repo: p.Repo, Number: i.Number, Title: i.Title, State: i.State, URL: i.HTMLURL})
		r.Undo = sdk.UndoWith(undo, map[string]any{"repo": p.Repo, "number": p.Number}, fmt.Sprintf("%s #%d", verb, p.Number))
		return r, nil

	case "comment":
		if !repoRe.MatchString(p.Repo) || p.Number == 0 || strings.TrimSpace(p.Body) == "" {
			return sdk.Result{}, errors.New("repo, number and body are required")
		}
		var cm struct {
			ID      int64  `json:"id"`
			HTMLURL string `json:"html_url"`
		}
		if _, err := a.api.Do(ctx, "POST", fmt.Sprintf("/repos/%s/issues/%d/comments", p.Repo, p.Number), nil, map[string]string{"body": p.Body}, &cm); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"commentId": cm.ID, "url": cm.HTMLURL})
		r.Undo = sdk.UndoWith("delete_comment", map[string]any{"repo": p.Repo, "commentId": cm.ID}, "Delete the comment")
		return r, nil

	case "delete_comment":
		if !repoRe.MatchString(p.Repo) || p.CommentID == 0 {
			return sdk.Result{}, errors.New("repo and commentId are required")
		}
		if _, err := a.api.Do(ctx, "DELETE", fmt.Sprintf("/repos/%s/issues/comments/%d", p.Repo, p.CommentID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.CommentID})

	case "merge":
		if !repoRe.MatchString(p.Repo) || p.Number == 0 {
			return sdk.Result{}, errors.New("repo and number are required")
		}
		method := p.Method
		if method == "" {
			method = "squash"
		}
		var pr struct {
			Title          string `json:"title"`
			State          string `json:"state"`
			Mergeable      *bool  `json:"mergeable"`
			MergeableState string `json:"mergeable_state"`
			Base           struct {
				Ref string `json:"ref"`
			} `json:"base"`
			Head struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			} `json:"head"`
			Commits int `json:"commits"`
		}
		if _, err := a.api.Do(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d", p.Repo, p.Number), nil, nil, &pr); err != nil {
			return sdk.Result{}, err
		}
		if pr.State != "open" {
			return sdk.Result{}, fmt.Errorf("#%d is %s", p.Number, pr.State)
		}
		if c.DryRun {
			before, _ := json.Marshal(map[string]any{"branch": pr.Head.Ref, "commits": pr.Commits, "checks": pr.MergeableState})
			after, _ := json.Marshal(map[string]any{"into": pr.Base.Ref, "method": method})
			return sdk.Result{Plan: &sdk.Plan{
				Summary: fmt.Sprintf("%s-merge #%d \"%s\" into %s", method, p.Number, pr.Title, pr.Base.Ref),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s#%d", p.Repo, p.Number), Op: "merge", Before: before, After: after}},
			}}, nil
		}
		if pr.Mergeable != nil && !*pr.Mergeable {
			return sdk.Result{}, fmt.Errorf("GitHub says #%d can't be merged (%s)", p.Number, pr.MergeableState)
		}
		var res struct {
			SHA    string `json:"sha"`
			Merged bool   `json:"merged"`
		}
		// Pin the head commit, so a push after the approval isn't merged unseen.
		if _, err := a.api.Do(ctx, "PUT", fmt.Sprintf("/repos/%s/pulls/%d/merge", p.Repo, p.Number), nil, map[string]string{"merge_method": method, "sha": pr.Head.SHA}, &res); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"merged": res.Merged, "sha": res.SHA})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
