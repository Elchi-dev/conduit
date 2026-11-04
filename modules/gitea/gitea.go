// Package gitea works with a Gitea or Forgejo server (API v1): repositories,
// pull requests, issues and Actions runs (with jobs and logs); it can open
// and close issues, comment, merge, start workflows and rerun runs.
package gitea

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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Gitea or Forgejo server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://git.example.com or https://codeberg.org
	Token string `json:"token"` // secret:// access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Gitea/Forgejo module.
func New() *Module { return &Module{} }

// Owner and repository names: Gitea allows letters, digits, - _ and . (not
// a name made of dots only).
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func validRepo(s string) (string, string, error) {
	o, r, ok := strings.Cut(s, "/")
	if !ok || !nameRe.MatchString(o) || !nameRe.MatchString(r) || strings.Trim(o, ".") == "" || strings.Trim(r, ".") == "" {
		return "", "", errors.New("the repository is owner/name, e.g. elchi/conduit")
	}
	return o, r, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"owner/name"}`
	num := `"number":{"type":"integer","minimum":1}`
	return sdk.Manifest{
		ID: "gitea", Name: "Gitea / Forgejo", Version: "0.1.0", Category: "Development", Icon: "git",
		Description: "Repositories, pull requests, issues and Actions runs, jobs and logs on a Gitea or Forgejo server (including Codeberg).",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://git.example.com"},
			"token":{"type":"string","x-secret":true,"description":"Access token (Settings, Applications) with repository and issue scopes"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repos", Title: "Repositories", Description: "Repositories the token's user can see.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"maximum":50}}}`)},
			{Name: "pulls", Title: "Open pull requests", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `}}`)},
			{Name: "issues", Title: "Open issues", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `}}`)},
			{Name: "runs", Title: "Actions runs", Description: "Recent workflow runs (Gitea 1.23+ / Forgejo).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"limit":{"type":"integer","default":20,"maximum":50}}}`)},
			{Name: "run", Title: "Actions run", Description: "One run with its jobs and steps (Gitea 1.23+; Forgejo shows the run without jobs where it lacks the API).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo","id"],"properties":{` + repo + `,"id":{"type":"integer","minimum":1,"description":"Run id (from runs)"}}}`)},
			{Name: "job_log", Title: "Actions job log", Description: "The end of one job's log (up to 2000 lines; Gitea 1.23+). Logs can hold sensitive output, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","job"],"properties":{` + repo + `,"job":{"type":"integer","minimum":1,"description":"Job id (from run)"},"lines":{"type":"integer","default":200,"maximum":2000}}}`)},
			{Name: "rerun", Title: "Rerun an Actions run", Description: "Runs the workflow again (its code runs with the repository's secrets); failedOnly reruns just the failed jobs. Needs Gitea 1.27+.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","id"],"properties":{` + repo + `,"id":{"type":"integer","minimum":1},"failedOnly":{"type":"boolean","default":false}}}`)},
			{Name: "dispatch_workflow", Title: "Start a workflow", Description: "Triggers a workflow with workflow_dispatch on a branch or tag (its code runs with the repository's secrets).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","workflow","ref"],"properties":{` + repo + `,"workflow":{"type":"string","description":"Workflow file name, e.g. deploy.yml"},"ref":{"type":"string","description":"Branch or tag"},"inputs":{"type":"object","additionalProperties":{"type":"string"}}}}`)},
			{Name: "create_issue", Title: "Open an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","title"],"properties":{` + repo + `,"title":{"type":"string"},"body":{"type":"string"}}}`)},
			{Name: "close_issue", Title: "Close an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "reopen_issue", Title: "Reopen an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "comment", Title: "Comment", Description: "Comments on an issue or pull request.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number","body"],"properties":{` + repo + `,` + num + `,"body":{"type":"string"}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","id"],"properties":{` + repo + `,"id":{"type":"integer","minimum":1}}}`)},
			{Name: "merge", Title: "Merge a pull request", Description: "Merges into the base branch. Can't be undone from here.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `,"method":{"type":"string","enum":["merge","squash","rebase"],"default":"merge"},"deleteBranch":{"type":"boolean","default":false}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return errors.New("the address is like https://git.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1") + "/api/v1"
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "token "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		// Through the instance's network, when it has one (a Forgejo
		// server inside a WireGuard network).
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
		Login string `json:"login"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "the server refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	_, _ = c.api.Do(ctx, http.MethodGet, "/version", nil, nil, &v)
	msg := "signed in as " + u.Login
	if v.Version != "" {
		msg += " · " + v.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type user struct {
	Login string `json:"login"`
}

type issue struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	State     string `json:"state"`
	HTMLURL   string `json:"html_url"`
	User      user   `json:"user"`
	Comments  int    `json:"comments"`
	UpdatedAt string `json:"updated_at"`
	Labels    []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Merged    bool `json:"merged"`
	Mergeable bool `json:"mergeable"`
	Base      *struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Head *struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

func summarize(is issue) map[string]any {
	labels := []string{}
	for _, l := range is.Labels {
		labels = append(labels, l.Name)
	}
	out := map[string]any{"number": is.Number, "title": is.Title, "author": is.User.Login, "url": is.HTMLURL, "comments": is.Comments, "updated": is.UpdatedAt, "labels": labels}
	if is.Base != nil && is.Head != nil {
		out["base"], out["head"], out["mergeable"] = is.Base.Ref, is.Head.Ref, is.Mergeable
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Repo         string            `json:"repo"`
		Number       int               `json:"number"`
		ID           int64             `json:"id"`
		Title        string            `json:"title"`
		Body         string            `json:"body"`
		Limit        int               `json:"limit"`
		Method       string            `json:"method"`
		DeleteBranch bool              `json:"deleteBranch"`
		Job          int64             `json:"job"`
		Lines        int               `json:"lines"`
		FailedOnly   bool              `json:"failedOnly"`
		Workflow     string            `json:"workflow"`
		Ref          string            `json:"ref"`
		Inputs       map[string]string `json:"inputs"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "repos" {
		limit := p.Limit
		if limit <= 0 || limit > 50 {
			limit = 50
		}
		var rs []struct {
			FullName      string `json:"full_name"`
			Description   string `json:"description"`
			Private       bool   `json:"private"`
			Fork          bool   `json:"fork"`
			Archived      bool   `json:"archived"`
			Stars         int    `json:"stars_count"`
			OpenIssues    int    `json:"open_issues_count"`
			OpenPRs       int    `json:"open_pr_counter"`
			DefaultBranch string `json:"default_branch"`
			HTMLURL       string `json:"html_url"`
			UpdatedAt     string `json:"updated_at"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/user/repos", url.Values{"limit": {strconv.Itoa(limit)}}, nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(rs)
	}
	owner, name, err := validRepo(p.Repo)
	if err != nil {
		return sdk.Result{}, err
	}
	rp := "/repos/" + owner + "/" + name
	needNumber := func() error {
		if p.Number <= 0 {
			return errors.New("enter the issue or pull request number")
		}
		return nil
	}
	switch call.Action {
	case "pulls", "issues":
		q := url.Values{"state": {"open"}, "limit": {"50"}}
		path := rp + "/pulls"
		if call.Action == "issues" {
			path = rp + "/issues"
			q.Set("type", "issues")
		}
		var list []issue
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, is := range list {
			out = append(out, summarize(is))
		}
		return sdk.JSON(out)

	case "runs":
		limit := p.Limit
		if limit <= 0 || limit > 50 {
			limit = 20
		}
		var r struct {
			Runs []struct {
				ID         int64  `json:"id"`
				Title      string `json:"display_title"`
				Workflow   string `json:"path"`
				Event      string `json:"event"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
				Branch     string `json:"head_branch"`
				HTMLURL    string `json:"html_url"`
				Started    string `json:"started_at"`
			} `json:"workflow_runs"`
			Total int `json:"total_count"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/actions/runs", url.Values{"limit": {strconv.Itoa(limit)}}, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("this server doesn't list Actions runs (needs Gitea 1.23 or a recent Forgejo, and Actions on for the repository)")
			}
			return sdk.Result{}, err
		}
		if len(r.Runs) > limit {
			r.Runs = r.Runs[:limit]
		}
		for i := range r.Runs {
			r.Runs[i].Title = rest.Redact(r.Runs[i].Title) // a push's commit message
		}
		return sdk.JSON(r)

	case "run", "job_log", "rerun", "dispatch_workflow":
		return c.actions(ctx, call, p.Repo, rp, actionsInput{ID: p.ID, Job: p.Job, Lines: p.Lines, FailedOnly: p.FailedOnly, Workflow: p.Workflow, Ref: p.Ref, Inputs: p.Inputs})

	case "create_issue":
		title := strings.TrimSpace(p.Title)
		if title == "" || len(title) > 255 {
			return sdk.Result{}, errors.New("the title is 1 to 255 characters")
		}
		var is issue
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/issues", nil, map[string]any{"title": title, "body": p.Body}, &is); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"number": is.Number, "url": is.HTMLURL})
		res.Undo = sdk.UndoWith("close_issue", map[string]any{"repo": p.Repo, "number": is.Number}, fmt.Sprintf("Close issue #%d", is.Number))
		return res, err

	case "close_issue", "reopen_issue":
		if err := needNumber(); err != nil {
			return sdk.Result{}, err
		}
		state, back, verb := "closed", "reopen_issue", "Reopen"
		if call.Action == "reopen_issue" {
			state, back, verb = "open", "close_issue", "Close"
		}
		var is issue
		if _, err := c.api.Do(ctx, http.MethodPatch, rp+"/issues/"+strconv.Itoa(p.Number), nil, map[string]any{"state": state}, &is); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"number": is.Number, "state": is.State, "url": is.HTMLURL})
		res.Undo = sdk.UndoWith(back, map[string]any{"repo": p.Repo, "number": p.Number}, fmt.Sprintf("%s #%d", verb, p.Number))
		return res, err

	case "comment":
		if err := needNumber(); err != nil {
			return sdk.Result{}, err
		}
		if strings.TrimSpace(p.Body) == "" {
			return sdk.Result{}, errors.New("write the comment")
		}
		var cm struct {
			ID      int64  `json:"id"`
			HTMLURL string `json:"html_url"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/issues/"+strconv.Itoa(p.Number)+"/comments", nil, map[string]any{"body": p.Body}, &cm); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": cm.ID, "url": cm.HTMLURL})
		res.Undo = sdk.UndoWith("delete_comment", map[string]any{"repo": p.Repo, "id": cm.ID}, "Delete the comment")
		return res, err

	case "delete_comment":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("enter the comment id")
		}
		path := rp + "/issues/comments/" + strconv.FormatInt(p.ID, 10)
		var cm struct {
			Body    string `json:"body"`
			User    user   `json:"user"`
			HTMLURL string `json:"html_url"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &cm); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(cm)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s's comment in %s", cm.User.Login, p.Repo),
				Changes: []sdk.Change{{Target: cm.HTMLURL, Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.ID})

	case "merge":
		if err := needNumber(); err != nil {
			return sdk.Result{}, err
		}
		method := p.Method
		if method == "" {
			method = "merge"
		}
		if method != "merge" && method != "squash" && method != "rebase" {
			return sdk.Result{}, errors.New("the method is merge, squash or rebase")
		}
		path := rp + "/pulls/" + strconv.Itoa(p.Number)
		var pr issue
		if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &pr); err != nil {
			return sdk.Result{}, err
		}
		if pr.Merged {
			return sdk.Result{}, fmt.Errorf("#%d is already merged", p.Number)
		}
		if pr.State != "open" {
			return sdk.Result{}, fmt.Errorf("#%d is %s", p.Number, pr.State)
		}
		base, head := "", ""
		if pr.Base != nil {
			base = pr.Base.Ref
		}
		if pr.Head != nil {
			head = pr.Head.Ref
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"title": pr.Title, "head": head, "mergeable": pr.Mergeable})
			after, _ := json.Marshal(map[string]any{"base": base, "method": method, "deleteBranch": p.DeleteBranch})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s #%d %q: %s into %s", strings.ToUpper(method[:1])+method[1:], p.Number, pr.Title, head, base),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s#%d", p.Repo, p.Number), Op: "merge", Before: before, After: after}}}}, nil
		}
		body := map[string]any{"Do": method, "delete_branch_after_merge": p.DeleteBranch}
		if _, err := c.api.Do(ctx, http.MethodPost, path+"/merge", nil, body, nil); err != nil {
			if rest.IsStatus(err, http.StatusMethodNotAllowed) || rest.IsStatus(err, http.StatusConflict) {
				return sdk.Result{}, fmt.Errorf("the server won't merge #%d yet (conflicts, failing checks or missing approvals)", p.Number)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"merged": p.Number, "title": pr.Title, "base": base, "head": head, "url": pr.HTMLURL})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
