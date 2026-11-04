// Package azuredevops works with an Azure DevOps organization through its
// REST API and a personal access token: projects, Git repositories and pull
// requests (commenting, completing with a preview), pipelines and builds
// (status, the tail of a log, queueing and cancelling), and Boards work
// items (WIQL queries, creating, changing state, deleting to the recycle bin
// and restoring).
package azuredevops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
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

// Config is one Azure DevOps organization.
type Config struct {
	Organization string `json:"organization"`
	Project      string `json:"project"` // default project; optional
	Token        string `json:"token"`   // secret:// personal access token
}

type conn struct {
	api     *rest.Client
	org     string
	project string
	web     string // https://dev.azure.com/<org>, for links
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://dev.azure.com (tests).
	Base string
}

// New returns the Azure DevOps module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://dev.azure.com"
	apiVersion  = "7.1"
	maxLineLen  = 2000
	maxLogBytes = 8 << 20
)

var (
	orgRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,48}[A-Za-z0-9]?$`)
	nameBad  = regexp.MustCompile(`[\x00-\x1f\x7f\\/:*?"<>|;#$%&{},+=\[\]']`)
	typeRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _-]{0,63}$`)
	stateRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/+@-]{1,250}$`)
	varRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,99}$`)
	pathRe   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
)

// nameSeg checks a project or repository name (or GUID) and escapes it for
// a path.
func nameSeg(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 || s == "." || s == ".." || strings.HasPrefix(s, "_") || strings.HasSuffix(s, ".") || nameBad.MatchString(s) {
		return "", fmt.Errorf("%q isn't a %s name", s, what)
	}
	return url.PathEscape(s), nil
}

var strategies = map[string]bool{"noFastForward": true, "squash": true, "rebase": true, "rebaseMerge": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project name (the instance's default project when empty)"}`
	id := `"id":{"type":"integer","minimum":1}`
	wi := `{"type":"object","required":["id"],"properties":{` + project + `,` + id + `}}`
	return sdk.Manifest{
		ID: "azuredevops", Name: "Azure DevOps", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Azure DevOps: projects, repos and pull requests, pipelines and builds (status, logs, queue, cancel), Boards work items.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["organization","token"],"properties":{
			"organization":{"type":"string","description":"Organization name, as in dev.azure.com/<organization>"},
			"project":{"type":"string","description":"Default project, used when an action names none"},
			"token":{"type":"string","x-secret":true,"description":"Personal access token (User settings, Personal access tokens) with an expiry and only the scopes you need: Code (read, or read and write), Build (read, or read and execute), Work Items (read, or read and write)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "The organization's projects with their state and visibility.", Risk: sdk.RiskRead},
			{Name: "repositories", Title: "Repositories", Description: "A project's Git repositories with default branch and size.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `}}`)},
			{Name: "pull_requests", Title: "Pull requests", Description: "Pull requests (active unless status is given), in one repository or the whole project, with reviewers' votes and merge status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"repo":{"type":"string"},"status":{"type":"string","enum":["active","completed","abandoned","all"]},"limit":{"type":"integer","default":30,"maximum":100}}}`)},
			{Name: "pull_request", Title: "Pull request details", Description: "Description, reviewers and votes, merge status and the state of branch policies.", Risk: sdk.RiskRead,
				Input: sdk.Schema(wi)},
			{Name: "comment_pull_request", Title: "Comment on a pull request", Description: "Starts a comment thread (Markdown). Reviewers are notified.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","text"],"properties":{` + project + `,` + id + `,"text":{"type":"string","maxLength":150000}}}`)},
			{Name: "complete_pull_request", Title: "Complete a pull request", Description: "Merges the pull request into its target branch. The preview shows branches, strategy, votes, merge status and blocking policies. Policies are never bypassed. No undo.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + project + `,` + id + `,"strategy":{"type":"string","enum":["noFastForward","squash","rebase","rebaseMerge"],"default":"noFastForward"},"deleteSourceBranch":{"type":"boolean"},"message":{"type":"string","maxLength":4000}}}`)},
			{Name: "pipelines", Title: "Pipelines", Description: "A project's pipeline (build) definitions with their repository and folder.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"search":{"type":"string","description":"Only names containing this"}}}`)},
			{Name: "builds", Title: "Builds", Description: "Recent runs (of one pipeline when given) with status, result, branch, commit and who started them.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"pipeline":{"type":["integer","string"],"description":"Pipeline id or name"},"branch":{"type":"string"},"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "build", Title: "Build status", Description: "One run's status with its stages and jobs and the failed tasks with their error messages.", Risk: sdk.RiskRead,
				Input: sdk.Schema(wi)},
			{Name: "build_log", Title: "Build log tail", Description: "The last lines of a run's log (the first failed task's unless a log id is given). Logs can hold secrets the run printed, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + project + `,` + id + `,"log":{"type":"integer","minimum":1,"description":"Log id (see build)"},"lines":{"type":"integer","default":200,"maximum":2000}}}`)},
			{Name: "queue_build", Title: "Queue a build", Description: "Starts a pipeline run. It runs the repository's code with the pipeline's service connections and secrets, so it's destructive. The preview shows the pipeline, branch and every value passed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + project + `,"pipeline":{"type":["integer","string"],"description":"Pipeline id or name"},"branch":{"type":"string","description":"Defaults to the pipeline's default branch"},"variables":{"type":"object","maxProperties":50,"additionalProperties":{"type":"string"},"description":"Queue-time variables (must be settable at queue time)"},"parameters":{"type":"object","maxProperties":50,"additionalProperties":{"type":"string"},"description":"YAML runtime parameters"}}}`)},
			{Name: "cancel_build", Title: "Cancel a build", Description: "Cancels a queued or running run. Destructive: it interrupts work in flight (a deploy may be left half done).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(wi)},
			{Name: "query_work_items", Title: "Query work items", Description: "Runs a WIQL SELECT query (read-only) and returns the matching work items with type, title, state and assignee.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["wiql"],"properties":{` + project + `,"wiql":{"type":"string","maxLength":32000,"description":"e.g. SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active' AND [System.AssignedTo] = @Me"},"limit":{"type":"integer","default":50,"maximum":200}}}`)},
			{Name: "work_item", Title: "Work item", Description: "One work item's fields: type, title, state, reason, assignee, area, iteration, tags and description.", Risk: sdk.RiskRead,
				Input: sdk.Schema(wi)},
			{Name: "create_work_item", Title: "Create a work item", Description: "Creates a work item. Undo deletes it to the recycle bin.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["type","title"],"properties":{` + project + `,"type":{"type":"string","description":"Work item type, e.g. Bug, Task, User Story"},"title":{"type":"string","maxLength":255},"description":{"type":"string","maxLength":32000},"assignedTo":{"type":"string","description":"Email or display name"},"areaPath":{"type":"string"},"iterationPath":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"maxItems":20}}}`)},
			{Name: "update_work_item_state", Title: "Change a work item's state", Description: "Moves a work item to another state (e.g. Active, Resolved, Closed). Undo moves it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","state"],"properties":{` + project + `,` + id + `,"state":{"type":"string"}}}`)},
			{Name: "delete_work_item", Title: "Delete a work item", Description: "Moves a work item to the project's recycle bin (never destroys it). Undo restores it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(wi)},
			{Name: "restore_work_item", Title: "Restore a work item", Description: "Brings a deleted work item back from the recycle bin. Undo deletes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(wi)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	org := strings.TrimSpace(c.Organization)
	if !orgRe.MatchString(org) {
		return errors.New("the organization is its name, as in dev.azure.com/<organization>")
	}
	project := strings.TrimSpace(c.Project)
	if project != "" {
		if _, err := nameSeg(project, "project"); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the personal access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	tok := c.Token
	api := rest.New(strings.TrimRight(base, "/")+"/"+org, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.SetBasicAuth("", strings.TrimSpace(t))
		return nil
	})
	// Answer 401 instead of redirecting to the sign-in page.
	api.Header.Set("X-TFS-FedAuthRedirect", "Suppress")
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org, project: project, web: defaultBase + "/" + url.PathEscape(org)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Azure DevOps refused the token (expired, revoked or not valid for this organization)")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the token isn't allowed to do this (missing scope or permission): %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

// call makes one API request with api-version set. body is JSON, or a JSON
// Patch when patch is true.
func (c *conn) call(ctx context.Context, method, path string, q url.Values, body any, patch bool, out any, ver string) error {
	if q == nil {
		q = url.Values{}
	}
	if ver == "" {
		ver = apiVersion
	}
	q.Set("api-version", ver)
	hdr := http.Header{"Accept": {"application/json"}}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
		hdr.Set("Content-Type", "application/json")
		if patch {
			hdr.Set("Content-Type", "application/json-patch+json")
		}
	}
	res, err := c.api.Send(ctx, method, path, q, rd, hdr)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNonAuthoritativeInfo || res.StatusCode >= 300 {
		// 203 with a sign-in page: the token wasn't accepted.
		return &rest.Error{Status: http.StatusUnauthorized, Message: "Azure DevOps refused the token"}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Azure DevOps")
		}
	}
	return nil
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.call(ctx, http.MethodGet, path, q, nil, false, out, "")
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := c.get(ctx, "/_apis/projects", url.Values{"$top": {"100"}}, &list); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "organization "+c.org).Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("organization %s · %d projects visible", c.org, list.Count)}
}

type input struct {
	Project            string            `json:"project"`
	Repo               string            `json:"repo"`
	ID                 int64             `json:"id"`
	Status             string            `json:"status"`
	Limit              int               `json:"limit"`
	Text               string            `json:"text"`
	Strategy           string            `json:"strategy"`
	DeleteSourceBranch bool              `json:"deleteSourceBranch"`
	Message            string            `json:"message"`
	Search             string            `json:"search"`
	Pipeline           json.RawMessage   `json:"pipeline"`
	Branch             string            `json:"branch"`
	Log                int64             `json:"log"`
	Lines              int               `json:"lines"`
	Variables          map[string]string `json:"variables"`
	Parameters         map[string]string `json:"parameters"`
	WIQL               string            `json:"wiql"`
	Type               string            `json:"type"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	AssignedTo         string            `json:"assignedTo"`
	AreaPath           string            `json:"areaPath"`
	IterationPath      string            `json:"iterationPath"`
	Tags               []string          `json:"tags"`
	State              string            `json:"state"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func plainText(s string) string {
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(strings.NewReplacer("<br>", "\n", "<br/>", "\n", "</p>", "\n", "</div>", "\n").Replace(s), "")))
}

func id64(n int64, what string) (string, error) {
	if n < 1 {
		return "", fmt.Errorf("the %s is its number, 1 or more", what)
	}
	return strconv.FormatInt(n, 10), nil
}

// projectPath returns "/<project>" for the input's project or the default.
func (c *conn) projectPath(p string) (string, string, error) {
	name := strings.TrimSpace(p)
	if name == "" {
		name = c.project
	}
	if name == "" {
		return "", "", errors.New("name the project (or set a default project in the settings)")
	}
	seg, err := nameSeg(name, "project")
	if err != nil {
		return "", "", err
	}
	return "/" + seg, name, nil
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
	if call.Action == "projects" {
		var list struct {
			Value []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				State       string `json:"state"`
				Visibility  string `json:"visibility"`
				Updated     string `json:"lastUpdateTime"`
			} `json:"value"`
		}
		if err := c.get(ctx, "/_apis/projects", url.Values{"$top": {"500"}}, &list); err != nil {
			return sdk.Result{}, friendly(err, "organization")
		}
		out := []map[string]any{}
		for _, x := range list.Value {
			out = append(out, map[string]any{"id": x.ID, "name": x.Name, "description": clip(x.Description, 300), "state": x.State, "visibility": x.Visibility, "updated": x.Updated})
		}
		return sdk.JSON(out)
	}
	pp, pname, err := c.projectPath(p.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "repositories":
		var list struct {
			Value []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				DefaultBranch string `json:"defaultBranch"`
				Size          int64  `json:"size"`
				WebURL        string `json:"webUrl"`
				Disabled      bool   `json:"isDisabled"`
			} `json:"value"`
		}
		if err := c.get(ctx, pp+"/_apis/git/repositories", nil, &list); err != nil {
			return sdk.Result{}, friendly(err, "project "+pname)
		}
		out := []map[string]any{}
		for _, r := range list.Value {
			out = append(out, map[string]any{"id": r.ID, "name": r.Name, "defaultBranch": strings.TrimPrefix(r.DefaultBranch, "refs/heads/"), "sizeBytes": r.Size, "url": r.WebURL, "disabled": r.Disabled})
		}
		return sdk.JSON(out)

	case "pull_requests":
		q := url.Values{"searchCriteria.status": {"active"}}
		if p.Status != "" {
			switch p.Status {
			case "active", "completed", "abandoned", "all":
				q.Set("searchCriteria.status", p.Status)
			default:
				return sdk.Result{}, errors.New("status is active, completed, abandoned or all")
			}
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 30
		}
		q.Set("$top", strconv.Itoa(limit))
		path := pp + "/_apis/git/pullrequests"
		if p.Repo != "" {
			rs, err := nameSeg(p.Repo, "repository")
			if err != nil {
				return sdk.Result{}, err
			}
			path = pp + "/_apis/git/repositories/" + rs + "/pullrequests"
		}
		var list struct {
			Value []pullRequest `json:"value"`
		}
		if err := c.get(ctx, path, q, &list); err != nil {
			return sdk.Result{}, friendly(err, "repository")
		}
		out := []map[string]any{}
		for _, pr := range list.Value {
			out = append(out, c.prSummary(pr))
		}
		return sdk.JSON(out)

	case "pull_request":
		pr, err := c.getPR(ctx, pp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.prSummary(pr)
		out["description"] = clip(pr.Description, 4000)
		out["policies"] = c.policies(ctx, pp, pr)
		return sdk.JSON(out)

	case "comment_pull_request":
		text := strings.TrimSpace(p.Text)
		if text == "" || len(text) > 150000 {
			return sdk.Result{}, errors.New("the comment needs text")
		}
		pr, err := c.getPR(ctx, pp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Comment on pull request %d %q in %s; reviewers are notified", pr.ID, clip(pr.Title, 80), pr.Repository.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("pull request %d", pr.ID), Op: "comment", After: mustJSON(map[string]any{"text": text})}}}}, nil
		}
		var th struct {
			ID int64 `json:"id"`
		}
		body := map[string]any{"comments": []any{map[string]any{"parentCommentId": 0, "content": text, "commentType": 1}}, "status": 1}
		if err := c.call(ctx, http.MethodPost, pp+"/_apis/git/repositories/"+pr.Repository.ID+"/pullRequests/"+strconv.FormatInt(pr.ID, 10)+"/threads", nil, body, false, &th, ""); err != nil {
			return sdk.Result{}, friendly(err, "pull request")
		}
		return sdk.JSON(map[string]any{"pullRequest": pr.ID, "thread": th.ID})

	case "complete_pull_request":
		return c.complete(ctx, call, pp, p)
	case "pipelines":
		q := url.Values{"$top": {"500"}}
		if s := strings.TrimSpace(p.Search); s != "" {
			if len(s) > 100 || strings.ContainsAny(s, "*\x00") {
				return sdk.Result{}, errors.New("search with up to 100 characters, no *")
			}
			q.Set("name", "*"+s+"*")
		}
		var list struct {
			Value []definition `json:"value"`
		}
		if err := c.get(ctx, pp+"/_apis/build/definitions", q, &list); err != nil {
			return sdk.Result{}, friendly(err, "project "+pname)
		}
		out := []map[string]any{}
		for _, d := range list.Value {
			out = append(out, map[string]any{"id": d.ID, "name": d.Name, "folder": d.Path, "repo": d.Repository.Name, "defaultBranch": strings.TrimPrefix(d.Repository.DefaultBranch, "refs/heads/"), "queueStatus": d.QueueStatus})
		}
		return sdk.JSON(out)

	case "builds":
		q := url.Values{"queryOrder": {"queueTimeDescending"}}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		q.Set("$top", strconv.Itoa(limit))
		if len(p.Pipeline) > 0 && string(p.Pipeline) != "null" {
			d, err := c.definition(ctx, pp, p.Pipeline)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("definitions", strconv.FormatInt(d.ID, 10))
		}
		if p.Branch != "" {
			b, err := branchRef(p.Branch)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("branchName", b)
		}
		var list struct {
			Value []build `json:"value"`
		}
		if err := c.get(ctx, pp+"/_apis/build/builds", q, &list); err != nil {
			return sdk.Result{}, friendly(err, "project "+pname)
		}
		out := []map[string]any{}
		for _, b := range list.Value {
			out = append(out, b.summary())
		}
		return sdk.JSON(out)

	case "build":
		b, err := c.getBuild(ctx, pp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := b.summary()
		tl, err := c.timeline(ctx, pp, b.ID)
		if err == nil {
			stages, failed := []map[string]any{}, []map[string]any{}
			for _, r := range tl {
				switch r.Type {
				case "Stage", "Phase", "Job":
					stages = append(stages, map[string]any{"type": strings.ToLower(r.Type), "name": r.Name, "state": r.State, "result": r.Result})
				case "Task":
					if r.Result == "failed" && len(failed) < 20 {
						e := map[string]any{"task": r.Name, "errors": r.ErrorCount}
						if r.Log != nil {
							e["log"] = r.Log.ID
						}
						var msgs []string
						for _, is := range r.Issues {
							if is.Type == "error" && len(msgs) < 5 {
								msgs = append(msgs, clip(rest.Redact(is.Message), 500))
							}
						}
						e["messages"] = msgs
						failed = append(failed, e)
					}
				}
			}
			out["stages"], out["failedTasks"] = stages, failed
		}
		return sdk.JSON(out)

	case "build_log":
		return c.buildLog(ctx, pp, p)
	case "queue_build":
		return c.queue(ctx, call, pp, p)
	case "cancel_build":
		b, err := c.getBuild(ctx, pp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if b.Status == "completed" || b.Status == "cancelling" {
			return sdk.Result{}, fmt.Errorf("build %s is already %s", b.Number, b.Status)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel %s run %s on %s (%s)", b.Definition.Name, b.Number, strings.TrimPrefix(b.SourceBranch, "refs/heads/"), b.Status),
				Changes: []sdk.Change{{Target: fmt.Sprintf("build %d", b.ID), Op: "cancel", Before: mustJSON(map[string]any{"status": b.Status})}}}}, nil
		}
		if err := c.call(ctx, http.MethodPatch, pp+"/_apis/build/builds/"+strconv.FormatInt(b.ID, 10), nil, map[string]any{"status": "cancelling"}, false, nil, ""); err != nil {
			return sdk.Result{}, friendly(err, "build")
		}
		return sdk.JSON(map[string]any{"build": b.ID, "number": b.Number, "status": "cancelling"})

	case "query_work_items":
		return c.query(ctx, pp, p)
	case "work_item":
		w, err := c.getWorkItem(ctx, pp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.wiSummary(pp, w)
		f := w.Fields
		out["reason"], out["area"], out["iteration"] = fstr(f, "System.Reason"), fstr(f, "System.AreaPath"), fstr(f, "System.IterationPath")
		out["created"], out["createdBy"] = fstr(f, "System.CreatedDate"), identity(f["System.CreatedBy"])
		out["description"] = clip(plainText(fstr(f, "System.Description")), 4000)
		if r := fstr(f, "Microsoft.VSTS.TCM.ReproSteps"); r != "" {
			out["reproSteps"] = clip(plainText(r), 4000)
		}
		out["rev"] = w.Rev
		return sdk.JSON(out)
	case "create_work_item":
		return c.create(ctx, call, pp, pname, p)
	case "update_work_item_state":
		return c.setState(ctx, call, pp, pname, p)
	case "delete_work_item", "restore_work_item":
		return c.deleteRestore(ctx, call, pp, pname, p.ID)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type identityRef struct {
	DisplayName string `json:"displayName"`
}

type pullRequest struct {
	ID          int64        `json:"pullRequestId"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Status      string       `json:"status"`
	Draft       bool         `json:"isDraft"`
	MergeStatus string       `json:"mergeStatus"`
	CreatedBy   *identityRef `json:"createdBy"`
	Created     string       `json:"creationDate"`
	Source      string       `json:"sourceRefName"`
	Target      string       `json:"targetRefName"`
	Repository  struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
	} `json:"repository"`
	LastSource *struct {
		CommitID string `json:"commitId"`
	} `json:"lastMergeSourceCommit"`
	Reviewers []struct {
		DisplayName string `json:"displayName"`
		Vote        int    `json:"vote"`
		Required    bool   `json:"isRequired"`
	} `json:"reviewers"`
}

func (r *identityRef) name() string {
	if r == nil {
		return ""
	}
	return r.DisplayName
}

func voteName(v int) string {
	switch {
	case v >= 10:
		return "approved"
	case v >= 5:
		return "approved with suggestions"
	case v <= -10:
		return "rejected"
	case v <= -5:
		return "waiting for author"
	}
	return "no vote"
}

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (c *conn) prSummary(pr pullRequest) map[string]any {
	revs := []map[string]any{}
	for _, r := range pr.Reviewers {
		revs = append(revs, map[string]any{"name": r.DisplayName, "vote": voteName(r.Vote), "required": r.Required})
	}
	out := map[string]any{"id": pr.ID, "title": clip(pr.Title, 300), "status": pr.Status, "repo": pr.Repository.Name, "author": pr.CreatedBy.name(),
		"source": strings.TrimPrefix(pr.Source, "refs/heads/"), "target": strings.TrimPrefix(pr.Target, "refs/heads/"), "created": pr.Created,
		"mergeStatus": pr.MergeStatus, "reviewers": revs,
		"url": c.web + "/" + url.PathEscape(pr.Repository.Project.Name) + "/_git/" + url.PathEscape(pr.Repository.Name) + "/pullrequest/" + strconv.FormatInt(pr.ID, 10)}
	if pr.Draft {
		out["draft"] = true
	}
	return out
}

func (c *conn) getPR(ctx context.Context, pp string, n int64) (pullRequest, error) {
	var pr pullRequest
	id, err := id64(n, "pull request")
	if err != nil {
		return pr, err
	}
	if err := c.get(ctx, pp+"/_apis/git/pullrequests/"+id, nil, &pr); err != nil {
		return pr, friendly(err, "pull request "+id)
	}
	if !guidRe.MatchString(pr.Repository.ID) {
		return pr, errors.New("unexpected repository id from Azure DevOps")
	}
	return pr, nil
}

// policies lists the branch policies evaluated for a pull request.
func (c *conn) policies(ctx context.Context, pp string, pr pullRequest) []map[string]any {
	out := []map[string]any{}
	if !guidRe.MatchString(pr.Repository.Project.ID) {
		return out
	}
	var list struct {
		Value []struct {
			Status        string `json:"status"`
			Configuration struct {
				Blocking bool `json:"isBlocking"`
				Enabled  bool `json:"isEnabled"`
				Type     struct {
					DisplayName string `json:"displayName"`
				} `json:"type"`
				Settings struct {
					DisplayName string `json:"displayName"`
				} `json:"settings"`
			} `json:"configuration"`
		} `json:"value"`
	}
	q := url.Values{"artifactId": {fmt.Sprintf("vstfs:///CodeReview/CodeReviewId/%s/%d", pr.Repository.Project.ID, pr.ID)}}
	if err := c.call(ctx, http.MethodGet, pp+"/_apis/policy/evaluations", q, nil, false, &list, "7.1-preview.1"); err != nil {
		return out
	}
	for _, e := range list.Value {
		name := e.Configuration.Type.DisplayName
		if e.Configuration.Settings.DisplayName != "" {
			name += ": " + e.Configuration.Settings.DisplayName
		}
		out = append(out, map[string]any{"policy": name, "status": e.Status, "blocking": e.Configuration.Blocking})
	}
	return out
}

func (c *conn) complete(ctx context.Context, call sdk.Call, pp string, p input) (sdk.Result, error) {
	strategy := p.Strategy
	if strategy == "" {
		strategy = "noFastForward"
	}
	if !strategies[strategy] {
		return sdk.Result{}, errors.New("the strategy is noFastForward, squash, rebase or rebaseMerge")
	}
	if len(p.Message) > 4000 {
		return sdk.Result{}, errors.New("the message is up to 4000 characters")
	}
	pr, err := c.getPR(ctx, pp, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	if pr.Status != "active" {
		return sdk.Result{}, fmt.Errorf("pull request %d is %s, not active", pr.ID, pr.Status)
	}
	if pr.Draft {
		return sdk.Result{}, fmt.Errorf("pull request %d is a draft; publish it first", pr.ID)
	}
	if pr.LastSource == nil || pr.LastSource.CommitID == "" {
		return sdk.Result{}, errors.New("Azure DevOps didn't say which commit the pull request is at")
	}
	src, dst := strings.TrimPrefix(pr.Source, "refs/heads/"), strings.TrimPrefix(pr.Target, "refs/heads/")
	if call.DryRun {
		pol := c.policies(ctx, pp, pr)
		sum := fmt.Sprintf("Complete pull request %d %q in %s: %s → %s (%s)", pr.ID, clip(pr.Title, 80), pr.Repository.Name, src, dst, strategy)
		var votes []string
		for _, r := range pr.Reviewers {
			votes = append(votes, r.DisplayName+": "+voteName(r.Vote))
			if r.Vote <= -5 {
				sum += fmt.Sprintf(", %s voted %s", r.DisplayName, strings.ToUpper(voteName(r.Vote)))
			}
		}
		if pr.MergeStatus != "" && pr.MergeStatus != "succeeded" {
			sum += ", merge status " + strings.ToUpper(pr.MergeStatus)
		}
		blocking := 0
		for _, x := range pol {
			if x["blocking"] == true && x["status"] != "approved" && x["status"] != "notApplicable" {
				blocking++
			}
		}
		if blocking > 0 {
			sum += fmt.Sprintf("; %d blocking polic(ies) not met, so Azure DevOps will hold the completion until they are", blocking)
		}
		if p.DeleteSourceBranch {
			sum += "; the source branch is deleted"
		}
		after := map[string]any{"strategy": strategy, "deleteSourceBranch": p.DeleteSourceBranch, "commit": pr.LastSource.CommitID, "votes": votes, "mergeStatus": pr.MergeStatus, "policies": pol}
		if p.Message != "" {
			after["message"] = p.Message
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: fmt.Sprintf("%s branch %s", pr.Repository.Name, dst), Op: "merge", Before: mustJSON(map[string]any{"status": pr.Status}), After: mustJSON(after)}}}}, nil
	}
	opts := map[string]any{"mergeStrategy": strategy, "deleteSourceBranch": p.DeleteSourceBranch, "bypassPolicy": false}
	if p.Message != "" {
		opts["mergeCommitMessage"] = p.Message
	}
	body := map[string]any{"status": "completed", "lastMergeSourceCommit": map[string]any{"commitId": pr.LastSource.CommitID}, "completionOptions": opts}
	var after pullRequest
	if err := c.call(ctx, http.MethodPatch, pp+"/_apis/git/repositories/"+pr.Repository.ID+"/pullrequests/"+strconv.FormatInt(pr.ID, 10), nil, body, false, &after, ""); err != nil {
		return sdk.Result{}, friendly(err, "pull request")
	}
	out := map[string]any{"pullRequest": pr.ID, "status": after.Status, "mergeStatus": after.MergeStatus, "strategy": strategy}
	if after.Status == "active" {
		out["note"] = "completion is queued: Azure DevOps completes it once the policies pass"
	}
	return sdk.JSON(out)
}

type definition struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	QueueStatus string `json:"queueStatus"`
	Repository  struct {
		Name          string `json:"name"`
		DefaultBranch string `json:"defaultBranch"`
	} `json:"repository"`
}

// definition finds a pipeline by id or exact name.
func (c *conn) definition(ctx context.Context, pp string, raw json.RawMessage) (definition, error) {
	var d definition
	var n int64
	var s string
	if json.Unmarshal(raw, &n) != nil {
		if json.Unmarshal(raw, &s) != nil {
			return d, errors.New("the pipeline is its id or name (see pipelines)")
		}
		s = strings.TrimSpace(s)
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			n = v
		}
	}
	if n > 0 {
		if err := c.get(ctx, pp+"/_apis/build/definitions/"+strconv.FormatInt(n, 10), nil, &d); err != nil {
			return d, friendly(err, fmt.Sprintf("pipeline %d", n))
		}
		return d, nil
	}
	if s == "" || len(s) > 260 || strings.ContainsAny(s, "*\x00\r\n") {
		return d, errors.New("the pipeline is its id or name (see pipelines)")
	}
	var list struct {
		Value []definition `json:"value"`
	}
	if err := c.get(ctx, pp+"/_apis/build/definitions", url.Values{"name": {s}}, &list); err != nil {
		return d, friendly(err, "pipeline")
	}
	switch len(list.Value) {
	case 0:
		return d, fmt.Errorf("there's no pipeline named %q", s)
	case 1:
	default:
		return d, fmt.Errorf("%d pipelines are named %q; use the id", len(list.Value), s)
	}
	// The list leaves out the repository's default branch.
	if err := c.get(ctx, pp+"/_apis/build/definitions/"+strconv.FormatInt(list.Value[0].ID, 10), nil, &d); err != nil {
		return d, friendly(err, "pipeline")
	}
	return d, nil
}

type build struct {
	ID            int64        `json:"id"`
	Number        string       `json:"buildNumber"`
	Status        string       `json:"status"`
	Result        string       `json:"result"`
	Reason        string       `json:"reason"`
	SourceBranch  string       `json:"sourceBranch"`
	SourceVersion string       `json:"sourceVersion"`
	Queued        string       `json:"queueTime"`
	Started       string       `json:"startTime"`
	Finished      string       `json:"finishTime"`
	RequestedFor  *identityRef `json:"requestedFor"`
	Definition    struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"definition"`
	Links struct {
		Web struct {
			Href string `json:"href"`
		} `json:"web"`
	} `json:"_links"`
}

func (b build) summary() map[string]any {
	out := map[string]any{"id": b.ID, "number": b.Number, "pipeline": b.Definition.Name, "pipelineId": b.Definition.ID, "status": b.Status, "result": b.Result,
		"branch": strings.TrimPrefix(b.SourceBranch, "refs/heads/"), "reason": b.Reason, "by": b.RequestedFor.name(), "queued": b.Queued, "url": b.Links.Web.Href}
	if len(b.SourceVersion) >= 12 {
		out["commit"] = b.SourceVersion[:12]
	}
	if b.Started != "" {
		out["started"] = b.Started
	}
	if b.Finished != "" {
		out["finished"] = b.Finished
	}
	return out
}

func (c *conn) getBuild(ctx context.Context, pp string, n int64) (build, error) {
	var b build
	id, err := id64(n, "build")
	if err != nil {
		return b, err
	}
	if err := c.get(ctx, pp+"/_apis/build/builds/"+id, nil, &b); err != nil {
		return b, friendly(err, "build "+id)
	}
	return b, nil
}

type record struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Result     string `json:"result"`
	ErrorCount int    `json:"errorCount"`
	Order      int    `json:"order"`
	Log        *struct {
		ID int64 `json:"id"`
	} `json:"log"`
	Issues []struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"issues"`
	Start string `json:"startTime"`
}

func (c *conn) timeline(ctx context.Context, pp string, id int64) ([]record, error) {
	var tl struct {
		Records []record `json:"records"`
	}
	if err := c.get(ctx, pp+"/_apis/build/builds/"+strconv.FormatInt(id, 10)+"/timeline", nil, &tl); err != nil {
		return nil, err
	}
	sort.SliceStable(tl.Records, func(i, j int) bool { return tl.Records[i].Start < tl.Records[j].Start })
	return tl.Records, nil
}

func (c *conn) buildLog(ctx context.Context, pp string, p input) (sdk.Result, error) {
	n := p.Lines
	if n == 0 {
		n = 200
	}
	if n < 1 || n > 2000 {
		return sdk.Result{}, errors.New("lines is between 1 and 2000")
	}
	if p.Log < 0 {
		return sdk.Result{}, errors.New("the log is its id (see build)")
	}
	b, err := c.getBuild(ctx, pp, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	var logs struct {
		Value []struct {
			ID        int64 `json:"id"`
			LineCount int64 `json:"lineCount"`
		} `json:"value"`
	}
	bp := pp + "/_apis/build/builds/" + strconv.FormatInt(b.ID, 10) + "/logs"
	if err := c.get(ctx, bp, nil, &logs); err != nil {
		return sdk.Result{}, friendly(err, "logs of this build")
	}
	if len(logs.Value) == 0 {
		return sdk.Result{}, fmt.Errorf("build %s has no logs yet", b.Number)
	}
	logID, task := p.Log, ""
	if logID == 0 {
		if tl, err := c.timeline(ctx, pp, b.ID); err == nil {
			for _, r := range tl {
				if r.Type == "Task" && r.Result == "failed" && r.Log != nil {
					logID, task = r.Log.ID, r.Name
					break
				}
			}
		}
	}
	if logID == 0 {
		logID = logs.Value[len(logs.Value)-1].ID
	}
	var count int64 = -1
	for _, l := range logs.Value {
		if l.ID == logID {
			count = l.LineCount
		}
	}
	if count < 0 {
		return sdk.Result{}, fmt.Errorf("build %s has no log %d", b.Number, logID)
	}
	q := url.Values{"api-version": {apiVersion}}
	if count > int64(n) {
		q.Set("startLine", strconv.FormatInt(count-int64(n)+1, 10))
		q.Set("endLine", strconv.FormatInt(count, 10))
	}
	res, err := c.api.Send(ctx, http.MethodGet, bp+"/"+strconv.FormatInt(logID, 10), q, nil, http.Header{"Accept": {"text/plain"}})
	if err != nil {
		return sdk.Result{}, friendly(err, "log")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return sdk.Result{}, errors.New("Azure DevOps refused the token")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxLogBytes))
	if err != nil {
		return sdk.Result{}, err
	}
	lines := strings.Split(strings.TrimRight(strings.ToValidUTF8(string(data), "�"), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	outLines := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimPrefix(ansiRe.ReplaceAllString(strings.TrimRight(l, "\r"), ""), "\ufeff")
		outLines = append(outLines, clip(l, maxLineLen))
	}
	out := map[string]any{"build": b.ID, "number": b.Number, "status": b.Status, "result": b.Result, "log": logID, "totalLines": count, "lines": outLines}
	if task != "" {
		out["task"] = task
	}
	return sdk.JSON(out)
}

func branchRef(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "refs/") {
		s = "refs/heads/" + s
	}
	if !branchRe.MatchString(s) || strings.Contains(s, "..") || strings.Contains(s, "//") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".lock") {
		return "", fmt.Errorf("%q isn't a branch name", strings.TrimPrefix(s, "refs/heads/"))
	}
	return s, nil
}

func checkVars(m map[string]string, what string) error {
	if len(m) > 50 {
		return fmt.Errorf("up to 50 %s", what)
	}
	for k, v := range m {
		if !varRe.MatchString(k) {
			return fmt.Errorf("%q isn't a valid name for %s", k, what)
		}
		if len(v) > 10000 {
			return fmt.Errorf("the value of %s is too long", k)
		}
	}
	return nil
}

func (c *conn) queue(ctx context.Context, call sdk.Call, pp string, p input) (sdk.Result, error) {
	if err := checkVars(p.Variables, "variables"); err != nil {
		return sdk.Result{}, err
	}
	if err := checkVars(p.Parameters, "parameters"); err != nil {
		return sdk.Result{}, err
	}
	var branch string
	if p.Branch != "" {
		b, err := branchRef(p.Branch)
		if err != nil {
			return sdk.Result{}, err
		}
		branch = b
	}
	if len(p.Pipeline) == 0 {
		return sdk.Result{}, errors.New("name the pipeline (see pipelines)")
	}
	d, err := c.definition(ctx, pp, p.Pipeline)
	if err != nil {
		return sdk.Result{}, err
	}
	if d.QueueStatus == "disabled" {
		return sdk.Result{}, fmt.Errorf("pipeline %s is disabled", d.Name)
	}
	if branch == "" {
		branch = d.Repository.DefaultBranch
	}
	if call.DryRun {
		after := map[string]any{"pipeline": d.Name, "branch": strings.TrimPrefix(branch, "refs/heads/")}
		if len(p.Variables) > 0 {
			after["variables"] = p.Variables
		}
		if len(p.Parameters) > 0 {
			after["parameters"] = p.Parameters
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Run pipeline %s (%d) on %s; it runs %s's code with the pipeline's service connections and secrets", d.Name, d.ID, strings.TrimPrefix(branch, "refs/heads/"), d.Repository.Name),
			Changes: []sdk.Change{{Target: "pipeline " + d.Name, Op: "queue", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"definition": map[string]any{"id": d.ID}}
	if branch != "" {
		body["sourceBranch"] = branch
	}
	if len(p.Variables) > 0 {
		body["parameters"] = string(mustJSON(p.Variables))
	}
	if len(p.Parameters) > 0 {
		body["templateParameters"] = p.Parameters
	}
	var b build
	if err := c.call(ctx, http.MethodPost, pp+"/_apis/build/builds", nil, body, false, &b, ""); err != nil {
		return sdk.Result{}, friendly(err, "pipeline")
	}
	return sdk.JSON(map[string]any{"build": b.ID, "number": b.Number, "status": b.Status, "url": b.Links.Web.Href})
}

type workItem struct {
	ID     int64          `json:"id"`
	Rev    int64          `json:"rev"`
	Fields map[string]any `json:"fields"`
}

func fstr(f map[string]any, k string) string {
	s, _ := f[k].(string)
	return s
}

func identity(v any) string {
	switch x := v.(type) {
	case string:
		// "Name <email>": keep the name.
		if i := strings.Index(x, " <"); i > 0 {
			return x[:i]
		}
		return x
	case map[string]any:
		s, _ := x["displayName"].(string)
		return s
	}
	return ""
}

func (c *conn) wiSummary(pp string, w workItem) map[string]any {
	f := w.Fields
	out := map[string]any{"id": w.ID, "type": fstr(f, "System.WorkItemType"), "title": clip(fstr(f, "System.Title"), 300), "state": fstr(f, "System.State"),
		"assignedTo": identity(f["System.AssignedTo"]), "changed": fstr(f, "System.ChangedDate"),
		"url": c.web + pp + "/_workitems/edit/" + strconv.FormatInt(w.ID, 10)}
	if t := fstr(f, "System.Tags"); t != "" {
		out["tags"] = t
	}
	return out
}

func (c *conn) getWorkItem(ctx context.Context, pp string, n int64) (workItem, error) {
	var w workItem
	id, err := id64(n, "work item")
	if err != nil {
		return w, err
	}
	if err := c.get(ctx, pp+"/_apis/wit/workitems/"+id, nil, &w); err != nil {
		return w, friendly(err, "work item "+id)
	}
	return w, nil
}

func (c *conn) query(ctx context.Context, pp string, p input) (sdk.Result, error) {
	wiql := strings.TrimSpace(p.WIQL)
	if len(wiql) > 32000 || !strings.HasPrefix(strings.ToUpper(wiql), "SELECT ") {
		return sdk.Result{}, errors.New("the query is a WIQL SELECT, like SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active'")
	}
	limit := p.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var res struct {
		WorkItems []struct {
			ID int64 `json:"id"`
		} `json:"workItems"`
		Relations []struct {
			Target *struct {
				ID int64 `json:"id"`
			} `json:"target"`
		} `json:"workItemRelations"`
	}
	if err := c.call(ctx, http.MethodPost, pp+"/_apis/wit/wiql", url.Values{"$top": {strconv.Itoa(limit)}}, map[string]any{"query": wiql}, false, &res, ""); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("Azure DevOps refused the query: %v", err)
		}
		return sdk.Result{}, friendly(err, "project")
	}
	var ids []string
	seen := map[int64]bool{}
	add := func(id int64) {
		if id > 0 && !seen[id] && len(ids) < limit {
			seen[id] = true
			ids = append(ids, strconv.FormatInt(id, 10))
		}
	}
	for _, w := range res.WorkItems {
		add(w.ID)
	}
	for _, r := range res.Relations {
		if r.Target != nil {
			add(r.Target.ID)
		}
	}
	out := []map[string]any{}
	if len(ids) == 0 {
		return sdk.JSON(out)
	}
	var list struct {
		Value []workItem `json:"value"`
	}
	q := url.Values{"ids": {strings.Join(ids, ",")}, "fields": {"System.Id,System.WorkItemType,System.Title,System.State,System.AssignedTo,System.ChangedDate,System.Tags"}, "errorPolicy": {"omit"}}
	if err := c.get(ctx, pp+"/_apis/wit/workitems", q, &list); err != nil {
		return sdk.Result{}, friendly(err, "work items")
	}
	for _, w := range list.Value {
		if w.ID > 0 {
			out = append(out, c.wiSummary(pp, w))
		}
	}
	return sdk.JSON(out)
}

func fieldPath(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if s != "" && (!pathRe.MatchString(s) || strings.Contains(s, "/")) {
		return "", fmt.Errorf("%q isn't a valid %s (use backslashes: Project\\Team)", s, what)
	}
	return s, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, pp, pname string, p input) (sdk.Result, error) {
	typ := strings.TrimSpace(p.Type)
	if !typeRe.MatchString(typ) {
		return sdk.Result{}, errors.New("the type is a work item type, like Bug, Task or User Story")
	}
	title := strings.TrimSpace(p.Title)
	if title == "" || len([]rune(title)) > 255 || strings.ContainsAny(title, "\r\n") {
		return sdk.Result{}, errors.New("the title is one line of up to 255 characters")
	}
	if len(p.Description) > 32000 || len(p.AssignedTo) > 256 || strings.ContainsAny(p.AssignedTo, "\r\n") {
		return sdk.Result{}, errors.New("the description or assignee is too long")
	}
	area, err := fieldPath(p.AreaPath, "area path")
	if err != nil {
		return sdk.Result{}, err
	}
	iter, err := fieldPath(p.IterationPath, "iteration path")
	if err != nil {
		return sdk.Result{}, err
	}
	if len(p.Tags) > 20 {
		return sdk.Result{}, errors.New("up to 20 tags")
	}
	var tags []string
	for _, t := range p.Tags {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 100 || strings.ContainsAny(t, ";,\r\n") {
			return sdk.Result{}, fmt.Errorf("%q isn't a tag", t)
		}
		tags = append(tags, t)
	}
	fields := map[string]any{"System.Title": title}
	if d := strings.TrimSpace(p.Description); d != "" {
		fields["System.Description"] = html.EscapeString(d)
	}
	if a := strings.TrimSpace(p.AssignedTo); a != "" {
		fields["System.AssignedTo"] = a
	}
	if area != "" {
		fields["System.AreaPath"] = area
	}
	if iter != "" {
		fields["System.IterationPath"] = iter
	}
	if len(tags) > 0 {
		fields["System.Tags"] = strings.Join(tags, "; ")
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create %s %q in %s", typ, clip(title, 80), pname),
			Changes: []sdk.Change{{Target: "project " + pname, Op: "create " + typ, After: mustJSON(fields)}}}}, nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ops := []map[string]any{}
	for _, k := range keys {
		ops = append(ops, map[string]any{"op": "add", "path": "/fields/" + k, "value": fields[k]})
	}
	var w workItem
	if err := c.call(ctx, http.MethodPost, pp+"/_apis/wit/workitems/"+url.PathEscape("$"+typ), nil, ops, true, &w, ""); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("Azure DevOps refused the work item: %v", err)
		}
		return sdk.Result{}, friendly(err, "project "+pname)
	}
	res, err := sdk.JSON(c.wiSummary(pp, w))
	if w.ID > 0 {
		res.Undo = sdk.UndoWith("delete_work_item", map[string]any{"project": pname, "id": w.ID}, fmt.Sprintf("Delete %s %d to the recycle bin", typ, w.ID))
	}
	return res, err
}

func (c *conn) setState(ctx context.Context, call sdk.Call, pp, pname string, p input) (sdk.Result, error) {
	state := strings.TrimSpace(p.State)
	if !stateRe.MatchString(state) {
		return sdk.Result{}, errors.New("the state is a state name, like Active, Resolved or Closed")
	}
	w, err := c.getWorkItem(ctx, pp, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	typ, before := fstr(w.Fields, "System.WorkItemType"), fstr(w.Fields, "System.State")
	if strings.EqualFold(before, state) {
		return sdk.JSON(map[string]any{"id": w.ID, "state": before, "note": "it's already in that state"})
	}
	// Check the state exists for this type, and use its exact spelling.
	if typeRe.MatchString(typ) {
		var states struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if c.get(ctx, pp+"/_apis/wit/workitemtypes/"+url.PathEscape(typ)+"/states", nil, &states) == nil && len(states.Value) > 0 {
			var names []string
			found := ""
			for _, s := range states.Value {
				names = append(names, s.Name)
				if strings.EqualFold(s.Name, state) {
					found = s.Name
				}
			}
			if found == "" {
				return sdk.Result{}, fmt.Errorf("a %s can be %s", typ, strings.Join(names, ", "))
			}
			state = found
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %s %d %q from %s to %s", typ, w.ID, clip(fstr(w.Fields, "System.Title"), 80), before, state),
			Changes: []sdk.Change{{Target: fmt.Sprintf("%s %d", typ, w.ID), Op: "update", Before: mustJSON(map[string]any{"state": before}), After: mustJSON(map[string]any{"state": state})}}}}, nil
	}
	ops := []map[string]any{{"op": "test", "path": "/rev", "value": w.Rev}, {"op": "add", "path": "/fields/System.State", "value": state}}
	var after workItem
	if err := c.call(ctx, http.MethodPatch, pp+"/_apis/wit/workitems/"+strconv.FormatInt(w.ID, 10), nil, ops, true, &after, ""); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("Azure DevOps refused the change (the item may have changed meanwhile, or the transition isn't allowed): %v", err)
		}
		return sdk.Result{}, friendly(err, "work item")
	}
	res, err := sdk.JSON(map[string]any{"id": w.ID, "from": before, "state": fstr(after.Fields, "System.State")})
	res.Undo = sdk.UndoWith("update_work_item_state", map[string]any{"project": pname, "id": w.ID, "state": before}, fmt.Sprintf("Move %s %d back to %s", typ, w.ID, before))
	return res, err
}

func (c *conn) deleteRestore(ctx context.Context, call sdk.Call, pp, pname string, n int64) (sdk.Result, error) {
	id, err := id64(n, "work item")
	if err != nil {
		return sdk.Result{}, err
	}
	deleting := call.Action == "delete_work_item"
	var w workItem
	if deleting {
		if w, err = c.getWorkItem(ctx, pp, n); err != nil {
			return sdk.Result{}, err
		}
	} else {
		var rb struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := c.get(ctx, pp+"/_apis/wit/recyclebin/"+id, nil, &rb); err != nil {
			return sdk.Result{}, friendly(err, "deleted work item "+id+" in the recycle bin")
		}
		w = workItem{ID: n, Fields: map[string]any{"System.WorkItemType": rb.Type, "System.Title": rb.Name}}
	}
	typ, title := fstr(w.Fields, "System.WorkItemType"), clip(fstr(w.Fields, "System.Title"), 80)
	if call.DryRun {
		sum := fmt.Sprintf("Delete %s %s %q to the recycle bin of %s (it can be restored)", typ, id, title, pname)
		op := "delete"
		if !deleting {
			sum, op = fmt.Sprintf("Restore %s %s %q from the recycle bin of %s", typ, id, title, pname), "restore"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: fmt.Sprintf("%s %s", typ, id), Op: op}}}}, nil
	}
	if deleting {
		if err := c.call(ctx, http.MethodDelete, pp+"/_apis/wit/workitems/"+id, url.Values{"destroy": {"false"}}, nil, false, nil, ""); err != nil {
			return sdk.Result{}, friendly(err, "work item "+id)
		}
		res, err := sdk.JSON(map[string]any{"id": n, "deleted": true, "recycleBin": true})
		res.Undo = sdk.UndoWith("restore_work_item", map[string]any{"project": pname, "id": n}, fmt.Sprintf("Restore %s %s", typ, id))
		return res, err
	}
	if err := c.call(ctx, http.MethodPatch, pp+"/_apis/wit/recyclebin/"+id, nil, map[string]any{"IsDeleted": false}, false, nil, ""); err != nil {
		return sdk.Result{}, friendly(err, "deleted work item "+id)
	}
	res, err := sdk.JSON(map[string]any{"id": n, "restored": true})
	res.Undo = sdk.UndoWith("delete_work_item", map[string]any{"project": pname, "id": n}, fmt.Sprintf("Delete %s %s again", typ, id))
	return res, err
}
