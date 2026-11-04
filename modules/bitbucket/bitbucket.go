// Package bitbucket works with Bitbucket Cloud through its REST API 2.0:
// a workspace's repositories, pull requests (reading, commenting,
// approving, merging with a preview, declining) and Pipelines (runs, step
// status, the tail of a step's log, starting and stopping runs).
package bitbucket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one Bitbucket Cloud workspace.
type Config struct {
	Workspace string `json:"workspace"`
	// Username, when set, sends the token with basic auth (an Atlassian API
	// token with the account's email, or a legacy app password with the
	// Bitbucket username). Empty sends it as a bearer access token
	// (workspace, project or repository access token).
	Username string `json:"username"`
	Token    string `json:"token"` // secret://
}

type conn struct {
	api *rest.Client
	ws  string
	// raw fetches a log from where Bitbucket redirects it, with no
	// credentials and no further redirects.
	raw *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.bitbucket.org/2.0 (tests).
	Base string
}

// New returns the Bitbucket module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.bitbucket.org/2.0"
	maxLogBytes = 512 << 10 // bytes of a step log fetched for its tail
	maxLineLen  = 2000
)

var (
	wsRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,61}$`)
	repoRe   = regexp.MustCompile(`^[a-z0-9_.-]{1,62}$`)
	uuidRe   = regexp.MustCompile(`^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/+@-]{1,255}$`)
	selRe    = regexp.MustCompile(`^[A-Za-z0-9._/:*+@ -]{1,200}$`)
	varRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
	searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._/-]{1,100}$`)
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
)

var strategies = map[string]bool{"merge_commit": true, "squash": true, "fast_forward": true, "squash_fast_forward": true, "rebase_fast_forward": true, "rebase_merge": true}

func repoSlug(ws, s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if w, r, ok := strings.Cut(s, "/"); ok { // workspace/repo
		if w != ws {
			return "", fmt.Errorf("this instance works in workspace %s", ws)
		}
		s = r
	}
	if s == "." || s == ".." || !repoRe.MatchString(s) {
		return "", errors.New("the repository is its slug, like my-repo (lowercase letters, digits, - _ .)")
	}
	return s, nil
}

func pipelineUUID(s string) (string, bool) {
	m := uuidRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return "{" + strings.ToLower(m[1]) + "}", true
}

func validBranch(s string) error {
	if !branchRe.MatchString(s) || strings.Contains(s, "..") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") ||
		strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".lock") || strings.Contains(s, "//") {
		return fmt.Errorf("%q isn't a branch name", s)
	}
	return nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"Repository slug (see repositories)"}`
	pr := `"id":{"type":"integer","minimum":1,"description":"Pull request number"}`
	pipe := `"pipeline":{"type":"string","description":"Pipeline UUID or build number (see pipelines)"}`
	rp := `{"type":"object","required":["repo","id"],"properties":{` + repo + `,` + pr + `}}`
	return sdk.Manifest{
		ID: "bitbucket", Name: "Bitbucket", Version: "0.1.0", Category: "Development", Icon: "git",
		Description: "Bitbucket Cloud: repositories, pull requests (comment, approve, merge, decline) and Pipelines (status, log tail, run, stop).",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["workspace","token"],"properties":{
			"workspace":{"type":"string","description":"Workspace ID, as in bitbucket.org/<workspace>/"},
			"username":{"type":"string","description":"For an Atlassian API token, your account email; for a legacy app password, your Bitbucket username. Leave empty for a workspace, project or repository access token"},
			"token":{"type":"string","x-secret":true,"description":"API token, app password or access token, with read scopes for repositories, pull requests and pipelines (and write scopes for the actions you want)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repositories", Title: "Repositories", Description: "The workspace's repositories with main branch, language, privacy and last update.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Only names containing this"}}}`)},
			{Name: "pull_requests", Title: "Pull requests", Description: "A repository's pull requests (open unless state is given) with author, branches, comments and tasks.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"state":{"type":"string","enum":["OPEN","MERGED","DECLINED","SUPERSEDED"]},"limit":{"type":"integer","default":30,"maximum":100}}}`)},
			{Name: "pull_request", Title: "Pull request details", Description: "Description, reviewers and their approvals or change requests, tasks, merge settings and the size of the change.", Risk: sdk.RiskRead,
				Input: sdk.Schema(rp)},
			{Name: "comment", Title: "Comment on a pull request", Description: "Adds a comment (Markdown). Participants are notified.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","id","text"],"properties":{` + repo + `,` + pr + `,"text":{"type":"string","maxLength":32000}}}`)},
			{Name: "approve", Title: "Approve", Description: "Approves the pull request as the token's user. Undo removes the approval.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(rp)},
			{Name: "unapprove", Title: "Remove approval", Description: "Withdraws the token user's approval. Undo approves again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(rp)},
			{Name: "merge", Title: "Merge", Description: "Merges the pull request into its destination branch. The preview shows the branches, strategy, approvals, open tasks and size of the change. There's no undo.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","id"],"properties":{` + repo + `,` + pr + `,"strategy":{"type":"string","enum":["merge_commit","squash","fast_forward","squash_fast_forward","rebase_fast_forward","rebase_merge"],"description":"Defaults to the destination branch's default"},"closeSourceBranch":{"type":"boolean"},"message":{"type":"string","maxLength":10000}}}`)},
			{Name: "decline", Title: "Decline", Description: "Declines the pull request. Bitbucket Cloud can't reopen a declined pull request.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","id"],"properties":{` + repo + `,` + pr + `,"message":{"type":"string","maxLength":2000}}}`)},
			{Name: "pipelines", Title: "Pipelines", Description: "A repository's recent pipeline runs: result, branch, commit, trigger, duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"limit":{"type":"integer","default":20,"maximum":100}}}`)},
			{Name: "pipeline", Title: "Pipeline status", Description: "One run's state and each step's state and duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo","pipeline"],"properties":{` + repo + `,` + pipe + `}}`)},
			{Name: "pipeline_log", Title: "Step log tail", Description: "The last lines of a step's log (the first failed step unless given). Logs can hold secrets the run printed, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","pipeline"],"properties":{` + repo + `,` + pipe + `,"step":{"type":"string","description":"Step UUID or name"},"lines":{"type":"integer","default":200,"maximum":2000}}}`)},
			{Name: "run_pipeline", Title: "Run a pipeline", Description: "Starts the branch's pipeline (or a custom one) from bitbucket-pipelines.yml. It runs the repository's code with its variables and deployment credentials, so it's destructive.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","branch"],"properties":{` + repo + `,"branch":{"type":"string"},"custom":{"type":"string","description":"Name of a custom pipeline (pipelines.custom)"},"variables":{"type":"object","maxProperties":50,"additionalProperties":{"type":"string"},"description":"Variables for a custom pipeline; values are shown in the preview, so keep secrets in repository variables"}}}`)},
			{Name: "stop_pipeline", Title: "Stop a pipeline", Description: "Stops a pending or running pipeline.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","pipeline"],"properties":{` + repo + `,` + pipe + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	ws := strings.ToLower(strings.TrimSpace(c.Workspace))
	if !wsRe.MatchString(ws) {
		return errors.New("the workspace is its ID, as in bitbucket.org/<workspace>/")
	}
	user := strings.TrimSpace(c.Username)
	if len(user) > 254 || strings.ContainsAny(user, ":\r\n\t ") {
		return errors.New("the username is an email address or a Bitbucket username")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
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
		if user != "" {
			r.SetBasicAuth(user, strings.TrimSpace(t))
		} else {
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		}
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	rawc := *client
	rawc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	m.set.Put(id, &conn{api: api, ws: ws, raw: &rawc})
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
	var page struct {
		Size int `json:"size"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/repositories/"+c.ws, url.Values{"pagelen": {"1"}}, nil, &page); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "workspace "+c.ws).Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("workspace %s · %d repositories visible", c.ws, page.Size)}
}

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Bitbucket refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the token isn't allowed to do this (missing scope or permission): %v", err)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

type user struct {
	DisplayName string `json:"display_name"`
	Nickname    string `json:"nickname"`
}

func (u *user) name() string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Nickname
}

type link struct {
	HTML struct {
		Href string `json:"href"`
	} `json:"html"`
}

type ref struct {
	Branch struct {
		Name                 string   `json:"name"`
		DefaultMergeStrategy string   `json:"default_merge_strategy"`
		MergeStrategies      []string `json:"merge_strategies"`
	} `json:"branch"`
	Commit *struct {
		Hash string `json:"hash"`
	} `json:"commit"`
	Repository *struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type pullRequest struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	State       string `json:"state"`
	Draft       bool   `json:"draft"`
	Author      *user  `json:"author"`
	Source      ref    `json:"source"`
	Destination ref    `json:"destination"`
	CloseSource bool   `json:"close_source_branch"`
	Comments    int    `json:"comment_count"`
	Tasks       int    `json:"task_count"`
	Created     string `json:"created_on"`
	Updated     string `json:"updated_on"`
	Links       link   `json:"links"`
	MergeCommit *struct {
		Hash string `json:"hash"`
	} `json:"merge_commit"`
	Participants []struct {
		User     *user  `json:"user"`
		Role     string `json:"role"`
		Approved bool   `json:"approved"`
		State    string `json:"state"`
	} `json:"participants"`
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func prSummary(p pullRequest) map[string]any {
	out := map[string]any{"id": p.ID, "title": clip(p.Title, 300), "state": p.State, "author": p.Author.name(),
		"source": p.Source.Branch.Name, "destination": p.Destination.Branch.Name, "comments": p.Comments, "tasks": p.Tasks,
		"created": p.Created, "updated": p.Updated, "url": p.Links.HTML.Href}
	if p.Draft {
		out["draft"] = true
	}
	return out
}

// reviews counts approvals and change requests.
func (p pullRequest) reviews() (approved, changes []string) {
	for _, x := range p.Participants {
		switch {
		case x.Approved || x.State == "approved":
			approved = append(approved, x.User.name())
		case x.State == "changes_requested":
			changes = append(changes, x.User.name())
		}
	}
	return
}

type input struct {
	Repo              string            `json:"repo"`
	ID                int64             `json:"id"`
	State             string            `json:"state"`
	Limit             int               `json:"limit"`
	Search            string            `json:"search"`
	Text              string            `json:"text"`
	Strategy          string            `json:"strategy"`
	CloseSourceBranch *bool             `json:"closeSourceBranch"`
	Message           string            `json:"message"`
	Pipeline          json.RawMessage   `json:"pipeline"`
	Step              string            `json:"step"`
	Lines             int               `json:"lines"`
	Branch            string            `json:"branch"`
	Custom            string            `json:"custom"`
	Variables         map[string]string `json:"variables"`
}

func (c *conn) repoPath(raw string) (string, string, error) {
	s, err := repoSlug(c.ws, raw)
	if err != nil {
		return "", "", err
	}
	return "/repositories/" + c.ws + "/" + s, s, nil
}

func (c *conn) getPR(ctx context.Context, rp string, id int64) (pullRequest, error) {
	var p pullRequest
	if id < 1 {
		return p, errors.New("the pull request is its number, 1 or more")
	}
	if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pullrequests/"+strconv.FormatInt(id, 10), nil, nil, &p); err != nil {
		return p, friendly(err, fmt.Sprintf("pull request #%d", id))
	}
	return p, nil
}

// diffstat totals the files and lines a pull request changes.
func (c *conn) diffstat(ctx context.Context, rp string, id int64) map[string]any {
	var ds struct {
		Values []struct {
			Status  string `json:"status"`
			Added   int    `json:"lines_added"`
			Removed int    `json:"lines_removed"`
		} `json:"values"`
		Next string `json:"next"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pullrequests/"+strconv.FormatInt(id, 10)+"/diffstat", url.Values{"pagelen": {"500"}}, nil, &ds); err != nil {
		return nil
	}
	add, rem, conflicts := 0, 0, 0
	for _, v := range ds.Values {
		add += v.Added
		rem += v.Removed
		if strings.Contains(v.Status, "conflict") {
			conflicts++
		}
	}
	out := map[string]any{"files": len(ds.Values), "linesAdded": add, "linesRemoved": rem}
	if ds.Next != "" {
		out["files"] = fmt.Sprintf("%d+", len(ds.Values))
	}
	if conflicts > 0 {
		out["conflictedFiles"] = conflicts
	}
	return out
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
	if call.Action == "repositories" {
		return c.repositories(ctx, p.Search)
	}
	rp, slug, err := c.repoPath(p.Repo)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "pull_requests":
		q := url.Values{"pagelen": {"50"}}
		if p.State != "" {
			switch p.State = strings.ToUpper(p.State); p.State {
			case "OPEN", "MERGED", "DECLINED", "SUPERSEDED":
				q.Set("state", p.State)
			default:
				return sdk.Result{}, errors.New("state is OPEN, MERGED, DECLINED or SUPERSEDED")
			}
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 30
		}
		q.Set("pagelen", strconv.Itoa(limit))
		var list struct {
			Values []pullRequest `json:"values"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pullrequests", q, nil, &list); err != nil {
			return sdk.Result{}, friendly(err, "repository "+slug)
		}
		out := []map[string]any{}
		for _, pr := range list.Values {
			out = append(out, prSummary(pr))
		}
		return sdk.JSON(out)

	case "pull_request":
		pr, err := c.getPR(ctx, rp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := prSummary(pr)
		out["description"] = clip(pr.Description, 4000)
		approved, changes := pr.reviews()
		out["approvedBy"], out["changesRequestedBy"] = nonNil(approved), nonNil(changes)
		var reviewers []map[string]any
		for _, x := range pr.Participants {
			reviewers = append(reviewers, map[string]any{"name": x.User.name(), "role": x.Role, "approved": x.Approved, "state": x.State})
		}
		out["participants"] = reviewers
		out["closeSourceBranch"] = pr.CloseSource
		out["defaultMergeStrategy"] = pr.Destination.Branch.DefaultMergeStrategy
		if pr.Source.Commit != nil {
			out["sourceCommit"] = short(pr.Source.Commit.Hash)
		}
		if pr.MergeCommit != nil {
			out["mergeCommit"] = short(pr.MergeCommit.Hash)
		}
		if ds := c.diffstat(ctx, rp, pr.ID); ds != nil {
			out["change"] = ds
		}
		return sdk.JSON(out)

	case "comment":
		text := strings.TrimSpace(p.Text)
		if text == "" || len(text) > 32000 {
			return sdk.Result{}, errors.New("the comment needs text (up to 32000 characters)")
		}
		pr, err := c.getPR(ctx, rp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Comment on %s #%d %q; its participants are notified", slug, pr.ID, clip(pr.Title, 80)),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s pull request #%d", slug, pr.ID), Op: "comment", After: mustJSON(map[string]any{"text": text})}}}}, nil
		}
		var out struct {
			ID    int64 `json:"id"`
			Links link  `json:"links"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/pullrequests/"+strconv.FormatInt(pr.ID, 10)+"/comments", nil, map[string]any{"content": map[string]any{"raw": text}}, &out); err != nil {
			return sdk.Result{}, friendly(err, "pull request")
		}
		return sdk.JSON(map[string]any{"repo": slug, "id": pr.ID, "comment": out.ID, "url": out.Links.HTML.Href})

	case "approve", "unapprove":
		return c.approve(ctx, call, rp, slug, p.ID)
	case "merge":
		return c.merge(ctx, call, rp, slug, p)
	case "decline":
		pr, err := c.getPR(ctx, rp, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if pr.State != "OPEN" {
			return sdk.Result{}, fmt.Errorf("#%d is %s, not open", pr.ID, strings.ToLower(pr.State))
		}
		msg := strings.TrimSpace(p.Message)
		if len(msg) > 2000 {
			return sdk.Result{}, errors.New("the message is up to 2000 characters")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Decline %s #%d %q (%s → %s); a declined pull request can't be reopened", slug, pr.ID, clip(pr.Title, 80), pr.Source.Branch.Name, pr.Destination.Branch.Name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s pull request #%d", slug, pr.ID), Op: "decline", Before: mustJSON(map[string]any{"state": pr.State}), After: mustJSON(map[string]any{"state": "DECLINED", "message": msg})}}}}, nil
		}
		var body any
		if msg != "" {
			body = map[string]any{"message": msg}
		}
		var after pullRequest
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/pullrequests/"+strconv.FormatInt(pr.ID, 10)+"/decline", nil, body, &after); err != nil {
			return sdk.Result{}, friendly(err, "pull request")
		}
		return sdk.JSON(map[string]any{"repo": slug, "id": pr.ID, "state": after.State})

	case "pipelines":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		var list struct {
			Values []pipeline `json:"values"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pipelines", url.Values{"sort": {"-created_on"}, "pagelen": {strconv.Itoa(limit)}}, nil, &list); err != nil {
			return sdk.Result{}, friendly(err, "repository "+slug)
		}
		out := []map[string]any{}
		for _, pl := range list.Values {
			out = append(out, pl.summary())
		}
		return sdk.JSON(out)

	case "pipeline":
		pl, err := c.getPipeline(ctx, rp, p.Pipeline)
		if err != nil {
			return sdk.Result{}, err
		}
		steps, err := c.steps(ctx, rp, pl.UUID)
		if err != nil {
			return sdk.Result{}, err
		}
		out := pl.summary()
		sl := []map[string]any{}
		for _, s := range steps {
			sl = append(sl, s.summary())
		}
		out["steps"] = sl
		return sdk.JSON(out)

	case "pipeline_log":
		return c.log(ctx, rp, p)
	case "run_pipeline":
		return c.run(ctx, call, rp, slug, p)
	case "stop_pipeline":
		pl, err := c.getPipeline(ctx, rp, p.Pipeline)
		if err != nil {
			return sdk.Result{}, err
		}
		if pl.State.Name == "COMPLETED" {
			return sdk.Result{}, fmt.Errorf("pipeline #%d has already finished (%s)", pl.Number, pl.status())
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop pipeline #%d of %s on %s, %s since %s", pl.Number, slug, pl.Target.RefName, pl.status(), pl.Created),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s pipeline #%d", slug, pl.Number), Op: "stop", Before: mustJSON(map[string]any{"state": pl.status()})}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/pipelines/"+url.PathEscape(pl.UUID)+"/stopPipeline", nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "pipeline")
		}
		return sdk.JSON(map[string]any{"repo": slug, "pipeline": pl.Number, "uuid": pl.UUID, "stopping": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *conn) repositories(ctx context.Context, search string) (sdk.Result, error) {
	q := url.Values{"pagelen": {"100"}, "sort": {"-updated_on"}}
	if s := strings.TrimSpace(search); s != "" {
		if !searchRe.MatchString(s) {
			return sdk.Result{}, errors.New("search with letters, digits, spaces and . _ / -")
		}
		q.Set("q", `name ~ "`+s+`"`)
	}
	out := []map[string]any{}
	for pg := 1; pg <= 5; pg++ {
		q.Set("page", strconv.Itoa(pg))
		var list struct {
			Values []struct {
				Slug       string `json:"slug"`
				Name       string `json:"name"`
				Private    bool   `json:"is_private"`
				Language   string `json:"language"`
				Updated    string `json:"updated_on"`
				MainBranch *struct {
					Name string `json:"name"`
				} `json:"mainbranch"`
				Project *struct {
					Key string `json:"key"`
				} `json:"project"`
				Links link `json:"links"`
			} `json:"values"`
			Next string `json:"next"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/repositories/"+c.ws, q, nil, &list); err != nil {
			return sdk.Result{}, friendly(err, "workspace "+c.ws)
		}
		for _, r := range list.Values {
			e := map[string]any{"slug": r.Slug, "name": r.Name, "private": r.Private, "language": r.Language, "updated": r.Updated, "url": r.Links.HTML.Href}
			if r.MainBranch != nil {
				e["mainBranch"] = r.MainBranch.Name
			}
			if r.Project != nil {
				e["project"] = r.Project.Key
			}
			out = append(out, e)
		}
		if list.Next == "" {
			break
		}
	}
	return sdk.JSON(out)
}

func (c *conn) approve(ctx context.Context, call sdk.Call, rp, slug string, id int64) (sdk.Result, error) {
	pr, err := c.getPR(ctx, rp, id)
	if err != nil {
		return sdk.Result{}, err
	}
	approving := call.Action == "approve"
	if approving && pr.State != "OPEN" {
		return sdk.Result{}, fmt.Errorf("#%d is %s, not open", pr.ID, strings.ToLower(pr.State))
	}
	verb, back, backDesc, method := "Approve", "unapprove", "Remove the approval of %s #%d", http.MethodPost
	if !approving {
		verb, back, backDesc, method = "Remove your approval of", "approve", "Approve %s #%d again", http.MethodDelete
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %s #%d %q", verb, slug, pr.ID, clip(pr.Title, 80)),
			Changes: []sdk.Change{{Target: fmt.Sprintf("%s pull request #%d", slug, pr.ID), Op: call.Action, After: mustJSON(map[string]any{"approved": approving})}}}}, nil
	}
	if _, err := c.api.Do(ctx, method, rp+"/pullrequests/"+strconv.FormatInt(pr.ID, 10)+"/approve", nil, nil, nil); err != nil {
		if !approving && rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"repo": slug, "id": pr.ID, "note": "you hadn't approved it"})
		}
		return sdk.Result{}, friendly(err, "pull request")
	}
	res, err := sdk.JSON(map[string]any{"repo": slug, "id": pr.ID, "approved": approving})
	res.Undo = sdk.UndoWith(back, map[string]any{"repo": slug, "id": pr.ID}, fmt.Sprintf(backDesc, slug, pr.ID))
	return res, err
}

func (c *conn) merge(ctx context.Context, call sdk.Call, rp, slug string, p input) (sdk.Result, error) {
	if p.Strategy != "" && !strategies[p.Strategy] {
		return sdk.Result{}, errors.New("the strategy is merge_commit, squash, fast_forward, squash_fast_forward, rebase_fast_forward or rebase_merge")
	}
	if len(p.Message) > 10000 {
		return sdk.Result{}, errors.New("the message is up to 10000 characters")
	}
	pr, err := c.getPR(ctx, rp, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	if pr.State != "OPEN" {
		return sdk.Result{}, fmt.Errorf("#%d is %s, not open", pr.ID, strings.ToLower(pr.State))
	}
	strategy := p.Strategy
	if strategy == "" {
		strategy = pr.Destination.Branch.DefaultMergeStrategy
	}
	if len(pr.Destination.Branch.MergeStrategies) > 0 && strategy != "" {
		ok := false
		for _, s := range pr.Destination.Branch.MergeStrategies {
			ok = ok || s == strategy
		}
		if !ok {
			return sdk.Result{}, fmt.Errorf("%s doesn't allow %s; it allows %s", pr.Destination.Branch.Name, strategy, strings.Join(pr.Destination.Branch.MergeStrategies, ", "))
		}
	}
	closeSrc := pr.CloseSource
	if p.CloseSourceBranch != nil {
		closeSrc = *p.CloseSourceBranch
	}
	if call.DryRun {
		approved, changes := pr.reviews()
		ds := c.diffstat(ctx, rp, pr.ID)
		sum := fmt.Sprintf("Merge %s #%d %q: %s → %s (%s), %d approval(s)", slug, pr.ID, clip(pr.Title, 80), pr.Source.Branch.Name, pr.Destination.Branch.Name, strategy, len(approved))
		if len(changes) > 0 {
			sum += fmt.Sprintf(", CHANGES REQUESTED by %s", strings.Join(changes, ", "))
		}
		if pr.Tasks > 0 {
			sum += fmt.Sprintf(", %d open task(s)", pr.Tasks)
		}
		if pr.Draft {
			sum += ", still a draft"
		}
		if closeSrc {
			sum += "; the source branch is deleted"
		}
		after := map[string]any{"strategy": strategy, "closeSourceBranch": closeSrc, "approvedBy": nonNil(approved), "changesRequestedBy": nonNil(changes), "openTasks": pr.Tasks}
		if ds != nil {
			after["change"] = ds
			if n, ok := ds["conflictedFiles"].(int); ok && n > 0 {
				sum += fmt.Sprintf("; %d file(s) have conflicts", n)
			}
		}
		if p.Message != "" {
			after["message"] = p.Message
		}
		if pr.Source.Commit != nil {
			after["sourceCommit"] = short(pr.Source.Commit.Hash)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: fmt.Sprintf("%s branch %s", slug, pr.Destination.Branch.Name), Op: "merge", Before: mustJSON(map[string]any{"state": pr.State}), After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"type": "pullrequest_merge_parameters", "close_source_branch": closeSrc}
	if strategy != "" {
		body["merge_strategy"] = strategy
	}
	if p.Message != "" {
		body["message"] = p.Message
	}
	res, err := c.api.Send(ctx, http.MethodPost, rp+"/pullrequests/"+strconv.FormatInt(pr.ID, 10)+"/merge", nil, strings.NewReader(string(mustJSON(body))),
		http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}})
	if err != nil {
		return sdk.Result{}, friendly(err, "pull request")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusAccepted {
		return sdk.JSON(map[string]any{"repo": slug, "id": pr.ID, "merging": true, "note": "Bitbucket is still merging; check pull_request in a moment"})
	}
	var after pullRequest
	_ = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&after)
	out := map[string]any{"repo": slug, "id": pr.ID, "state": after.State, "strategy": strategy}
	if after.MergeCommit != nil {
		out["mergeCommit"] = short(after.MergeCommit.Hash)
	}
	return sdk.JSON(out)
}

type pipeline struct {
	UUID    string `json:"uuid"`
	Number  int64  `json:"build_number"`
	Created string `json:"created_on"`
	Done    string `json:"completed_on"`
	Seconds int    `json:"duration_in_seconds"`
	State   state  `json:"state"`
	Creator *user  `json:"creator"`
	Trigger *struct {
		Name string `json:"name"`
	} `json:"trigger"`
	Target struct {
		RefName  string `json:"ref_name"`
		RefType  string `json:"ref_type"`
		Selector *struct {
			Type    string `json:"type"`
			Pattern string `json:"pattern"`
		} `json:"selector"`
		Commit *struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	} `json:"target"`
}

type state struct {
	Name   string `json:"name"`
	Result *struct {
		Name string `json:"name"`
	} `json:"result"`
	Stage *struct {
		Name string `json:"name"`
	} `json:"stage"`
}

func (s state) String() string {
	switch {
	case s.Result != nil && s.Result.Name != "":
		return strings.ToLower(s.Result.Name)
	case s.Stage != nil && s.Stage.Name != "":
		return strings.ToLower(s.Stage.Name)
	}
	return strings.ToLower(s.Name)
}

func (p pipeline) status() string { return p.State.String() }

func (p pipeline) summary() map[string]any {
	out := map[string]any{"uuid": p.UUID, "number": p.Number, "status": p.status(), "branch": p.Target.RefName, "created": p.Created, "seconds": p.Seconds, "by": p.Creator.name()}
	if p.Done != "" {
		out["completed"] = p.Done
	}
	if p.Target.Commit != nil {
		out["commit"] = short(p.Target.Commit.Hash)
	}
	if p.Target.Selector != nil && p.Target.Selector.Type != "" {
		sel := p.Target.Selector.Type
		if p.Target.Selector.Pattern != "" {
			sel += ": " + p.Target.Selector.Pattern
		}
		out["pipeline"] = sel
	}
	if p.Trigger != nil {
		out["trigger"] = strings.ToLower(p.Trigger.Name)
	}
	return out
}

type step struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	State   state  `json:"state"`
	Started string `json:"started_on"`
	Done    string `json:"completed_on"`
	Seconds int    `json:"duration_in_seconds"`
}

func (s step) summary() map[string]any {
	out := map[string]any{"uuid": s.UUID, "name": s.Name, "status": s.State.String(), "seconds": s.Seconds}
	if s.Started != "" {
		out["started"] = s.Started
	}
	return out
}

// getPipeline finds a run by UUID or build number.
func (c *conn) getPipeline(ctx context.Context, rp string, raw json.RawMessage) (pipeline, error) {
	var pl pipeline
	var s string
	var n int64
	if err := json.Unmarshal(raw, &s); err != nil {
		if err := json.Unmarshal(raw, &n); err != nil || n < 1 {
			return pl, errors.New("the pipeline is its UUID or build number (see pipelines)")
		}
		s = strconv.FormatInt(n, 10)
	}
	s = strings.TrimPrefix(strings.TrimSpace(s), "#")
	if id, ok := pipelineUUID(s); ok {
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pipelines/"+url.PathEscape(id), nil, nil, &pl); err != nil {
			return pl, friendly(err, "pipeline "+id)
		}
		return pl, nil
	}
	num, err := strconv.ParseInt(s, 10, 64)
	if err != nil || num < 1 {
		return pl, errors.New("the pipeline is its UUID or build number (see pipelines)")
	}
	for pg := 1; pg <= 5; pg++ {
		var list struct {
			Values []pipeline `json:"values"`
			Next   string     `json:"next"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pipelines", url.Values{"sort": {"-created_on"}, "pagelen": {"100"}, "page": {strconv.Itoa(pg)}}, nil, &list); err != nil {
			return pl, friendly(err, "repository")
		}
		for _, x := range list.Values {
			if x.Number == num {
				if _, ok := pipelineUUID(x.UUID); !ok {
					return pl, errors.New("unexpected pipeline UUID from Bitbucket")
				}
				return x, nil
			}
		}
		if list.Next == "" {
			break
		}
	}
	return pl, fmt.Errorf("there's no pipeline #%d among the last 500 runs; use its UUID", num)
}

func (c *conn) steps(ctx context.Context, rp, uuid string) ([]step, error) {
	if _, ok := pipelineUUID(uuid); !ok {
		return nil, errors.New("unexpected pipeline UUID from Bitbucket")
	}
	var list struct {
		Values []step `json:"values"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, rp+"/pipelines/"+url.PathEscape(uuid)+"/steps", url.Values{"pagelen": {"100"}}, nil, &list); err != nil {
		return nil, friendly(err, "pipeline")
	}
	return list.Values, nil
}

func (c *conn) log(ctx context.Context, rp string, p input) (sdk.Result, error) {
	n := p.Lines
	if n == 0 {
		n = 200
	}
	if n < 1 || n > 2000 {
		return sdk.Result{}, errors.New("lines is between 1 and 2000")
	}
	if len(p.Step) > 200 {
		return sdk.Result{}, errors.New("the step is its UUID or name")
	}
	pl, err := c.getPipeline(ctx, rp, p.Pipeline)
	if err != nil {
		return sdk.Result{}, err
	}
	steps, err := c.steps(ctx, rp, pl.UUID)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(steps) == 0 {
		return sdk.Result{}, fmt.Errorf("pipeline #%d has no steps yet", pl.Number)
	}
	var st *step
	want := strings.TrimSpace(p.Step)
	wantUUID, isUUID := pipelineUUID(want)
	for i := range steps {
		s := &steps[i]
		switch {
		case want == "":
			if st == nil && (s.State.String() == "failed" || s.State.String() == "error") {
				st = s
			}
		case isUUID && strings.EqualFold(s.UUID, wantUUID), !isUUID && strings.EqualFold(s.Name, want):
			st = s
		}
	}
	if st == nil && want == "" {
		// No failed step: the last one that started.
		for i := range steps {
			if steps[i].Started != "" {
				st = &steps[i]
			}
		}
		if st == nil {
			st = &steps[0]
		}
	}
	if st == nil {
		return sdk.Result{}, fmt.Errorf("pipeline #%d has no step %q", pl.Number, want)
	}
	if _, ok := pipelineUUID(st.UUID); !ok {
		return sdk.Result{}, errors.New("unexpected step UUID from Bitbucket")
	}
	data, partial, err := c.fetchLog(ctx, rp+"/pipelines/"+url.PathEscape(pl.UUID)+"/steps/"+url.PathEscape(st.UUID)+"/log")
	if err != nil {
		return sdk.Result{}, err
	}
	lines := tailLines(data, n, partial)
	out := map[string]any{"pipeline": pl.Number, "step": st.Name, "status": st.State.String(), "lines": lines}
	if partial {
		out["note"] = fmt.Sprintf("the log is longer than %d KiB; these are lines from its end", maxLogBytes>>10)
	}
	return sdk.JSON(out)
}

// fetchLog reads the end of a step log. Bitbucket may answer with a
// redirect to its log storage; that location is fetched with no
// credentials (the link is pre-signed) and only over https.
func (c *conn) fetchLog(ctx context.Context, path string) ([]byte, bool, error) {
	hdr := http.Header{"Accept": {"text/plain, application/octet-stream"}, "Range": {fmt.Sprintf("bytes=-%d", maxLogBytes)}}
	cp := *c.api
	cp.HTTP = c.raw
	res, err := cp.Send(ctx, http.MethodGet, path, nil, nil, hdr)
	if err != nil {
		if rest.IsStatus(err, http.StatusRequestedRangeNotSatisfiable) {
			return nil, false, nil // empty log
		}
		return nil, false, friendly(err, "log for this step")
	}
	for hop := 0; res.StatusCode >= 300 && res.StatusCode < 400; hop++ {
		loc, lerr := res.Location()
		res.Body.Close()
		if lerr != nil || hop >= 3 {
			return nil, false, errors.New("unexpected redirect for the log")
		}
		if loc.Scheme != "https" {
			return nil, false, errors.New("refusing to fetch the log over plain http")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Range", hdr.Get("Range"))
		req.Header.Set("User-Agent", "Conduit")
		if res, err = c.raw.Do(req); err != nil {
			return nil, false, err
		}
		if res.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			res.Body.Close()
			return nil, false, nil
		}
		if res.StatusCode >= 400 {
			res.Body.Close()
			return nil, false, fmt.Errorf("the log storage answered %s", res.Status)
		}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, false, err
	}
	partial := false
	if res.StatusCode == http.StatusPartialContent {
		// Content-Range: bytes start-end/total
		cr := res.Header.Get("Content-Range")
		partial = !strings.HasPrefix(cr, "bytes 0-")
	}
	if len(data) > maxLogBytes {
		data, partial = data[len(data)-maxLogBytes:], true
	}
	return data, partial, nil
}

// tailLines keeps the last n lines, without terminal color codes and with
// long lines cut. When the data starts mid-log its first line is dropped.
func tailLines(data []byte, n int, partial bool) []string {
	s := strings.ToValidUTF8(string(data), "�")
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	if partial && len(lines) > 1 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, clip(ansiRe.ReplaceAllString(strings.TrimRight(l, "\r"), ""), maxLineLen))
	}
	if len(out) == 1 && out[0] == "" {
		return []string{}
	}
	return out
}

func (c *conn) run(ctx context.Context, call sdk.Call, rp, slug string, p input) (sdk.Result, error) {
	branch := strings.TrimSpace(p.Branch)
	if err := validBranch(branch); err != nil {
		return sdk.Result{}, err
	}
	custom := strings.TrimSpace(p.Custom)
	if custom != "" && !selRe.MatchString(custom) {
		return sdk.Result{}, errors.New("the custom pipeline is its name under pipelines.custom")
	}
	if len(p.Variables) > 0 && custom == "" {
		return sdk.Result{}, errors.New("variables can only be given to a custom pipeline")
	}
	if len(p.Variables) > 50 {
		return sdk.Result{}, errors.New("up to 50 variables")
	}
	vars := []map[string]any{}
	for k, v := range p.Variables {
		if !varRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a variable name (letters, digits, _)", k)
		}
		if len(v) > 10000 {
			return sdk.Result{}, fmt.Errorf("the value of %s is too long", k)
		}
		vars = append(vars, map[string]any{"key": k, "value": v})
	}
	target := map[string]any{"type": "pipeline_ref_target", "ref_type": "branch", "ref_name": branch}
	if custom != "" {
		target["selector"] = map[string]any{"type": "custom", "pattern": custom}
	}
	if call.DryRun {
		which := "the default pipeline for " + branch
		if custom != "" {
			which = "custom pipeline " + custom + " on " + branch
		}
		after := map[string]any{"branch": branch}
		if custom != "" {
			after["custom"] = custom
		}
		if len(p.Variables) > 0 {
			after["variables"] = p.Variables
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Run %s of %s; it runs the repository's code with its variables and deployment credentials", which, slug),
			Changes: []sdk.Change{{Target: "repository " + slug, Op: "run pipeline", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"target": target}
	if len(vars) > 0 {
		body["variables"] = vars
	}
	var pl pipeline
	if _, err := c.api.Do(ctx, http.MethodPost, rp+"/pipelines", nil, body, &pl); err != nil {
		return sdk.Result{}, friendly(err, "repository "+slug)
	}
	return sdk.JSON(map[string]any{"repo": slug, "pipeline": pl.Number, "uuid": pl.UUID, "status": pl.status()})
}
