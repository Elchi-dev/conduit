// Package circleci works with CircleCI through its API v2 with a personal
// API token: a project's pipelines, their workflows and jobs, rerunning or
// cancelling a workflow, and workflow insights (success rate, duration).
package circleci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// Config is one CircleCI account.
type Config struct {
	Token string `json:"token"` // secret:// personal API token
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://circleci.com/api/v2 (tests).
	Base string
}

// New returns the CircleCI module.
func New() *Module { return &Module{} }

const defaultBase = "https://circleci.com/api/v2"

var (
	// Organization and repository names (or, for circleci/ slugs, UUIDs).
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@#-]{1,255}$`)
	vcsTypes = map[string]bool{"gh": true, "github": true, "bb": true, "bitbucket": true, "circleci": true}
	windows  = map[string]bool{"last-24-hours": true, "last-7-days": true, "last-30-days": true, "last-60-days": true, "last-90-days": true}
)

// validProject checks a project slug: vcs/org/repo, e.g. gh/elchi/conduit,
// or circleci/<org id>/<project id>.
func validProject(s string) (string, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 3 || !vcsTypes[parts[0]] {
		return "", errors.New("the project is its slug, vcs/org/repo, e.g. gh/elchi/conduit (or circleci/<org id>/<project id>)")
	}
	for _, p := range parts[1:] {
		if !nameRe.MatchString(p) || strings.Trim(p, ".") == "" {
			return "", errors.New("the project is its slug, vcs/org/repo, e.g. gh/elchi/conduit")
		}
	}
	return strings.Join(parts, "/"), nil
}

func validBranch(s string) (string, error) {
	b := strings.TrimSpace(s)
	if b == "" {
		return "", nil
	}
	if !branchRe.MatchString(b) || strings.Contains(b, "..") {
		return "", errors.New("that isn't a branch name")
	}
	return b, nil
}

func validID(s, what string) (string, error) {
	id := strings.TrimSpace(s)
	if !uuidRe.MatchString(id) {
		return "", fmt.Errorf("the %s is its ID, a UUID like 5034460f-c7c4-4c43-9457-de07e2029e7b", what)
	}
	return strings.ToLower(id), nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	project := `"project":{"type":"string","description":"Project slug, vcs/org/repo, e.g. gh/elchi/conduit"}`
	workflow := `"workflow":{"type":"string","description":"Workflow ID (see workflows)"}`
	return sdk.Manifest{
		ID: "circleci", Name: "CircleCI", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "CircleCI: pipelines, workflow and job status, insights (success rate, duration), and rerunning or cancelling workflows.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A personal API token (User Settings, Personal API Tokens)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pipelines", Title: "Pipelines", Description: "A project's recent pipelines, newest first: number, state, branch, commit, trigger.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `,"branch":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "workflows", Title: "Workflows", Description: "The workflows of one pipeline (by project and pipeline number, or pipeline ID) with status and duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + project + `,"number":{"type":"integer","minimum":1,"description":"Pipeline number"},"pipeline":{"type":"string","description":"Pipeline ID, instead of project and number"}}}`)},
			{Name: "jobs", Title: "Jobs", Description: "One workflow's status and its jobs with status, type and duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["workflow"],"properties":{` + workflow + `}}`)},
			{Name: "rerun_workflow", Title: "Rerun a workflow", Description: "Runs a finished workflow again (all jobs, or only the failed ones), so its code runs again with the project's secrets and contexts.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["workflow"],"properties":{` + workflow + `,"fromFailed":{"type":"boolean","default":false,"description":"Rerun only the failed jobs and what depends on them"}}}`)},
			{Name: "cancel_workflow", Title: "Cancel a workflow", Description: "Stops a running or on-hold workflow; jobs in progress are killed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["workflow"],"properties":{` + workflow + `}}`)},
			{Name: "insights", Title: "Workflow insights", Description: "Per workflow over a reporting window: runs, success rate, failures, duration (median, p95, max), mean time to recovery and credits used.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + project + `,"branch":{"type":"string","description":"Branch (the default branch when empty)"},"allBranches":{"type":"boolean"},"window":{"type":"string","enum":["last-24-hours","last-7-days","last-30-days","last-60-days","last-90-days"],"default":"last-30-days"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "pipeline", Title: "Pipelines", ListAction: "pipelines", ViewHint: "table"}},
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
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Circle-Token", strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("CircleCI refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("CircleCI refused: the token's user can't do this here")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("no %s (or the token's user can't see it)", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("CircleCI's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Login string `json:"login"`
	}
	if err := c.get(ctx, "/me", nil, &me, "user"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Login}
}

type pipeline struct {
	ID        string `json:"id"`
	Number    int64  `json:"number"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	Project   string `json:"project_slug"`
	Trigger   struct {
		Type  string `json:"type"`
		Actor struct {
			Login string `json:"login"`
		} `json:"actor"`
	} `json:"trigger"`
	VCS struct {
		Branch   string `json:"branch"`
		Tag      string `json:"tag"`
		Revision string `json:"revision"`
		Commit   struct {
			Subject string `json:"subject"`
		} `json:"commit"`
	} `json:"vcs"`
	Errors []struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"errors"`
}

type workflow struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	PipelineID  string  `json:"pipeline_id"`
	PipelineNum int64   `json:"pipeline_number"`
	Project     string  `json:"project_slug"`
	CreatedAt   string  `json:"created_at"`
	StoppedAt   *string `json:"stopped_at"`
}

type job struct {
	ID        string  `json:"id"`
	Number    *int64  `json:"job_number"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Type      string  `json:"type"`
	StartedAt *string `json:"started_at"`
	StoppedAt *string `json:"stopped_at"`
}

type page[T any] struct {
	Items []T     `json:"items"`
	Next  *string `json:"next_page_token"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// firstLine is the first line of free text the server passes on (a commit
// message, a step's error), with anything that looks like a credential
// redacted (rest.Redact) and cut to 200 characters.
func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	s = rest.Redact(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func took(start, end string) string {
	a, err1 := time.Parse(time.RFC3339, start)
	b, err2 := time.Parse(time.RFC3339, end)
	if err1 != nil || err2 != nil || b.Before(a) {
		return ""
	}
	return b.Sub(a).Round(time.Second).String()
}

func seconds(s float64) string {
	if s <= 0 {
		return ""
	}
	return (time.Duration(s) * time.Second).String()
}

func short(rev string) string {
	if len(rev) > 10 {
		return rev[:10]
	}
	return rev
}

// all pages through a list until max items (or 10 pages).
func all[T any](ctx context.Context, c *conn, path string, q url.Values, max int, what string) ([]T, error) {
	var out []T
	if q == nil {
		q = url.Values{}
	}
	for i := 0; i < 10 && len(out) < max; i++ {
		var p page[T]
		if err := c.get(ctx, path, q, &p, what); err != nil {
			return nil, err
		}
		out = append(out, p.Items...)
		if p.Next == nil || *p.Next == "" {
			break
		}
		q.Set("page-token", *p.Next)
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

func (c *conn) workflow(ctx context.Context, id string) (workflow, error) {
	var w workflow
	if err := c.get(ctx, "/workflow/"+id, nil, &w, "workflow "+id); err != nil {
		return workflow{}, err
	}
	if w.ID == "" {
		return workflow{}, fmt.Errorf("unexpected answer looking up workflow %s", id)
	}
	return w, nil
}

func wfRow(w workflow) map[string]any {
	return map[string]any{"id": w.ID, "name": w.Name, "status": w.Status, "created": w.CreatedAt, "stopped": str(w.StoppedAt), "duration": took(w.CreatedAt, str(w.StoppedAt))}
}

// active is whether a workflow is still going (or waiting on approval).
func active(status string) bool {
	return status == "running" || status == "on_hold" || status == "failing"
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Project     string `json:"project"`
		Branch      string `json:"branch"`
		Limit       int    `json:"limit"`
		Number      int64  `json:"number"`
		Pipeline    string `json:"pipeline"`
		Workflow    string `json:"workflow"`
		FromFailed  bool   `json:"fromFailed"`
		AllBranches bool   `json:"allBranches"`
		Window      string `json:"window"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "pipelines":
		slug, err := validProject(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		branch, err := validBranch(p.Branch)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit <= 0 {
			limit = 20
		}
		if limit > 50 {
			return sdk.Result{}, errors.New("limit is at most 50")
		}
		q := url.Values{}
		if branch != "" {
			q.Set("branch", branch)
		}
		ps, err := all[pipeline](ctx, c, "/project/"+slug+"/pipeline", q, limit, "project "+slug)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			row := map[string]any{"id": x.ID, "number": x.Number, "state": x.State, "created": x.CreatedAt, "branch": x.VCS.Branch,
				"commit": short(x.VCS.Revision), "subject": firstLine(x.VCS.Commit.Subject), "trigger": x.Trigger.Type, "actor": x.Trigger.Actor.Login}
			if x.VCS.Tag != "" {
				row["tag"] = x.VCS.Tag
			}
			if len(x.Errors) > 0 {
				row["error"] = firstLine(x.Errors[0].Message)
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "workflows":
		var pl pipeline
		switch {
		case strings.TrimSpace(p.Pipeline) != "":
			id, err := validID(p.Pipeline, "pipeline")
			if err != nil {
				return sdk.Result{}, err
			}
			if err := c.get(ctx, "/pipeline/"+id, nil, &pl, "pipeline "+id); err != nil {
				return sdk.Result{}, err
			}
		default:
			slug, err := validProject(p.Project)
			if err != nil {
				return sdk.Result{}, err
			}
			if p.Number <= 0 {
				return sdk.Result{}, errors.New("enter the pipeline number (or its ID as pipeline)")
			}
			if err := c.get(ctx, "/project/"+slug+"/pipeline/"+strconv.FormatInt(p.Number, 10), nil, &pl, fmt.Sprintf("pipeline #%d in %s", p.Number, slug)); err != nil {
				return sdk.Result{}, err
			}
		}
		if !uuidRe.MatchString(pl.ID) {
			return sdk.Result{}, errors.New("unexpected answer looking up the pipeline")
		}
		ws, err := all[workflow](ctx, c, "/pipeline/"+pl.ID+"/workflow", nil, 100, "pipeline")
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, w := range ws {
			rows = append(rows, wfRow(w))
		}
		return sdk.JSON(map[string]any{"pipeline": pl.ID, "number": pl.Number, "project": pl.Project, "state": pl.State, "branch": pl.VCS.Branch, "workflows": rows})

	case "jobs":
		id, err := validID(p.Workflow, "workflow")
		if err != nil {
			return sdk.Result{}, err
		}
		w, err := c.workflow(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		js, err := all[job](ctx, c, "/workflow/"+id+"/job", nil, 500, "workflow "+id)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, j := range js {
			row := map[string]any{"name": j.Name, "status": j.Status, "type": j.Type, "started": str(j.StartedAt), "duration": took(str(j.StartedAt), str(j.StoppedAt))}
			if j.Number != nil {
				row["number"] = *j.Number
			}
			rows = append(rows, row)
		}
		out := wfRow(w)
		out["project"], out["pipelineNumber"], out["jobs"] = w.Project, w.PipelineNum, rows
		return sdk.JSON(out)

	case "rerun_workflow", "cancel_workflow":
		id, err := validID(p.Workflow, "workflow")
		if err != nil {
			return sdk.Result{}, err
		}
		w, err := c.workflow(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("%s #%d %s", w.Project, w.PipelineNum, w.Name)
		cancel := call.Action == "cancel_workflow"
		switch {
		case cancel && !active(w.Status):
			return sdk.Result{}, fmt.Errorf("%s is %s, nothing to cancel", target, w.Status)
		case !cancel && active(w.Status):
			return sdk.Result{}, fmt.Errorf("%s is still %s; cancel it or wait for it to finish before rerunning", target, w.Status)
		case !cancel && p.FromFailed && w.Status == "success":
			return sdk.Result{}, fmt.Errorf("%s succeeded, so no job failed; rerun it without fromFailed", target)
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"workflow": w.Name, "status": w.Status, "project": w.Project, "pipeline": w.PipelineNum})
			sum := "Cancel " + target + " (" + w.Status + "); jobs in progress are killed"
			op := "cancel"
			if !cancel {
				op = "rerun"
				sum = "Run " + target + " again, all jobs, as a new workflow"
				if p.FromFailed {
					sum = "Run the failed jobs of " + target + " again as a new workflow"
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: before}}}}, nil
		}
		if cancel {
			if _, err := c.api.Do(ctx, http.MethodPost, "/workflow/"+id+"/cancel", nil, nil, nil); err != nil {
				return sdk.Result{}, friendly(err, "workflow "+id)
			}
			return sdk.JSON(map[string]any{"cancelled": target, "workflow": id})
		}
		var res struct {
			WorkflowID string `json:"workflow_id"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/workflow/"+id+"/rerun", nil, map[string]any{"from_failed": p.FromFailed}, &res); err != nil {
			return sdk.Result{}, friendly(err, "workflow "+id)
		}
		return sdk.JSON(map[string]any{"rerun": target, "workflow": res.WorkflowID, "fromFailed": p.FromFailed})

	case "insights":
		slug, err := validProject(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		branch, err := validBranch(p.Branch)
		if err != nil {
			return sdk.Result{}, err
		}
		window := p.Window
		if window == "" {
			window = "last-30-days"
		}
		if !windows[window] {
			return sdk.Result{}, errors.New("window is one of last-24-hours, last-7-days, last-30-days, last-60-days, last-90-days")
		}
		if branch != "" && p.AllBranches {
			return sdk.Result{}, errors.New("give a branch or allBranches, not both")
		}
		q := url.Values{"reporting-window": {window}}
		if branch != "" {
			q.Set("branch", branch)
		}
		if p.AllBranches {
			q.Set("all-branches", "true")
		}
		type metrics struct {
			Name    string `json:"name"`
			Metrics struct {
				SuccessRate float64 `json:"success_rate"`
				TotalRuns   int64   `json:"total_runs"`
				FailedRuns  int64   `json:"failed_runs"`
				Successful  int64   `json:"successful_runs"`
				Throughput  float64 `json:"throughput"`
				MTTR        float64 `json:"mttr"`
				Credits     float64 `json:"total_credits_used"`
				Duration    struct {
					Min    float64 `json:"min"`
					Mean   float64 `json:"mean"`
					Median float64 `json:"median"`
					P95    float64 `json:"p95"`
					Max    float64 `json:"max"`
				} `json:"duration_metrics"`
			} `json:"metrics"`
			WindowStart string `json:"window_start"`
			WindowEnd   string `json:"window_end"`
		}
		ms, err := all[metrics](ctx, c, "/insights/"+slug+"/workflows", q, 200, "project "+slug)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for _, x := range ms {
			rows = append(rows, map[string]any{"workflow": x.Name, "runs": x.Metrics.TotalRuns, "failed": x.Metrics.FailedRuns,
				"successPercent": math.Round(x.Metrics.SuccessRate*1000) / 10, "throughputPerDay": math.Round(x.Metrics.Throughput*100) / 100,
				"durationMedian": seconds(x.Metrics.Duration.Median), "durationP95": seconds(x.Metrics.Duration.P95), "durationMax": seconds(x.Metrics.Duration.Max),
				"mttr": seconds(x.Metrics.MTTR), "credits": x.Metrics.Credits})
		}
		out := map[string]any{"project": slug, "window": window, "workflows": rows}
		if branch != "" {
			out["branch"] = branch
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
