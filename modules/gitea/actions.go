package gitea

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

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	maxLogLines = 2000
	maxLogBytes = 256 << 10
)

var (
	workflowRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}\.ya?ml$`)
	refRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
	inputRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,99}$`)
)

type actionsInput struct {
	ID         int64
	Job        int64
	Lines      int
	FailedOnly bool
	Workflow   string
	Ref        string
	Inputs     map[string]string
}

type workflowRun struct {
	ID         int64  `json:"id"`
	Number     int64  `json:"run_number"`
	Attempt    int64  `json:"run_attempt"`
	Title      string `json:"display_title"`
	Workflow   string `json:"path"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Branch     string `json:"head_branch"`
	SHA        string `json:"head_sha"`
	HTMLURL    string `json:"html_url"`
	Started    string `json:"started_at"`
	Completed  string `json:"completed_at"`
}

const notSupported = "this server doesn't have that Actions API"

// actions runs run, job_log, rerun and dispatch_workflow. repo is already
// validated and rp is its API path.
func (c *conn) actions(ctx context.Context, call sdk.Call, repo, rp string, in actionsInput) (sdk.Result, error) {
	getRun := func() (workflowRun, error) {
		if in.ID <= 0 {
			return workflowRun{}, errors.New("enter the run id (from runs)")
		}
		var r workflowRun
		if _, err := c.api.Do(ctx, http.MethodGet, rp+"/actions/runs/"+strconv.FormatInt(in.ID, 10), nil, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return r, fmt.Errorf("no run %d in %s (or %s: viewing one run needs Gitea 1.23+ or a recent Forgejo)", in.ID, repo, notSupported)
			}
			return r, err
		}
		r.Title = rest.Redact(r.Title) // a push's commit message
		return r, nil
	}
	switch call.Action {
	case "run":
		r, err := getRun()
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"run": r}
		var jobs struct {
			Jobs []struct {
				ID         int64  `json:"id"`
				Name       string `json:"name"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
				Runner     string `json:"runner_name"`
				Started    string `json:"started_at"`
				Completed  string `json:"completed_at"`
				Steps      []struct {
					Number     int    `json:"number"`
					Name       string `json:"name"`
					Status     string `json:"status"`
					Conclusion string `json:"conclusion"`
				} `json:"steps"`
			} `json:"jobs"`
		}
		_, err = c.api.Do(ctx, http.MethodGet, rp+"/actions/runs/"+strconv.FormatInt(in.ID, 10)+"/jobs", url.Values{"limit": {"50"}}, nil, &jobs)
		switch {
		case err == nil:
			out["jobs"] = jobs.Jobs
		case rest.IsStatus(err, http.StatusNotFound):
			out["jobs"] = nil
			out["note"] = "this server doesn't list a run's jobs (needs Gitea 1.23+)"
		default:
			return sdk.Result{}, err
		}
		return sdk.JSON(out)

	case "job_log":
		if in.Job <= 0 {
			return sdk.Result{}, errors.New("enter the job id (from run)")
		}
		lines := in.Lines
		if lines <= 0 {
			lines = 200
		}
		if lines > maxLogLines {
			lines = maxLogLines
		}
		text, err := c.raw(ctx, rp+"/actions/jobs/"+strconv.FormatInt(in.Job, 10)+"/logs")
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("no job %d in %s (or %s: job logs need Gitea 1.23+)", in.Job, repo, notSupported)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		tail, total, cut := tailLines(text, lines)
		return sdk.JSON(map[string]any{"job": in.Job, "lines": total, "truncated": cut, "log": tail})

	case "rerun":
		r, err := getRun()
		if err != nil {
			return sdk.Result{}, err
		}
		what := "all jobs"
		path := rp + "/actions/runs/" + strconv.FormatInt(in.ID, 10) + "/rerun"
		if in.FailedOnly {
			what, path = "the failed jobs", path+"-failed-jobs"
		}
		target := fmt.Sprintf("%s run %d", repo, r.ID)
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"title": r.Title, "workflow": r.Workflow, "branch": r.Branch, "status": r.Status, "conclusion": r.Conclusion})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Rerun %s of %q (%s on %s)", what, r.Title, r.Workflow, r.Branch),
				Changes: []sdk.Change{{Target: target, Op: "rerun", Before: before}}}}, nil
		}
		var nr workflowRun
		if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, &nr); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusMethodNotAllowed) {
				return sdk.Result{}, errors.New(notSupported + ": rerunning needs Gitea 1.27 or later")
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"rerun": target, "jobs": what, "url": r.HTMLURL})

	case "dispatch_workflow":
		if !workflowRe.MatchString(in.Workflow) {
			return sdk.Result{}, errors.New("the workflow is its file name in .gitea/workflows (or .github/workflows), e.g. deploy.yml")
		}
		ref := strings.TrimPrefix(strings.TrimSpace(in.Ref), "refs/heads/")
		if !refRe.MatchString(ref) || strings.Contains(ref, "..") || strings.HasSuffix(ref, "/") {
			return sdk.Result{}, errors.New("the ref is a branch or tag name")
		}
		if len(in.Inputs) > 25 {
			return sdk.Result{}, errors.New("a workflow takes at most 25 inputs")
		}
		for k := range in.Inputs {
			if !inputRe.MatchString(k) {
				return sdk.Result{}, fmt.Errorf("%q isn't an input name", k)
			}
		}
		target := repo + " " + in.Workflow
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"ref": ref, "inputs": in.Inputs})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Start %s on %s", target, ref),
				Changes: []sdk.Change{{Target: target, Op: "dispatch", After: after}}}}, nil
		}
		body := map[string]any{"ref": ref}
		if len(in.Inputs) > 0 {
			body["inputs"] = in.Inputs
		}
		if _, err := c.api.Do(ctx, http.MethodPost, rp+"/actions/workflows/"+in.Workflow+"/dispatches", nil, body, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no workflow %s with workflow_dispatch in %s (or %s: needs Gitea 1.23+ or Forgejo 9+)", in.Workflow, repo, notSupported)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"started": target, "ref": ref})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// raw GETs a text answer (at most maxLogBytes*4 read, the end kept).
func (c *conn) raw(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api.Base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Conduit")
	if c.api.Auth != nil {
		if err := c.api.Auth(ctx, req); err != nil {
			return "", err
		}
	}
	res, err := c.api.HTTP.Do(req)
	if err != nil {
		return "", rest.TransportError(err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", &rest.Error{Status: res.StatusCode, Message: res.Status}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	return string(b), err
}

// tailLines keeps the last n lines and at most maxLogBytes.
func tailLines(s string, n int) (string, int, bool) {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return "", 0, false
	}
	all := strings.Split(s, "\n")
	cut := false
	if len(all) > n {
		all, cut = all[len(all)-n:], true
	}
	out := strings.Join(all, "\n") + "\n"
	if len(out) > maxLogBytes {
		out = out[len(out)-maxLogBytes:]
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			out = out[i+1:]
		}
		cut = true
	}
	return out, len(strings.Split(s, "\n")), cut
}
