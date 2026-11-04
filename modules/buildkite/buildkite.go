// Package buildkite works with one Buildkite organization through the REST
// API with an API access token: pipelines, builds and their jobs, the tail
// of a job's log, rebuilding or cancelling a build, and the agents.
package buildkite

import (
	"bufio"
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

// Config is one Buildkite organization.
type Config struct {
	Organization string `json:"organization"` // organization slug
	Token        string `json:"token"`        // secret:// API access token
}

type conn struct {
	api *rest.Client
	org string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.buildkite.com/v2 (tests).
	Base string
}

// New returns the Buildkite module.
func New() *Module { return &Module{} }

const (
	defaultBase = "https://api.buildkite.com/v2"
	maxLogLines = 2000
	maxLogRead  = 32 << 20 // bytes of a log read to find its tail
	maxLineLen  = 2000
)

var (
	slugRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@#*-]{1,255}$`)
	// Terminal colours and Buildkite's timestamp markers (ESC _ bk;t=… BEL).
	ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[_\]][^\x07\x1b]*(\x07|\x1b\\)`)
	states = map[string]bool{"running": true, "scheduled": true, "passed": true, "failing": true, "failed": true, "blocked": true,
		"canceled": true, "canceling": true, "skipped": true, "not_run": true, "finished": true}
	// States a build can be cancelled from.
	cancellable = map[string]bool{"scheduled": true, "running": true, "failing": true, "blocked": true, "creating": true, "waiting": true}
)

func validSlug(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !slugRe.MatchString(v) || strings.Contains(v, "..") {
		return "", fmt.Errorf("the %s is its slug, like my-app", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	pipe := `"pipeline":{"type":"string","description":"Pipeline slug (see pipelines)"}`
	num := `"number":{"type":"integer","minimum":1,"description":"Build number"}`
	return sdk.Manifest{
		ID: "buildkite", Name: "Buildkite", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Buildkite: pipelines, builds and jobs with their status, job log tails, agents, and rebuilding or cancelling builds.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["organization","token"],"properties":{
			"organization":{"type":"string","description":"Organization slug, as in buildkite.com/<slug>"},
			"token":{"type":"string","x-secret":true,"description":"An API access token (Personal Settings, API Access Tokens) with read_pipelines, read_builds, read_build_logs, read_agents, and write_builds for rebuild and cancel"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pipelines", Title: "Pipelines", Description: "The organization's pipelines with repository, default branch and running or scheduled build counts.", Risk: sdk.RiskRead},
			{Name: "builds", Title: "Builds", Description: "Recent builds, newest first, of one pipeline or the whole organization: number, state, branch, commit, creator, duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + pipe + `,"branch":{"type":"string"},"state":{"type":"string","enum":["running","scheduled","passed","failing","failed","blocked","canceled","canceling","skipped","not_run","finished"]},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "build", Title: "Build", Description: "One build with its jobs: id (for job_log), name, type, state, exit status and duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pipeline","number"],"properties":{` + pipe + `,` + num + `}}`)},
			{Name: "job_log", Title: "Job log", Description: "The last lines of one job's log (up to 2000). Logs can hold secrets the build printed, so this is sensitive and stays out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline","number","job"],"properties":{` + pipe + `,` + num + `,"job":{"type":"string","description":"Job ID (see build)"},"lines":{"type":"integer","minimum":1,"maximum":2000,"default":200}}}`)},
			{Name: "rebuild", Title: "Rebuild", Description: "Runs a finished build again as a new build, so its code runs again with the pipeline's secrets and can deploy.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline","number"],"properties":{` + pipe + `,` + num + `}}`)},
			{Name: "cancel_build", Title: "Cancel a build", Description: "Cancels a scheduled, running, failing or blocked build; jobs in progress are stopped.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline","number"],"properties":{` + pipe + `,` + num + `}}`)},
			{Name: "agents", Title: "Agents", Description: "Connected agents with state, host name, version, queue and whether they're busy.", Risk: sdk.RiskRead},
		},
		Resources: []sdk.ResourceSpec{{Kind: "build", Title: "Builds", ListAction: "builds", GetAction: "build", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	org, err := validSlug(c.Organization, "organization")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API access token in the vault and enter its secret:// reference")
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
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, org: org})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Buildkite refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Buildkite refused: the token lacks the scope for this (or isn't allowed in this organization)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("no %s (or the token can't see it)", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Buildkite's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) orgPath() string { return "/organizations/" + c.org }

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) (http.Header, error) {
	hdr, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return hdr, friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var tok struct {
		Scopes []string `json:"scopes"`
	}
	if _, err := c.get(ctx, "/access-token", nil, &tok, "token"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var org struct {
		Name string `json:"name"`
	}
	if _, err := c.get(ctx, c.orgPath(), nil, &org, "organization "+c.org); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := org.Name
	if len(tok.Scopes) > 0 {
		msg += " · scopes: " + strings.Join(tok.Scopes, ", ")
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type job struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Name       string  `json:"name"`
	Label      string  `json:"label"`
	StepKey    string  `json:"step_key"`
	State      string  `json:"state"`
	ExitStatus *int    `json:"exit_status"`
	SoftFailed bool    `json:"soft_failed"`
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

type build struct {
	ID         string  `json:"id"`
	Number     int64   `json:"number"`
	State      string  `json:"state"`
	Blocked    bool    `json:"blocked"`
	Message    string  `json:"message"`
	Commit     string  `json:"commit"`
	Branch     string  `json:"branch"`
	Tag        *string `json:"tag"`
	Source     string  `json:"source"`
	WebURL     string  `json:"web_url"`
	CreatedAt  string  `json:"created_at"`
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Creator    *struct {
		Name string `json:"name"`
	} `json:"creator"`
	Pipeline struct {
		Slug string `json:"slug"`
	} `json:"pipeline"`
	Jobs []job `json:"jobs"`
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

func summary(b build) map[string]any {
	commit := b.Commit
	if len(commit) > 10 {
		commit = commit[:10]
	}
	row := map[string]any{"number": b.Number, "pipeline": b.Pipeline.Slug, "state": b.State, "branch": b.Branch, "commit": commit,
		"message": firstLine(b.Message), "source": b.Source, "created": b.CreatedAt, "duration": took(str(b.StartedAt), str(b.FinishedAt)), "url": b.WebURL}
	if b.Creator != nil {
		row["creator"] = b.Creator.Name
	}
	if b.Blocked {
		row["blocked"] = true
	}
	if t := str(b.Tag); t != "" {
		row["tag"] = t
	}
	return row
}

func (c *conn) build(ctx context.Context, pipe string, n int64) (build, error) {
	if n <= 0 {
		return build{}, errors.New("enter the build number")
	}
	var b build
	if _, err := c.get(ctx, fmt.Sprintf("%s/pipelines/%s/builds/%d", c.orgPath(), pipe, n), nil, &b, fmt.Sprintf("build #%d in %s", n, pipe)); err != nil {
		return build{}, err
	}
	if b.Number != n {
		return build{}, fmt.Errorf("unexpected answer looking up build #%d", n)
	}
	return b, nil
}

// hasNext reads a Link header for a rel="next" page.
func hasNext(h http.Header) bool {
	for _, l := range h.Values("Link") {
		if strings.Contains(l, `rel="next"`) {
			return true
		}
	}
	return false
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Pipeline string `json:"pipeline"`
		Number   int64  `json:"number"`
		Branch   string `json:"branch"`
		State    string `json:"state"`
		Limit    int    `json:"limit"`
		Job      string `json:"job"`
		Lines    int    `json:"lines"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "pipelines":
		type pipeline struct {
			Slug          string  `json:"slug"`
			Name          string  `json:"name"`
			Repository    string  `json:"repository"`
			DefaultBranch string  `json:"default_branch"`
			WebURL        string  `json:"web_url"`
			Running       int     `json:"running_builds_count"`
			Scheduled     int     `json:"scheduled_builds_count"`
			Archived      *string `json:"archived_at"`
		}
		out := []map[string]any{}
		for page := 1; page <= 10; page++ {
			var ps []pipeline
			hdr, err := c.get(ctx, c.orgPath()+"/pipelines", url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}, &ps, "organization "+c.org)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, x := range ps {
				row := map[string]any{"slug": x.Slug, "name": x.Name, "repository": rest.StripUserinfo(x.Repository), "defaultBranch": x.DefaultBranch,
					"runningBuilds": x.Running, "scheduledBuilds": x.Scheduled, "url": x.WebURL}
				if x.Archived != nil {
					row["archived"] = true
				}
				out = append(out, row)
			}
			if !hasNext(hdr) {
				break
			}
		}
		return sdk.JSON(out)

	case "builds":
		path, what := c.orgPath()+"/builds", "organization "+c.org
		if strings.TrimSpace(p.Pipeline) != "" {
			pipe, err := validSlug(p.Pipeline, "pipeline")
			if err != nil {
				return sdk.Result{}, err
			}
			path, what = c.orgPath()+"/pipelines/"+pipe+"/builds", "pipeline "+pipe
		}
		limit := p.Limit
		if limit <= 0 {
			limit = 20
		}
		if limit > 50 {
			return sdk.Result{}, errors.New("limit is at most 50")
		}
		q := url.Values{"per_page": {strconv.Itoa(limit)}, "exclude_jobs": {"true"}}
		if b := strings.TrimSpace(p.Branch); b != "" {
			if !branchRe.MatchString(b) {
				return sdk.Result{}, errors.New("that isn't a branch name")
			}
			q.Set("branch", b)
		}
		if p.State != "" {
			if !states[p.State] {
				return sdk.Result{}, errors.New("state is one of running, scheduled, passed, failing, failed, blocked, canceled, canceling, skipped, not_run, finished")
			}
			q.Set("state", p.State)
		}
		var bs []build
		if _, err := c.get(ctx, path, q, &bs, what); err != nil {
			return sdk.Result{}, err
		}
		if len(bs) > limit {
			bs = bs[:limit]
		}
		out := []map[string]any{}
		for _, b := range bs {
			out = append(out, summary(b))
		}
		return sdk.JSON(out)
	case "build", "job_log", "rebuild", "cancel_build":
	case "agents":
		type agent struct {
			ID              string   `json:"id"`
			Name            string   `json:"name"`
			ConnectionState string   `json:"connection_state"`
			Hostname        string   `json:"hostname"`
			Version         string   `json:"version"`
			MetaData        []string `json:"meta_data"`
			CreatedAt       string   `json:"created_at"`
			LastJobFinished *string  `json:"last_job_finished_at"`
			Paused          bool     `json:"paused"`
			Job             *struct {
				ID string `json:"id"`
			} `json:"job"`
		}
		out := []map[string]any{}
		for page := 1; page <= 10; page++ {
			var as []agent
			hdr, err := c.get(ctx, c.orgPath()+"/agents", url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}, &as, "organization "+c.org)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, a := range as {
				queue := "default"
				for _, md := range a.MetaData {
					if v, ok := strings.CutPrefix(md, "queue="); ok {
						queue = v
					}
				}
				row := map[string]any{"name": a.Name, "state": a.ConnectionState, "hostname": a.Hostname, "version": a.Version,
					"queue": queue, "busy": a.Job != nil, "connected": a.CreatedAt, "lastJobFinished": str(a.LastJobFinished)}
				if a.Paused {
					row["paused"] = true
				}
				out = append(out, row)
			}
			if !hasNext(hdr) {
				break
			}
		}
		return sdk.JSON(out)
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}

	pipe, err := validSlug(p.Pipeline, "pipeline")
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Number <= 0 {
		return sdk.Result{}, errors.New("enter the build number")
	}
	switch call.Action {
	case "build":
		b, err := c.build(ctx, pipe, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(b)
		jobs := []map[string]any{}
		for _, j := range b.Jobs {
			name := j.Name
			if name == "" {
				name = j.Label
			}
			row := map[string]any{"id": j.ID, "type": j.Type, "name": name, "state": j.State, "duration": took(str(j.StartedAt), str(j.FinishedAt))}
			if j.StepKey != "" {
				row["key"] = j.StepKey
			}
			if j.ExitStatus != nil {
				row["exitStatus"] = *j.ExitStatus
			}
			if j.SoftFailed {
				row["softFailed"] = true
			}
			jobs = append(jobs, row)
		}
		out["jobs"] = jobs
		return sdk.JSON(out)

	case "job_log":
		jid := strings.ToLower(strings.TrimSpace(p.Job))
		if !uuidRe.MatchString(jid) {
			return sdk.Result{}, errors.New("the job is its ID, a UUID (see build)")
		}
		n := p.Lines
		if n == 0 {
			n = 200
		}
		if n < 1 || n > maxLogLines {
			return sdk.Result{}, fmt.Errorf("lines is between 1 and %d", maxLogLines)
		}
		b, err := c.build(ctx, pipe, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		var found *job
		for i, j := range b.Jobs {
			if strings.EqualFold(j.ID, jid) {
				found = &b.Jobs[i]
			}
		}
		if found == nil {
			return sdk.Result{}, fmt.Errorf("build #%d has no job %s (see build)", p.Number, jid)
		}
		if found.Type != "script" {
			return sdk.Result{}, fmt.Errorf("job %s is a %s step, which has no log", jid, found.Type)
		}
		res, err := c.api.Send(ctx, http.MethodGet, fmt.Sprintf("%s/pipelines/%s/builds/%d/jobs/%s/log.txt", c.orgPath(), pipe, p.Number, jid), nil, nil, http.Header{"Accept": {"text/plain"}})
		if err != nil {
			return sdk.Result{}, friendly(err, "log for job "+jid)
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			return sdk.Result{}, fmt.Errorf("Buildkite answered %s for the log", res.Status)
		}
		lines, read, more, err := tail(io.LimitReader(res.Body, maxLogRead+1), n)
		if err != nil {
			return sdk.Result{}, err
		}
		name := found.Name
		if name == "" {
			name = found.Label
		}
		out := map[string]any{"job": name, "state": found.State, "lines": lines, "bytesRead": read}
		if found.ExitStatus != nil {
			out["exitStatus"] = *found.ExitStatus
		}
		if more {
			out["note"] = fmt.Sprintf("the log is longer than %d MiB; these are the last lines of its first %d MiB", maxLogRead>>20, maxLogRead>>20)
		}
		return sdk.JSON(out)

	case "rebuild", "cancel_build":
		b, err := c.build(ctx, pipe, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("%s/%s#%d", c.org, pipe, b.Number)
		cancel := call.Action == "cancel_build"
		if cancel && !cancellable[b.State] {
			return sdk.Result{}, fmt.Errorf("%s is %s, nothing to cancel", target, b.State)
		}
		if !cancel && cancellable[b.State] {
			return sdk.Result{}, fmt.Errorf("%s is still %s; cancel it or wait for it to finish before rebuilding", target, b.State)
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"state": b.State, "branch": b.Branch, "source": b.Source})
			sum := fmt.Sprintf("Run %s again (%s) as a new build", target, b.Branch)
			op := "rebuild"
			if cancel {
				op, sum = "cancel", fmt.Sprintf("Cancel %s (%s); jobs in progress are stopped", target, b.State)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: op, Before: before}}}}, nil
		}
		path := fmt.Sprintf("%s/pipelines/%s/builds/%d/", c.orgPath(), pipe, b.Number)
		if cancel {
			path += "cancel"
		} else {
			path += "rebuild"
		}
		var nb build
		if _, err := c.api.Do(ctx, http.MethodPut, path, nil, nil, &nb); err != nil {
			if rest.IsStatus(err, http.StatusUnprocessableEntity) {
				return sdk.Result{}, fmt.Errorf("Buildkite wouldn't %s %s: %v", verb(cancel), target, err)
			}
			return sdk.Result{}, friendly(err, "build "+target)
		}
		if cancel {
			return sdk.JSON(map[string]any{"cancelled": target, "state": nb.State})
		}
		return sdk.JSON(map[string]any{"rebuilt": target, "build": summary(nb)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func verb(cancel bool) string {
	if cancel {
		return "cancel"
	}
	return "rebuild"
}

// tail keeps the last n lines of r, each cut at maxLineLen, with terminal
// codes and Buildkite's timestamp markers removed.
func tail(r io.Reader, n int) (lines []string, read int64, more bool, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	ring := make([]string, 0, n)
	start := 0
	var cur []byte
	push := func(b []byte) {
		s := strings.TrimRight(strings.ToValidUTF8(string(b), "�"), "\r\n")
		s = ansiRe.ReplaceAllString(s, "")
		if i := strings.LastIndexByte(s, '\r'); i >= 0 { // progress bars: keep what was drawn last
			s = s[i+1:]
		}
		if r := []rune(s); len(r) > maxLineLen {
			s = string(r[:maxLineLen]) + "…"
		}
		if len(ring) < n {
			ring = append(ring, s)
			return
		}
		ring[start] = s
		start = (start + 1) % n
	}
	for {
		chunk, e := br.ReadSlice('\n')
		read += int64(len(chunk))
		if len(cur) < maxLineLen*4 {
			cur = append(cur, chunk...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' || (e == io.EOF && len(cur) > 0) {
			push(cur)
			cur = cur[:0]
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, read, false, e
		}
	}
	if read > maxLogRead {
		more = true
	}
	return append(ring[start:], ring[:start]...), read, more, nil
}
