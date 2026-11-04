// Package woodpecker works with a Woodpecker CI server (API of Woodpecker
// 2 and 3): repositories, pipelines with their workflows and steps, step
// logs, and restarting or cancelling pipelines.
package woodpecker

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

// Config is one Woodpecker server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://ci.example.com
	Token string `json:"token"` // secret:// personal access token
}

type conn struct {
	api  *rest.Client
	base string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Woodpecker module.
func New() *Module { return &Module{} }

// Forge owner and repository names: letters, digits, - _ and . (not dots
// only).
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func validRepo(s string) (string, error) {
	o, r, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || !nameRe.MatchString(o) || !nameRe.MatchString(r) || strings.Trim(o, ".") == "" || strings.Trim(r, ".") == "" {
		return "", errors.New("the repository is owner/name, e.g. elchi/conduit")
	}
	return o + "/" + r, nil
}

const (
	maxLogLines = 2000
	maxLogBytes = 256 << 10
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"owner/name"}`
	num := `"number":{"type":"integer","minimum":1,"description":"Pipeline number"}`
	return sdk.Manifest{
		ID: "woodpecker", Name: "Woodpecker CI", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Woodpecker CI pipelines: status, steps and logs, and restarting or cancelling them.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://ci.example.com"},
			"token":{"type":"string","x-secret":true,"description":"Personal access token (your user menu, Personal Access Token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repos", Title: "Repositories", Description: "Repositories the token's user can see, active ones first.", Risk: sdk.RiskRead},
			{Name: "pipelines", Title: "Pipelines", Description: "Recent pipelines of a repository, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"branch":{"type":"string"},"limit":{"type":"integer","default":20,"maximum":50}}}`)},
			{Name: "pipeline", Title: "Pipeline", Description: "One pipeline with its workflows and steps (step ids for logs).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "logs", Title: "Step log", Description: "The end of one step's log (up to 2000 lines). Woodpecker masks registered secrets, but logs can still hold sensitive output, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number","step"],"properties":{` + repo + `,` + num + `,"step":{"type":"string","description":"Step name or id (from pipeline)"},"lines":{"type":"integer","default":200,"maximum":2000}}}`)},
			{Name: "restart", Title: "Restart a pipeline", Description: "Runs the pipeline again as a new pipeline (its code runs with the repository's secrets).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "cancel", Title: "Cancel a pipeline", Description: "Stops a pending or running pipeline; steps in progress are killed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "pipeline", Title: "Pipelines", ListAction: "pipelines", GetAction: "pipeline", ViewHint: "table"}},
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
		return errors.New("the address is like https://ci.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	tok := c.Token
	api := rest.New(base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, base: base})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("Woodpecker refused the token")
	}
	return err
}

type repo struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Active   bool   `json:"active"`
	Private  bool   `json:"private"`
	Branch   string `json:"default_branch"`
	ForgeURL string `json:"forge_url"`
}

func (c *conn) repo(ctx context.Context, name string) (repo, error) {
	full, err := validRepo(name)
	if err != nil {
		return repo{}, err
	}
	var r repo
	if err := c.do(ctx, http.MethodGet, "/repos/lookup/"+full, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return repo{}, fmt.Errorf("no repository %s in Woodpecker (or it isn't activated)", full)
		}
		return repo{}, err
	}
	if r.ID <= 0 {
		return repo{}, fmt.Errorf("unexpected answer looking up %s", full)
	}
	return r, nil
}

type step struct {
	ID       int64  `json:"id"`
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	State    string `json:"state"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
}

type workflow struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Error    string `json:"error"`
	Children []step `json:"children"`
}

type pipeline struct {
	ID        int64      `json:"id"`
	Number    int        `json:"number"`
	Status    string     `json:"status"`
	Event     string     `json:"event"`
	Branch    string     `json:"branch"`
	Ref       string     `json:"ref"`
	Commit    string     `json:"commit"`
	Message   string     `json:"message"`
	Author    string     `json:"author"`
	Created   int64      `json:"created"`
	Started   int64      `json:"started"`
	Finished  int64      `json:"finished"`
	ForgeURL  string     `json:"forge_url"`
	Workflows []workflow `json:"workflows"`
}

func stamp(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func took(start, end int64) string {
	if start <= 0 || end < start {
		return ""
	}
	return (time.Duration(end-start) * time.Second).String()
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

func (c *conn) summary(full string, p pipeline) map[string]any {
	commit := p.Commit
	if len(commit) > 10 {
		commit = commit[:10]
	}
	return map[string]any{"number": p.Number, "status": p.Status, "event": p.Event, "branch": p.Branch, "commit": commit,
		"message": firstLine(p.Message), "author": p.Author, "created": stamp(p.Created), "duration": took(p.Started, p.Finished),
		"url": c.base + "/repos/" + full + "/pipeline/" + strconv.Itoa(p.Number)}
}

func (c *conn) pipeline(ctx context.Context, r repo, n int) (pipeline, error) {
	if n <= 0 {
		return pipeline{}, errors.New("enter the pipeline number")
	}
	var p pipeline
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%d/pipelines/%d", r.ID, n), nil, &p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return pipeline{}, fmt.Errorf("no pipeline #%d in %s", n, r.FullName)
		}
		return pipeline{}, err
	}
	return p, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Login string `json:"login"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	_ = c.do(ctx, http.MethodGet, "/version", nil, &v)
	msg := "signed in as " + u.Login
	if v.Version != "" {
		msg += " · " + v.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Repo   string `json:"repo"`
		Number int    `json:"number"`
		Branch string `json:"branch"`
		Limit  int    `json:"limit"`
		Step   any    `json:"step"`
		Lines  int    `json:"lines"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "repos" {
		var rs []repo
		if err := c.do(ctx, http.MethodGet, "/user/repos", nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, active := range []bool{true, false} {
			for _, r := range rs {
				if r.Active == active {
					out = append(out, map[string]any{"repo": r.FullName, "active": r.Active, "private": r.Private, "defaultBranch": r.Branch, "forgeUrl": r.ForgeURL})
				}
			}
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "pipelines", "pipeline", "logs", "restart", "cancel":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	r, err := c.repo(ctx, p.Repo)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "pipelines":
		limit := p.Limit
		if limit <= 0 || limit > 50 {
			limit = 20
		}
		q := url.Values{"page": {"1"}, "perPage": {strconv.Itoa(limit)}}
		if b := strings.TrimSpace(p.Branch); b != "" {
			q.Set("branch", b)
		}
		var ps []pipeline
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%d/pipelines", r.ID), q, &ps); err != nil {
			return sdk.Result{}, err
		}
		if len(ps) > limit {
			ps = ps[:limit]
		}
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, c.summary(r.FullName, x))
		}
		return sdk.JSON(out)

	case "pipeline":
		pl, err := c.pipeline(ctx, r, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(r.FullName, pl)
		wfs := []map[string]any{}
		for _, w := range pl.Workflows {
			steps := []map[string]any{}
			for _, s := range w.Children {
				row := map[string]any{"id": s.ID, "name": s.Name, "state": s.State, "duration": took(s.Started, s.Finished)}
				if s.ExitCode != 0 {
					row["exitCode"] = s.ExitCode
				}
				if s.Error != "" {
					row["error"] = rest.Redact(s.Error)
				}
				steps = append(steps, row)
			}
			wfs = append(wfs, map[string]any{"name": w.Name, "state": w.State, "error": rest.Redact(w.Error), "steps": steps})
		}
		out["workflows"] = wfs
		return sdk.JSON(out)

	case "logs":
		pl, err := c.pipeline(ctx, r, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		var want string
		switch v := p.Step.(type) {
		case string:
			want = strings.TrimSpace(v)
		case float64:
			want = strconv.FormatInt(int64(v), 10)
		}
		if want == "" {
			return sdk.Result{}, errors.New("enter the step name or id (see pipeline)")
		}
		var found *step
		var names []string
		for _, w := range pl.Workflows {
			for i, s := range w.Children {
				names = append(names, s.Name)
				if strconv.FormatInt(s.ID, 10) == want || s.Name == want || w.Name+"/"+s.Name == want {
					if found != nil && found.ID != s.ID {
						return sdk.Result{}, fmt.Errorf("several steps are called %s; use workflow/step or the step id", want)
					}
					found = &w.Children[i]
				}
			}
		}
		if found == nil {
			return sdk.Result{}, fmt.Errorf("pipeline #%d has no step %s (steps: %s)", p.Number, want, strings.Join(names, ", "))
		}
		lines := p.Lines
		if lines <= 0 {
			lines = 200
		}
		if lines > maxLogLines {
			lines = maxLogLines
		}
		var entries []struct {
			Line int    `json:"line"`
			Data []byte `json:"data"` // base64 in JSON
			Time int64  `json:"time"`
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%d/logs/%d/%d", r.ID, pl.Number, found.ID), nil, &entries); err != nil {
			return sdk.Result{}, err
		}
		total := len(entries)
		if total > lines {
			entries = entries[total-lines:]
		}
		var b strings.Builder
		for _, e := range entries {
			b.WriteString(strings.TrimRight(string(e.Data), "\n"))
			b.WriteByte('\n')
		}
		text := b.String()
		truncated := total > lines
		if len(text) > maxLogBytes {
			text = text[len(text)-maxLogBytes:]
			if i := strings.IndexByte(text, '\n'); i >= 0 {
				text = text[i+1:]
			}
			truncated = true
		}
		return sdk.JSON(map[string]any{"step": found.Name, "state": found.State, "exitCode": found.ExitCode, "lines": total, "truncated": truncated, "log": text})

	case "restart", "cancel":
		pl, err := c.pipeline(ctx, r, p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		active := pl.Status == "pending" || pl.Status == "running" || pl.Status == "blocked"
		if call.Action == "cancel" && !active {
			return sdk.Result{}, fmt.Errorf("#%d is %s, nothing to cancel", p.Number, pl.Status)
		}
		target := fmt.Sprintf("%s#%d", r.FullName, p.Number)
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"status": pl.Status, "event": pl.Event, "branch": pl.Branch, "message": firstLine(pl.Message)})
			sum := fmt.Sprintf("Run %s again (%s on %s) as a new pipeline", target, pl.Event, pl.Branch)
			if call.Action == "cancel" {
				sum = fmt.Sprintf("Cancel %s (%s)", target, pl.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: call.Action, Before: before}}}}, nil
		}
		path := fmt.Sprintf("/repos/%d/pipelines/%d", r.ID, p.Number)
		if call.Action == "cancel" {
			path += "/cancel"
		}
		var np pipeline
		if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, &np); err != nil {
			return sdk.Result{}, err
		}
		if call.Action == "cancel" {
			return sdk.JSON(map[string]any{"cancelled": target})
		}
		return sdk.JSON(map[string]any{"restarted": target, "pipeline": c.summary(r.FullName, np)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
