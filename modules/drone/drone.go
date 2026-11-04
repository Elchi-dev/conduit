// Package drone works with a Drone CI server through its API with a
// personal token: repositories, builds with their stages and steps, step
// logs, and restarting, cancelling or promoting builds.
package drone

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

// Config is one Drone server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://drone.example.com
	Token string `json:"token"` // secret:// personal token
}

type conn struct {
	api  *rest.Client
	base string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Drone module.
func New() *Module { return &Module{} }

const (
	maxLogLines = 2000
	maxLogBytes = 256 << 10
	maxLineLen  = 2000
)

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@#-]{1,255}$`)
	targetRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
)

func validRepo(s string) (string, error) {
	o, r, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || !nameRe.MatchString(o) || !nameRe.MatchString(r) || strings.Trim(o, ".") == "" || strings.Trim(r, ".") == "" {
		return "", errors.New("the repository is owner/name, e.g. elchi/conduit")
	}
	return o + "/" + r, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"owner/name"}`
	num := `"number":{"type":"integer","minimum":1,"description":"Build number"}`
	return sdk.Manifest{
		ID: "drone", Name: "Drone CI", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Drone CI: repositories, builds with stages and steps, step logs, and restarting, cancelling or promoting builds.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://drone.example.com"},
			"token":{"type":"string","x-secret":true,"description":"Your personal token (User settings, Your Personal Token)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repos", Title: "Repositories", Description: "Repositories the token's user can see, active ones first, with their latest build.", Risk: sdk.RiskRead},
			{Name: "builds", Title: "Builds", Description: "Recent builds of a repository, newest first: number, status, event, branch, commit, author, duration.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"branch":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20}}}`)},
			{Name: "build", Title: "Build", Description: "One build with its stages and steps (numbers for logs), states, exit codes and durations.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "logs", Title: "Step log", Description: "The end of one step's log (up to 2000 lines). Drone masks registered secrets, but logs can still hold sensitive output, so they stay out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number","step"],"properties":{` + repo + `,` + num + `,"step":{"type":"string","description":"Step name, stage/step, or stage.step numbers like 1.2 (see build)"},"lines":{"type":"integer","minimum":1,"maximum":2000,"default":200}}}`)},
			{Name: "restart", Title: "Restart a build", Description: "Runs a finished build again as a new build (its code runs with the repository's secrets).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "cancel", Title: "Cancel a build", Description: "Stops a pending, running or blocked build; steps in progress are killed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number"],"properties":{` + repo + `,` + num + `}}`)},
			{Name: "promote", Title: "Promote a build", Description: "Promotes a successful build to a deployment target (e.g. production): a new build runs the pipelines for that target, which usually deploys.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","number","target"],"properties":{` + repo + `,` + num + `,"target":{"type":"string","description":"Deployment target, e.g. production"}}}`)},
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
	u, err := url.Parse(strings.TrimSpace(c.URL))
	prefix := ""
	if err == nil {
		prefix = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is like https://drone.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the personal token in the vault and enter its secret:// reference")
	}
	base := u.Scheme + "://" + u.Host + prefix
	ref := c.Token
	api := rest.New(base+"/api", func(ctx context.Context, r *http.Request) error {
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
	m.set.Put(id, &conn{api: api, base: base})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Drone refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Drone refused: the token's user lacks the permission for this on the repository")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("no %s in Drone (or it isn't activated)", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	return friendly(err, what)
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
	if err := c.do(ctx, http.MethodGet, "/user", nil, &u, "user"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + u.Login}
}

type step struct {
	Number   int    `json:"number"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error"`
	Started  int64  `json:"started"`
	Stopped  int64  `json:"stopped"`
}

type stage struct {
	Number   int    `json:"number"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error"`
	Machine  string `json:"machine"`
	Started  int64  `json:"started"`
	Stopped  int64  `json:"stopped"`
	Steps    []step `json:"steps"`
}

type build struct {
	ID       int64   `json:"id"`
	Number   int64   `json:"number"`
	Parent   int64   `json:"parent"`
	Status   string  `json:"status"`
	Event    string  `json:"event"`
	Ref      string  `json:"ref"`
	Target   string  `json:"target"`
	Source   string  `json:"source"`
	After    string  `json:"after"`
	Message  string  `json:"message"`
	Author   string  `json:"author_login"`
	Sender   string  `json:"sender"`
	DeployTo string  `json:"deploy_to"`
	Created  int64   `json:"created"`
	Started  int64   `json:"started"`
	Finished int64   `json:"finished"`
	Stages   []stage `json:"stages"`
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

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func (c *conn) summary(full string, b build) map[string]any {
	commit := b.After
	if len(commit) > 10 {
		commit = commit[:10]
	}
	row := map[string]any{"number": b.Number, "status": b.Status, "event": b.Event, "branch": b.Target, "commit": commit,
		"message": firstLine(b.Message), "author": b.Author, "created": stamp(b.Created), "duration": took(b.Started, b.Finished),
		"url": c.base + "/" + full + "/" + strconv.FormatInt(b.Number, 10)}
	if b.DeployTo != "" {
		row["deployTo"] = b.DeployTo
	}
	if b.Parent > 0 {
		row["parent"] = b.Parent
	}
	return row
}

func (c *conn) build(ctx context.Context, full string, n int64) (build, error) {
	var b build
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/builds/%d", full, n), nil, &b, fmt.Sprintf("build #%d in %s", n, full)); err != nil {
		return build{}, err
	}
	if b.Number != n {
		return build{}, fmt.Errorf("unexpected answer looking up build #%d", n)
	}
	return b, nil
}

func active(status string) bool {
	return status == "pending" || status == "running" || status == "blocked" || status == "waiting_on_dependencies"
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Repo   string `json:"repo"`
		Number int64  `json:"number"`
		Branch string `json:"branch"`
		Limit  int    `json:"limit"`
		Step   any    `json:"step"`
		Lines  int    `json:"lines"`
		Target string `json:"target"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "repos" {
		var rs []struct {
			Slug       string `json:"slug"`
			Active     bool   `json:"active"`
			Private    bool   `json:"private"`
			Visibility string `json:"visibility"`
			Branch     string `json:"default_branch"`
			Link       string `json:"link"`
			Build      *build `json:"build"`
		}
		if err := c.do(ctx, http.MethodGet, "/user/repos", url.Values{"latest": {"true"}}, &rs, "repositories"); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, act := range []bool{true, false} {
			for _, r := range rs {
				if r.Active != act {
					continue
				}
				row := map[string]any{"repo": r.Slug, "active": r.Active, "private": r.Private, "defaultBranch": r.Branch, "link": rest.StripUserinfo(r.Link)}
				if r.Build != nil && r.Build.Number > 0 {
					row["lastBuild"] = map[string]any{"number": r.Build.Number, "status": r.Build.Status, "branch": r.Build.Target, "created": stamp(r.Build.Created)}
				}
				out = append(out, row)
			}
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "builds", "build", "logs", "restart", "cancel", "promote":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	full, err := validRepo(p.Repo)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "builds" {
		limit := p.Limit
		if limit <= 0 {
			limit = 20
		}
		if limit > 50 {
			return sdk.Result{}, errors.New("limit is at most 50")
		}
		q := url.Values{"page": {"1"}, "per_page": {strconv.Itoa(limit)}}
		branch := strings.TrimSpace(p.Branch)
		if branch != "" {
			if !branchRe.MatchString(branch) {
				return sdk.Result{}, errors.New("that isn't a branch name")
			}
			q.Set("branch", branch)
		}
		var bs []build
		if err := c.do(ctx, http.MethodGet, "/repos/"+full+"/builds", q, &bs, "repository "+full); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range bs {
			if branch != "" && b.Target != branch {
				continue // servers that ignore the filter
			}
			if len(out) == limit {
				break
			}
			out = append(out, c.summary(full, b))
		}
		return sdk.JSON(out)
	}
	if p.Number <= 0 {
		return sdk.Result{}, errors.New("enter the build number")
	}
	var target string
	if call.Action == "promote" {
		target = strings.TrimSpace(p.Target)
		if !targetRe.MatchString(target) {
			return sdk.Result{}, errors.New("the target is a deployment target name, like production")
		}
	}
	var want string
	lines := p.Lines
	if call.Action == "logs" {
		switch v := p.Step.(type) {
		case string:
			want = strings.TrimSpace(v)
		case float64:
			want = strconv.FormatFloat(v, 'f', -1, 64)
		}
		if want == "" || len(want) > 200 {
			return sdk.Result{}, errors.New("enter the step name, stage/step, or stage.step numbers (see build)")
		}
		if lines == 0 {
			lines = 200
		}
		if lines < 1 || lines > maxLogLines {
			return sdk.Result{}, fmt.Errorf("lines is between 1 and %d", maxLogLines)
		}
	}
	b, err := c.build(ctx, full, p.Number)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "build":
		out := c.summary(full, b)
		stages := []map[string]any{}
		for _, s := range b.Stages {
			steps := []map[string]any{}
			for _, st := range s.Steps {
				row := map[string]any{"number": st.Number, "name": st.Name, "status": st.Status, "duration": took(st.Started, st.Stopped)}
				if st.ExitCode != 0 {
					row["exitCode"] = st.ExitCode
				}
				if st.Error != "" {
					row["error"] = firstLine(st.Error)
				}
				steps = append(steps, row)
			}
			row := map[string]any{"number": s.Number, "name": s.Name, "status": s.Status, "duration": took(s.Started, s.Stopped), "steps": steps}
			if s.Error != "" {
				row["error"] = firstLine(s.Error)
			}
			stages = append(stages, row)
		}
		out["stages"] = stages
		return sdk.JSON(out)

	case "logs":
		var fs *stage
		var fst *step
		var names []string
		for i := range b.Stages {
			s := &b.Stages[i]
			for j := range s.Steps {
				st := &s.Steps[j]
				names = append(names, s.Name+"/"+st.Name)
				if want == st.Name || want == s.Name+"/"+st.Name || want == fmt.Sprintf("%d.%d", s.Number, st.Number) {
					if fst != nil {
						return sdk.Result{}, fmt.Errorf("several steps are called %s; use stage/step or stage.step numbers", want)
					}
					fs, fst = s, st
				}
			}
		}
		if fst == nil {
			return sdk.Result{}, fmt.Errorf("build #%d has no step %s (steps: %s)", p.Number, want, strings.Join(names, ", "))
		}
		var entries []struct {
			Pos int    `json:"pos"`
			Out string `json:"out"`
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/builds/%d/logs/%d/%d", full, b.Number, fs.Number, fst.Number), nil, &entries, "log for that step"); err != nil {
			return sdk.Result{}, err
		}
		var all []string
		for _, e := range entries {
			for _, l := range strings.Split(strings.TrimRight(e.Out, "\n"), "\n") {
				l = ansiRe.ReplaceAllString(strings.TrimRight(l, "\r"), "")
				if r := []rune(l); len(r) > maxLineLen {
					l = string(r[:maxLineLen]) + "…"
				}
				all = append(all, l)
			}
		}
		total := len(all)
		truncated := total > lines
		if truncated {
			all = all[total-lines:]
		}
		size := 0
		cut := 0
		for i := len(all) - 1; i >= 0; i-- {
			size += len(all[i]) + 1
			if size > maxLogBytes {
				cut = i + 1
				truncated = true
				break
			}
		}
		all = all[cut:]
		return sdk.JSON(map[string]any{"stage": fs.Name, "step": fst.Name, "status": fst.Status, "exitCode": fst.ExitCode, "totalLines": total, "truncated": truncated, "lines": all})

	case "restart", "cancel", "promote":
		ref := fmt.Sprintf("%s#%d", full, b.Number)
		switch {
		case call.Action == "cancel" && !active(b.Status):
			return sdk.Result{}, fmt.Errorf("%s is %s, nothing to cancel", ref, b.Status)
		case call.Action == "restart" && active(b.Status):
			return sdk.Result{}, fmt.Errorf("%s is still %s; cancel it or wait for it to finish before restarting", ref, b.Status)
		case call.Action == "promote" && b.Status != "success":
			return sdk.Result{}, fmt.Errorf("%s is %s; only a successful build can be promoted", ref, b.Status)
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"status": b.Status, "event": b.Event, "branch": b.Target})
			var sum string
			ch := sdk.Change{Target: ref, Op: call.Action, Before: before}
			switch call.Action {
			case "restart":
				sum = fmt.Sprintf("Run %s again (%s on %s) as a new build", ref, b.Event, b.Target)
			case "cancel":
				sum = fmt.Sprintf("Cancel %s (%s); steps in progress are killed", ref, b.Status)
			case "promote":
				sum = fmt.Sprintf("Promote %s (%s) to %s: a new build runs that target's pipelines", ref, b.Target, target)
				ch.After, _ = json.Marshal(map[string]any{"deployTo": target})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
		}
		path := fmt.Sprintf("/repos/%s/builds/%d", full, b.Number)
		switch call.Action {
		case "cancel":
			if _, err := c.api.Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
				return sdk.Result{}, friendly(err, "build "+ref)
			}
			return sdk.JSON(map[string]any{"cancelled": ref})
		case "restart":
			var nb build
			if _, err := c.api.Do(ctx, http.MethodPost, path, nil, nil, &nb); err != nil {
				return sdk.Result{}, friendly(err, "build "+ref)
			}
			return sdk.JSON(map[string]any{"restarted": ref, "build": c.summary(full, nb)})
		case "promote":
			var nb build
			if _, err := c.api.Do(ctx, http.MethodPost, path+"/promote", url.Values{"target": {target}}, nil, &nb); err != nil {
				return sdk.Result{}, friendly(err, "build "+ref)
			}
			return sdk.JSON(map[string]any{"promoted": ref, "target": target, "build": c.summary(full, nb)})
		}
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
