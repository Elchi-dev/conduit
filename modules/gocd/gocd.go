// Package gocd works with a GoCD server through its API and a personal
// access token: pipelines with their groups and last runs, a pipeline's
// history and the stages and jobs of a run, running a pipeline (with
// declared environment variables), and pausing or unpausing it.
package gocd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one GoCD server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://gocd.example.com
	Token              string `json:"token"` // secret:// personal access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the GoCD module.
func New() *Module { return &Module{} }

const (
	v1          = "application/vnd.go.cd.v1+json"
	v4          = "application/vnd.go.cd.v4+json"
	latest      = "application/vnd.go.cd+json"
	maxValueLen = 10000
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// GoCD names: letters, digits, _ - and . (up to 255).
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)
	varRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	// secretNameRe matches variable names that look like they hold a secret;
	// their values are hidden in previews like secure variables.
	secretNameRe = regexp.MustCompile(`(?i)password|passwd|secret|token|key|credential`)
)

func validName(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !nameRe.MatchString(v) || strings.Contains(v, "..") {
		return "", fmt.Errorf("the %s is its name, like build-and-test", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	pipe := `"pipeline":{"type":"string","description":"Pipeline name (see pipelines)"}`
	one := `{"type":"object","required":["pipeline"],"properties":{` + pipe + `}}`
	return sdk.Manifest{
		ID: "gocd", Name: "GoCD", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "GoCD: pipelines with their last runs, pipeline history, stages and jobs, running pipelines, and pausing or unpausing them.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The GoCD server's address, e.g. https://gocd.example.com (the /go path is added)"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token (user menu, Personal Access Tokens); it acts with its user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pipelines", Title: "Pipelines", Description: "Pipelines by group with whether they're paused (by whom and why) or locked, and their last run's label, trigger and stage results.", Risk: sdk.RiskRead},
			{Name: "pipeline_history", Title: "Pipeline history", Description: "A pipeline's recent runs, newest first: counter, label, when, what triggered it, and each stage's result.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + pipe + `,"limit":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "stages", Title: "Stages", Description: "The stages of one run of a pipeline (the latest when no counter is given) with their jobs, states and results.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + pipe + `,"counter":{"type":"integer","minimum":1,"description":"Run counter (see pipeline_history)"}}}`)},
			{Name: "trigger_pipeline", Title: "Run a pipeline", Description: "Schedules a run of a pipeline, optionally with values for its declared environment variables. A run executes the pipeline's code with its credentials and can deploy, so this is destructive. Secure variables can't be passed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + pipe + `,"variables":{"type":"object","description":"Values for the pipeline's declared environment variables by name","additionalProperties":{"type":["string","number","boolean"]}},"updateMaterials":{"type":"boolean","default":true,"description":"Check materials for new revisions first"}}}`)},
			{Name: "pause_pipeline", Title: "Pause a pipeline", Description: "Pauses a pipeline so no new runs start (runs in progress go on). Destructive: changes and timers stop triggering it. Undo unpauses it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + pipe + `,"reason":{"type":"string","maxLength":255,"description":"Why it's paused (shown in GoCD)"}}}`)},
			{Name: "unpause_pipeline", Title: "Unpause a pipeline", Description: "Unpauses a pipeline. Destructive: it can run at once on changes it missed, with its credentials. Undo pauses it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(one)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://gocd.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/go")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/go", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("GoCD refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("GoCD refused: the token's user lacks the permission for this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

// do sends one request with GoCD's versioned Accept header. Changes carry
// X-GoCD-Confirm, which GoCD asks for on POSTs.
func (c *conn) do(ctx context.Context, method, path, accept string, q url.Values, body, out any, what string) error {
	hdr := http.Header{"Accept": {accept}}
	var rd io.Reader
	if method != http.MethodGet {
		hdr.Set("X-GoCD-Confirm", "true")
		if body == nil {
			body = map[string]any{}
		}
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
		hdr.Set("Content-Type", "application/json")
	}
	res, err := c.api.Send(ctx, method, path, q, rd, hdr)
	if err != nil {
		return friendly(err, what)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("GoCD answered %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if json.Unmarshal(raw, out) != nil {
			return errors.New("unexpected answer from GoCD (is this the GoCD address?)")
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Login string `json:"login_name"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/current_user", v1, nil, nil, &me, "GoCD at this address"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/version", v1, nil, nil, &ver, "GoCD at this address"); err != nil || ver.Version == "" {
		return sdk.Health{Status: "down", Message: "no GoCD at this address"}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Login + " · GoCD " + ver.Version}
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// text is free text the server passes on (a pause reason, a trigger
// message): redacted first, then cut.
func text(s string, n int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return clip(rest.Redact(s), n)
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// stamp reads the dashboard's dates, which are RFC 3339 or epoch millis.
func stamp(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return when(int64(x))
	}
	return ""
}

type status struct {
	Paused      bool   `json:"paused"`
	PausedCause string `json:"pausedCause"`
	PausedBy    string `json:"pausedBy"`
	Locked      bool   `json:"locked"`
	Schedulable bool   `json:"schedulable"`
}

func (c *conn) status(ctx context.Context, name string) (status, error) {
	// GoCD answers this one in camelCase or snake_case depending on version.
	var raw struct {
		status
		PausedCause2 string `json:"paused_cause"`
		PausedBy2    string `json:"paused_by"`
	}
	raw.Schedulable = true
	if err := c.do(ctx, http.MethodGet, "/api/pipelines/"+url.PathEscape(name)+"/status", v1, nil, nil, &raw, "pipeline "+name); err != nil {
		return status{}, err
	}
	s := raw.status
	if s.PausedCause == "" {
		s.PausedCause = raw.PausedCause2
	}
	if s.PausedBy == "" {
		s.PausedBy = raw.PausedBy2
	}
	return s, nil
}

type run struct {
	Name       string `json:"name"`
	Counter    int64  `json:"counter"`
	Label      string `json:"label"`
	Scheduled  int64  `json:"scheduled_date"`
	BuildCause struct {
		Message  string `json:"trigger_message"`
		Forced   bool   `json:"trigger_forced"`
		Approver string `json:"approver"`
	} `json:"build_cause"`
	Stages []struct {
		Name     string `json:"name"`
		Counter  string `json:"counter"`
		Result   string `json:"result"`
		Status   string `json:"status"`
		Approval string `json:"approval_type"`
		Approved string `json:"approved_by"`
		Jobs     []struct {
			Name      string `json:"name"`
			State     string `json:"state"`
			Result    string `json:"result"`
			Scheduled int64  `json:"scheduled_date"`
		} `json:"jobs"`
	} `json:"stages"`
}

func runSummary(r run) map[string]any {
	stages := []map[string]any{}
	for _, s := range r.Stages {
		st := map[string]any{"name": s.Name, "counter": s.Counter, "status": s.Status}
		if s.Result != "" && s.Result != "Unknown" {
			st["result"] = s.Result
		}
		stages = append(stages, st)
	}
	row := map[string]any{"counter": r.Counter, "label": r.Label, "scheduled": when(r.Scheduled), "trigger": text(r.BuildCause.Message, 200), "stages": stages}
	if r.BuildCause.Forced {
		row["forced"] = true
	}
	if r.BuildCause.Approver != "" {
		row["by"] = r.BuildCause.Approver
	}
	return row
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Pipeline        string         `json:"pipeline"`
		Limit           int            `json:"limit"`
		Counter         int64          `json:"counter"`
		Variables       map[string]any `json:"variables"`
		UpdateMaterials *bool          `json:"updateMaterials"`
		Reason          string         `json:"reason"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "pipelines" {
		return c.pipelines(ctx)
	}
	switch call.Action {
	case "pipeline_history", "stages", "trigger_pipeline", "pause_pipeline", "unpause_pipeline":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	name, err := validName(p.Pipeline, "pipeline")
	if err != nil {
		return sdk.Result{}, err
	}
	esc := url.PathEscape(name)
	switch call.Action {
	case "pipeline_history":
		n := p.Limit
		if n == 0 {
			n = 10
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("limit is between 1 and 50")
		}
		var out struct {
			Pipelines []run `json:"pipelines"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/pipelines/"+esc+"/history", v1, url.Values{"page_size": {strconv.Itoa(n)}}, nil, &out, "pipeline "+name); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for i, r := range out.Pipelines {
			if i >= n {
				break
			}
			list = append(list, runSummary(r))
		}
		return sdk.JSON(list)

	case "stages":
		if p.Counter < 0 {
			return sdk.Result{}, errors.New("the counter is positive")
		}
		var r run
		if p.Counter == 0 {
			var out struct {
				Pipelines []run `json:"pipelines"`
			}
			if err := c.do(ctx, http.MethodGet, "/api/pipelines/"+esc+"/history", v1, url.Values{"page_size": {"1"}}, nil, &out, "pipeline "+name); err != nil {
				return sdk.Result{}, err
			}
			if len(out.Pipelines) == 0 {
				return sdk.Result{}, fmt.Errorf("%s hasn't run yet", name)
			}
			r = out.Pipelines[0]
		} else if err := c.do(ctx, http.MethodGet, "/api/pipelines/"+esc+"/"+strconv.FormatInt(p.Counter, 10), v1, nil, nil, &r, fmt.Sprintf("run %d of %s", p.Counter, name)); err != nil {
			return sdk.Result{}, err
		}
		out := runSummary(r)
		stages := []map[string]any{}
		for _, s := range r.Stages {
			jobs := []map[string]any{}
			for _, j := range s.Jobs {
				jobs = append(jobs, map[string]any{"name": j.Name, "state": j.State, "result": j.Result, "scheduled": when(j.Scheduled)})
			}
			st := map[string]any{"name": s.Name, "counter": s.Counter, "status": s.Status, "result": s.Result, "approval": s.Approval, "jobs": jobs}
			if s.Approved != "" {
				st["approvedBy"] = s.Approved
			}
			stages = append(stages, st)
		}
		out["pipeline"], out["stages"] = name, stages
		return sdk.JSON(out)

	case "trigger_pipeline":
		return c.trigger(ctx, call, name, p.Variables, p.UpdateMaterials == nil || *p.UpdateMaterials)

	default: // pause_pipeline, unpause_pipeline
		pause := call.Action == "pause_pipeline"
		reason := strings.TrimSpace(p.Reason)
		if !pause {
			reason = ""
		}
		if utf8.RuneCountInString(reason) > 255 || strings.ContainsAny(reason, "\x00\r\n") {
			return sdk.Result{}, errors.New("the reason is one line of up to 255 characters")
		}
		st, err := c.status(ctx, name)
		if err != nil {
			return sdk.Result{}, err
		}
		if st.Paused == pause {
			return sdk.JSON(map[string]any{"pipeline": name, "paused": pause, "note": "nothing to change"})
		}
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"paused": st.Paused})
			want := map[string]any{"paused": pause}
			if reason != "" {
				want["reason"] = reason
			}
			after, _ := json.Marshal(want)
			sum := "Pause " + name + " so no new runs start"
			if !pause {
				sum = "Unpause " + name + "; it can run at once on changes it missed"
				if st.PausedBy != "" {
					sum += " (paused by " + st.PausedBy + ")"
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "pipeline " + name, Op: strings.TrimSuffix(call.Action, "_pipeline"), Before: before, After: after}}}}, nil
		}
		path, body := "/api/pipelines/"+esc+"/unpause", any(nil)
		if pause {
			path, body = "/api/pipelines/"+esc+"/pause", map[string]string{"pause_cause": reason}
		}
		if err := c.do(ctx, http.MethodPost, path, v1, nil, body, nil, "pipeline "+name); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"pipeline": name, "paused": pause})
		if pause {
			res.Undo = sdk.UndoWith("unpause_pipeline", map[string]string{"pipeline": name}, "Unpause "+name+" again")
		} else {
			in := map[string]string{"pipeline": name}
			// 254 and the "…" of a cut reason stay within the 255
			// pause_pipeline takes, so the undo isn't refused.
			if cause := text(st.PausedCause, 254); cause != "" {
				in["reason"] = cause
			}
			res.Undo = sdk.UndoWith("pause_pipeline", in, "Pause "+name+" again")
		}
		return res, err
	}
}

func (c *conn) pipelines(ctx context.Context) (sdk.Result, error) {
	var d struct {
		Embedded struct {
			Groups []struct {
				Name      string   `json:"name"`
				Pipelines []string `json:"pipelines"`
			} `json:"pipeline_groups"`
			Pipelines []struct {
				Name      string `json:"name"`
				Locked    bool   `json:"locked"`
				PauseInfo struct {
					Paused   bool   `json:"paused"`
					PausedBy string `json:"paused_by"`
					Reason   string `json:"pause_reason"`
				} `json:"pause_info"`
				FromConfigRepo bool `json:"from_config_repo"`
				Embedded       struct {
					Instances []struct {
						Label       string `json:"label"`
						Counter     int64  `json:"counter"`
						TriggeredBy string `json:"triggered_by"`
						ScheduledAt any    `json:"scheduled_at"`
						Embedded    struct {
							Stages []struct {
								Name   string `json:"name"`
								Status string `json:"status"`
							} `json:"stages"`
						} `json:"_embedded"`
					} `json:"instances"`
				} `json:"_embedded"`
			} `json:"pipelines"`
		} `json:"_embedded"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/dashboard", v4, nil, nil, &d, "dashboard"); err != nil {
		return sdk.Result{}, err
	}
	group := map[string]string{}
	for _, g := range d.Embedded.Groups {
		for _, p := range g.Pipelines {
			group[p] = g.Name
		}
	}
	list := []map[string]any{}
	for _, p := range d.Embedded.Pipelines {
		row := map[string]any{"name": p.Name, "group": group[p.Name], "paused": p.PauseInfo.Paused, "locked": p.Locked}
		if p.PauseInfo.Paused {
			row["pausedBy"] = p.PauseInfo.PausedBy
			if p.PauseInfo.Reason != "" {
				row["pauseReason"] = text(p.PauseInfo.Reason, 200)
			}
		}
		if p.FromConfigRepo {
			row["fromConfigRepo"] = true
		}
		if in := p.Embedded.Instances; len(in) > 0 {
			last := in[len(in)-1]
			stages := []map[string]string{}
			for _, s := range last.Embedded.Stages {
				stages = append(stages, map[string]string{"name": s.Name, "status": s.Status})
			}
			row["lastRun"] = map[string]any{"label": last.Label, "counter": last.Counter, "triggeredBy": text(last.TriggeredBy, 200), "scheduled": stamp(last.ScheduledAt), "stages": stages}
		}
		list = append(list, row)
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i]["group"].(string)+"/"+list[i]["name"].(string), list[j]["group"].(string)+"/"+list[j]["name"].(string)
		return a < b
	})
	return sdk.JSON(list)
}

func (c *conn) trigger(ctx context.Context, call sdk.Call, name string, vars map[string]any, update bool) (sdk.Result, error) {
	names := make([]string, 0, len(vars))
	values := map[string]string{}
	for k, raw := range vars {
		if !varRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a variable name", k)
		}
		var v string
		switch x := raw.(type) {
		case string:
			v = x
		case bool:
			v = strconv.FormatBool(x)
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return sdk.Result{}, fmt.Errorf("variable %s is a string, number or boolean", k)
		}
		if len(v) > maxValueLen || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return sdk.Result{}, fmt.Errorf("variable %s is too long or not text", k)
		}
		names = append(names, k)
		values[k] = v
	}
	sort.Strings(names)
	st, err := c.status(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	switch {
	case st.Paused:
		return sdk.Result{}, fmt.Errorf("%s is paused; unpause it first", name)
	case st.Locked:
		return sdk.Result{}, fmt.Errorf("%s is locked while a run is in progress", name)
	case !st.Schedulable:
		return sdk.Result{}, fmt.Errorf("GoCD can't schedule %s right now (a run may be waiting or in progress)", name)
	}
	envs := []map[string]any{}
	shown := map[string]string{}
	if len(names) > 0 {
		// Declared variables come from the pipeline's configuration; the
		// secure ones' (encrypted) values are never decoded.
		var cfg struct {
			Env []struct {
				Name   string `json:"name"`
				Secure bool   `json:"secure"`
			} `json:"environment_variables"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/admin/pipelines/"+url.PathEscape(name), latest, nil, nil, &cfg, "pipeline "+name); err != nil {
			if strings.Contains(err.Error(), "lacks the permission") {
				return sdk.Result{}, errors.New("reading the pipeline's declared variables needs a token whose user administers its group; run it without variables, or use such a token")
			}
			return sdk.Result{}, err
		}
		decl := map[string]bool{}
		for _, e := range cfg.Env {
			decl[e.Name] = decl[e.Name] || e.Secure
		}
		for _, k := range names {
			secure, ok := decl[k]
			if !ok {
				return sdk.Result{}, fmt.Errorf("%s declares no environment variable %q", name, k)
			}
			// A secure variable whose name differs only in case is
			// refused too, in case GoCD matches names that way.
			for n, s := range decl {
				secure = secure || (s && strings.EqualFold(n, k))
			}
			if secure {
				return sdk.Result{}, fmt.Errorf("%s is a secure variable; Conduit doesn't pass those (its stored value is used)", k)
			}
			envs = append(envs, map[string]any{"name": k, "value": values[k], "secure": false})
			if secretNameRe.MatchString(k) {
				shown[k] = "[hidden]"
			} else {
				shown[k] = clip(values[k], 300)
			}
		}
	}
	if call.DryRun {
		sum := "Run " + name + " now"
		if update {
			sum += ", checking its materials for new revisions first"
		}
		ch := sdk.Change{Target: "pipeline " + name, Op: "run"}
		if len(shown) > 0 {
			ch.After, _ = json.Marshal(map[string]any{"variables": shown})
			sum += ", with variables"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	body := map[string]any{"update_materials_before_scheduling": update}
	if len(envs) > 0 {
		body["environment_variables"] = envs
	}
	var out struct {
		Message string `json:"message"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/pipelines/"+url.PathEscape(name)+"/schedule", v1, nil, body, &out, "pipeline "+name); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"pipeline": name, "scheduled": true, "message": text(out.Message, 200)})
}
