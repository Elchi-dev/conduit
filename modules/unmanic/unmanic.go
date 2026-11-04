// Package unmanic works with an Unmanic library optimiser through its API
// v2: the workers and what they're doing, pending task counts, a summary of
// completed tasks, and pausing and resuming all workers.
package unmanic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Unmanic server.
type Config struct {
	URL                string `json:"url"` // e.g. http://nas.lan:8888
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

// New returns the Unmanic module.
func New() *Module { return &Module{} }

// pendingPage is how many pending tasks are read to count them by status
// and library.
const pendingPage = 500

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// maxWorkers is the most workers named in the output or in one call.
const maxWorkers = 50

var workerRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

const workersIn = `"workers":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"string","pattern":"^[A-Za-z0-9_.-]{1,64}$"},"description":"Worker ids (from workers); all workers when left out"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "unmanic", Name: "Unmanic", Version: "0.1.0", Category: "Media", Icon: "video",
		Description: "Unmanic: workers and what they're doing, pending task counts, completed task history, pause and resume all workers.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Unmanic's address, e.g. http://nas.lan:8888"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "workers", Title: "Workers", Description: "How many workers there are, how many are busy and paused, and each worker's name, state, start time and the name of the file it's on.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "pending", Title: "Pending tasks", Description: "How many tasks wait, counted by status and by library.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "history", Title: "Completed tasks", Description: "How many tasks finished, succeeded and failed, and the most recent ones with their name, result and finish time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "pause", Title: "Pause workers", Description: "Pauses every worker, or only the workers given: tasks in progress halt until resumed. Undo resumes exactly the workers it paused.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + workersIn + `}}`)},
			{Name: "resume", Title: "Resume workers", Description: "Resumes every paused worker, or only the workers given. Undo pauses exactly the workers it resumed.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + workersIn + `}}`)},
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
		return errors.New("the address is like http://nas.lan:8888")
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
	base := strings.TrimRight(u.Path, "/")
	base = strings.TrimSuffix(base, "/api/v2")
	base = strings.TrimSuffix(base, "/unmanic")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/unmanic/api/v2", nil)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, p string, body, out any) error {
	_, err := c.api.Do(ctx, method, p, nil, body, out)
	err = scrub(err)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Unmanic refused the request (is something in front of it asking for a login?)")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Unmanic API at this address")
	}
	return err
}

type worker struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Idle      bool   `json:"idle"`
	Paused    bool   `json:"paused"`
	StartTime any    `json:"start_time"`
	File      string `json:"current_file"`
	// The command line and log tail aren't read: they hold full paths.
}

func (c *conn) workers(ctx context.Context) ([]worker, error) {
	var out struct {
		Workers *[]worker `json:"workers_status"`
	}
	if err := c.do(ctx, http.MethodGet, "/workers/status", nil, &out); err != nil {
		return nil, err
	}
	if out.Workers == nil {
		return nil, errors.New("unexpected answer: is this Unmanic?")
	}
	ws := *out.Workers
	sort.SliceStable(ws, func(i, j int) bool { return ws[i].ID < ws[j].ID })
	return ws, nil
}

// pathRun is a word with a slash or backslash in a server's error text:
// a file or folder (/library/Family/a.mkv, C:\x\y).
var pathRun = regexp.MustCompile(`[^\s"'<>]*[\\/][^\s"'<>]*`)

// scrub keeps folders out of an error Unmanic sent.
func scrub(err error) error {
	var e *rest.Error
	if errors.As(err, &e) {
		return &rest.Error{Status: e.Status, Message: pathRun.ReplaceAllString(e.Message, "[path]")}
	}
	return err
}

// clip redacts a server's text, then keeps it to one line of n bytes.
func clip(s string, n int) string {
	s = rest.Redact(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// shortName keeps only a file's name: paths say where someone keeps what.
func shortName(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	return clip(path.Base(p), 200)
}

func counts(ws []worker) (busy, paused int) {
	for _, w := range ws {
		if !w.Idle {
			busy++
		}
		if w.Paused {
			paused++
		}
	}
	return
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/version/read", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if v.Version == "" {
		return sdk.Health{Status: "down", Message: "unexpected answer: is this Unmanic?"}
	}
	ws, err := c.workers(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	busy, paused := counts(ws)
	msg := fmt.Sprintf("Unmanic %s · %d workers, %d busy", rest.Redact(v.Version), len(ws), busy)
	if paused > 0 {
		msg += fmt.Sprintf(", %d paused", paused)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Limit   int      `json:"limit"`
	Workers []string `json:"workers"`
}

func startTime(v any) string {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			return time.Unix(int64(x), 0).UTC().Format(time.RFC3339)
		}
	case string:
		if len(x) <= 40 {
			return x
		}
	}
	return ""
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
	switch call.Action {
	case "workers":
		ws, err := c.workers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, w := range ws {
			if i == maxWorkers {
				break
			}
			e := map[string]any{"id": clip(w.ID, 64), "name": clip(w.Name, 100), "busy": !w.Idle, "paused": w.Paused}
			if !w.Idle {
				e["file"] = shortName(w.File)
				if s := startTime(w.StartTime); s != "" {
					e["started"] = s
				}
			}
			out = append(out, e)
		}
		busy, paused := counts(ws)
		res := map[string]any{"total": len(ws), "busy": busy, "paused": paused, "workers": out}
		if len(ws) > maxWorkers {
			res["note"] = fmt.Sprintf("the first %d workers only", maxWorkers)
		}
		return sdk.JSON(res)

	case "pending":
		var res struct {
			Total   *int64 `json:"recordsTotal"`
			Results []struct {
				Status  string `json:"status"`
				Library string `json:"library_name"`
				// The path isn't read.
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodPost, "/pending/tasks", map[string]any{"start": 0, "length": pendingPage}, &res); err != nil {
			return sdk.Result{}, err
		}
		if res.Total == nil {
			return sdk.Result{}, errors.New("unexpected answer: is this Unmanic?")
		}
		byStatus, byLib := map[string]int{}, map[string]int{}
		for _, r := range res.Results {
			byStatus[clip(r.Status, 40)]++
			byLib[clip(r.Library, 100)]++
		}
		out := map[string]any{"total": *res.Total, "byStatus": byStatus, "byLibrary": byLib}
		if *res.Total > int64(len(res.Results)) {
			out["note"] = fmt.Sprintf("status and library counts cover the first %d tasks", len(res.Results))
		}
		return sdk.JSON(out)

	case "history":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		var res struct {
			Total   *int64 `json:"recordsTotal"`
			Success int64  `json:"successCount"`
			Failed  int64  `json:"failedCount"`
			Results []struct {
				ID      int64   `json:"id"`
				Label   string  `json:"task_label"`
				Success bool    `json:"task_success"`
				Finish  float64 `json:"finish_time"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodPost, "/history/tasks", map[string]any{"start": 0, "length": limit, "order_by": "finish_time", "order_direction": "desc"}, &res); err != nil {
			return sdk.Result{}, err
		}
		if res.Total == nil {
			return sdk.Result{}, errors.New("unexpected answer: is this Unmanic?")
		}
		recent := []map[string]any{}
		for _, r := range res.Results {
			e := map[string]any{"id": r.ID, "name": shortName(r.Label), "success": r.Success}
			if r.Finish > 0 {
				e["finished"] = time.Unix(int64(r.Finish), 0).UTC().Format(time.RFC3339)
			}
			recent = append(recent, e)
		}
		return sdk.JSON(map[string]any{"total": *res.Total, "succeeded": res.Success, "failed": res.Failed, "recent": recent})

	case "pause", "resume":
		return c.pauseResume(ctx, call, p.Workers)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// pick checks the worker ids given (all workers when none are) against
// Unmanic's list and returns the ones not yet in the state asked for.
func pick(ws []worker, in []string, pausing bool) ([]string, error) {
	byID := map[string]worker{}
	for _, w := range ws {
		byID[w.ID] = w
	}
	want := map[string]bool{}
	for _, id := range in {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("there's no worker %s (see workers)", id)
		}
		want[id] = true
	}
	var out []string
	for _, w := range ws {
		if (len(in) == 0 || want[w.ID]) && w.Paused != pausing {
			out = append(out, w.ID)
		}
	}
	return out, nil
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call, in []string) (sdk.Result, error) {
	pausing := call.Action == "pause"
	if in != nil && len(in) == 0 {
		return sdk.Result{}, errors.New("workers lists at least one worker id; leave it out for all workers")
	}
	if len(in) > maxWorkers {
		return sdk.Result{}, fmt.Errorf("pick at most %d workers", maxWorkers)
	}
	for _, id := range in {
		if !workerRe.MatchString(id) {
			return sdk.Result{}, errors.New("workers are worker ids (from workers)")
		}
	}
	ws, err := c.workers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	busy, paused := counts(ws)
	ids, err := pick(ws, in, pausing)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(ids) == 0 {
		return sdk.JSON(map[string]any{"workers": len(ws), "paused": paused, "note": "nothing to change"})
	}
	for _, id := range ids {
		if !workerRe.MatchString(id) {
			return sdk.Result{}, errors.New("unexpected worker id from Unmanic")
		}
	}
	verb, back := "Pause", "resume"
	if !pausing {
		verb, back = "Resume", "pause"
	}
	if call.DryRun {
		after := paused + len(ids)
		if !pausing {
			after = paused - len(ids)
		}
		b, _ := json.Marshal(map[string]int{"workers": len(ws), "paused": paused, "busy": busy})
		a, _ := json.Marshal(map[string]any{"workers": len(ws), "paused": after, "changed": ids})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d of %d Unmanic workers", verb, len(ids), len(ws)),
			Changes: []sdk.Change{{Target: "workers " + strings.Join(ids, ", "), Op: call.Action, Before: b, After: a}}}}, nil
	}
	var ok struct {
		Success *bool `json:"success"`
	}
	send := func(p string, body any) error {
		ok.Success = nil
		if err := c.do(ctx, http.MethodPost, p, body, &ok); err != nil {
			return err
		}
		if ok.Success != nil && !*ok.Success {
			return fmt.Errorf("Unmanic didn't %s the workers", call.Action)
		}
		return nil
	}
	if len(ids) == len(ws) {
		// Every worker changes: one call for all of them.
		if err := send("/workers/worker/"+call.Action+"/all", map[string]any{}); err != nil {
			return sdk.Result{}, err
		}
	} else {
		for i, id := range ids {
			if err := send("/workers/worker/"+call.Action, map[string]string{"worker_id": id}); err != nil {
				if i > 0 {
					return sdk.Result{}, fmt.Errorf("%s workers %s, then: %w", map[bool]string{true: "paused", false: "resumed"}[pausing], strings.Join(ids[:i], ", "), err)
				}
				return sdk.Result{}, err
			}
		}
	}
	after, err := c.workers(ctx)
	if err != nil {
		return sdk.Result{}, fmt.Errorf("sent the change, but couldn't read the workers back: %w", err)
	}
	now := map[string]bool{}
	for _, w := range after {
		now[w.ID] = w.Paused
	}
	kept := 0
	for _, id := range ids {
		if p, ok := now[id]; !ok || p != pausing {
			kept++
		}
	}
	_, nowPaused := counts(after)
	if kept > 0 {
		return sdk.Result{}, fmt.Errorf("Unmanic has %d of %d workers paused after %s (%d of %d not changed)", nowPaused, len(after), call.Action, kept, len(ids))
	}
	res, err := sdk.JSON(map[string]any{"workers": len(after), "paused": nowPaused, "changed": ids})
	undo := map[string]any{"workers": ids}
	if len(ids) > maxWorkers {
		undo = map[string]any{} // every worker changed, so all of them go back
	}
	res.Undo = sdk.UndoWith(back, undo, fmt.Sprintf("%s the %d workers again", back, len(ids)))
	return res, err
}
