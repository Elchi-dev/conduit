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
			{Name: "pause", Title: "Pause all workers", Description: "Pauses every worker: tasks in progress halt until resumed. Undo resumes them.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
			{Name: "resume", Title: "Resume all workers", Description: "Resumes every paused worker. Undo pauses them again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{}}`)},
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

// shortName keeps only a file's name: paths say where someone keeps what.
func shortName(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	return rest.Redact(path.Base(p))
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
	Limit int `json:"limit"`
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
		for _, w := range ws {
			e := map[string]any{"id": w.ID, "name": w.Name, "busy": !w.Idle, "paused": w.Paused}
			if !w.Idle {
				e["file"] = shortName(w.File)
				if s := startTime(w.StartTime); s != "" {
					e["started"] = s
				}
			}
			out = append(out, e)
		}
		busy, paused := counts(ws)
		return sdk.JSON(map[string]any{"total": len(ws), "busy": busy, "paused": paused, "workers": out})

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
			byStatus[r.Status]++
			byLib[r.Library]++
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
		return c.pauseResume(ctx, call)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	pausing := call.Action == "pause"
	ws, err := c.workers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	busy, paused := counts(ws)
	change := len(ws) - paused // workers to pause
	if !pausing {
		change = paused
	}
	if change == 0 {
		return sdk.JSON(map[string]any{"workers": len(ws), "paused": paused, "note": "nothing to change"})
	}
	verb, back := "Pause", "resume"
	if !pausing {
		verb, back = "Resume", "pause"
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]int{"workers": len(ws), "paused": paused, "busy": busy})
		a, _ := json.Marshal(map[string]int{"workers": len(ws), "paused": map[bool]int{true: len(ws), false: 0}[pausing]})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s all Unmanic workers (%d change)", verb, change),
			Changes: []sdk.Change{{Target: "workers", Op: call.Action, Before: b, After: a}}}}, nil
	}
	var ok struct {
		Success *bool `json:"success"`
	}
	if err := c.do(ctx, http.MethodPost, "/workers/worker/"+call.Action+"/all", map[string]any{}, &ok); err != nil {
		return sdk.Result{}, err
	}
	if ok.Success != nil && !*ok.Success {
		return sdk.Result{}, fmt.Errorf("Unmanic didn't %s the workers", call.Action)
	}
	after, err := c.workers(ctx)
	if err != nil {
		return sdk.Result{}, fmt.Errorf("sent the change, but couldn't read the workers back: %w", err)
	}
	_, nowPaused := counts(after)
	if (pausing && nowPaused != len(after)) || (!pausing && nowPaused != 0) {
		return sdk.Result{}, fmt.Errorf("Unmanic has %d of %d workers paused after %s", nowPaused, len(after), call.Action)
	}
	res, err := sdk.JSON(map[string]any{"workers": len(after), "paused": nowPaused})
	res.Undo = sdk.UndoWith(back, map[string]any{}, strings.ToUpper(back[:1])+back[1:]+" all workers again")
	return res, err
}
