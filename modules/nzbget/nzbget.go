// Package nzbget works with an NZBGet Usenet downloader through its
// JSON-RPC API and control password: the queue and its speed, history (with
// failure states), pausing and resuming the queue or single jobs, deleting
// jobs and the speed limit.
package nzbget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one NZBGet server.
type Config struct {
	URL                string `json:"url"`      // e.g. http://nas.lan:6789
	Username           string `json:"username"` // ControlUsername (default nzbget)
	Password           string `json:"password"` // secret:// ControlPassword
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

// New returns the NZBGet module.
func New() *Module { return &Module{} }

const maxJobs = 50

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	jobs := `"jobs":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"integer","minimum":1},"description":"Job ids (from queue)"}`
	return sdk.Manifest{
		ID: "nzbget", Name: "NZBGet", Version: "0.1.0", Category: "Media", Icon: "download",
		Description: "NZBGet: the download queue and speed, history with failures, pause and resume, delete jobs, speed limit.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"NZBGet's address, e.g. http://nas.lan:6789"},
			"username":{"type":"string","default":"nzbget","description":"ControlUsername (Settings, Security)"},
			"password":{"type":"string","x-secret":true,"description":"ControlPassword (Settings, Security)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "queue", Title: "Queue", Description: "Whether downloads run or are paused, speed, speed limit, what's left and free disk space, and the jobs with status, progress, size, category and priority.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "history", Title: "History", Description: "Finished and failed jobs with status, size, category, completion time and download time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"failedOnly":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "pause", Title: "Pause downloads", Description: "Pauses all downloading, or with jobs only those jobs. Undo resumes what was running.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + jobs + `}}`)},
			{Name: "resume", Title: "Resume downloads", Description: "Resumes all downloading, or with jobs only those jobs. Undo pauses what was paused.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + jobs + `}}`)},
			{Name: "delete", Title: "Delete jobs", Description: "Removes jobs from the queue (they go to history as deleted). NZBGet removes what they downloaded when its DeleteCleanupDisk option is on.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["jobs"],"properties":{` + jobs + `}}`)},
			{Name: "set_speed_limit", Title: "Set the speed limit", Description: "Sets the download speed limit in KiB/s (0 = unlimited). Undo restores the previous limit.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["kiBs"],"properties":{"kiBs":{"type":"integer","minimum":0,"maximum":10000000}}}`)},
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
		return errors.New("the address is like http://nas.lan:6789")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "nzbget"
	}
	if strings.ContainsAny(user, ":\r\n") || len(user) > 200 {
		return errors.New("the user name is NZBGet's ControlUsername")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the control password in the vault and enter its secret:// reference")
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
	ref := c.Password
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/jsonrpc")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errAuth = errors.New("NZBGet refused the user name or password")

// rpc calls one JSON-RPC method and decodes its result into out.
func (c *conn) rpc(ctx context.Context, method string, out any, params ...any) error {
	if params == nil {
		params = []any{}
	}
	var res struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/jsonrpc", nil, map[string]any{"version": "1.1", "id": 1, "method": method, "params": params}, &res)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errAuth
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no NZBGet API at this address")
	case err != nil:
		return err
	case res.Error != nil:
		msg := rest.Redact(strings.SplitN(res.Error.Message, "\n", 2)[0])
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return errors.New("NZBGet: " + msg)
	case len(res.Result) == 0:
		return errors.New("unexpected answer: is this NZBGet?")
	}
	if out != nil {
		if err := json.Unmarshal(res.Result, out); err != nil {
			return fmt.Errorf("unexpected answer from NZBGet: %w", err)
		}
	}
	return nil
}

// ok calls a method that answers true when it did what was asked.
func (c *conn) ok(ctx context.Context, method string, params ...any) error {
	var done bool
	if err := c.rpc(ctx, method, &done, params...); err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("NZBGet didn't do %s", method)
	}
	return nil
}

type status struct {
	RemainingMB   int64 `json:"RemainingSizeMB"`
	Rate          int64 `json:"DownloadRate"`  // bytes/s
	Limit         int64 `json:"DownloadLimit"` // bytes/s, 0 = none
	Paused        bool  `json:"DownloadPaused"`
	PostPaused    bool  `json:"PostPaused"`
	FreeDiskMB    int64 `json:"FreeDiskSpaceMB"`
	ServerStandBy bool  `json:"ServerStandBy"`
	UpTimeSec     int64 `json:"UpTimeSec"`
}

func (c *conn) status(ctx context.Context) (status, error) {
	var s status
	err := c.rpc(ctx, "status", &s)
	return s, err
}

type group struct {
	ID          int    `json:"NZBID"`
	Name        string `json:"NZBName"`
	Status      string `json:"Status"`
	Category    string `json:"Category"`
	SizeMB      int64  `json:"FileSizeMB"`
	RemainingMB int64  `json:"RemainingSizeMB"`
	PausedMB    int64  `json:"PausedSizeMB"`
	Priority    int    `json:"MaxPriority"`
}

func (c *conn) groups(ctx context.Context) ([]group, error) {
	var gs []group
	err := c.rpc(ctx, "listgroups", &gs, 0)
	return gs, err
}

// paused reports whether a job is paused: all that's left of it is paused.
func (g group) paused() bool {
	return g.Status == "PAUSED" || (g.Status == "QUEUED" && g.RemainingMB > 0 && g.PausedMB >= g.RemainingMB)
}

func (g group) downloading() bool {
	return g.Status == "QUEUED" || g.Status == "DOWNLOADING" || g.Status == "FETCHING" || g.Status == "PAUSED"
}

// safeName hides an indexer's key in a job's name: a job added by URL can
// be named after the URL, query and all.
func safeName(s string) string {
	low := strings.ToLower(s)
	if !strings.Contains(low, "://") && !strings.Contains(low, "key=") {
		return s
	}
	fields := strings.Fields(s)
	for i, f := range fields {
		if strings.Contains(f, "://") {
			f = rest.CleanURL(f)
			if j := strings.IndexByte(f, '&'); j >= 0 {
				f = f[:j]
			}
			fields[i] = f
		}
	}
	return rest.Redact(strings.Join(fields, " "))
}

func kib(bytes int64) int64 { return (bytes + 1023) >> 10 }

func limitOut(s status) any {
	if s.Limit > 0 {
		return kib(s.Limit)
	}
	return "unlimited"
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v string
	if err := c.rpc(ctx, "version", &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	s, err := c.status(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	gs, err := c.groups(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("NZBGet %s · %d jobs", v, len(gs))
	if s.Paused {
		msg += ", paused"
	} else if s.Rate > 0 {
		msg += fmt.Sprintf(", downloading at %d KiB/s", s.Rate>>10)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Limit      int     `json:"limit"`
	FailedOnly bool    `json:"failedOnly"`
	Jobs       []int64 `json:"jobs"`
	KiBs       *int64  `json:"kiBs"`
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
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	switch call.Action {
	case "queue":
		s, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		gs, err := c.groups(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		jobs := []map[string]any{}
		for _, g := range gs {
			if len(jobs) == limit {
				break
			}
			progress := 0.0
			if g.SizeMB > 0 {
				progress = float64(g.SizeMB-g.RemainingMB) * 100 / float64(g.SizeMB)
			}
			st := strings.ToLower(g.Status)
			if g.paused() {
				st = "paused"
			}
			jobs = append(jobs, map[string]any{"id": g.ID, "name": safeName(g.Name), "status": st, "progress": float64(int(progress*10)) / 10,
				"sizeMB": g.SizeMB, "leftMB": g.RemainingMB, "category": g.Category, "priority": g.Priority})
		}
		return sdk.JSON(map[string]any{"paused": s.Paused, "postProcessingPaused": s.PostPaused, "speedKiBs": s.Rate >> 10, "leftMB": s.RemainingMB,
			"speedLimitKiBs": limitOut(s), "freeDiskGB": float64(s.FreeDiskMB*10/1024) / 10, "total": len(gs), "jobs": jobs})

	case "history":
		var hs []struct {
			ID          int    `json:"NZBID"`
			Name        string `json:"Name"`
			Status      string `json:"Status"`
			Kind        string `json:"Kind"`
			Category    string `json:"Category"`
			SizeMB      int64  `json:"FileSizeMB"`
			HistoryTime int64  `json:"HistoryTime"`
			DownloadSec int64  `json:"DownloadTimeSec"`
			DestDir     string `json:"DestDir"`
			// The URL of a job added by URL isn't read: indexers put their
			// API key in it.
		}
		if err := c.rpc(ctx, "history", &hs, false); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		failed := 0
		for _, h := range hs {
			bad := !strings.HasPrefix(h.Status, "SUCCESS") && !strings.HasPrefix(h.Status, "DELETED")
			if bad {
				failed++
			}
			if (p.FailedOnly && !bad) || len(out) == limit {
				continue
			}
			e := map[string]any{"id": h.ID, "name": safeName(h.Name), "status": strings.ToLower(h.Status), "kind": strings.ToLower(h.Kind),
				"sizeMB": h.SizeMB, "category": h.Category, "downloadSeconds": h.DownloadSec}
			if h.HistoryTime > 0 {
				e["completed"] = time.Unix(h.HistoryTime, 0).UTC().Format(time.RFC3339)
			}
			if h.DestDir != "" {
				e["path"] = safeName(h.DestDir)
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"total": len(hs), "failed": failed, "entries": out})

	case "pause", "resume":
		return c.pauseResume(ctx, call, p.Jobs)
	case "delete":
		return c.delete(ctx, call.DryRun, p.Jobs)
	case "set_speed_limit":
		return c.speedLimit(ctx, call.DryRun, p.KiBs)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func checkJobs(in []int64, need bool) ([]int64, error) {
	if len(in) > maxJobs {
		return nil, fmt.Errorf("pick at most %d jobs", maxJobs)
	}
	if need && len(in) == 0 {
		return nil, errors.New("name the jobs (ids from queue)")
	}
	seen := map[int64]bool{}
	var out []int64
	for _, j := range in {
		if j < 1 || j > 1<<31-1 {
			return nil, errors.New("a job is its id from queue")
		}
		if !seen[j] {
			seen[j] = true
			out = append(out, j)
		}
	}
	return out, nil
}

func (c *conn) find(ctx context.Context, ids []int64) ([]group, error) {
	gs, err := c.groups(ctx)
	if err != nil {
		return nil, err
	}
	by := map[int64]group{}
	for _, g := range gs {
		by[int64(g.ID)] = g
	}
	var out []group
	for _, id := range ids {
		g, ok := by[id]
		if !ok {
			return nil, fmt.Errorf("there's no job %d in the queue", id)
		}
		out = append(out, g)
	}
	return out, nil
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call, in []int64) (sdk.Result, error) {
	pausing := call.Action == "pause"
	ids, err := checkJobs(in, false)
	if err != nil {
		return sdk.Result{}, err
	}
	verb, back := "Pause", "resume"
	if !pausing {
		verb, back = "Resume", "pause"
	}
	if len(ids) == 0 {
		s, err := c.status(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if s.Paused == pausing {
			return sdk.JSON(map[string]any{"downloadsPaused": s.Paused, "note": "nothing to change"})
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]bool{"paused": s.Paused})
			a, _ := json.Marshal(map[string]bool{"paused": pausing})
			return sdk.Result{Plan: &sdk.Plan{Summary: verb + " all NZBGet downloads", Changes: []sdk.Change{{Target: fmt.Sprintf("downloads (%d MB left)", s.RemainingMB), Op: call.Action, Before: b, After: a}}}}, nil
		}
		if err := c.ok(ctx, call.Action+"download"); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"downloadsPaused": pausing})
		res.Undo = sdk.UndoWith(back, map[string]any{}, verbPast(back)+" downloads again")
		return res, err
	}
	gs, err := c.find(ctx, ids)
	if err != nil {
		return sdk.Result{}, err
	}
	var change []int64
	var changes []sdk.Change
	for _, g := range gs {
		if !g.downloading() || g.paused() == pausing {
			continue
		}
		change = append(change, int64(g.ID))
		b, _ := json.Marshal(strings.ToLower(g.Status))
		changes = append(changes, sdk.Change{Target: safeName(g.Name), Op: call.Action, Before: b})
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []int64{}, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d jobs", verb, len(change)), Changes: changes}}, nil
	}
	if err := c.ok(ctx, "editqueue", "Group"+verb, "", change); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"jobs": change}, fmt.Sprintf("%s %d jobs again", verbPast(back), len(change)))
	return res, err
}

func verbPast(action string) string { return strings.ToUpper(action[:1]) + action[1:] }

func (c *conn) delete(ctx context.Context, dry bool, in []int64) (sdk.Result, error) {
	ids, err := checkJobs(in, true)
	if err != nil {
		return sdk.Result{}, err
	}
	gs, err := c.find(ctx, ids)
	if err != nil {
		return sdk.Result{}, err
	}
	if dry {
		var changes []sdk.Change
		for _, g := range gs {
			b, _ := json.Marshal(map[string]any{"status": strings.ToLower(g.Status), "sizeMB": g.SizeMB, "leftMB": g.RemainingMB})
			changes = append(changes, sdk.Change{Target: safeName(g.Name), Op: "delete", Before: b})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %d jobs from the NZBGet queue", len(gs)), Changes: changes}}, nil
	}
	if err := c.ok(ctx, "editqueue", "GroupDelete", "", ids); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"deleted": ids})
}

func (c *conn) speedLimit(ctx context.Context, dry bool, k *int64) (sdk.Result, error) {
	if k == nil || *k < 0 || *k > 10000000 {
		return sdk.Result{}, errors.New("kiBs is the limit in KiB/s, 0 for unlimited")
	}
	s, err := c.status(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	was := kib(s.Limit)
	if s.Limit <= 0 {
		was = 0
	}
	if was == *k {
		return sdk.JSON(map[string]any{"speedLimitKiBs": limitOut(s), "note": "nothing to change"})
	}
	show := func(v int64) any {
		if v == 0 {
			return "unlimited"
		}
		return v
	}
	if dry {
		b, _ := json.Marshal(show(was))
		a, _ := json.Marshal(show(*k))
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set the NZBGet speed limit to %v", show(*k)),
			Changes: []sdk.Change{{Target: "download speed limit (KiB/s)", Op: "update", Before: b, After: a}}}}, nil
	}
	if err := c.ok(ctx, "rate", *k); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"speedLimitKiBs": show(*k), "was": show(was)})
	res.Undo = sdk.UndoWith("set_speed_limit", map[string]int64{"kiBs": was}, fmt.Sprintf("Set the speed limit back to %v", show(was)))
	return res, err
}
