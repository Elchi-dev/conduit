// Package sabnzbd works with a SABnzbd Usenet downloader through its API
// and API key: the queue and its speed, history (with failure reasons),
// pausing and resuming, adding an NZB by URL, deleting jobs, and the speed
// limit.
package sabnzbd

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one SABnzbd server.
type Config struct {
	URL                string `json:"url"`    // e.g. http://nas.lan:8080 or http://nas.lan:8080/sabnzbd
	APIKey             string `json:"apiKey"` // secret:// API key
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

// New returns the SABnzbd module.
func New() *Module { return &Module{} }

const maxJobs = 50

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	jobRe  = regexp.MustCompile(`^SABnzbd_nzo_[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	jobs := `"jobs":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"string","pattern":"^SABnzbd_nzo_[A-Za-z0-9_-]{1,64}$"},"description":"Job ids (from queue or history)"}`
	return sdk.Manifest{
		ID: "sabnzbd", Name: "SABnzbd", Version: "0.1.0", Category: "Media", Icon: "download",
		Description: "SABnzbd: the download queue and speed, history with failure reasons, pause and resume, add an NZB by URL, delete jobs, speed limit.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"SABnzbd's address, e.g. http://nas.lan:8080 (with its URL base if it has one, e.g. /sabnzbd)"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key (Config, General, Security); the NZB key isn't enough"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "queue", Title: "Queue", Description: "Whether the queue runs or is paused, speed, speed limit, what's left and free disk space, and the jobs with progress, size, time left, category and priority.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "history", Title: "History", Description: "Finished and failed jobs with status, failure reason, size, category, completion time and download time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"failedOnly":{"type":"boolean","default":false},"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "pause", Title: "Pause downloads", Description: "Pauses the whole queue, or with jobs only those jobs. Undo resumes what was running.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + jobs + `}}`)},
			{Name: "resume", Title: "Resume downloads", Description: "Resumes the whole queue, or with jobs only those jobs. Undo pauses what was paused.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + jobs + `}}`)},
			{Name: "add_url", Title: "Add an NZB by URL", Description: "Has SABnzbd fetch an NZB from an http(s) URL and queue it. The URL usually holds an indexer's API key, so the call is kept out of the audit log. Undo deletes the new job.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["url"],"properties":{
					"url":{"type":"string","description":"http(s) URL of the NZB"},
					"name":{"type":"string","description":"Job name (default: from the NZB)"},
					"category":{"type":"string","description":"A category set up in SABnzbd"},
					"priority":{"type":"string","enum":["default","paused","low","normal","high","force"],"default":"default"}}}`)},
			{Name: "delete", Title: "Delete jobs", Description: "Removes jobs from the queue or entries from history, and with deleteFiles also their files.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["jobs"],"properties":{` + jobs + `,"deleteFiles":{"type":"boolean","default":false,"description":"Also delete the job's files"}}}`)},
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
		return errors.New("the address is like http://nas.lan:8080")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		if r.URL.Query().Get("mode") == "version" {
			return nil // answers without a key
		}
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		q.Set("apikey", strings.TrimSpace(k))
		r.URL.RawQuery = q.Encode()
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errKey = errors.New("SABnzbd refused the API key")

// call runs one API mode and decodes its JSON answer into out.
func (c *conn) call(ctx context.Context, q url.Values, out any) error {
	q.Set("output", "json")
	res, err := c.api.Send(ctx, http.MethodGet, "/api", q, nil, http.Header{"Accept": {"application/json"}})
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errKey
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no SABnzbd API at this address (check the URL base)")
	case err != nil:
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("SABnzbd answered %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(raw))
	var env struct {
		Status *bool  `json:"status"`
		Error  string `json:"error"`
	}
	msg := ""
	if strings.HasPrefix(text, "error:") || strings.HasPrefix(text, "error ") {
		msg = strings.TrimSpace(strings.TrimPrefix(text, "error"))
		msg = strings.TrimSpace(strings.TrimPrefix(msg, ":"))
	} else if json.Unmarshal(raw, &env) != nil {
		return errors.New("unexpected answer: is this SABnzbd?")
	} else if env.Error != "" || (env.Status != nil && !*env.Status) {
		msg = env.Error
	}
	if msg != "" || env.Status != nil && !*env.Status {
		if strings.Contains(strings.ToLower(msg), "api key") || strings.Contains(strings.ToLower(msg), "apikey") {
			return errKey
		}
		if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
			msg = msg[:i]
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if msg == "" {
			msg = "the request failed"
		}
		return errors.New("SABnzbd: " + rest.Redact(msg))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from SABnzbd: %w", err)
		}
	}
	return nil
}

func mode(m string, kv ...string) url.Values {
	q := url.Values{"mode": {m}}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return q
}

type slot struct {
	ID         string `json:"nzo_id"`
	Name       string `json:"filename"`
	Status     string `json:"status"`
	Percentage string `json:"percentage"`
	MB         string `json:"mb"`
	MBLeft     string `json:"mbleft"`
	TimeLeft   string `json:"timeleft"`
	Category   string `json:"cat"`
	Priority   string `json:"priority"`
}

type queue struct {
	Status        string `json:"status"`
	Paused        bool   `json:"paused"`
	KBPerSec      string `json:"kbpersec"`
	MBLeft        string `json:"mbleft"`
	TimeLeft      string `json:"timeleft"`
	SpeedLimit    string `json:"speedlimit"`
	SpeedLimitAbs string `json:"speedlimit_abs"`
	DiskSpace     string `json:"diskspace1"`
	Count         int    `json:"noofslots"`
	Slots         []slot `json:"slots"`
}

func (c *conn) queue(ctx context.Context, limit int, ids []string) (queue, error) {
	var out struct {
		Queue queue `json:"queue"`
	}
	q := mode("queue", "start", "0", "limit", strconv.Itoa(limit))
	if len(ids) > 0 {
		q.Set("nzo_ids", strings.Join(ids, ","))
		q.Del("limit")
	}
	err := c.call(ctx, q, &out)
	return out.Queue, err
}

type histSlot struct {
	ID           string `json:"nzo_id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	FailMessage  string `json:"fail_message"`
	Bytes        int64  `json:"bytes"`
	Category     string `json:"category"`
	Completed    int64  `json:"completed"`
	DownloadTime int64  `json:"download_time"`
	Storage      string `json:"storage"`
	// The NZB's URL isn't read: indexers put their API key in it.
}

func (c *conn) history(ctx context.Context, limit int, failed bool, ids []string) ([]histSlot, int, error) {
	var out struct {
		History struct {
			Count int        `json:"noofslots"`
			Slots []histSlot `json:"slots"`
		} `json:"history"`
	}
	q := mode("history", "start", "0", "limit", strconv.Itoa(limit))
	if failed {
		q.Set("failed_only", "1")
	}
	if len(ids) > 0 {
		q.Set("nzo_ids", strings.Join(ids, ","))
		q.Del("limit")
	}
	err := c.call(ctx, q, &out)
	return out.History.Slots, out.History.Count, err
}

func num(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
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
	if err := c.call(ctx, mode("version"), &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	q, err := c.queue(ctx, 1, nil)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("SABnzbd %s · %d jobs", v.Version, q.Count)
	if q.Paused {
		msg += ", paused"
	} else if s := num(q.KBPerSec); s > 0 {
		msg += fmt.Sprintf(", downloading at %.0f KiB/s", s)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Limit       int      `json:"limit"`
	FailedOnly  bool     `json:"failedOnly"`
	Jobs        []string `json:"jobs"`
	DeleteFiles bool     `json:"deleteFiles"`
	URL         string   `json:"url"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Priority    string   `json:"priority"`
	KiBs        *int64   `json:"kiBs"`
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
		q, err := c.queue(ctx, limit, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		jobs := []map[string]any{}
		for _, s := range q.Slots {
			jobs = append(jobs, map[string]any{"id": s.ID, "name": s.Name, "status": s.Status, "progress": num(s.Percentage),
				"sizeMB": num(s.MB), "leftMB": num(s.MBLeft), "timeLeft": s.TimeLeft, "category": s.Category, "priority": s.Priority})
		}
		return sdk.JSON(map[string]any{"status": q.Status, "paused": q.Paused, "speedKiBs": num(q.KBPerSec), "leftMB": num(q.MBLeft),
			"timeLeft": q.TimeLeft, "speedLimitKiBs": limitOut(q), "freeDiskGB": num(q.DiskSpace), "total": q.Count, "jobs": jobs})
	case "history":
		slots, n, err := c.history(ctx, limit, p.FailedOnly, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range slots {
			e := map[string]any{"id": s.ID, "name": s.Name, "status": s.Status, "sizeMB": s.Bytes >> 20, "category": s.Category,
				"downloadSeconds": s.DownloadTime}
			if s.Completed > 0 {
				e["completed"] = time.Unix(s.Completed, 0).UTC().Format(time.RFC3339)
			}
			if s.FailMessage != "" {
				e["failure"] = rest.Redact(s.FailMessage)
			}
			if s.Storage != "" {
				e["path"] = s.Storage
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"total": n, "entries": out})
	case "pause", "resume":
		return c.pauseResume(ctx, call, p.Jobs)
	case "add_url":
		return c.addURL(ctx, call.DryRun, p)
	case "delete":
		return c.delete(ctx, call.DryRun, p)
	case "set_speed_limit":
		return c.speedLimit(ctx, call.DryRun, p.KiBs)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// limitKiB is the queue's speed limit in KiB/s, 0 when there's none.
func limitKiB(q queue) int64 {
	abs := num(q.SpeedLimitAbs)
	if abs <= 0 || (q.SpeedLimit != "" && num(q.SpeedLimit) <= 0) {
		return 0
	}
	return int64(abs+1023) >> 10
}

func limitOut(q queue) any {
	if k := limitKiB(q); k > 0 {
		return k
	}
	return "unlimited"
}

func checkJobs(in []string) ([]string, error) {
	if len(in) > maxJobs {
		return nil, fmt.Errorf("pick at most %d jobs", maxJobs)
	}
	seen := map[string]bool{}
	var out []string
	for _, j := range in {
		j = strings.TrimSpace(j)
		if !jobRe.MatchString(j) {
			return nil, errors.New("a job is its id from queue or history, like SABnzbd_nzo_abc123")
		}
		if !seen[j] {
			seen[j] = true
			out = append(out, j)
		}
	}
	return out, nil
}

func (c *conn) pauseResume(ctx context.Context, call sdk.Call, in []string) (sdk.Result, error) {
	pausing := call.Action == "pause"
	ids, err := checkJobs(in)
	if err != nil {
		return sdk.Result{}, err
	}
	verb, back := "Pause", "resume"
	if !pausing {
		verb, back = "Resume", "pause"
	}
	if len(ids) == 0 {
		q, err := c.queue(ctx, 1, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		if q.Paused == pausing {
			return sdk.JSON(map[string]any{"queuePaused": q.Paused, "note": "nothing to change"})
		}
		if call.DryRun {
			b, _ := json.Marshal(map[string]bool{"paused": q.Paused})
			a, _ := json.Marshal(map[string]bool{"paused": pausing})
			return sdk.Result{Plan: &sdk.Plan{Summary: verb + " the SABnzbd queue", Changes: []sdk.Change{{Target: fmt.Sprintf("queue (%d jobs)", q.Count), Op: call.Action, Before: b, After: a}}}}, nil
		}
		if err := c.call(ctx, mode(call.Action), nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"queuePaused": pausing})
		res.Undo = sdk.UndoWith(back, map[string]any{}, verbPast(back)+" the queue again")
		return res, err
	}
	q, err := c.queue(ctx, 0, ids)
	if err != nil {
		return sdk.Result{}, err
	}
	found := map[string]slot{}
	for _, s := range q.Slots {
		found[s.ID] = s
	}
	var change []string
	var changes []sdk.Change
	for _, id := range ids {
		s, ok := found[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("there's no job %s in the queue", id)
		}
		if (s.Status == "Paused") == pausing {
			continue
		}
		change = append(change, id)
		b, _ := json.Marshal(s.Status)
		changes = append(changes, sdk.Change{Target: s.Name, Op: call.Action, Before: b})
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []string{}, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %d jobs", verb, len(change)), Changes: changes}}, nil
	}
	if err := c.call(ctx, mode("queue", "name", call.Action, "value", strings.Join(change, ",")), nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"jobs": change}, fmt.Sprintf("%s %d jobs again", verbPast(back), len(change)))
	return res, err
}

func verbPast(action string) string { return strings.ToUpper(action[:1]) + action[1:] }

var priorities = map[string]string{"default": "-100", "paused": "-2", "low": "-1", "normal": "0", "high": "1", "force": "2"}

func clean(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 200 || strings.ContainsAny(s, "\r\n\x00") {
		return "", fmt.Errorf("the %s is one line of at most 200 characters", what)
	}
	return s, nil
}

func (c *conn) addURL(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	s := strings.TrimSpace(p.URL)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(s, "\r\n") || len(s) > 8192 {
		return sdk.Result{}, errors.New("the url is the http(s) address of an NZB")
	}
	shown := u.Scheme + "://" + u.Host + u.EscapedPath() // the query holds the indexer's key
	q := mode("addurl", "name", s)
	name, err := clean(p.Name, "name")
	if err != nil {
		return sdk.Result{}, err
	}
	if name != "" {
		q.Set("nzbname", name)
	}
	cat, err := clean(p.Category, "category")
	if err != nil {
		return sdk.Result{}, err
	}
	if cat != "" {
		q.Set("cat", cat)
	}
	prio := p.Priority
	if prio == "" {
		prio = "default"
	}
	pv, ok := priorities[prio]
	if !ok {
		return sdk.Result{}, fmt.Errorf("unknown priority %q", prio)
	}
	q.Set("priority", pv)
	if dry {
		a, _ := json.Marshal(map[string]string{"name": name, "category": cat, "priority": prio})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Add an NZB to SABnzbd", Changes: []sdk.Change{{Target: shown, Op: "add", After: a}}}}, nil
	}
	var out struct {
		IDs []string `json:"nzo_ids"`
	}
	if err := c.call(ctx, q, &out); err != nil {
		return sdk.Result{}, err
	}
	var ids []string
	for _, id := range out.IDs {
		if jobRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return sdk.Result{}, errors.New("SABnzbd didn't queue the NZB")
	}
	res, err := sdk.JSON(map[string]any{"added": ids, "source": shown})
	res.Undo = sdk.UndoWith("delete", map[string]any{"jobs": ids, "deleteFiles": false}, "Delete the added job")
	return res, err
}

func (c *conn) delete(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	ids, err := checkJobs(p.Jobs)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(ids) == 0 {
		return sdk.Result{}, errors.New("pick the jobs to delete")
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	q, err := c.queue(ctx, 0, ids)
	if err != nil {
		return sdk.Result{}, err
	}
	hist, _, err := c.history(ctx, 0, false, ids)
	if err != nil {
		return sdk.Result{}, err
	}
	var inQueue, inHist []string
	names := map[string]string{}
	for _, s := range q.Slots {
		if want[s.ID] && names[s.ID] == "" {
			inQueue = append(inQueue, s.ID)
			names[s.ID] = s.Name + " (queue)"
		}
	}
	for _, s := range hist {
		if want[s.ID] && names[s.ID] == "" {
			inHist = append(inHist, s.ID)
			names[s.ID] = s.Name + " (history)"
		}
	}
	for _, id := range ids {
		if names[id] == "" {
			return sdk.Result{}, fmt.Errorf("there's no job %s", id)
		}
	}
	op := "delete (files kept)"
	if p.DeleteFiles {
		op = "delete with files"
	}
	var changes []sdk.Change
	for _, id := range ids {
		changes = append(changes, sdk.Change{Target: names[id], Op: op})
	}
	if dry {
		sum := fmt.Sprintf("Delete %d jobs", len(ids))
		if p.DeleteFiles {
			sum += " and their files"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	del := "0"
	if p.DeleteFiles {
		del = "1"
	}
	for _, part := range []struct {
		mode string
		ids  []string
	}{{"queue", inQueue}, {"history", inHist}} {
		if len(part.ids) == 0 {
			continue
		}
		if err := c.call(ctx, mode(part.mode, "name", "delete", "value", strings.Join(part.ids, ","), "del_files", del), nil); err != nil {
			return sdk.Result{}, err
		}
	}
	return sdk.JSON(map[string]any{"deleted": ids, "filesDeleted": p.DeleteFiles})
}

func (c *conn) speedLimit(ctx context.Context, dry bool, want *int64) (sdk.Result, error) {
	if want == nil || *want < 0 || *want > 10000000 {
		return sdk.Result{}, errors.New("kiBs is 0 (unlimited) to 10000000")
	}
	q, err := c.queue(ctx, 1, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	prev := limitKiB(q)
	if prev == *want {
		return sdk.JSON(map[string]any{"speedLimitKiBs": limitOut(q), "note": "nothing to change"})
	}
	show := func(k int64) any {
		if k == 0 {
			return "unlimited"
		}
		return k
	}
	if dry {
		b, _ := json.Marshal(show(prev))
		a, _ := json.Marshal(show(*want))
		return sdk.Result{Plan: &sdk.Plan{Summary: "Change SABnzbd's speed limit", Changes: []sdk.Change{{Target: "download speed limit (KiB/s)", Op: "update", Before: b, After: a}}}}, nil
	}
	value := "0"
	if *want > 0 {
		value = strconv.FormatInt(*want, 10) + "K"
	}
	if err := c.call(ctx, mode("config", "name", "speedlimit", "value", value), nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"speedLimitKiBs": show(*want)})
	res.Undo = sdk.UndoWith("set_speed_limit", map[string]any{"kiBs": prev}, "Restore the previous speed limit")
	return res, err
}
