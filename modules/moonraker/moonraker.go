// Package moonraker works with a Klipper 3D printer through Moonraker's API,
// with an optional API key: the printer's status (state, file, progress,
// heaters), any printer object's status, the job queue and print history,
// pausing, resuming and cancelling a print and setting heater targets.
// Anything that heats or moves the printer, or ends a print, is destructive;
// heater targets above the configured maximums are refused. No G-code is
// sent as such, and the emergency stop isn't offered (see the docs page).
package moonraker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Moonraker server.
type Config struct {
	URL    string `json:"url"`    // e.g. http://voron.local:7125
	APIKey string `json:"apiKey"` // secret://, optional (trusted clients need none)
	// MaxHotend and MaxBed are the highest heater targets set_temperature
	// accepts, in °C (defaults 260 and 110).
	MaxHotend          float64 `json:"maxHotend"`
	MaxBed             float64 `json:"maxBed"`
	Fingerprint        string  `json:"fingerprint"`
	InsecureSkipVerify bool    `json:"insecureSkipVerify"`
}

type conn struct {
	api              *rest.Client
	maxHotend, maxBd float64
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Moonraker module.
func New() *Module { return &Module{} }

const (
	defaultHotend = 260
	defaultBed    = 110
	maxObjects    = 20
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Klipper object names: print_stats, extruder1, "temperature_sensor chamber".
	objectRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}( [A-Za-z0-9_-]{1,64})?$`)
	heaterRe = regexp.MustCompile(`^(extruder[0-9]?|heater_bed)$`)
	// hidden objects can be large or carry the whole configuration.
	hidden = map[string]bool{"configfile": true}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "moonraker", Name: "Moonraker (Klipper)", Version: "0.1.0", Category: "Smart home", Icon: "layers",
		Description: "Klipper printers through Moonraker: status, heaters, job queue and history; pause, resume or cancel a print and set heater targets.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Moonraker's address, e.g. http://voron.local:7125 (or the Mainsail/Fluidd address that proxies it)"},
			"apiKey":{"type":"string","x-secret":true,"description":"Moonraker's API key, if Conduit isn't a trusted client (Mainsail or Fluidd: settings, API key)"},
			"maxHotend":{"type":"number","default":260,"minimum":1,"maximum":500,"description":"Highest extruder target set_temperature accepts, in °C"},
			"maxBed":{"type":"number","default":110,"minimum":1,"maximum":200,"description":"Highest bed target set_temperature accepts, in °C"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Printer status", Description: "Klipper's state, the print's state, file, progress, durations and filament, and each extruder's and the bed's temperature, target and power. objects adds other printer objects.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"objects":{"type":"array","maxItems":20,"items":{"type":"string"},"description":"More printer objects to include, e.g. toolhead or temperature_sensor chamber (see objects)"}}}`)},
			{Name: "objects", Title: "Printer objects", Description: "The names of the printer's objects (heaters, fans, sensors, toolhead …) and its heaters.", Risk: sdk.RiskRead},
			{Name: "job_queue", Title: "Job queue", Description: "The queue's state and the files waiting in it, with how long they've waited.", Risk: sdk.RiskRead},
			{Name: "history", Title: "Print history", Description: "Recent prints, newest first: file, result, start and end, print time and filament.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "pause_print", Title: "Pause the print", Description: "Pauses the running print. A long pause can leave a mark or let a part come loose. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true},
			{Name: "resume_print", Title: "Resume the print", Description: "Resumes a paused print: the printer heats and moves again. Undo pauses it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true},
			{Name: "cancel_print", Title: "Cancel the print", Description: "Cancels the running or paused print. The part can't be finished afterwards.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "set_temperature", Title: "Set a heater target", Description: "Sets an extruder (extruder, extruder1 …) or heater_bed target in °C; 0 turns the heater off. Targets above maxHotend or maxBed are refused. Undo sets the previous target.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["heater","target"],"properties":{"heater":{"type":"string","description":"extruder, extruder1 … or heater_bed"},"target":{"type":"number","minimum":0,"maximum":500,"description":"°C; 0 turns it off"}}}`)},
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
		return errors.New("the address is like http://voron.local:7125")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	if c.MaxHotend == 0 {
		c.MaxHotend = defaultHotend
	}
	if c.MaxBed == 0 {
		c.MaxBed = defaultBed
	}
	if c.MaxHotend < 1 || c.MaxHotend > 500 || c.MaxBed < 1 || c.MaxBed > 200 {
		return errors.New("maxHotend is 1–500 °C and maxBed 1–200 °C")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Api-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, maxHotend: c.MaxHotend, maxBd: c.MaxBed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Moonraker refused the request: set its API key, or add Conduit's address to trusted_clients")
	}
	return err
}

// do calls Moonraker and unwraps its {"result": …} answer.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if _, err := c.api.Do(ctx, method, path, q, body, &env); err != nil {
		return friendly(err)
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return errors.New("unexpected answer from Moonraker")
	}
	return nil
}

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// clean redacts and shortens every string in an object's status, and cuts
// deep or long structures.
func clean(v any, depth int) any {
	switch x := v.(type) {
	case string:
		return clip(x, 200)
	case map[string]any:
		if depth > 4 {
			return "…"
		}
		out := map[string]any{}
		for k, e := range x {
			if len(out) >= 100 {
				break
			}
			out[clip(k, 64)] = clean(e, depth+1)
		}
		return out
	case []any:
		if depth > 4 {
			return "…"
		}
		out := []any{}
		for i, e := range x {
			if i >= 100 {
				break
			}
			out = append(out, clean(e, depth+1))
		}
		return out
	}
	return v
}

func round(f float64) float64 { return math.Round(f*10) / 10 }

type info struct {
	KlippyConnected bool   `json:"klippy_connected"`
	KlippyState     string `json:"klippy_state"`
	Version         string `json:"moonraker_version"`
}

type printStats struct {
	Filename      string  `json:"filename"`
	State         string  `json:"state"`
	Message       string  `json:"message"`
	TotalDuration float64 `json:"total_duration"`
	PrintDuration float64 `json:"print_duration"`
	FilamentUsed  float64 `json:"filament_used"`
}

type heater struct {
	Temperature *float64 `json:"temperature"`
	Target      *float64 `json:"target"`
	Power       *float64 `json:"power"`
}

type snapshot struct {
	Stats    printStats
	Progress *float64
	Heaters  map[string]heater
	Extra    map[string]any
}

// query reads print_stats, the progress, the heaters and extra objects.
func (c *conn) query(ctx context.Context, extra []string) (snapshot, error) {
	var hs struct {
		Status struct {
			Heaters struct {
				Available []string `json:"available_heaters"`
			} `json:"heaters"`
		} `json:"status"`
	}
	if err := c.do(ctx, http.MethodPost, "/printer/objects/query", nil, map[string]any{"objects": map[string]any{"heaters": []string{"available_heaters"}}}, &hs); err != nil {
		return snapshot{}, c.klippyErr(ctx, err)
	}
	objs := map[string]any{"print_stats": nil, "virtual_sdcard": []string{"progress", "is_active"}}
	var heaters []string
	for _, h := range hs.Status.Heaters.Available {
		if heaterRe.MatchString(h) {
			heaters = append(heaters, h)
			objs[h] = []string{"temperature", "target", "power"}
		}
	}
	for _, e := range extra {
		objs[e] = nil
	}
	var res struct {
		Status map[string]json.RawMessage `json:"status"`
	}
	if err := c.do(ctx, http.MethodPost, "/printer/objects/query", nil, map[string]any{"objects": objs}, &res); err != nil {
		return snapshot{}, c.klippyErr(ctx, err)
	}
	s := snapshot{Heaters: map[string]heater{}, Extra: map[string]any{}}
	json.Unmarshal(res.Status["print_stats"], &s.Stats)
	var sd struct {
		Progress *float64 `json:"progress"`
	}
	if json.Unmarshal(res.Status["virtual_sdcard"], &sd) == nil {
		s.Progress = sd.Progress
	}
	for _, h := range heaters {
		var ht heater
		if json.Unmarshal(res.Status[h], &ht) == nil && ht.Temperature != nil {
			s.Heaters[h] = ht
		}
	}
	for _, e := range extra {
		if v, ok := res.Status[e]; ok {
			var x any
			if len(v) > 32<<10 || json.Unmarshal(v, &x) != nil {
				s.Extra[e] = "too large to show"
				continue
			}
			s.Extra[e] = clean(x, 0)
		}
	}
	return s, nil
}

// klippyErr explains a failed printer query when Klipper isn't ready.
func (c *conn) klippyErr(ctx context.Context, err error) error {
	if rest.IsStatus(err, http.StatusServiceUnavailable) || rest.IsStatus(err, http.StatusBadRequest) {
		var i info
		if c.do(ctx, http.MethodGet, "/server/info", nil, nil, &i) == nil && i.KlippyState != "ready" {
			return fmt.Errorf("Klipper isn't ready (%s)", clip(i.KlippyState, 40))
		}
	}
	return err
}

func (s snapshot) heaters() map[string]any {
	out := map[string]any{}
	for k, h := range s.Heaters {
		row := map[string]any{"temperature": round(*h.Temperature)}
		if h.Target != nil {
			row["target"] = round(*h.Target)
		}
		if h.Power != nil {
			row["power"] = math.Round(*h.Power * 100)
		}
		out[k] = row
	}
	return out
}

func (s snapshot) view() map[string]any {
	out := map[string]any{"state": s.Stats.State, "heaters": s.heaters()}
	if s.Stats.Filename != "" {
		out["file"] = clip(s.Stats.Filename, 300)
	}
	if s.Stats.Message != "" {
		out["message"] = clip(s.Stats.Message, 200)
	}
	if s.Progress != nil {
		out["progress"] = round(*s.Progress * 100)
	}
	if s.Stats.State == "printing" || s.Stats.State == "paused" || s.Stats.State == "complete" {
		out["printSeconds"] = int(s.Stats.PrintDuration)
		out["totalSeconds"] = int(s.Stats.TotalDuration)
		out["filamentMm"] = math.Round(s.Stats.FilamentUsed)
	}
	if len(s.Extra) > 0 {
		out["objects"] = s.Extra
	}
	return out
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var i info
	if err := c.do(ctx, http.MethodGet, "/server/info", nil, nil, &i); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Moonraker API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Moonraker " + clip(i.Version, 30)
	if !i.KlippyConnected || i.KlippyState != "ready" {
		return sdk.Health{Status: "degraded", Message: msg + ", Klipper " + clip(i.KlippyState, 40)}
	}
	s, err := c.query(ctx, nil)
	if err != nil {
		return sdk.Health{Status: "degraded", Message: msg + ", " + err.Error()}
	}
	msg += ", printer " + s.Stats.State
	if s.Stats.State == "error" {
		return sdk.Health{Status: "degraded", Message: msg}
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
		Objects []string `json:"objects"`
		Limit   int      `json:"limit"`
		Heater  string   `json:"heater"`
		Target  *float64 `json:"target"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		if len(p.Objects) > maxObjects {
			return sdk.Result{}, fmt.Errorf("ask for at most %d objects", maxObjects)
		}
		var extra []string
		for _, o := range p.Objects {
			o = strings.TrimSpace(o)
			if !objectRe.MatchString(o) {
				return sdk.Result{}, fmt.Errorf("%q isn't a printer object name like toolhead or temperature_sensor chamber", o)
			}
			if hidden[o] {
				return sdk.Result{}, fmt.Errorf("%s isn't offered: it holds the printer's whole configuration", o)
			}
			extra = append(extra, o)
		}
		s, err := c.query(ctx, extra)
		if err != nil {
			return sdk.Result{}, err
		}
		var i info
		out := s.view()
		if c.do(ctx, http.MethodGet, "/server/info", nil, nil, &i) == nil {
			out["klippy"] = i.KlippyState
		}
		return sdk.JSON(out)
	case "objects":
		var res struct {
			Objects []string `json:"objects"`
		}
		if err := c.do(ctx, http.MethodGet, "/printer/objects/list", nil, nil, &res); err != nil {
			return sdk.Result{}, c.klippyErr(ctx, err)
		}
		names := []string{}
		for _, o := range res.Objects {
			if !hidden[o] && objectRe.MatchString(o) {
				names = append(names, o)
			}
		}
		sort.Strings(names)
		var heaters []string
		for _, o := range names {
			if heaterRe.MatchString(o) {
				heaters = append(heaters, o)
			}
		}
		return sdk.JSON(map[string]any{"objects": names, "heaters": heaters})
	case "job_queue":
		var q struct {
			State string `json:"queue_state"`
			Jobs  []struct {
				Filename    string  `json:"filename"`
				JobID       string  `json:"job_id"`
				TimeAdded   float64 `json:"time_added"`
				TimeInQueue float64 `json:"time_in_queue"`
			} `json:"queued_jobs"`
		}
		if err := c.do(ctx, http.MethodGet, "/server/job_queue/status", nil, nil, &q); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("the job queue isn't enabled in moonraker.conf ([job_queue])")
			}
			return sdk.Result{}, err
		}
		jobs := []map[string]any{}
		for _, j := range q.Jobs {
			jobs = append(jobs, map[string]any{"file": clip(j.Filename, 300), "id": clip(j.JobID, 40), "added": unix(j.TimeAdded), "waitingSeconds": int(j.TimeInQueue)})
		}
		return sdk.JSON(map[string]any{"state": q.State, "jobs": jobs})
	case "history":
		if p.Limit == 0 {
			p.Limit = 20
		}
		if p.Limit < 1 || p.Limit > 100 {
			return sdk.Result{}, errors.New("limit is 1–100")
		}
		var h struct {
			Count int `json:"count"`
			Jobs  []struct {
				JobID         string   `json:"job_id"`
				Filename      string   `json:"filename"`
				Status        string   `json:"status"`
				StartTime     float64  `json:"start_time"`
				EndTime       *float64 `json:"end_time"`
				PrintDuration float64  `json:"print_duration"`
				TotalDuration float64  `json:"total_duration"`
				FilamentUsed  float64  `json:"filament_used"`
				Exists        bool     `json:"exists"`
			} `json:"jobs"`
		}
		q := url.Values{"limit": {strconv.Itoa(p.Limit)}, "order": {"desc"}}
		if err := c.do(ctx, http.MethodGet, "/server/history/list", q, nil, &h); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("print history isn't enabled in moonraker.conf ([history])")
			}
			return sdk.Result{}, err
		}
		jobs := []map[string]any{}
		for _, j := range h.Jobs {
			row := map[string]any{"id": clip(j.JobID, 40), "file": clip(j.Filename, 300), "status": j.Status, "started": unix(j.StartTime),
				"printSeconds": int(j.PrintDuration), "totalSeconds": int(j.TotalDuration), "filamentMm": math.Round(j.FilamentUsed), "fileExists": j.Exists}
			if j.EndTime != nil {
				row["ended"] = unix(*j.EndTime)
			}
			jobs = append(jobs, row)
		}
		return sdk.JSON(map[string]any{"total": h.Count, "jobs": jobs})
	case "pause_print", "resume_print", "cancel_print":
		return c.control(ctx, call)
	case "set_temperature":
		p.Heater = strings.TrimSpace(p.Heater)
		if !heaterRe.MatchString(p.Heater) {
			return sdk.Result{}, errors.New("a heater is extruder, extruder1 … or heater_bed")
		}
		if p.Target == nil || math.IsNaN(*p.Target) || *p.Target < 0 {
			return sdk.Result{}, errors.New("target is a temperature in °C (0 turns the heater off)")
		}
		limit := c.maxHotend
		if p.Heater == "heater_bed" {
			limit = c.maxBd
		}
		if *p.Target > limit {
			return sdk.Result{}, fmt.Errorf("%g °C is above the highest %s target allowed here (%g °C, maxHotend/maxBed in the settings)", *p.Target, p.Heater, limit)
		}
		return c.setTemp(ctx, call, p.Heater, round(*p.Target))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func unix(f float64) string {
	if f <= 0 {
		return ""
	}
	return time.Unix(int64(f), 0).UTC().Format(time.RFC3339)
}

func (c *conn) control(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	s, err := c.query(ctx, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	name := clip(s.Stats.Filename, 300)
	state := s.Stats.State
	var verb, op, path, back string
	switch call.Action {
	case "pause_print":
		if state == "paused" {
			return sdk.JSON(map[string]any{"file": name, "state": state, "note": "nothing to change"})
		}
		if state != "printing" {
			return sdk.Result{}, fmt.Errorf("no print is running (%s)", state)
		}
		verb, op, path, back = "Pause", "pause", "/printer/print/pause", "resume_print"
	case "resume_print":
		if state == "printing" {
			return sdk.JSON(map[string]any{"file": name, "state": state, "note": "nothing to change"})
		}
		if state != "paused" {
			return sdk.Result{}, fmt.Errorf("no print is paused (%s)", state)
		}
		verb, op, path, back = "Resume", "resume", "/printer/print/resume", "pause_print"
	default:
		if state != "printing" && state != "paused" {
			return sdk.Result{}, fmt.Errorf("no print is running or paused (%s)", state)
		}
		verb, op, path = "Cancel", "cancel", "/printer/print/cancel"
	}
	if call.DryRun {
		sum := verb + " the print of " + name
		if s.Progress != nil {
			sum += fmt.Sprintf(" at %.0f%%", *s.Progress*100)
		}
		switch op {
		case "cancel":
			sum += "; it can't be finished afterwards"
		case "resume":
			sum += "; the printer heats and moves again"
		}
		b, _ := json.Marshal(map[string]string{"state": state})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "print " + name, Op: op, Before: b}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"file": name, "done": op})
	switch back {
	case "resume_print":
		res.Undo = sdk.UndoWith(back, map[string]any{}, "Resume "+name)
	case "pause_print":
		res.Undo = sdk.UndoWith(back, map[string]any{}, "Pause "+name+" again")
	}
	return res, err
}

func (c *conn) setTemp(ctx context.Context, call sdk.Call, name string, target float64) (sdk.Result, error) {
	s, err := c.query(ctx, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	h, ok := s.Heaters[name]
	if !ok {
		return sdk.Result{}, fmt.Errorf("the printer has no heater %s", name)
	}
	prev := 0.0
	if h.Target != nil {
		prev = round(*h.Target)
	}
	if prev == target {
		return sdk.JSON(map[string]any{"heater": name, "target": target, "note": "nothing to change"})
	}
	now := round(*h.Temperature)
	if call.DryRun {
		b, _ := json.Marshal(map[string]float64{"target": prev, "temperature": now})
		a, _ := json.Marshal(map[string]float64{"target": target})
		sum := fmt.Sprintf("Set %s to %g °C (now %g °C, target %g °C)", name, target, now, prev)
		if target == 0 {
			sum = fmt.Sprintf("Turn %s off (now %g °C, target %g °C)", name, now, prev)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "heater " + name, Op: "set target", Before: b, After: a}}}}, nil
	}
	// The script is built from the checked heater name and a number only.
	script := "SET_HEATER_TEMPERATURE HEATER=" + name + " TARGET=" + strconv.FormatFloat(target, 'f', -1, 64)
	if err := c.do(ctx, http.MethodPost, "/printer/gcode/script", url.Values{"script": {script}}, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"heater": name, "target": target, "was": prev})
	res.Undo = sdk.UndoWith("set_temperature", map[string]any{"heater": name, "target": prev}, fmt.Sprintf("Set %s back to %g °C", name, prev))
	return res, err
}
