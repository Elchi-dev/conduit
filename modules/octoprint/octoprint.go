// Package octoprint works with a 3D printer through OctoPrint's REST API and
// an API key: printer state and temperatures, the current job and its
// progress, the uploaded files, pausing, resuming and cancelling a print,
// starting one from an uploaded file and setting heater targets. Anything
// that heats or moves the printer, or ends a print, is destructive; heater
// targets above the configured maximums are refused, and no G-code is ever
// sent as such.
package octoprint

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
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OctoPrint server.
type Config struct {
	URL    string `json:"url"`    // e.g. http://octopi.local
	APIKey string `json:"apiKey"` // secret://
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

// New returns the OctoPrint module.
func New() *Module { return &Module{} }

const (
	defaultHotend = 260
	defaultBed    = 110
	maxFiles      = 1000
)

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	heaterRe = regexp.MustCompile(`^(tool[0-9]|bed)$`)
	gcodeExt = regexp.MustCompile(`(?i)\.(gcode|gco|g)$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "octoprint", Name: "OctoPrint", Version: "0.1.0", Category: "Smart home", Icon: "layers",
		Description: "OctoPrint 3D printers: state, temperatures, job progress and files; pause, resume or cancel a print, start one and set heater targets.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"OctoPrint's address, e.g. http://octopi.local"},
			"apiKey":{"type":"string","x-secret":true,"description":"An application key or your user's API key (Settings, Application Keys or User Settings, API Key)"},
			"maxHotend":{"type":"number","default":260,"minimum":1,"maximum":500,"description":"Highest hotend target set_temperature accepts, in °C"},
			"maxBed":{"type":"number","default":110,"minimum":1,"maximum":200,"description":"Highest bed target set_temperature accepts, in °C"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "printer", Title: "Printer", Description: "Whether the printer is connected, its state (printing, paused, ready, error) and each heater's temperature and target.", Risk: sdk.RiskRead},
			{Name: "job", Title: "Current job", Description: "The file being printed, progress, time printed and time left, estimated print time and filament.", Risk: sdk.RiskRead},
			{Name: "files", Title: "Files", Description: "Uploaded files (folders flattened) with path, origin, size, upload date and estimated print time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"origin":{"type":"string","enum":["local","sdcard"],"description":"Only local uploads or the printer's SD card"}}}`)},
			{Name: "pause_print", Title: "Pause the print", Description: "Pauses the running print. A long pause can leave a mark or let a part come loose. Undo resumes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true},
			{Name: "resume_print", Title: "Resume the print", Description: "Resumes a paused print: the printer heats and moves again. Undo pauses it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true},
			{Name: "cancel_print", Title: "Cancel the print", Description: "Cancels the running or paused print. The part can't be finished afterwards.", Risk: sdk.RiskDestructive, DryRun: true},
			{Name: "start_print", Title: "Start a print", Description: "Selects an uploaded file and prints it. The printer heats up and moves: make sure the bed is clear. The preview names the file, its estimated time and the current temperatures.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":1024,"description":"The file's path from files, e.g. benchy.gcode or parts/clip.gcode"},"origin":{"type":"string","enum":["local","sdcard"],"default":"local"}}}`)},
			{Name: "set_temperature", Title: "Set a heater target", Description: "Sets a hotend (tool0, tool1 …) or bed target in °C; 0 turns the heater off. Targets above maxHotend or maxBed are refused. Undo sets the previous target.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["heater","target"],"properties":{"heater":{"type":"string","description":"tool0, tool1 … or bed"},"target":{"type":"number","minimum":0,"maximum":500,"description":"°C; 0 turns it off"}}}`)},
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
		return errors.New("the address is like http://octopi.local")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
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

var errOffline = errors.New("the printer isn't connected to OctoPrint")

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("OctoPrint refused the API key")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return friendly(err)
}

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

type temp struct {
	Actual *float64 `json:"actual"`
	Target *float64 `json:"target"`
}

type flags struct {
	Operational   bool `json:"operational"`
	Printing      bool `json:"printing"`
	Paused        bool `json:"paused"`
	Pausing       bool `json:"pausing"`
	Cancelling    bool `json:"cancelling"`
	Ready         bool `json:"ready"`
	Error         bool `json:"error"`
	ClosedOrError bool `json:"closedOrError"`
}

type printer struct {
	Connected bool
	State     string
	Flags     flags
	Temps     map[string]temp
}

func (c *conn) printer(ctx context.Context) (printer, error) {
	var raw struct {
		Temperature map[string]json.RawMessage `json:"temperature"`
		State       struct {
			Text  string `json:"text"`
			Flags flags  `json:"flags"`
		} `json:"state"`
	}
	err := c.do(ctx, http.MethodGet, "/printer", nil, &raw)
	if rest.IsStatus(err, http.StatusConflict) {
		return printer{State: "Offline"}, nil
	}
	if err != nil {
		return printer{}, err
	}
	p := printer{Connected: true, State: clip(raw.State.Text, 80), Flags: raw.State.Flags, Temps: map[string]temp{}}
	for k, v := range raw.Temperature {
		var t temp
		if heaterRe.MatchString(k) || k == "chamber" {
			if json.Unmarshal(v, &t) == nil && t.Actual != nil {
				p.Temps[k] = t
			}
		}
	}
	return p, nil
}

func (p printer) temps() map[string]any {
	out := map[string]any{}
	for k, t := range p.Temps {
		row := map[string]any{"actual": round(*t.Actual)}
		if t.Target != nil {
			row["target"] = round(*t.Target)
		}
		out[k] = row
	}
	return out
}

func round(f float64) float64 { return math.Round(f*10) / 10 }

type jobInfo struct {
	Job struct {
		File struct {
			Name    string `json:"name"`
			Display string `json:"display"`
			Path    string `json:"path"`
			Origin  string `json:"origin"`
			Size    *int64 `json:"size"`
		} `json:"file"`
		EstimatedPrintTime *float64 `json:"estimatedPrintTime"`
		Filament           map[string]struct {
			Length float64 `json:"length"`
		} `json:"filament"`
	} `json:"job"`
	Progress struct {
		Completion    *float64 `json:"completion"`
		PrintTime     *float64 `json:"printTime"`
		PrintTimeLeft *float64 `json:"printTimeLeft"`
	} `json:"progress"`
	State string `json:"state"`
	Error string `json:"error"`
}

func (j jobInfo) view() map[string]any {
	out := map[string]any{"state": clip(j.State, 80)}
	f := j.Job.File
	if f.Path != "" || f.Name != "" {
		name := f.Display
		if name == "" {
			name = f.Name
		}
		out["file"] = clip(name, 200)
		out["path"] = clip(f.Path, 1024)
		out["origin"] = f.Origin
		if f.Size != nil {
			out["size"] = *f.Size
		}
	}
	if j.Progress.Completion != nil {
		out["progress"] = round(*j.Progress.Completion)
	}
	if j.Progress.PrintTime != nil {
		out["printTimeSeconds"] = int(*j.Progress.PrintTime)
	}
	if j.Progress.PrintTimeLeft != nil {
		out["timeLeftSeconds"] = int(*j.Progress.PrintTimeLeft)
	}
	if j.Job.EstimatedPrintTime != nil {
		out["estimatedSeconds"] = int(*j.Job.EstimatedPrintTime)
	}
	if mm := filament(j.Job.Filament); mm > 0 {
		out["filamentMm"] = mm
	}
	if j.Error != "" {
		out["error"] = clip(j.Error, 200)
	}
	return out
}

func filament(f map[string]struct {
	Length float64 `json:"length"`
}) float64 {
	total := 0.0
	for _, t := range f {
		total += t.Length
	}
	return math.Round(total)
}

type file struct {
	Name     string   `json:"name"`
	Display  string   `json:"display"`
	Path     string   `json:"path"`
	Type     string   `json:"type"`
	Origin   string   `json:"origin"`
	Size     *int64   `json:"size"`
	Date     *int64   `json:"date"`
	Children []file   `json:"children"`
	Analysis analysis `json:"gcodeAnalysis"`
}

type analysis struct {
	EstimatedPrintTime *float64 `json:"estimatedPrintTime"`
	Filament           map[string]struct {
		Length float64 `json:"length"`
	} `json:"filament"`
}

func (f file) view() map[string]any {
	name := f.Display
	if name == "" {
		name = f.Name
	}
	row := map[string]any{"path": clip(f.Path, 1024), "name": clip(name, 200), "origin": f.Origin}
	if f.Size != nil {
		row["size"] = *f.Size
	}
	if f.Date != nil && *f.Date > 0 {
		row["uploaded"] = time.Unix(*f.Date, 0).UTC().Format(time.RFC3339)
	}
	if f.Analysis.EstimatedPrintTime != nil {
		row["estimatedSeconds"] = int(*f.Analysis.EstimatedPrintTime)
	}
	if mm := filament(f.Analysis.Filament); mm > 0 {
		row["filamentMm"] = mm
	}
	return row
}

func flatten(fs []file, out *[]file) {
	for _, f := range fs {
		if len(*out) >= maxFiles {
			return
		}
		if f.Type == "folder" {
			flatten(f.Children, out)
			continue
		}
		*out = append(*out, f)
	}
}

// filePath checks a file path from files and escapes it for a URL.
func filePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	bad := errors.New("a file is its path from files, like benchy.gcode or parts/clip.gcode")
	if p == "" || len(p) > 1024 || !gcodeExt.MatchString(p) {
		return "", bad
	}
	var parts []string
	for _, s := range strings.Split(p, "/") {
		if s == "" || strings.HasPrefix(s, ".") || len(s) > 255 {
			return "", bad
		}
		for _, r := range s {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" ._-()+,@~[]", r)) {
				return "", bad
			}
		}
		parts = append(parts, url.PathEscape(s))
	}
	return strings.Join(parts, "/"), nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Text   string `json:"text"`
		Server string `json:"server"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no OctoPrint API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	p, err := c.printer(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "OctoPrint " + clip(v.Server, 20)
	if !p.Connected {
		return sdk.Health{Status: "degraded", Message: msg + ", printer not connected"}
	}
	return sdk.Health{Status: "ok", Message: msg + ", printer " + strings.ToLower(p.State)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Origin string   `json:"origin"`
		Path   string   `json:"path"`
		Heater string   `json:"heater"`
		Target *float64 `json:"target"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Origin != "" && p.Origin != "local" && p.Origin != "sdcard" {
		return sdk.Result{}, errors.New("origin is local or sdcard")
	}
	switch call.Action {
	case "printer":
		pr, err := c.printer(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"connected": pr.Connected, "state": pr.State, "printing": pr.Flags.Printing, "paused": pr.Flags.Paused,
			"ready": pr.Flags.Ready, "error": pr.Flags.Error, "temperatures": pr.temps()})
	case "job":
		var j jobInfo
		if err := c.do(ctx, http.MethodGet, "/job", nil, &j); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(j.view())
	case "files":
		var fs struct {
			Files []file `json:"files"`
			Free  *int64 `json:"free"`
		}
		path := "/files"
		if p.Origin != "" {
			path += "/" + p.Origin
		}
		if err := c.do(ctx, http.MethodGet, path+"?recursive=true", nil, &fs); err != nil {
			return sdk.Result{}, err
		}
		var flat []file
		flatten(fs.Files, &flat)
		sort.Slice(flat, func(i, j int) bool { return flat[i].Path < flat[j].Path })
		rows := []map[string]any{}
		for _, f := range flat {
			rows = append(rows, f.view())
		}
		out := map[string]any{"files": rows}
		if fs.Free != nil {
			out["freeBytes"] = *fs.Free
		}
		return sdk.JSON(out)
	case "pause_print", "resume_print", "cancel_print":
		return c.control(ctx, call)
	case "start_print":
		origin := p.Origin
		if origin == "" {
			origin = "local"
		}
		fp, err := filePath(p.Path)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.start(ctx, call, origin, fp)
	case "set_temperature":
		p.Heater = strings.TrimSpace(p.Heater)
		if !heaterRe.MatchString(p.Heater) {
			return sdk.Result{}, errors.New("a heater is tool0, tool1 … or bed")
		}
		if p.Target == nil || math.IsNaN(*p.Target) || *p.Target < 0 {
			return sdk.Result{}, errors.New("target is a temperature in °C (0 turns the heater off)")
		}
		limit := c.maxHotend
		if p.Heater == "bed" {
			limit = c.maxBd
		}
		if *p.Target > limit {
			return sdk.Result{}, fmt.Errorf("%g °C is above the highest %s target allowed here (%g °C, maxHotend/maxBed in the settings)", *p.Target, p.Heater, limit)
		}
		return c.setTemp(ctx, call, p.Heater, round(*p.Target))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) control(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	pr, err := c.printer(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if !pr.Connected {
		return sdk.Result{}, errOffline
	}
	var j jobInfo
	if err := c.do(ctx, http.MethodGet, "/job", nil, &j); err != nil {
		return sdk.Result{}, err
	}
	name := j.Job.File.Display
	if name == "" {
		name = j.Job.File.Name
	}
	name = clip(name, 200)
	f := pr.Flags
	running := f.Printing || f.Pausing
	held := f.Paused
	var verb, op, back string
	var body map[string]string
	switch call.Action {
	case "pause_print":
		if held {
			return sdk.JSON(map[string]any{"file": name, "paused": true, "note": "nothing to change"})
		}
		if !running {
			return sdk.Result{}, errors.New("no print is running")
		}
		verb, op, back = "Pause", "pause", "resume_print"
		body = map[string]string{"command": "pause", "action": "pause"}
	case "resume_print":
		if running && !held {
			return sdk.JSON(map[string]any{"file": name, "paused": false, "note": "nothing to change"})
		}
		if !held {
			return sdk.Result{}, errors.New("no print is paused")
		}
		verb, op, back = "Resume", "resume", "pause_print"
		body = map[string]string{"command": "pause", "action": "resume"}
	default:
		if f.Cancelling {
			return sdk.JSON(map[string]any{"file": name, "note": "nothing to change: the print is already being cancelled"})
		}
		if !running && !held {
			return sdk.Result{}, errors.New("no print is running or paused")
		}
		verb, op = "Cancel", "cancel"
		body = map[string]string{"command": "cancel"}
	}
	progress := ""
	if j.Progress.Completion != nil {
		progress = fmt.Sprintf(" at %.0f%%", *j.Progress.Completion)
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"state": pr.State})
		summary := verb + " the print of " + name + progress
		if op == "cancel" {
			summary += "; it can't be finished afterwards"
		}
		if op == "resume" {
			summary += "; the printer heats and moves again"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "print " + name, Op: op, Before: b}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/job", body, nil); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("OctoPrint couldn't %s the print now (its state changed)", op)
		}
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"file": name, "done": op})
	if back != "" {
		undo := "Resume " + name
		if back == "pause_print" {
			undo = "Pause " + name + " again"
		}
		res.Undo = sdk.UndoWith(back, map[string]any{}, undo)
	}
	return res, err
}

func (c *conn) start(ctx context.Context, call sdk.Call, origin, fp string) (sdk.Result, error) {
	pr, err := c.printer(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if !pr.Connected {
		return sdk.Result{}, errOffline
	}
	f := pr.Flags
	if f.Printing || f.Paused || f.Pausing || f.Cancelling {
		return sdk.Result{}, errors.New("a print is already running or paused; cancel it first")
	}
	if f.Error || !f.Ready {
		return sdk.Result{}, fmt.Errorf("the printer isn't ready (%s)", pr.State)
	}
	var fl file
	if err := c.do(ctx, http.MethodGet, "/files/"+origin+"/"+fp, nil, &fl); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, errors.New("there's no such file; see files")
		}
		return sdk.Result{}, err
	}
	if fl.Type != "machinecode" {
		return sdk.Result{}, errors.New("that isn't a printable G-code file")
	}
	v := fl.view()
	name := v["name"].(string)
	if call.DryRun {
		a, _ := json.Marshal(v)
		b, _ := json.Marshal(map[string]any{"state": pr.State, "temperatures": pr.temps()})
		sum := "Print " + name + " (" + origin
		if s, ok := v["estimatedSeconds"].(int); ok {
			sum += fmt.Sprintf(", about %s", (time.Duration(s) * time.Second).Round(time.Minute))
		}
		sum += "); the printer heats up and moves: make sure the bed is clear"
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "printer", Op: "start print", Before: b, After: a}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/files/"+origin+"/"+fp, map[string]any{"command": "select", "print": true}, nil); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, errors.New("OctoPrint couldn't start the print now (printer busy or not ready)")
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"started": name, "origin": origin})
}

func (c *conn) setTemp(ctx context.Context, call sdk.Call, heater string, target float64) (sdk.Result, error) {
	pr, err := c.printer(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if !pr.Connected {
		return sdk.Result{}, errOffline
	}
	t, ok := pr.Temps[heater]
	if !ok {
		return sdk.Result{}, fmt.Errorf("the printer has no heater %s", heater)
	}
	prev := 0.0
	if t.Target != nil {
		prev = round(*t.Target)
	}
	if prev == target {
		return sdk.JSON(map[string]any{"heater": heater, "target": target, "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]float64{"target": prev, "actual": round(*t.Actual)})
		a, _ := json.Marshal(map[string]float64{"target": target})
		sum := fmt.Sprintf("Set %s to %g °C (now %g °C, target %g °C)", heater, target, round(*t.Actual), prev)
		if target == 0 {
			sum = fmt.Sprintf("Turn %s off (now %g °C, target %g °C)", heater, round(*t.Actual), prev)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "heater " + heater, Op: "set target", Before: b, After: a}}}}, nil
	}
	path, body := "/printer/bed", map[string]any{"command": "target", "target": target}
	if heater != "bed" {
		path, body = "/printer/tool", map[string]any{"command": "target", "targets": map[string]float64{heater: target}}
	}
	if err := c.do(ctx, http.MethodPost, path, body, nil); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, errOffline
		}
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"heater": heater, "target": target, "was": prev})
	res.Undo = sdk.UndoWith("set_temperature", map[string]any{"heater": heater, "target": prev}, fmt.Sprintf("Set %s back to %g °C", heater, prev))
	return res, err
}
