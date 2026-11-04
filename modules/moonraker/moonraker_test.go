package moonraker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeMoon struct {
	mu      sync.Mutex
	seen    []string
	state   string
	klippy  string
	ext     float64
	bed     float64
	scripts []string
	needKey bool
}

func (f *fakeMoon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.needKey && r.Header.Get("X-Api-Key") != "moon-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Unauthorized"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	res := func(v string) { fmt.Fprintf(w, `{"result":%s}`, v) }
	switch r.Method + " " + r.URL.Path {
	case "GET /server/info":
		res(fmt.Sprintf(`{"klippy_connected":true,"klippy_state":%q,"moonraker_version":"v0.9.3"}`, f.klippy))
	case "POST /printer/objects/query":
		if f.klippy != "ready" {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":{"code":503,"message":"Klippy Host not connected"}}`)
			return
		}
		var q struct {
			Objects map[string]any `json:"objects"`
		}
		json.Unmarshal(body, &q)
		if _, ok := q.Objects["heaters"]; ok {
			res(`{"eventtime":1,"status":{"heaters":{"available_heaters":["extruder","heater_bed","heater_generic chamber"]}}}`)
			return
		}
		st := map[string]any{
			"print_stats":    map[string]any{"filename": "benchy.gcode", "state": f.state, "message": "", "print_duration": 600.5, "total_duration": 700, "filament_used": 1234.4},
			"virtual_sdcard": map[string]any{"progress": 0.25},
			"extruder":       map[string]any{"temperature": 210.04, "target": f.ext, "power": 0.5},
			"heater_bed":     map[string]any{"temperature": 60, "target": f.bed, "power": 0.2},
		}
		if _, ok := q.Objects["toolhead"]; ok {
			st["toolhead"] = map[string]any{"homed_axes": "xyz", "note": "Bearer abcdefghijklmnopqrstuvwxyz0123"}
		}
		b, _ := json.Marshal(map[string]any{"eventtime": 1, "status": st})
		res(string(b))
	case "GET /printer/objects/list":
		res(`{"objects":["webhooks","configfile","print_stats","extruder","heater_bed","toolhead","temperature_sensor chamber"]}`)
	case "GET /server/job_queue/status":
		res(`{"queued_jobs":[{"filename":"part.gcode","job_id":"0000000066D991F0","time_added":1730000000,"time_in_queue":120.5}],"queue_state":"ready"}`)
	case "GET /server/history/list":
		res(`{"count":1,"jobs":[{"job_id":"000001","filename":"benchy.gcode","status":"completed","start_time":1730000000,"end_time":1730003600,"print_duration":3500,"total_duration":3600,"filament_used":2500,"exists":true,"metadata":{"thumbnails":"LEAKME"}}]}`)
	case "POST /printer/print/pause":
		f.state = "paused"
		res(`"ok"`)
	case "POST /printer/print/resume":
		f.state = "printing"
		res(`"ok"`)
	case "POST /printer/print/cancel":
		f.state = "cancelled"
		res(`"ok"`)
	case "POST /printer/gcode/script":
		s := r.URL.Query().Get("script")
		f.scripts = append(f.scripts, s)
		var h string
		var t float64
		if n, _ := fmt.Sscanf(s, "SET_HEATER_TEMPERATURE HEATER=%s TARGET=%g", &h, &t); n == 2 {
			if h == "extruder" {
				f.ext = t
			} else {
				f.bed = t
			}
		}
		res(`"ok"`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeMoon) {
	f := &fakeMoon{state: "printing", klippy: "ready", ext: 210, bed: 60, needKey: cfg.APIKey != ""}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mk": "moon-good", "secret://bad": "moon-bad"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMoonraker(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://mk"})
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "Moonraker v0.9.3, printer printing" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"progress":25`},
		{"status", `{}`, `"extruder":{"power":50,"target":210,"temperature":210}`},
		{"status", `{"objects":["toolhead"]}`, `"homed_axes":"xyz"`},
		{"objects", `{}`, `"heaters":["extruder","heater_bed"]`},
		{"job_queue", `{}`, `"file":"part.gcode"`},
		{"history", `{"limit":5}`, `"status":"completed"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "abcdefghijklmnop") || strings.Contains(out, "configfile") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Pause: preview, real, undo resumes; no-ops.
	r, err := invoke(m, "pause_print", `{}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Pause the print of benchy.gcode at 25%" || f.state != "printing" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "resume_print", `{}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	r, err = invoke(m, "pause_print", `{}`, false)
	if err != nil || f.state != "paused" || r.Undo == nil || r.Undo.Action != "resume_print" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "printing" {
		t.Fatal(err)
	}
	r, err = invoke(m, "cancel_print", `{}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "can't be finished") || f.state != "printing" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "cancel_print", `{}`, false); err != nil || f.state != "cancelled" || r.Undo != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "pause_print", `{}`, false); err == nil {
		t.Fatal("paused nothing")
	}

	// Heaters.
	r, err = invoke(m, "set_temperature", `{"heater":"heater_bed","target":0}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Turn heater_bed off (now 60 °C, target 60 °C)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_temperature", `{"heater":"extruder","target":245.5}`, false)
	if err != nil || f.ext != 245.5 || r.Undo == nil || string(r.Undo.Input) != `{"heater":"extruder","target":210}` {
		t.Fatalf("%+v %v %v", r, err, f.scripts)
	}
	if f.scripts[0] != "SET_HEATER_TEMPERATURE HEATER=extruder TARGET=245.5" {
		t.Fatal(f.scripts)
	}
	if r, err := invoke(m, "set_temperature", `{"heater":"extruder","target":245.5}`, false); err != nil || r.Undo != nil || len(f.scripts) != 1 {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "set_temperature", `{"heater":"extruder1","target":200}`, false); err == nil || !strings.Contains(err.Error(), "no heater") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk == sdk.RiskWrite {
			t.Fatalf("%s is write", a.Name)
		}
		for _, bad := range []string{"gcode", "script", "emergency", "estop", "firmware_restart"} {
			if strings.Contains(a.Name, bad) {
				t.Fatalf("%s is offered", a.Name)
			}
		}
	}

	// Klipper not ready.
	f.klippy = "shutdown"
	if h := m.Health(context.Background(), "k"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "status", `{}`, false); err == nil || !strings.Contains(err.Error(), "isn't ready (shutdown)") {
		t.Fatal(err)
	}
}

func TestMoonrakerSafety(t *testing.T) {
	m, f := setup(t, Config{MaxHotend: 250})
	for _, c := range []struct{ action, in string }{
		{"set_temperature", `{"heater":"extruder","target":251}`},
		{"set_temperature", `{"heater":"heater_bed","target":111}`},
		{"set_temperature", `{"heater":"extruder TARGET=300","target":200}`},
		{"set_temperature", `{"heater":"heater_generic chamber","target":50}`},
		{"set_temperature", `{"heater":"extruder\nM112","target":200}`},
		{"set_temperature", `{"heater":"extruder"}`},
		{"status", `{"objects":["configfile"]}`},
		{"status", `{"objects":["toolhead&x=1"]}`},
		{"status", `{"objects":["a\nb"]}`},
		{"history", `{"limit":1000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Without a key no header is sent and trusted clients work.
	if h := m.Health(context.Background(), "k"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, s := range f.scripts {
		if !strings.HasPrefix(s, "SET_HEATER_TEMPERATURE HEATER=") {
			t.Fatal(s)
		}
		if _, err := strconv.ParseFloat(s[strings.LastIndex(s, "=")+1:], 64); err != nil {
			t.Fatal(s)
		}
	}
}

func TestMoonrakerSettings(t *testing.T) {
	for _, c := range []Config{
		{URL: "http://voron.local:7125", APIKey: "plain"},
		{URL: "voron.local", APIKey: "secret://mk"},
		{URL: "http://u:p@voron.local"},
		{URL: "http://voron.local/?a=1"},
		{URL: "http://voron.local/#a"},
		{URL: "http://voron.local", MaxBed: 500},
		{URL: "http://voron.local", InsecureSkipVerify: true},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") || strings.Contains(h.Message, "moon-bad") {
		t.Fatalf("%+v", h)
	}
}

func TestMoonrakerRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://mk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mk": "moon-good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
