package octoprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeOcto struct {
	mu       sync.Mutex
	seen     []string
	printing bool
	paused   bool
	offline  bool
	tool     float64
	bed      float64
}

func (f *fakeOcto) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Api-Key") != "octo-good-key" {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"Invalid API key octo-bad-key-1234567890abcdef"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	state := "Operational"
	if f.printing {
		state = "Printing"
	}
	if f.paused {
		state = "Paused"
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/version":
		io.WriteString(w, `{"api":"0.1","server":"1.10.2","text":"OctoPrint 1.10.2"}`)
	case "GET /api/printer":
		if f.offline {
			w.WriteHeader(409)
			io.WriteString(w, `{"error":"Printer is not operational"}`)
			return
		}
		fmt.Fprintf(w, `{"temperature":{"tool0":{"actual":24.3,"target":%g,"offset":0},"bed":{"actual":23.1,"target":%g,"offset":0}},
			"state":{"text":%q,"flags":{"operational":true,"printing":%t,"paused":%t,"pausing":false,"cancelling":false,"ready":%t,"error":false,"closedOrError":false}}}`,
			f.tool, f.bed, state, f.printing, f.paused, !f.printing && !f.paused)
	case "GET /api/job":
		fmt.Fprintf(w, `{"job":{"file":{"name":"benchy.gcode","display":"benchy.gcode","path":"benchy.gcode","origin":"local","size":1234},"estimatedPrintTime":3600,"filament":{"tool0":{"length":2500.4}}},
			"progress":{"completion":42.17,"printTime":1500,"printTimeLeft":2100},"state":%q}`, state)
	case "POST /api/job":
		var b map[string]string
		json.Unmarshal(body, &b)
		switch {
		case b["command"] == "pause" && b["action"] == "pause" && f.printing:
			f.printing, f.paused = false, true
		case b["command"] == "pause" && b["action"] == "resume" && f.paused:
			f.printing, f.paused = true, false
		case b["command"] == "cancel":
			f.printing, f.paused = false, false
		default:
			w.WriteHeader(409)
			return
		}
		w.WriteHeader(204)
	case "GET /api/files":
		io.WriteString(w, `{"files":[{"name":"benchy.gcode","display":"benchy.gcode","path":"benchy.gcode","type":"machinecode","origin":"local","size":1234,"date":1730000000,"gcodeAnalysis":{"estimatedPrintTime":3600,"filament":{"tool0":{"length":2500}}},"refs":{"download":"http://x/downloads/files/local/benchy.gcode?apikey=LEAKME"}},
			{"name":"parts","path":"parts","type":"folder","children":[{"name":"clip.gcode","display":"clip.gcode","path":"parts/clip.gcode","type":"machinecode","origin":"local","size":99}]}],"free":5000}`)
	case "GET /api/files/local/benchy.gcode", "GET /api/files/local/parts/my clip.gcode":
		io.WriteString(w, `{"name":"benchy.gcode","display":"benchy.gcode","path":"benchy.gcode","type":"machinecode","origin":"local","size":1234,"gcodeAnalysis":{"estimatedPrintTime":3600}}`)
	case "POST /api/files/local/benchy.gcode":
		f.printing = true
		w.WriteHeader(204)
	case "POST /api/printer/tool":
		var b struct {
			Targets map[string]float64 `json:"targets"`
		}
		json.Unmarshal(body, &b)
		f.tool = b.Targets["tool0"]
		w.WriteHeader(204)
	case "POST /api/printer/bed":
		var b struct {
			Target float64 `json:"target"`
		}
		json.Unmarshal(body, &b)
		f.bed = b.Target
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeOcto) {
	f := &fakeOcto{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://op": "octo-good-key", "secret://bad": "octo-bad-key-1234567890abcdef"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOctoPrint(t *testing.T) {
	m, f := setup(t, "secret://op")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || h.Message != "OctoPrint 1.10.2, printer operational" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"printer", `{}`, `"tool0":{"actual":24.3,"target":0}`},
		{"job", `{}`, `"progress":42.2`},
		{"files", `{}`, `"path":"parts/clip.gcode"`},
		{"files", `{}`, `"estimatedSeconds":3600`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "octo-good-key") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Start: preview, then real.
	r, err := invoke(m, "start_print", `{"path":"benchy.gcode"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "bed is clear") || f.printing {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "start_print", `{"path":"benchy.gcode"}`, false); err != nil || !f.printing {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start_print", `{"path":"benchy.gcode"}`, false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}

	// Pause, undo resumes; resume when running is a no-op.
	r, err = invoke(m, "pause_print", `{}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "42%") || f.paused {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "resume_print", `{}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	r, err = invoke(m, "pause_print", `{}`, false)
	if err != nil || !f.paused || r.Undo == nil || r.Undo.Action != "resume_print" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause_print", `{}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.printing {
		t.Fatal(err)
	}
	if _, err := invoke(m, "cancel_print", `{}`, false); err != nil || f.printing {
		t.Fatal(err)
	}
	if _, err := invoke(m, "cancel_print", `{}`, false); err == nil {
		t.Fatal("cancelled nothing")
	}

	// Temperatures: preview, set, undo, no-op, limits.
	r, err = invoke(m, "set_temperature", `{"heater":"tool0","target":210}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set tool0 to 210 °C (now 24.3 °C, target 0 °C)" || f.tool != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_temperature", `{"heater":"tool0","target":210}`, false)
	if err != nil || f.tool != 210 || r.Undo == nil || string(r.Undo.Input) != `{"heater":"tool0","target":0}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "set_temperature", `{"heater":"tool0","target":210}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "set_temperature", `{"heater":"bed","target":60}`, false); err != nil || f.bed != 60 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		if strings.Contains(strings.ToLower(a.Name), "gcode") || strings.Contains(strings.ToLower(a.Name), "command") {
			t.Fatalf("%s sends raw commands", a.Name)
		}
	}
}

func TestOctoPrintSafety(t *testing.T) {
	m, f := setup(t, "secret://op")
	for _, c := range []struct{ action, in string }{
		{"set_temperature", `{"heater":"tool0","target":261}`},
		{"set_temperature", `{"heater":"bed","target":111}`},
		{"set_temperature", `{"heater":"chamber","target":40}`},
		{"set_temperature", `{"heater":"tool0"}`},
		{"set_temperature", `{"heater":"tool0","target":-5}`},
		{"start_print", `{"path":"../config.yaml"}`},
		{"start_print", `{"path":"benchy.stl"}`},
		{"start_print", `{"path":"/etc/passwd.gcode"}`},
		{"start_print", `{"path":"a/../b.gcode"}`},
		{"start_print", `{"path":"x.gcode?apikey=1"}`},
		{"start_print", `{"path":"benchy.gcode","origin":"../x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// A higher configured limit is honoured.
	srv := httptest.NewServer(f)
	defer srv.Close()
	hi := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://op", MaxHotend: 300})
	if err := hi.Configure(context.Background(), fakehost.New(map[string]string{"secret://op": "octo-good-key"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(hi, "set_temperature", `{"heater":"tool0","target":290}`, false); err != nil || f.tool != 290 {
		t.Fatal(err)
	}
	// A path with a space is escaped, never passed raw.
	f.seen = nil
	if _, err := invoke(m, "start_print", `{"path":"parts/my clip.gcode"}`, true); err != nil || !strings.Contains(f.seen[1], "/parts/my%20clip.gcode") {
		t.Fatalf("%v %v", err, f.seen)
	}
	// An offline printer is reported, not acted on.
	f.offline = true
	if h := m.Health(context.Background(), "o"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "set_temperature", `{"heater":"tool0","target":200}`, false); err == nil || !strings.Contains(err.Error(), "isn't connected") {
		t.Fatal(err)
	}
}

func TestOctoPrintSettings(t *testing.T) {
	for _, c := range []Config{
		{URL: "http://octopi.local", APIKey: "plain-key"},
		{URL: "octopi.local", APIKey: "secret://op"},
		{URL: "http://user:pw@octopi.local", APIKey: "secret://op"},
		{URL: "http://octopi.local/?x=1", APIKey: "secret://op"},
		{URL: "http://octopi.local/#x", APIKey: "secret://op"},
		{URL: "http://octopi.local", APIKey: "secret://op", MaxHotend: 900},
		{URL: "http://octopi.local", APIKey: "secret://op", MaxBed: -1},
		{URL: "http://octopi.local", APIKey: "secret://op", Fingerprint: "ab"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "o")
	if h.Status != "down" || h.Message != "OctoPrint refused the API key" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "job", `{}`, false); err == nil || strings.Contains(err.Error(), "octo-bad-key") {
		t.Fatal(err)
	}
}

func TestOctoPrintRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://op"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://op": "octo-good-key"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
