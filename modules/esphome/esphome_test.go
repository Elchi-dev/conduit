package esphome

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeDevice struct {
	mu     sync.Mutex
	relay  bool
	server bool
	light  struct {
		on      bool
		bri     int
		r, g, b int
	}
	writes []string
}

func (f *fakeDevice) entity(id string) (map[string]any, bool) {
	switch id {
	case "sensor/temperature":
		return map[string]any{"id": "sensor-temperature", "value": 21.5, "state": "21.5 °C"}, true
	case "binary_sensor/motion":
		return map[string]any{"id": "binary_sensor-motion", "value": false, "state": "OFF"}, true
	case "switch/relay":
		return map[string]any{"id": "switch-relay", "value": f.relay, "state": map[bool]string{true: "ON", false: "OFF"}[f.relay]}, true
	case "switch/server_power":
		return map[string]any{"id": "switch-server_power", "value": f.server, "state": map[bool]string{true: "ON", false: "OFF"}[f.server]}, true
	case "switch/restart":
		return map[string]any{"id": "switch-restart", "value": false, "state": "OFF"}, true
	case "light/desk":
		return map[string]any{"id": "light-desk", "state": map[bool]string{true: "ON", false: "OFF"}[f.light.on], "brightness": f.light.bri, "color_mode": "rgb",
			"color": map[string]int{"r": f.light.r, "g": f.light.g, "b": f.light.b}}, true
	case "button/identify":
		return map[string]any{"id": "button-identify"}, true
	case "button/factory_reset":
		return map[string]any{"id": "button-factory_reset"}, true
	}
	return nil, false
}

var all = []string{"sensor/temperature", "binary_sensor/motion", "switch/relay", "switch/server_power", "switch/restart", "light/desk", "button/identify", "button/factory_reset"}

func (f *fakeDevice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		w.WriteHeader(401)
		return
	}
	if r.URL.Path == "/events" {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		io.WriteString(w, "retry: 30000\nid: 1\nevent: ping\ndata: {\"title\":\"Living room\",\"ota\":true,\"log\":true}\n\n")
		io.WriteString(w, "event: log\ndata: [D][wifi] password=hunter2\n\n")
		f.mu.Lock()
		for _, id := range all {
			e, _ := f.entity(id)
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		}
		f.mu.Unlock()
		io.WriteString(w, "event: state\ndata: {\"id\":\"weird id/../x\",\"state\":\"x\"}\n\n")
		fl.Flush()
		select { // the device keeps the stream open
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		w.WriteHeader(404)
		return
	}
	id := parts[0] + "/" + parts[1]
	if _, ok := f.entity(id); !ok {
		w.WriteHeader(404)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 2 {
		e, _ := f.entity(id)
		json.NewEncoder(w).Encode(e)
		return
	}
	if r.Method != http.MethodPost || len(parts) != 3 {
		w.WriteHeader(405)
		return
	}
	f.writes = append(f.writes, r.URL.RequestURI())
	q := r.URL.Query()
	switch id + "/" + parts[2] {
	case "switch/relay/turn_on":
		f.relay = true
	case "switch/relay/turn_off":
		f.relay = false
	case "switch/restart/turn_on", "button/identify/press", "button/factory_reset/press":
	case "light/desk/turn_on":
		f.light.on = true
		if v := q.Get("brightness"); v != "" {
			f.light.bri, _ = strconv.Atoi(v)
		}
		if v := q.Get("r"); v != "" {
			f.light.r, _ = strconv.Atoi(v)
			f.light.g, _ = strconv.Atoi(q.Get("g"))
			f.light.b, _ = strconv.Atoi(q.Get("b"))
		}
	case "light/desk/turn_off":
		f.light.on = false
	default:
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
}

func setup(t *testing.T, c Config) (*Module, *fakeDevice) {
	f := &fakeDevice{}
	f.light.on, f.light.bri, f.light.r, f.light.g, f.light.b = true, 128, 255, 200, 100
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c.URL = srv.URL
	if c.Username == "" {
		c.Username = "admin"
	}
	if c.Password == "" {
		c.Password = "secret://pw"
	}
	c.CriticalEntities = append(c.CriticalEntities, "switch.server_power")
	m := New()
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "e", raw); err != nil {
		t.Fatal(err)
	}
	cn, _ := m.set.Get("e")
	cn.quiet = 150 * time.Millisecond
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "e", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestESPHomeRead(t *testing.T) {
	m, _ := setup(t, Config{})
	start := time.Now()
	// A password over http: working, but degraded.
	if h := m.Health(context.Background(), "e"); h.Status != "degraded" || h.Message != "Living room · 8 entities · password sent without encryption (the device is on http)" || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v %s", h, time.Since(start))
	}
	r, err := invoke(m, "entities", `{}`, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{"domain":"binary_sensor","entity":"binary_sensor.motion","id":"motion","state":"OFF","value":false}`,
		`{"critical":true,"domain":"button","entity":"button.factory_reset","id":"factory_reset"}`,
		`{"domain":"button","entity":"button.identify","id":"identify"}`,
		`{"brightness":50,"color":"#ffc864","domain":"light","entity":"light.desk","id":"desk","state":"ON"}`,
		`{"domain":"sensor","entity":"sensor.temperature","id":"temperature","state":"21.5 °C","value":21.5}`,
		`{"critical":true,"domain":"switch","entity":"switch.restart","id":"restart","state":"OFF","value":false}`,
		`{"critical":true,"domain":"switch","entity":"switch.server_power","id":"server_power","state":"OFF","value":false}`,
	} {
		if !strings.Contains(string(r.Output), want) {
			t.Fatalf("missing %s in %s", want, r.Output)
		}
	}
	if strings.Contains(string(r.Output), "hunter2") || strings.Contains(string(r.Output), "weird") {
		t.Fatalf("%s", r.Output)
	}
	if r, err = invoke(m, "entities", `{"domain":"sensor"}`, false); err != nil || string(r.Output) != `[{"domain":"sensor","entity":"sensor.temperature","id":"temperature","state":"21.5 °C","value":21.5}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err = invoke(m, "state", `{"entity":"switch.relay"}`, false); err != nil || string(r.Output) != `{"domain":"switch","entity":"switch.relay","id":"relay","state":"OFF","value":false}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	// With a list in the settings, no stream is read.
	lm, _ := setup(t, Config{Entities: []string{"sensor.temperature", "switch.relay"}})
	if h := lm.Health(context.Background(), "e"); h.Status != "degraded" || !strings.HasPrefix(h.Message, "2 entities · ") {
		t.Fatalf("%+v", h)
	}
}

func TestESPHomeWrite(t *testing.T) {
	m, f := setup(t, Config{})
	p, err := invoke(m, "set_switch", `{"id":"relay","on":true}`, true)
	if err != nil || p.Plan.Summary != "Turn on switch.relay" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "set_switch", `{"id":"switch.relay","on":true}`, false)
	if err != nil || !f.relay || f.writes[0] != "/switch/relay/turn_on" || string(r.Undo.Input) != `{"id":"relay","on":false}` {
		t.Fatalf("%v %v %+v", err, f.writes, r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.relay {
		t.Fatal(err)
	}
	r, err = invoke(m, "set_light", `{"id":"desk","brightness":100,"color":"#0000FF","transition":1.5}`, false)
	if err != nil || f.writes[2] != "/light/desk/turn_on?b=255&brightness=255&g=0&r=0&transition=1.5" {
		t.Fatalf("%v %v", err, f.writes)
	}
	if string(r.Undo.Input) != `{"brightness":50.2,"color":"#ffc864","id":"desk","on":true}` {
		t.Fatalf("%s", r.Undo.Input)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.light.bri != 128 || f.light.r != 255 || f.light.b != 100 {
		t.Fatal(err, f.light)
	}
	r, err = invoke(m, "set_light", `{"id":"desk","on":false}`, false)
	if err != nil || f.light.on {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.light.on {
		t.Fatal(err)
	}
	if r, err = invoke(m, "press_button", `{"id":"identify"}`, false); err != nil || r.Undo != nil || f.writes[len(f.writes)-1] != "/button/identify/press" {
		t.Fatal(err, f.writes)
	}
	p, err = invoke(m, "press_critical", `{"id":"factory_reset"}`, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "lose its settings") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "press_critical", `{"id":"factory_reset"}`, false); err != nil || f.writes[len(f.writes)-1] != "/button/factory_reset/press" {
		t.Fatal(err, f.writes)
	}
	if _, err := invoke(m, "press_critical", `{"id":"restart","domain":"switch"}`, false); err != nil || f.writes[len(f.writes)-1] != "/switch/restart/turn_on" {
		t.Fatal(err, f.writes)
	}
	for _, a := range m.Manifest().Actions {
		want := map[string]sdk.Risk{"entities": sdk.RiskRead, "state": sdk.RiskRead, "press_critical": sdk.RiskDestructive}[a.Name]
		if want == "" {
			want = sdk.RiskWrite
		}
		if a.Risk != want || (a.Risk != sdk.RiskRead && !a.DryRun) {
			t.Fatalf("%s: %+v", a.Name, a)
		}
	}
}

func TestESPHomeRefusals(t *testing.T) {
	bad, _ := setup(t, Config{Password: "secret://bad"})
	if h := bad.Health(context.Background(), "e"); h.Status != "down" || h.Message != "the device refused the username or password" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, Config{})
	for _, c := range []struct{ action, in string }{
		{"set_switch", `{"id":"restart","on":true}`},
		{"set_switch", `{"id":"server_power","on":false}`},
		{"set_switch", `{"id":"relay"}`},
		{"set_switch", `{"id":"../light/desk","on":true}`},
		{"set_switch", `{"id":"relay/turn_on?x=","on":true}`},
		{"set_switch", `{"id":"Relay","on":true}`},
		{"set_switch", `{"id":"nothing","on":true}`},
		{"set_light", `{"id":"desk","brightness":120}`},
		{"set_light", `{"id":"desk","color":"blue"}`},
		{"set_light", `{"id":"desk","on":false,"brightness":10}`},
		{"set_light", `{"id":"desk","transition":600}`},
		{"press_button", `{"id":"factory_reset"}`},
		{"press_button", `{"id":"restart_device"}`},
		{"press_button", `{"id":"safe_mode"}`},
		{"press_critical", `{"id":"identify"}`},
		{"press_critical", `{"id":"relay","domain":"switch"}`},
		{"press_critical", `{"id":"factory_reset","domain":"lock"}`},
		{"state", `{"entity":"switch/relay"}`},
		{"state", `{"entity":"shell.x"}`},
		{"entities", `{"domain":"x"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("refused input reached the device: %v", f.writes)
	}
	for _, c := range []Config{
		{URL: "http://esp", Username: "admin", Password: "plain"},
		{URL: "http://esp", Username: "admin"},
		{URL: "http://esp", Password: "secret://pw"},
		{URL: "esp.local"},
		{URL: "http://esp/x"},
		{URL: "http://esp", Entities: []string{"switch.../x"}},
		{URL: "http://esp", Entities: []string{"bogus.x"}},
		{URL: "http://esp", CriticalEntities: []string{"switch"}},
		{URL: "http://esp", Fingerprint: strings.Repeat("ab", 32)},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + r.URL.Path }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "e", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "e"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// Critical words match anywhere in the object id, for switches and buttons.
func TestESPHomeCriticalNames(t *testing.T) {
	c := &conn{critical: map[entityRef]bool{}}
	for _, id := range []string{"restart", "restart2", "esp_reboot", "reboot1", "rebootdevice", "factoryreset", "factory_reset", "restart_safe_mode", "safe_mode_boot",
		"safemode", "shutdown", "firmware_update", "ota", "flash", "garage_door", "gate_open", "frontdoor", "door_lock", "unlock", "water_valve", "siren", "alarm_silence", "silence"} {
		for _, d := range []string{"button", "switch"} {
			if !c.isCritical(entityRef{d, id}) {
				t.Errorf("%s.%s isn't critical", d, id)
			}
		}
	}
	for _, r := range []entityRef{{"button", "identify"}, {"switch", "relay"}, {"switch", "led"}, {"light", "garage_light"}, {"sensor", "door"}} {
		if c.isCritical(r) {
			t.Errorf("%s is critical", r)
		}
	}
}
