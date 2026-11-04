package shelly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

type fakeShelly struct {
	mu       sync.Mutex
	password string // "" when authentication is off
	on       map[int]bool
	pos      int
	state    string
	writes   []string
	pulse    map[int]string // switch id → in_mode, with auto_off on
	noConfig bool           // GetConfig fails
}

var readOnly = map[string]bool{"Shelly.GetDeviceInfo": true, "Shelly.GetStatus": true, "Shelly.GetConfig": true, "Shelly.CheckForUpdate": true}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

const realm, nonce = "shellyplus2pm-a8032ab12345", "6412abcd"

// authorized checks a SHA-256 digest answer the way the firmware does.
func (f *fakeShelly) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Digest ") {
		return false
	}
	ps := map[string]string{}
	for _, m := range paramRe.FindAllStringSubmatch(h[7:], -1) {
		v := m[2]
		if strings.HasPrefix(v, `"`) {
			v = m[3]
		}
		ps[m[1]] = v
	}
	if ps["username"] != "admin" || ps["realm"] != realm || ps["nonce"] != nonce || ps["algorithm"] != "SHA-256" || ps["qop"] != "auth" {
		return false
	}
	ha1, ha2 := sha("admin:"+realm+":"+f.password), sha(r.Method+":"+ps["uri"])
	return ps["response"] == sha(ha1+":"+nonce+":"+ps["nc"]+":"+ps["cnonce"]+":auth:"+ha2)
}

func (f *fakeShelly) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/rpc" {
		w.WriteHeader(404)
		return
	}
	var req struct {
		ID     int             `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if f.password != "" && req.Method != "Shelly.GetDeviceInfo" && !f.authorized(r) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest qop="auth", realm=%q, nonce=%q, algorithm=SHA-256`, realm, nonce))
		w.WriteHeader(401)
		io.WriteString(w, `{"code":401,"message":"unauthorized"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !readOnly[req.Method] {
		f.writes = append(f.writes, req.Method+" "+string(req.Params))
	}
	var p struct {
		ID  int  `json:"id"`
		On  bool `json:"on"`
		Pos int  `json:"pos"`
	}
	json.Unmarshal(req.Params, &p)
	reply := func(v any) {
		b, _ := json.Marshal(map[string]any{"id": req.ID, "src": "shellyplus2pm-a8032ab12345", "result": v})
		w.Write(b)
	}
	switch req.Method {
	case "Shelly.GetDeviceInfo":
		reply(map[string]any{"name": "Rack", "id": "shellyplus2pm-a8032ab12345", "mac": "A8032AB12345", "model": "SNSW-102P16EU", "gen": 2, "ver": "1.3.2", "app": "Plus2PM", "auth_en": f.password != ""})
	case "Shelly.GetStatus":
		reply(map[string]any{
			"sys":      map[string]any{"uptime": 3600, "restart_required": false, "available_updates": map[string]any{"stable": map[string]string{"version": "1.4.4"}}},
			"wifi":     map[string]any{"sta_ip": "192.168.1.40", "status": "got ip", "ssid": "home", "rssi": -61},
			"switch:0": map[string]any{"id": 0, "output": f.on[0], "apower": 12.345, "voltage": 230.1, "current": 0.056, "aenergy": map[string]any{"total": 1234.5}, "temperature": map[string]any{"tC": 41.2}},
			"switch:1": map[string]any{"id": 1, "output": f.on[1], "apower": 80.0, "voltage": 230.1, "current": 0.4, "aenergy": map[string]any{"total": 50000.0}},
			"cover:0":  map[string]any{"id": 0, "state": f.state, "current_pos": f.pos, "pos_control": true, "apower": 0.0},
			"cover:1":  map[string]any{"id": 1, "state": "closed", "pos_control": false},
		})
	case "Shelly.GetConfig":
		if f.noConfig {
			io.WriteString(w, `{"id":1,"error":{"code":-103,"message":"busy"}}`)
			return
		}
		cfg := map[string]any{"switch:0": map[string]any{"id": 0, "name": "Lamp", "in_mode": "follow", "auto_off": false}, "switch:1": map[string]any{"id": 1, "name": "NAS"}, "cover:0": map[string]any{"name": "Blinds"}, "sys": map[string]any{"device": map[string]any{"name": "Rack"}}}
		for id, mode := range f.pulse {
			cfg[fmt.Sprintf("switch:%d", id)] = map[string]any{"id": id, "name": "Garage", "in_mode": mode, "auto_off": true, "auto_off_delay": 1.0}
		}
		reply(cfg)
	case "Shelly.CheckForUpdate":
		reply(map[string]any{"stable": map[string]string{"version": "1.4.4", "build_id": "x"}})
	case "Switch.Set":
		was := f.on[p.ID]
		f.on[p.ID] = p.On
		reply(map[string]any{"was_on": was})
	case "Cover.GoToPosition":
		f.pos = p.Pos
		reply(nil)
	case "Cover.Open":
		f.pos, f.state = 100, "open"
		reply(nil)
	case "Cover.Close", "Cover.Stop", "Shelly.Reboot":
		reply(nil)
	default:
		io.WriteString(w, `{"id":1,"error":{"code":-114,"message":"Method `+req.Method+` failed: No handler!"}}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeShelly) {
	f := &fakeShelly{password: "s3cret", on: map[int]bool{0: false, 1: true}, pos: 40, state: "stopped"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: pw, CriticalSwitches: []int{1}, GarageCovers: []int{1}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "s3cret", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestShellyRead(t *testing.T) {
	m, _ := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "s"); h.Status != "degraded" || h.Message != "Rack · SNSW-102P16EU 1.3.2 · 2 switch(es) · 2 cover(s) · password sent without encryption (the device is on http)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"device", `{"app":"Plus2PM","authEnabled":true,"firmware":"1.3.2","generation":2,"id":"shellyplus2pm-a8032ab12345","mac":"A8032AB12345","model":"SNSW-102P16EU","name":"Rack","restartRequired":false,"updates":{"stable":"1.4.4"},"uptimeSeconds":3600,"wifi":{"rssi":-61,"ssid":"home","status":"got ip"}}`},
		{"switches", `[{"currentA":0.06,"energyKWh":1.23,"id":0,"name":"Lamp","on":false,"powerW":12.35,"temperatureC":41.2,"voltage":230.1},{"critical":true,"currentA":0.4,"energyKWh":50,"id":1,"name":"NAS","on":true,"powerW":80,"voltage":230.1}]`},
		{"power", `{"channels":[{"channel":"cover:0","name":"Blinds","powerW":0},{"channel":"switch:0","currentA":0.06,"energyKWh":1.23,"name":"Lamp","powerW":12.35,"voltage":230.1},{"channel":"switch:1","currentA":0.4,"energyKWh":50,"name":"NAS","powerW":80,"voltage":230.1}],"totalW":92.35}`},
		{"covers", `[{"id":0,"name":"Blinds","position":40,"powerW":0,"state":"stopped"},{"garage":true,"id":1,"state":"closed"}]`},
		{"check_update", `{"current":"1.3.2","stable":"1.4.4","updateAvailable":true}`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		if err != nil || string(r.Output) != c.want {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
}

func TestShellyWrite(t *testing.T) {
	m, f := setup(t, "secret://pw")
	p, err := invoke(m, "set_switch", `{"id":0,"on":true}`, true)
	if err != nil || p.Plan.Summary != "Turn on switch 0 (Lamp)" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "set_switch", `{"id":0,"on":true}`, false)
	if err != nil || !f.on[0] || r.Undo == nil || r.Undo.Action != "set_switch" || string(r.Undo.Input) != `{"id":0,"on":false}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.on[0] {
		t.Fatal(err)
	}
	// Already off: nothing is sent.
	n := len(f.writes)
	if r, err = invoke(m, "set_switch", `{"id":0,"on":false}`, false); err != nil || len(f.writes) != n || r.Undo != nil {
		t.Fatal(err)
	}

	// A critical switch: off only through the destructive action.
	if _, err := invoke(m, "set_switch", `{"id":1,"on":false}`, false); err == nil || !strings.Contains(err.Error(), "switch_off_critical") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "switch_off_critical", `{"id":0}`, false); err == nil {
		t.Fatal("switch_off_critical took a switch that isn't critical")
	}
	p, err = invoke(m, "switch_off_critical", `{"id":1}`, true)
	if err != nil || p.Plan.Summary != "Turn off switch 1 (NAS) (it draws 80 W now)" || !f.on[1] {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "switch_off_critical", `{"id":1}`, false)
	if err != nil || f.on[1] || r.Undo == nil || string(r.Undo.Input) != `{"id":1,"on":true}` {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.on[1] || r.Undo == nil || r.Undo.Action != "switch_off_critical" {
		t.Fatalf("undoing the undo must stay destructive: %+v %v", r.Undo, err)
	}

	// Covers: back to the old position.
	r, err = invoke(m, "cover", `{"id":0,"action":"open"}`, false)
	if err != nil || f.pos != 100 || r.Undo == nil || string(r.Undo.Input) != `{"action":"position","id":0,"position":40}` {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.pos != 40 {
		t.Fatal(err, f.pos)
	}
	if r, err = invoke(m, "cover", `{"id":0,"action":"stop"}`, false); err != nil || r.Undo != nil {
		t.Fatal(err)
	}
	p, err = invoke(m, "reboot", `{}`, true)
	if err != nil || !strings.HasPrefix(p.Plan.Summary, "Reboot Rack") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "reboot", `{}`, false); err != nil || f.writes[len(f.writes)-1] != `Shelly.Reboot {"delay_ms":1000}` {
		t.Fatal(err, f.writes)
	}
	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["reboot"] != sdk.RiskDestructive || risks["switch_off_critical"] != sdk.RiskDestructive || risks["switch_locked"] != sdk.RiskDestructive || risks["set_switch"] != sdk.RiskWrite || risks["cover"] != sdk.RiskWrite || risks["check_update"] != sdk.RiskRead {
		t.Fatal(risks)
	}
}

func TestShellyRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != errAuth.Error() {
		t.Fatalf("%+v", h)
	}
	none, _ := setup(t, "")
	if h := none.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "has a password") {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"set_switch", `{"id":0}`},
		{"set_switch", `{"on":true}`},
		{"set_switch", `{"id":-1,"on":true}`},
		{"set_switch", `{"id":100,"on":true}`},
		{"set_switch", `{"id":5,"on":true}`}, // no such switch
		{"set_switch", `{"id":"0; Shelly.Reboot","on":true}`},
		{"set_switch", `{"id":1,"on":false}`},
		{"switch_off_critical", `{"id":0}`},
		{"cover", `{"id":1,"action":"open"}`}, // garage
		{"cover", `{"id":1,"action":"close"}`},
		{"cover", `{"id":0,"action":"tilt"}`},
		{"cover", `{"id":0,"action":"position","position":120}`},
		{"cover", `{"id":0,"action":"position"}`},
		{"cover", `{"id":0,"action":"open","position":10}`},
		{"cover", `{"id":4,"action":"open"}`},
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
		{URL: "http://shelly", Password: "plain"},
		{URL: "shelly.local"},
		{URL: "http://admin:pw@shelly"},
		{URL: "http://shelly/rpc"},
		{URL: "http://shelly", CriticalSwitches: []int{-1}},
		{URL: "http://shelly", GarageCovers: []int{200}},
		{URL: "http://shelly", Fingerprint: strings.Repeat("ab", 32)},
		{URL: "https://shelly", Fingerprint: "abcd"},
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "s3cret"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestDigestMD5(t *testing.T) {
	ch, ok := parseChallenge(`Digest realm="r", nonce="n", qop="auth"`)
	if !ok || ch.realm != "r" || ch.nonce != "n" {
		t.Fatalf("%+v", ch)
	}
	a, err := ch.answer("admin", "pw", "POST", "/rpc")
	if err != nil || !strings.Contains(a, "algorithm=MD5") || !strings.Contains(a, `qop=auth`) {
		t.Fatal(a, err)
	}
	if _, err := (challenge{nonce: "n", algorithm: "SHA-512-256"}).answer("admin", "pw", "POST", "/rpc"); err == nil {
		t.Fatal("accepted an unknown algorithm")
	}
	if _, ok := parseChallenge(`Basic realm="x"`); ok {
		t.Fatal("parsed a Basic challenge")
	}
}

func TestShellyHealthNoPassword(t *testing.T) {
	f := &fakeShelly{on: map[int]bool{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(nil), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
}

// A relay wired to a garage opener, a door strike or a valve: no change at
// write, listed or detected from its pulse wiring.
func TestShellyLockedSwitches(t *testing.T) {
	f := &fakeShelly{password: "s3cret", on: map[int]bool{0: false, 1: true}, state: "stopped"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cfg := func(c Config) *Module {
		c.URL, c.Password = srv.URL, "secret://pw"
		m := New()
		raw, _ := json.Marshal(c)
		if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "s3cret"}), "s", raw); err != nil {
			t.Fatal(err)
		}
		return m
	}
	// Listed.
	m := cfg(Config{LockedSwitches: []int{0}, CriticalSwitches: []int{1}})
	for _, in := range []string{`{"id":0,"on":true}`, `{"id":0,"on":false}`} {
		if _, err := invoke(m, "set_switch", in, false); err == nil || !strings.Contains(err.Error(), "switch_locked") {
			t.Fatalf("%s: %v", in, err)
		}
	}
	if _, err := invoke(m, "switch_locked", `{"id":1,"on":false}`, false); err == nil {
		t.Fatal("switch_locked took a switch that isn't locked")
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	p, err := invoke(m, "switch_locked", `{"id":0,"on":true}`, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "locked switch 0 (Lamp)") || !strings.Contains(p.Plan.Summary, "garage opener") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "switch_locked", `{"id":0,"on":true}`, false)
	if err != nil || !f.on[0] || r.Undo != nil {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	r, _ = invoke(m, "switches", `{}`, false)
	if !strings.Contains(string(r.Output), `"id":0,"locked":true`) {
		t.Fatalf("%s", r.Output)
	}

	// Detected: auto-off with a momentary or detached input.
	f.writes, f.on[0] = nil, false
	for _, mode := range []string{"momentary", "detached"} {
		f.pulse = map[int]string{0: mode}
		m = cfg(Config{})
		if _, err := invoke(m, "set_switch", `{"id":0,"on":true}`, false); err == nil || !strings.Contains(err.Error(), "auto-off") {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	// A pulse switch on a follow input isn't an opener's wiring.
	f.pulse = map[int]string{0: "follow"}
	if _, err := invoke(cfg(Config{}), "set_switch", `{"id":0,"on":true}`, true); err != nil {
		t.Fatal(err)
	}
	// notLocked overrides the detection, not the list.
	f.pulse = map[int]string{0: "momentary"}
	if _, err := invoke(cfg(Config{NotLocked: []int{0}}), "set_switch", `{"id":0,"on":true}`, true); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(cfg(Config{NotLocked: []int{0}, LockedSwitches: []int{0}}), "set_switch", `{"id":0,"on":true}`, true); err == nil {
		t.Fatal("notLocked unlocked a listed switch")
	}
	// The configuration can't be read: refused unless notLocked.
	f.pulse, f.noConfig = nil, true
	if _, err := invoke(cfg(Config{}), "set_switch", `{"id":0,"on":true}`, false); err == nil || !strings.Contains(err.Error(), "couldn't be read") {
		t.Fatal(err)
	}
	if _, err := invoke(cfg(Config{NotLocked: []int{0}}), "set_switch", `{"id":0,"on":true}`, true); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
}
