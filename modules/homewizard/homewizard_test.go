package homewizard

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

type fakeHW struct {
	mu      sync.Mutex
	product string
	token   string // v2 when set
	on      bool
	lock    bool
	ignore  bool // the socket doesn't switch
	quiet   bool // the PUT answers {} (the state is read back)
	writes  []string
	seen    int
}

func (f *fakeHW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen++
	if f.token != "" && r.URL.Path != "/api" && (r.Header.Get("Authorization") != "Bearer "+f.token || r.Header.Get("X-Api-Version") != "2") {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"user:unauthorized"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api":
		fmt.Fprintf(w, `{"product_type":%q,"product_name":"Energy Socket","serial":"3c39e7aabbcc","firmware_version":"4.07","api_version":"v1"}`, f.product)
	case "GET /api/v1/data":
		io.WriteString(w, `{"wifi_ssid":"LEAKME-home","wifi_strength":92,"unique_id":"LEAKME4530303434","meter_model":"ISKRA","total_power_import_kwh":1234.5678,"total_power_export_kwh":0,"active_power_w":61.25,"active_voltage_v":231.4,"active_current_a":0.31,"external":[{"unique_id":"LEAKME-GAS","type":"gas_meter","timestamp":230125220957,"value":2569.646,"unit":"m3"}]}`)
	case "GET /api/measurement":
		io.WriteString(w, `{"power_w":-543,"energy_import_kwh":3000.123,"energy_export_kwh":800,"tariff":2,"meter_model":"x","unique_id":"LEAKME"}`)
	case "GET /api/v1/state":
		if f.product != "HWE-SKT" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"power_on":%t,"switch_lock":%t,"brightness":255}`, f.on, f.lock)
	case "PUT /api/v1/state":
		b, _ := io.ReadAll(r.Body)
		f.writes = append(f.writes, string(b))
		var s struct {
			PowerOn *bool `json:"power_on"`
		}
		json.Unmarshal(b, &s)
		if s.PowerOn != nil && !f.lock && !f.ignore {
			f.on = *s.PowerOn
		}
		if f.quiet {
			io.WriteString(w, `{}`)
			return
		}
		fmt.Fprintf(w, `{"power_on":%t}`, f.on)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config, product string) (*Module, *fakeHW) {
	f := &fakeHW{product: product, on: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hw": "hwtok_good", "secret://bad": "hwtok_bad"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(`{}`), DryRun: dry})
}

func TestHomeWizardRead(t *testing.T) {
	m, _ := setup(t, Config{}, "HWE-SKT")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "Energy Socket 3c39e7aabbcc · firmware 4.07 · 61.25 W" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"device", `{"apiVersion":"v1","critical":false,"firmware":"4.07","localApi":"v1","product":"Energy Socket","serial":"3c39e7aabbcc","type":"HWE-SKT"}`},
		{"measurements", `{"currentA":0.31,"exportKWh":0,"external":[{"timestamp":230125220957,"type":"gas_meter","unit":"m3","value":2569.646}],"importKWh":1234.568,"powerW":61.25,"voltageV":231.4,"wifiStrength":92}`},
		{"plug", `{"brightness":255,"critical":false,"on":true,"switchLock":false}`},
	} {
		r, err := invoke(m, c.action, false)
		if err != nil || string(r.Output) != c.want || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
}

func TestHomeWizardSwitch(t *testing.T) {
	m, f := setup(t, Config{}, "HWE-SKT")
	p, err := invoke(m, "plug_off", true)
	if err != nil || p.Plan.Summary != "Switch off Energy Socket 3c39e7aabbcc, cutting power to what's plugged in (it draws 61.3 W now)" || len(f.writes) != 0 || !f.on {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "plug_off", false)
	if err != nil || f.on || r.Undo == nil || r.Undo.Action != "plug_on" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	// Already off: nothing is sent.
	if r, err := invoke(m, "plug_off", false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.writes) != 1 {
		t.Fatalf("%s %v", r.Output, err)
	}
	if p, _ := invoke(m, "plug_off", true); p.Plan.Summary != "Energy Socket 3c39e7aabbcc is already off; nothing would change" {
		t.Fatal(p.Plan.Summary)
	}
	r, err = invoke(m, r.Undo.Action, false)
	if err != nil || !f.on || r.Undo == nil || r.Undo.Action != "plug_off" || f.writes[1] != `{"power_on":true}` {
		t.Fatalf("%+v %v %v", r.Undo, err, f.writes)
	}

	// The device's switch lock is respected, before anything is sent.
	f.lock = true
	for _, a := range []string{"plug_on", "plug_off"} {
		if _, err := invoke(m, a, false); err == nil || !strings.Contains(err.Error(), "switch lock") {
			t.Fatal(a, err)
		}
	}
	f.lock = false
	f.on, f.ignore = false, true
	if _, err := invoke(m, "plug_on", false); err == nil || !strings.Contains(err.Error(), "stayed off") {
		t.Fatal(err)
	}
	if n := len(f.writes); n != 3 {
		t.Fatal(f.writes)
	}

	for _, a := range m.Manifest().Actions {
		want := map[string]sdk.Risk{"plug_on": sdk.RiskWrite, "plug_off": sdk.RiskDestructive}[a.Name]
		if want == "" {
			want = sdk.RiskRead
		}
		if a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestHomeWizardCritical(t *testing.T) {
	m, f := setup(t, Config{Critical: true}, "HWE-SKT")
	if _, err := invoke(m, "plug_off", true); err == nil || !strings.Contains(err.Error(), "critical") || f.seen != 0 {
		t.Fatal(err, f.seen)
	}
	f.on = false
	r, err := invoke(m, "plug_on", false)
	if err != nil || !f.on || r.Undo != nil {
		t.Fatalf("%+v %v", r.Undo, err)
	}
}

func TestHomeWizardNotASocket(t *testing.T) {
	m, f := setup(t, Config{}, "HWE-P1")
	if _, err := invoke(m, "plug_on", false); err == nil || !strings.Contains(err.Error(), "not an Energy Socket") || len(f.writes) != 0 {
		t.Fatal(err)
	}
}

func TestHomeWizardV2(t *testing.T) {
	f := &fakeHW{product: "HWE-P1", token: "hwtok_good"}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	conf := func(ref string) *Module {
		m := New()
		m.HTTP = srv.Client()
		raw, _ := json.Marshal(Config{URL: srv.URL, Token: ref})
		if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hw": "hwtok_good", "secret://bad": "hwtok_bad"}), "h", raw); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := conf("secret://hw")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "Energy Socket 3c39e7aabbcc · firmware 4.07 · -543 W" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "measurements", false)
	if err != nil || string(r.Output) != `{"exportKWh":800,"importKWh":3000.123,"powerW":-543,"tariff":2}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Switching is API v1 only, refused before anything is sent.
	n := f.seen
	if _, err := invoke(m, "plug_off", false); err == nil || !strings.Contains(err.Error(), "API v1") || f.seen != n {
		t.Fatal(err)
	}
	bad := conf("secret://bad")
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || h.Message != "the device refused the token" || strings.Contains(h.Message, "hwtok") {
		t.Fatalf("%+v", h)
	}
}

func TestHomeWizardSettings(t *testing.T) {
	for _, c := range []Config{
		{URL: "http://8.8.8.8"},                                // not on the LAN
		{URL: "http://homewizard.example.com"},                 // a public name
		{URL: "http://admin:pw@192.168.1.50"},                  // userinfo
		{URL: "http://192.168.1.50/?x=1"},                      // query
		{URL: "http://192.168.1.50/#x"},                        // fragment
		{URL: "http://192.168.1.50/api"},                       // path
		{URL: "192.168.1.50"},                                  // no scheme
		{URL: "https://192.168.1.50"},                          // v1 is http
		{URL: "http://192.168.1.50", Token: "secret://hw"},     // v2 is https
		{URL: "https://192.168.1.50", Token: "hwtok_plain"},    // plain token
		{URL: "http://192.168.1.50", InsecureSkipVerify: true}, // TLS setting on http
		{URL: "https://192.168.1.50", Token: "secret://hw", Fingerprint: "nope"},
		{URL: "http://[2001:db8::1]"},
		{URL: "http://134744072"}, // 8.8.8.8 to inet_aton
		{URL: "http://0x8080808"}, // the same in hex
		{URL: "http://8.8.8.010"}, // octal, not a name
		{URL: "http://[::ffff:8.8.8.8]"},
		{URL: "http://0.0.0.0"},
		{URL: "http://evil.example.com."},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, u := range []string{"http://192.168.1.50", "http://10.0.0.7:80", "http://energysocket-1a2b3c.local", "http://p1meter", "http://[fd00::5]", "http://[fe80::1]", "http://[fe80::1%25eth0]", "http://p1meter.local.", "http://[::ffff:192.168.1.5]"} {
		raw, _ := json.Marshal(Config{URL: u})
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
			t.Fatalf("refused %s: %v", u, err)
		}
	}
}

func TestHomeWizardRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Api-Version") + r.Header.Get("Authorization")
	}))
	defer evil.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://hw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hw": "hwtok_good"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// A socket whose answer to the switch doesn't carry the state is read back.
func TestHomeWizardReadBack(t *testing.T) {
	m, f := setup(t, Config{}, "HWE-SKT")
	f.quiet, f.ignore = true, true
	if _, err := invoke(m, "plug_off", false); err == nil || !strings.Contains(err.Error(), "stayed on") {
		t.Fatal(err)
	}
	f.ignore = false
	r, err := invoke(m, "plug_off", false)
	if err != nil || f.on || r.Undo == nil || strings.Contains(string(r.Output), "note") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestHomeWizardLANIncludesCGNAT(t *testing.T) {
	for _, h := range []string{"100.64.0.1", "100.127.255.254"} {
		if !lanHost(h) {
			t.Errorf("%s refused", h)
		}
	}
	for _, h := range []string{"100.63.255.255", "100.128.0.1"} {
		if lanHost(h) {
			t.Errorf("%s accepted", h)
		}
	}
}
