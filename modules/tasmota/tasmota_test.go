package tasmota

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

type fakeTasmota struct {
	mu    sync.Mutex
	power map[int]bool
	cmds  []string // every command received
}

func onOff(b bool) string { return map[bool]string{true: "ON", false: "OFF"}[b] }

func (f *fakeTasmota) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/cm" {
		w.WriteHeader(404)
		return
	}
	if r.URL.Query().Has("password") {
		w.WriteHeader(400) // the module never puts the password in the URL
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		io.WriteString(w, `{"WARNING":"Need user=<username>&password=<password>"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := r.URL.Query().Get("cmnd")
	f.cmds = append(f.cmds, c)
	sts := func() map[string]any {
		return map[string]any{"Time": "2026-11-04T10:00:00", "Uptime": "1T02:03:04", "POWER1": onOff(f.power[1]), "POWER2": onOff(f.power[2]),
			"Wifi": map[string]any{"AP": 1, "SSId": "home", "RSSI": 76, "Signal": -62}}
	}
	var out any
	switch c {
	case "Status 0":
		out = map[string]any{
			"Status":    map[string]any{"Module": 0, "DeviceName": "Rack PDU", "FriendlyName": []string{"Router", "Heater"}, "Topic": "pdu", "Power": 1},
			"StatusPRM": map[string]any{"Uptime": "1T02:03:04", "RestartReason": "Software/System restart", "BootCount": 12, "OtaUrl": "http://user:otapw@ota.example/tasmota.bin.gz"},
			"StatusFWR": map[string]any{"Version": "14.3.0(release-tasmota)", "Hardware": "ESP8266EX"},
			"StatusNET": map[string]any{"Hostname": "pdu", "IPAddress": "192.168.1.50", "Mac": "AA:BB:CC:DD:EE:FF"},
			"StatusMQT": map[string]any{"MqttHost": "broker", "MqttUser": "DVES_USER"},
			"StatusSTS": sts(),
		}
	case "Status 1":
		out = map[string]any{"StatusPRM": map[string]any{"OtaUrl": "http://user:otapw@ota.example/x.bin", "Uptime": "1T02:03:04", "MqttPassword": "mqttpw"}}
	case "Status 10":
		out = map[string]any{"StatusSNS": map[string]any{"Time": "2026-11-04T10:00:00", "ENERGY": map[string]any{"TotalStartTime": "2025-01-01T00:00:00",
			"Total": 123.456, "Yesterday": 1.2, "Today": 0.8, "Power": 45, "ApparentPower": 50, "ReactivePower": 10, "Factor": 0.9, "Voltage": 231, "Current": 0.2}}}
	case "Power1", "Power2":
		n := int(c[5] - '0')
		out = map[string]string{fmt.Sprintf("POWER%d", n): onOff(f.power[n])}
	case "Power1 On", "Power1 Off", "Power2 On", "Power2 Off":
		n := int(c[5] - '0')
		f.power[n] = strings.HasSuffix(c, "On")
		out = map[string]string{fmt.Sprintf("POWER%d", n): onOff(f.power[n])}
	case "Dimmer":
		out = map[string]any{"Dimmer": 40}
	case "Restart 1":
		out = map[string]string{"Restart": "Restarting"}
	default:
		out = map[string]string{"Command": "Unknown", "Input": c}
	}
	json.NewEncoder(w).Encode(out)
}

func setup(t *testing.T, pw string) (*Module, *fakeTasmota) {
	f := &fakeTasmota{power: map[int]bool{1: true, 2: false}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: pw, CriticalRelays: []int{1}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTasmotaRead(t *testing.T) {
	m, _ := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "Rack PDU · Tasmota 14.3.0(release-tasmota) · 2 relay(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `{"bootCount":12,"firmware":"14.3.0(release-tasmota)","hardware":"ESP8266EX","hostname":"pdu","ip":"192.168.1.50","mac":"AA:BB:CC:DD:EE:FF","name":"Rack PDU","relays":{"1":"ON","2":"OFF"},"restartReason":"Software/System restart","uptime":"1T02:03:04","wifi":{"rssiPercent":76,"signalDbm":-62,"ssid":"home"}}`},
		{"power", `{}`, `[{"critical":true,"name":"Router","on":true,"relay":1},{"name":"Heater","on":false,"relay":2}]`},
		{"energy", `{}`, `{"apparentVA":50,"currentA":0.2,"powerFactor":0.9,"powerW":45,"time":"2026-11-04T10:00:00","todayKWh":0.8,"totalKWh":123.456,"voltage":231,"yesterdayKWh":1.2}`},
		{"command", `{"command":"dimmer"}`, `{"command":"Dimmer","result":{"Dimmer":40}}`},
		{"command", `{"command":"status 1"}`, `{"command":"Status 1","result":{"StatusPRM":{"MqttPassword":"[redacted]","OtaUrl":"[redacted]","Uptime":"1T02:03:04"}}}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || string(r.Output) != c.want {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestTasmotaWrite(t *testing.T) {
	m, f := setup(t, "secret://pw")
	n := len(f.cmds)
	p, err := invoke(m, "set_power", `{"relay":2,"state":"toggle"}`, true)
	if err != nil || p.Plan.Summary != "Turn on relay 2 (Heater)" || f.power[2] || len(f.cmds) != n+1 { // only Status 0
		t.Fatalf("%+v %v %v", p.Plan, err, f.cmds)
	}
	r, err := invoke(m, "set_power", `{"relay":2,"state":"toggle"}`, false)
	if err != nil || !f.power[2] || f.cmds[len(f.cmds)-1] != "Power2 On" || string(r.Undo.Input) != `{"relay":2,"state":"off"}` {
		t.Fatalf("%v %v %+v", err, f.cmds, r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.power[2] {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_power", `{"relay":1,"state":"off"}`, false); err == nil || !strings.Contains(err.Error(), "power_off_critical") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_power", `{"relay":1,"state":"toggle"}`, false); err == nil {
		t.Fatal("toggled a critical relay")
	}
	r, err = invoke(m, "power_off_critical", `{"relay":1}`, false)
	if err != nil || f.power[1] || r.Undo == nil || string(r.Undo.Input) != `{"relay":1,"state":"on"}` {
		t.Fatalf("%v %+v", err, r.Undo)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.power[1] || r.Undo.Action != "power_off_critical" {
		t.Fatalf("%v %+v", err, r.Undo)
	}
	if p, err = invoke(m, "restart", `{}`, true); err != nil || !strings.HasPrefix(p.Plan.Summary, "Restart Rack PDU") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "restart", `{}`, false); err != nil || f.cmds[len(f.cmds)-1] != "Restart 1" {
		t.Fatal(err, f.cmds)
	}
	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["restart"] != sdk.RiskDestructive || risks["power_off_critical"] != sdk.RiskDestructive || risks["set_power"] != sdk.RiskWrite || risks["command"] != sdk.RiskRead {
		t.Fatal(risks)
	}
}

func TestTasmotaRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || h.Message != "the device refused the username or password" {
		t.Fatalf("%+v", h)
	}
	none, _ := setup(t, "")
	if h := none.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "web password") {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"command", `{"command":"Reset 1"}`},
		{"command", `{"command":"reset"}`},
		{"command", `{"command":"Upgrade 1"}`},
		{"command", `{"command":"OtaUrl http://evil/x.bin"}`},
		{"command", `{"command":"Backlog Power1 Off; Reset 1"}`},
		{"command", `{"command":"Backlog0 Status 0"}`},
		{"command", `{"command":"WifiConfig 2"}`},
		{"command", `{"command":"Restart 1"}`},
		{"command", `{"command":"Restart"}`},
		{"command", `{"command":"WebPassword x"}`},
		{"command", `{"command":"SetOption0 1"}`},
		{"command", `{"command":"SO19 1"}`},
		{"command", `{"command":"Rule1 ON"}`},
		{"command", `{"command":"Power1 Off"}`},
		{"command", `{"command":"Power9"}`},
		{"command", `{"command":"Dimmer 100"}`},
		{"command", `{"command":"Status 99"}`},
		{"command", `{"command":"Status 0;Reset 1"}`},
		{"command", `{"command":"Status\n0"}`},
		{"command", `{"command":"State%3BReset"}`},
		{"command", `{"command":";;"}`},
		{"command", `{"command":""}`},
		{"set_power", `{"relay":0,"state":"on"}`},
		{"set_power", `{"relay":9,"state":"on"}`},
		{"set_power", `{"relay":1,"state":"blink"}`},
		{"set_power", `{"relay":1,"state":"on; Reset 1"}`},
		{"set_power", `{"relay":1,"state":"off"}`},
		{"power_off_critical", `{"relay":2}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.cmds) != 0 {
		t.Fatalf("refused input reached the device: %q", f.cmds)
	}
	// set_power on a relay the device doesn't have reads status first, and
	// sends nothing else.
	if _, err := invoke(m, "set_power", `{"relay":5,"state":"on"}`, false); err == nil || len(f.cmds) != 1 || f.cmds[0] != "Status 0" {
		t.Fatal(err, f.cmds)
	}
	for _, c := range []Config{
		{URL: "http://plug", Password: "plain"},
		{URL: "plug.local"},
		{URL: "http://admin:pw@plug"},
		{URL: "http://plug/cm"},
		{URL: "http://plug?user=admin"},
		{URL: "http://plug", CriticalRelays: []int{0}},
		{URL: "http://plug", Username: "a:b"},
		{URL: "http://plug", Fingerprint: strings.Repeat("ab", 32)},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" || strings.Contains(h.Message, "pw") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestQuery(t *testing.T) {
	for in, want := range map[string]cmd{"State": "State", "status": "Status", "STATUS 8": "Status 8", "Status  10": "Status 10", "power2": "Power2", "Power": "Power", "hsbcolor": "HSBColor", "Timezone": "Timezone"} {
		if got, err := query(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}
