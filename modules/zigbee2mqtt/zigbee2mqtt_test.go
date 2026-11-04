package zigbee2mqtt

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mqttsrv "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type authHook struct{ mqttsrv.HookBase }

func (h *authHook) ID() string { return "auth" }
func (h *authHook) Provides(b byte) bool {
	return b == mqttsrv.OnConnectAuthenticate || b == mqttsrv.OnACLCheck
}
func (h *authHook) OnConnectAuthenticate(_ *mqttsrv.Client, pk packets.Packet) bool {
	return string(pk.Connect.Username) == "u" && string(pk.Connect.Password) == "pw"
}
func (h *authHook) OnACLCheck(*mqttsrv.Client, string, bool) bool { return true }

// fakeZ2M answers like Zigbee2MQTT: /set changes and reports the state,
// /get reports it, and permit_join requests get a response.
type fakeZ2M struct {
	srv    *mqttsrv.Server
	mu     sync.Mutex
	states map[string]map[string]any
	keep   map[string]bool // devices whose state is retained
	writes []string
}

const devices = `[
 {"ieee_address":"0x00124b0000000001","type":"Coordinator","friendly_name":"Coordinator","supported":true,"interview_completed":true,"definition":null},
 {"ieee_address":"0x0017880100000001","type":"Router","friendly_name":"Desk lamp","supported":true,"interview_completed":true,"power_source":"Mains (single phase)",
  "definition":{"model":"9290012573A","vendor":"Philips","description":"Hue white and color","exposes":[
   {"type":"light","features":[
    {"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF","value_toggle":"TOGGLE"},
    {"type":"numeric","name":"brightness","property":"brightness","access":7,"value_min":0,"value_max":254},
    {"type":"composite","name":"color_xy","property":"color","access":7,"features":[{"type":"numeric","name":"x","property":"x","access":7},{"type":"numeric","name":"y","property":"y","access":7}]}]},
   {"type":"numeric","name":"linkquality","property":"linkquality","access":1}]}},
 {"ieee_address":"0x0017880100000002","type":"Router","friendly_name":"kitchen/plug","supported":true,"interview_completed":true,
  "definition":{"model":"ZNCZ02LM","vendor":"Aqara","description":"Smart plug","exposes":[
   {"type":"switch","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF","value_toggle":"TOGGLE"}]},
   {"type":"numeric","name":"power","property":"power","access":5,"unit":"W"}]}},
 {"ieee_address":"0x0017880100000003","type":"EndDevice","friendly_name":"Front door","supported":true,"interview_completed":true,"power_source":"Battery",
  "definition":{"model":"YRD226","vendor":"Yale","description":"Lock","exposes":[
   {"type":"lock","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"LOCK","value_off":"UNLOCK"}]},
   {"type":"numeric","name":"battery","property":"battery","access":1}]}},
 {"ieee_address":"0x0017880100000004","type":"EndDevice","friendly_name":"Thermostat","supported":true,"interview_completed":true,
  "definition":{"model":"TRV","vendor":"Danfoss","description":"Radiator valve","exposes":[
   {"type":"climate","features":[{"type":"enum","name":"system_mode","property":"system_mode","access":7,"values":["off","heat"]},
    {"type":"numeric","name":"occupied_heating_setpoint","property":"occupied_heating_setpoint","access":7,"value_min":5,"value_max":35}]}]}},
 {"ieee_address":"0x0017880100000005","type":"EndDevice","friendly_name":"Siren","supported":true,"interview_completed":true,
  "definition":{"model":"S1","vendor":"Heiman","description":"Siren","exposes":[
   {"type":"composite","name":"warning","property":"warning","access":2,"features":[{"type":"enum","name":"mode","property":"mode","access":2,"values":["stop","burglar"]}]},
   {"type":"binary","name":"led","property":"led","access":7,"value_on":true,"value_off":false}]}}
]`

func startZ2M(t *testing.T) (*fakeZ2M, string) {
	t.Helper()
	srv := mqttsrv.New(&mqttsrv.Options{InlineClient: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := srv.AddHook(&authHook{}, nil); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.AddListener(listeners.NewNet("t", l)); err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	f := &fakeZ2M{srv: srv, keep: map[string]bool{"Desk lamp": true}, states: map[string]map[string]any{
		"Desk lamp":    {"state": "ON", "brightness": 200.0, "color": map[string]any{"x": 0.3, "y": 0.3}, "linkquality": 120.0},
		"kitchen/plug": {"state": "OFF", "power": 0.0},
		"Front door":   {"state": "LOCK", "battery": 90.0},
		"Thermostat":   {"system_mode": "heat", "occupied_heating_setpoint": 21.0},
	}}
	pub := func(topic string, v any, retain bool) {
		b, _ := json.Marshal(v)
		srv.Publish(topic, b, retain, 0)
	}
	pub("zigbee2mqtt/bridge/info", map[string]any{"version": "2.1.0", "commit": "abc", "coordinator": map[string]any{"type": "zStack3x0", "ieee_address": "0x00124b0000000001", "meta": map[string]any{"revision": 20230507}},
		"network": map[string]any{"channel": 15, "pan_id": 6754}, "log_level": "info", "permit_join": false, "restart_required": false,
		"config": map[string]any{"advanced": map[string]any{"network_key": []int{1, 2, 3}}, "mqtt": map[string]any{"password": "LEAKME"}}}, true)
	pub("zigbee2mqtt/bridge/state", map[string]string{"state": "online"}, true)
	srv.Publish("zigbee2mqtt/bridge/devices", []byte(devices), true, 0)
	pub("zigbee2mqtt/Desk lamp", f.states["Desk lamp"], true)
	pub("zigbee2mqtt/Desk lamp/availability", map[string]string{"state": "online"}, true)
	err = srv.Subscribe("zigbee2mqtt/#", 1, func(_ *mqttsrv.Client, _ packets.Subscription, pk packets.Packet) {
		topic := strings.TrimPrefix(pk.TopicName, "zigbee2mqtt/")
		go func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			switch {
			case topic == "bridge/request/permit_join":
				f.writes = append(f.writes, topic+" "+string(pk.Payload))
				var r map[string]any
				json.Unmarshal(pk.Payload, &r)
				pub("zigbee2mqtt/bridge/response/permit_join", map[string]any{"status": "ok", "data": map[string]any{"time": r["time"]}, "transaction": r["transaction"]}, false)
			case strings.HasSuffix(topic, "/set"):
				name := strings.TrimSuffix(topic, "/set")
				f.writes = append(f.writes, topic+" "+string(pk.Payload))
				var in map[string]any
				json.Unmarshal(pk.Payload, &in)
				st := f.states[name]
				if st == nil {
					st = map[string]any{}
					f.states[name] = st
				}
				for k, v := range in {
					st[k] = v
				}
				pub("zigbee2mqtt/"+name, st, f.keep[name])
			case strings.HasSuffix(topic, "/get"):
				name := strings.TrimSuffix(topic, "/get")
				if st, ok := f.states[name]; ok {
					pub("zigbee2mqtt/"+name, st, false)
				}
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, l.Addr().String()
}

func (f *fakeZ2M) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func setup(t *testing.T, mod func(*Config)) (*Module, *fakeZ2M) {
	t.Helper()
	f, addr := startZ2M(t)
	c := Config{URL: "mqtt://" + addr, Username: "u", Password: "secret://pw", CriticalDevices: []string{"0x0017880100000099"}}
	if mod != nil {
		mod(&c)
	}
	m := New()
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	cn, _ := m.set.Get("z")
	cn.Settle, cn.Timeout = 150*time.Millisecond, 3*time.Second
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZ2MRead(t *testing.T) {
	m, _ := setup(t, nil)
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "Zigbee2MQTT 2.1.0" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "bridge", `{}`, false)
	if err != nil || string(r.Output) != `{"channel":15,"commit":"abc","coordinator":{"ieee":"0x00124b0000000001","revision":20230507,"type":"zStack3x0"},"logLevel":"info","permitJoin":false,"restartRequired":false,"state":"online","version":"2.1.0"}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "devices", `{}`, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{"ieee":"0x00124b0000000001","name":"Coordinator","type":"Coordinator"}`,
		`{"description":"Hue white and color","ieee":"0x0017880100000001","interviewed":true,"model":"9290012573A","name":"Desk lamp","power":"Mains (single phase)","supported":true,"type":"Router","vendor":"Philips","writable":["brightness","color","state"]}`,
		`"critical":true,"description":"Lock"`, `"critical":true,"description":"Radiator valve"`, `"critical":true,"description":"Siren"`,
	} {
		if !strings.Contains(string(r.Output), want) {
			t.Fatalf("missing %s in %s", want, r.Output)
		}
	}
	if strings.Contains(string(r.Output), `"description":"Smart plug","ieee":"0x0017880100000002","interviewed":true,"model":"ZNCZ02LM","name":"kitchen/plug","supported":true,"type":"Router","vendor":"Aqara","writable":["state"]}`) == false {
		t.Fatalf("plug: %s", r.Output)
	}
	r, err = invoke(m, "state", `{"device":"Desk lamp"}`, false)
	if err != nil || string(r.Output) != `{"availability":"online","device":"Desk lamp","ieee":"0x0017880100000001","retained":true,"state":{"brightness":200,"color":{"x":0.3,"y":0.3},"linkquality":120,"state":"ON"}}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Not retained: the module asks with /get.
	r, err = invoke(m, "state", `{"device":"0x0017880100000002"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"retained":false,"state":{"power":0,"state":"OFF"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestZ2MWrite(t *testing.T) {
	m, f := setup(t, nil)
	p, err := invoke(m, "set_device", `{"device":"Desk lamp","payload":{"state":"OFF"}}`, true)
	if err != nil || string(p.Plan.Changes[0].Before) != `{"state":"ON"}` || len(f.sent()) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "set_device", `{"device":"Desk lamp","payload":{"state":"OFF","brightness":10}}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"confirmed":true`) || r.Undo == nil || r.Undo.Action != "set_device" ||
		string(r.Undo.Input) != `{"device":"Desk lamp","payload":{"brightness":200,"state":"ON"}}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if st := f.states["Desk lamp"]; st["state"] != "ON" || st["brightness"] != 200.0 {
		t.Fatalf("not restored: %v", st)
	}
	f.mu.Unlock()
	if r, err = invoke(m, "set_device", `{"device":"kitchen/plug","payload":{"state":"ON"}}`, false); err != nil || r.Undo == nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if w := f.sent(); w[len(w)-1] != `kitchen/plug/set {"state":"ON"}` {
		t.Fatal(w)
	}

	// Locks and thermostats only through set_critical.
	if _, err := invoke(m, "set_device", `{"device":"Front door","payload":{"state":"UNLOCK"}}`, false); err == nil || !strings.Contains(err.Error(), "set_critical") {
		t.Fatal(err)
	}
	r, err = invoke(m, "set_critical", `{"device":"Front door","payload":{"state":"UNLOCK"}}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "set_critical" || string(r.Undo.Input) != `{"device":"Front door","payload":{"state":"LOCK"}}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}

	p, err = invoke(m, "permit_join", `{"seconds":120}`, true)
	if err != nil || p.Plan.Summary != "Let new devices join for 120 seconds" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "permit_join", `{"seconds":120}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"seconds":0}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if w := f.sent(); !strings.HasPrefix(w[len(w)-1], `bridge/request/permit_join {"time":120,"transaction":"`) {
		t.Fatal(w)
	}
	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["permit_join"] != sdk.RiskDestructive || risks["set_critical"] != sdk.RiskDestructive || risks["set_device"] != sdk.RiskWrite || risks["state"] != sdk.RiskRead {
		t.Fatal(risks)
	}
}

func TestZ2MRefusals(t *testing.T) {
	bad, _ := setup(t, func(c *Config) { c.Password = "secret://bad" })
	if h := bad.Health(context.Background(), "z"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, func(c *Config) { c.CriticalDevices = []string{"kitchen/plug"} })
	for _, c := range []struct{ action, in string }{
		{"set_device", `{"device":"Front door","payload":{"state":"UNLOCK"}}`},
		{"set_device", `{"device":"Thermostat","payload":{"system_mode":"off"}}`},
		{"set_device", `{"device":"Thermostat","payload":{"occupied_heating_setpoint":5}}`},
		{"set_device", `{"device":"Siren","payload":{"warning":{"mode":"stop"}}}`},
		{"set_device", `{"device":"Siren","payload":{"led":true,"warning":{"mode":"stop"}}}`},
		{"set_device", `{"device":"kitchen/plug","payload":{"state":"OFF"}}`}, // in criticalDevices
		{"set_device", `{"device":"Desk lamp","payload":{"brightness":999}}`},
		{"set_device", `{"device":"Desk lamp","payload":{"state":"MAYBE"}}`},
		{"set_device", `{"device":"Desk lamp","payload":{"linkquality":1}}`}, // read only
		{"set_device", `{"device":"Desk lamp","payload":{"frobnicate":1}}`},  // not exposed
		{"set_device", `{"device":"Desk lamp","payload":{}}`},
		{"set_device", `{"device":"Desk lamp","payload":{"color":"red"}}`},
		{"set_device", `{"device":"Desk lamp","payload":{"color":{"x":{"y":1}}}}`},
		{"set_device", `{"device":"Desk lamp","payload":{"State":"ON"}}`},
		{"set_device", `{"device":"Coordinator","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"bridge/request/permit_join","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"Desk lamp/set","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"+","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"#","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"$SYS/x","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"Nope","payload":{"state":"ON"}}`},
		{"set_device", `{"device":"Desk\u0000lamp","payload":{"state":"ON"}}`},
		{"set_critical", `{"device":"Front door","payload":{"state":"OPEN"}}`},
		{"state", `{"device":"Desk lamp","seconds":60}`},
		{"state", `{"device":"zigbee2mqtt/#"}`},
		{"permit_join", `{"seconds":255}`},
		{"permit_join", `{}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if w := f.sent(); len(w) != 0 {
		t.Fatalf("refused input reached Zigbee2MQTT: %q", w)
	}
	for _, c := range []Config{
		{URL: "mqtt://broker", Username: "u", Password: "pw"},
		{URL: "http://broker"},
		{URL: "mqtt://broker", BaseTopic: "zigbee2mqtt/#"},
		{URL: "mqtt://broker", BaseTopic: "$SYS"},
		{URL: "mqtt://broker", BaseTopic: "a//b"},
		{URL: "mqtt://broker", CriticalDevices: []string{"a/+/b"}},
		{URL: "mqtt://broker", Fingerprint: strings.Repeat("ab", 32)},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// The bridge info's config (network key, MQTT password) never comes out.
	r, _ := invoke(m, "bridge", `{}`, false)
	if strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "network_key") {
		t.Fatalf("%s", r.Output)
	}
}
