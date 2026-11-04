package openhab

import (
	"context"
	"encoding/base64"
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

const token = "oh.conduit.GOODTOKENGOODTOKENGOODTOKEN"

type fakeHAB struct {
	mu     sync.Mutex
	seen   []string
	states map[string]string
	ran    []string
}

func (f *fakeHAB) items() []map[string]any {
	return []map[string]any{
		{"name": "Desk_Lamp", "label": "Desk lamp", "type": "Switch", "state": f.states["Desk_Lamp"], "tags": []string{"Lightbulb"}},
		{"name": "Hall_Dimmer", "label": "Hall", "type": "Dimmer", "state": f.states["Hall_Dimmer"],
			"stateDescription": map[string]any{"minimum": 0, "maximum": 100, "readOnly": false}},
		{"name": "Rack_Plug", "label": "Rack", "type": "Switch", "state": f.states["Rack_Plug"]},
		{"name": "Front_Lock", "label": "Front", "type": "Switch", "state": f.states["Front_Lock"], "tags": []string{"Lock"}},
		{"name": "Driveway_Relay", "label": "Driveway relay", "type": "Switch", "state": f.states["Driveway_Relay"], "groupNames": []string{"gOpener"}},
		{"name": "gOpener", "label": "Opener", "type": "Group", "groupType": "", "state": "NULL", "tags": []string{"GarageDoor"}},
		{"name": "Living_Setpoint", "label": "Living", "type": "Number:Temperature", "state": f.states["Living_Setpoint"]},
		{"name": "Mystery", "label": "Mystery", "type": "", "state": "ON"},
		{"name": "Window_Contact", "label": "Bath window", "type": "Contact", "state": "CLOSED"},
		{"name": "Mode", "label": "Mode", "type": "String", "state": f.states["Mode"],
			"commandDescription": map[string]any{"commandOptions": []map[string]any{{"command": "home"}, {"command": "away"}}}},
		{"name": "Odd_Item", "label": "x", "type": "Switch", "state": "OFF"},
		// Critical without an English word in the item, its tags or groups.
		{"name": "Switch_3", "label": "Entrance", "type": "Switch", "state": f.states["Switch_3"]},
		{"name": "Plug_7", "label": "Plug", "type": "Switch", "state": "OFF", "metadata": map[string]any{"homekit": map[string]any{"value": "LockMechanism"}}},
		{"name": "Orphan", "label": "Orphan", "type": "Switch", "state": "OFF", "groupNames": []string{"gHidden"}},
		{"name": "Relais_Hoftor", "label": "Relais", "type": "Switch", "state": "OFF"},
		{"name": "Living_Level", "label": "Living", "type": "Dimmer", "state": "40", "stateDescription": map[string]any{"pattern": "%.1f °C"}},
	}
}

func (f *fakeHAB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(token+":")) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Authentication required","http-code":401}}`)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/rest/items":
		json.NewEncoder(w).Encode(f.items())
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/rest/items/"):
		name := strings.TrimPrefix(r.URL.Path, "/rest/items/")
		if name == "Odd_Item" {
			json.NewEncoder(w).Encode(f.items()[0])
			return
		}
		for _, it := range f.items() {
			if it["name"] == name {
				json.NewEncoder(w).Encode(it)
				return
			}
		}
		w.WriteHeader(404)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/rest/items/"):
		if r.Header.Get("Content-Type") != "text/plain" {
			w.WriteHeader(415)
			return
		}
		f.states[strings.TrimPrefix(r.URL.Path, "/rest/items/")] = string(body)
	case r.Method == "GET" && r.URL.Path == "/rest/links":
		if r.URL.Query().Get("itemName") == "Switch_3" {
			io.WriteString(w, `[{"itemName":"Switch_3","channelUID":"nuki:smartlock:bridge1:front:lock"}]`)
			return
		}
		io.WriteString(w, `[{"itemName":"Other","channelUID":"zwave:device:ctrl:node5:lock_door"}]`)
	case r.Method == "GET" && r.URL.Path == "/rest/things":
		if r.URL.Query().Get("summary") != "true" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"UID":"zwave:device:ctrl:node5","label":"Front lock","thingTypeUID":"zwave:lock","bridgeUID":"zwave:serial_zstick:ctrl","statusInfo":{"status":"OFFLINE","statusDetail":"COMMUNICATION_ERROR","description":"Node not responding"},"configuration":{"password":"LEAKME"}}]`)
	case r.Method == "GET" && r.URL.Path == "/rest/rules":
		st := "IDLE"
		if len(f.ran) > 0 {
			st = "RUNNING"
		}
		fmt.Fprintf(w, `[{"uid":"evening_lights","name":"Evening lights","tags":["Lights"],"status":{"status":%q,"statusDetail":"NONE"},"actions":[{"configuration":{"script":"LEAKME"}}]}]`, st)
	case r.Method == "POST" && r.URL.Path == "/rest/rules/evening_lights/runnow":
		f.ran = append(f.ran, "evening_lights")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string, critical ...string) (*Module, *fakeHAB) {
	f := &fakeHAB{states: map[string]string{"Desk_Lamp": "OFF", "Hall_Dimmer": "40", "Rack_Plug": "ON", "Front_Lock": "ON", "Driveway_Relay": "OFF", "Living_Setpoint": "20 °C", "Mode": "home", "Switch_3": "OFF"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: ref, CriticalItems: critical})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://oh": token, "secret://bad": "oh.bad.BADBADBADBADBADBADBAD"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func cmd(item, c string) string { return fmt.Sprintf(`{"item":%q,"command":%q}`, item, c) }

func TestOpenHAB(t *testing.T) {
	m, f := setup(t, "secret://oh", "rack")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || h.Message != "openHAB is up with 16 items" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"items", `{}`, `"name":"Desk_Lamp"`},
		{"items", `{"tag":"lock"}`, `"critical":true`},
		{"items", `{"type":"Number"}`, `"Living_Setpoint"`},
		{"item", `{"item":"Driveway_Relay"}`, `"criticalBecause":"in group Opener (gOpener), tagged GarageDoor"`},
		{"item", `{"item":"Hall_Dimmer"}`, `"max":100`},
		{"things", `{}`, `"statusDetail":"COMMUNICATION_ERROR"`},
		{"rules", `{}`, `"status":"IDLE"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, token) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}

	// A plain switch: preview, send, read back, undo, no-op.
	r, err := invoke(m, "send_command", cmd("Desk_Lamp", "on"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Send ON to Desk lamp (Desk_Lamp) (a Switch item, now OFF)" || f.states["Desk_Lamp"] != "OFF" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_command", cmd("Desk_Lamp", "on"), false)
	if err != nil || f.states["Desk_Lamp"] != "ON" || !strings.Contains(string(r.Output), `"state":"ON"`) || r.Undo == nil || r.Undo.Action != "send_command" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.states["Desk_Lamp"] != "OFF" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "send_command", cmd("Desk_Lamp", "OFF"), false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if r, err := invoke(m, "send_command", cmd("Hall_Dimmer", "ON"), false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("dimmer no-op: %s %v", r.Output, err)
	}
	if r, err := invoke(m, "send_command", cmd("Hall_Dimmer", "75"), false); err != nil || f.states["Hall_Dimmer"] != "75" || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"command":"40"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "send_command", cmd("Mode", "away"), false); err != nil || f.states["Mode"] != "away" {
		t.Fatal(err)
	}

	// Critical items need the destructive action, with a clear preview.
	for _, c := range [][2]string{{"Front_Lock", "OFF"}, {"Driveway_Relay", "ON"}, {"Rack_Plug", "OFF"}, {"Living_Setpoint", "25 °C"}, {"gOpener", "ON"},
		{"Switch_3", "ON"}, {"Plug_7", "ON"}, {"Orphan", "ON"}, {"Relais_Hoftor", "ON"}, {"Living_Level", "80"}} {
		if _, err := invoke(m, "send_command", cmd(c[0], c[1]), false); err == nil || !strings.Contains(err.Error(), "send_critical_command") {
			t.Fatalf("%s: %v", c[0], err)
		}
	}
	if f.states["Front_Lock"] != "ON" || f.states["Driveway_Relay"] != "OFF" || f.states["Rack_Plug"] != "ON" || f.states["Switch_3"] != "OFF" {
		t.Fatal("a critical item changed")
	}
	for _, c := range [][2]string{{"Switch_3", "linked to channel nuki:smartlock:bridge1:front:lock"}, {"Plug_7", "its homekit metadata is LockMechanism"},
		{"Orphan", "in group gHidden, which openHAB doesn't list"}, {"Living_Level", "a temperature"}} {
		if r, err := invoke(m, "item", fmt.Sprintf(`{"item":%q}`, c[0]), false); err != nil || !strings.Contains(string(r.Output), c[1]) {
			t.Fatalf("%s: %s %v", c[0], r.Output, err)
		}
	}
	r, err = invoke(m, "send_critical_command", cmd("Driveway_Relay", "ON"), true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "this turns it on (a gate or door opener fires") || !strings.Contains(r.Plan.Summary, "tagged GarageDoor") || f.states["Driveway_Relay"] != "OFF" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_critical_command", cmd("Front_Lock", "OFF"), false)
	if err != nil || f.states["Front_Lock"] != "OFF" || r.Undo == nil || r.Undo.Action != "send_critical_command" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.states["Front_Lock"] != "ON" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "send_critical_command", cmd("Desk_Lamp", "ON"), false); err == nil || !strings.Contains(err.Error(), "isn't critical") {
		t.Fatal(err)
	}

	// Rules.
	r, err = invoke(m, "run_rule", `{"rule":"evening_lights"}`, true)
	if err != nil || r.Plan == nil || len(f.ran) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "run_rule", `{"rule":"evening_lights"}`, false)
	if err != nil || len(f.ran) != 1 || !strings.Contains(string(r.Output), `"status":"RUNNING"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "run_rule", `{"rule":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no rule") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "run_rule" || a.Name == "send_critical_command") && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Name)
		}
	}
}

func TestOpenHABValidation(t *testing.T) {
	m, f := setup(t, "secret://oh")
	for _, c := range [][2]string{
		{"send_command", `{}`},
		{"send_command", cmd("../things", "ON")},
		{"send_command", cmd("Desk_Lamp?x=1", "ON")},
		{"send_command", cmd("Desk_Lamp", "")},
		{"send_command", cmd("Desk_Lamp", "ON\nOFF")},
		{"item", `{"item":"a/b"}`},
		{"run_rule", `{"rule":"../items"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %s %s", c[0], c[1])
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Commands that don't fit the item never reach it.
	for _, c := range [][2]string{{"Desk_Lamp", "50"}, {"Hall_Dimmer", "101"}, {"Hall_Dimmer", "UP"}, {"Mode", "party"},
		{"Window_Contact", "OPEN"}, {"Mystery", "OFF"}, {"Living_Setpoint", "hot"}} {
		action := "send_command"
		if c[0] == "Living_Setpoint" || c[0] == "Window_Contact" {
			action = "send_critical_command"
		}
		if _, err := invoke(m, action, cmd(c[0], c[1]), false); err == nil {
			t.Fatalf("accepted %s=%s", c[0], c[1])
		}
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "POST") {
			t.Fatalf("a bad command reached openHAB: %s", s)
		}
	}
	// The item changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "send_command", cmd("Odd_Item", "ON"), false); err == nil || f.states["Desk_Lamp"] != "OFF" {
		t.Fatalf("changed another item: %v", err)
	}
	if _, err := invoke(m, "item", `{"item":"Nope"}`, false); err == nil || !strings.Contains(err.Error(), "no item") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "http://oh.local", Token: "oh.plain.token"},
		{URL: "http://oh.local"},
		{URL: "oh.local", Token: "secret://oh"},
		{URL: "http://u:p@oh.local", Token: "secret://oh"},
		{URL: "http://oh.local/?x=1", Token: "secret://oh"},
		{URL: "http://oh.local/#x", Token: "secret://oh"},
		{URL: "http://oh.local", Token: "secret://oh", Fingerprint: "ab"},
		{URL: "http://oh.local", Token: "secret://oh", CriticalItems: []string{""}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "o")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API token") || strings.Contains(h.Message, "BAD") {
		t.Fatalf("%+v", h)
	}
}

func TestOpenHABRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://oh"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://oh": token}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
