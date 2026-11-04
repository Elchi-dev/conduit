package domoticz

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

type fakeDomo struct {
	mu        sync.Mutex
	seen      []string
	status    map[string]string
	activated []string
}

func (f *fakeDomo) devices() []map[string]any {
	return []map[string]any{
		{"idx": "1", "Name": "Desk lamp", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "On/Off", "Status": f.status["1"], "Data": f.status["1"], "Protected": false, "HardwareName": "Zigbee"},
		{"idx": "2", "Name": "Hall", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "Dimmer", "Status": f.status["2"], "Data": f.status["2"]},
		{"idx": "3", "Name": "Front", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "Door Lock", "Status": f.status["3"]},
		{"idx": "4", "Name": "Driveway Gate", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "On/Off", "Status": f.status["4"]},
		{"idx": "5", "Name": "Rack", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "On/Off", "Status": f.status["5"]},
		{"idx": "6", "Name": "Living", "Type": "Thermostat", "SubType": "SetPoint", "SwitchType": "", "Status": "", "Data": "21.0"},
		{"idx": "7", "Name": "Hallway motion", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "Motion Sensor", "Status": "Off"},
		{"idx": "8", "Name": "Pump", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "On/Off", "Status": "Off"},
		{"idx": "10", "Name": "Fan", "Type": "Light/Switch", "SubType": "Switch", "SwitchType": "On/Off", "Status": "Off", "Protected": true},
		{"idx": "9", "Name": "Mystery", "Type": "General", "SubType": "Custom", "Status": "On"},
	}
}

func (f *fakeDomo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	if r.URL.Path != "/json.htm" {
		w.WriteHeader(404)
		return
	}
	if q.Get("param") == "getversion" {
		io.WriteString(w, `{"status":"OK","title":"GetVersion","version":"2024.7"}`)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "dz-good" {
		w.WriteHeader(401)
		io.WriteString(w, `<html>401 Unauthorized</html>`)
		return
	}
	res := func(v any) {
		b, _ := json.Marshal(map[string]any{"status": "OK", "title": "x", "result": v})
		w.Write(b)
	}
	switch q.Get("param") {
	case "getdevices":
		if rid := q.Get("rid"); rid != "" {
			for _, d := range f.devices() {
				if d["idx"] == rid {
					res([]any{d})
					return
				}
			}
			if rid == "99" { // answers with another device
				res([]any{f.devices()[0]})
				return
			}
			res(nil)
			return
		}
		res(f.devices())
	case "switchlight":
		idx := q.Get("idx")
		if idx == "8" {
			io.WriteString(w, `{"status":"ERR","message":"WRONG CODE"}`)
			return
		}
		f.status[idx] = q.Get("switchcmd")
		io.WriteString(w, `{"status":"OK","title":"SwitchLight"}`)
	case "getscenes":
		st := "Off"
		if len(f.activated) > 0 {
			st = "On"
		}
		res([]map[string]any{{"idx": "1", "Name": "Movie", "Type": "Scene", "Status": st, "LastUpdate": "2026-11-04 20:00:00"}, {"idx": "2", "Name": "Away", "Type": "Group", "Status": "Mixed", "Protected": true}})
	case "switchscene":
		f.activated = append(f.activated, q.Get("idx"))
		io.WriteString(w, `{"status":"OK","title":"SwitchScene"}`)
	default:
		io.WriteString(w, `{"status":"ERR","message":"unknown command"}`)
	}
}

func setup(t *testing.T, ref string, critical ...string) (*Module, *fakeDomo) {
	f := &fakeDomo{status: map[string]string{"1": "Off", "2": "Set Level: 40 %", "3": "Locked", "4": "Off", "5": "On"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: ref, CriticalDevices: critical})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dz": "dz-good", "secret://bad": "dz-bad"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func sw(idx, s string) string { return fmt.Sprintf(`{"idx":%q,"switch":%q}`, idx, s) }

func TestDomoticz(t *testing.T) {
	m, f := setup(t, "secret://dz", "rack")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "Domoticz 2024.7 is up" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"devices", `{}`, `"switchType":"Door Lock"`},
		{"devices", `{"search":"gate"}`, `"critical":true`},
		{"device", `{"idx":"6"}`, `"criticalBecause":"a thermostat setpoint device"`},
		{"device", `{"idx":"1"}`, `"hardware":"Zigbee"`},
		{"scenes", `{}`, `"name":"Movie"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "dz-good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}

	r, err := invoke(m, "switch_device", sw("1", "on"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Switch Desk lamp (1) On (a On/Off, now Off)" || f.status["1"] != "Off" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "switch_device", sw("1", "On"), false)
	if err != nil || f.status["1"] != "On" || !strings.Contains(string(r.Output), `"status":"On"`) || r.Undo == nil || r.Undo.Action != "switch_device" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["1"] != "Off" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "switch_device", sw("2", "On"), false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	// Critical devices need the destructive action, with a clear preview.
	for _, idx := range []string{"3", "4", "5", "6"} {
		if _, err := invoke(m, "switch_device", sw(idx, "Off"), false); err == nil || !strings.Contains(err.Error(), "switch_critical_device") {
			t.Fatalf("%s: %v", idx, err)
		}
	}
	if f.status["3"] != "Locked" || f.status["4"] != "Off" || f.status["5"] != "On" {
		t.Fatal("a critical device changed")
	}
	r, err = invoke(m, "switch_critical_device", sw("4", "On"), true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "this turns it on (a gate or door opener fires") || f.status["4"] != "Off" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "switch_critical_device", sw("3", "Off"), true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "locks or unlocks it (a door lock switch)") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "switch_critical_device", sw("4", "On"), false)
	if err != nil || f.status["4"] != "On" || r.Undo == nil || r.Undo.Action != "switch_critical_device" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["4"] != "Off" {
		t.Fatal(err)
	}
	// A lock's status isn't On or Off: no undo is guessed.
	if r, err := invoke(m, "switch_critical_device", sw("3", "Off"), false); err != nil || r.Undo != nil || f.status["3"] != "Off" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "switch_critical_device", sw("1", "On"), false); err == nil || !strings.Contains(err.Error(), "isn't critical") {
		t.Fatal(err)
	}
	// A thermostat has no switch type: refused, not guessed.
	if _, err := invoke(m, "switch_critical_device", sw("6", "On"), false); err == nil || !strings.Contains(err.Error(), "doesn't say what kind") {
		t.Fatal(err)
	}

	// Scenes.
	r, err = invoke(m, "activate_scene", `{"idx":"1"}`, true)
	if err != nil || r.Plan == nil || len(f.activated) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "activate_scene", `{"idx":"1"}`, false)
	if err != nil || len(f.activated) != 1 || !strings.Contains(string(r.Output), `"status":"On"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "activate_scene", `{"idx":"2"}`, false); err == nil || !strings.Contains(err.Error(), "protected") || len(f.activated) != 1 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "activate_scene" || a.Name == "switch_critical_device") && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Name)
		}
	}
}

func TestDomoticzValidation(t *testing.T) {
	m, f := setup(t, "secret://dz")
	for _, c := range [][2]string{
		{"switch_device", `{}`},
		{"switch_device", sw("1&param=switchscene", "On")},
		{"switch_device", sw("-1", "On")},
		{"switch_device", sw("1", "Toggle")},
		{"device", `{"idx":"a"}`},
		{"activate_scene", `{"idx":"1;2"}`},
		{"devices", `{"filter":"x&y=1"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %s %s", c[0], c[1])
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Sensors, protected and unknown devices aren't switched.
	for _, idx := range []string{"7", "10", "9"} {
		if _, err := invoke(m, "switch_device", sw(idx, "On"), false); err == nil {
			t.Fatalf("switched %s", idx)
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "switchlight") {
			t.Fatalf("a refused switch reached Domoticz: %s", s)
		}
	}
	// The device switched is the one asked for, whatever the server answers.
	if _, err := invoke(m, "switch_device", sw("99", "On"), false); err == nil || f.status["1"] != "Off" {
		t.Fatalf("switched another device: %v", err)
	}
	if _, err := invoke(m, "device", `{"idx":"42"}`, false); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "http://dz.local", Username: "admin", Password: "plain"},
		{URL: "http://dz.local", Username: "admin"},
		{URL: "http://dz.local", Password: "secret://dz"},
		{URL: "dz.local", Username: "admin", Password: "secret://dz"},
		{URL: "http://u:p@dz.local", Username: "admin", Password: "secret://dz"},
		{URL: "http://dz.local/?x=1", Username: "admin", Password: "secret://dz"},
		{URL: "http://dz.local", Username: "a:b", Password: "secret://dz"},
		{URL: "http://dz.local", Username: "admin", Password: "secret://dz", InsecureSkipVerify: true},
		{URL: "http://dz.local", Username: "admin", Password: "secret://dz", CriticalDevices: []string{" "}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "d")
	if h.Status != "down" || !strings.HasPrefix(h.Message, "Domoticz refused the username or password") {
		t.Fatalf("%+v", h)
	}
	// A refusal in the JSON envelope is an error, not a success.
	if r, err := invoke(m, "switch_device", sw("8", "On"), false); err == nil || err.Error() != "Domoticz refused: WRONG CODE" || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDomoticzRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://dz"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dz": "dz-good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
