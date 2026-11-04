package iobroker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeBroker struct {
	mu   sync.Mutex
	seen []string
	vals map[string]any
}

// objects are the fake's objects: _id, type, common.
var objects = map[string]string{
	"hue.0.Desk_lamp":              `{"type":"device","common":{"name":"Desk lamp"}}`,
	"hue.0.Desk_lamp.on":           `{"type":"state","common":{"name":"On","type":"boolean","role":"switch.light","read":true,"write":true}}`,
	"hue.0.Desk_lamp.level":        `{"type":"state","common":{"name":{"en":"Brightness","de":"Helligkeit"},"type":"number","role":"level.dimmer","min":0,"max":100,"unit":"%","read":true,"write":true}}`,
	"hue.0.Desk_lamp.reachable":    `{"type":"state","common":{"name":"Reachable","type":"boolean","role":"indicator.reachable","read":true,"write":false}}`,
	"zigbee.0.aa11":                `{"type":"device","common":{"name":"Garage opener"}}`,
	"zigbee.0.aa11.state":          `{"type":"state","common":{"name":"Relay","type":"boolean","role":"switch","read":true,"write":true}}`,
	"nuki.0.front.action":          `{"type":"state","common":{"name":"Action","type":"number","role":"switch.lock","states":{"1":"unlock","2":"lock"},"read":true,"write":true}}`,
	"shelly.0.rack.Relay0.Switch":  `{"type":"state","common":{"name":"Rack","type":"boolean","role":"switch","read":true,"write":true}}`,
	"tv.0.input":                   `{"type":"state","common":{"name":"Input","type":"string","role":"media.input","states":{"hdmi1":"HDMI 1","hdmi2":"HDMI 2"},"read":true,"write":true}}`,
	"misc.0.blob":                  `{"type":"state","common":{"name":"Blob","type":"json","role":"json","read":true,"write":true}}`,
	"misc.0.untyped":               `{"type":"state","common":{"name":"Untyped","role":"state","read":true,"write":true}}`,
	"misc.0.mode":                  `{"type":"state","common":{"name":"Mode","type":"number","role":"value","states":"0:off;1:eco;2:full","read":true,"write":true}}`,
	"misc.0.odd":                   `{"type":"state","common":{"name":"Odd","type":"boolean","role":"switch","read":true,"write":true}}`,
	"system.adapter.admin.0.alive": `{"type":"state","common":{"name":"alive","type":"boolean","role":"indicator","read":true,"write":true}}`,
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "io-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"authentication failed"}`)
		return
	}
	obj := func(id string) string {
		o, ok := objects[id]
		if !ok {
			return ""
		}
		b, _ := json.Marshal(f.vals[id])
		return fmt.Sprintf(`{"_id":%q,%s,"val":%s,"ack":true,"ts":1762300000000,"lc":1762300000000,"from":"system.adapter.x","native":{"password":"LEAKME"}}`, id, o[1:len(o)-1], b)
	}
	match := func(pat, id string) bool {
		ok, _ := path.Match(strings.ReplaceAll(pat, ".", "/"), strings.ReplaceAll(id, ".", "/"))
		return ok || strings.HasPrefix(id, strings.TrimSuffix(pat, "*")) && strings.HasSuffix(pat, "*")
	}
	switch {
	case r.URL.Path == "/help":
		io.WriteString(w, `{"getPlainValue":"http://x/getPlainValue/stateID"}`)
	case strings.HasPrefix(r.URL.Path, "/get/"):
		id := strings.TrimPrefix(r.URL.Path, "/get/")
		if id == "misc.0.odd" {
			io.WriteString(w, obj("hue.0.Desk_lamp.on"))
			return
		}
		o := obj(id)
		if o == "" {
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"error":"datapoint \"%s\" not found"}`, id)
			return
		}
		io.WriteString(w, o)
	case r.URL.Path == "/states":
		out := map[string]json.RawMessage{}
		for id, o := range objects {
			if strings.Contains(o, `"type":"state"`) && match(r.URL.Query().Get("pattern"), id) {
				b, _ := json.Marshal(f.vals[id])
				out[id] = json.RawMessage(fmt.Sprintf(`{"val":%s,"ack":false,"ts":1,"lc":1762300000000,"from":"x"}`, b))
			}
		}
		json.NewEncoder(w).Encode(out)
	case r.URL.Path == "/objects":
		out := map[string]json.RawMessage{}
		for id := range objects {
			if match(r.URL.Query().Get("pattern"), id) {
				out[id] = json.RawMessage(obj(id))
			}
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/set/"):
		id := strings.TrimPrefix(r.URL.Path, "/set/")
		q := r.URL.Query()
		if q.Get("ack") != "false" {
			w.WriteHeader(400)
			return
		}
		v := q.Get("value")
		switch q.Get("type") {
		case "boolean":
			f.vals[id] = v == "true"
		case "number":
			n, _ := strconv.ParseFloat(v, 64)
			f.vals[id] = n
		default:
			f.vals[id] = v
		}
		fmt.Fprintf(w, `{"id":%q,"value":%q}`, id, v)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string, critical ...string) (*Module, *fakeBroker) {
	f := &fakeBroker{vals: map[string]any{"hue.0.Desk_lamp.on": false, "hue.0.Desk_lamp.level": 40.0, "zigbee.0.aa11.state": false, "nuki.0.front.action": 2.0,
		"shelly.0.rack.Relay0.Switch": true, "tv.0.input": "hdmi1", "misc.0.mode": 1.0, "misc.0.odd": false, "system.adapter.admin.0.alive": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: ref, CriticalStates: critical})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://io": "io-good", "secret://bad": "io-bad"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func set(id, v string) string { return fmt.Sprintf(`{"id":%q,"value":%s}`, id, v) }

func TestIOBroker(t *testing.T) {
	m, f := setup(t, "secret://io", "shelly.0.rack")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"states", `{"pattern":"hue.0.*"}`, `"name":"Brightness","role":"level.dimmer","type":"number","unit":"%","value":40,"writable":true`},
		{"states", `{"pattern":"zigbee.0.*"}`, `"critical":true`},
		{"state", `{"id":"zigbee.0.aa11.state"}`, `"criticalBecause":"part of zigbee.0.aa11, its name says`},
		{"state", `{"id":"nuki.0.front.action"}`, `"allowed":["1","2"]`},
		{"state", `{"id":"hue.0.Desk_lamp.level"}`, `"max":100`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "io-good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}

	r, err := invoke(m, "set_state", set("hue.0.Desk_lamp.level", "75"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set Brightness (hue.0.Desk_lamp.level) to 75 (now 40)" || f.vals["hue.0.Desk_lamp.level"] != 40.0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_state", set("hue.0.Desk_lamp.level", "75"), false)
	if err != nil || f.vals["hue.0.Desk_lamp.level"] != 75.0 || !strings.Contains(string(r.Output), `"now":75`) || r.Undo == nil || r.Undo.Action != "set_state" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.vals["hue.0.Desk_lamp.level"] != 40.0 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "set_state", set("hue.0.Desk_lamp.on", "false"), false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "set_state", set("tv.0.input", `"hdmi2"`), false); err != nil || f.vals["tv.0.input"] != "hdmi2" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_state", set("misc.0.mode", "2"), false); err != nil || f.vals["misc.0.mode"] != 2.0 {
		t.Fatal(err)
	}

	// Critical states need the destructive action, with a clear preview.
	for _, id := range []string{"zigbee.0.aa11.state", "nuki.0.front.action", "shelly.0.rack.Relay0.Switch"} {
		v := "true"
		if id == "nuki.0.front.action" {
			v = "1"
		}
		if _, err := invoke(m, "set_state", set(id, v), false); err == nil || !strings.Contains(err.Error(), "set_critical_state") {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if f.vals["zigbee.0.aa11.state"] != false || f.vals["nuki.0.front.action"] != 2.0 {
		t.Fatal("a critical state changed")
	}
	r, err = invoke(m, "set_critical_state", set("nuki.0.front.action", "1"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set Action (nuki.0.front.action) to 1 (now 2); this sets it to 1 (a position, mode or temperature of a lock, door, alarm, valve or heating) (its role is switch.lock)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_critical_state", set("zigbee.0.aa11.state", "true"), false)
	if err != nil || f.vals["zigbee.0.aa11.state"] != true || r.Undo == nil || r.Undo.Action != "set_critical_state" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.vals["zigbee.0.aa11.state"] != false {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_critical_state", set("hue.0.Desk_lamp.on", "true"), false); err == nil || !strings.Contains(err.Error(), "isn't critical") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "set_critical_state" && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Name)
		}
	}
}

func TestIOBrokerValidation(t *testing.T) {
	m, f := setup(t, "secret://io")
	for _, c := range [][2]string{
		{"set_state", `{}`},
		{"set_state", set("../set/x", "true")},
		{"set_state", set("hue.0.Desk_lamp.on?ack=true", "true")},
		{"set_state", set("hue", "true")},
		{"set_state", set("hue.0.Desk_lamp.on", "null")},
		{"set_state", set("system.adapter.admin.0.alive", "false")},
		{"set_critical_state", set("admin.0.info", "1")},
		{"state", `{"id":"a/b.c"}`},
		{"states", `{"pattern":"*"}`},
		{"states", `{"pattern":"hue.0.*&pattern=x"}`},
		{"states", `{}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %s %s", c[0], c[1])
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Values that don't fit the state, and states that can't be set, never
	// reach ioBroker.
	for _, c := range [][2]string{
		{"hue.0.Desk_lamp.level", "101"}, {"hue.0.Desk_lamp.level", `"high"`}, {"hue.0.Desk_lamp.on", `"yes"`}, {"hue.0.Desk_lamp.on", "1"},
		{"hue.0.Desk_lamp.reachable", "false"}, {"tv.0.input", `"hdmi9"`}, {"misc.0.blob", `"{}"`}, {"misc.0.untyped", `"x"`},
		{"misc.0.mode", "5"}, {"hue.0.Desk_lamp", "true"}, {"tv.0.input", `"a\nb"`},
	} {
		if _, err := invoke(m, "set_state", set(c[0], c[1]), false); err == nil {
			t.Fatalf("accepted %s=%s", c[0], c[1])
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "/set/") {
			t.Fatalf("a bad value reached ioBroker: %s", s)
		}
	}
	// The state changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "set_state", set("misc.0.odd", "true"), false); err == nil || f.vals["hue.0.Desk_lamp.on"] != false {
		t.Fatalf("changed another state: %v", err)
	}
	if _, err := invoke(m, "state", `{"id":"nope.0.x"}`, false); err == nil || !strings.Contains(err.Error(), "no state") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "http://io.local", Username: "admin", Password: "plain"},
		{URL: "http://io.local", Username: "admin"},
		{URL: "http://io.local", Password: "secret://io"},
		{URL: "io.local"},
		{URL: "http://u:p@io.local"},
		{URL: "http://io.local/?user=a&pass=b"},
		{URL: "http://io.local", Fingerprint: "ab"},
		{URL: "http://io.local", CriticalStates: []string{"garage"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "i")
	if h.Status != "down" || h.Message != "ioBroker refused the username or password" {
		t.Fatalf("%+v", h)
	}
}

func TestIOBrokerRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://io"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://io": "io-good"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "i"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
