package homebridge

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

const (
	lampID   = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	lockID   = "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	gateID   = "c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	plugID   = "d1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	otherID  = "e1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	camID    = "91b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	motionID = "92b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	strangeR = "f1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
)

type fakeBridge struct {
	mu        sync.Mutex
	seen      []string
	logins    int
	on        bool
	bri       float64
	lock      float64 // LockTargetState: 1 secured
	gate      bool
	plug      bool
	motion    bool
	restarted bool
}

func (f *fakeBridge) svc(id string) string {
	info := `"accessoryInformation":{"Manufacturer":"Acme","Model":"X1","Name":"%s","Serial Number":"LEAKME-SERIAL"},"instance":{"name":"Homebridge 1A2B","username":"0E:LEAKME","ipAddress":"10.0.0.2"}`
	switch id {
	case lampID:
		return fmt.Sprintf(`{"uniqueId":%q,"type":"Lightbulb","humanType":"Lightbulb","serviceName":"Desk lamp","serviceCharacteristics":[
			{"type":"On","format":"bool","value":%t,"canRead":true,"canWrite":true},
			{"type":"Brightness","format":"int","value":%g,"minValue":0,"maxValue":100,"minStep":1,"unit":"percentage","canRead":true,"canWrite":true},
			{"type":"Name","format":"string","value":"Desk lamp","canRead":true,"canWrite":false}],`+info+`}`, id, f.on, f.bri, "Desk lamp")
	case lockID:
		return fmt.Sprintf(`{"uniqueId":%q,"type":"LockMechanism","humanType":"Lock Mechanism","serviceName":"Front","serviceCharacteristics":[
			{"type":"LockCurrentState","format":"uint8","value":%g,"canRead":true,"canWrite":false},
			{"type":"LockTargetState","format":"uint8","value":%g,"minValue":0,"maxValue":1,"canRead":true,"canWrite":true}],`+info+`}`, id, f.lock, f.lock, "Front")
	case gateID:
		return fmt.Sprintf(`{"uniqueId":%q,"type":"Switch","humanType":"Switch","serviceName":"Driveway Gate","serviceCharacteristics":[
			{"type":"On","format":"bool","value":%t,"canRead":true,"canWrite":true}],`+info+`}`, id, f.gate, "Driveway Gate")
	case plugID:
		return fmt.Sprintf(`{"uniqueId":%q,"type":"Outlet","humanType":"Outlet","serviceName":"Rack","serviceCharacteristics":[
			{"type":"On","format":"bool","value":%t,"canRead":true,"canWrite":true}],`+info+`}`, id, f.plug, "Rack")
	case camID, motionID: // one camera accessory (aid 7) with a motion switch
		cam := `"accessoryInformation":{"Name":"Driveway"},"instance":{"name":"Homebridge 1A2B","username":"0E:LEAKME"}`
		if id == camID {
			return fmt.Sprintf(`{"uniqueId":%q,"aid":7,"iid":10,"type":"CameraRTPStreamManagement","humanType":"Camera Rtp Stream Management","serviceName":"Driveway","serviceCharacteristics":[
				{"type":"Active","format":"uint8","value":1,"canRead":true,"canWrite":true}],`+cam+`}`, id)
		}
		return fmt.Sprintf(`{"uniqueId":%q,"aid":7,"iid":20,"type":"Switch","humanType":"Switch","serviceName":"Driveway Motion","serviceCharacteristics":[
			{"type":"On","format":"bool","value":%t,"canRead":true,"canWrite":true}],`+cam+`}`, id, f.motion)
	case strangeR: // answers with another accessory
		return f.svc(lampID)
	}
	return ""
}

func (f *fakeBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.Method+" "+r.URL.Path == "POST /api/auth/login" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if b["username"] != "admin" || b["password"] != "hb-good" {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"Forbidden","statusCode":403}`)
			return
		}
		f.logins++
		fmt.Fprintf(w, `{"access_token":"jwt%d.BBBBBBBBBBBBBBBBBBBBBBBBBB","token_type":"Bearer","expires_in":28800}`, f.logins)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), fmt.Sprintf("Bearer jwt%d.", f.logins)) || f.logins == 0 {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/status/homebridge":
		io.WriteString(w, `{"status":"up"}`)
	case r.Method == "GET" && r.URL.Path == "/api/accessories":
		fmt.Fprintf(w, `[%s,%s,%s,%s,%s,%s,{"uniqueId":%q,"type":"AccessoryInformation","serviceName":"x","serviceCharacteristics":[]}]`, f.svc(lampID), f.svc(lockID), f.svc(gateID), f.svc(plugID), f.svc(camID), f.svc(motionID), otherID)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/accessories/"):
		s := f.svc(strings.TrimPrefix(r.URL.Path, "/api/accessories/"))
		if s == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found","statusCode":404}`)
			return
		}
		io.WriteString(w, s)
	case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/accessories/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/accessories/")
		var b struct {
			Type  string `json:"characteristicType"`
			Value any    `json:"value"`
		}
		json.Unmarshal(body, &b)
		switch id + "/" + b.Type {
		case lampID + "/On":
			f.on = b.Value == true
		case lampID + "/Brightness":
			f.bri = b.Value.(float64)
		case lockID + "/LockTargetState":
			f.lock = b.Value.(float64)
		case gateID + "/On":
			f.gate = b.Value == true
		case plugID + "/On":
			f.plug = b.Value == true
		case motionID + "/On":
			f.motion = b.Value == true
		default:
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, f.svc(id))
	case r.Method == "PUT" && r.URL.Path == "/api/server/restart":
		f.restarted = true
		io.WriteString(w, `{"ok":true,"command":"SIGTERM","restartingUI":false}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string, critical ...string) (*Module, *fakeBridge) {
	f := &fakeBridge{bri: 40, lock: 1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: pw, CriticalAccessories: critical})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hb": "hb-good", "secret://bad": "hb-bad"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func set(id, ch, v string) string {
	return fmt.Sprintf(`{"accessory":%q,"characteristic":%q,"value":%s}`, id, ch, v)
}

func TestHomebridge(t *testing.T) {
	m, f := setup(t, "secret://hb", "rack")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "Homebridge is up" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"accessories", `{}`, `"values":{"Brightness":40,"Name":"Desk lamp","On":false}`},
		{"accessories", `{"type":"Lock Mechanism"}`, `"critical":true`},
		{"accessories", `{"search":"desk"}`, `"manufacturer":"Acme"`},
		{"accessory", `{"accessory":"` + lampID + `"}`, `"max":100`},
		{"accessory", `{"accessory":"` + gateID + `"}`, `"criticalBecause":"its name says`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "hb-good") || strings.Contains(out, "AccessoryInformation") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "accessories", `{"search":"desk"}`, false); strings.Contains(string(r.Output), "Front") {
		t.Fatal(string(r.Output))
	}

	// A plain light: preview, set, undo, no-op.
	r, err := invoke(m, "set_characteristic", set(lampID, "Brightness", "75"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set Brightness of Desk lamp to 75 (now 40)" || f.bri != 40 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_characteristic", set(lampID, "Brightness", "75"), false)
	if err != nil || f.bri != 75 || r.Undo == nil || r.Undo.Action != "set_characteristic" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.bri != 40 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "set_characteristic", set(lampID, "on", "0"), false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "set_characteristic", set(lampID, "On", "true"), false); err != nil || !f.on {
		t.Fatal(err)
	}

	// Critical accessories need the destructive action, with a clear preview.
	for _, c := range []struct{ id, ch, v string }{{lockID, "LockTargetState", "0"}, {gateID, "On", "true"}, {plugID, "On", "true"}} {
		if _, err := invoke(m, "set_characteristic", set(c.id, c.ch, c.v), false); err == nil || !strings.Contains(err.Error(), "set_critical_characteristic") {
			t.Fatalf("%s: %v", c.id, err)
		}
	}
	if f.lock != 1 || f.gate || f.plug {
		t.Fatal("a critical accessory changed")
	}
	r, err = invoke(m, "set_critical_characteristic", set(lockID, "LockTargetState", "0"), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set LockTargetState of Front to 0 (now 1); this unlocks it (a lock mechanism accessory)" || f.lock != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_critical_characteristic", set(lockID, "LockTargetState", "0"), false)
	if err != nil || f.lock != 0 || r.Undo == nil || r.Undo.Action != "set_critical_characteristic" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.lock != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_critical_characteristic", set(lampID, "On", "false"), false); err == nil || !strings.Contains(err.Error(), "isn't critical") {
		t.Fatal(err)
	}

	// Restart.
	r, err = invoke(m, "restart_bridge", `{}`, true)
	if err != nil || r.Plan == nil || f.restarted {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "restart_bridge", `{}`, false); err != nil || !f.restarted {
		t.Fatal(err)
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "restart_bridge" || a.Name == "set_critical_characteristic") && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Name)
		}
	}
}

// A plain switch on a camera's (or lock's) accessory is as critical as the
// camera: turning off its motion detection mustn't be a plain write.
func TestHomebridgeCriticalSiblings(t *testing.T) {
	m, f := setup(t, "secret://hb")
	if _, err := invoke(m, "set_characteristic", set(motionID, "On", "true"), false); err == nil || !strings.Contains(err.Error(), "set_critical_characteristic") || f.motion {
		t.Fatalf("a camera's switch was set as a plain write: %v", err)
	}
	r, err := invoke(m, "accessory", `{"accessory":"`+motionID+`"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"criticalBecause":"part of the same accessory as Driveway`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "accessories", `{"search":"motion"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"critical":true`) || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "set_critical_characteristic", set(motionID, "On", "true"), false); err != nil || !f.motion || r.Undo == nil || r.Undo.Action != "set_critical_characteristic" {
		t.Fatalf("%+v %v", r, err)
	}
	// Integers stay within HAP's 32 bits.
	if _, err := coerce(char{Type: "X", Format: "int"}, json.RawMessage(`1e300`)); err == nil {
		t.Fatal("accepted 1e300 for an int")
	}
}

func TestHomebridgeValidation(t *testing.T) {
	m, f := setup(t, "secret://hb")
	for _, in := range []string{
		`{}`,
		set("../server/restart", "On", "true"),
		set(lampID+"?x=1", "On", "true"),
		set(lampID, "On/../x", "true"),
		set(lampID, "On", "null"),
		`{"accessory":"` + lampID + `","characteristic":"On"}`,
	} {
		if _, err := invoke(m, "set_characteristic", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "accessory", `{"accessory":"a/b"}`, false); err == nil {
		t.Fatal("accepted a/b")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Values outside the characteristic's format or range never reach it.
	for _, c := range []struct{ ch, v string }{{"Brightness", "101"}, {"Brightness", "-1"}, {"Brightness", "50.5"}, {"Brightness", `"high"`}, {"On", `"yes"`}, {"On", "2"}, {"Name", `"x"`}, {"Hue", "1"}} {
		if _, err := invoke(m, "set_characteristic", set(lampID, c.ch, c.v), false); err == nil {
			t.Fatalf("accepted %s=%s", c.ch, c.v)
		}
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "PUT") {
			t.Fatalf("a bad value reached the bridge: %s", s)
		}
	}
	// The accessory changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "set_characteristic", set(strangeR, "On", "true"), false); err == nil || f.on {
		t.Fatalf("changed another accessory: %v", err)
	}
	if _, err := invoke(m, "accessory", `{"accessory":"`+otherID+`0"}`, false); err == nil || !strings.Contains(err.Error(), "no accessory") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "http://hb.local", Username: "admin", Password: "plain"},
		{URL: "http://hb.local", Username: "admin"},
		{URL: "http://hb.local", Password: "secret://hb"},
		{URL: "hb.local", Username: "admin", Password: "secret://hb"},
		{URL: "http://u:p@hb.local", Username: "admin", Password: "secret://hb"},
		{URL: "http://hb.local/?x=1", Username: "admin", Password: "secret://hb"},
		{URL: "http://hb.local", Username: "admin", Password: "secret://hb", CriticalAccessories: []string{""}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "b")
	if h.Status != "down" || h.Message != "Homebridge refused the username or password" {
		t.Fatalf("%+v", h)
	}
}

func TestHomebridgeRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://hb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hb": "hb-good"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
