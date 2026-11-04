package librenms

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

type fakeNMS struct {
	mu    sync.Mutex
	seen  []string
	state map[string]int
	body  map[string]any
}

func (f *fakeNMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != "tok-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthenticated."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	alert := func(id string) string {
		return fmt.Sprintf(`{"id":%s,"device_id":1,"rule_id":3,"state":%d,"severity":"critical","timestamp":"2026-11-04 09:00:00","hostname":"core-sw"}`, id, f.state[id])
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v0/devices":
		io.WriteString(w, `{"status":"ok","count":2,"devices":[{"device_id":1,"hostname":"core-sw","sysName":"core-sw.lan","os":"ios","version":"15.2","hardware":"WS-C2960","location":"Rack 1","status":1,"uptime":864000,"last_polled":"2026-11-04 10:00:00","disabled":0,"ignore":0,"community":"COMMUNITY-LEAKME","authpass":"AUTH-LEAKME","cryptopass":"CRYPT-LEAKME"},
			{"device_id":2,"hostname":"ap1","status":0,"status_reason":"icmp","disabled":0,"ignore":0,"community":"COMMUNITY-LEAKME"}]}`)
	case r.Method == "GET" && (r.URL.Path == "/api/v0/ports" || r.URL.Path == "/api/v0/devices/core-sw/ports"):
		if !strings.Contains(r.URL.Query().Get("columns"), "ifOperStatus") {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"status":"ok","ports":[{"port_id":10,"device_id":1,"ifName":"Gi0/1","ifAlias":"uplink","ifOperStatus":"up","ifAdminStatus":"up","ifSpeed":1000000000,"ifInOctets_rate":12345,"ifOutOctets_rate":"678","ifInErrors_delta":0,"deleted":0},
			{"port_id":11,"device_id":1,"ifName":"Gi0/2","ifOperStatus":"down","ifAdminStatus":"up","deleted":0},{"port_id":12,"device_id":1,"ifName":"Gi0/3","deleted":1}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/v0/devices/nope/ports":
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"error","message":"Device nope does not exist"}`)
	case r.Method == "GET" && r.URL.Path == "/api/v0/alerts":
		st := r.URL.Query().Get("state")
		out := []string{}
		for _, id := range []string{"5", "6"} {
			if st == "" || st == fmt.Sprint(f.state[id]) {
				out = append(out, alert(id))
			}
		}
		fmt.Fprintf(w, `{"status":"ok","alerts":[%s]}`, strings.Join(out, ","))
	case r.Method == "GET" && r.URL.Path == "/api/v0/rules":
		io.WriteString(w, `{"status":"ok","rules":[{"id":3,"name":"Port down","severity":"critical"}]}`)
	case r.Method == "GET" && (r.URL.Path == "/api/v0/alerts/5" || r.URL.Path == "/api/v0/alerts/6" || r.URL.Path == "/api/v0/alerts/7"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v0/alerts/")
		if id == "7" { // answers with another alert
			id = "5"
		}
		fmt.Fprintf(w, `{"status":"ok","alerts":[%s]}`, alert(id))
	case r.Method == "PUT" && (r.URL.Path == "/api/v0/alerts/5" || r.URL.Path == "/api/v0/alerts/6"):
		json.Unmarshal(body, &f.body)
		f.state[strings.TrimPrefix(r.URL.Path, "/api/v0/alerts/")] = 2
		io.WriteString(w, `{"status":"ok","message":"Alert has been acknowledged"}`)
	case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/v0/alerts/unmute/"):
		f.state[strings.TrimPrefix(r.URL.Path, "/api/v0/alerts/unmute/")] = 1
		io.WriteString(w, `{"status":"ok","message":"Alert has been unmuted"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"error","message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNMS) {
	f := &fakeNMS{state: map[string]int{"5": 1, "6": 0}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nms": "tok-good", "secret://bad": "tok-bad"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLibreNMS(t *testing.T) {
	m, f := setup(t, "secret://nms")
	if h := m.Health(context.Background(), "l"); h.Status != "degraded" || h.Message != "2 devices, 1 down" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"devices", `{}`, `"hardware":"WS-C2960"`},
		{"devices", `{"down":true}`, `"downReason":"icmp"`},
		{"ports", `{}`, `"alias":"uplink"`},
		{"ports", `{"device":"core-sw"}`, `"outBytesPerSecond":678`},
		{"ports", `{"down":true}`, `"name":"Gi0/2"`},
		{"alerts", `{}`, `"rule":"Port down"`},
		{"alerts", `{"state":"all"}`, `"state":"ok"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "tok-good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "ports", `{}`, false); strings.Contains(string(r.Output), "Gi0/3") {
		t.Fatal("deleted port listed")
	}
	if r, _ := invoke(m, "devices", `{"down":true}`, false); strings.Contains(string(r.Output), "core-sw") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "ports", `{"device":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatal(err)
	}

	// Acknowledge: preview, real, undo.
	r, err := invoke(m, "ack_alert", `{"alert":5,"note":"looking into it"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Acknowledge alert 5 (Port down on core-sw.lan, critical); its notifications stop" || f.state["5"] != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "ack_alert", `{"alert":5,"note":"looking into it"}`, false)
	if err != nil || f.state["5"] != 2 || r.Undo == nil || r.Undo.Action != "unmute_alert" || string(r.Undo.Input) != `{"alert":5}` {
		t.Fatalf("%+v %v", r, err)
	}
	if f.body["note"] != "looking into it" || f.body["until_clear"] != true {
		t.Fatal(f.body)
	}
	if r, err := invoke(m, "ack_alert", `{"alert":5}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state["5"] != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "ack_alert", `{"alert":6}`, false); err == nil || !strings.Contains(err.Error(), "cleared") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "ack_alert", `{"alert":7}`, false); err == nil || !strings.Contains(err.Error(), "no alert 7") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "ack_alert" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestLibreNMSValidation(t *testing.T) {
	m, f := setup(t, "secret://nms")
	for _, c := range []struct{ action, in string }{
		{"ack_alert", `{}`},
		{"ack_alert", `{"alert":-1}`},
		{"ack_alert", `{"alert":"5/../x"}`},
		{"ack_alert", `{"alert":5,"note":"` + strings.Repeat("x", 600) + `"}`},
		{"ack_alert", `{"alert":5,"note":"a\u0000b"}`},
		{"unmute_alert", `{"alert":0}`},
		{"ports", `{"device":"../users"}`},
		{"ports", `{"device":"a b"}`},
		{"ports", `{"device":"x?y=1"}`},
		{"alerts", `{"state":"weird"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached LibreNMS: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://nms", Token: "plain"}, {URL: "nms.example.com", Token: "secret://nms"}, {URL: "https://u:p@nms", Token: "secret://nms"},
		{URL: "https://nms/?a=1", Token: "secret://nms"}, {URL: "https://nms/#a", Token: "secret://nms"}, {URL: "https://nms", Token: "secret://nms", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || h.Message != "LibreNMS refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestLibreNMSRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Auth-Token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://nms"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nms": "tok-good"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
