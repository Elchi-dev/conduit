package netbird

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

type fakeNetBird struct {
	mu       sync.Mutex
	seen     []string
	waiting  map[string]bool
	lastBody map[string]any
	ignore   bool // like a server without peer approval
}

func (f *fakeNetBird) peer(id string) string {
	return fmt.Sprintf(`{"id":%q,"name":"peer-%s","hostname":"host-%s","ip":"100.90.0.%d","dns_label":"peer-%s.netbird.cloud","connected":%t,"last_seen":"2026-11-04T10:00:00Z",
		"os":"Linux 6.1","version":"0.30.1","groups":[{"id":"g1","name":"All"},{"id":"g2","name":"servers"}],"ssh_enabled":true,"login_expiration_enabled":false,
		"inactivity_expiration_enabled":false,"login_expired":false,"approval_required":%t,"user_id":"google-oauth2|LEAKME","city_name":"LEAKME","serial_number":"LEAKME","accessible_peers_count":3}`,
		id, id, id, len(id), id, id == "cabc1", f.waiting[id])
}

func (f *fakeNetBird) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token nbp_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"token invalid","code":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/peers":
		fmt.Fprintf(w, `[%s,%s]`, f.peer("cabc1"), f.peer("cdef2"))
	case "GET /api/peers/cabc1", "GET /api/peers/cdef2":
		io.WriteString(w, f.peer(strings.TrimPrefix(r.URL.Path, "/api/peers/")))
	case "PUT /api/peers/cabc1", "PUT /api/peers/cdef2":
		id := strings.TrimPrefix(r.URL.Path, "/api/peers/")
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastBody = b
		if !f.ignore {
			f.waiting[id] = b["approval_required"] == true
		}
		io.WriteString(w, f.peer(id))
	case "GET /api/groups":
		io.WriteString(w, `[{"id":"g1","name":"All","peers_count":2,"resources_count":0,"issued":"api","peers":[{"id":"cabc1","name":"peer-cabc1"}]},{"id":"g2","name":"servers","peers_count":1,"issued":"jwt"}]`)
	case "GET /api/policies":
		io.WriteString(w, `[{"id":"p1","name":"Default","description":"all to all","enabled":true,"rules":[{"name":"Default","enabled":true,"action":"accept","bidirectional":true,"protocol":"tcp","ports":["22"],"port_ranges":[{"start":8000,"end":8080}],"sources":[{"id":"g1","name":"All"}],"destinations":[{"id":"g2","name":"servers"}]}]}]`)
	case "GET /api/routes":
		io.WriteString(w, `[{"id":"r1","network_id":"office","description":"LAN","enabled":true,"peer":"cabc1","network":"192.168.1.0/24","metric":9999,"masquerade":true,"groups":["g1"],"keep_route":true}]`)
	case "GET /api/setup-keys":
		io.WriteString(w, `[{"id":"k1","key":"A616B1C3-LEAKME-KEY","name":"servers","type":"reusable","valid":true,"revoked":false,"state":"valid","expires":"2027-01-01T00:00:00Z","used_times":4,"usage_limit":0,"last_used":"2026-10-01T00:00:00Z","ephemeral":false,"auto_groups":["g2"]}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found","code":404}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNetBird) {
	f := &fakeNetBird{waiting: map[string]bool{"cabc1": false, "cdef2": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nb": "nbp_good", "secret://bad": "nbp_bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNetBird(t *testing.T) {
	m, f := setup(t, "secret://nb")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "2 peers, 1 connected, 1 waiting for approval" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"peers", `{}`, `"version":"0.30.1"`},
		{"peers", `{}`, `"groups":["All","servers"]`},
		{"peers", `{"connected":true}`, `"connected":true`},
		{"groups", `{}`, `"issued":"jwt"`},
		{"policies", `{}`, `"ports":["22","8000-8080"]`},
		{"policies", `{}`, `"destinations":["servers"]`},
		{"routes", `{}`, `"peer":"peer-cabc1"`},
		{"routes", `{}`, `"distributionGroups":["All"]`},
		{"setup_keys", `{}`, `"autoGroups":["servers"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "peers", `{"connected":true}`, false); strings.Contains(string(r.Output), "cdef2") {
		t.Fatal(string(r.Output))
	}

	// Approve the waiting peer: preview, real, undo.
	r, err := invoke(m, "approve_peer", `{"peer":"cdef2"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Approve peer-cdef2" || !f.waiting["cdef2"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "approve_peer", `{"peer":"cdef2"}`, false)
	if err != nil || f.waiting["cdef2"] || r.Undo == nil || r.Undo.Action != "disable_peer" || string(r.Undo.Input) != `{"peer":"cdef2"}` {
		t.Fatalf("%+v %v", r, err)
	}
	// The update sends the peer's other settings back unchanged.
	if f.lastBody["name"] != "peer-cdef2" || f.lastBody["ssh_enabled"] != true || f.lastBody["inactivity_expiration_enabled"] != false {
		t.Fatal(f.lastBody)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.waiting["cdef2"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "disable_peer", `{"peer":"cdef2"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	f.ignore = true
	if _, err := invoke(m, "disable_peer", `{"peer":"cabc1"}`, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "approve_peer", `{"peer":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no peer") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_peer") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestNetBirdValidation(t *testing.T) {
	m, f := setup(t, "secret://nb")
	for _, in := range []string{`{}`, `{"peer":"../users"}`, `{"peer":"a b"}`, `{"peer":"x?y=1"}`} {
		if _, err := invoke(m, "approve_peer", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "nbp_plain"}, {URL: "netbird.example.com", Token: "secret://nb"}, {URL: "https://nb.example.com/?x=1", Token: "secret://nb"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "NetBird refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestNetBirdRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://nb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nb": "nbp_good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
