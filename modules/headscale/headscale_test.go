package headscale

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeHeadscale answers like Headscale 0.26 (routes on the node), or like
// 0.23-0.25 (a routes API, pre-auth keys by user name) when old is set.
type fakeHeadscale struct {
	old bool

	mu       sync.Mutex
	seen     []string
	names    map[string]string
	approved map[string][]string
	enabled  map[string]bool // old API: route id → enabled
}

func (f *fakeHeadscale) node(id string) string {
	routes := ""
	if !f.old {
		appr, _ := json.Marshal(f.approved[id])
		avail := `[]`
		if id == "1" {
			avail = `["10.0.0.0/24","0.0.0.0/0","::/0"]`
		}
		routes = fmt.Sprintf(`,"approvedRoutes":%s,"availableRoutes":%s,"subnetRoutes":%s`, appr, avail, appr)
	}
	return fmt.Sprintf(`{"id":%q,"machineKey":"mkey:LEAKME","nodeKey":"nodekey:LEAKME","name":"host-%s","givenName":%q,"user":{"id":"1","name":"alice","email":"alice@example.com"},
		"ipAddresses":["100.64.0.%s"],"lastSeen":"2026-11-04T10:00:00Z","expiry":%q,"online":%t,"forcedTags":["tag:server"],
		"preAuthKey":{"key":"LEAKME-preauth"},"createdAt":"2026-01-01T00:00:00Z"%s}`,
		id, id, f.names[id], id, map[string]string{"1": "0001-01-01T00:00:00Z", "2": "2026-01-01T00:00:00Z"}[id], id == "1", routes)
}

func (f *fakeHeadscale) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer hkey" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	p := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == "GET" && p == "/node":
		fmt.Fprintf(w, `{"nodes":[%s,%s]}`, f.node("1"), f.node("2"))
	case r.Method == "GET" && (p == "/node/1" || p == "/node/2"):
		fmt.Fprintf(w, `{"node":%s}`, f.node(p[6:]))
	case r.Method == "GET" && p == "/node/3": // answers with another node
		fmt.Fprintf(w, `{"node":%s}`, f.node("1"))
	case r.Method == "GET" && p == "/user":
		io.WriteString(w, `{"users":[{"id":"1","name":"alice","displayName":"Alice","email":"alice@example.com","profilePicUrl":"https://x/LEAKME","createdAt":"2026-01-01T00:00:00Z","provider":"oidc"}]}`)
	case r.Method == "GET" && p == "/preauthkey":
		want := "1"
		if f.old {
			want = "alice"
		}
		if r.URL.Query().Get("user") != want {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":3,"message":"invalid user"}`)
			return
		}
		io.WriteString(w, `{"preAuthKeys":[{"user":{"id":"1","name":"alice"},"id":"5","key":"LEAKME-key","reusable":true,"ephemeral":false,"used":false,"expiration":"2026-01-02T00:00:00Z","createdAt":"2026-01-01T00:00:00Z","aclTags":["tag:ci"]}]}`)
	case r.Method == "POST" && strings.HasPrefix(p, "/node/1/rename/"):
		f.names["1"] = strings.TrimPrefix(p, "/node/1/rename/")
		fmt.Fprintf(w, `{"node":%s}`, f.node("1"))
	case r.Method == "POST" && p == "/node/2/expire":
		fmt.Fprintf(w, `{"node":%s}`, f.node("2"))
	case r.Method == "POST" && p == "/node/1/approve_routes" && !f.old:
		var b struct {
			Routes []string `json:"routes"`
		}
		json.Unmarshal(body, &b)
		f.approved["1"] = b.Routes
		fmt.Fprintf(w, `{"node":%s}`, f.node("1"))
	case r.Method == "GET" && p == "/routes" && f.old:
		var rs []string
		for i, pf := range []string{"10.0.0.0/24", "0.0.0.0/0", "::/0"} {
			id := fmt.Sprint(i + 1)
			rs = append(rs, fmt.Sprintf(`{"id":%q,"node":{"id":"1","givenName":"one"},"prefix":%q,"advertised":true,"enabled":%t,"isPrimary":%t}`, id, pf, f.enabled[id], f.enabled[id]))
		}
		fmt.Fprintf(w, `{"routes":[%s]}`, strings.Join(rs, ","))
	case r.Method == "POST" && f.old && strings.HasPrefix(p, "/routes/"):
		parts := strings.Split(p, "/") // "", routes, id, enable|disable
		f.enabled[parts[2]] = parts[3] == "enable"
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":5,"message":"Not Found"}`)
	}
}

func setup(t *testing.T, key string, old bool) (*Module, *fakeHeadscale) {
	f := &fakeHeadscale{old: old, names: map[string]string{"1": "one", "2": "two"}, approved: map[string][]string{"1": {}}, enabled: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://h": "hkey", "secret://bad": "nope"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHeadscale(t *testing.T) {
	m, f := setup(t, "secret://h", false)
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "2 nodes, 1 online" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"nodes", `"online":true`},
		{"nodes", `"keyExpires":"never"`},
		{"nodes", `"expired":true`},
		{"nodes", `"advertisedRoutes":["10.0.0.0/24","0.0.0.0/0","::/0"]`},
		{"users", `"nodes":2`},
		{"users", `"displayName":"Alice"`},
		{"routes", `"route":"0.0.0.0/0"`},
		{"preauth_keys", `"reusable":true`},
		{"preauth_keys", `"expired":true`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "@example.com") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Rename: preview, real, undo.
	r, err := invoke(m, "rename_node", `{"node":"1","name":"nas"}`, true)
	if err != nil || r.Plan == nil || f.names["1"] != "one" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "rename_node", `{"node":"1","name":"nas"}`, false)
	if err != nil || f.names["1"] != "nas" || r.Undo == nil || string(r.Undo.Input) != `{"name":"one","node":"1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.names["1"] != "one" {
		t.Fatal(err, f.names)
	}

	// Expire.
	r, err = invoke(m, "expire_node", `{"node":"2"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "two") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "expire_node", `{"node":"2"}`, false); err != nil || !strings.HasPrefix(f.seen[len(f.seen)-1], "POST /api/v1/node/2/expire") {
		t.Fatal(err, f.seen)
	}

	// An exit route is approved and withdrawn as a pair; undo reverses it.
	r, err = invoke(m, "enable_route", `{"node":"1","route":"0.0.0.0/0"}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || len(f.approved["1"]) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "enable_route", `{"node":"1","route":"0.0.0.0/0"}`, false)
	if err != nil || strings.Join(f.approved["1"], ",") != "0.0.0.0/0,::/0" || r.Undo == nil || r.Undo.Action != "disable_route" {
		t.Fatalf("%+v %v %v", r, err, f.approved)
	}
	if _, err := invoke(m, "enable_route", `{"node":"1","route":"10.0.0.0/24"}`, false); err != nil || len(f.approved["1"]) != 3 {
		t.Fatal(err, f.approved)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || strings.Join(f.approved["1"], ",") != "10.0.0.0/24" {
		t.Fatal(err, f.approved)
	}
	if r, err := invoke(m, "disable_route", `{"node":"1","route":"0.0.0.0/0"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "enable_route", `{"node":"1","route":"192.168.9.0/24"}`, false); err == nil || !strings.Contains(err.Error(), "doesn't advertise") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rename_node", `{"node":"9","name":"x"}`, false); err == nil || !strings.Contains(err.Error(), "no node") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (strings.HasSuffix(a.Name, "_route") || a.Name == "expire_node") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestHeadscaleOldRoutesAPI(t *testing.T) {
	m, f := setup(t, "secret://h", true)
	if r, err := invoke(m, "routes", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"route":"10.0.0.0/24"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "preauth_keys", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"id":"5"`) {
		t.Fatalf("by name: %s %v", r.Output, err)
	}
	r, err := invoke(m, "enable_route", `{"node":"1","route":"::/0"}`, false)
	if err != nil || !f.enabled["2"] || !f.enabled["3"] || f.enabled["1"] {
		t.Fatalf("%v %v", err, f.enabled)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.enabled["2"] || f.enabled["3"] {
		t.Fatalf("%v %v", err, f.enabled)
	}
}

func TestHeadscaleValidation(t *testing.T) {
	m, f := setup(t, "secret://h", false)
	for _, c := range []struct{ action, in string }{
		{"expire_node", `{}`},
		{"expire_node", `{"node":"1/../../apikey"}`},
		{"rename_node", `{"node":"1","name":"Bad Name"}`},
		{"rename_node", `{"node":"1","name":"x/../../apikey/expire"}`},
		{"rename_node", `{"node":"1","name":"-dash"}`},
		{"enable_route", `{"node":"1","route":"10.0.0.1/24"}`},
		{"enable_route", `{"node":"1","route":"not-a-route"}`},
		{"disable_route", `{"node":"1"}`},
		{"nodes", `{"user":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://hs.example.com", APIKey: "plain-key"}, {URL: "hs.example.com", APIKey: "secret://h"}, {URL: "https://u:p@hs.example.com", APIKey: "secret://h"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// The node acted on is the one asked for, whatever the server answers.
	if _, err := invoke(m, "expire_node", `{"node":"3"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("acted on another node: %v %v", err, f.seen)
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || h.Message != "Headscale refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestHeadscaleRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://h"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://h": "hkey"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
