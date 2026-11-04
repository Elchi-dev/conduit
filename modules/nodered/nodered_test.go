package nodered

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

type fakeRED struct {
	mu       sync.Mutex
	seen     []string
	disabled map[string]bool
	logins   int
	lastPut  map[string]any
	ignore   bool
	noAuth   bool
}

func (f *fakeRED) flow(id string) string {
	return fmt.Sprintf(`{"id":%q,"label":"Lights %s","disabled":%t,"info":"LEAKME notes","nodes":[{"id":"n1","type":"mqtt out","z":%q,"broker":"b1"},{"id":"n2","type":"http request","z":%q,"url":"https://api.example.com/?key=LEAKME"}],"configs":[{"id":"b1","type":"mqtt-broker","broker":"mqtt.local","credentials":{"user":"LEAKME"}}]}`,
		id, id, f.disabled[id], id, id)
}

func (f *fakeRED) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if r.URL.Path == "/admin/auth/token" && r.Method == "POST" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if b["username"] != "admin" || b["password"] != "red-good" || b["client_id"] != "node-red-admin" || b["grant_type"] != "password" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"unauthorized","message":"bad password red-bad"}`)
			return
		}
		f.logins++
		fmt.Fprintf(w, `{"access_token":"tok%d-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_in":604800,"token_type":"Bearer"}`, f.logins)
		return
	}
	if !f.noAuth && !strings.HasPrefix(r.Header.Get("Authorization"), fmt.Sprintf("Bearer tok%d-", f.logins)) || f.logins == 0 && !f.noAuth {
		w.WriteHeader(401)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /admin/settings":
		io.WriteString(w, `{"httpNodeRoot":"/","version":"4.0.5","user":{"username":"admin","permissions":"*"}}`)
	case "GET /admin/flows":
		fmt.Fprintf(w, `[{"id":"t1","type":"tab","label":"Lights","disabled":%t,"info":"LEAKME"},{"id":"t2","type":"tab","label":"Garden","disabled":%t},
			{"id":"s1","type":"subflow","name":"Debounce","info":"x"},{"id":"n1","type":"inject","z":"t1","payload":"LEAKME"},{"id":"n2","type":"mqtt out","z":"t1"},
			{"id":"n3","type":"function","z":"s1","func":"LEAKME"},{"id":"b1","type":"mqtt-broker","broker":"mqtt.local","credentials":{"password":"LEAKME"}}]`, f.disabled["t1"], f.disabled["t2"])
	case "GET /admin/nodes":
		io.WriteString(w, `[{"id":"node-red/inject","name":"inject","types":["inject"],"enabled":true,"module":"node-red","version":"4.0.5"},
			{"id":"node-red/mqtt","name":"mqtt","types":["mqtt in","mqtt out","mqtt-broker"],"enabled":true,"module":"node-red","version":"4.0.5"},
			{"id":"node-red-contrib-x/x","name":"x","types":["x"],"enabled":false,"module":"node-red-contrib-x","version":"1.0.0","err":"token=abcdefghijklmnop failed"}]`)
	case "GET /admin/flow/t1", "GET /admin/flow/t2":
		io.WriteString(w, f.flow(strings.TrimPrefix(r.URL.Path, "/admin/flow/")))
	case "GET /admin/flow/t9":
		io.WriteString(w, f.flow("t1"))
	case "PUT /admin/flow/t1", "PUT /admin/flow/t2":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastPut = b
		if !f.ignore {
			f.disabled[b["id"].(string)] = b["disabled"] == true
		}
		io.WriteString(w, `{"id":"t1"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"not_found","message":"Not Found"}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeRED) {
	f := &fakeRED{disabled: map[string]bool{"t2": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/admin/", Username: "admin", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nr": "red-good", "secret://bad": "red-bad"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNodeRED(t *testing.T) {
	m, f := setup(t, "secret://nr")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "Node-RED 4.0.5, 2 flows, 1 disabled" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"flows", `{}`, `{"disabled":false,"id":"t1","name":"Lights","nodes":2}`},
		{"flows", `{}`, `"subflows":[{"id":"s1","name":"Debounce","nodes":1}]`},
		{"flows", `{}`, `"configNodes":1`},
		{"nodes", `{}`, `"types":["inject","mqtt in","mqtt out","mqtt-broker"]`},
		{"nodes", `{"search":"contrib"}`, `"enabled":false`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "abcdefghijklmnop") || strings.Contains(out, "mqtt.local") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}

	// Disable: preview, real (the flow goes back whole), undo.
	r, err := invoke(m, "disable_flow", `{"flow":"t1"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable the flow Lights t1 (2 nodes); the automations it runs stop" || f.disabled["t1"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if b, _ := json.Marshal(r.Plan); strings.Contains(string(b), "LEAKME") || strings.Contains(string(b), "mqtt") {
		t.Fatal(string(b))
	}
	r, err = invoke(m, "disable_flow", `{"flow":"t1"}`, false)
	if err != nil || !f.disabled["t1"] || r.Undo == nil || r.Undo.Action != "enable_flow" || string(r.Undo.Input) != `{"flow":"t1"}` || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%+v %v", r, err)
	}
	if nodes, _ := f.lastPut["nodes"].([]any); len(nodes) != 2 || f.lastPut["info"] != "LEAKME notes" {
		t.Fatalf("the flow didn't go back whole: %v", f.lastPut)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.disabled["t1"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "enable_flow", `{"flow":"t1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	f.ignore = true
	if _, err := invoke(m, "enable_flow", `{"flow":"t2"}`, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "disable_flow", `{"flow":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no flow") {
		t.Fatal(err)
	}
	// An expired session is renewed once.
	f.logins++
	if _, err := invoke(m, "flows", `{}`, false); err != nil || f.logins != 3 {
		t.Fatalf("%v %d", err, f.logins)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "disable_flow" && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Risk)
		}
	}
}

func TestNodeREDValidation(t *testing.T) {
	m, f := setup(t, "secret://nr")
	for _, in := range []string{`{}`, `{"flow":"../flows"}`, `{"flow":"a b"}`, `{"flow":"x?y=1"}`, `{"flow":"global"}`, `{"flow":"t1/../t2"}`} {
		if _, err := invoke(m, "disable_flow", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The flow changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "disable_flow", `{"flow":"t9"}`, false); err == nil || f.lastPut != nil {
		t.Fatalf("changed another flow: %v %v", err, f.seen)
	}
	for _, c := range []Config{
		{URL: "http://nr.local", Username: "admin", Password: "plain"},
		{URL: "http://nr.local", Token: "plain"},
		{URL: "http://nr.local", Username: "admin"},
		{URL: "http://nr.local", Username: "admin", Password: "secret://nr", Token: "secret://t"},
		{URL: "nr.local"},
		{URL: "http://u:p@nr.local"},
		{URL: "http://nr.local/?x=1"},
		{URL: "http://nr.local", InsecureSkipVerify: true},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "r")
	if h.Status != "down" || h.Message != "Node-RED refused the username or password" {
		t.Fatalf("%+v", h)
	}
}

func TestNodeREDNoAuth(t *testing.T) {
	f := &fakeRED{disabled: map[string]bool{}, noAuth: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/admin"})
	if err := m.Configure(context.Background(), fakehost.New(nil), "r", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
}

func TestNodeREDRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://nr"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nr": "red-good"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
