package flagsmith

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

type fakeFlagsmith struct {
	mu        sync.Mutex
	seen      []string
	patches   []string
	on        bool // new_checkout in Production
	versioned bool
}

const feat = `{"id":31,"name":"new_checkout","type":"STANDARD","description":"New checkout","default_enabled":false,"initial_value":"LEAKME-config","tags":[1],"is_archived":false}`

func (f *fakeFlagsmith) states() string {
	return fmt.Sprintf(`{"count":3,"next":null,"results":[
		{"id":501,"feature":31,"enabled":%t,"feature_state_value":"LEAKME-value","identity":null,"feature_segment":null,"updated_at":"2026-11-04T10:00:00Z"},
		{"id":502,"feature":31,"enabled":true,"feature_state_value":null,"identity":null,"feature_segment":9},
		{"id":503,"feature":31,"enabled":true,"identity":{"id":4,"identifier":"leakme@example.com"},"feature_segment":null}]}`, f.on)
}

func (f *fakeFlagsmith) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Api-Key fs_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid API Key"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/projects/":
		io.WriteString(w, `[{"id":7,"name":"Web","organisation":2}]`)
	case "GET /api/v1/environments/":
		if r.URL.Query().Get("project") != "7" {
			io.WriteString(w, `{"count":0,"next":null,"results":[]}`)
			return
		}
		fmt.Fprintf(w, `{"count":2,"next":null,"results":[{"id":11,"name":"Development","api_key":"LEAKMEdevkey","project":7},{"id":12,"name":"Production","description":"live","api_key":"LEAKMEprodkey","project":7,"use_v2_feature_versioning":%t}]}`, f.versioned)
	case "GET /api/v1/projects/7/features/":
		fmt.Fprintf(w, `{"count":1,"next":null,"results":[%s]}`, feat)
	case "GET /api/v1/projects/7/features/31/":
		io.WriteString(w, feat)
	case "GET /api/v1/environments/LEAKMEprodkey/featurestates/":
		io.WriteString(w, f.states())
	case "PATCH /api/v1/environments/LEAKMEprodkey/featurestates/501/":
		f.patches = append(f.patches, string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		f.on = in["enabled"] == true
		fmt.Fprintf(w, `{"id":501,"feature":31,"enabled":%t,"identity":null,"feature_segment":null}`, f.on)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeFlagsmith) {
	f := &fakeFlagsmith{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fs": "fs_good", "secret://bad": "fs_bad"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFlagsmith(t *testing.T) {
	m, f := setup(t, "secret://fs")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "1 projects" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"organisation":2`},
		{"environments", `{"project":7}`, `"name":"Production"`},
		{"flags", `{"project":"7"}`, `"name":"new_checkout"`},
		{"flags", `{"project":7,"environment":"production"}`, `"segmentOverrides":1`},
		{"flags", `{"project":7,"environment":12}`, `"enabled":false`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(strings.ToLower(out), "leakme") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	in := `{"project":7,"environment":"Production","flag":"new_checkout"}`
	r, err := invoke(m, "turn_on", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "new_checkout on in Production (project 7)") || f.on || len(f.patches) != 0 ||
		string(r.Plan.Changes[0].Before) != `{"enabled":false}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "turn_on", in, false)
	if err != nil || !f.on || f.patches[0] != `{"enabled":true}` || r.Undo == nil || r.Undo.Action != "turn_off" ||
		string(r.Undo.Input) != `{"environment":"12","flag":"31","project":"7"}` || strings.Contains(strings.ToLower(string(r.Output)), "leakme") {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "turn_on", in, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.on {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"project":7,"environment":"Staging","flag":"new_checkout"}`, false); err == nil || !strings.Contains(err.Error(), "Development, Production") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"project":7,"environment":"Production","flag":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no flag nope") {
		t.Fatal(err)
	}
	f.versioned = true
	for _, dry := range []bool{true, false} {
		if r, err := invoke(m, "turn_on", in, dry); err == nil || !strings.Contains(err.Error(), "versioning") || f.on || r.Plan != nil {
			t.Fatal(dry, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "turn_") && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestFlagsmithValidation(t *testing.T) {
	m, f := setup(t, "secret://fs")
	for _, c := range []struct{ action, in string }{
		{"turn_on", `{"environment":"Production","flag":"x"}`},
		{"turn_on", `{"project":"7/../8","environment":"Production","flag":"x"}`},
		{"turn_on", `{"project":7,"flag":"x"}`},
		{"turn_on", `{"project":7,"environment":"Production"}`},
		{"turn_off", `{"project":7,"environment":"Production","flag":"../x"}`},
		{"turn_off", `{"project":7,"environment":"Production","flag":"a b"}`},
		{"turn_off", `{"project":7,"environment":"Prod\nuction","flag":"x"}`},
		{"environments", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{APIKey: "fs_plain"}, {URL: "flagsmith.example.com", APIKey: "secret://fs"}, {URL: "https://fs.example.com/?x=1", APIKey: "secret://fs"},
		{URL: "https://u:p@fs.example.com", APIKey: "secret://fs"}, {URL: "https://fs.example.com/#a", APIKey: "secret://fs"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || h.Message != "Flagsmith refused the API key" {
		t.Fatalf("%+v", h)
	}
}

// The environment key is in the request path, which a transport error
// quotes and a server may echo; neither reaches the error.
func TestFlagsmithHidesEnvironmentKeyInErrors(t *testing.T) {
	m, f := setup(t, "secret://fs")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/featurestates/") {
			if r.Method == http.MethodPatch {
				w.WriteHeader(400)
				io.WriteString(w, `{"detail":"bad request for /environments/LEAKMEprodkey/featurestates/501/"}`)
				return
			}
			if r.URL.Query().Get("feature") == "" {
				// Drop the connection: Go's error quotes the URL.
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://fs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fs": "fs_good"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ action, in string }{
		{"flags", `{"project":7,"environment":"Production"}`},
		{"turn_on", `{"project":7,"environment":"Production","flag":"new_checkout"}`},
	} {
		_, err := invoke(m, c.action, c.in, false)
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "leakme") {
			t.Fatalf("%s: %v", c.action, err)
		}
	}
}

func TestFlagsmithRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://fs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fs": "fs_good"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
