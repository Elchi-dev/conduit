package launchdarkly

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

type fakeLD struct {
	mu      sync.Mutex
	seen    []string
	patches []string
	on      bool // new-checkout in production
	version int
	ignore  bool
}

func (f *fakeLD) flag(key string) string {
	return fmt.Sprintf(`{"key":%q,"name":"New checkout","kind":"boolean","temporary":true,"tags":["web"],
		"variations":[{"value":true,"name":"Enabled"},{"value":{"secret":"LEAKME"}}],
		"environments":{"production":{"on":%t,"_version":%d,"lastModified":1762250000000,"offVariation":1,"_site":{"href":"/x"},
			"targets":[{"values":["leakme-user-1","leakme-user-2"],"variation":0}],
			"contextTargets":[{"contextKind":"org","values":["leakme-org"],"variation":0}],
			"rules":[{"clauses":[{"attribute":"email","op":"in","values":["leakme@example.com"]}],"variation":0}],
			"fallthrough":{"rollout":{"variations":[{"variation":0,"weight":25000}]}},"prerequisites":[]}}}`, key, f.on, f.version)
}

func (f *fakeLD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "api-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"unauthorized","message":"Invalid account ID header"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/projects":
		io.WriteString(w, `{"items":[{"key":"default","name":"Default","tags":["main"]}],"totalCount":1}`)
	case "GET /api/v2/projects/default/environments":
		io.WriteString(w, `{"items":[{"key":"production","name":"Production","color":"417505","apiKey":"sdk-LEAKME","mobileKey":"mob-LEAKME","_id":"LEAKME-client-id","critical":true,"requireComments":true,"confirmChanges":false,"tags":[],"approvalSettings":{"required":false}}]}`)
	case "GET /api/v2/flags/default":
		if r.URL.Query().Get("env") != "production" || r.URL.Query().Get("summary") != "true" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"items":[%s]}`, f.flag("new-checkout"))
	case "GET /api/v2/flags/default/new-checkout":
		io.WriteString(w, f.flag("new-checkout"))
	case "GET /api/v2/flags/default/other":
		io.WriteString(w, f.flag("new-checkout")) // answers with another flag
	case "PATCH /api/v2/flags/default/new-checkout":
		if r.Header.Get("Content-Type") != "application/json; domain-model=launchdarkly.semanticpatch" {
			w.WriteHeader(400)
			io.WriteString(w, `{"message":"expected a semantic patch"}`)
			return
		}
		f.patches = append(f.patches, string(body))
		var in struct {
			Env          string `json:"environmentKey"`
			Instructions []struct {
				Kind string `json:"kind"`
			} `json:"instructions"`
		}
		json.Unmarshal(body, &in)
		if in.Env == "production" && len(in.Instructions) == 1 && !f.ignore {
			f.on = in.Instructions[0].Kind == "turnFlagOn"
			f.version++
		}
		io.WriteString(w, f.flag("new-checkout"))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"not_found","message":"Unknown resource"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeLD) {
	f := &fakeLD{version: 7}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ld": "api-good", "secret://bad": "api-bad"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLaunchDarkly(t *testing.T) {
	m, f := setup(t, "secret://ld")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "1 projects" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"key":"default"`},
		{"environments", `{"project":"default"}`, `"critical":true`},
		{"flags", `{"project":"default","environment":"production"}`, `"on":false`},
		{"flag", `{"project":"default","environment":"production","flag":"new-checkout"}`, `"individualTargets":3`},
		{"flag", `{"project":"default","environment":"production","flag":"new-checkout"}`, `"rules":[{"clauses":1,"rollout":false}]`},
		{"flag", `{"project":"default","environment":"production","flag":"new-checkout"}`, `"offVariation":"variation 1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(strings.ToLower(out), "leakme") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	in := `{"project":"default","environment":"production","flag":"new-checkout"}`
	r, err := invoke(m, "turn_on", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "new-checkout on in production (project default)") || f.on ||
		string(r.Plan.Changes[0].Before) != `{"on":false,"version":7}` || len(f.patches) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "turn_on", `{"project":"default","environment":"production","flag":"new-checkout","comment":"launch"}`, false)
	if err != nil || !f.on || r.Undo == nil || r.Undo.Action != "turn_off" || string(r.Undo.Input) != `{"environment":"production","flag":"new-checkout","project":"default"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if f.patches[0] != `{"comment":"launch","environmentKey":"production","instructions":[{"kind":"turnFlagOn"}]}` {
		t.Fatal(f.patches[0])
	}
	if r, err := invoke(m, "turn_on", in, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.on || !strings.Contains(f.patches[1], "turnFlagOff") || !strings.Contains(f.patches[1], `"comment":"Turned off through Conduit"`) {
		t.Fatal(err, f.patches)
	}
	f.ignore = true
	if _, err := invoke(m, "turn_on", in, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"project":"default","environment":"staging","flag":"new-checkout"}`, false); err == nil || !strings.Contains(err.Error(), "no environment staging") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"project":"default","environment":"production","flag":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no flag nope") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "turn_") && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestLaunchDarklyValidation(t *testing.T) {
	m, f := setup(t, "secret://ld")
	for _, c := range []struct{ action, in string }{
		{"turn_on", `{"environment":"production","flag":"x"}`},
		{"turn_on", `{"project":"default","flag":"x"}`},
		{"turn_on", `{"project":"default","environment":"production"}`},
		{"turn_off", `{"project":"default","environment":"production","flag":"../x"}`},
		{"turn_off", `{"project":"de fault","environment":"production","flag":"x"}`},
		{"turn_off", `{"project":"default","environment":"prod?x=1","flag":"x"}`},
		{"turn_off", `{"project":"default","environment":"production","flag":"x","comment":"` + strings.Repeat("a", 501) + `"}`},
		{"environments", `{}`},
		{"flags", `{"project":"default"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "turn_on", `{"project":"default","environment":"production","flag":"other"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another flag: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "api-plain"}, {Token: "secret://ld", Region: "https://evil.example.com"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || h.Message != "LaunchDarkly refused the API access token" {
		t.Fatalf("%+v", h)
	}
}

func TestLaunchDarklyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://ld"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ld": "api-good"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
