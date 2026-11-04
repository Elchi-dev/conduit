package unleash

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

type fakeUnleash struct {
	mu     sync.Mutex
	seen   []string
	ignore bool            // answer the on and off endpoints without changing anything
	on     map[string]bool // environment -> enabled, for feature new-checkout
}

func (f *fakeUnleash) feature(name string) string {
	return fmt.Sprintf(`{"name":%q,"type":"release","project":"default","stale":false,"description":"New checkout","lastSeenAt":"2026-11-04T10:00:00Z","environments":[
		{"name":"development","type":"development","enabled":%t,"strategies":[]},
		{"name":"production","type":"production","enabled":%t,"strategies":[
			{"name":"flexibleRollout","title":"Beta","disabled":false,"parameters":{"rollout":"25","stickiness":"default","groupId":"new-checkout"},
			 "constraints":[{"contextName":"email","operator":"IN","values":["leakme@example.com","other@example.com"],"inverted":false}],"segments":[1],"variants":[]},
			{"name":"userWithId","parameters":{"userIds":"LEAKME-user-1,LEAKME-user-2"},"constraints":[]}]}]}`, name, f.on["development"], f.on["production"])
}

func (f *fakeUnleash) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "user:good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"name":"AuthenticationRequired","message":"You must log in to use Unleash."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET /prefix/api/admin/projects":
		io.WriteString(w, `{"version":1,"projects":[{"id":"default","name":"Default","description":"Default project","health":95,"featureCount":2,"memberCount":3,"mode":"open"}]}`)
	case "GET /prefix/api/admin/projects/default/features":
		fmt.Fprintf(w, `{"version":2,"features":[%s]}`, f.feature("new-checkout"))
	case "GET /prefix/api/admin/projects/default/features/new-checkout":
		io.WriteString(w, f.feature("new-checkout"))
	case "GET /prefix/api/admin/projects/default/features/other":
		io.WriteString(w, f.feature("new-checkout")) // answers with another feature
	case "POST /prefix/api/admin/projects/default/features/new-checkout/environments/production/on":
		if !f.ignore {
			f.on["production"] = true
		}
	case "POST /prefix/api/admin/projects/default/features/new-checkout/environments/production/off":
		if !f.ignore {
			f.on["production"] = false
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"name":"NotFoundError","message":"Could not find feature"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeUnleash) {
	f := &fakeUnleash{on: map[string]bool{"development": true, "production": false}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/prefix/api/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://un": "user:good", "secret://bad": "user:bad"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestUnleash(t *testing.T) {
	m, f := setup(t, "secret://un")
	if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "1 projects, 2 features" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"health":95`},
		{"features", `{}`, `"enabled":{"development":true,"production":false}`},
		{"strategies", `{"feature":"new-checkout"}`, `"constraints":[{"context":"email","inverted":false,"operator":"IN","values":2}]`},
		{"strategies", `{"feature":"new-checkout","environment":"production"}`, `"otherParameters":["userIds"]`},
		{"strategies", `{"feature":"new-checkout"}`, `"rollout":"25"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "leakme") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	in := `{"feature":"new-checkout","environment":"production"}`
	r, err := invoke(m, "turn_on", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "new-checkout on in production (project default)") || f.on["production"] ||
		string(r.Plan.Changes[0].Before) != `{"enabled":false}` || string(r.Plan.Changes[0].After) != `{"enabled":true}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "turn_on", in, false)
	if err != nil || !f.on["production"] || r.Undo == nil || r.Undo.Action != "turn_off" || string(r.Undo.Input) != `{"environment":"production","feature":"new-checkout","project":"default"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "turn_on", in, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.on["production"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "turn_on", in, true); err != nil || strings.Contains(r.Plan.Summary, "default strategy") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	f.ignore = true
	if _, err := invoke(m, "turn_on", in, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	f.ignore = false
	f.on["development"] = false
	if r, err := invoke(m, "turn_on", `{"feature":"new-checkout","environment":"development"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "default strategy") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "turn_on", `{"feature":"new-checkout","environment":"staging"}`, false); err == nil || !strings.Contains(err.Error(), "development, production") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "turn_on", `{"feature":"nope","environment":"production"}`, false); err == nil || !strings.Contains(err.Error(), "no feature nope") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "turn_") && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestUnleashValidation(t *testing.T) {
	m, f := setup(t, "secret://un")
	for _, c := range []struct{ action, in string }{
		{"turn_on", `{"environment":"production"}`},
		{"turn_on", `{"feature":"new-checkout"}`},
		{"turn_off", `{"feature":"../users","environment":"production"}`},
		{"turn_off", `{"feature":"a b","environment":"production"}`},
		{"turn_on", `{"feature":"x","environment":"prod?x=1"}`},
		{"features", `{"project":"a/b"}`},
		{"strategies", `{"feature":"x%2f"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The feature changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "turn_on", `{"feature":"other","environment":"production"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another feature: %v %v", err, f.seen)
	}
	for _, c := range []Config{{URL: "https://unleash.example.com", Token: "user:plain"}, {Token: "secret://un"}, {URL: "unleash.example.com", Token: "secret://un"},
		{URL: "https://unleash.example.com/?x=1", Token: "secret://un"}, {URL: "https://u:p@unleash.example.com", Token: "secret://un"}, {URL: "https://unleash.example.com/#x", Token: "secret://un"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "u"); h.Status != "down" || h.Message != "Unleash refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestUnleashRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://un"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://un": "user:good"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "u"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
