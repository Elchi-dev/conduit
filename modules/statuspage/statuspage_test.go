package statuspage

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

type fake struct {
	mu       sync.Mutex
	seen     []string
	comp     map[string]string
	incident string // status of incident inc1
	lastBody map[string]any
}

func (f *fake) components() string {
	return fmt.Sprintf(`[{"id":"grp1","name":"Backend","status":"operational","group":true},{"id":"api1","name":"API","status":%q,"group_id":"grp1","group":false},{"id":"web1","name":"Website","status":%q,"group":false}]`, f.comp["api1"], f.comp["web1"])
}

func (f *fake) inc() string {
	return fmt.Sprintf(`{"id":"inc1","name":"Slow API","status":%q,"impact":"minor","shortlink":"https://stspg.io/abc","created_at":"2026-11-04T10:00:00Z","updated_at":"2026-11-04T10:05:00Z","resolved_at":null,
		"components":[{"id":"api1","name":"API","status":%q}],"incident_updates":[{"status":%q,"body":"We are looking into it.","created_at":"2026-11-04T10:05:00Z"}]}`, f.incident, f.comp["api1"], f.incident)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "OAuth spkey-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Could not authenticate"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /pages":
		io.WriteString(w, `[{"id":"pg1","name":"Example","subdomain":"example","domain":"status.example.com","page_description":"x"}]`)
	case "GET /pages/pg1":
		io.WriteString(w, `{"id":"pg1","name":"Example","subdomain":"example","domain":"status.example.com"}`)
	case "GET /pages/pg1/components":
		io.WriteString(w, f.components())
	case "GET /pages/pg1/components/api1", "GET /pages/pg1/components/web1":
		id := strings.TrimPrefix(r.URL.Path, "/pages/pg1/components/")
		fmt.Fprintf(w, `{"id":%q,"name":"C-%s","status":%q,"group":false}`, id, id, f.comp[id])
	case "GET /pages/pg1/components/grp1":
		io.WriteString(w, `{"id":"grp1","name":"Backend","status":"operational","group":true}`)
	case "PATCH /pages/pg1/components/api1", "PATCH /pages/pg1/components/web1":
		id := strings.TrimPrefix(r.URL.Path, "/pages/pg1/components/")
		f.comp[id] = b["component"].(map[string]any)["status"].(string)
		fmt.Fprintf(w, `{"id":%q,"name":"C-%s","status":%q}`, id, id, f.comp[id])
	case "GET /pages/pg1/incidents", "GET /pages/pg1/incidents/unresolved":
		fmt.Fprintf(w, `[%s]`, f.inc())
	case "GET /pages/pg1/incidents/inc1":
		io.WriteString(w, f.inc())
	case "POST /pages/pg1/incidents":
		f.lastBody = b["incident"].(map[string]any)
		f.incident = f.lastBody["status"].(string)
		io.WriteString(w, f.inc())
	case "PATCH /pages/pg1/incidents/inc1":
		f.lastBody = b["incident"].(map[string]any)
		if s, ok := f.lastBody["status"].(string); ok {
			f.incident = s
		}
		io.WriteString(w, f.inc())
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{comp: map[string]string{"api1": "operational", "web1": "operational"}, incident: "investigating"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sp": "spkey-good", "secret://bad": "spkey-bad"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestStatuspageReads(t *testing.T) {
	m, _ := setup(t, "secret://sp")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "1 page(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"pages", `{}`, `"address":"https://status.example.com"`},
		{"components", `{"page":"pg1"}`, `"group":"Backend"`},
		{"components", `{"page":"pg1"}`, `"isGroup":true`},
		{"incidents", `{"page":"pg1"}`, `"body":"We are looking into it."`},
		{"incidents", `{"page":"pg1","unresolved":true}`, `"impact":"minor"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "spkey") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
}

func TestStatuspageChanges(t *testing.T) {
	m, f := setup(t, "secret://sp")

	// Posting: the preview shows the exact text and that nobody is notified.
	in := `{"page":"pg1","name":"Slow API","body":"Requests take over 2s.\nWe're on it.","impact":"minor","components":{"api1":"degraded_performance"}}`
	r, err := invoke(m, "create_incident", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "not notified") || !strings.Contains(r.Plan.Summary, "status.example.com") ||
		!strings.Contains(string(r.Plan.Changes[0].After), `Requests take over 2s.\nWe're on it.`) || !strings.Contains(string(r.Plan.Changes[0].After), `API: operational → degraded_performance`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("the preview changed something: %s", s)
		}
	}
	r, err = invoke(m, "create_incident", in, false)
	if err != nil || f.lastBody["deliver_notifications"] != false || f.lastBody["body"] != "Requests take over 2s.\nWe're on it." || f.lastBody["impact_override"] != "minor" {
		t.Fatalf("%v %v", f.lastBody, err)
	}
	if comps, _ := f.lastBody["components"].(map[string]any); comps["api1"] != "degraded_performance" {
		t.Fatal(f.lastBody)
	}
	// Notifications only when asked.
	r, err = invoke(m, "update_incident", `{"page":"pg1","incident":"inc1","status":"monitoring","body":"Fixed, watching.","notify":true}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "subscribers are notified") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err = invoke(m, "update_incident", `{"page":"pg1","incident":"inc1","status":"monitoring","body":"Fixed, watching.","notify":true}`, false); err != nil || f.lastBody["deliver_notifications"] != true || f.incident != "monitoring" {
		t.Fatalf("%v %v", f.lastBody, err)
	}
	n := len(f.seen)
	if r, err := invoke(m, "update_incident", `{"page":"pg1","incident":"inc1","status":"monitoring"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, s := range f.seen[n:] {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("no-op wrote: %s", s)
		}
	}

	// Component status: preview, change, undo, no-op.
	r, err = invoke(m, "set_component_status", `{"page":"pg1","component":"web1","status":"major_outage"}`, true)
	if err != nil || r.Plan == nil || f.comp["web1"] != "operational" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_component_status", `{"page":"pg1","component":"web1","status":"major_outage"}`, false)
	if err != nil || f.comp["web1"] != "major_outage" || r.Undo == nil || r.Undo.Action != "set_component_status" || string(r.Undo.Input) != `{"component":"web1","page":"pg1","status":"operational"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.comp["web1"] != "operational" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "set_component_status", `{"page":"pg1","component":"web1","status":"operational"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "set_component_status", `{"page":"pg1","component":"grp1","status":"major_outage"}`, false); err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s: anything public is destructive", a.Name, a.Risk)
		}
	}
}

func TestStatuspageValidation(t *testing.T) {
	m, f := setup(t, "secret://sp")
	for _, c := range []struct{ action, in string }{
		{"components", `{}`},
		{"components", `{"page":"../pages"}`},
		{"incidents", `{"page":"pg1","limit":500}`},
		{"create_incident", `{"page":"pg1"}`},
		{"create_incident", `{"page":"pg1","name":"<script>x</script>"}`},
		{"create_incident", `{"page":"pg1","name":"ok","body":"a <b>bold</b> claim"}`},
		{"create_incident", `{"page":"pg1","name":"line\u0000break"}`},
		{"create_incident", `{"page":"pg1","name":"ok","status":"fixed"}`},
		{"create_incident", `{"page":"pg1","name":"ok","impact":"huge"}`},
		{"create_incident", `{"page":"pg1","name":"ok","components":{"api1":"broken"}}`},
		{"create_incident", `{"page":"pg1","name":"ok","components":{"a/b":"major_outage"}}`},
		{"update_incident", `{"page":"pg1","incident":"inc1"}`},
		{"update_incident", `{"page":"pg1","incident":"x?y=1","status":"resolved"}`},
		{"set_component_status", `{"page":"pg1","component":"web1","status":"down"}`},
		{"set_component_status", `{"page":"pg1","component":"web 1","status":"major_outage"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"spkey-plain"}`, `{}`, `{"token":5}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Statuspage refused the API key" || strings.Contains(h.Message, "spkey") {
		t.Fatalf("%+v", h)
	}
}

func TestStatuspageRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://sp"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sp": "spkey-good"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
