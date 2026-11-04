package instatus

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

type fake struct {
	mu       sync.Mutex
	seen     []string
	comp     map[string]string
	status   string
	lastBody map[string]any
}

func (f *fake) inc() string {
	return fmt.Sprintf(`{"id":"inc1","name":"Slow API","status":%q,"started":"2026-11-04T10:00:00Z","resolved":null,
		"components":[{"id":"api1","name":"API","status":%q}],"updates":[{"message":"Looking.","status":"INVESTIGATING","createdAt":"2026-11-04T10:00:00Z"},{"message":"Found it.","status":%q,"createdAt":"2026-11-04T10:05:00Z"}]}`, f.status, f.comp["api1"], f.status)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer isk-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/pages":
		io.WriteString(w, `[{"id":"pg1","name":"Example","subdomain":"example","customDomain":null,"status":"HASISSUES","publicEmail":"ops@example.com"}]`)
	case "GET /v1/pg1/components":
		fmt.Fprintf(w, `[{"id":"api1","name":"API","status":%q,"group":{"id":"g1","name":"Backend"}},{"id":"web1","name":"Website","status":%q,"group":null}]`, f.comp["api1"], f.comp["web1"])
	case "GET /v1/pg1/incidents":
		fmt.Fprintf(w, `[%s,{"id":"old","name":"Old","status":"RESOLVED","started":"2026-10-01T00:00:00Z","resolved":"2026-10-01T01:00:00Z"}]`, f.inc())
	case "GET /v1/pg1/incidents/inc1":
		io.WriteString(w, f.inc())
	case "POST /v1/pg1/incidents", "POST /v1/pg1/incidents/inc1/incident-updates":
		f.lastBody = b
		f.status = b["status"].(string)
		for _, s := range b["statuses"].([]any) {
			m := s.(map[string]any)
			f.comp[m["id"].(string)] = m["status"].(string)
		}
		io.WriteString(w, f.inc())
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{comp: map[string]string{"api1": "OPERATIONAL", "web1": "OPERATIONAL"}, status: "INVESTIGATING"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://is": "isk-good", "secret://bad": "isk-bad"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestInstatusReads(t *testing.T) {
	m, _ := setup(t, "secret://is")
	if h := m.Health(context.Background(), "i"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"pages", `{}`, `"address":"https://example.instatus.com"`},
		{"components", `{"page":"pg1"}`, `"group":"Backend"`},
		{"incidents", `{"page":"pg1"}`, `"message":"Found it."`},
		{"incidents", `{"page":"pg1"}`, `"resolved":"2026-10-01T01:00:00Z"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := string(r.Output); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "isk-") || strings.Contains(out, "ops@example.com") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "incidents", `{"page":"pg1","unresolved":true}`, false); strings.Contains(string(r.Output), `"old"`) {
		t.Fatal(string(r.Output))
	}
}

func TestInstatusChanges(t *testing.T) {
	m, f := setup(t, "secret://is")
	in := `{"page":"pg1","name":"Slow API","message":"Latency over 2s.\nInvestigating.","components":{"api1":"DEGRADEDPERFORMANCE"}}`
	r, err := invoke(m, "create_incident", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "not notified") || !strings.Contains(r.Plan.Summary, "example.instatus.com") ||
		!strings.Contains(string(r.Plan.Changes[0].After), `Latency over 2s.\nInvestigating.`) || !strings.Contains(string(r.Plan.Changes[0].After), "API: OPERATIONAL → DEGRADEDPERFORMANCE") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("the preview changed something: %s", s)
		}
	}
	if _, err := invoke(m, "create_incident", in, false); err != nil || f.lastBody["notify"] != false || f.lastBody["message"] != "Latency over 2s.\nInvestigating." || f.lastBody["started"] != "2026-11-04T12:00:00Z" || f.comp["api1"] != "DEGRADEDPERFORMANCE" {
		t.Fatalf("%v %v", f.lastBody, err)
	}
	// An update keeps the incident's components and changes what's asked.
	up := `{"page":"pg1","incident":"inc1","status":"RESOLVED","message":"Fixed.","components":{"api1":"OPERATIONAL"},"notify":true}`
	if r, err := invoke(m, "update_incident", up, true); err != nil || !strings.Contains(r.Plan.Summary, "subscribers are notified") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "update_incident", up, false); err != nil || f.lastBody["notify"] != true || f.status != "RESOLVED" || f.comp["api1"] != "OPERATIONAL" {
		t.Fatalf("%v %v", f.lastBody, err)
	}
	n := len(f.seen)
	if r, err := invoke(m, "update_incident", `{"page":"pg1","incident":"inc1","status":"RESOLVED"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "update_incident", `{"page":"pg1","incident":"inc1","status":"MONITORING"}`, false); err == nil || !strings.Contains(err.Error(), "message") {
		t.Fatal(err)
	}
	for _, s := range f.seen[n:] {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("wrote: %s", s)
		}
	}
	if _, err := invoke(m, "create_incident", `{"page":"pg1","name":"x","message":"y","components":{"nope1":"MAJOROUTAGE"}}`, false); err == nil || !strings.Contains(err.Error(), "no component") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestInstatusValidation(t *testing.T) {
	m, f := setup(t, "secret://is")
	for _, c := range []struct{ action, in string }{
		{"components", `{}`},
		{"components", `{"page":"../v2"}`},
		{"incidents", `{"page":"pg1","limit":0.5}`},
		{"incidents", `{"page":"pg1","limit":101}`},
		{"create_incident", `{"page":"pg1","name":"x","components":{"api1":"MAJOROUTAGE"}}`},
		{"create_incident", `{"page":"pg1","name":"x","message":"y"}`},
		{"create_incident", `{"page":"pg1","name":"<img src=x>","message":"y","components":{"api1":"MAJOROUTAGE"}}`},
		{"create_incident", `{"page":"pg1","name":"x","message":"y","components":{"api1":"down"}}`},
		{"create_incident", `{"page":"pg1","name":"x","message":"y","status":"open","components":{"api1":"MAJOROUTAGE"}}`},
		{"update_incident", `{"page":"pg1","incident":"inc1"}`},
		{"update_incident", `{"page":"pg1","incident":"a/b","message":"x"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"isk-plain"}`, `{}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "i"); h.Status != "down" || h.Message != "Instatus refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestInstatusRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://is"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://is": "isk-good"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "i"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
