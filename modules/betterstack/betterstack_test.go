package betterstack

import (
	"context"
	"encoding/json"
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
	mu        sync.Mutex
	seen      []string
	acked     map[string]string
	resolved  map[string]string
	noV3      bool
	pageCalls int
}

func (f *fake) incident(id string) map[string]any {
	a := map[string]any{"name": "API down", "url": "https://api.example.com/health?key=s3cr3t", "cause": "Status 503", "started_at": "2026-11-04T10:00:00Z", "status": "Started", "team_name": "Ops", "acknowledged_by": "ana@example.com"}
	if id == "8" {
		a["name"], a["resolved_at"], a["status"] = "Old", "2026-11-01T00:00:00Z", "Resolved"
	}
	if by, ok := f.acked[id]; ok {
		a["acknowledged_at"], a["acknowledged_by"] = "2026-11-04T10:05:00Z", by
	}
	if by, ok := f.resolved[id]; ok {
		a["resolved_at"], a["resolved_by"] = "2026-11-04T10:10:00Z", by
	}
	return map[string]any{"id": id, "type": "incident", "attributes": a}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer bstok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":"Invalid Team API token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	path := r.URL.Path
	if f.noV3 && strings.HasPrefix(path, "/v3/") {
		w.WriteHeader(404)
		return
	}
	switch {
	case r.Method == "GET" && path == "/v2/monitors":
		f.pageCalls++
		if r.URL.Query().Get("page") == "2" {
			io.WriteString(w, `{"data":[{"id":"3","type":"monitor","attributes":{"url":"https://hb.example","pronounceable_name":"Nightly job","monitor_type":"heartbeat","status":"paused","check_frequency":3600}}],"pagination":{"next":null}}`)
			return
		}
		io.WriteString(w, `{"data":[{"id":"1","type":"monitor","attributes":{"url":"https://u:p@shop.example.com/?t=1","pronounceable_name":"Shop","monitor_type":"status","status":"up","last_checked_at":"2026-11-04T11:59:00Z","check_frequency":30}},{"id":"2","type":"monitor","attributes":{"url":"https://api.example.com","pronounceable_name":"","monitor_type":"keyword","status":"down","check_frequency":60}}],"pagination":{"next":"https://uptime.betterstack.com/api/v2/monitors?page=2"}}`)
	case r.Method == "GET" && (path == "/v3/incidents" || path == "/v2/incidents"):
		var data []any
		for _, id := range []string{"7", "8"} {
			if r.URL.Query().Get("resolved") == "false" && id == "8" {
				continue
			}
			data = append(data, f.incident(id))
		}
		enc.Encode(map[string]any{"data": data, "pagination": map[string]any{"next": nil}})
	case r.Method == "GET" && (path == "/v3/incidents/7" || path == "/v2/incidents/7" || path == "/v3/incidents/8" || path == "/v2/incidents/8"):
		enc.Encode(map[string]any{"data": f.incident(path[len(path)-1:])})
	case r.Method == "POST" && path == "/v2/incidents/7/acknowledge":
		var b map[string]string
		json.Unmarshal(body, &b)
		f.acked["7"] = b["acknowledged_by"]
		enc.Encode(map[string]any{"data": f.incident("7")})
	case r.Method == "POST" && path == "/v2/incidents/7/resolve":
		var b map[string]string
		json.Unmarshal(body, &b)
		f.resolved["7"] = b["resolved_by"]
		enc.Encode(map[string]any{"data": f.incident("7")})
	case r.Method == "GET" && path == "/v2/on-calls":
		io.WriteString(w, `{"data":[{"id":"55","type":"on_call_calendar","attributes":{"name":null,"default_calendar":true},"relationships":{"on_call_users":{"data":[{"id":"9","type":"user"}]}}}],"included":[{"id":"9","type":"user","attributes":{"first_name":"Ana","last_name":"Lima","email":"ana@example.com","phone_numbers":["+15550100"]}}]}`)
	case r.Method == "GET" && path == "/v2/status-pages":
		io.WriteString(w, `{"data":[{"id":"4","type":"status_page","attributes":{"company_name":"Example","subdomain":"example","custom_domain":"status.example.com","aggregate_state":"degraded"}}],"pagination":{"next":null}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":"Resource not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{acked: map[string]string{}, resolved: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bs": "bstok", "secret://bad": "nope"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBetterStackReads(t *testing.T) {
	m, f := setup(t, "secret://bs")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"monitors", `{}`, `"byStatus":{"down":1,"paused":1,"up":1}`},
		{"monitors", `{"status":"down"}`, `"name":"https://api.example.com"`},
		{"incidents", `{}`, `"acknowledged":false`},
		{"incidents", `{"includeResolved":true,"days":30}`, `"name":"Old"`},
		{"on_call", `{}`, `"onCall":[{"email":"ana@example.com","name":"Ana Lima"}]`},
		{"status_pages", `{}`, `"address":"https://status.example.com"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"u:p@", "t=1", "s3cr3t", "+1555", "hb.example"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %s: %s", c.action, leak, out)
			}
		}
		if c.action == "incidents" && strings.Contains(out, "ana@") {
			t.Fatalf("incidents carry who acknowledged: %s", out)
		}
	}
	r, _ := invoke(m, "incidents", `{}`, false)
	if strings.Contains(string(r.Output), "Old") {
		t.Fatalf("resolved incident listed: %s", r.Output)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "/v3/incidents?") && strings.Contains(s, "resolved=false") && !strings.Contains(s, "from=2026-10-28") {
			t.Fatal(s)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "on_call" && !a.Sensitive {
			t.Fatal("on_call returns names and emails: it must be sensitive")
		}
	}
}

func TestBetterStackIncidents(t *testing.T) {
	m, f := setup(t, "secret://bs")
	r, err := invoke(m, "acknowledge_incident", `{"incident":"7","by":"ops@example.com"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Acknowledge incident API down") || len(f.acked) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "acknowledge_incident", `{"incident":"7","by":"ops@example.com"}`, false); err != nil || f.acked["7"] != "ops@example.com" {
		t.Fatalf("%v %v", err, f.acked)
	}
	if r, err := invoke(m, "acknowledge_incident", `{"incident":"7"}`, false); err != nil || !strings.Contains(string(r.Output), "already acknowledged") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "resolve_incident", `{"incident":"7"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "still failing") || len(f.resolved) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "resolve_incident", `{"incident":"7"}`, false); err != nil || f.resolved["7"] != "Conduit" {
		t.Fatalf("%v %v", err, f.resolved)
	}
	if r, err := invoke(m, "resolve_incident", `{"incident":"8"}`, false); err != nil || !strings.Contains(string(r.Output), "already resolved") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "resolve_incident", `{"incident":"99"}`, false); err == nil || !strings.Contains(err.Error(), "no incident 99") {
		t.Fatal(err)
	}
	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["resolve_incident"] != sdk.RiskDestructive || risks["acknowledge_incident"] != sdk.RiskWrite {
		t.Fatalf("%v", risks)
	}
}

func TestBetterStackV2Fallback(t *testing.T) {
	m, f := setup(t, "secret://bs")
	f.noV3 = true
	if r, err := invoke(m, "incidents", `{}`, false); err != nil || !strings.Contains(string(r.Output), "API down") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "acknowledge_incident", `{"incident":"7"}`, false); err != nil || f.acked["7"] != "Conduit" {
		t.Fatal(err)
	}
}

func TestBetterStackValidation(t *testing.T) {
	m, f := setup(t, "secret://bs")
	for _, c := range []struct{ action, in string }{
		{"monitors", `{"status":"broken"}`},
		{"incidents", `{"days":365}`},
		{"incidents", `{"limit":0.5}`},
		{"incidents", `{"limit":500}`},
		{"acknowledge_incident", `{"incident":"../monitors"}`},
		{"acknowledge_incident", `{"incident":"7/resolve"}`},
		{"acknowledge_incident", `{}`},
		{"resolve_incident", `{"incident":"7","by":"a\nb"}`},
		{"resolve_incident", `{"incident":"7","by":"` + strings.Repeat("x", 101) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	raw, _ := json.Marshal(Config{Token: "plaintoken"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "Better Stack refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestBetterStackRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://bs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bs": "bstok"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
