package datadog

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

const dtID = "00000000-0000-1234-0000-000000000001"

type fake struct {
	mu        sync.Mutex
	seen      []string
	downtimes map[string]string // id -> status
	events    []string
	created   []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("DD-API-KEY") != "apikey" {
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":["Forbidden"]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.URL.Path != "/api/v1/validate" && r.Header.Get("DD-APPLICATION-KEY") != "appkey" {
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":["Forbidden"]}`)
		return
	}
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/validate":
		io.WriteString(w, `{"valid":true}`)
	case "GET /api/v1/monitor":
		io.WriteString(w, `[{"id":42,"name":"API latency","type":"metric alert","overall_state":"Alert","tags":["team:web"],"priority":2,"matching_downtimes":[{"id":1,"active":true,"scope":["host:a"]}]}]`)
	case "GET /api/v1/monitor/42":
		io.WriteString(w, `{"id":42,"name":"API latency","type":"metric alert","overall_state":"Alert","query":"avg(last_5m):avg:latency{*} > 1","state":{"groups":{"host:web-1":{"status":"Alert","last_triggered_ts":1700000000}}}}`)
	case "GET /api/v1/monitor/search":
		if !strings.Contains(r.URL.Query().Get("query"), "status:(alert") {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"monitors":[{"id":42,"name":"API latency","status":"Alert","type":"metric alert","last_triggered_ts":1700000000}]}`)
	case "POST /api/v2/downtime":
		f.created = append(f.created, string(body))
		f.downtimes[dtID] = "active"
		io.WriteString(w, `{"data":{"id":"`+dtID+`","type":"downtime"}}`)
	case "GET /api/v2/downtime":
		var data []any
		for id, st := range f.downtimes {
			data = append(data, map[string]any{"id": id, "attributes": map[string]any{"scope": "host:web-1", "status": st, "monitor_identifier": map[string]any{"monitor_id": 42}}})
		}
		data = append(data, map[string]any{"id": "00000000-0000-1234-0000-000000000009", "attributes": map[string]any{"scope": "*", "status": "active", "monitor_identifier": map[string]any{"monitor_tags": []string{"x"}}}})
		enc.Encode(map[string]any{"data": data})
	case "GET /api/v2/downtime/" + dtID:
		enc.Encode(map[string]any{"data": map[string]any{"id": dtID, "attributes": map[string]any{"scope": "host:web-1", "status": f.downtimes[dtID]}}})
	case "DELETE /api/v2/downtime/" + dtID:
		f.downtimes[dtID] = "canceled"
		w.WriteHeader(204)
	case "GET /api/v2/incidents":
		io.WriteString(w, `{"data":[{"id":"inc-1","attributes":{"public_id":7,"title":"Checkout down","severity":"SEV-1","state":"active","customer_impacted":true}}]}`)
	case "POST /api/v1/events":
		f.events = append(f.events, string(body))
		io.WriteString(w, `{"status":"ok","event":{"id":123,"url":"https://app.datadoghq.eu/event/event?id=123"}}`)
	case "GET /api/v1/dashboard":
		io.WriteString(w, `{"dashboards":[{"id":"abc-def-ghi","title":"Web overview","url":"/dashboard/abc-def-ghi/web","author_handle":"ana@example.com"},{"id":"x","title":"Billing"}]}`)
	case "GET /api/v1/slo/search":
		io.WriteString(w, `{"data":{"attributes":{"slos":[{"data":{"id":"slo1","attributes":{"name":"API availability","slo_type":"metric","overall_status":[{"timeframe":"30d","target":99.9,"status":99.95,"error_budget_remaining":50.1,"state":"ok"}]}}}]}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":["Not found"]}`)
	}
}

func setup(t *testing.T, apiKey string) (*Module, *fake) {
	f := &fake{downtimes: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Site: "datadoghq.eu", APIKey: apiKey, AppKey: "secret://app"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://api": "apikey", "secret://app": "appkey", "secret://bad": "nope"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDatadogReads(t *testing.T) {
	m, _ := setup(t, "secret://api")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "connected to datadoghq.eu" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"monitors", `{"tags":["team:web"]}`, `"muted":true`},
		{"monitor", `{"id":42}`, `"group":"host:web-1","lastTriggered":"2023-11-14T22:13:20Z","status":"Alert"`},
		{"triggered_monitors", `{}`, `"status":"Alert"`},
		{"incidents", `{}`, `"severity":"SEV-1"`},
		{"dashboards", `{"search":"web"}`, `"url":"https://app.datadoghq.eu/dashboard/abc-def-ghi/web"`},
		{"slos", `{"search":"service:api"}`, `"errorBudgetRemaining":50.1`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "ana@example.com") || strings.Contains(string(r.Output), "Billing") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestDatadogMute(t *testing.T) {
	m, f := setup(t, "secret://api")
	r, err := invoke(m, "mute_monitor", `{"id":42,"scope":"host:web-1","minutes":30}`, true)
	if err != nil || r.Plan == nil || len(f.created) != 0 || !strings.Contains(r.Plan.Summary, "until 2026-11-04T10:30:00Z") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "mute_monitor", `{"id":42,"scope":"host:web-1","minutes":30}`, false)
	if err != nil || len(f.created) != 1 || r.Undo == nil || r.Undo.Action != "unmute_monitor" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.created[0], `"monitor_identifier":{"monitor_id":42}`) || !strings.Contains(f.created[0], `"scope":"host:web-1"`) || !strings.Contains(f.created[0], `"end":"2026-11-04T10:30:00Z"`) {
		t.Fatal(f.created[0])
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || f.downtimes[dtID] != "active" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.downtimes[dtID] != "canceled" {
		t.Fatal(err)
	}
	// Unmute by monitor finds only downtimes that name it.
	f.downtimes[dtID] = "active"
	p, err := invoke(m, "unmute_monitor", `{"id":42}`, true)
	if err != nil || len(p.Plan.Changes) != 1 || p.Plan.Changes[0].Target != "downtime "+dtID {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "unmute_monitor", `{"id":42}`, false); err != nil || f.downtimes[dtID] != "canceled" {
		t.Fatal(err)
	}
	// Whole monitor only when asked for explicitly.
	if _, err := invoke(m, "mute_monitor", `{"id":42,"allGroups":true}`, false); err != nil || !strings.Contains(f.created[1], `"monitor_id":42`) {
		t.Fatal(err)
	}
}

func TestDatadogEvent(t *testing.T) {
	m, f := setup(t, "secret://api")
	in := `{"title":"Deploy web v42","text":"Rolled out","alertType":"success","tags":["env:prod","service:web"]}`
	if r, err := invoke(m, "post_event", in, true); err != nil || r.Plan == nil || len(f.events) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "post_event", in, false); err != nil || len(f.events) != 1 || !strings.Contains(string(r.Output), `"event":123`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.events[0], `"alert_type":"success"`) || !strings.Contains(f.events[0], `"tags":["env:prod","service:web"]`) {
		t.Fatal(f.events[0])
	}
}

func TestDatadogValidation(t *testing.T) {
	m, f := setup(t, "secret://api")
	for _, c := range []struct{ action, in string }{
		{"monitor", `{"id":0}`},
		{"monitors", `{"tags":["a b"]}`},
		{"mute_monitor", `{"scope":"*","allGroups":true}`},
		{"mute_monitor", `{"id":42,"scope":"*"}`},
		{"mute_monitor", `{"id":42,"scope":"host:web-*"}`},
		{"mute_monitor", `{"id":42}`},
		{"mute_monitor", `{"id":42,"scope":"host:a","allGroups":true}`},
		{"mute_monitor", `{"id":42,"scope":"host:a","minutes":20000}`},
		{"mute_monitor", `{"id":42,"scope":"host:a\nx"}`},
		{"unmute_monitor", `{}`},
		{"unmute_monitor", `{"downtime":"../downtime"}`},
		{"post_event", `{"title":"","text":"x"}`},
		{"post_event", `{"title":"x","text":"y","alertType":"panic"}`},
		{"post_event", `{"title":"x","text":"y","tags":["bad tag"]}`},
		{"slos", `{"search":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Site: "datadoghq.com", APIKey: "plain", AppKey: "secret://app"}, {Site: "datadoghq.com", APIKey: "secret://api", AppKey: "plain"}, {Site: "evil.example.com", APIKey: "secret://api", AppKey: "secret://app"}, {Site: "datadoghq.com.evil.com", APIKey: "secret://api", AppKey: "secret://app"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Site: "https://app.datadoghq.eu", APIKey: "secret://api", AppKey: "secret://app"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
}

func TestDatadogRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("DD-API-KEY") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Site: "datadoghq.com", APIKey: "secret://api", AppKey: "secret://app"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://api": "apikey", "secret://app": "appkey"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
