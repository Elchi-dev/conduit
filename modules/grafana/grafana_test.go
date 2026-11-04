package grafana

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

type fakeGrafana struct {
	mu       sync.Mutex
	seen     []string
	silences map[string]string // id -> state
	annots   map[string]bool
}

func (f *fakeGrafana) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer gtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"invalid API key"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	am := "/grafana" + amPath
	switch r.Method + " " + r.URL.Path {
	case "GET /grafana/api/org":
		io.WriteString(w, `{"id":1,"name":"Main Org."}`)
	case "GET /grafana/api/health":
		io.WriteString(w, `{"database":"ok","version":"11.3.0"}`)
	case "GET /grafana/api/search":
		if r.URL.Query().Get("type") != "dash-db" || r.URL.Query().Get("query") != "node" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"uid":"abc","title":"Node exporter","url":"/grafana/d/abc/node","folderTitle":"Infra","tags":["linux"]}]`)
	case "GET /grafana/api/prometheus/grafana/api/v1/rules":
		io.WriteString(w, `{"status":"success","data":{"groups":[{"name":"hosts","file":"Infra","rules":[
			{"uid":"r1","name":"High CPU","state":"firing","health":"ok","labels":{"severity":"page"},"alerts":[{"state":"Alerting"}]},
			{"uid":"r2","name":"Disk","state":"inactive","health":"ok","alerts":[]}]}]}}`)
	case "GET " + am + "/alerts":
		if r.URL.Query().Get("active") != "true" || r.URL.Query().Get("silenced") != "false" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"labels":{"alertname":"High CPU","instance":"web-1"},"annotations":{"summary":"CPU at 98%"},"startsAt":"2026-11-04T10:00:00Z","fingerprint":"f1","status":{"state":"active"}}]`)
	case "GET " + am + "/silences":
		io.WriteString(w, `[{"id":"s-old","status":{"state":"expired"},"matchers":[]},{"id":"s-1","status":{"state":"`+f.silences["s-1"]+`"},"matchers":[{"name":"alertname","value":"High CPU","isRegex":false,"isEqual":true}],"endsAt":"2026-11-04T14:00:00Z","comment":"maint"}]`)
	case "POST " + am + "/silences":
		f.silences["s-1"] = "active"
		io.WriteString(w, `{"silenceID":"s-1"}`)
	case "GET " + am + "/silence/s-1":
		io.WriteString(w, `{"id":"s-1","status":{"state":"`+f.silences["s-1"]+`"},"matchers":[{"name":"alertname","value":"High CPU","isRegex":false,"isEqual":true}],"startsAt":"2026-11-04T12:00:00Z","endsAt":"2026-11-04T14:00:00Z","comment":"maint"}`)
	case "DELETE " + am + "/silence/s-1":
		f.silences["s-1"] = "expired"
		io.WriteString(w, `{}`)
	case "POST /grafana/api/annotations":
		f.annots["7"] = true
		io.WriteString(w, `{"id":7,"message":"Annotation added"}`)
	case "DELETE /grafana/api/annotations/7":
		delete(f.annots, "7")
		io.WriteString(w, `{"message":"Annotation deleted"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGrafana) {
	f := &fakeGrafana{silences: map[string]string{}, annots: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/grafana/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://g": "gtok", "secret://bad": "x"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGrafana(t *testing.T) {
	m, f := setup(t, "secret://g")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "organization Main Org. · Grafana 11.3.0" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "dashboards", `{"query":"node"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"url":"http://127.0.0.1`) || !strings.Contains(string(r.Output), `/grafana/d/abc/node"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "alert_rules", `{"state":"firing"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"High CPU"`) || strings.Contains(string(r.Output), "Disk") || !strings.Contains(string(r.Output), `"activeAlerts":1`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "alerts", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"summary":"CPU at 98%"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	in := `{"matchers":[{"name":"alertname","value":"High CPU"}],"comment":"maint","durationMinutes":120}`
	r, err = invoke(m, "create_silence", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Silence alerts matching alertname="High CPU" for 2h0m0s` || f.silences["s-1"] != "" {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_silence", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "expire_silence" || f.silences["s-1"] != "active" {
		t.Fatalf("%+v %v", r, err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.Contains(last, `"endsAt":"2026-11-04T14:00:00Z"`) || !strings.Contains(last, `"isEqual":true`) {
		t.Fatal(last)
	}
	if r, err := invoke(m, "silences", `{}`, false); err != nil || strings.Contains(string(r.Output), "s-old") || !strings.Contains(string(r.Output), "s-1") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || f.silences["s-1"] != "active" {
		t.Fatalf("dry %+v %v", p, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.silences["s-1"] != "expired" || r.Undo == nil || r.Undo.Action != "create_silence" || !strings.Contains(string(r.Undo.Input), `"durationMinutes":120`) {
		t.Fatalf("expire %+v %v", r, err)
	}
	if _, err := invoke(m, "expire_silence", `{"id":"s-1"}`, false); err == nil || !strings.Contains(err.Error(), "already expired") {
		t.Fatal(err)
	}

	r, err = invoke(m, "annotate", `{"text":"deploy v2","tags":["deploy"],"dashboardUID":"abc","panelId":3}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_annotation" || !f.annots["7"] {
		t.Fatalf("%+v %v", r, err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.Contains(last, `"dashboardUID":"abc"`) || !strings.Contains(last, `"panelId":3`) || !strings.Contains(last, `"time":1793793600000`) {
		t.Fatal(last)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || !f.annots["7"] {
		t.Fatalf("dry %+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.annots["7"] {
		t.Fatal("annotation not deleted", err)
	}
}

func TestGrafanaValidation(t *testing.T) {
	m, f := setup(t, "secret://g")
	for _, c := range []struct{ action, in string }{
		{"expire_silence", `{"id":"../../api/admin"}`},
		{"expire_silence", `{"id":"a/b"}`},
		{"expire_silence", `{}`},
		{"delete_annotation", `{"id":0}`},
		{"delete_annotation", `{"id":"7/../x"}`},
		{"annotate", `{"text":"x","dashboardUID":"a/../b"}`},
		{"annotate", `{"text":"x","panelId":2}`},
		{"annotate", `{"text":" "}`},
		{"create_silence", `{"matchers":[],"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"("," isRegex":true}],"comment":""}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"(","isRegex":true}],"comment":"x"}`},
		{"create_silence", `{"matchers":[{"name":"a","value":"b"}],"comment":"x","durationMinutes":99999}`},
		{"alert_rules", `{"state":"weird"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://grafana", Token: "plain"}, {URL: "grafana.example.com", Token: "secret://g"}, {URL: "https://u:p@grafana", Token: "secret://g"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not be followed.
func TestGrafanaRefusesCrossHostRedirect(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://g"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://g": "gtok"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked {
		t.Fatalf("followed the redirect: %+v %v", h, leaked)
	}
}
