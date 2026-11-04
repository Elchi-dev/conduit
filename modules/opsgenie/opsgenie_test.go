package opsgenie

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

const alertID = "70413a06-38d6-4c85-92b8-5ebc900d42e2-1568289498744"

type fake struct {
	mu     sync.Mutex
	seen   []string
	acked  bool
	closed bool
	bodies []map[string]string
}

func (f *fake) alert() string {
	status := "open"
	if f.closed {
		status = "closed"
	}
	return fmt.Sprintf(`{"id":%q,"tinyId":"42","alias":"db","message":"DB down token=abcdef1234567890abcdef","status":%q,"acknowledged":%t,"snoozed":false,"count":3,"priority":"P1",
		"tags":["db"],"createdAt":"2026-11-04T10:00:00Z","updatedAt":"2026-11-04T10:05:00Z","lastOccurredAt":"2026-11-04T10:04:00Z","owner":"ana@example.com","source":"ana@example.com",
		"description":"Primary is unreachable","details":{"host":"db-1"},"integration":{"name":"Prometheus","type":"Prometheus"},"report":{"ackTime":60000,"acknowledgedBy":"ana@example.com"}}`, alertID, status, f.acked)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "GenieKey og-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Key format is not valid!","took":0.0,"requestId":"r0"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/alerts/count":
		io.WriteString(w, `{"data":{"count":2}}`)
	case "GET /v2/alerts":
		if q.Get("query") != "status:open AND priority:P1" && q.Get("query") != "status:open" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"data":[%s]}`, f.alert())
	case "GET /v2/alerts/" + alertID, "GET /v2/alerts/42":
		if (strings.HasSuffix(r.URL.Path, "/42") && q.Get("identifierType") != "tiny") || (strings.HasSuffix(r.URL.Path, alertID) && q.Get("identifierType") != "id") {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"data":%s}`, f.alert())
	case "GET /v2/alerts/7": // answers with another alert
		fmt.Fprintf(w, `{"data":%s}`, f.alert())
	case "POST /v2/alerts/" + alertID + "/acknowledge", "POST /v2/alerts/" + alertID + "/unacknowledge", "POST /v2/alerts/" + alertID + "/close", "POST /v2/alerts/" + alertID + "/notes":
		var b map[string]string
		json.Unmarshal(body, &b)
		f.bodies = append(f.bodies, b)
		switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
		case "acknowledge":
			f.acked = true
		case "unacknowledge":
			f.acked = false
		case "close":
			f.closed = true
		}
		w.WriteHeader(202)
		io.WriteString(w, `{"result":"Request will be processed","took":0.1,"requestId":"req-1"}`)
	case "GET /v2/schedules":
		io.WriteString(w, `{"data":[{"id":"s-1","name":"Primary","timezone":"Europe/Berlin","enabled":true,"ownerTeam":{"id":"t1","name":"Ops"}},{"id":"s-2","name":"Off","enabled":false}]}`)
	case "GET /v2/schedules/s-1/on-calls":
		if q.Get("flat") != "true" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"data":{"_parent":{"id":"s-1","name":"Primary","enabled":true},"onCallRecipients":["ana@example.com"]}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok, Region: "eu"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://og": "og-good", "secret://bad": "og-bad"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOpsgenieReads(t *testing.T) {
	m, _ := setup(t, "secret://og")
	if h := m.Health(context.Background(), "o"); h.Status != "degraded" || h.Message != "2 open unacknowledged alert(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"alerts", `{}`, `"tinyId":"42"`},
		{"alerts", `{"priority":"P1"}`, `"priority":"P1"`},
		{"alert", `{"alert":"42"}`, `"details":{"host":"db-1"}`},
		{"alert", `{"alert":"` + alertID + `"}`, `"integration":"Prometheus (Prometheus)"`},
		{"schedules", `{}`, `"team":"Ops"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "ana@example.com") || strings.Contains(out, "abcdef1234567890abcdef") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	r, err := invoke(m, "on_call", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"onCall":["ana@example.com"]`) || strings.Contains(string(r.Output), "Off") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "on_call") != a.Sensitive {
			t.Fatalf("%s sensitive=%v: only who's on call carries personal data", a.Name, a.Sensitive)
		}
	}
}

func TestOpsgenieChanges(t *testing.T) {
	m, f := setup(t, "secret://og")
	r, err := invoke(m, "acknowledge_alert", `{"alert":"42","by":"ops@example.com"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Conduit (for ops@example.com)") || !strings.Contains(r.Plan.Summary, "escalation stop") || f.acked {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "acknowledge_alert", `{"alert":"42","note":"on it"}`, false)
	if err != nil || !f.acked || f.bodies[0]["user"] != "Conduit" || f.bodies[0]["note"] != "on it" || r.Undo == nil || r.Undo.Action != "unacknowledge_alert" || string(r.Undo.Input) != `{"alert":"`+alertID+`"}` {
		t.Fatalf("%+v %v %v", r, err, f.bodies)
	}
	if r, err := invoke(m, "acknowledge_alert", `{"alert":"42"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.acked {
		t.Fatal(err)
	}
	if _, err := invoke(m, "add_note", `{"alert":"42","note":"Restarted the primary."}`, false); err != nil || f.bodies[2]["note"] != "Restarted the primary." {
		t.Fatalf("%v %v", err, f.bodies)
	}
	if r, err := invoke(m, "close_alert", `{"alert":"42"}`, true); err != nil || r.Plan == nil || f.closed {
		t.Fatal(err)
	}
	if r, err := invoke(m, "close_alert", `{"alert":"42"}`, false); err != nil || !f.closed || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "close_alert", `{"alert":"42"}`, false); err != nil || !strings.Contains(string(r.Output), "already closed") {
		t.Fatalf("%s %v", r.Output, err)
	}
	risk := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["acknowledge_alert"] != sdk.RiskDestructive || risk["close_alert"] != sdk.RiskDestructive || risk["add_note"] != sdk.RiskWrite {
		t.Fatal(risk)
	}
}

func TestOpsgenieValidation(t *testing.T) {
	m, f := setup(t, "secret://og")
	for _, c := range []struct{ action, in string }{
		{"alerts", `{"status":"x"}`},
		{"alerts", `{"priority":"P9"}`},
		{"alerts", `{"limit":1000}`},
		{"alert", `{}`},
		{"alert", `{"alert":"../users"}`},
		{"acknowledge_alert", `{"alert":"a?b"}`},
		{"acknowledge_alert", `{"alert":"42","by":"` + strings.Repeat("x", 81) + `"}`},
		{"add_note", `{"alert":"42"}`},
		{"add_note", `{"alert":"42","note":"a\u0000b"}`},
		{"on_call", `{"schedule":"s/1"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The alert changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "close_alert", `{"alert":"7"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("closed another alert: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "og-plain"}, {Token: "secret://og", Region: "ap"}, {}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.HasPrefix(h.Message, "Opsgenie refused the API key") || strings.Contains(h.Message, "og-bad") {
		t.Fatalf("%+v", h)
	}
}

func TestOpsgenieRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://og"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://og": "og-good"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
