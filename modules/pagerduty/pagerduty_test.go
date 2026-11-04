package pagerduty

import (
	"context"
	"encoding/json"
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
	mu     sync.Mutex
	status map[string]string
	events []map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/ev/") {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		if b["routing_key"] != "R0UTE" {
			w.WriteHeader(400)
			io.WriteString(w, `{"status":"invalid event","message":"Invalid routing key"}`)
			return
		}
		f.events = append(f.events, b)
		io.WriteString(w, `{"status":"success","message":"Event processed","dedup_key":"dk-1"}`)
		return
	}
	if r.Header.Get("Authorization") != "Token token=t0k" || !strings.Contains(r.Header.Get("Accept"), "version=2") {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Unauthorized"}}`)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api")
	switch r.Method + " " + p {
	case "GET /incidents":
		if len(r.URL.Query()["statuses[]"]) == 0 {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"incidents":[{"id":"PT4KHLK","incident_number":42,"title":"DB down","status":"`+f.status["PT4KHLK"]+`","urgency":"high","service":{"summary":"api"},"assignments":[{"assignee":{"summary":"Sam"}}]}],"more":false}`)
	case "GET /oncalls":
		io.WriteString(w, `{"oncalls":[{"user":{"summary":"Sam"},"schedule":{"summary":"Primary"},"escalation_policy":{"summary":"Default"},"escalation_level":1,"end":"2026-11-04T09:00:00Z"}]}`)
	case "PUT /incidents/PT4KHLK":
		if r.Header.Get("From") != "ops@example.com" {
			w.WriteHeader(400)
			return
		}
		var b struct {
			Incident struct{ Status string } `json:"incident"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.status["PT4KHLK"] = b.Incident.Status
		io.WriteString(w, `{"incident":{}}`)
	default:
		w.WriteHeader(404)
	}
}

func TestPagerDuty(t *testing.T) {
	f := &fake{status: map[string]string{"PT4KHLK": "triggered"}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://pd": "t0k", "secret://route": "R0UTE"})
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://pd", From: "ops@example.com", RoutingKey: "secret://route", API: srv.URL + "/api", Events: srv.URL + "/ev"})
	if err := m.Configure(ctx, host, "p", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "p"); h.Status != "degraded" {
		t.Fatalf("health %+v", h)
	}
	call := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	if out := string(call("incidents", "").Output); !strings.Contains(out, "DB down") || !strings.Contains(out, "Sam") {
		t.Fatal(out)
	}
	call("oncall", "")
	call("acknowledge", `{"id":"PT4KHLK"}`)
	if f.status["PT4KHLK"] != "acknowledged" {
		t.Fatal("ack")
	}
	call("resolve", `{"id":"PT4KHLK"}`)
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "resolve", Input: json.RawMessage(`{"id":"../users"}`)}); err == nil {
		t.Fatal("bad id accepted")
	}
	r := call("trigger", `{"summary":"Backup failed","severity":"critical"}`)
	if r.Undo == nil || f.events[0]["event_action"] != "trigger" {
		t.Fatalf("trigger %+v", f.events)
	}
	call(r.Undo.Action, string(r.Undo.Input))
	if f.events[1]["event_action"] != "resolve" || f.events[1]["dedup_key"] != "dk-1" {
		t.Fatalf("resolve %+v", f.events[1])
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "trigger", Input: json.RawMessage(`{"summary":"x","severity":"meh"}`)}); err == nil {
		t.Fatal("bad severity accepted")
	}

	// Events-only setup: no API calls, and changes say what's missing.
	eo := New()
	cfg, _ = json.Marshal(Config{RoutingKey: "secret://route", Events: srv.URL + "/ev"})
	_ = eo.Configure(ctx, host, "e", cfg)
	if _, err := eo.Invoke(ctx, sdk.Call{Instance: "e", Action: "incidents"}); err == nil {
		t.Fatal("incidents without a key")
	}
	if err := New().Configure(ctx, host, "x", json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty settings accepted")
	}
}

// What these do reaches past what an agent approved for write may do
// (going public, paging or silencing people, filtering every client,
// network access, stopping a service), so they're destructive.
func TestRiskOfReachingActions(t *testing.T) {
	want := map[string]bool{}
	for _, n := range []string{"acknowledge", "resolve", "trigger", "resolve_event"} {
		want[n] = true
	}
	for _, a := range New().Manifest().Actions {
		if want[a.Name] {
			delete(want, a.Name)
			if a.Risk != sdk.RiskDestructive {
				t.Errorf("%s must be destructive, is %s", a.Name, a.Risk)
			}
		}
	}
	for n := range want {
		t.Errorf("no action %s", n)
	}
}
