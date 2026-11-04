package incidentio

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

const incID = "01G18REBY9AYH6CMWCJ2CVCYCH"

var statusNames = map[string][2]string{
	"01STATUSINVESTIGATING": {"Investigating", "active"},
	"01STATUSMONITORING000": {"Monitoring", "active"},
	"01STATUSCLOSED0000000": {"Closed", "closed"},
}

type fake struct {
	mu       sync.Mutex
	seen     []string
	status   string
	lastBody map[string]any
	ignore   bool
}

func (f *fake) incident() string {
	s := statusNames[f.status]
	return fmt.Sprintf(`{"id":%q,"reference":"INC-42","name":"Checkout errors","summary":"Payments fail. key=sk_fake_abcdefghijklmnopqrstuvwxyz","incident_status":{"id":%q,"name":%q,"category":%q},
		"severity":{"id":"01SEVMAJOR0000","name":"Major","rank":2},"mode":"standard","visibility":"public","created_at":"2026-11-04T10:00:00Z","updated_at":"2026-11-04T10:05:00Z",
		"permalink":"https://app.incident.io/example/incidents/42","slack_channel_name":"inc-42-checkout","creator":{"user":{"name":"Ana Lima","email":"ana@example.com"}},
		"incident_role_assignments":[{"assignee":{"name":"Ana Lima","email":"ana@example.com"},"role":{"name":"Lead"}}],"incident_type":{"name":"Default"}}`, incID, f.status, s[0], s[1])
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer inc-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"authentication_error","status":401,"errors":[{"code":"unauthorized","message":"invalid API key"}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/incidents":
		if cats := r.URL.Query()["status_category[one_of]"]; len(cats) == 2 && cats[0] == "triage" && cats[1] == "active" {
			fmt.Fprintf(w, `{"incidents":[%s]}`, f.incident())
			return
		}
		io.WriteString(w, `{"incidents":[]}`)
	case "GET /v2/incidents/" + incID:
		fmt.Fprintf(w, `{"incident":%s}`, f.incident())
	case "GET /v2/incidents/01OTHERINCIDENT000":
		fmt.Fprintf(w, `{"incident":%s}`, f.incident())
	case "POST /v2/incidents/" + incID + "/actions/edit":
		f.lastBody = b
		if !f.ignore {
			f.status = b["incident"].(map[string]any)["incident_status_id"].(string)
		}
		fmt.Fprintf(w, `{"incident":%s}`, f.incident())
	case "POST /v2/incidents":
		f.lastBody = b
		fmt.Fprintf(w, `{"incident":%s}`, f.incident())
	case "GET /v1/severities":
		io.WriteString(w, `{"severities":[{"id":"01SEVMINOR0000","name":"Minor","rank":3,"description":"Small"},{"id":"01SEVMAJOR0000","name":"Major","rank":2,"description":"Big"}]}`)
	case "GET /v1/incident_statuses":
		io.WriteString(w, `{"incident_statuses":[{"id":"01STATUSCLOSED0000000","name":"Closed","category":"closed","rank":3},{"id":"01STATUSINVESTIGATING","name":"Investigating","category":"active","rank":1},{"id":"01STATUSMONITORING000","name":"Monitoring","category":"active","rank":2}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"type":"not_found","status":404,"errors":[{"code":"not_found","message":"Not found"}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "01STATUSINVESTIGATING"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://io": "inc-good", "secret://bad": "inc-bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestIncidentIOReads(t *testing.T) {
	m, _ := setup(t, "secret://io")
	if h := m.Health(context.Background(), "n"); h.Status != "degraded" || h.Message != "1 live incident(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"incidents", `{}`, `"reference":"INC-42"`},
		{"incidents", `{"status":"closed"}`, `[]`},
		{"incident", `{"incident":"` + incID + `"}`, `"channel":"#inc-42-checkout"`},
		{"incident", `{"incident":"` + incID + `"}`, `"summary":"Payments fail.`},
		{"severities", `{}`, `"name":"Major","rank":2`},
		{"statuses", `{}`, `"category":"closed"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "ana@example.com") || strings.Contains(out, "Ana Lima") || strings.Contains(out, "sk_live") || strings.Contains(out, "inc-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Severities come in rank order.
	if r, _ := invoke(m, "severities", `{}`, false); strings.Index(string(r.Output), "Major") > strings.Index(string(r.Output), "Minor") {
		t.Fatal(string(r.Output))
	}
}

func TestIncidentIOChanges(t *testing.T) {
	m, f := setup(t, "secret://io")
	r, err := invoke(m, "create_incident", `{"name":"Checkout errors","summary":"Payments fail.","severity":"major","test":true}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "test incident") || !strings.Contains(r.Plan.Summary, "page people") || !strings.Contains(string(r.Plan.Changes[0].After), `"severity":"Major"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("the preview changed something: %s", s)
		}
	}
	if _, err := invoke(m, "create_incident", `{"name":"Checkout errors","severity":"01SEVMAJOR0000"}`, false); err != nil || f.lastBody["severity_id"] != "01SEVMAJOR0000" || f.lastBody["mode"] != "standard" ||
		f.lastBody["visibility"] != "public" || !strings.HasPrefix(f.lastBody["idempotency_key"].(string), "conduit-") {
		t.Fatalf("%v %v", f.lastBody, err)
	}
	if _, err := invoke(m, "create_incident", `{"name":"x","severity":"Critical"}`, false); err == nil || !strings.Contains(err.Error(), "no severity") {
		t.Fatal(err)
	}

	in := `{"incident":"` + incID + `","status":"monitoring"}`
	r, err = invoke(m, "update_status", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from Investigating to Monitoring") || !strings.Contains(r.Plan.Summary, "isn't told") || f.status != "01STATUSINVESTIGATING" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "update_status", in, false)
	if err != nil || f.status != "01STATUSMONITORING000" || f.lastBody["notify_incident_channel"] != false || r.Undo == nil || r.Undo.Action != "update_status" ||
		string(r.Undo.Input) != `{"incident":"`+incID+`","status":"01STATUSINVESTIGATING"}` {
		t.Fatalf("%+v %v %v", r, err, f.lastBody)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "01STATUSINVESTIGATING" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "update_status", `{"incident":"`+incID+`","status":"Investigating"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "update_status", `{"incident":"`+incID+`","status":"Closed","notifyChannel":true}`, false); err != nil || f.lastBody["notify_incident_channel"] != true {
		t.Fatal(err)
	}
	f.ignore = true
	if _, err := invoke(m, "update_status", `{"incident":"`+incID+`","status":"Monitoring"}`, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "create_incident" || a.Name == "update_status") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestIncidentIOValidation(t *testing.T) {
	m, f := setup(t, "secret://io")
	for _, c := range []struct{ action, in string }{
		{"incidents", `{"status":"open"}`},
		{"incidents", `{"limit":101}`},
		{"incident", `{}`},
		{"incident", `{"incident":"../../v1/api_keys"}`},
		{"create_incident", `{}`},
		{"create_incident", `{"name":"a\u0007b"}`},
		{"create_incident", `{"name":"x","visibility":"everyone"}`},
		{"create_incident", `{"name":"` + strings.Repeat("x", 201) + `"}`},
		{"update_status", `{"incident":"` + incID + `"}`},
		{"update_status", `{"incident":"short","status":"Closed"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The incident changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "update_status", `{"incident":"01OTHERINCIDENT000","status":"Closed"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another incident: %v %v", err, f.seen)
	}
	for _, raw := range []string{`{"token":"inc-plain"}`, `{}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "incident.io refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestIncidentIORefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://io"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://io": "inc-good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
