package semgrep

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

// leaks sit in the fields that carry code or free text; none may reach the output.
var leaks = []string{"AKIAPLANTEDSNIPPETVALUE", "plantedFixCodeSecret", "plantedTriageComment"}

type fakeSemgrep struct {
	mu      sync.Mutex
	seen    []string
	state   string
	reason  string
	triage  map[string]any
	triaged string // the triage answer's ids; ["42"] when empty
}

func (s *fakeSemgrep) finding(id int, sev string) string {
	return fmt.Sprintf(`{"id":%d,"ref":"main","status":"open","triage_state":%q,"triage_reason":%q,"triage_comment":"plantedTriageComment","severity":%q,"confidence":"high",
		"rule_name":"python.secrets.hardcoded","rule_message":"Found key AKIAPLANTEDSNIPPETVALUE","rule":{"name":"python.secrets.hardcoded","message":"Found key AKIAPLANTEDSNIPPETVALUE"},
		"repository":{"name":"acme/api","url":"https://github.com/acme/api"},"line_of_code_url":"https://github.com/acme/api/blob/main/app.py#L12",
		"location":{"file_path":"app.py","line":12,"column":1,"end_line":12,"end_column":40},"assistant":{"autofix":{"fix_code":"key = os.environ['plantedFixCodeSecret']"}}}`,
		id, s.state, s.reason, sev)
}

func (s *fakeSemgrep) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer sg-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Not authorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/api/v1/deployments":
		io.WriteString(w, `{"deployments":[{"id":"120","name":"Acme","slug":"acme","findings":{"url":"https://semgrep.dev/api/v1/deployments/acme/findings"}}]}`)
	case r.URL.Path == "/api/v1/deployments/acme/projects":
		io.WriteString(w, `{"projects":[{"id":5,"name":"acme/api","tags":["prod"],"primary_branch":"main","latest_scan_at":"2026-11-01T00:00:00Z"}]}`)
	case r.URL.Path == "/api/v1/deployments/acme/findings":
		if q.Get("page") != "0" {
			io.WriteString(w, `{"findings":[]}`)
			return
		}
		io.WriteString(w, `{"findings":[`+s.finding(41, "medium")+`,`+s.finding(42, "critical")+`]}`)
	case r.Method == "POST" && r.URL.Path == "/api/v1/deployments/acme/triage":
		var b map[string]any
		json.Unmarshal(body, &b)
		s.triage = b
		st, _ := b["new_triage_state"].(string)
		s.state, _ = b["new_triage_reason"].(string)
		s.state, s.reason = st, s.state
		if st == "reopened" {
			s.state = "untriaged"
		}
		ids := s.triaged
		if ids == "" {
			ids = `["42"]`
		}
		io.WriteString(w, `{"num_triaged":"1","triaged_issues":`+ids+`}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeSemgrep) {
	s := &fakeSemgrep{state: "untriaged"}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sg": "sg-good", "secret://bad": "sg-bad"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, s
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, what string, r sdk.Result) {
	t.Helper()
	all, _ := json.Marshal(r)
	for _, l := range append(leaks, "sg-good") {
		if strings.Contains(string(all), l) {
			t.Fatalf("%s leaked %q: %s", what, l, all)
		}
	}
}

func TestSemgrep(t *testing.T) {
	m, s := setup(t, "secret://sg")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "deployment Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"deployments", `{}`, `"slug":"acme"`},
		{"projects", `{}`, `"branch":"main"`},
		{"findings", `{}`, `"bySeverity":{"critical":1,"high":0,"low":0,"medium":1}`},
		{"findings", `{"repo":"acme/api","severity":"critical"}`, `"findings":[{"confidence":"high","id":42,"line":12,"path":"app.py"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
		noLeak(t, c.action, r)
	}
	if !strings.Contains(s.seen[len(s.seen)-1], "repos=acme%2Fapi") || !strings.Contains(s.seen[len(s.seen)-1], "severities=critical") {
		t.Fatal(s.seen)
	}
	// Ignore: preview, real, nothing to change, undo reopens.
	in := `{"finding":42,"repo":"acme/api","state":"ignored","reason":"false_positive"}`
	r, err := invoke(m, "triage_finding", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Changes[0].Target, "app.py line 12") || s.triage != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	noLeak(t, "preview", r)
	r, err = invoke(m, "triage_finding", in, false)
	if err != nil || s.state != "ignored" || s.reason != "false_positive" || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"state":"reopened"`) {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if ids, _ := s.triage["issue_ids"].([]any); len(ids) != 1 || s.triage["limit"] != float64(1) || s.triage["issue_type"] != "sast" || fmt.Sprint(s.triage["repos"]) != "[acme/api]" {
		t.Fatalf("%v", s.triage)
	}
	if r, err := invoke(m, "triage_finding", in, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Reviewing from ignored: undo ignores again with the same reason.
	r, err = invoke(m, "triage_finding", `{"finding":42,"repo":"acme/api","state":"reviewing"}`, false)
	if err != nil || s.state != "reviewing" || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"reason":"false_positive"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || s.state != "ignored" || s.reason != "false_positive" {
		t.Fatal(err, s.state)
	}
	if _, err := invoke(m, "triage_finding", `{"finding":7,"repo":"acme/api","state":"reviewing"}`, false); err == nil || !strings.Contains(err.Error(), "no sast finding 7") {
		t.Fatal(err)
	}
}

// A triage answer naming findings outside the repository means Semgrep
// changed more than the one finding: that's reported as a failure, while
// copies within the repository (other branches) are accepted.
func TestSemgrepTriageScope(t *testing.T) {
	m, s := setup(t, "secret://sg")
	in := `{"finding":42,"repo":"acme/api","state":"reviewing"}`
	s.triaged = `["42","41"]`
	if r, err := invoke(m, "triage_finding", in, false); err != nil || !strings.Contains(string(r.Output), "other branches") {
		t.Fatalf("%s %v", r.Output, err)
	}
	s.state = "untriaged"
	s.triaged = `["42","9001","9002"]`
	if r, err := invoke(m, "triage_finding", in, false); err == nil || !strings.Contains(err.Error(), "3 findings for finding 42, 2 of them outside acme/api") || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestSemgrepValidation(t *testing.T) {
	m, s := setup(t, "secret://sg")
	s.seen = nil
	for _, c := range []struct{ action, in string }{
		{"triage_finding", `{}`}, {"triage_finding", `{"finding":42,"state":"ignored"}`}, {"triage_finding", `{"finding":-1,"repo":"a","state":"ignored"}`},
		{"triage_finding", `{"finding":42,"repo":"a","state":"deleted"}`}, {"triage_finding", `{"finding":42,"repo":"a","state":"reviewing","reason":"no_time"}`},
		{"triage_finding", `{"finding":42,"repo":"a","state":"ignored","reason":"meh"}`}, {"triage_finding", `{"finding":"42/../x","repo":"a","state":"ignored"}`},
		{"triage_finding", `{"finding":42,"repo":"a","state":"ignored","note":"` + strings.Repeat("x", 3001) + `"}`},
		{"findings", `{"severity":"severe"}`}, {"findings", `{"status":"gone"}`}, {"findings", `{"limit":1000}`}, {"findings", `{"issue_type":"secrets"}`},
		{"projects", `{"deployment":"../admin"}`}, {"findings", `{"repo":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(s.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", s.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {Token: "secret://sg", Deployment: "a/b"}, {Token: "secret://sg", Deployment: "../x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Semgrep refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestSemgrepRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://sg"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sg": "sg-good"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
