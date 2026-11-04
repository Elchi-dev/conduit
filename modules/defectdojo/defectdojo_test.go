package defectdojo

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

type state struct{ active, verified, mitigated, accepted, fp bool }

type fakeDojo struct {
	mu        sync.Mutex
	seen      []string
	f         map[int64]*state
	simpleRA  bool
	lastClose map[string]any
}

func (d *fakeDojo) finding(id int64) string {
	s := d.f[id]
	return fmt.Sprintf(`{"id":%d,"title":"SQL injection in /login?token=LEAKMEsecretvalue123","severity":"High","active":%t,"verified":%t,"is_mitigated":%t,"risk_accepted":%t,
		"false_p":%t,"duplicate":false,"out_of_scope":false,"date":"2026-11-01","cwe":89,"component_name":"app","component_version":"1.2","file_path":"src/login.py","line":42,"test":3,
		"vulnerability_ids":[{"vulnerability_id":"CVE-2026-1234"}],"description":"payload: <script>LEAKME</script>","steps_to_reproduce":"LEAKME"}`,
		id, s.active, s.verified, s.mitigated, s.accepted, s.fp)
}

func (d *fakeDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token dd-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	var b map[string]any
	json.Unmarshal(body, &b)
	switch {
	case r.URL.Path == "/api/v2/products/":
		io.WriteString(w, `{"count":1,"next":null,"results":[{"id":1,"name":"Shop","prod_type":1,"business_criticality":"high","lifecycle":"production","findings_count":5}]}`)
	case r.URL.Path == "/api/v2/engagements/":
		io.WriteString(w, `{"count":1,"results":[{"id":2,"name":"CI scan","product":1,"engagement_type":"CI/CD","status":"In Progress","target_start":"2026-10-01","target_end":"2026-12-01","active":true}]}`)
	case r.URL.Path == "/api/v2/findings/":
		if q.Get("active") != "true" || q.Get("risk_accepted") != "false" {
			w.WriteHeader(400)
			return
		}
		n := map[string]int{"Critical": 1, "High": 3, "Medium": 0, "Low": 2, "Info": 0}[q.Get("severity")]
		if q.Get("severity") == "" {
			n = 6
		}
		if q.Get("limit") == "1" {
			fmt.Fprintf(w, `{"count":%d,"results":[]}`, n)
			return
		}
		fmt.Fprintf(w, `{"count":%d,"results":[%s]}`, n, d.finding(10))
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v2/findings/"):
		var id int64
		fmt.Sscanf(r.URL.Path, "/api/v2/findings/%d/", &id)
		if d.f[id] == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		io.WriteString(w, d.finding(id))
	case r.Method == "POST" && r.URL.Path == "/api/v2/findings/10/close/":
		d.lastClose = b
		d.f[10].active, d.f[10].mitigated = false, true
		d.f[10].fp, _ = b["false_p"].(bool)
		io.WriteString(w, `{}`)
	case r.Method == "PATCH" && r.URL.Path == "/api/v2/findings/10/":
		s := d.f[10]
		if v, ok := b["verified"].(bool); ok {
			s.verified = v
		}
		if v, ok := b["risk_accepted"].(bool); ok {
			if v && !d.simpleRA {
				w.WriteHeader(400)
				io.WriteString(w, `{"risk_accepted":["Simple risk acceptance is disabled for this product, use the UI to accept this finding."]}`)
				return
			}
			s.accepted = v
			if v {
				s.active = false
			}
		}
		if v, ok := b["active"].(bool); ok {
			s.active = v
		}
		if v, ok := b["is_mitigated"].(bool); ok {
			s.mitigated = v
		}
		io.WriteString(w, d.finding(10))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeDojo) {
	d := &fakeDojo{f: map[int64]*state{10: {active: true}}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v2/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dd": "dd-good", "secret://bad": "dd-bad"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, d
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDefectDojo(t *testing.T) {
	m, d := setup(t, "secret://dd")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "1 products, 6 open findings" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"products", `{}`, `"findings":5`},
		{"engagements", `{"product":1}`, `"status":"In Progress"`},
		{"findings", `{"product":1}`, `"bySeverity":{"Critical":1,"High":3,"Info":0,"Low":2,"Medium":0}`},
		{"findings", `{"severity":"High"}`, `"vulnerabilityIds":["CVE-2026-1234"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "dd-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Close: preview, real, nothing to change, undo reopens.
	r, err := invoke(m, "close_finding", `{"finding":10,"note":"fixed in 1.3"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Close finding 10" || !d.f[10].active {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "close_finding", `{"finding":10,"note":"fixed in 1.3"}`, false)
	if err != nil || d.f[10].active || r.Undo == nil || r.Undo.Action != "reopen_finding" || d.lastClose["note"] != "fixed in 1.3" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "close_finding", `{"finding":10}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !d.f[10].active || d.f[10].mitigated || r.Undo == nil || r.Undo.Action != "close_finding" {
		t.Fatalf("%+v %v", r, err)
	}
	// Verify and set back.
	r, err = invoke(m, "verify_finding", `{"finding":10}`, false)
	if err != nil || !d.f[10].verified || r.Undo == nil || string(r.Undo.Input) != `{"finding":10,"verified":false}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || d.f[10].verified {
		t.Fatal(err)
	}
	// Risk acceptance needs simple risk acceptance on the product.
	if _, err := invoke(m, "risk_accept_finding", `{"finding":10}`, false); err == nil || !strings.Contains(err.Error(), "simple risk acceptance") {
		t.Fatal(err)
	}
	d.simpleRA = true
	r, err = invoke(m, "risk_accept_finding", `{"finding":10}`, false)
	if err != nil || !d.f[10].accepted || r.Undo == nil || r.Undo.Action != "reopen_finding" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "reopen_finding", `{"finding":10}`, false); err != nil || d.f[10].accepted || r.Undo == nil || r.Undo.Action != "risk_accept_finding" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "close_finding", `{"finding":99}`, false); err == nil || !strings.Contains(err.Error(), "no finding") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name != "reopen_finding" && strings.HasSuffix(a.Name, "_finding") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestDefectDojoValidation(t *testing.T) {
	m, d := setup(t, "secret://dd")
	for _, c := range []struct{ action, in string }{
		{"close_finding", `{}`}, {"close_finding", `{"finding":-3}`}, {"close_finding", `{"finding":"10/../1"}`}, {"verify_finding", `{"finding":99999999999}`},
		{"findings", `{"severity":"Severe"}`}, {"findings", `{"limit":1000}`}, {"engagements", `{"product":-1}`}, {"findings", `{"product":"1&x=2"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(d.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", d.seen)
	}
	for _, c := range []Config{{URL: "https://dd.example.com", Token: "plain"}, {URL: "dd.example.com", Token: "secret://dd"}, {URL: "https://a:b@dd.example.com", Token: "secret://dd"},
		{URL: "https://dd.example.com/#x", Token: "secret://dd"}, {URL: "https://dd.example.com?x=1", Token: "secret://dd"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "DefectDojo refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestDefectDojoRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://dd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dd": "dd-good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestDefectDojoUndoOnlyWhenExact(t *testing.T) {
	m, d := setup(t, "secret://dd")
	// A false positive keeps its flag when closed (DefectDojo would clear
	// it if it weren't sent), and has no undo: reopening wouldn't restore it.
	d.f[10] = &state{fp: true}
	r, err := invoke(m, "close_finding", `{"finding":10}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].Before), `"falsePositive":true`) || !strings.Contains(string(r.Plan.Changes[0].After), `"falsePositive":true`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "close_finding", `{"finding":10}`, false)
	if err != nil || d.lastClose["false_p"] != true || !d.f[10].fp || r.Undo != nil || !strings.Contains(string(r.Output), "no undo") {
		t.Fatalf("%s %+v %v %v", r.Output, r.Undo, d.lastClose, err)
	}
	// Inactive but not closed or accepted: reopen refuses.
	d.f[10] = &state{fp: true}
	d.seen = nil
	if _, err := invoke(m, "reopen_finding", `{"finding":10}`, false); err == nil || !strings.Contains(err.Error(), "neither closed nor risk-accepted") {
		t.Fatal(err)
	}
	// Risk-accepting a closed finding has no reopen as its undo.
	d.simpleRA = true
	d.f[10] = &state{mitigated: true}
	if r, err := invoke(m, "risk_accept_finding", `{"finding":10}`, false); err != nil || r.Undo != nil || !d.f[10].accepted {
		t.Fatalf("%+v %v", r, err)
	}
	// Closed and accepted at once: reopening can't be undone exactly.
	if r, err := invoke(m, "reopen_finding", `{"finding":10}`, false); err != nil || r.Undo != nil || !d.f[10].active {
		t.Fatalf("%+v %v", r, err)
	}
}
