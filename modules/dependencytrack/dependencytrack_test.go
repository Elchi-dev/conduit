package dependencytrack

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

const (
	proj = "11111111-1111-1111-1111-111111111111"
	comp = "22222222-2222-2222-2222-222222222222"
	vuln = "33333333-3333-3333-3333-333333333333"
)

type fakeDT struct {
	mu       sync.Mutex
	seen     []string
	analysis map[string]any // nil until audited
	lastPut  map[string]any
}

func (f *fakeDT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Api-Key") != "odt_good" {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/version":
		io.WriteString(w, `{"version":"4.12.1","application":"Dependency-Track"}`)
	case "GET /api/v1/project":
		w.Header().Set("X-Total-Count", "1")
		io.WriteString(w, `[{"uuid":"`+proj+`","name":"shop","version":"1.0","classifier":"APPLICATION","active":true,"lastBomImport":1793000000000,
			"metrics":{"critical":1,"high":2,"medium":3,"low":0,"unassigned":0,"inheritedRiskScore":21}}]`)
	case "GET /api/v1/metrics/portfolio/current":
		io.WriteString(w, `{"critical":4,"high":5,"medium":6,"low":7,"unassigned":0,"vulnerabilities":22,"projects":3,"vulnerableProjects":2,"suppressed":1,"findingsTotal":22,"findingsAudited":2,"inheritedRiskScore":80.5,"lastOccurrence":1793000000000}`)
	case "GET /api/v1/metrics/project/" + proj + "/current":
		io.WriteString(w, `{"critical":1,"high":2,"medium":3,"low":0,"vulnerabilities":6}`)
	case "GET /api/v1/finding/project/" + proj:
		sup := f.analysis != nil && f.analysis["isSuppressed"] == true
		if sup && r.URL.Query().Get("suppressed") == "false" {
			io.WriteString(w, `[]`)
			return
		}
		io.WriteString(w, `[{"component":{"uuid":"`+comp+`","name":"log4j-core","group":"org.apache.logging.log4j","version":"2.14.1","purl":"pkg:maven/x?token=LEAKMEsecretvalue123"},
			"vulnerability":{"uuid":"`+vuln+`","vulnId":"CVE-2021-44228","source":"NVD","severity":"CRITICAL","cvssV3BaseScore":10,"epssScore":0.97,"aliases":[{"cveId":"CVE-2021-44228","ghsaId":"GHSA-jfh8-c2jp-5v3q"}],"description":"LEAKME long text"},
			"analysis":{"isSuppressed":false},"matrix":"x"},
			{"component":{"uuid":"`+comp+`","name":"lib"},"vulnerability":{"uuid":"`+vuln+`","vulnId":"CVE-2020-1","severity":"LOW"}}]`)
	case "GET /api/v1/analysis":
		if f.analysis == nil {
			w.WriteHeader(404)
			io.WriteString(w, `No analysis exists.`)
			return
		}
		json.NewEncoder(w).Encode(f.analysis)
	case "PUT /api/v1/analysis":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastPut = b
		f.analysis = map[string]any{"analysisState": b["analysisState"], "analysisJustification": b["analysisJustification"], "analysisResponse": b["analysisResponse"], "isSuppressed": b["isSuppressed"]}
		json.NewEncoder(w).Encode(f.analysis)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeDT) {
	f := &fakeDT{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dt": "odt_good", "secret://bad": "odt_bad"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDependencyTrack(t *testing.T) {
	m, f := setup(t, "secret://dt")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "Dependency-Track 4.12.1, 1 projects" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"vulnerabilities":{"critical":1,"high":2,"low":0,"medium":3,"unassigned":0}`},
		{"projects", `{"search":"shop"}`, `"lastBomImport":"2026-`},
		{"metrics", `{}`, `"vulnerableProjects":2`},
		{"metrics", `{"project":"` + proj + `"}`, `"bySeverity":{"critical":1,"high":2,"low":0,"medium":3,"unassigned":0}`},
		{"findings", `{"project":"` + proj + `"}`, `"aliases":["GHSA-jfh8-c2jp-5v3q"]`},
		{"findings", `{"project":"` + proj + `","severity":"LOW"}`, `"vulnerability":"CVE-2020-1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "odt_good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	finding := proj + ":" + comp + ":" + vuln
	if r, _ := invoke(m, "findings", `{"project":"`+proj+`"}`, false); !strings.Contains(string(r.Output), `"finding":"`+finding+`"`) {
		t.Fatal(string(r.Output))
	}
	in := `{"finding":"` + finding + `","state":"NOT_AFFECTED","justification":"CODE_NOT_REACHABLE","suppressed":true,"comment":"not used"}`
	r, err := invoke(m, "audit_finding", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Suppress a finding" || f.lastPut != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "audit_finding", in, false)
	if err != nil || f.analysis["isSuppressed"] != true || f.lastPut["comment"] != "not used" || r.Undo == nil || r.Undo.Action != "audit_finding" ||
		!strings.Contains(string(r.Undo.Input), `"state":"NOT_SET"`) || !strings.Contains(string(r.Undo.Input), `"suppressed":false`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "audit_finding", `{"finding":"`+finding+`","state":"NOT_AFFECTED","suppressed":true}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.analysis["isSuppressed"] != false || f.analysis["analysisState"] != "NOT_SET" {
		t.Fatal(err, f.analysis)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "audit_finding" && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Risk)
		}
	}
}

func TestDependencyTrackValidation(t *testing.T) {
	m, f := setup(t, "secret://dt")
	good := proj + ":" + comp + ":" + vuln
	for _, c := range []struct{ action, in string }{
		{"findings", `{}`}, {"findings", `{"project":"../admin"}`}, {"findings", `{"project":"` + proj + `","severity":"SEVERE"}`},
		{"findings", `{"project":"` + proj + `","limit":5000}`}, {"metrics", `{"project":"x"}`}, {"projects", `{"search":"a&b=c"}`},
		{"audit_finding", `{"finding":"` + proj + `","state":"NOT_AFFECTED"}`}, {"audit_finding", `{"finding":"` + good + `:x","state":"NOT_AFFECTED"}`},
		{"audit_finding", `{"finding":"` + good + `","state":"FINE"}`}, {"audit_finding", `{"finding":"` + good + `","response":"IGNORE"}`},
		{"audit_finding", `{"finding":"` + good + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://dt.example.com", APIKey: "odt_plain"}, {URL: "dt.example.com", APIKey: "secret://dt"},
		{URL: "https://u:p@dt.example.com", APIKey: "secret://dt"}, {URL: "https://dt.example.com/?a", APIKey: "secret://dt"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "Dependency-Track refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestDependencyTrackRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://dt"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dt": "odt_good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
