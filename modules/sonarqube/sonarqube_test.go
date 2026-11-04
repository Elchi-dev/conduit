package sonarqube

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
	mu    sync.Mutex
	seen  []string
	admin bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "squ_good" || p != "" {
		w.WriteHeader(401)
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.URL.RequestURI())
	q := r.URL.Query()
	switch r.URL.Path {
	case "/sonar/api/authentication/validate":
		io.WriteString(w, `{"valid":true}`)
	case "/sonar/api/system/status":
		io.WriteString(w, `{"status":"UP","version":"10.6"}`)
	case "/sonar/api/projects/search":
		if !f.admin {
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":[{"msg":"Insufficient privileges"}]}`)
			return
		}
		io.WriteString(w, `{"paging":{"total":1},"components":[{"key":"web","name":"Web","lastAnalysisDate":"2026-11-01T00:00:00+0000"}]}`)
	case "/sonar/api/components/search":
		if q.Get("qualifiers") != "TRK" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"paging":{"total":2},"components":[{"key":"web","name":"Web"},{"key":"api","name":"API"}]}`)
	case "/sonar/api/qualitygates/project_status":
		if q.Get("projectKey") != "web" {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[{"msg":"Project not found"}]}`)
			return
		}
		io.WriteString(w, `{"projectStatus":{"status":"ERROR","conditions":[{"status":"ERROR","metricKey":"new_coverage","comparator":"LT","errorThreshold":"80","actualValue":"61.2"},{"status":"OK","metricKey":"new_bugs","comparator":"GT","errorThreshold":"0","actualValue":"0"}]}}`)
	case "/sonar/api/issues/search":
		if q.Get("componentKeys") != "web" || q.Get("resolved") != "false" || q.Get("branch") != "feature/x" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"total":14,"paging":{"total":14},"issues":[{"message":"x"}],"facets":[{"property":"severities","values":[{"val":"MAJOR","count":10},{"val":"BLOCKER","count":4}]},{"property":"types","values":[{"val":"CODE_SMELL","count":13},{"val":"BUG","count":1}]}]}`)
	case "/sonar/api/project_analyses/search":
		io.WriteString(w, `{"analyses":[{"key":"A1","date":"2026-11-01T00:00:00+0000","projectVersion":"1.4","events":[{"category":"QUALITY_GATE","name":"Failed"}]}]}`)
	case "/sonar/api/hotspots/search":
		if q.Get("status") == "REVIEWED" {
			io.WriteString(w, `{"paging":{"total":7},"hotspots":[{}]}`)
			return
		}
		io.WriteString(w, `{"paging":{"total":3},"hotspots":[{"vulnerabilityProbability":"HIGH"},{"vulnerabilityProbability":"LOW"},{"vulnerabilityProbability":"HIGH"}]}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL + "/sonar", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sq": "squ_good", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestSonarReads(t *testing.T) {
	m, f := setup(t, "secret://sq")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "up · 10.6" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"total":2`},
		{"quality_gate", `{"project":"web"}`, `"failing":["new_coverage"],"passed":false`},
		{"issues", `{"project":"web","branch":"feature/x"}`, `"bySeverity":{"blocker":4,"major":10},"byType":{"bug":1,"code_smell":13},"open":14`},
		{"analyses", `{"project":"web"}`, `"events":["quality_gate: Failed"]`},
		{"hotspots", `{"project":"web"}`, `"byProbability":{"high":2,"low":1},"project":"web","reviewed":7,"toReview":3`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	f.admin = true
	if r, _ := invoke(m, "projects", `{}`); !strings.Contains(string(r.Output), `"lastAnalysis"`) {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "quality_gate", `{"project":"nope"}`); err == nil || !strings.Contains(err.Error(), "there's no project nope") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestSonarValidation(t *testing.T) {
	m, f := setup(t, "secret://sq")
	for _, c := range []struct{ action, in string }{
		{"quality_gate", `{}`},
		{"quality_gate", `{"project":"web&x=1"}`},
		{"quality_gate", `{"project":"web","branch":"a b"}`},
		{"quality_gate", `{"project":"web","branch":"../x"}`},
		{"quality_gate", `{"project":"web","branch":"main","pullRequest":"1"}`},
		{"issues", `{"project":"web","pullRequest":"1&x"}`},
		{"analyses", `{"project":"web","limit":500}`},
		{"analyses", `{"project":"web","pullRequest":"3"}`},
		{"projects", `{"search":"x"}`},
		{"projects", `{"search":"a&b=c"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Address: "http://x", Token: "plain"}, {Address: "http://x"}, {Address: "ftp://x", Token: "secret://sq"}, {Address: "http://u:p@x", Token: "secret://sq"},
		{Address: "https://sonarcloud.io", Token: "secret://sq"}, {Address: "https://sonarcloud.io", Token: "secret://sq", Organization: "Bad Org"}, {Address: "http://x/a/../b", Token: "secret://sq"}, {Address: "https://x", Token: "secret://sq", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Address: "https://sonarcloud.io", Token: "secret://sq", Organization: "my-org"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "issues", `{"project":"web"}`); err == nil || !strings.Contains(err.Error(), "refused the token") {
		t.Fatal(err)
	}
}

func TestSonarRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: "secret://sq"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sq": "squ_good"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "projects", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
