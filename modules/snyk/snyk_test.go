package snyk

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
	orgID  = "11111111-2222-3333-4444-555555555555"
	projID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token sktok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"jsonapi":{"version":"1.0"},"errors":[{"status":"401","detail":"Unauthorized"}]}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	q := r.URL.Query()
	if strings.HasPrefix(r.URL.Path, "/rest/") && (q.Get("version") != version || r.Header.Get("Accept") != "application/vnd.api+json") {
		w.WriteHeader(400)
		io.WriteString(w, `{"errors":[{"detail":"version and accept"}]}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /rest/self":
		io.WriteString(w, `{"data":{"id":"u1","type":"user","attributes":{"name":"Kim Lee","username":"kim","email":"kim@example.com"}}}`)
	case "GET /rest/orgs":
		io.WriteString(w, `{"data":[{"id":"`+orgID+`","type":"org","attributes":{"name":"Acme","slug":"acme","is_personal":false}}],"links":{}}`)
	case "GET /rest/orgs/" + orgID + "/projects":
		if q.Get("meta.latest_issue_counts") != "true" {
			w.WriteHeader(400)
			return
		}
		if q.Get("starting_after") == "" {
			io.WriteString(w, `{"data":[{"id":"`+projID+`","type":"project","attributes":{"name":"acme/web:package.json","type":"npm","target_file":"package.json","target_reference":"main","origin":"github","status":"active","created":"2026-01-01T00:00:00Z"},
				"meta":{"latest_issue_counts":{"critical":1,"high":2,"medium":3,"low":4,"updated_at":"2026-11-04T08:00:00Z"}}}],
				"links":{"next":"https://evil.example.com/rest/orgs/x/projects?version=2024-10-15&starting_after=c2"}}`)
			return
		}
		if q.Get("starting_after") != "c2" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"data":[{"id":"bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee","attributes":{"name":"acme/api:go.mod","type":"gomodules"},"meta":{"latest_issue_counts":{"critical":0,"high":5,"medium":0,"low":0}}}],"links":{"next":""}}`)
	case "GET /rest/orgs/" + orgID + "/issues":
		if q.Get("scan_item.id") != projID || q.Get("scan_item.type") != "project" || q.Get("status") != "open" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"data":[
			{"id":"i1","attributes":{"title":"Prototype Pollution","type":"package_vulnerability","effective_severity_level":"critical"}},
			{"id":"i2","attributes":{"title":"ReDoS","type":"package_vulnerability","effective_severity_level":"high"}},
			{"id":"i3","attributes":{"title":"ReDoS","type":"package_vulnerability","effective_severity_level":"high"}},
			{"id":"i4","attributes":{"title":"GPL-3.0","type":"license","effective_severity_level":"medium"}}],"links":{}}`)
	case "POST /v1/org/" + orgID + "/project/" + projID + "/history":
		if q.Get("perPage") != "2" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"snapshots":[{"id":"s1","created":"2026-11-04T08:00:00Z","method":"recurring","totalDependencies":321,"issueCounts":{"vuln":{"critical":1,"high":2,"medium":3,"low":4},"license":{"critical":0,"high":0,"medium":1,"low":0}}},
			{"id":"s0","created":"2026-11-03T08:00:00Z","method":"cli","totalDependencies":320,"issueCounts":{"vuln":{"critical":2,"high":2,"medium":3,"low":4},"license":{}}}],"total":40}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"status":"404","detail":"Not Found"}]}`)
	}
}

func setup(t *testing.T, tok, org string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok, Organization: org})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sk": "sktok", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestSnyk(t *testing.T) {
	m, f := setup(t, "secret://sk", orgID)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "signed in as kim" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"orgs", `{}`, []string{`"slug":"acme"`, `"default":true`}},
		{"projects", `{}`, []string{`"issues":{"critical":1,"high":2,"low":4,"medium":3}`, `"lastTested":"2026-11-04T08:00:00Z"`, `"name":"acme/api:go.mod"`, `"truncated":false`}},
		{"issues", `{}`, []string{`"bySeverity":{"critical":1,"high":7,"low":4,"medium":3}`, `"mostAffected":[{"critical":1,"high":2,"project":"acme/web:package.json","total":10}`, `"projects":2`}},
		{"issues", `{"project":"` + projID + `"}`, []string{`"open":4`, `"bySeverity":{"critical":1,"high":2,"low":0,"medium":1}`, `"byType":{"license":1,"package_vulnerability":3}`, `"top":[{"count":1,"severity":"critical","title":"Prototype Pollution"},{"count":2,"severity":"high","title":"ReDoS"}]`}},
		{"tests", `{"org":"` + strings.ToUpper(orgID) + `","project":"` + projID + `","limit":2}`, []string{`"method":"recurring"`, `"dependencies":321`, `"total":40`, `"vulnerabilities":{"critical":2`}},
	} {
		r, err := invoke(m, c.action, c.in)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "evil") {
			t.Fatalf("followed links.next's address: %v", f.seen)
		}
	}
}

func TestSnykValidation(t *testing.T) {
	m, f := setup(t, "secret://sk", "")
	for _, c := range []struct{ action, in string }{
		{"projects", `{}`}, // no default organization
		{"projects", `{"org":"../../self"}`},
		{"issues", `{"org":"` + orgID + `","project":"x/../y"}`},
		{"tests", `{"org":"` + orgID + `"}`},
		{"tests", `{"org":"` + orgID + `","project":"` + projID + `","limit":500}`},
		{"ignore_issue", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {Token: "secret://sk", Region: "mars"}, {Token: "secret://sk", Organization: "acme"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the API token") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestSnykRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://sk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sk": "sktok"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestSnykReadOnly(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Risk != sdk.RiskRead || a.Sensitive {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}
