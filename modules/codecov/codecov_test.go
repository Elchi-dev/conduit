package codecov

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

const sha = "0123456789abcdef0123456789abcdef01234567"

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer cvtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/github/elchi/repos/":
		if q.Get("page_size") == "1" {
			io.WriteString(w, `{"count":2,"next":null,"results":[]}`)
			return
		}
		if q.Get("active") != "true" {
			w.WriteHeader(400)
			return
		}
		if q.Get("page") == "1" {
			io.WriteString(w, `{"count":2,"next":"https://api.codecov.io/api/v2/github/elchi/repos/?page=2","results":[{"name":"conduit","private":true,"branch":"main","language":"go","active":true,"updatestamp":"2026-11-04T10:00:00Z","totals":{"coverage":81.234}}]}`)
			return
		}
		io.WriteString(w, `{"count":2,"next":null,"results":[{"name":"site","branch":"main","active":true,"totals":null}]}`)
	case "/github/elchi/repos/conduit/totals/":
		if q.Get("branch") == "dev" || q.Get("sha") == sha {
			io.WriteString(w, `{"files":10,"lines":1000,"hits":700,"misses":250,"partials":50,"coverage":"70.00"}`)
			return
		}
		io.WriteString(w, `{"files":10,"lines":1000,"hits":812,"misses":150,"partials":38,"coverage":81.2}`)
	case "/github/elchi/repos/conduit/commits/" + sha + "/":
		io.WriteString(w, `{"commitid":"`+sha+`","message":"Add tests\n\nbody","timestamp":"2026-11-04T09:00:00Z","ci_passed":true,"branch":"main","state":"complete","parent":"fedcba9876543210","author":{"username":"kim"},"totals":{"files":10,"lines":1000,"hits":812,"misses":150,"partials":38,"coverage":81.2}}`)
	case "/github/elchi/repos/conduit/compare/":
		if q.Get("pullid") != "7" && !(q.Get("base") == "aaaaaaa" && q.Get("head") == "bbbbbbb") {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		io.WriteString(w, `{"base_commit":"aaaaaaaaaaaaaaaa","head_commit":"bbbbbbbbbbbbbbbb","totals":{"base":{"coverage":80.0},"head":{"coverage":81.5},"patch":{"coverage":92.31}},
			"files":[{"name":{"base":"a.go","head":"a.go"},"totals":{"base":{"coverage":50},"head":{"coverage":75}},"has_diff":true},
			{"name":{"base":"b.go","head":"b.go"},"totals":{"base":{"coverage":90},"head":{"coverage":90}},"has_diff":false},
			{"name":{"base":null,"head":"c.go"},"totals":{"base":null,"head":{"coverage":100},"patch":{"coverage":100}},"has_diff":true},
			{"name":{"base":"d.go","head":"d.go"},"totals":{"base":{"coverage":60},"head":{"coverage":58}},"has_diff":false}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Service: "github", Owner: "elchi", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cv": "cvtok", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in)})
}

func TestCodecov(t *testing.T) {
	m, _ := setup(t, "secret://cv")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "elchi · 2 active repositories" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"repos", `{}`, []string{`"coverage":81.23`, `"repo":"conduit"`, `"coverage":null`, `"repo":"site"`}},
		{"coverage", `{"repo":"conduit"}`, []string{`"coverage":81.2`, `"misses":150`}},
		{"coverage", `{"repo":"conduit","branch":"dev"}`, []string{`"coverage":70`, `"branch":"dev"`}},
		{"coverage", `{"repo":"conduit","sha":"` + strings.ToUpper(sha) + `"}`, []string{`"coverage":70`}},
		{"commit", `{"repo":"conduit","sha":"` + sha + `"}`, []string{`"message":"Add tests"`, `"ciPassed":true`, `"author":"kim"`, `"sha":"0123456789"`}},
		{"compare", `{"repo":"conduit","pullRequest":7}`, []string{`"change":1.5`, `"patch":92.31`, `"changedFiles":3`, `"files":[{"base":50,"change":25,"file":"a.go"`, `"file":"c.go"`, `"change":-2`}},
		{"compare", `{"repo":"conduit","base":"aaaaaaa","head":"bbbbbbb","files":1}`, []string{`"changedFiles":3`, `"file":"a.go"`}},
	} {
		r, err := invoke(m, c.action, c.in)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		if strings.Contains(string(r.Output), `"file":"b.go"`) {
			t.Fatalf("unchanged file listed: %s", r.Output)
		}
	}
	if r, _ := invoke(m, "compare", `{"repo":"conduit","pullRequest":7,"files":1}`); strings.Contains(string(r.Output), "c.go") {
		t.Fatalf("files limit ignored: %s", r.Output)
	}
	if _, err := invoke(m, "compare", `{"repo":"conduit","pullRequest":8}`); err == nil || !strings.Contains(err.Error(), "pull request #8") {
		t.Fatal(err)
	}
}

func TestCodecovValidation(t *testing.T) {
	m, f := setup(t, "secret://cv")
	for _, c := range []struct{ action, in string }{
		{"coverage", `{"repo":""}`},
		{"coverage", `{"repo":"../x"}`},
		{"coverage", `{"repo":"a/b"}`},
		{"coverage", `{"repo":".."}`},
		{"coverage", `{"repo":"conduit","branch":"a b"}`},
		{"coverage", `{"repo":"conduit","branch":"main","sha":"` + sha + `"}`},
		{"coverage", `{"repo":"conduit","sha":"xyz"}`},
		{"commit", `{"repo":"conduit","sha":"../../me"}`},
		{"commit", `{"repo":"conduit"}`},
		{"compare", `{"repo":"conduit"}`},
		{"compare", `{"repo":"conduit","pullRequest":7,"base":"aaaaaaa"}`},
		{"compare", `{"repo":"conduit","base":"aaaaaaa"}`},
		{"compare", `{"repo":"conduit","pullRequest":7,"files":500}`},
		{"delete_repo", `{"repo":"conduit"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Owner: "elchi", Token: "plain"}, {Service: "sourceforge", Owner: "elchi", Token: "secret://cv"}, {Owner: "../x", Token: "secret://cv"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused the API token") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestCodecovRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Owner: "elchi", Token: "secret://cv"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cv": "cvtok"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestCodecovReadOnly(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Risk != sdk.RiskRead || a.Sensitive {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}
