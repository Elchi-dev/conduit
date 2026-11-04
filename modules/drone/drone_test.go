package drone

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

type fake struct {
	mu        sync.Mutex
	seen      []string
	status    string
	restarted bool
	cancelled bool
	promoted  string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer drtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	build := func(n int, status, target string) string {
		return fmt.Sprintf(`{"id":%d,"number":%d,"status":%q,"event":"push","target":%q,"after":"0123456789abcdef","message":"Fix build\n\nlong body","author_login":"kim","created":1800000000,"started":1800000005,"finished":1800000065,
			"stages":[{"number":1,"name":"default","status":%q,"started":1800000005,"stopped":1800000065,"steps":[{"number":1,"name":"clone","status":"success"},{"number":2,"name":"test","status":"failure","exit_code":2,"started":1800000005,"stopped":1800000060}]},
			{"number":2,"name":"docs","status":"success","steps":[{"number":1,"name":"test","status":"success"}]}]}`, 100+n, n, status, target, status)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /ci/api/user":
		io.WriteString(w, `{"login":"kim","email":"kim@example.com"}`)
	case "GET /ci/api/user/repos":
		io.WriteString(w, `[{"slug":"elchi/old","active":false},{"slug":"elchi/conduit","active":true,"default_branch":"main","link":"https://bot:s3cret@git.example.com/elchi/conduit","build":{"number":42,"status":"failure","target":"main","created":1800000000}}]`)
	case "GET /ci/api/repos/elchi/conduit/builds":
		if r.URL.Query().Get("per_page") != "20" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "["+build(42, f.status, "main")+","+build(41, "success", "dev")+"]")
	case "GET /ci/api/repos/elchi/conduit/builds/42":
		io.WriteString(w, build(42, f.status, "main"))
	case "GET /ci/api/repos/elchi/conduit/builds/42/logs/1/2":
		var lines []string
		for i := 1; i <= 300; i++ {
			lines = append(lines, fmt.Sprintf(`{"pos":%d,"out":"\u001b[31mline %d\u001b[0m\n","time":%d}`, i-1, i, i))
		}
		io.WriteString(w, "["+strings.Join(lines, ",")+"]")
	case "POST /ci/api/repos/elchi/conduit/builds/42":
		f.restarted = true
		w.WriteHeader(201)
		io.WriteString(w, build(43, "pending", "main"))
	case "DELETE /ci/api/repos/elchi/conduit/builds/42":
		f.cancelled = true
		w.WriteHeader(204)
	case "POST /ci/api/repos/elchi/conduit/builds/42/promote":
		f.promoted = r.URL.Query().Get("target")
		io.WriteString(w, build(44, "pending", "main"))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "failure"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/ci/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dr": "drtok", "secret://bad": "x"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDroneReads(t *testing.T) {
	m, _ := setup(t, "secret://dr")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "signed in as kim" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"repos", `{}`, []string{`[{"active":true,"defaultBranch":"main","lastBuild":{"branch":"main","created":"2027-01-15T08:00:00Z","number":42,"status":"failure"},"link":"https://git.example.com/elchi/conduit"`}},
		{"builds", `{"repo":"elchi/conduit"}`, []string{`"message":"Fix build"`, `"duration":"1m0s"`, `"commit":"0123456789"`, `"number":41`, `/ci/elchi/conduit/42"`}},
		{"build", `{"repo":"elchi/conduit","number":42}`, []string{`"exitCode":2`, `"name":"docs"`, `"name":"clone"`}},
		{"logs", `{"repo":"elchi/conduit","number":42,"step":"default/test","lines":3}`, []string{`"lines":["line 298","line 299","line 300"]`, `"truncated":true`, `"totalLines":300`}},
		{"logs", `{"repo":"elchi/conduit","number":42,"step":"1.2","lines":3}`, []string{`"step":"test"`, `"exitCode":2`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		if strings.Contains(string(r.Output), "s3cret") {
			t.Fatalf("leaks: %s", r.Output)
		}
	}
	if r, err := invoke(m, "builds", `{"repo":"elchi/conduit","branch":"dev"}`, false); err != nil || strings.Contains(string(r.Output), `"number":42`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "logs", `{"repo":"elchi/conduit","number":42,"step":"test"}`, false); err == nil || !strings.Contains(err.Error(), "several steps") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "logs", `{"repo":"elchi/conduit","number":42,"step":"deploy"}`, false); err == nil || !strings.Contains(err.Error(), "steps: default/clone, default/test, docs/test") {
		t.Fatal(err)
	}
}

func TestDroneActions(t *testing.T) {
	m, f := setup(t, "secret://dr")
	if _, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, false); err == nil || !strings.Contains(err.Error(), "nothing to cancel") || f.cancelled {
		t.Fatal(err)
	}
	if _, err := invoke(m, "promote", `{"repo":"elchi/conduit","number":42,"target":"production"}`, false); err == nil || f.promoted != "" {
		t.Fatal("promoted a failed build")
	}
	p, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":42}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Run elchi/conduit#42 again (push on main) as a new build" || f.restarted {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":42}`, false); err != nil || !f.restarted || !strings.Contains(string(r.Output), `"number":43`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.status = "success"
	p, err = invoke(m, "promote", `{"repo":"elchi/conduit","number":42,"target":"production"}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "to production") || f.promoted != "" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err := invoke(m, "promote", `{"repo":"elchi/conduit","number":42,"target":"production"}`, false); err != nil || f.promoted != "production" || !strings.Contains(string(r.Output), `"number":44`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.status, f.restarted = "running", false
	if _, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":42}`, false); err == nil || f.restarted {
		t.Fatal("restarted a running build")
	}
	if p, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, true); err != nil || p.Plan == nil || f.cancelled {
		t.Fatal(err)
	}
	if _, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, false); err != nil || !f.cancelled {
		t.Fatal(err)
	}
}

func TestDroneValidation(t *testing.T) {
	m, f := setup(t, "secret://dr")
	for _, c := range []struct{ action, in string }{
		{"builds", `{"repo":""}`},
		{"builds", `{"repo":"conduit"}`},
		{"builds", `{"repo":"../x"}`},
		{"builds", `{"repo":"a/b/c"}`},
		{"builds", `{"repo":"a/.."}`},
		{"builds", `{"repo":"a/b?x=1"}`},
		{"builds", `{"repo":"elchi/conduit","limit":500}`},
		{"builds", `{"repo":"elchi/conduit","branch":"a b"}`},
		{"build", `{"repo":"elchi/conduit","number":0}`},
		{"logs", `{"repo":"elchi/conduit","number":42}`},
		{"logs", `{"repo":"elchi/conduit","number":42,"step":"test","lines":9000}`},
		{"restart", `{"repo":"elchi/conduit","number":-1}`},
		{"promote", `{"repo":"elchi/conduit","number":42,"target":"prod&x=1"}`},
		{"promote", `{"repo":"elchi/conduit","number":42}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://ci", Token: "plain"}, {URL: "ci.example.com", Token: "secret://dr"}, {URL: "https://u:p@ci.example.com", Token: "secret://dr"}, {URL: "https://ci.example.com/?x=1", Token: "secret://dr"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestDroneRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://dr"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dr": "drtok"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestDroneRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "restart", "cancel", "promote":
			want = sdk.RiskDestructive
			if !a.DryRun {
				t.Errorf("%s has no preview", a.Name)
			}
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
		if (a.Name == "logs") != a.Sensitive {
			t.Errorf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
}
