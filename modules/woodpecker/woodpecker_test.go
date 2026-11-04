package woodpecker

import (
	"context"
	"encoding/base64"
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

type fakeWP struct {
	mu        sync.Mutex
	seen      []string
	status    string
	restarted bool
	cancelled bool
}

func (f *fakeWP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer wptok" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	pipe := func(n int, status string) string {
		return fmt.Sprintf(`{"id":%d,"number":%d,"status":%q,"event":"push","branch":"main","commit":"0123456789abcdef","message":"Fix build\n\nlong body","author":"kim","created":1800000000,"started":1800000005,"finished":1800000065,
			"workflows":[{"id":1,"name":"ci","state":%q,"children":[{"id":11,"name":"test","state":"failure","exit_code":1,"started":1800000005,"finished":1800000060},{"id":12,"name":"lint","state":"success"}]}]}`, 100+n, n, status, status)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/user":
		io.WriteString(w, `{"login":"kim"}`)
	case "GET /api/version":
		io.WriteString(w, `{"source":"https://github.com/woodpecker-ci/woodpecker","version":"3.8.0"}`)
	case "GET /api/user/repos":
		io.WriteString(w, `[{"id":2,"full_name":"elchi/old","active":false},{"id":7,"full_name":"elchi/conduit","active":true,"default_branch":"main"}]`)
	case "GET /api/repos/lookup/elchi/conduit":
		io.WriteString(w, `{"id":7,"full_name":"elchi/conduit","active":true}`)
	case "GET /api/repos/7/pipelines":
		if r.URL.Query().Get("perPage") != "20" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "["+pipe(42, f.status)+"]")
	case "GET /api/repos/7/pipelines/42":
		io.WriteString(w, pipe(42, f.status))
	case "GET /api/repos/7/logs/42/11":
		var lines []string
		for i := 1; i <= 300; i++ {
			lines = append(lines, fmt.Sprintf(`{"line":%d,"step_id":11,"data":%q}`, i, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("line %d", i)))))
		}
		io.WriteString(w, "["+strings.Join(lines, ",")+"]")
	case "POST /api/repos/7/pipelines/42":
		f.restarted = true
		io.WriteString(w, pipe(43, "pending"))
	case "POST /api/repos/7/pipelines/42/cancel":
		f.cancelled = true
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeWP) {
	t.Helper()
	f := &fakeWP{status: "failure"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://wp": "wptok", "secret://bad": "x"}), "ci", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "ci", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestWoodpecker(t *testing.T) {
	m, f := setup(t, "secret://wp")
	if h := m.Health(context.Background(), "ci"); h.Status != "ok" || h.Message != "signed in as kim · 3.8.0" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "repos", `{}`, false); err != nil || !strings.HasPrefix(string(r.Output), `[{"active":true,"defaultBranch":"main","forgeUrl":"","private":false,"repo":"elchi/conduit"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "pipelines", `{"repo":"elchi/conduit"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"message":"Fix build"`) || !strings.Contains(string(r.Output), `"duration":"1m0s"`) || !strings.Contains(string(r.Output), `"commit":"0123456789"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "pipeline", `{"repo":"elchi/conduit","number":42}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"exitCode":1`) || !strings.Contains(string(r.Output), `"name":"lint"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, step := range []string{`"test"`, `11`, `"ci/test"`} {
		r, err = invoke(m, "logs", `{"repo":"elchi/conduit","number":42,"step":`+step+`,"lines":5}`, false)
		if err != nil || !strings.Contains(string(r.Output), `"log":"line 296\nline 297\nline 298\nline 299\nline 300\n"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
			t.Fatalf("%s: %s %v", step, r.Output, err)
		}
	}
	if _, err := invoke(m, "logs", `{"repo":"elchi/conduit","number":42,"step":"deploy"}`, false); err == nil || !strings.Contains(err.Error(), "steps: test, lint") {
		t.Fatal(err)
	}

	if _, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, false); err == nil || !strings.Contains(err.Error(), "nothing to cancel") {
		t.Fatal(err)
	}
	p, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":42}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Run elchi/conduit#42 again (push on main) as a new pipeline" || f.restarted {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":42}`, false); err != nil || !f.restarted || !strings.Contains(string(r.Output), `"number":43`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.status = "running"
	if p, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, true); err != nil || p.Plan == nil || f.cancelled {
		t.Fatal(err)
	}
	if _, err := invoke(m, "cancel", `{"repo":"elchi/conduit","number":42}`, false); err != nil || !f.cancelled {
		t.Fatal(err)
	}
}

func TestWoodpeckerValidation(t *testing.T) {
	m, f := setup(t, "secret://wp")
	for _, repo := range []string{"", "conduit", "../x", "a/b/c", "a/..", "a b/c", "a/b?x=1", "../../user"} {
		in, _ := json.Marshal(map[string]any{"repo": repo, "number": 1})
		if _, err := invoke(m, "pipelines", string(in), false); err == nil {
			t.Fatalf("accepted %q", repo)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "restart", `{"repo":"elchi/conduit","number":0}`, false); err == nil || f.restarted {
		t.Fatal("accepted number 0")
	}
	for _, c := range []Config{{URL: "https://ci", Token: "plain"}, {URL: "ci.example.com", Token: "secret://wp"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "ci"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

// Cancelling kills the steps in progress: destructive.
func TestWoodpeckerRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Name == "cancel" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("cancel is %s", a.Risk)
		}
	}
}
