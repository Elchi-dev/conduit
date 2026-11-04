package gitea

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
)

type fakeActions struct {
	mu        sync.Mutex
	seen      []string
	old       bool // a server without jobs, logs and rerun (Forgejo, older Gitea)
	rerun     string
	dispatch  string
	logLength int
}

func (f *fakeActions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token gtok" {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	rp := "/api/v1/repos/elchi/conduit/actions"
	switch r.Method + " " + r.URL.Path {
	case "GET " + rp + "/runs/9":
		io.WriteString(w, `{"id":9,"run_number":31,"display_title":"Fix build","path":"ci.yml@refs/heads/main","event":"push","status":"completed","conclusion":"failure","head_branch":"main","html_url":"https://git/elchi/conduit/actions/runs/31"}`)
		return
	case "POST " + rp + "/workflows/deploy.yml/dispatches":
		f.dispatch = string(body)
		w.WriteHeader(204)
		return
	}
	if f.old {
		w.WriteHeader(404)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET " + rp + "/runs/9/jobs":
		io.WriteString(w, `{"jobs":[{"id":77,"name":"test","status":"completed","conclusion":"failure","steps":[{"number":1,"name":"go test","status":"completed","conclusion":"failure"}]}],"total_count":1}`)
	case "GET " + rp + "/jobs/77/logs":
		var b strings.Builder
		for i := 1; i <= f.logLength; i++ {
			fmt.Fprintf(&b, "2026-11-04T10:00:00Z line %d\n", i)
		}
		io.WriteString(w, b.String())
	case "POST " + rp + "/runs/9/rerun", "POST " + rp + "/runs/9/rerun-failed-jobs":
		f.rerun = r.URL.Path
		w.WriteHeader(201)
		io.WriteString(w, `{"id":9,"run_attempt":2}`)
	default:
		w.WriteHeader(404)
	}
}

func setupActions(t *testing.T) (*Module, *fakeActions) {
	t.Helper()
	f := &fakeActions{logLength: 500}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://g"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://g": "gtok"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func TestGiteaActions(t *testing.T) {
	m, f := setupActions(t)
	r, err := invoke(m, "run", `{"repo":"elchi/conduit","id":9}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"conclusion":"failure"`) || !strings.Contains(string(r.Output), `"name":"go test"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "job_log", `{"repo":"elchi/conduit","job":77,"lines":3}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"log":"2026-11-04T10:00:00Z line 498\n2026-11-04T10:00:00Z line 499\n2026-11-04T10:00:00Z line 500\n"`) || !strings.Contains(string(r.Output), `"lines":500`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	p, err := invoke(m, "rerun", `{"repo":"elchi/conduit","id":9,"failedOnly":true}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != `Rerun the failed jobs of "Fix build" (ci.yml@refs/heads/main on main)` || f.rerun != "" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "rerun", `{"repo":"elchi/conduit","id":9,"failedOnly":true}`, false); err != nil || !strings.HasSuffix(f.rerun, "/rerun-failed-jobs") {
		t.Fatal(err, f.rerun)
	}

	in := `{"repo":"elchi/conduit","workflow":"deploy.yml","ref":"main","inputs":{"env":"prod"}}`
	if p, err := invoke(m, "dispatch_workflow", in, true); err != nil || p.Plan == nil || p.Plan.Summary != "Start elchi/conduit deploy.yml on main" || f.dispatch != "" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "dispatch_workflow", in, false); err != nil || f.dispatch != `{"inputs":{"env":"prod"},"ref":"main"}` {
		t.Fatal(err, f.dispatch)
	}

	// Older servers: the run without jobs, and clear messages.
	f.old = true
	if r, err := invoke(m, "run", `{"repo":"elchi/conduit","id":9}`, false); err != nil || !strings.Contains(string(r.Output), `"note"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "rerun", `{"repo":"elchi/conduit","id":9}`, false); err == nil || !strings.Contains(err.Error(), "Gitea 1.27") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "job_log", `{"repo":"elchi/conduit","job":77}`, false); err == nil || !strings.Contains(err.Error(), "1.23") {
		t.Fatal(err)
	}

	f.seen = nil
	for action, in := range map[string][]string{
		"dispatch_workflow": {
			`{"repo":"elchi/conduit","workflow":"../../../admin.yml","ref":"main"}`,
			`{"repo":"elchi/conduit","workflow":"deploy","ref":"main"}`,
			`{"repo":"elchi/conduit","workflow":"deploy.yml","ref":"../main"}`,
			`{"repo":"elchi/conduit","workflow":"deploy.yml","ref":"-x"}`,
			`{"repo":"elchi/conduit","workflow":"deploy.yml","ref":"main","inputs":{"a b":"x"}}`,
		},
		"run":     {`{"repo":"elchi/conduit","id":0}`, `{"repo":"../x","id":9}`},
		"job_log": {`{"repo":"elchi/conduit","job":0}`},
		"rerun":   {`{"repo":"elchi/conduit"}`},
	} {
		for _, x := range in {
			if _, err := invoke(m, action, x, false); err == nil {
				t.Fatalf("%s accepted %s", action, x)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
}

func TestTailLines(t *testing.T) {
	out, total, cut := tailLines("a\nb\nc\n", 2)
	if out != "b\nc\n" || total != 3 || !cut {
		t.Fatal(out, total, cut)
	}
	big := strings.Repeat(strings.Repeat("x", 1000)+"\n", 1000)
	if out, _, cut := tailLines(big, 2000); len(out) > maxLogBytes || !cut || !strings.HasPrefix(out, "x") {
		t.Fatal(len(out), cut)
	}
}
