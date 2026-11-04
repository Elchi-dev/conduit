package circleci

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
	wfID  = "5034460f-c7c4-4c43-9457-de07e2029e7b"
	newWF = "11111111-2222-3333-4444-555555555555"
	plID  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type fake struct {
	mu        sync.Mutex
	seen      []string
	status    string
	rerunBody string
	cancelled bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Circle-Token") != "cctok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"You must log in first."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	q := r.URL.Query()
	wf := `{"id":"` + wfID + `","name":"build-and-test","status":"` + f.status + `","pipeline_id":"` + plID + `","pipeline_number":42,"project_slug":"gh/elchi/conduit","created_at":"2026-11-04T10:00:00Z","stopped_at":"2026-11-04T10:03:30Z"}`
	switch r.Method + " " + r.URL.Path {
	case "GET /me":
		io.WriteString(w, `{"id":"u1","login":"kim","name":"Kim"}`)
	case "GET /project/gh/elchi/conduit/pipeline":
		if q.Get("page-token") == "" {
			io.WriteString(w, `{"items":[{"id":"`+plID+`","number":42,"state":"created","created_at":"2026-11-04T10:00:00Z","trigger":{"type":"webhook","actor":{"login":"kim"}},"vcs":{"branch":"`+q.Get("branch")+`","revision":"0123456789abcdef","commit":{"subject":"Fix build\nbody"}}}],"next_page_token":"p2"}`)
			return
		}
		io.WriteString(w, `{"items":[{"id":"bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee","number":41,"state":"errored","errors":[{"type":"config","message":"Config does not conform"}]}],"next_page_token":null}`)
	case "GET /project/gh/elchi/conduit/pipeline/42", "GET /pipeline/" + plID:
		io.WriteString(w, `{"id":"`+plID+`","number":42,"project_slug":"gh/elchi/conduit","state":"created","vcs":{"branch":"main"}}`)
	case "GET /pipeline/" + plID + "/workflow":
		io.WriteString(w, `{"items":[`+wf+`],"next_page_token":null}`)
	case "GET /workflow/" + wfID:
		io.WriteString(w, wf)
	case "GET /workflow/" + wfID + "/job":
		io.WriteString(w, `{"items":[{"id":"j1","job_number":7,"name":"test","status":"failed","type":"build","started_at":"2026-11-04T10:00:10Z","stopped_at":"2026-11-04T10:02:10Z"},{"id":"j2","name":"hold","status":"on_hold","type":"approval"}]}`)
	case "POST /workflow/" + wfID + "/rerun":
		b, _ := io.ReadAll(r.Body)
		f.rerunBody = string(b)
		io.WriteString(w, `{"workflow_id":"`+newWF+`"}`)
	case "POST /workflow/" + wfID + "/cancel":
		f.cancelled = true
		w.WriteHeader(202)
		io.WriteString(w, `{"message":"Accepted."}`)
	case "GET /insights/gh/elchi/conduit/workflows":
		if q.Get("reporting-window") != "last-7-days" || q.Get("branch") != "main" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"name":"build-and-test","metrics":{"success_rate":0.875,"total_runs":40,"failed_runs":5,"successful_runs":35,"throughput":5.714,"mttr":1800,"total_credits_used":12000,"duration_metrics":{"min":60,"mean":200,"median":190,"p95":420,"max":600}}}],"next_page_token":null}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "failed"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cc": "cctok", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCircleCIReads(t *testing.T) {
	m, _ := setup(t, "secret://cc")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "signed in as kim" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"pipelines", `{"project":"gh/elchi/conduit","branch":"main"}`, []string{`"subject":"Fix build"`, `"commit":"0123456789"`, `"branch":"main"`, `"number":41`, `"error":"Config does not conform"`}},
		{"pipelines", `{"project":"gh/elchi/conduit","limit":1}`, []string{`"number":42`}},
		{"workflows", `{"project":"gh/elchi/conduit","number":42}`, []string{`"name":"build-and-test"`, `"duration":"3m30s"`}},
		{"workflows", `{"pipeline":"` + plID + `"}`, []string{`"status":"failed"`}},
		{"jobs", `{"workflow":"` + wfID + `"}`, []string{`"number":7`, `"duration":"2m0s"`, `"type":"approval"`}},
		{"insights", `{"project":"gh/elchi/conduit","branch":"main","window":"last-7-days"}`, []string{`"successPercent":87.5`, `"durationMedian":"3m10s"`, `"durationP95":"7m0s"`, `"mttr":"30m0s"`, `"runs":40`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
	}
	if r, _ := invoke(m, "pipelines", `{"project":"gh/elchi/conduit","limit":1}`, false); strings.Contains(string(r.Output), `"number":41`) {
		t.Fatalf("limit ignored: %s", r.Output)
	}
}

func TestCircleCIRerunCancel(t *testing.T) {
	m, f := setup(t, "secret://cc")
	p, err := invoke(m, "rerun_workflow", `{"workflow":"`+wfID+`","fromFailed":true}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Run the failed jobs of gh/elchi/conduit #42 build-and-test again as a new workflow" || f.rerunBody != "" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "rerun_workflow", `{"workflow":"`+wfID+`","fromFailed":true}`, false)
	if err != nil || f.rerunBody != `{"from_failed":true}` || !strings.Contains(string(r.Output), newWF) {
		t.Fatalf("%s %v %s", r.Output, err, f.rerunBody)
	}
	if _, err := invoke(m, "cancel_workflow", `{"workflow":"`+wfID+`"}`, false); err == nil || !strings.Contains(err.Error(), "nothing to cancel") || f.cancelled {
		t.Fatal(err)
	}
	f.status = "success"
	if _, err := invoke(m, "rerun_workflow", `{"workflow":"`+wfID+`","fromFailed":true}`, false); err == nil || !strings.Contains(err.Error(), "no job failed") {
		t.Fatal(err)
	}
	f.status = "running"
	f.rerunBody = ""
	if _, err := invoke(m, "rerun_workflow", `{"workflow":"`+wfID+`"}`, false); err == nil || f.rerunBody != "" {
		t.Fatal("reran a running workflow")
	}
	if p, err := invoke(m, "cancel_workflow", `{"workflow":"`+wfID+`"}`, true); err != nil || p.Plan == nil || f.cancelled || !strings.HasPrefix(p.Plan.Summary, "Cancel gh/elchi/conduit #42") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "cancel_workflow", `{"workflow":"`+wfID+`"}`, false); err != nil || !f.cancelled {
		t.Fatal(err)
	}
}

func TestCircleCIValidation(t *testing.T) {
	m, f := setup(t, "secret://cc")
	for _, c := range []struct{ action, in string }{
		{"pipelines", `{"project":""}`},
		{"pipelines", `{"project":"elchi/conduit"}`},
		{"pipelines", `{"project":"xx/elchi/conduit"}`},
		{"pipelines", `{"project":"gh/../me"}`},
		{"pipelines", `{"project":"gh/elchi/conduit/x"}`},
		{"pipelines", `{"project":"gh/elchi/a?b"}`},
		{"pipelines", `{"project":"gh/elchi/conduit","limit":500}`},
		{"pipelines", `{"project":"gh/elchi/conduit","branch":"a b"}`},
		{"workflows", `{"project":"gh/elchi/conduit","number":0}`},
		{"workflows", `{"pipeline":"../me"}`},
		{"jobs", `{"workflow":"../../me"}`},
		{"rerun_workflow", `{"workflow":"5034460f"}`},
		{"cancel_workflow", `{}`},
		{"insights", `{"project":"gh/elchi/conduit","window":"forever"}`},
		{"insights", `{"project":"gh/elchi/conduit","branch":"main","allBranches":true}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	raw, _ := json.Marshal(Config{Token: "plain-token"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "pipelines", `{"project":"gh/elchi/conduit"}`, false); err == nil || !strings.Contains(err.Error(), "refused the API token") {
		t.Fatal(err)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestCircleCIRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://cc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cc": "cctok"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// Rerunning runs code with the project's secrets and cancelling kills jobs:
// both destructive.
func TestCircleCIRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		if a.Name == "rerun_workflow" || a.Name == "cancel_workflow" {
			want = sdk.RiskDestructive
			if !a.DryRun {
				t.Errorf("%s has no preview", a.Name)
			}
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}
