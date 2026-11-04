package bitbucket

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
	pipeUUID = "{11111111-2222-3333-4444-555555555555}"
	stepOK   = "{aaaaaaaa-0000-0000-0000-000000000001}"
	stepBad  = "{aaaaaaaa-0000-0000-0000-000000000002}"
)

type fake struct {
	mu        sync.Mutex
	seen      []string
	approved  bool
	state     string
	stopped   bool
	runs      []string
	storage   string // log storage URL to redirect to
	storeAuth string
}

func (f *fake) pr() map[string]any {
	parts := []any{map[string]any{"user": map[string]any{"display_name": "Ana"}, "role": "REVIEWER", "state": "changes_requested"}}
	if f.approved {
		parts = append(parts, map[string]any{"user": map[string]any{"display_name": "Me"}, "role": "PARTICIPANT", "approved": true, "state": "approved"})
	}
	return map[string]any{"id": 7, "title": "Add cache", "description": "Adds a cache", "state": f.state, "author": map[string]any{"display_name": "Bo"},
		"source":      map[string]any{"branch": map[string]any{"name": "feature/cache"}, "commit": map[string]any{"hash": "abcdef1234567890"}},
		"destination": map[string]any{"branch": map[string]any{"name": "main", "default_merge_strategy": "squash", "merge_strategies": []string{"merge_commit", "squash"}}},
		"task_count":  2, "comment_count": 3, "participants": parts, "links": map[string]any{"html": map[string]any{"href": "https://bitbucket.org/acme/web/pull-requests/7"}}}
}

func (f *fake) pipeline() map[string]any {
	st := map[string]any{"name": "IN_PROGRESS", "stage": map[string]any{"name": "RUNNING"}}
	if f.stopped {
		st = map[string]any{"name": "COMPLETED", "result": map[string]any{"name": "STOPPED"}}
	}
	return map[string]any{"uuid": pipeUUID, "build_number": 42, "state": st, "created_on": "2026-11-04T10:00:00Z", "creator": map[string]any{"display_name": "Bo"},
		"target": map[string]any{"ref_name": "main", "commit": map[string]any{"hash": "0123456789abcdef"}}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "me@example.com" || p != "bbtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"error","error":{"message":"Unauthorized"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	rp := "/repositories/acme/web"
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /repositories/acme":
		io.WriteString(w, `{"size":1,"values":[{"slug":"web","name":"Web","is_private":true,"mainbranch":{"name":"main"},"project":{"key":"WEB"}}]}`)
	case "GET " + rp + "/pullrequests":
		enc.Encode(map[string]any{"values": []any{f.pr()}})
	case "GET " + rp + "/pullrequests/7":
		enc.Encode(f.pr())
	case "GET " + rp + "/pullrequests/7/diffstat":
		io.WriteString(w, `{"values":[{"status":"modified","lines_added":10,"lines_removed":2},{"status":"merge conflict","lines_added":1,"lines_removed":1}]}`)
	case "POST " + rp + "/pullrequests/7/comments":
		io.WriteString(w, `{"id":99,"links":{"html":{"href":"https://x/99"}}}`)
	case "POST " + rp + "/pullrequests/7/approve":
		f.approved = true
		io.WriteString(w, `{"approved":true}`)
	case "DELETE " + rp + "/pullrequests/7/approve":
		f.approved = false
		w.WriteHeader(204)
	case "POST " + rp + "/pullrequests/7/merge":
		f.state = "MERGED"
		pr := f.pr()
		pr["merge_commit"] = map[string]any{"hash": "fedcba9876543210"}
		enc.Encode(pr)
	case "POST " + rp + "/pullrequests/7/decline":
		f.state = "DECLINED"
		enc.Encode(f.pr())
	case "GET " + rp + "/pipelines":
		enc.Encode(map[string]any{"values": []any{f.pipeline()}})
	case "POST " + rp + "/pipelines":
		f.runs = append(f.runs, string(body))
		io.WriteString(w, `{"uuid":"{99999999-2222-3333-4444-555555555555}","build_number":43,"state":{"name":"PENDING"}}`)
	case "GET " + rp + "/pipelines/%7B11111111-2222-3333-4444-555555555555%7D":
		enc.Encode(f.pipeline())
	case "GET " + rp + "/pipelines/%7B11111111-2222-3333-4444-555555555555%7D/steps":
		io.WriteString(w, `{"values":[{"uuid":"`+stepOK+`","name":"Build","state":{"name":"COMPLETED","result":{"name":"SUCCESSFUL"}},"started_on":"x"},{"uuid":"`+stepBad+`","name":"Test","state":{"name":"COMPLETED","result":{"name":"FAILED"}},"started_on":"y"}]}`)
	case "GET " + rp + "/pipelines/%7B11111111-2222-3333-4444-555555555555%7D/steps/%7Baaaaaaaa-0000-0000-0000-000000000001%7D/log":
		w.Header().Set("Content-Range", "bytes 0-20/21")
		w.WriteHeader(206)
		io.WriteString(w, "line one\n\x1b[32mok\x1b[0m\n")
	case "GET " + rp + "/pipelines/%7B11111111-2222-3333-4444-555555555555%7D/steps/%7Baaaaaaaa-0000-0000-0000-000000000002%7D/log":
		http.Redirect(w, r, f.storage+"/log", http.StatusTemporaryRedirect)
	case "POST " + rp + "/pipelines/%7B11111111-2222-3333-4444-555555555555%7D/stopPipeline":
		f.stopped = true
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"type":"error","error":{"message":"not found"}}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{state: "OPEN"}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	store := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.storeAuth = r.Header.Get("Authorization")
		f.mu.Unlock()
		w.WriteHeader(206)
		w.Header().Set("Content-Range", "bytes 100-200/200")
		io.WriteString(w, "partial first\n+ npm test\nFAIL app.test.js\n")
	}))
	t.Cleanup(store.Close)
	f.storage = store.URL
	m := New()
	m.Base = srv.URL
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Workspace: "acme", Username: "me@example.com", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bb": "bbtok", "secret://bad": "nope"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBitbucketReads(t *testing.T) {
	m, _ := setup(t, "secret://bb")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || !strings.Contains(h.Message, "1 repositories") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"repositories", `{"search":"we"}`, `"mainBranch":"main"`},
		{"pull_requests", `{"repo":"web"}`, `"source":"feature/cache"`},
		{"pull_request", `{"repo":"acme/Web","id":7}`, `"changesRequestedBy":["Ana"]`},
		{"pull_request", `{"repo":"web","id":7}`, `"conflictedFiles":1`},
		{"pipelines", `{"repo":"web"}`, `"status":"running"`},
		{"pipeline", `{"repo":"web","pipeline":42}`, `"started":"y","status":"failed"`},
		{"pipeline", `{"repo":"web","pipeline":"11111111-2222-3333-4444-555555555555"}`, `"number":42`},
		{"pipeline_log", `{"repo":"web","pipeline":"#42","step":"Build"}`, `"lines":["line one","ok"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestBitbucketLogFromStorage(t *testing.T) {
	m, f := setup(t, "secret://bb")
	r, err := invoke(m, "pipeline_log", `{"repo":"web","pipeline":42}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"lines":["+ npm test","FAIL app.test.js"]`) || !strings.Contains(string(r.Output), `"step":"Test"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if f.storeAuth != "" {
		t.Fatalf("credentials sent to log storage: %q", f.storeAuth)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "pipeline_log" && !a.Sensitive {
			t.Fatal("logs must be sensitive")
		}
	}
}

func TestBitbucketWrites(t *testing.T) {
	m, f := setup(t, "secret://bb")
	if r, err := invoke(m, "comment", `{"repo":"web","id":7,"text":"LGTM"}`, true); err != nil || r.Plan == nil || len(f.seen) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "comment", `{"repo":"web","id":7,"text":"LGTM"}`, false); err != nil || !strings.Contains(string(r.Output), `"comment":99`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "approve", `{"repo":"web","id":7}`, false)
	if err != nil || !f.approved || r.Undo == nil || r.Undo.Action != "unapprove" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.approved {
		t.Fatal(err)
	}

	// Merge preview: default strategy, change requests, tasks, conflicts.
	r, err = invoke(m, "merge", `{"repo":"web","id":7}`, true)
	if err != nil || r.Plan == nil || f.state != "OPEN" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, want := range []string{"feature/cache → main (squash)", "CHANGES REQUESTED by Ana", "2 open task(s)", "1 file(s) have conflicts"} {
		if !strings.Contains(r.Plan.Summary, want) {
			t.Fatalf("preview lacks %q: %s", want, r.Plan.Summary)
		}
	}
	if _, err := invoke(m, "merge", `{"repo":"web","id":7,"strategy":"fast_forward"}`, true); err == nil || !strings.Contains(err.Error(), "doesn't allow") {
		t.Fatal(err)
	}
	r, err = invoke(m, "merge", `{"repo":"web","id":7,"closeSourceBranch":true}`, false)
	if err != nil || f.state != "MERGED" || !strings.Contains(string(r.Output), `"mergeCommit":"fedcba987654"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `"merge_strategy":"squash"`) || !strings.Contains(f.seen[len(f.seen)-1], `"close_source_branch":true`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, "decline", `{"repo":"web","id":7}`, false); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatal(err)
	}
	f.state = "OPEN"
	if r, err := invoke(m, "decline", `{"repo":"web","id":7}`, true); err != nil || r.Plan == nil || f.state != "OPEN" || !strings.Contains(r.Plan.Summary, "can't be reopened") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "decline", `{"repo":"web","id":7}`, false); err != nil || f.state != "DECLINED" {
		t.Fatal(err)
	}

	// Pipelines.
	if r, err := invoke(m, "run_pipeline", `{"repo":"web","branch":"main","custom":"deploy","variables":{"ENV":"prod"}}`, true); err != nil || r.Plan == nil || len(f.runs) != 0 || !strings.Contains(string(r.Plan.Changes[0].After), `"ENV":"prod"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "run_pipeline", `{"repo":"web","branch":"main","custom":"deploy","variables":{"ENV":"prod"}}`, false); err != nil || len(f.runs) != 1 || !strings.Contains(string(r.Output), `"pipeline":43`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.runs[0], `"selector":{"pattern":"deploy","type":"custom"}`) || !strings.Contains(f.runs[0], `{"key":"ENV","value":"prod"}`) {
		t.Fatal(f.runs[0])
	}
	if r, err := invoke(m, "stop_pipeline", `{"repo":"web","pipeline":42}`, true); err != nil || r.Plan == nil || f.stopped {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "stop_pipeline", `{"repo":"web","pipeline":42}`, false); err != nil || !f.stopped {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop_pipeline", `{"repo":"web","pipeline":42}`, false); err == nil || !strings.Contains(err.Error(), "already finished") {
		t.Fatal(err)
	}
	risks := map[string]sdk.Risk{"merge": sdk.RiskDestructive, "decline": sdk.RiskDestructive, "run_pipeline": sdk.RiskDestructive, "stop_pipeline": sdk.RiskWrite, "comment": sdk.RiskWrite, "approve": sdk.RiskWrite}
	for _, a := range m.Manifest().Actions {
		if want, ok := risks[a.Name]; ok && (a.Risk != want || !a.DryRun) {
			t.Fatalf("%s: %s dry=%v", a.Name, a.Risk, a.DryRun)
		}
	}
}

func TestBitbucketValidation(t *testing.T) {
	m, f := setup(t, "secret://bb")
	for _, c := range []struct{ action, in string }{
		{"pull_requests", `{"repo":"../x"}`},
		{"pull_requests", `{"repo":"other/web"}`},
		{"pull_requests", `{"repo":"acme/web/x"}`},
		{"pull_requests", `{"repo":"web?x=1"}`},
		{"pull_requests", `{"repo":"web","state":"ALL"}`},
		{"pull_request", `{"repo":"web","id":0}`},
		{"pull_request", `{"repo":"..","id":1}`},
		{"pipeline", `{"repo":"web","pipeline":"../../x"}`},
		{"pipeline", `{"repo":"web","pipeline":"{1111}"}`},
		{"comment", `{"repo":"web","id":7,"text":"  "}`},
		{"merge", `{"repo":"web","id":7,"strategy":"octopus"}`},
		{"run_pipeline", `{"repo":"web","branch":"../main"}`},
		{"run_pipeline", `{"repo":"web","branch":"-x"}`},
		{"run_pipeline", `{"repo":"web","branch":"main","variables":{"A":"b"}}`},
		{"run_pipeline", `{"repo":"web","branch":"main","custom":"d","variables":{"bad-key":"b"}}`},
		{"repositories", `{"search":"x\" OR name ~ \""}`},
		{"pipeline_log", `{"repo":"web","pipeline":42,"lines":5000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Workspace: "acme", Token: "plain"}, {Workspace: "../x", Token: "secret://bb"}, {Workspace: "acme", Username: "a:b", Token: "secret://bb"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
}

func TestBitbucketBearerToken(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.WriteString(w, `{"size":3}`)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Workspace: "acme", Token: "secret://bb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bb": "at"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || auth != "Bearer at" {
		t.Fatalf("%+v %q", h, auth)
	}
}

func TestBitbucketRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Workspace: "acme", Token: "secret://bb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bb": "x"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "pull_requests", `{"repo":"web"}`, false); err == nil || hit {
		t.Fatalf("followed the redirect: %v", err)
	}
}
