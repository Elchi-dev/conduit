package github

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
	calls []string
	state string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer ghp_test" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /user":
		w.Header().Set("X-RateLimit-Remaining", "4999")
		io.WriteString(w, `{"login":"octo"}`)
	case "GET /repos/acme/app/pulls":
		io.WriteString(w, `[{"number":7,"title":"Fix login","user":{"login":"sam"},"draft":false,"updated_at":"2026-11-01T10:00:00Z","html_url":"https://github.com/acme/app/pull/7"}]`)
	case "GET /repos/acme/app/issues":
		io.WriteString(w, `[{"number":3,"title":"Crash","state":"open","user":{"login":"kim"},"labels":[{"name":"bug"}]},{"number":7,"title":"Fix login","pull_request":{}}]`)
	case "GET /repos/acme/app/actions/runs":
		io.WriteString(w, `{"workflow_runs":[{"id":99,"name":"ci","head_branch":"main","event":"push","status":"completed","conclusion":"failure"}]}`)
	case "POST /repos/acme/app/issues":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		io.WriteString(w, `{"number":12,"title":"`+b["title"].(string)+`","state":"open","html_url":"u"}`)
	case "PATCH /repos/acme/app/issues/12":
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		f.state = b["state"]
		io.WriteString(w, `{"number":12,"title":"t","state":"`+b["state"]+`"}`)
	case "GET /repos/acme/app/pulls/7":
		io.WriteString(w, `{"title":"Fix login","state":"open","mergeable":true,"mergeable_state":"clean","base":{"ref":"main"},"head":{"ref":"fix","sha":"abc123"},"commits":2}`)
	case "PUT /repos/acme/app/pulls/7/merge":
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["sha"] != "abc123" || b["merge_method"] != "squash" {
			w.WriteHeader(409)
			io.WriteString(w, `{"message":"Head branch was modified"}`)
			return
		}
		io.WriteString(w, `{"merged":true,"sha":"def456"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://gh", API: srv.URL, Repos: []string{"acme/app"}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gh": "ghp_test"}), "gh", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(t *testing.T, m *Module, action string, input any, dry bool) sdk.Result {
	t.Helper()
	b, _ := json.Marshal(input)
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: action, Input: b, DryRun: dry})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestReads(t *testing.T) {
	m, _ := setup(t)
	if h := m.Health(context.Background(), "gh"); h.Status != "ok" || h.Message != "Signed in as octo" {
		t.Fatalf("health %+v", h)
	}
	var prs []PR
	json.Unmarshal(call(t, m, "pull_requests", nil, false).Output, &prs)
	if len(prs) != 1 || prs[0].Repo != "acme/app" || prs[0].Author != "sam" {
		t.Fatalf("prs %+v", prs)
	}
	var issues []Issue
	json.Unmarshal(call(t, m, "issues", nil, false).Output, &issues)
	if len(issues) != 1 || issues[0].Labels != "bug" {
		t.Fatalf("pull requests must be filtered out of issues: %+v", issues)
	}
	var runs []Run
	json.Unmarshal(call(t, m, "runs", map[string]any{"repo": "acme/app"}, false).Output, &runs)
	if len(runs) != 1 || runs[0].Conclusion != "failure" {
		t.Fatalf("runs %+v", runs)
	}
}

func TestWritesAndUndo(t *testing.T) {
	m, f := setup(t)
	r := call(t, m, "create_issue", map[string]any{"repo": "acme/app", "title": "Disk full"}, false)
	if r.Undo == nil || r.Undo.Action != "close_issue" {
		t.Fatalf("undo %+v", r.Undo)
	}
	var u map[string]any
	json.Unmarshal(r.Undo.Input, &u)
	r2 := call(t, m, r.Undo.Action, u, false)
	if f.state != "closed" || r2.Undo.Action != "reopen_issue" {
		t.Fatalf("state %s undo %+v", f.state, r2.Undo)
	}
}

func TestMerge(t *testing.T) {
	m, f := setup(t)
	plan := call(t, m, "merge", map[string]any{"repo": "acme/app", "number": 7}, true)
	if plan.Plan == nil || !strings.Contains(plan.Plan.Summary, "Fix login") {
		t.Fatalf("plan %+v", plan.Plan)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "PUT") {
			t.Fatal("a dry run must not merge")
		}
	}
	var out map[string]any
	json.Unmarshal(call(t, m, "merge", map[string]any{"repo": "acme/app", "number": 7}, false).Output, &out)
	if out["merged"] != true {
		t.Fatalf("merge %v", out)
	}
}

func TestErrors(t *testing.T) {
	m := New()
	srv := httptest.NewServer(&fake{})
	defer srv.Close()
	cfg, _ := json.Marshal(Config{Token: "secret://gh", API: srv.URL})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gh": "wrong"}), "gh", cfg)
	if h := m.Health(context.Background(), "gh"); h.Status != "down" || h.Message != "Bad credentials" {
		t.Fatalf("health %+v", h)
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: "issues"}); err == nil || !strings.Contains(err.Error(), "watch") {
		t.Fatalf("issues without repos: %v", err)
	}
	if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"token":"t","repos":["nope"]}`)); err == nil {
		t.Fatal("bad repo name accepted")
	}
}
