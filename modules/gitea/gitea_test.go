package gitea

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

type fakeGitea struct {
	mu       sync.Mutex
	seen     []string
	closed   bool
	merged   bool
	comments map[string]bool
}

func (f *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token gtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"token is required"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/user":
		io.WriteString(w, `{"login":"elchi"}`)
	case "GET /api/v1/version":
		io.WriteString(w, `{"version":"1.23.1"}`)
	case "GET /api/v1/user/repos":
		io.WriteString(w, `[{"full_name":"elchi/conduit","open_issues_count":2,"default_branch":"main"}]`)
	case "GET /api/v1/repos/elchi/conduit/pulls":
		io.WriteString(w, `[{"number":7,"title":"Add S3","user":{"login":"sam"},"base":{"ref":"main"},"head":{"ref":"s3"},"mergeable":true,"labels":[{"name":"feature"}]}]`)
	case "GET /api/v1/repos/elchi/conduit/issues":
		if r.URL.Query().Get("type") != "issues" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"number":3,"title":"Bug","user":{"login":"kim"}}]`)
	case "GET /api/v1/repos/elchi/conduit/actions/runs":
		io.WriteString(w, `{"workflow_runs":[{"id":1,"display_title":"CI","status":"completed","conclusion":"success"}],"total_count":1}`)
	case "POST /api/v1/repos/elchi/conduit/issues":
		io.WriteString(w, `{"number":12,"html_url":"https://git/elchi/conduit/issues/12","state":"open"}`)
	case "PATCH /api/v1/repos/elchi/conduit/issues/12":
		f.closed = strings.Contains(string(body), `"closed"`)
		st := "open"
		if f.closed {
			st = "closed"
		}
		io.WriteString(w, `{"number":12,"state":"`+st+`"}`)
	case "POST /api/v1/repos/elchi/conduit/issues/12/comments":
		f.comments["55"] = true
		io.WriteString(w, `{"id":55,"html_url":"https://git/c/55"}`)
	case "GET /api/v1/repos/elchi/conduit/issues/comments/55":
		if !f.comments["55"] {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"id":55,"body":"hi","user":{"login":"elchi"},"html_url":"https://git/c/55"}`)
	case "DELETE /api/v1/repos/elchi/conduit/issues/comments/55":
		delete(f.comments, "55")
		w.WriteHeader(204)
	case "GET /api/v1/repos/elchi/conduit/pulls/7":
		io.WriteString(w, `{"number":7,"title":"Add S3","state":"open","merged":`+map[bool]string{true: "true", false: "false"}[f.merged]+`,"base":{"ref":"main"},"head":{"ref":"s3"},"mergeable":true}`)
	case "POST /api/v1/repos/elchi/conduit/pulls/7/merge":
		f.merged = true
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGitea) {
	f := &fakeGitea{comments: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://g": "gtok", "secret://bad": "x"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGitea(t *testing.T) {
	m, f := setup(t, "secret://g")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "signed in as elchi · 1.23.1" {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{"pulls": `"head":"s3"`, "issues": `"title":"Bug"`, "runs": `"conclusion":"success"`} {
		r, err := invoke(m, action, `{"repo":"elchi/conduit"}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}
	if r, err := invoke(m, "repos", `{}`, false); err != nil || !strings.Contains(string(r.Output), "elchi/conduit") {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err := invoke(m, "create_issue", `{"repo":"elchi/conduit","title":"New"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "close_issue" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.closed || r.Undo.Action != "reopen_issue" {
		t.Fatalf("close %+v %v", r, err)
	}

	r, err = invoke(m, "comment", `{"repo":"elchi/conduit","number":12,"body":"hi"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_comment" {
		t.Fatalf("%+v %v", r, err)
	}
	if p, err := invoke(m, "delete_comment", string(r.Undo.Input), true); err != nil || p.Plan == nil || !f.comments["55"] {
		t.Fatalf("dry %+v %v", p, err)
	}
	if _, err := invoke(m, "delete_comment", string(r.Undo.Input), false); err != nil || f.comments["55"] {
		t.Fatal("comment not deleted", err)
	}

	r, err = invoke(m, "merge", `{"repo":"elchi/conduit","number":7,"method":"squash"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Squash #7 "Add S3": s3 into main` || f.merged {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "merge", `{"repo":"elchi/conduit","number":7,"method":"squash","deleteBranch":true}`, false); err != nil || !f.merged {
		t.Fatal(err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.Contains(last, `"Do":"squash"`) || !strings.Contains(last, `"delete_branch_after_merge":true`) {
		t.Fatal(last)
	}
	if _, err := invoke(m, "merge", `{"repo":"elchi/conduit","number":7}`, false); err == nil || !strings.Contains(err.Error(), "already merged") {
		t.Fatal(err)
	}
}

func TestGiteaValidation(t *testing.T) {
	m, f := setup(t, "secret://g")
	for _, repo := range []string{"", "conduit", "../x", "a/b/c", "a/..", "a b/c", "a/b?x=1", "../../admin"} {
		in, _ := json.Marshal(map[string]any{"repo": repo, "number": 1})
		if _, err := invoke(m, "pulls", string(in), false); err == nil {
			t.Fatalf("accepted %q", repo)
		}
	}
	if _, err := invoke(m, "merge", `{"repo":"elchi/conduit","number":7,"method":"force"}`, false); err == nil {
		t.Fatal("accepted method")
	}
	if _, err := invoke(m, "comment", `{"repo":"elchi/conduit","number":0,"body":"x"}`, false); err == nil {
		t.Fatal("accepted number 0")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://git", Token: "plain"}, {URL: "git.example.com", Token: "secret://g"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
}
