package linear

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

// fake answers the GraphQL operations the module sends, keyed by the
// root field each one asks for.
type fake struct {
	mu       sync.Mutex
	state    string
	archived string
	comments map[string]string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "lin_api_x" {
		io.WriteString(w, `{"errors":[{"message":"Authentication required"}]}`)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	q := req.Query
	data := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	iss := func() map[string]any {
		return map[string]any{"id": "uuid-1", "identifier": "ENG-1", "title": "Fix login", "url": "https://linear.app/x/ENG-1", "priority": 2,
			"state": map[string]any{"id": "s-" + f.state, "name": f.state, "type": "started"}}
	}
	switch {
	case strings.Contains(q, "viewer { name organization"):
		data(map[string]any{"viewer": map[string]any{"name": "Alex", "organization": map[string]any{"name": "Acme"}}})
	case strings.Contains(q, "assignedIssues"):
		data(map[string]any{"viewer": map[string]any{"assignedIssues": map[string]any{"nodes": []any{iss()}}}})
	case strings.Contains(q, "searchIssues"):
		data(map[string]any{"searchIssues": map[string]any{"nodes": []any{iss()}}})
	case strings.Contains(q, "teams(filter"):
		if req.Variables["k"] != "ENG" {
			data(map[string]any{"teams": map[string]any{"nodes": []any{}}})
			return
		}
		data(map[string]any{"teams": map[string]any{"nodes": []any{map[string]any{"id": "team-1"}}}})
	case strings.Contains(q, "issueCreate"):
		data(map[string]any{"issueCreate": map[string]any{"success": true, "issue": map[string]any{"id": "uuid-2", "identifier": "ENG-2", "url": "u", "state": map[string]any{}}}})
	case strings.Contains(q, "issueArchive"):
		f.archived = req.Variables["id"].(string)
		data(map[string]any{"issueArchive": map[string]any{"success": true}})
	case strings.Contains(q, "commentCreate"):
		f.comments["c-1"] = req.Variables["in"].(map[string]any)["body"].(string)
		data(map[string]any{"commentCreate": map[string]any{"success": true, "comment": map[string]any{"id": "c-1", "url": "u"}}})
	case strings.Contains(q, "commentDelete"):
		delete(f.comments, req.Variables["id"].(string))
		data(map[string]any{"commentDelete": map[string]any{"success": true}})
	case strings.Contains(q, "issueUpdate"):
		in := req.Variables["in"].(map[string]any)
		f.state = strings.TrimPrefix(in["stateId"].(string), "s-")
		data(map[string]any{"issueUpdate": map[string]any{"success": true}})
	case strings.Contains(q, "team { states"):
		i := iss()
		i["team"] = map[string]any{"states": map[string]any{"nodes": []any{
			map[string]any{"id": "s-Todo", "name": "Todo"}, map[string]any{"id": "s-In Progress", "name": "In Progress"}, map[string]any{"id": "s-Done", "name": "Done"}}}}
		data(map[string]any{"issue": i})
	case strings.Contains(q, "issue(id"):
		i := iss()
		i["description"] = "Steps…"
		i["assignee"] = map[string]any{"name": "Alex"}
		i["comments"] = map[string]any{"nodes": []any{map[string]any{"body": "on it", "createdAt": "2026-11-03T10:00:00Z", "user": map[string]any{"name": "Sam"}}}}
		data(map[string]any{"issue": i})
	default:
		io.WriteString(w, `{"errors":[{"message":"unknown query"}]}`)
	}
}

func TestLinear(t *testing.T) {
	f := &fake{state: "Todo", comments: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	m := New()
	cfg, _ := json.Marshal(Config{APIKey: "secret://lin", API: srv.URL})
	if err := m.Configure(ctx, fakehost.New(map[string]string{"secret://lin": "lin_api_x"}), "l", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "l"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	call := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	if out := string(call("my_issues", "").Output); !strings.Contains(out, "ENG-1") {
		t.Fatal(out)
	}
	call("search", `{"query":"login"}`)
	if out := string(call("issue", `{"issue":"ENG-1"}`).Output); !strings.Contains(out, "on it") {
		t.Fatal(out)
	}
	r := call("create", `{"team":"eng","title":"New thing"}`)
	call(r.Undo.Action, string(r.Undo.Input))
	if f.archived != "ENG-2" {
		t.Fatal("undo didn't archive")
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "create", Input: json.RawMessage(`{"team":"NOPE","title":"x"}`)}); err == nil {
		t.Fatal("unknown team accepted")
	}
	r = call("comment", `{"issue":"ENG-1","body":"done"}`)
	call(r.Undo.Action, string(r.Undo.Input))
	if len(f.comments) != 0 {
		t.Fatal("comment undo")
	}
	dry, _ := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "set_state", DryRun: true, Input: json.RawMessage(`{"issue":"ENG-1","state":"done"}`)})
	if dry.Plan == nil || f.state != "Todo" {
		t.Fatal("dry run")
	}
	r = call("set_state", `{"issue":"ENG-1","state":"done"}`)
	if f.state != "Done" || r.Undo == nil {
		t.Fatalf("state %s", f.state)
	}
	call(r.Undo.Action, string(r.Undo.Input))
	if f.state != "Todo" {
		t.Fatalf("undo state %s", f.state)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "set_state", Input: json.RawMessage(`{"issue":"ENG-1","state":"Shipped"}`)}); err == nil || !strings.Contains(err.Error(), "In Progress") {
		t.Fatalf("unknown state: %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "issue", Input: json.RawMessage(`{"issue":"ENG 1\"}"}`)}); err == nil {
		t.Fatal("bad id accepted")
	}
	bad := New()
	cfg, _ = json.Marshal(Config{APIKey: "secret://lin", API: srv.URL})
	_ = bad.Configure(ctx, fakehost.New(map[string]string{"secret://lin": "wrong"}), "x", cfg)
	if h := bad.Health(ctx, "x"); h.Status != "down" {
		t.Fatalf("wrong key: %+v", h)
	}
}
