package asana

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

type fakeAsana struct {
	mu        sync.Mutex
	seen      []string
	completed bool
	name      string
	due       string
	lastBody  map[string]any
}

func (f *fakeAsana) task() string {
	due := "null"
	if f.due != "" {
		due = fmt.Sprintf("%q", f.due)
	}
	return fmt.Sprintf(`{"data":{"gid":"30","name":%q,"notes":"n","completed":%t,"due_on":%s,"due_at":null,"assignee":{"gid":"1","name":"Kim","email":"kim@LEAKME.example"},
		"projects":[{"gid":"20","name":"Launch"}],"tags":[{"gid":"5","name":"urgent"}],"permalink_url":"https://app.asana.com/0/20/30","created_at":"2026-11-01T00:00:00Z","modified_at":"2026-11-02T00:00:00Z"}}`,
		f.name, f.completed, due)
}

func (f *fakeAsana) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer as_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Not Authorized"}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b struct {
		Data map[string]any `json:"data"`
	}
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /users/me":
		io.WriteString(w, `{"data":{"gid":"1","name":"Kim","email":"kim@LEAKME.example","workspaces":[{"gid":"10","name":"Acme"}]}}`)
	case "GET /workspaces":
		io.WriteString(w, `{"data":[{"gid":"10","name":"Acme","is_organization":true}]}`)
	case "GET /projects":
		io.WriteString(w, `{"data":[{"gid":"20","name":"Launch","archived":false,"permalink_url":"https://app.asana.com/0/20","team":{"gid":"7","name":"Eng"}}]}`)
	case "GET /projects/20":
		io.WriteString(w, `{"data":{"gid":"20","name":"Launch"}}`)
	case "GET /tasks":
		io.WriteString(w, `{"data":[`+strings.TrimSuffix(strings.TrimPrefix(f.task(), `{"data":`), "}")+`]}`)
	case "GET /tasks/30":
		io.WriteString(w, f.task())
	case "GET /tasks/31": // answers with another task
		io.WriteString(w, f.task())
	case "PUT /tasks/30":
		f.lastBody = b.Data
		if v, ok := b.Data["completed"].(bool); ok {
			f.completed = v
		}
		if v, ok := b.Data["name"].(string); ok {
			f.name = v
		}
		if v, ok := b.Data["due_on"]; ok {
			f.due, _ = v.(string)
		}
		io.WriteString(w, f.task())
	case "POST /tasks":
		f.lastBody = b.Data
		io.WriteString(w, `{"data":{"gid":"40","name":"New","completed":false,"permalink_url":"https://app.asana.com/0/20/40"}}`)
	case "DELETE /tasks/40", "DELETE /stories/50":
		io.WriteString(w, `{"data":{}}`)
	case "GET /tasks/30/stories":
		io.WriteString(w, `{"data":[{"gid":"49","type":"system","text":"Kim added this task"},{"gid":"50","type":"comment","text":"looks good","created_at":"2026-11-03T00:00:00Z","created_by":{"gid":"1","name":"Kim"}}]}`)
	case "POST /tasks/30/stories":
		io.WriteString(w, `{"data":{"gid":"50","type":"comment"}}`)
	case "GET /stories/50":
		io.WriteString(w, `{"data":{"gid":"50","type":"comment","text":"looks good","created_by":{"gid":"1","name":"Kim"}}}`)
	case "GET /stories/49":
		io.WriteString(w, `{"data":{"gid":"49","type":"system","text":"Kim added this task"}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"message":"Not found"}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeAsana) {
	f := &fakeAsana{name: "Ship it", due: "2026-12-01"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://as": "as_good", "secret://bad": "as_bad"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAsana(t *testing.T) {
	m, f := setup(t, "secret://as")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as Kim, 1 workspaces" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"workspaces", `{}`, `"organization":true`},
		{"projects", `{}`, `"team":"Eng"`},
		{"tasks", `{"project":"20"}`, `"assignee":"Kim"`},
		{"tasks", `{}`, `"due":"2026-12-01"`},
		{"task", `{"task":"30"}`, `"tags":["urgent"]`},
		{"task", `{"task":"30"}`, `"comments":[{"at":"2026-11-03T00:00:00Z","by":"Kim","id":"50","text":"looks good"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "assignee=me&completed_since=now") {
		t.Fatal(f.seen)
	}

	// Complete: preview, real, no-op, undo.
	r, err := invoke(m, "complete_task", `{"task":"30"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Complete task "Ship it"` || f.completed {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "complete_task", `{"task":"30"}`, false)
	if err != nil || !f.completed || r.Undo == nil || r.Undo.Action != "reopen_task" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "complete_task", `{"task":"30"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.completed {
		t.Fatal(err)
	}

	// Update: only what changes, undo restores.
	if r, err := invoke(m, "update_task", `{"task":"30","name":"Ship it","due":"2026-12-01"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "update_task", `{"task":"30","name":"Ship it now","due":""}`, false)
	if err != nil || f.name != "Ship it now" || f.due != "" || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.name != "Ship it" || f.due != "2026-12-01" {
		t.Fatal(err, f.name, f.due)
	}

	// Create, undo deletes.
	r, err = invoke(m, "create_task", `{"project":"20","name":"New","due":"2026-12-24"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_task" || string(r.Undo.Input) != `{"task":"40"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if p, _ := f.lastBody["projects"].([]any); len(p) != 1 || f.lastBody["due_on"] != "2026-12-24" {
		t.Fatal(f.lastBody)
	}

	// Comment, undo deletes it; a wildcard mention is refused.
	r, err = invoke(m, "comment", `{"task":"30","text":"done, thanks"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_comment" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_comment", `{"comment":"49"}`, false); err == nil || !strings.Contains(err.Error(), "isn't a comment") {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_task", `{"task":"30"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Changes[0].Op != "delete" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "delete_") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestAsanaValidation(t *testing.T) {
	m, f := setup(t, "secret://as")
	for _, c := range []struct{ action, in string }{
		{"task", `{"task":"../users/me"}`},
		{"task", `{}`},
		{"tasks", `{"project":"20?x=1"}`},
		{"projects", `{"workspace":"a/b"}`},
		{"update_task", `{"task":"30"}`},
		{"update_task", `{"task":"30","due":"tomorrow"}`},
		{"update_task", `{"task":"30","assignee":"kim@example.com"}`},
		{"create_task", `{"project":"20"}`},
		{"create_task", `{"name":"x"}`},
		{"create_task", `{"project":"20","name":"  "}`},
		{"comment", `{"task":"30","text":""}`},
		{"comment", `{"task":"30","text":"@everyone look"}`},
		{"delete_comment", `{"comment":"1 2"}`},
		{"complete_task", `{"task":"30/stories"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The task changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "complete_task", `{"task":"31"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another task: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "as_plain"}, {}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "a")
	if h.Status != "down" || h.Message != "Asana refused the access token" || strings.Contains(h.Message, "as_bad") {
		t.Fatalf("%+v", h)
	}
}

func TestAsanaRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://as"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://as": "as_good"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
