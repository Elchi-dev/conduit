package todoist

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

type fakeTodoist struct {
	mu    sync.Mutex
	seen  []string
	tasks map[string]map[string]any
}

func (f *fakeTodoist) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ttok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthorized","error_tag":"UNAUTHORIZED","http_code":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	list := func(items ...any) {
		b, _ := json.Marshal(map[string]any{"results": items, "next_cursor": nil})
		w.Write(b)
	}
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/user":
		io.WriteString(w, `{"full_name":"Elchi","email":"private@example.com"}`)
	case r.Method == "GET" && path == "/projects":
		if q.Get("cursor") == "" {
			io.WriteString(w, `{"results":[{"id":"inbox1","name":"Inbox","inbox_project":true}],"next_cursor":"c2"}`)
			return
		}
		list(map[string]any{"id": "work", "name": "Work", "is_favorite": true})
	case r.Method == "GET" && path == "/projects/work":
		io.WriteString(w, `{"id":"work","name":"Work"}`)
	case r.Method == "GET" && path == "/labels":
		list(map[string]any{"id": "l1", "name": "waiting", "color": "red"})
	case r.Method == "GET" && path == "/tasks/filter":
		switch q.Get("query") {
		case "today":
			list(f.tasks["t1"])
		case "overdue":
			list(f.tasks["t2"])
		case "#Work & p1":
			list(f.tasks["t1"], f.tasks["t2"])
		default:
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"Invalid filter"}`)
		}
	case r.Method == "GET" && path == "/tasks":
		if q.Get("project_id") != "work" {
			w.WriteHeader(400)
			return
		}
		list(f.tasks["t1"])
	case r.Method == "POST" && path == "/tasks":
		var b map[string]any
		json.Unmarshal(body, &b)
		b["id"] = "new1"
		f.tasks["new1"] = b
		json.NewEncoder(w).Encode(b)
	case strings.HasPrefix(path, "/tasks/"):
		parts := strings.Split(strings.TrimPrefix(path, "/tasks/"), "/")
		t := f.tasks[parts[0]]
		if t == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"Task not found"}`)
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			json.NewEncoder(w).Encode(t)
		case r.Method == "DELETE" && len(parts) == 1:
			delete(f.tasks, parts[0])
			w.WriteHeader(204)
		case r.Method == "POST" && len(parts) == 1:
			var b map[string]any
			json.Unmarshal(body, &b)
			for k, v := range b {
				switch k {
				case "due_string", "due_date", "due_datetime":
					t["due"] = map[string]any{"date": v, "string": v}
				default:
					t[k] = v
				}
			}
			json.NewEncoder(w).Encode(t)
		case r.Method == "POST" && parts[1] == "close":
			if d, ok := t["due"].(map[string]any); ok && d["is_recurring"] == true {
				d["date"] = "2026-11-11"
			} else {
				t["checked"] = true
			}
			w.WriteHeader(204)
		case r.Method == "POST" && parts[1] == "reopen":
			t["checked"] = false
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeTodoist) {
	f := &fakeTodoist{tasks: map[string]map[string]any{
		"t1": {"id": "t1", "content": "Write report", "project_id": "work", "priority": 4, "labels": []string{"waiting"}, "due": map[string]any{"date": "2026-11-04", "string": "today"}},
		"t2": {"id": "t2", "content": "Water plants", "project_id": "inbox1", "priority": 1, "due": map[string]any{"date": "2026-11-04", "string": "every week", "is_recurring": true, "lang": "en"}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "ttok", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTodoistReads(t *testing.T) {
	m, _ := setup(t, "secret://t")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "signed in as Elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"name":"Work"`}, // second page
		{"projects", `{}`, `"inbox":true`},
		{"labels", `{}`, `"waiting"`},
		{"today", `{}`, `"priority":"p1"`},
		{"overdue", `{}`, `"recurring":true`},
		{"tasks", `{"filter":"#Work & p1"}`, `"count":2`},
		{"tasks", `{"project":"work"}`, `"project":"Work"`},
		{"task", `{"task":"t1"}`, `"url":"https://app.todoist.com/app/task/t1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if _, err := invoke(m, "tasks", `{"filter":"bogus"}`, false); err == nil || !strings.Contains(err.Error(), "Invalid filter") {
		t.Fatal(err)
	}
}

func TestTodoistWrites(t *testing.T) {
	m, f := setup(t, "secret://t")

	r, err := invoke(m, "add_task", `{"content":"Call Bob","project":"work","priority":1,"due":"tomorrow 5pm"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Add "Call Bob" to Work` || f.tasks["new1"] != nil {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_task", `{"content":"Call Bob","project":"work","priority":1,"due":"tomorrow 5pm"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_task" || string(r.Undo.Input) != `{"task":"new1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if nt := f.tasks["new1"]; nt["priority"] != float64(4) || nt["due_string"] != "tomorrow 5pm" || nt["project_id"] != "work" {
		t.Fatalf("sent %v", nt)
	}
	if r, err := invoke(m, "delete_task", `{"task":"new1"}`, true); err != nil || r.Plan == nil || r.Plan.Changes[0].Op != "delete" || f.tasks["new1"] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.tasks["new1"] != nil {
		t.Fatal(err)
	}

	// Complete and undo by reopening.
	r, err = invoke(m, "complete_task", `{"task":"t1"}`, false)
	if err != nil || f.tasks["t1"]["checked"] != true || r.Undo == nil || r.Undo.Action != "reopen_task" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.tasks["t1"]["checked"] != false || r.Undo.Action != "complete_task" {
		t.Fatalf("%+v %v", r, err)
	}

	// A recurring task: completing moves the date, undo puts it back.
	r, err = invoke(m, "complete_task", `{"task":"t2"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "next one") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "complete_task", `{"task":"t2"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "update_task" || string(r.Undo.Input) != `{"due":"every week","dueLang":"en","task":"t2"}` {
		t.Fatalf("%+v %v", r.Undo, err)
	}

	// Update shows before/after and undo restores.
	r, err = invoke(m, "update_task", `{"task":"t1","content":"Write the report","priority":2,"due":"friday"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].Before), `"content":"Write report"`) || !strings.Contains(string(r.Plan.Changes[0].Before), `"priority":1`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "update_task", `{"task":"t1","content":"Write the report","priority":2,"due":"friday"}`, false)
	if err != nil || f.tasks["t1"]["content"] != "Write the report" || f.tasks["t1"]["priority"] != float64(3) || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	last := f.seen[len(f.seen)-1]
	if f.tasks["t1"]["content"] != "Write report" || f.tasks["t1"]["priority"] != float64(4) || !strings.Contains(last, `"due_date":"2026-11-04"`) {
		t.Fatalf("undo: %v %s", f.tasks["t1"], last)
	}
	if _, err := invoke(m, "complete_task", `{"task":"zzz"}`, false); err == nil || !strings.Contains(err.Error(), "no task zzz") {
		t.Fatal(err)
	}
}

func TestTodoistValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"task", `{"task":"../projects"}`},
		{"task", `{"task":"a/b"}`},
		{"delete_task", `{}`},
		{"complete_task", `{"task":"t1?x=1"}`},
		{"add_task", `{}`},
		{"add_task", `{"content":"  "}`},
		{"add_task", `{"content":"x","priority":0}`},
		{"add_task", `{"content":"x","project":"../user"}`},
		{"update_task", `{"task":"t1"}`},
		{"tasks", `{"project":"a b"}`},
		{"tasks", `{"filter":"today","project":"work"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
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
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	man := m.Manifest()
	for _, a := range man.Actions {
		if a.Name == "delete_task" && a.Risk != sdk.RiskDestructive {
			t.Fatal("delete_task must be destructive")
		}
		if a.Risk == sdk.RiskWrite && !a.DryRun {
			t.Fatalf("%s has no preview", a.Name)
		}
	}
}

func TestTodoistRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://t"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "ttok"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
