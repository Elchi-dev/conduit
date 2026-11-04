package vikunja

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

type fakeVikunja struct {
	mu    sync.Mutex
	seen  []string
	tasks map[int]map[string]any
	next  int
}

func (f *fakeVikunja) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tk_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":11,"message":"missing, malformed, expired or otherwise invalid token provided"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var id int
	if strings.HasPrefix(r.URL.Path, "/api/v1/tasks/") {
		fmt.Sscanf(r.URL.Path, "/api/v1/tasks/%d", &id)
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/user":
		io.WriteString(w, `{"id":1,"username":"elchi","email":"e@x","settings":{"timezone":"Europe/Berlin"}}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/info":
		io.WriteString(w, `{"version":"v0.24.6"}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/projects":
		w.Header().Set("X-Pagination-Total-Pages", "1")
		io.WriteString(w, `[{"id":7,"title":"Old","is_archived":true},{"id":2,"title":"Home","is_favorite":true}]`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/projects/2":
		io.WriteString(w, `{"id":2,"title":"Home"}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/tasks/all":
		if r.URL.Query().Get("filter_timezone") != "Europe/Berlin" && r.URL.Query().Get("filter") != "" {
			w.WriteHeader(400)
			return
		}
		var list []map[string]any
		for _, t := range f.tasks {
			list = append(list, t)
		}
		json.NewEncoder(w).Encode(list)
	case r.Method == "PUT" && r.URL.Path == "/api/v1/projects/2/tasks":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.next++
		b["id"], b["project_id"], b["done"], b["repeat_after"] = f.next, 2, false, 0
		f.tasks[f.next] = b
		json.NewEncoder(w).Encode(b)
	case id > 0:
		t, ok := f.tasks[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":2001,"message":"This task does not exist"}`)
			return
		}
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(t)
		case "POST":
			var b map[string]any
			json.Unmarshal(body, &b)
			// Vikunja replaces the task: anything missing would be lost.
			if b["hex_color"] != t["hex_color"] {
				w.WriteHeader(400)
				io.WriteString(w, `{"message":"lost a field"}`)
				return
			}
			if b["done"] == true && fmt.Sprint(t["repeat_after"]) != "0" {
				b["done"], b["due_date"] = false, "2026-11-11T09:00:00Z"
			}
			f.tasks[id] = b
			json.NewEncoder(w).Encode(b)
		case "DELETE":
			delete(f.tasks, id)
			io.WriteString(w, `{"message":"Successfully deleted."}`)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeVikunja) {
	f := &fakeVikunja{next: 100, tasks: map[int]map[string]any{
		1: {"id": 1, "title": "Water plants", "done": false, "due_date": "2026-11-04T08:00:00Z", "priority": 3, "project_id": 2, "repeat_after": 0, "hex_color": "ff0000", "labels": []any{map[string]any{"title": "home"}}},
		2: {"id": 2, "title": "Bins", "done": false, "due_date": "2026-11-04T09:00:00Z", "priority": 0, "project_id": 2, "repeat_after": 604800, "hex_color": ""},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "tk_good", "secret://bad": "nope"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestVikunja(t *testing.T) {
	m, f := setup(t, "secret://v")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || h.Message != "signed in as elchi · Vikunja v0.24.6" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "projects", `{}`, false)
	if err != nil || !strings.HasPrefix(string(r.Output), `[{"favorite":true,"id":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, c := range []struct{ action, in, want string }{
		{"today", `{}`, `"project":"Home"`},
		{"overdue", `{}`, `"priority":"high"`},
		{"tasks", `{"filter":"priority >= 3","project":2}`, `"labels":["home"]`},
		{"task", `{"id":1}`, `"description":""`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	last := ""
	for _, s := range f.seen {
		if strings.Contains(s, "priority+%3E%3D+3") {
			last = s
		}
	}
	if !strings.Contains(last, "filter=%28priority+%3E%3D+3%29+%26%26+project+%3D+2") {
		t.Fatal(last)
	}

	// Create; undo deletes.
	r, err = invoke(m, "create_task", `{"project":2,"title":"Call mum","due":"2026-11-05","priority":2}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Add "Call mum" to Home` || !strings.Contains(string(r.Plan.Changes[0].After), `"due_date":"2026-11-05T00:00:00+01:00"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_task", `{"project":2,"title":"Call mum"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_task" || string(r.Undo.Input) != `{"id":101}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.tasks[101] != nil {
		t.Fatal(err)
	}

	// Done and undone undo each other, and keep the fields we didn't touch.
	r, err = invoke(m, "mark_done", `{"id":1}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "mark_undone" || f.tasks[1]["done"] != true || f.tasks[1]["hex_color"] != "ff0000" {
		t.Fatalf("%+v %v %v", r, err, f.tasks[1])
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || r.Undo == nil || r.Undo.Action != "mark_done" || f.tasks[1]["done"] != false {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "mark_undone", `{"id":1}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	// A repeating task moves on; undo puts the date back.
	r, err = invoke(m, "mark_done", `{"id":2}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "update_task" || string(r.Undo.Input) != `{"due":"2026-11-04T09:00:00Z","id":2}` || f.tasks[2]["due_date"] != "2026-11-11T09:00:00Z" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.tasks[2]["due_date"] != "2026-11-04T09:00:00Z" {
		t.Fatal(err, f.tasks[2])
	}

	// Update; undo restores.
	r, err = invoke(m, "update_task", `{"id":1,"title":"Water all plants","due":""}`, false)
	if err != nil || r.Undo == nil || f.tasks[1]["title"] != "Water all plants" || f.tasks[1]["due_date"] != zero || f.tasks[1]["hex_color"] != "ff0000" {
		t.Fatalf("%+v %v %v", r, err, f.tasks[1])
	}
	if string(r.Undo.Input) != `{"due":"2026-11-04T08:00:00Z","id":1,"title":"Water plants"}` {
		t.Fatal(string(r.Undo.Input))
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.tasks[1]["title"] != "Water plants" || f.tasks[1]["due_date"] != "2026-11-04T08:00:00Z" {
		t.Fatal(err, f.tasks[1])
	}

	// A description change has no undo, and the preview gives only the
	// old description's size: it's private.
	f.tasks[1]["description"] = "PRIVATE door code 4711"
	p, err := invoke(m, "update_task", `{"id":1,"description":"new notes"}`, true)
	if err != nil || p.Plan == nil || strings.Contains(string(p.Plan.Changes[0].Before), "4711") || !strings.Contains(string(p.Plan.Changes[0].Before), `"descriptionChars":22`) {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "update_task", `{"id":1,"description":"new notes","priority":2}`, false)
	if err != nil || r.Undo != nil || f.tasks[1]["description"] != "new notes" || strings.Contains(string(r.Output), "4711") {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "task" && !a.Sensitive {
			t.Fatal("task details (with the description) must be sensitive")
		}
	}

	r, err = invoke(m, "delete_task", `{"id":1}`, true)
	if err != nil || r.Plan == nil || f.tasks[1] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_task", `{"id":1}`, false); err != nil || f.tasks[1] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "task", `{"id":1}`, false); err == nil || !strings.Contains(err.Error(), "no task 1") {
		t.Fatal(err)
	}
}

func TestVikunjaValidation(t *testing.T) {
	m, f := setup(t, "secret://v")
	for _, c := range []struct{ action, in string }{
		{"task", `{"id":0}`},
		{"task", `{"id":"1/../../user"}`},
		{"tasks", `{"filter":"done = false","search":"x"}`},
		{"tasks", `{"project":-1}`},
		{"tasks", `{"filter":"` + strings.Repeat("x", 1025) + `"}`},
		{"create_task", `{"title":"x"}`},
		{"create_task", `{"project":2}`},
		{"create_task", `{"project":2,"title":" "}`},
		{"create_task", `{"project":2,"title":"x","priority":9}`},
		{"create_task", `{"project":2,"title":"x","due":"tomorrow"}`},
		{"create_task", `{"project":2,"title":"x","due":"2026-13-45"}`},
		{"update_task", `{"id":1}`},
		{"update_task", `{"title":"x"}`},
		{"mark_done", `{}`},
		{"delete_task", `{"id":-3}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://tasks.example.com", Token: "tk_plain"}, {URL: "tasks.example.com", Token: "secret://v"}, {URL: "https://tasks.example.com", Token: "secret://v", Timezone: "Mars/Olympus"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "v"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestVikunjaRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://v"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "tk_good"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "v"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
