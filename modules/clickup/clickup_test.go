package clickup

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

type fakeClickUp struct {
	mu       sync.Mutex
	seen     []string
	name     string
	status   string
	due      string // ms
	lastBody map[string]any
}

func (f *fakeClickUp) task() string {
	due := "null"
	if f.due != "" {
		due = fmt.Sprintf("%q", f.due)
	}
	return fmt.Sprintf(`{"id":"86abc","custom_id":null,"name":%q,"text_content":"plain","status":{"status":%q,"type":"open"},"priority":{"id":"2","priority":"high"},
		"due_date":%s,"assignees":[{"id":1,"username":"kim","email":"kim@LEAKME.example"}],"tags":[{"name":"bug"}],"list":{"id":"900","name":"Backlog"},
		"url":"https://app.clickup.com/t/86abc","date_created":"1730000000000","date_updated":"1730500000000"}`, f.name, f.status, due)
}

func (f *fakeClickUp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "pk_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"err":"Token invalid","ECODE":"OAUTH_025"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /user":
		io.WriteString(w, `{"user":{"id":1,"username":"kim","email":"kim@LEAKME.example"}}`)
	case "GET /team":
		io.WriteString(w, `{"teams":[{"id":"100","name":"Acme","members":[{"user":{"email":"kim@LEAKME.example"}}]}]}`)
	case "GET /team/100/space":
		io.WriteString(w, `{"spaces":[{"id":"200","name":"Eng","private":false,"statuses":[{"status":"to do","type":"open"},{"status":"complete","type":"closed"}]}]}`)
	case "GET /space/200/folder":
		io.WriteString(w, `{"folders":[{"id":"300","name":"Q4","lists":[{"id":"901","name":"Sprint","task_count":4}]}]}`)
	case "GET /space/200/list":
		io.WriteString(w, `{"lists":[{"id":"900","name":"Backlog","task_count":"7"}]}`)
	case "GET /list/900":
		io.WriteString(w, `{"id":"900","name":"Backlog"}`)
	case "GET /list/900/task":
		io.WriteString(w, `{"tasks":[`+f.task()+`],"last_page":false}`)
	case "GET /task/86abc":
		io.WriteString(w, f.task())
	case "GET /task/86xyz": // answers with another task
		io.WriteString(w, f.task())
	case "PUT /task/86abc":
		f.lastBody = b
		if v, ok := b["name"].(string); ok {
			f.name = v
		}
		if v, ok := b["status"].(string); ok {
			f.status = v
		}
		if v, ok := b["due_date"]; ok {
			if n, ok := v.(float64); ok {
				f.due = fmt.Sprintf("%.0f", n)
			} else {
				f.due = ""
			}
		}
		io.WriteString(w, f.task())
	case "POST /list/900/task":
		f.lastBody = b
		io.WriteString(w, `{"id":"86new","name":"New","status":{"status":"to do","type":"open"},"list":{"id":"900","name":"Backlog"}}`)
	case "GET /task/86new":
		io.WriteString(w, `{"id":"86new","name":"New","status":{"status":"to do","type":"open"},"list":{"id":"900","name":"Backlog"}}`)
	case "GET /task/86abc/comment":
		io.WriteString(w, `{"comments":[{"id":"501","comment_text":"on it","date":"1730600000000","user":{"username":"kim","email":"kim@LEAKME.example"}}]}`)
	case "POST /task/86abc/comment":
		f.lastBody = b
		io.WriteString(w, `{"id":502,"hist_id":"x","date":1730700000000}`)
	case "DELETE /comment/502", "DELETE /task/86new":
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"err":"Not found","ECODE":"X"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeClickUp) {
	f := &fakeClickUp{name: "Fix login", status: "to do", due: "1764547200000"} // 2025-12-01
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cu": "pk_good", "secret://bad": "pk_bad"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestClickUp(t *testing.T) {
	m, f := setup(t, "secret://cu")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "signed in as kim, 1 workspaces" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"workspaces", `{}`, `"name":"Acme"`},
		{"spaces", `{}`, `"statuses":["to do","complete"]`},
		{"lists", `{"space":"200"}`, `"folder":"Q4"`},
		{"tasks", `{"list":"900"}`, `"due":"2025-12-01"`},
		{"tasks", `{"list":"900"}`, `"nextPage":1`},
		{"task", `{"task":"86abc"}`, `"assignees":["kim"]`},
		{"task", `{"task":"86abc"}`, `"text":"on it"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Update: no-op, preview, real, undo.
	if r, err := invoke(m, "update_task", `{"task":"86abc","status":"TO DO","due":"2025-12-01","priority":2}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err := invoke(m, "update_task", `{"task":"86abc","status":"complete"}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"status":"to do"}` || f.status != "to do" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "update_task", `{"task":"86abc","status":"complete","name":"Fix login now","due":""}`, false)
	if err != nil || f.status != "complete" || f.name != "Fix login now" || f.due != "" || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "to do" || f.name != "Fix login" || f.due != "1764547200000" {
		t.Fatal(err, f.status, f.name, f.due)
	}

	// Create, undo deletes.
	r, err = invoke(m, "create_task", `{"list":"900","name":"New","priority":1,"due":"2026-12-24"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"task":"86new"}` || f.lastBody["priority"] != float64(1) {
		t.Fatalf("%+v %v %v", r, err, f.lastBody)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}

	// Comment never notifies everyone; undo deletes it.
	r, err = invoke(m, "comment", `{"task":"86abc","text":"done"}`, false)
	if err != nil || f.lastBody["notify_all"] != false || r.Undo == nil || string(r.Undo.Input) != `{"comment":"502"}` {
		t.Fatalf("%+v %v %v", r, err, f.lastBody)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_task", `{"task":"86abc"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Changes[0].Op != "delete" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "delete_") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestClickUpValidation(t *testing.T) {
	m, f := setup(t, "secret://cu")
	for _, c := range []struct{ action, in string }{
		{"spaces", `{"workspace":"../user"}`},
		{"lists", `{}`},
		{"lists", `{"space":"200/list"}`},
		{"tasks", `{"list":"x?y"}`},
		{"task", `{"task":"86a-bc"}`},
		{"update_task", `{"task":"86abc"}`},
		{"update_task", `{"task":"86abc","priority":7}`},
		{"update_task", `{"task":"86abc","due":"next week"}`},
		{"create_task", `{"list":"900"}`},
		{"create_task", `{"name":"x"}`},
		{"comment", `{"task":"86abc","text":"  "}`},
		{"comment", `{"task":"86abc","text":"hey @here please look"}`},
		{"delete_comment", `{"comment":"abc"}`},
		{"delete_task", `{"task":"../team"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "update_task", `{"task":"86xyz","name":"y"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another task: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "pk_plain"}, {}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "ClickUp refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestClickUpRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://cu"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cu": "pk_good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
