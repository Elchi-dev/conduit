package kimai

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type entry struct {
	project, activity int
	desc              string
	running           bool
}

type fakeKimai struct {
	mu      sync.Mutex
	seen    []string
	entries map[int]*entry
	next    int
}

func (f *fakeKimai) sheet(id int) string {
	e := f.entries[id]
	end := `"2026-11-04T11:00:00+0100"`
	if e.running {
		end = "null"
	}
	return fmt.Sprintf(`{"id":%d,"begin":"2026-11-04T09:00:00+0100","end":%s,"duration":7200,"description":%q,"project":{"id":%d,"name":"Website","customer":{"id":1,"name":"Acme"}},"activity":{"id":%d,"name":"Design"},"tags":["web"],"rate":250,"hourlyRate":125,"user":7}`,
		id, end, e.desc, e.project, e.activity)
}

func (f *fakeKimai) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer kimai_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":401,"message":"Invalid credentials"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var id int
	fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/timesheets/"), "%d", &id)
	switch {
	case r.URL.Path == "/api/version":
		io.WriteString(w, `{"version":"2.24.0","versionId":22400}`)
	case r.URL.Path == "/api/projects":
		io.WriteString(w, `[{"id":3,"name":"Website","parentTitle":"Acme Ltd","customer":1,"orderNumber":"PO-7","visible":true,"billable":true,"budget":5000}]`)
	case r.URL.Path == "/api/activities":
		io.WriteString(w, `[{"id":5,"name":"Design","project":3,"parentTitle":"Website","visible":true},{"id":6,"name":"Meeting","project":null,"visible":true}]`)
	case r.URL.Path == "/api/timesheets/active":
		items := []string{}
		for id, e := range f.entries {
			if e.running {
				items = append(items, f.sheet(id))
			}
		}
		io.WriteString(w, "["+strings.Join(items, ",")+"]")
	case r.URL.Path == "/api/timesheets" && r.Method == "GET":
		if r.URL.Query().Get("begin") != "2026-10-29T00:00:00" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "["+f.sheet(1)+"]")
	case r.URL.Path == "/api/timesheets" && r.Method == "POST":
		var b struct {
			Project, Activity int
			Description       string
			Begin             *string
		}
		json.Unmarshal(body, &b)
		if b.Begin != nil {
			w.WriteHeader(400)
			return
		}
		f.next++
		f.entries[f.next] = &entry{project: b.Project, activity: b.Activity, desc: b.Description, running: true}
		io.WriteString(w, f.sheet(f.next))
	case strings.HasSuffix(r.URL.Path, "/stop") && r.Method == "PATCH" && f.entries[id] != nil:
		f.entries[id].running = false
		io.WriteString(w, f.sheet(id))
	case id == 99: // answers with another timesheet
		io.WriteString(w, f.sheet(1))
	case f.entries[id] != nil && r.Method == "GET":
		io.WriteString(w, f.sheet(id))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":404,"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeKimai) {
	f := &fakeKimai{entries: map[int]*entry{1: {project: 3, activity: 5, desc: "Mockups"}}, next: 1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kimai_good", "secret://bad": "kimai_bad"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKimai(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "signed in · Kimai 2.24.0" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"customer":"Acme Ltd"`},
		{"projects", `{"query":"acme"}`, `"orderNumber":"PO-7"`},
		{"activities", `{"project":3}`, `"global":true`},
		{"timesheets", `{}`, `"durationSeconds":7200`},
		{"timesheets", `{}`, `"projectName":"Website"`},
		{"timesheets", `{"running":true}`, `[]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "250") || strings.Contains(out, "budget") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Start: preview, real, no-op, then undo stops it.
	in := `{"project":3,"activity":5,"description":"Header","tags":["web"]}`
	r, err := invoke(m, "start_timer", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start a timer on project 3, activity 5" || len(f.entries) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_timer", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "stop_timer" || string(r.Undo.Input) != `{"id":2}` || !f.entries[2].running {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `"tags":"web"`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if r2, err := invoke(m, "start_timer", in, false); err != nil || r2.Undo != nil || !strings.Contains(string(r2.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r2, err)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || !f.entries[2].running {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.entries[2].running || r.Undo == nil || r.Undo.Action != "start_timer" || string(r.Undo.Input) != `{"activity":5,"description":"Header","project":3,"tags":["web"]}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "stop_timer", `{"id":2}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if r, err := invoke(m, "stop_timer", `{}`, false); err != nil || !strings.Contains(string(r.Output), "no timer is running") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Undo of the stop starts a new timer, which stop_timer (no id) finds.
	if _, err := invoke(m, "start_timer", string(r.Undo.Input), false); err != nil || !f.entries[3].running {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop_timer", `{}`, false); err != nil || f.entries[3].running {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop_timer", `{"id":42}`, false); err == nil || !strings.Contains(err.Error(), "no timesheet 42") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_timer") && (a.Risk != sdk.RiskWrite || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestKimaiValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"activities", `{"project":-1}`},
		{"timesheets", `{"start":"last week"}`},
		{"timesheets", `{"end":"2026-13-01"}`},
		{"timesheets", `{"start":"2026-11-05","end":"2026-11-04"}`},
		{"timesheets", `{"limit":1000}`},
		{"start_timer", `{"project":3}`},
		{"start_timer", `{"project":"3/../users","activity":5}`},
		{"start_timer", `{"project":3,"activity":5,"tags":["a,b"]}`},
		{"start_timer", `{"project":3,"activity":5,"description":"` + strings.Repeat("x", 2001) + `"}`},
		{"stop_timer", `{"id":-4}`},
		{"stop_timer", `{"id":"1/stop"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// The timesheet stopped is the one asked for, whatever the server answers.
	if _, err := invoke(m, "stop_timer", `{"id":99}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("stopped another timesheet: %v %v", err, f.seen)
	}
	for _, c := range []Config{{URL: "https://time.example.com", Token: "plain"}, {Token: "secret://k"}, {URL: "time.example.com", Token: "secret://k"}, {URL: "https://u:p@time.example.com", Token: "secret://k"}, {URL: "https://time.example.com/?a=1", Token: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || h.Message != "Kimai refused the API token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "projects", `{}`, false); err == nil || strings.Contains(err.Error(), "kimai_bad") {
		t.Fatal(err)
	}
}

func TestKimaiRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = "hit " + r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kimai_good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
