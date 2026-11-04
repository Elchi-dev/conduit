package unmanic

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

type fakeUnmanic struct {
	mu     sync.Mutex
	seen   []string
	paused [2]bool
	ignore bool
	deny   bool
}

func (f *fakeUnmanic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.deny {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /unmanic/api/v2/version/read":
		fmt.Fprint(w, `{"version":"0.2.8"}`)
	case "GET /unmanic/api/v2/workers/status":
		fmt.Fprintf(w, `{"workers_status":[{"id":"W0","name":"Worker-W0","idle":false,"paused":%t,"start_time":"1793700000.5","current_file":"/library/private/Family/holiday.mkv","current_command":["ffmpeg","-i","/library/private/Family/holiday.mkv"],"worker_log_tail":["/library/private"]},
			{"id":"W1","name":"Worker-W1","idle":true,"paused":%t,"current_file":""}]}`, f.paused[0], f.paused[1])
	case "POST /unmanic/api/v2/pending/tasks":
		fmt.Fprint(w, `{"recordsTotal":3,"recordsFiltered":3,"results":[{"id":1,"abspath":"/library/private/a.mkv","status":"pending","library_name":"Movies"},{"id":2,"abspath":"/library/private/b.mkv","status":"pending","library_name":"TV"},{"id":3,"abspath":"/library/private/c.mkv","status":"in_progress","library_name":"TV"}]}`)
	case "POST /unmanic/api/v2/history/tasks":
		if !strings.Contains(string(body), `"order_direction":"desc"`) {
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, `{"recordsTotal":12,"recordsFiltered":12,"successCount":10,"failedCount":2,"results":[{"id":7,"task_label":"holiday.mkv","task_success":true,"finish_time":1793700000.25}]}`)
	case "POST /unmanic/api/v2/workers/worker/pause/all", "POST /unmanic/api/v2/workers/worker/resume/all":
		if !f.ignore {
			p := strings.Contains(r.URL.Path, "/pause/")
			f.paused = [2]bool{p, p}
		}
		fmt.Fprint(w, `{"success":true}`)
	case "POST /unmanic/api/v2/workers/worker/pause", "POST /unmanic/api/v2/workers/worker/resume":
		var in struct {
			ID string `json:"worker_id"`
		}
		json.Unmarshal(body, &in)
		i := map[string]int{"W0": 0, "W1": 1}
		n, ok := i[in.ID]
		if !ok {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"no such worker in /config/private/unmanic.db"}`)
			return
		}
		if !f.ignore {
			f.paused[n] = strings.HasSuffix(r.URL.Path, "/pause")
		}
		fmt.Fprint(w, `{"success":true}`)
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"404: Endpoint not found"}`)
	}
}

func setup(t *testing.T) (*Module, *fakeUnmanic) {
	f := &fakeUnmanic{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/unmanic/"})
	if err := m.Configure(context.Background(), fakehost.New(nil), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestUnmanic(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "Unmanic 0.2.8 · 2 workers, 1 busy" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"workers", `{}`, `"file":"holiday.mkv"`},
		{"workers", `{}`, `"busy":1`},
		{"pending", `{}`, `"byLibrary":{"Movies":1,"TV":2}`},
		{"pending", `{}`, `"total":3`},
		{"history", `{}`, `"failed":2`},
		{"history", `{"limit":5}`, `"finished":"2026-11-03T`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "/library/private") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	r, err := invoke(m, "pause", `{}`, true)
	if err != nil || r.Plan == nil || f.paused[0] {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "pause", `{}`, false)
	if err != nil || !f.paused[0] || !f.paused[1] || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause", `{}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused[0] {
		t.Fatal(err)
	}
	f.ignore = true
	if _, err := invoke(m, "pause", `{}`, false); err == nil || !strings.Contains(err.Error(), "0 of 2 workers paused") {
		t.Fatal(err)
	}

	risks := map[string]sdk.Risk{"pause": sdk.RiskDestructive, "resume": sdk.RiskWrite}
	for _, a := range m.Manifest().Actions {
		if want, ok := risks[a.Name]; ok && a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

// An undo puts back only the workers the action changed: W1 was paused
// before "pause", so resuming must leave it paused.
func TestUnmanicExactUndo(t *testing.T) {
	m, f := setup(t)
	f.paused = [2]bool{false, true}
	r, err := invoke(m, "pause", `{}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "1 of 2") || f.paused[0] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", `{}`, false)
	if err != nil || f.paused != [2]bool{true, true} || r.Undo == nil || string(r.Undo.Input) != `{"workers":["W0"]}` {
		t.Fatalf("%+v %v %v", r, err, f.paused)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused != [2]bool{false, true} {
		t.Fatalf("%v %v", err, f.paused)
	}
	n := len(f.seen)
	for _, in := range []string{`{"workers":["W9"]}`, `{"workers":["../x"]}`, `{"workers":[]}`} {
		if _, err := invoke(m, "resume", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, s := range f.seen[n:] {
		if strings.Contains(s, "/worker/") {
			t.Fatalf("sent %s", s)
		}
	}
	r, err = invoke(m, "resume", `{"workers":["W1"]}`, false)
	if err != nil || f.paused != [2]bool{false, false} || string(r.Undo.Input) != `{"workers":["W1"]}` {
		t.Fatalf("%+v %v %v", r, err, f.paused)
	}
}

func TestUnmanicValidation(t *testing.T) {
	m, f := setup(t)
	for _, c := range []struct{ action, in string }{
		{"history", `{"limit":"5; drop"}`},
		{"history", `[]`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "nas:8888"}, {URL: "ftp://nas:8888"}, {URL: "http://u:p@nas:8888"}, {URL: "http://nas:8888/?x=1"}, {URL: "http://nas:8888/#x"}, {URL: "http://nas:8888/a b"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	f.deny = true
	if h := m.Health(context.Background(), "u"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestUnmanicRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(nil), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "u"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// A server error naming a file loses the folder before it's shown.
func TestUnmanicErrorsHidePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"Errno 2: No such file: '/library/private/Family/a.mkv'"}`)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(nil), "u", raw); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "history", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), "No such file") {
		t.Fatal(err)
	}
}
