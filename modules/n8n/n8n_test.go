package n8n

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

type fakeN8N struct {
	mu     sync.Mutex
	seen   []string
	active bool
}

func (f *fakeN8N) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-N8N-API-KEY") != "nkey" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"unauthorized"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	wf := func() string {
		a := map[bool]string{true: "true", false: "false"}[f.active]
		return `{"id":"aB3dE5","name":"Backup notify","active":` + a + `,"updatedAt":"2026-11-01T08:00:00.000Z","tags":[{"name":"ops"}],"nodes":[{"type":"n8n-nodes-base.cron"},{"type":"n8n-nodes-base.code"}]}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/workflows":
		switch {
		case q.Get("cursor") == "" && q.Get("limit") == "100":
			io.WriteString(w, `{"data":[`+wf()+`],"nextCursor":"c2"}`)
		case q.Get("cursor") == "c2":
			io.WriteString(w, `{"data":[{"id":"7","name":"Old one","active":false,"nodes":[]}],"nextCursor":null}`)
		default:
			io.WriteString(w, `{"data":[`+wf()+`],"nextCursor":null}`)
		}
	case "GET /api/v1/workflows/aB3dE5":
		io.WriteString(w, wf())
	case "POST /api/v1/workflows/aB3dE5/activate":
		f.active = true
		io.WriteString(w, wf())
	case "POST /api/v1/workflows/aB3dE5/deactivate":
		f.active = false
		io.WriteString(w, wf())
	case "GET /api/v1/executions":
		if q.Get("includeData") != "false" {
			w.WriteHeader(400)
			return
		}
		if q.Get("status") == "error" {
			io.WriteString(w, `{"data":[{"id":"901","finished":false,"mode":"trigger","status":"error","startedAt":"2026-11-04T10:00:00.000Z","stoppedAt":"2026-11-04T10:00:02.500Z","workflowId":"aB3dE5"}],"nextCursor":null}`)
			return
		}
		io.WriteString(w, `{"data":[{"id":902,"finished":true,"mode":"manual","status":"success","startedAt":"2026-11-04T11:00:00.000Z","stoppedAt":null,"workflowId":7}],"nextCursor":null}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeN8N) {
	f := &fakeN8N{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1/", APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "nkey", "secret://bad": "x"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestN8N(t *testing.T) {
	m, f := setup(t, "secret://n")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "workflows", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"tags":["ops"]`) || !strings.Contains(string(r.Output), `"Old one"`) || !strings.Contains(string(r.Output), `"nodes":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(string(r.Output), `/workflow/aB3dE5"`) || strings.Contains(string(r.Output), "/api/v1/workflow") {
		t.Fatal(string(r.Output))
	}

	r, err = invoke(m, "activate", `{"id":"aB3dE5"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Activate workflow "Backup notify"` || f.active {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "activate", `{"id":"aB3dE5"}`, false)
	if err != nil || !f.active || r.Undo == nil || r.Undo.Action != "deactivate" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "activate", `{"id":"aB3dE5"}`, false); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatal(err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.active || r.Undo.Action != "activate" {
		t.Fatalf("%+v %v", r, err)
	}

	r, err = invoke(m, "failed_executions", `{"workflow":"aB3dE5"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"workflow":"Backup notify"`) || !strings.Contains(string(r.Output), `"seconds":2.5`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if last := f.seen[len(f.seen)-3]; !strings.Contains(last, "status=error") || !strings.Contains(last, "workflowId=aB3dE5") {
		t.Fatal(f.seen)
	}
	if r, err = invoke(m, "executions", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"id":"902"`) || !strings.Contains(string(r.Output), `"workflow":"Old one"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestN8NValidation(t *testing.T) {
	m, f := setup(t, "secret://n")
	for _, c := range []struct{ action, in string }{
		{"activate", `{"id":"../../owner"}`},
		{"activate", `{"id":"a/b"}`},
		{"deactivate", `{}`},
		{"deactivate", `{"id":"a b"}`},
		{"executions", `{"status":"lost"}`},
		{"executions", `{"workflow":"x&status=success"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://n8n", APIKey: "plain"}, {URL: "n8n.local", APIKey: "secret://n"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not carry the X-N8N-API-KEY there.
func TestN8NRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-N8N-API-KEY") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://n"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "nkey"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// Deactivating stops a workflow's automations: destructive. Activating only
// restores them and stays write.
func TestN8NRisks(t *testing.T) {
	risk := map[string]sdk.Risk{}
	for _, a := range New().Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["deactivate"] != sdk.RiskDestructive || risk["activate"] != sdk.RiskWrite {
		t.Fatalf("%v", risk)
	}
}
