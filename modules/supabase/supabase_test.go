package supabase

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

const (
	ref1  = "abcdefghijklmnopqrst"
	token = "sbpfake_0123456789abcdef0123456789abcdef01234567"
)

type fakeSupabase struct {
	mu     sync.Mutex
	seen   []string
	status string
}

func (f *fakeSupabase) project() map[string]any {
	return map[string]any{"id": ref1, "organization_id": "org-acme", "name": "shop", "region": "eu-central-1", "status": f.status, "created_at": "2026-01-02T03:04:05Z",
		"database": map[string]any{"host": "db." + ref1 + ".supabase.co", "version": "15.6.1"}}
}

func (f *fakeSupabase) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/organizations":
		io.WriteString(w, `[{"id":"org-acme","name":"Acme"}]`)
	case "GET /v1/projects":
		enc.Encode([]any{f.project()})
	case "GET /v1/projects/" + ref1:
		enc.Encode(f.project())
	case "GET /v1/projects/" + ref1 + "/health":
		if len(r.URL.Query()["services"]) != len(services) {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"name":"db","healthy":true,"status":"ACTIVE_HEALTHY"},{"name":"auth","healthy":false,"status":"UNHEALTHY","error":"timeout"}]`)
	case "GET /v1/projects/" + ref1 + "/functions":
		io.WriteString(w, `[{"id":"f1","slug":"hello","name":"hello","status":"ACTIVE","version":3,"verify_jwt":true,"updated_at":1793000000000}]`)
	case "GET /v1/projects/" + ref1 + "/api-keys":
		io.WriteString(w, `[{"name":"service_role","api_key":"SECRET-KEY"}]`)
	case "POST /v1/projects/" + ref1 + "/database/query":
		var q struct{ Query string }
		json.Unmarshal(body, &q)
		if q.Query == usageSQL {
			io.WriteString(w, `[{"bytes":52428800,"connections":12,"max_connections":60}]`)
		} else if q.Query == tablesSQL {
			io.WriteString(w, `[{"name":"public.orders","bytes":10485760,"rows":40000}]`)
		} else {
			w.WriteHeader(400)
		}
	case "POST /v1/projects/" + ref1 + "/pause":
		f.status = "INACTIVE"
	case "POST /v1/projects/" + ref1 + "/restore":
		f.status = "ACTIVE_HEALTHY"
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeSupabase) {
	f := &fakeSupabase{status: "ACTIVE_HEALTHY"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sb": token, "secret://bad": "sbp_00000000000000000000000000000000"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSupabaseReads(t *testing.T) {
	m, f := setup(t, "secret://sb")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "1 projects" {
		t.Fatalf("%+v", h)
	}
	in := `{"project":"` + ref1 + `"}`
	for _, c := range []struct{ action, in, want string }{
		{"organizations", `{}`, `"name":"Acme"`},
		{"projects", `{}`, `"state":"running"`},
		{"projects", `{}`, `"region":"eu-central-1"`},
		{"health", in, `"error":"timeout"`},
		{"health", in, `"healthy":false`},
		{"database_usage", in, `"size":"50.0 MB"`},
		{"database_usage", in, `"table":"public.orders"`},
		{"functions", in, `"verifyJWT":true`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "SECRET-KEY") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "api-keys") {
			t.Fatalf("asked for API keys: %s", s)
		}
	}
}

func TestSupabasePauseRestore(t *testing.T) {
	m, f := setup(t, "secret://sb")
	in := `{"project":"` + strings.ToUpper(ref1) + `"}`
	r, err := invoke(m, "pause", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Pause project shop") || f.status != "ACTIVE_HEALTHY" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", in, false)
	if err != nil || f.status != "INACTIVE" || r.Undo == nil || r.Undo.Action != "restore" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause", in, false); err != nil || !strings.Contains(string(r.Output), "already paused") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.status != "ACTIVE_HEALTHY" || r.Undo == nil || r.Undo.Action != "pause" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "pause" && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatal("pause must be destructive, previewed and undoable")
		}
	}
}

func TestSupabaseValidation(t *testing.T) {
	m, f := setup(t, "secret://sb")
	for _, c := range []struct{ action, in string }{
		{"health", `{"project":"../organizations"}`},
		{"health", `{"project":"abc"}`},
		{"functions", `{"project":"abcdefghijklmnopqrs1"}`},
		{"pause", `{}`},
		{"database_usage", `{"project":"abcdefghijklmnopqrst/x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"token":"sbp_plain"}`)); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestSupabaseRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sb": token}), "s", json.RawMessage(`{"token":"secret://sb"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
