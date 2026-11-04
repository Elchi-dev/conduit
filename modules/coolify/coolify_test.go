package coolify

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

type fakeCoolify struct {
	mu     sync.Mutex
	seen   []string
	status map[string]string
}

func (f *fakeCoolify) app(id string) string {
	return fmt.Sprintf(`{"uuid":%q,"name":"app-%s","description":"shop","fqdn":"https://shop.example.com,https://www.example.com","status":%q,"build_pack":"nixpacks",
		"git_repository":"https://bob:ghp_LEAKME@github.com/acme/shop","git_branch":"main","git_commit_sha":"HEAD","ports_exposes":"3000","last_online_at":"2026-11-04T10:00:00Z",
		"manual_webhook_secret_github":"LEAKME","http_basic_auth_password":"LEAKME","dockerfile":"FROM LEAKME","environment_variables":[{"key":"DB","value":"LEAKME"}]}`, id, id, f.status[id])
}

func (f *fakeCoolify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthenticated."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.URL.Path {
	case "/api/v1/version":
		io.WriteString(w, `"4.0.0-beta.400"`)
	case "/api/v1/applications":
		fmt.Fprintf(w, `[%s,%s]`, f.app("a1"), f.app("a2"))
	case "/api/v1/applications/a1", "/api/v1/applications/a2":
		io.WriteString(w, f.app(strings.TrimPrefix(r.URL.Path, "/api/v1/applications/")))
	case "/api/v1/applications/a1/stop":
		f.status["a1"] = "exited:unhealthy"
		io.WriteString(w, `{"message":"Application stopping request queued."}`)
	case "/api/v1/applications/a1/start":
		f.status["a1"] = "running:healthy"
		io.WriteString(w, `{"message":"Deployment request queued.","deployment_uuid":"d9"}`)
	case "/api/v1/applications/a1/restart":
		io.WriteString(w, `{"message":"Restart request queued.","deployment_uuid":"d8"}`)
	case "/api/v1/deploy":
		fmt.Fprintf(w, `{"deployments":[{"message":"queued","resource_uuid":%q,"deployment_uuid":"d7"}]}`, r.URL.Query().Get("uuid"))
	case "/api/v1/servers":
		io.WriteString(w, `[{"uuid":"s1","name":"main","ip":"10.0.0.2","port":22,"user":"root","private_key_id":7,"private_key":"-----BEGIN LEAKME","settings":{"is_reachable":true,"is_usable":true,"is_build_server":false},"proxy":{"type":"traefik"}}]`)
	case "/api/v1/projects":
		io.WriteString(w, `[{"id":1,"uuid":"p1","name":"shop","description":"web"}]`)
	case "/api/v1/projects/p1":
		io.WriteString(w, `{"uuid":"p1","name":"shop","environments":[{"id":1,"name":"production"},{"id":2,"name":"staging"}]}`)
	case "/api/v1/deployments":
		io.WriteString(w, `[{"deployment_uuid":"d1","application_name":"app-a1","status":"in_progress","commit":"abc123","commit_message":"fix cart\n\nsecret details","is_webhook":true,"logs":"[{\"output\":\"DB=LEAKME\"}]","server_name":"main"}]`)
	case "/api/v1/deployments/applications/a1":
		io.WriteString(w, `{"count":1,"deployments":[{"deployment_uuid":"d2","application_name":"app-a1","status":"finished","is_api":true,"logs":"LEAKME"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeCoolify) {
	f := &fakeCoolify{status: map[string]string{"a1": "running:healthy", "a2": "exited:unhealthy"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "good", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCoolify(t *testing.T) {
	m, f := setup(t, "secret://c")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "2 applications, 1 running · Coolify 4.0.0-beta.400" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"applications", `{}`, `"gitRepository":"https://github.com/acme/shop"`},
		{"applications", `{}`, `"domains":["https://shop.example.com","https://www.example.com"]`},
		{"application", `{"application":"a2"}`, `"status":"exited:unhealthy"`},
		{"servers", `{}`, `"reachable":true`},
		{"servers", `{}`, `"proxy":"traefik"`},
		{"projects", `{}`, `"environments":["production","staging"]`},
		{"deployments", `{}`, `"commitMessage":"fix cart"`},
		{"deployments", `{}`, `"trigger":"webhook"`},
		{"deployments", `{"application":"a1"}`, `"trigger":"api"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "secret details") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Stop: preview, real, undo; then nothing to change.
	r, err := invoke(m, "stop_application", `{"application":"a1"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Stop app-a1" || f.status["a1"] != "running:healthy" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "stop_application", `{"application":"a1"}`, false)
	if err != nil || f.status["a1"] != "exited:unhealthy" || r.Undo == nil || r.Undo.Action != "start_application" || string(r.Undo.Input) != `{"application":"a1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "stop_application", `{"application":"a1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["a1"] != "running:healthy" || !strings.Contains(string(r.Output), `"deployment":"d9"`) {
		t.Fatal(string(r.Output), err)
	}
	if r, err := invoke(m, "restart_application", `{"application":"a1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"deployment":"d8"`) {
		t.Fatal(string(r.Output), err)
	}
	if r, err := invoke(m, "deploy_application", `{"application":"a1","force":true}`, true); err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"force":true`) {
		t.Fatal(err)
	}
	if r, err := invoke(m, "deploy_application", `{"application":"a1","force":true}`, false); err != nil || !strings.Contains(string(r.Output), `"deployment":"d7"`) {
		t.Fatal(string(r.Output), err)
	}
	if last := f.seen[len(f.seen)-1]; last != "GET /api/v1/deploy?force=true&uuid=a1" {
		t.Fatal(last)
	}
	if _, err := invoke(m, "deploy_application", `{"application":"zz"}`, false); err == nil || !strings.Contains(err.Error(), "no application") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_application") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestCoolifyValidation(t *testing.T) {
	m, f := setup(t, "secret://c")
	for _, c := range []struct{ action, in string }{
		{"deploy_application", `{}`}, {"stop_application", `{"application":"../servers"}`}, {"application", `{"application":"a b"}`},
		{"restart_application", `{"application":"x?y=1"}`}, {"deployments", `{"application":"a/b"}`}, {"deployments", `{"limit":500}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {URL: "coolify.example.com", Token: "secret://c"}, {URL: "https://u:p@coolify.example.com", Token: "secret://c"},
		{URL: "https://coolify.example.com/?x=1", Token: "secret://c"}, {URL: "https://coolify.example.com/#x", Token: "secret://c"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "Coolify refused the API token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "applications", `{}`, false); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

func TestCoolifyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
