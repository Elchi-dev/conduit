package dokploy

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

type fakeDokploy struct {
	mu     sync.Mutex
	seen   []string
	status map[string]string
}

func (f *fakeDokploy) app(id string) string {
	return fmt.Sprintf(`{"applicationId":%q,"name":"web-%s","appName":"web-%s-x1","applicationStatus":%q,"sourceType":"git","customGitUrl":"https://bob:LEAKME@git.example.com/shop.git","customGitBranch":"main",
		"buildType":"nixpacks","replicas":2,"env":"DB=LEAKME","buildArgs":"TOKEN=LEAKME","password":"LEAKME","registry":{"password":"LEAKME"},"customGitSSHKeyId":"LEAKME",
		"domains":[{"host":"shop.example.com","https":true,"port":3000,"path":"/"}],"deployments":[{"deploymentId":"d1","title":"Rebuild\nmore","status":"done","createdAt":"2026-11-04","logPath":"/etc/dokploy/LEAKME.log"}]}`,
		id, id, id, f.status[id])
}

func (f *fakeDokploy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("x-api-key") != "good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]string
	json.Unmarshal(body, &b)
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/project.all":
		io.WriteString(w, `[{"projectId":"p1","name":"shop","description":"web","env":"LEAKME","environments":[{"name":"production","env":"LEAKME","applications":[{"applicationId":"a1","name":"web-a1","applicationStatus":"done","env":"LEAKME"}],"compose":[{"composeId":"c1","name":"db","composeStatus":"error","env":"LEAKME"}]}]},
			{"projectId":"p2","name":"old","applications":[{"applicationId":"a2","name":"web-a2","applicationStatus":"idle"}],"compose":[]}]`)
	case "GET /api/application.one":
		id := q.Get("applicationId")
		if _, ok := f.status[id]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Application not found"}`)
			return
		}
		io.WriteString(w, f.app(id))
	case "GET /api/compose.one":
		fmt.Fprintf(w, `{"composeId":%q,"name":"db","composeStatus":%q,"composeType":"docker-compose","sourceType":"github","owner":"acme","repository":"db","branch":"main","env":"LEAKME","composeFile":"LEAKME"}`, q.Get("composeId"), f.status[q.Get("composeId")])
	case "GET /api/deployment.all":
		io.WriteString(w, `[{"deploymentId":"d2","title":"Manual deployment","status":"done","createdAt":"2026-11-04","logPath":"/LEAKME"}]`)
	case "GET /api/deployment.allByCompose":
		io.WriteString(w, `[{"deploymentId":"d3","title":"Compose","status":"error","createdAt":"2026-11-03"}]`)
	case "POST /api/application.stop":
		f.status[b["applicationId"]] = "idle"
	case "POST /api/application.start":
		f.status[b["applicationId"]] = "done"
	case "POST /api/application.deploy", "POST /api/compose.deploy":
		io.WriteString(w, `true`)
	case "POST /api/compose.stop":
		f.status[b["composeId"]] = "idle"
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeDokploy) {
	f := &fakeDokploy{status: map[string]string{"a1": "done", "a2": "idle", "c1": "error"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://d": "good", "secret://bad": "nope"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDokploy(t *testing.T) {
	m, f := setup(t, "secret://d")
	if h := m.Health(context.Background(), "d"); h.Status != "degraded" || h.Message != "2 projects, 3 services · 1 failed their last deployment" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"compose":[{"id":"c1","name":"db","status":"error"}]`},
		{"projects", `{}`, `"name":"production"`},
		{"application", `{"application":"a1"}`, `"repository":"https://git.example.com/shop.git"`},
		{"application", `{"application":"a1"}`, `"domains":["https://shop.example.com/"]`},
		{"application", `{"application":"a1"}`, `"title":"Rebuild"`},
		{"compose", `{"compose":"c1"}`, `"repository":"acme/db"`},
		{"deployments", `{"application":"a1"}`, `"id":"d2"`},
		{"deployments", `{"compose":"c1"}`, `"status":"error"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	r, err := invoke(m, "stop_application", `{"application":"a1"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Stop application web-a1" || f.status["a1"] != "done" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "stop_application", `{"application":"a1"}`, false)
	if err != nil || f.status["a1"] != "idle" || r.Undo == nil || r.Undo.Action != "start_application" || string(r.Undo.Input) != `{"application":"a1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(r.Undo.Description, "as one instance") {
		t.Fatal(r.Undo.Description)
	}
	// "idle" is only what Dokploy recorded: the stop is sent again, without
	// an undo that would start what may have been stopped before.
	n := len(f.seen)
	if r, err := invoke(m, "stop_application", `{"application":"a1"}`, false); err != nil || r.Undo != nil || len(f.seen) != n+2 || !strings.HasPrefix(f.seen[n+1], "POST /api/application.stop") {
		t.Fatalf("idle stop: %+v %v", r, err)
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["a1"] != "done" || !strings.Contains(string(r.Output), "deploy it to run all 2 replicas") {
		t.Fatal(err)
	}
	// Starting an application with replicas that may be running would cut
	// it to one instance.
	f.status["a1"] = "error"
	n = len(f.seen)
	if _, err := invoke(m, "start_application", `{"application":"a1"}`, false); err == nil || !strings.Contains(err.Error(), "deploy it instead") || len(f.seen) != n+1 {
		t.Fatal(err, f.seen[n:])
	}
	f.status["a1"] = "done"
	if r, err := invoke(m, "start_application", `{"application":"a1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "deploy_application", `{"application":"a1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"done":"deploy"`) {
		t.Fatal(err)
	}
	if r, err := invoke(m, "stop_compose", `{"compose":"c1"}`, false); err != nil || r.Undo == nil || r.Undo.Action != "start_compose" || f.status["c1"] != "idle" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "deploy_compose", `{"compose":"c1"}`, true); err != nil || r.Plan == nil || !strings.HasPrefix(r.Plan.Summary, "Deploy compose service db") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "deploy_application", `{"application":"zz"}`, false); err == nil || !strings.Contains(err.Error(), "no application") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (strings.HasPrefix(a.Name, "deploy_") || strings.HasPrefix(a.Name, "stop_")) && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestDokployValidation(t *testing.T) {
	m, f := setup(t, "secret://d")
	for _, c := range []struct{ action, in string }{
		{"deploy_application", `{}`}, {"stop_application", `{"application":"../x"}`}, {"compose", `{"compose":"a b"}`},
		{"deploy_compose", `{"application":"a1"}`}, {"deployments", `{}`}, {"deployments", `{"application":"a1","compose":"c1"}`},
		{"deployments", `{"compose":"x&y=1"}`}, {"deployments", `{"application":"a1","limit":101}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://d.example.com", APIKey: "plain"}, {APIKey: "secret://d"}, {URL: "https://u:p@d.example.com", APIKey: "secret://d"},
		{URL: "https://d.example.com/?x=1", APIKey: "secret://d"}, {URL: "ftp://d.example.com", APIKey: "secret://d"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "Dokploy refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestDokployRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("x-api-key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://d"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://d": "good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
