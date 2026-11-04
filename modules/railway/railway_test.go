package railway

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
	proj = "11111111-1111-4111-8111-111111111111"
	svc  = "22222222-2222-4222-8222-222222222222"
	env  = "33333333-3333-4333-8333-333333333333"
	dep  = "44444444-4444-4444-8444-444444444444"
	dep2 = "55555555-5555-4555-8555-555555555555"
)

type fakeRailway struct {
	mu        sync.Mutex
	seen      []string
	redeploys int
	restarts  int
}

func (f *fakeRailway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	project := r.Header.Get("Project-Access-Token") == "ptok"
	if auth != "Bearer rtok" && !project {
		io.WriteString(w, `{"errors":[{"message":"Not Authorized"}],"data":null}`)
		return
	}
	var req struct {
		Query     string
		Variables map[string]any
	}
	json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req.Query)
	data := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	edges := func(nodes ...any) map[string]any {
		es := []any{}
		for _, n := range nodes {
			es = append(es, map[string]any{"node": n})
		}
		return map[string]any{"edges": es}
	}
	pr := map[string]any{"id": proj, "name": "shop", "updatedAt": "2026-11-01T00:00:00Z", "environments": edges(map[string]any{"id": env, "name": "production"}), "services": edges(map[string]any{"id": svc, "name": "api"})}
	depl := func(id, status string) map[string]any {
		return map[string]any{"id": id, "status": status, "createdAt": "2026-11-02T00:00:00Z", "staticUrl": "api.up.railway.app", "projectId": proj, "serviceId": svc, "environmentId": env,
			"service": map[string]any{"name": "api"}, "environment": map[string]any{"name": "production"},
			"meta": map[string]any{"commitHash": "abc123", "branch": "main", "commitMessage": "fix cart\n\ndetails", "secretEnv": "DATABASE_URL=postgres://x"}}
	}
	switch req.Query {
	case qMe:
		data(map[string]any{"me": map[string]any{"name": "Elchi", "email": "private@example.com"}})
	case qProjectToken:
		data(map[string]any{"projectToken": map[string]any{"projectId": proj, "environmentId": env}})
	case qProjects:
		data(map[string]any{"projects": edges(pr)})
	case qProject:
		data(map[string]any{"project": pr})
	case qServices:
		s := map[string]any{"id": svc, "name": "api", "serviceInstances": edges(map[string]any{"environmentId": env, "latestDeployment": depl(dep, "SUCCESS")})}
		data(map[string]any{"project": map[string]any{"id": proj, "environments": pr["environments"], "services": edges(s)}})
	case qDeployments:
		in := req.Variables["input"].(map[string]any)
		if in["projectId"] != proj || in["serviceId"] != svc {
			io.WriteString(w, `{"errors":[{"message":"Problem processing request"}]}`)
			return
		}
		data(map[string]any{"deployments": edges(depl(dep, "SUCCESS"), depl(dep2, "FAILED"))})
	case qDeployment:
		switch req.Variables["id"] {
		case dep:
			data(map[string]any{"deployment": depl(dep, "SUCCESS")})
		case dep2:
			data(map[string]any{"deployment": depl(dep2, "FAILED")})
		default:
			data(map[string]any{"deployment": nil})
		}
	case qLogs:
		lines := []any{}
		for i := 0; i < 600; i++ {
			lines = append(lines, map[string]any{"timestamp": "t", "message": "line", "severity": "info"})
		}
		lines = append(lines, map[string]any{"timestamp": "t", "message": "panic: boom", "severity": "error"})
		data(map[string]any{"deploymentLogs": lines})
	case qBuildLogs:
		data(map[string]any{"buildLogs": []any{map[string]any{"timestamp": "t", "message": "go build ./..."}}})
	case mRedeploy:
		f.redeploys++
		data(map[string]any{"deploymentRedeploy": map[string]any{"id": "66666666-6666-4666-8666-666666666666", "status": "INITIALIZING"}})
	case mRestart:
		f.restarts++
		data(map[string]any{"deploymentRestart": true})
	default:
		io.WriteString(w, `{"errors":[{"message":"Cannot query field"}]}`)
	}
}

func setup(t *testing.T, ref, kind string) (*Module, *fakeRailway) {
	f := &fakeRailway{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref, TokenType: kind})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rw": "rtok", "secret://pt": "ptok", "secret://bad": "nope"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRailwayReads(t *testing.T) {
	m, _ := setup(t, "secret://rw", "")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "signed in as Elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"name":"production"`},
		{"environments", `{"project":"` + proj + `"}`, `"name":"production"`},
		{"services", `{"project":"` + proj + `"}`, `"status":"SUCCESS"`},
		{"deployments", `{"project":"` + proj + `","service":"` + svc + `"}`, `"message":"fix cart"`},
		{"deployments", `{"project":"` + proj + `","service":"` + svc + `"}`, `"status":"FAILED"`},
		{"logs", `{"deployment":"` + dep + `","lines":5}`, `"severity":"error"`},
		{"logs", `{"deployment":"` + dep + `","build":true}`, `go build`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "private@") || strings.Contains(out, "DATABASE_URL") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	r, _ := invoke(m, "logs", `{"deployment":"`+dep+`","lines":5000}`, false)
	var l struct{ Lines []any }
	json.Unmarshal(r.Output, &l)
	if len(l.Lines) != 100 {
		t.Fatalf("log tail not bounded: %d", len(l.Lines))
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "logs" && !a.Sensitive {
			t.Fatal("logs must be sensitive")
		}
		if (a.Name == "restart" || a.Name == "redeploy") && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Name + " must be destructive")
		}
	}

	pm, _ := setup(t, "secret://pt", "project")
	if h := pm.Health(context.Background(), "r"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(pm, "projects", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"name":"shop"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestRailwayWrites(t *testing.T) {
	m, f := setup(t, "secret://rw", "account")
	r, err := invoke(m, "redeploy", `{"project":"`+proj+`","service":"`+svc+`","environment":"`+env+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Build and deploy api in production (deployment "+dep+") again" || f.redeploys != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "redeploy", `{"deployment":"`+dep2+`"}`, false)
	if err != nil || f.redeploys != 1 || !strings.Contains(string(r.Output), `"status":"INITIALIZING"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "restart", `{"deployment":"`+dep+`"}`, true); err != nil || r.Plan == nil || f.restarts != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "restart", `{"deployment":"`+dep+`"}`, false); err != nil || f.restarts != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "restart", `{"deployment":"`+dep2+`"}`, false); err == nil || !strings.Contains(err.Error(), "FAILED") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "restart", `{"deployment":"77777777-7777-4777-8777-777777777777"}`, false); err == nil || !strings.Contains(err.Error(), "no deployment") {
		t.Fatal(err)
	}
}

func TestRailwayValidation(t *testing.T) {
	m, f := setup(t, "secret://rw", "")
	for _, c := range []struct{ action, in string }{
		{"environments", `{"project":"shop"}`},
		{"services", `{"project":"` + proj + `\") { x }"}`},
		{"deployments", `{"project":"` + proj + `"}`},
		{"deployments", `{"project":"` + proj + `","service":"` + svc + `","environment":"prod"}`},
		{"logs", `{"deployment":"../x"}`},
		{"redeploy", `{"project":"` + proj + `"}`},
		{"restart", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Railway: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {Token: "secret://rw", TokenType: "admin"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "")
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestRailwayRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pt": "ptok"}), "r", json.RawMessage(`{"token":"secret://pt","tokenType":"project"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
