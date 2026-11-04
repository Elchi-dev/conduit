package portainer

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

type fakePortainer struct {
	mu        sync.Mutex
	seen      []string
	stack     int    // 1 active, 2 inactive
	container string // running, exited
}

func (f *fakePortainer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "ptr_tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized","details":"A valid authorisation token is missing"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	stack := func(id int, git bool) string {
		g := "null"
		if git {
			g = `{"URL":"https://deploy:glpat_x@git.example.com/ops/media.git","ReferenceName":"refs/heads/main"}`
		}
		return `{"Id":` + map[bool]string{true: "3", false: "4"}[git] + `,"Name":"` + map[bool]string{true: "media", false: "web"}[git] + `","Type":2,"EndpointId":1,"Status":` + map[int]string{1: "1", 2: "2"}[id] + `,"Env":[{"name":"DB_PASSWORD","value":"hunter2"}],"GitConfig":` + g + `}`
	}
	ctr := "/api/endpoints/1/docker/containers/jellyfin"
	switch r.Method + " " + r.URL.Path {
	case "GET /api/endpoints":
		io.WriteString(w, `[{"Id":1,"Name":"local","Type":1,"URL":"unix:///var/run/docker.sock","Status":1,"Snapshots":[{"DockerVersion":"27.3.1","RunningContainerCount":5,"StoppedContainerCount":1,"StackCount":2,"ImageCount":9}]}]`)
	case "GET /api/system/status":
		io.WriteString(w, `{"Version":"2.24.0"}`)
	case "GET /api/stacks":
		io.WriteString(w, "["+stack(f.stack, true)+","+stack(1, false)+"]")
	case "GET /api/stacks/3":
		io.WriteString(w, stack(f.stack, true))
	case "GET /api/stacks/4":
		io.WriteString(w, stack(1, false))
	case "GET /api/stacks/4/file":
		io.WriteString(w, `{"StackFileContent":"services:\n  web:\n    image: nginx\n"}`)
	case "POST /api/stacks/3/stop":
		f.stack = 2
		io.WriteString(w, stack(2, true))
	case "POST /api/stacks/3/start":
		f.stack = 1
		io.WriteString(w, stack(1, true))
	case "PUT /api/stacks/3/git/redeploy", "PUT /api/stacks/4":
		io.WriteString(w, `{}`)
	case "GET /api/endpoints/1/docker/containers/json":
		io.WriteString(w, `[{"Id":"0123456789abcdef0123","Names":["/jellyfin"],"Image":"jellyfin/jellyfin","State":"`+f.container+`","Status":"Up 2 hours","Labels":{"com.docker.compose.project":"media"}}]`)
	case "GET /api/endpoints/1/docker/images/json":
		io.WriteString(w, `[{"Id":"sha256:aaaabbbbccccdddd","RepoTags":["nginx:latest"],"Size":187000000,"Created":1700000000}]`)
	case "GET " + ctr + "/json":
		io.WriteString(w, `{"Id":"0123","Name":"/jellyfin","State":{"Status":"`+f.container+`"},"Config":{"Image":"jellyfin/jellyfin"}}`)
	case "POST " + ctr + "/stop":
		f.container = "exited"
		w.WriteHeader(204)
	case "POST " + ctr + "/start":
		if f.container == "running" {
			w.WriteHeader(304)
			return
		}
		f.container = "running"
		w.WriteHeader(204)
	case "POST " + ctr + "/restart":
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakePortainer) {
	f := &fakePortainer{stack: 1, container: "running"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "ptr_tok", "secret://bad": "x"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPortainer(t *testing.T) {
	m, f := setup(t, "secret://p")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "1 environments · Portainer 2.24.0" {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{
		"environments": `"running":5`,
		"stacks":       `"git":"https://git.example.com/ops/media.git"`,
		"containers":   `"stack":"media"`,
		"images":       `"sizeMB":187`,
	} {
		r, err := invoke(m, action, `{"environment":1}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) || strings.Contains(string(r.Output), "hunter2") || strings.Contains(string(r.Output), "glpat_x") {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}

	r, err := invoke(m, "stop_stack", `{"id":3}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Stop stack media on environment 1" || f.stack != 1 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "stop_stack", `{"id":3}`, false)
	if err != nil || f.stack != 2 || r.Undo == nil || r.Undo.Action != "start_stack" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "/api/stacks/3/stop?endpointId=1") {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, "stop_stack", `{"id":3}`, false); err == nil || !strings.Contains(err.Error(), "already inactive") {
		t.Fatal(err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.stack != 1 || r.Undo.Action != "stop_stack" {
		t.Fatalf("%+v %v", r, err)
	}

	r, err = invoke(m, "redeploy_stack", `{"id":3}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Git https://git.example.com/ops/media.git@refs/heads/main") || strings.Contains(string(r.Plan.Changes[0].Before), "hunter2") {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if b, _ := json.Marshal(r.Plan); strings.Contains(string(b), "glpat_x") {
		t.Fatalf("the preview shows the repository's credentials: %s", b)
	}
	if r, err := invoke(m, "redeploy_stack", `{"id":3,"pullImage":false}`, false); err != nil || strings.Contains(string(r.Output), "glpat_x") {
		t.Fatal(err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.HasPrefix(last, "PUT /api/stacks/3/git/redeploy?endpointId=1") || !strings.Contains(last, `"pullImage":false`) || !strings.Contains(last, `"DB_PASSWORD"`) {
		t.Fatal(last)
	}
	if r, err := invoke(m, "redeploy_stack", `{"id":4}`, false); err != nil || !strings.Contains(string(r.Output), "compose file") {
		t.Fatal(err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.HasPrefix(last, "PUT /api/stacks/4?endpointId=1") || !strings.Contains(last, `image: nginx`) || !strings.Contains(last, `"pullImage":true`) {
		t.Fatal(last)
	}

	ctr := `{"environment":1,"container":"jellyfin"}`
	if p, err := invoke(m, "stop_container", ctr, true); err != nil || p.Plan == nil || f.container != "running" {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "stop_container", ctr, false)
	if err != nil || f.container != "exited" || r.Undo == nil || r.Undo.Action != "start_container" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.container != "running" || r.Undo.Action != "stop_container" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "start_container", ctr, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "restart_container", ctr, false); err != nil || r.Undo != nil {
		t.Fatal(err)
	}
}

func TestPortainerValidation(t *testing.T) {
	m, f := setup(t, "secret://p")
	for _, c := range []struct{ action, in string }{
		{"start_container", `{"environment":1,"container":"../../../api/users"}`},
		{"start_container", `{"environment":1,"container":"a/b"}`},
		{"start_container", `{"environment":1,"container":"x?y"}`},
		{"start_container", `{"environment":0,"container":"web"}`},
		{"restart_container", `{"environment":1}`},
		{"containers", `{}`},
		{"images", `{"environment":-2}`},
		{"stop_stack", `{"id":0}`},
		{"redeploy_stack", `{}`},
		{"stop_stack", `{"id":"3/../4"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://portainer", Token: "plain"}, {URL: "portainer:9443", Token: "secret://p"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not carry the X-API-Key there.
func TestPortainerRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://p"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "ptr_tok"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
