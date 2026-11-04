package argoworkflows

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

type fake struct {
	mu        sync.Mutex
	seen      []string
	phase     string
	submitted map[string]any
	acted     string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer awtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":16,"message":"token not valid"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	wf := func(name, phase, created string) string {
		return `{"metadata":{"name":"` + name + `","namespace":"argo","creationTimestamp":"` + created + `","labels":{"workflows.argoproj.io/phase":"` + phase + `"}},
			"spec":{"entrypoint":"main","workflowTemplateRef":{"name":"deploy"},"arguments":{"parameters":[{"name":"env","value":"prod"},{"name":"api_token","value":"tok-plain-xyz"},{"name":"repo","value":"https://ci:glfake-abcdefghijklmnopqrstu@git.example.com/x"}]},
			"templates":[{"name":"main","container":{"env":[{"name":"PW","value":"inline-secret-123"}]}}]},
			"status":{"phase":"` + phase + `","startedAt":"2026-11-04T10:00:00Z","finishedAt":"2026-11-04T10:02:00Z","progress":"1/2","message":"child failed: password=hunter2hunter2",
			"nodes":{"a":{"displayName":"build","templateName":"build","type":"Pod","phase":"Succeeded","startedAt":"2026-11-04T10:00:00Z","finishedAt":"2026-11-04T10:01:00Z"},
			"b":{"displayName":"` + name + `","type":"Steps","phase":"` + phase + `"},
			"c":{"displayName":"test","templateName":"test","type":"Pod","phase":"Failed","message":"exit code 1","startedAt":"2026-11-04T10:01:00Z"}}}}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/version":
		io.WriteString(w, `{"version":"v3.6.2","gitCommit":"x"}`)
	case "GET /api/v1/workflows/argo":
		q := r.URL.Query()
		if q.Get("listOptions.limit") == "1" {
			io.WriteString(w, `{"items":null}`)
			return
		}
		if q.Get("listOptions.labelSelector") != "workflows.argoproj.io/phase=Failed" || q.Get("listOptions.limit") != "20" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"metadata":{},"items":[`+wf("old-1", "Failed", "2026-11-03T10:00:00Z")+`,`+wf("new-2", "Failed", "2026-11-04T10:00:00Z")+`]}`)
	case "GET /api/v1/workflows/argo/new-2":
		io.WriteString(w, wf("new-2", f.phase, "2026-11-04T10:00:00Z"))
	case "GET /api/v1/workflow-templates/argo":
		io.WriteString(w, `{"items":[{"metadata":{"name":"deploy","creationTimestamp":"2026-11-01T00:00:00Z"},"spec":{"entrypoint":"main","arguments":{"parameters":[{"name":"env","value":"staging","enum":["staging","prod"],"description":"Where to"},{"name":"db_password","value":"plain-default-pw"},{"name":"cfg","valueFrom":{"configMapKeyRef":{"name":"x","key":"y"}}}]}}}]}`)
	case "GET /api/v1/workflow-templates/argo/deploy":
		io.WriteString(w, `{"metadata":{"name":"deploy"},"spec":{"entrypoint":"main","arguments":{"parameters":[{"name":"env","value":"staging","enum":["staging","prod"]},{"name":"replicas","value":"1"},{"name":"cfg","valueFrom":{"configMapKeyRef":{"name":"x","key":"y"}}}]}}}`)
	case "POST /api/v1/workflows/argo/submit":
		json.NewDecoder(r.Body).Decode(&f.submitted)
		io.WriteString(w, `{"metadata":{"name":"deploy-abc12","namespace":"argo"},"status":{}}`)
	case "PUT /api/v1/workflows/argo/new-2/stop", "PUT /api/v1/workflows/argo/new-2/terminate", "PUT /api/v1/workflows/argo/new-2/retry":
		f.acted = r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		io.WriteString(w, `{"metadata":{"name":"new-2"},"status":{"phase":"Running"}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":5,"message":"workflows.argoproj.io \"x\" not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{phase: "Failed"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://aw": "Bearer awtok\n", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestArgoReads(t *testing.T) {
	m, _ := setup(t, "secret://aw")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "Argo Workflows v3.6.2 · namespace argo" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"workflows", `{"phase":"Failed"}`, []string{`"name":"new-2"`, `"template":"deploy"`, `"duration":"2m0s"`, `"progress":"1/2"`}},
		{"workflow", `{"workflow":"new-2"}`, []string{`"entrypoint":"main"`, `{"name":"env","value":"prod"}`, `{"name":"api_token","value":"[hidden]"}`, `"message":"exit code 1"`, `"duration":"1m0s"`}},
		{"workflow_templates", `{}`, []string{`"enum":["staging","prod"]`, `"value":"[hidden]"`, `"valueFrom":true`, `"description":"Where to"`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		for _, leak := range []string{"tok-plain-xyz", "inline-secret-123", "hunter2", "plain-default-pw", "glpat-"} {
			if strings.Contains(string(r.Output), leak) {
				t.Fatalf("%s leaks %s: %s", c.action, leak, r.Output)
			}
		}
	}
	if r, _ := invoke(m, "workflows", `{"phase":"Failed"}`, false); !strings.Contains(string(r.Output), `[{"created":"2026-11-04`) {
		t.Fatalf("not newest first: %s", r.Output)
	}
	if r, _ := invoke(m, "workflow", `{"workflow":"new-2"}`, false); strings.Index(string(r.Output), `"name":"build"`) > strings.Index(string(r.Output), `"name":"test"`) || strings.Contains(string(r.Output), `"type":"Steps"`) {
		t.Fatalf("steps: %s", r.Output)
	}
}

func TestArgoSubmit(t *testing.T) {
	m, f := setup(t, "secret://aw")
	p, err := invoke(m, "submit_workflow", `{"template":"deploy","parameters":{"env":"prod","replicas":3}}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Submit a workflow from template deploy in argo with parameters" || f.submitted != nil {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "submit_workflow", `{"template":"deploy","parameters":{"env":"prod","replicas":3}}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"workflow":"deploy-abc12"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if b, _ := json.Marshal(f.submitted); string(b) != `{"namespace":"argo","resourceKind":"WorkflowTemplate","resourceName":"deploy","submitOptions":{"parameters":["env=prod","replicas=3"]}}` {
		t.Fatalf("submitted %s", b)
	}
	for _, bad := range []string{
		`{"template":"deploy","parameters":{"env":"qa"}}`,
		`{"template":"deploy","parameters":{"undeclared":"x"}}`,
		`{"template":"deploy","parameters":{"cfg":"x"}}`,
		`{"template":"deploy","parameters":{"env":null}}`,
	} {
		f.submitted = nil
		if _, err := invoke(m, "submit_workflow", bad, false); err == nil || f.submitted != nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestArgoStopTerminateRetry(t *testing.T) {
	m, f := setup(t, "secret://aw")
	for _, a := range []string{"stop_workflow", "terminate_workflow"} {
		if r, err := invoke(m, a, `{"workflow":"new-2"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || f.acted != "" {
			t.Fatalf("%s %s %v", a, r.Output, err)
		}
	}
	if p, err := invoke(m, "retry_workflow", `{"workflow":"new-2"}`, true); err != nil || p.Plan == nil || p.Plan.Summary != "Retry argo/new-2 from its failed steps (from template deploy)" || f.acted != "" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "retry_workflow", `{"workflow":"new-2"}`, false); err != nil || f.acted != "retry" {
		t.Fatal(err, f.acted)
	}
	f.phase, f.acted = "Succeeded", ""
	if _, err := invoke(m, "retry_workflow", `{"workflow":"new-2"}`, false); err == nil || f.acted != "" {
		t.Fatal("retried a succeeded workflow")
	}
	f.phase = "Running"
	if _, err := invoke(m, "retry_workflow", `{"workflow":"new-2"}`, false); err == nil || f.acted != "" {
		t.Fatal("retried a running workflow")
	}
	if p, err := invoke(m, "terminate_workflow", `{"workflow":"new-2"}`, true); err != nil || p.Plan == nil || f.acted != "" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, a := range []string{"stop", "terminate"} {
		f.acted = ""
		if r, err := invoke(m, a+"_workflow", `{"workflow":"new-2"}`, false); err != nil || f.acted != a || !strings.Contains(string(r.Output), `"was":"Running"`) {
			t.Fatalf("%s %s %v", a, r.Output, err)
		}
	}
}

func TestArgoValidation(t *testing.T) {
	m, f := setup(t, "secret://aw")
	for _, c := range []struct{ action, in string }{
		{"workflows", `{"namespace":"../kube-system"}`},
		{"workflows", `{"namespace":"Argo"}`},
		{"workflows", `{"phase":"Exploded"}`},
		{"workflows", `{"limit":500}`},
		{"workflow", `{"workflow":"a/b"}`},
		{"workflow", `{}`},
		{"workflow_templates", `{"namespace":"a b"}`},
		{"submit_workflow", `{"template":"Deploy"}`},
		{"submit_workflow", `{"template":"deploy","parameters":{"db_password":"x"}}`},
		{"submit_workflow", `{"template":"deploy","parameters":{"a b":"x"}}`},
		{"stop_workflow", `{"workflow":"x?y"}`},
		{"terminate_workflow", `{"workflow":".."}`},
		{"retry_workflow", `{"workflow":"-x"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://argo.example.com", Token: "plain"},
		{URL: "https://u:p@argo.example.com", Token: "secret://aw"},
		{URL: "https://argo.example.com?x=1", Token: "secret://aw"},
		{URL: "https://argo.example.com#x", Token: "secret://aw"},
		{URL: "https://argo.example.com", Token: "secret://aw", Namespace: "Bad_NS"},
		{URL: "https://argo.example.com", Token: "secret://aw", Fingerprint: "zz"},
		{Token: "secret://aw"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestArgoRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://aw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://aw": "awtok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestArgoRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "submit_workflow", "stop_workflow", "terminate_workflow", "retry_workflow":
			want = sdk.RiskDestructive
			if !a.DryRun {
				t.Errorf("%s has no preview", a.Name)
			}
		}
		if a.Risk != want || a.Sensitive {
			t.Errorf("%s is %s sensitive=%v", a.Name, a.Risk, a.Sensitive)
		}
	}
}
