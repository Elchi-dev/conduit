package buildkite

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

const jobID = "01890000-aaaa-bbbb-cccc-000000000001"

type fake struct {
	mu        sync.Mutex
	seen      []string
	state     string
	rebuilt   bool
	cancelled bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer bktok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Authentication required. Please supply a valid API Access Token"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	q := r.URL.Query()
	build := func(n int, state string) string {
		return fmt.Sprintf(`{"id":"b%d","number":%d,"state":%q,"message":"Ship it\n\nbody","commit":"abcdef0123456789","branch":"main","source":"webhook","web_url":"https://buildkite.com/acme/web/builds/%d",
			"created_at":"2026-11-04T10:00:00Z","started_at":"2026-11-04T10:00:05Z","finished_at":"2026-11-04T10:02:05Z","creator":{"name":"Kim","email":"kim@example.com"},"pipeline":{"slug":"web"},
			"jobs":[{"id":%q,"type":"script","name":":go: test","step_key":"test","state":"failed","exit_status":1,"started_at":"2026-11-04T10:00:05Z","finished_at":"2026-11-04T10:01:05Z"},{"id":"01890000-aaaa-bbbb-cccc-000000000002","type":"waiter","state":"passed"}]}`, n, n, state, n, jobID)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /access-token":
		io.WriteString(w, `{"uuid":"t1","scopes":["read_builds","write_builds"]}`)
	case "GET /organizations/acme":
		io.WriteString(w, `{"slug":"acme","name":"Acme Inc"}`)
	case "GET /organizations/acme/pipelines":
		if q.Get("page") == "1" {
			w.Header().Set("Link", `<https://api.buildkite.com/v2/organizations/acme/pipelines?page=2&per_page=100>; rel="next"`)
			io.WriteString(w, `[{"slug":"web","name":"Web","repository":"https://bot:s3cret@github.com/acme/web.git","default_branch":"main","running_builds_count":1}]`)
			return
		}
		io.WriteString(w, `[{"slug":"api","name":"API","repository":"git@github.com:acme/api.git","default_branch":"main","archived_at":"2026-01-01T00:00:00Z"}]`)
	case "GET /organizations/acme/pipelines/web/builds", "GET /organizations/acme/builds":
		if q.Get("per_page") != "20" || q.Get("branch") != "main" || q.Get("state") != "failed" {
			w.WriteHeader(400)
			io.WriteString(w, `{"message":"bad query"}`)
			return
		}
		io.WriteString(w, "["+build(12, "failed")+"]")
	case "GET /organizations/acme/pipelines/web/builds/12":
		io.WriteString(w, build(12, f.state))
	case "GET /organizations/acme/pipelines/web/builds/12/jobs/" + jobID + "/log.txt":
		var b strings.Builder
		for i := 1; i <= 300; i++ {
			fmt.Fprintf(&b, "\x1b_bk;t=17000000%02d\x07\x1b[32mline %d\x1b[0m\n", i%100, i)
		}
		io.WriteString(w, b.String())
	case "PUT /organizations/acme/pipelines/web/builds/12/rebuild":
		f.rebuilt = true
		io.WriteString(w, build(13, "scheduled"))
	case "PUT /organizations/acme/pipelines/web/builds/12/cancel":
		f.cancelled = true
		io.WriteString(w, build(12, "canceling"))
	case "GET /organizations/acme/agents":
		io.WriteString(w, `[{"id":"a1","name":"ci-1","connection_state":"connected","hostname":"ci-1.internal","ip_address":"10.0.0.9","version":"3.80.0","meta_data":["queue=deploy","os=linux"],"created_at":"2026-11-01T00:00:00Z","job":{"id":"x"}}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"No build found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "failed"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Organization: "acme", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bk": "bktok", "secret://bad": "nope"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBuildkiteReads(t *testing.T) {
	m, _ := setup(t, "secret://bk")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "Acme Inc · scopes: read_builds, write_builds" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"pipelines", `{}`, []string{`"repository":"https://github.com/acme/web.git"`, `"slug":"api"`, `"archived":true`, `"runningBuilds":1`}},
		{"builds", `{"pipeline":"web","branch":"main","state":"failed"}`, []string{`"number":12`, `"message":"Ship it"`, `"commit":"abcdef0123"`, `"duration":"2m0s"`, `"creator":"Kim"`}},
		{"builds", `{"branch":"main","state":"failed"}`, []string{`"pipeline":"web"`}},
		{"build", `{"pipeline":"web","number":12}`, []string{`"id":"` + jobID + `"`, `"exitStatus":1`, `"key":"test"`, `"type":"waiter"`}},
		{"job_log", `{"pipeline":"web","number":12,"job":"` + jobID + `","lines":3}`, []string{`"lines":["line 298","line 299","line 300"]`, `"exitStatus":1`, `"job":":go: test"`}},
		{"agents", `{}`, []string{`"queue":"deploy"`, `"busy":true`, `"hostname":"ci-1.internal"`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		if strings.Contains(string(r.Output), "s3cret") || strings.Contains(string(r.Output), "10.0.0.9") || strings.Contains(string(r.Output), "kim@example.com") {
			t.Fatalf("%s leaks: %s", c.action, r.Output)
		}
	}
	if _, err := invoke(m, "job_log", `{"pipeline":"web","number":12,"job":"01890000-aaaa-bbbb-cccc-000000000002"}`, false); err == nil || !strings.Contains(err.Error(), "no log") {
		t.Fatal(err)
	}
}

func TestBuildkiteRebuildCancel(t *testing.T) {
	m, f := setup(t, "secret://bk")
	if _, err := invoke(m, "cancel_build", `{"pipeline":"web","number":12}`, false); err == nil || !strings.Contains(err.Error(), "nothing to cancel") || f.cancelled {
		t.Fatal(err)
	}
	p, err := invoke(m, "rebuild", `{"pipeline":"web","number":12}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Run acme/web#12 again (main) as a new build" || f.rebuilt {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err := invoke(m, "rebuild", `{"pipeline":"web","number":12}`, false); err != nil || !f.rebuilt || !strings.Contains(string(r.Output), `"number":13`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.state, f.rebuilt = "running", false
	if _, err := invoke(m, "rebuild", `{"pipeline":"web","number":12}`, false); err == nil || f.rebuilt {
		t.Fatal("rebuilt a running build")
	}
	if p, err := invoke(m, "cancel_build", `{"pipeline":"web","number":12}`, true); err != nil || p.Plan == nil || f.cancelled || !strings.HasPrefix(p.Plan.Summary, "Cancel acme/web#12 (running)") {
		t.Fatalf("%+v %v", p, err)
	}
	if r, err := invoke(m, "cancel_build", `{"pipeline":"web","number":12}`, false); err != nil || !f.cancelled || !strings.Contains(string(r.Output), `"state":"canceling"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestBuildkiteValidation(t *testing.T) {
	m, f := setup(t, "secret://bk")
	for _, c := range []struct{ action, in string }{
		{"builds", `{"pipeline":"../me"}`},
		{"builds", `{"pipeline":"web/builds"}`},
		{"builds", `{"pipeline":"web","limit":500}`},
		{"builds", `{"pipeline":"web","state":"exploded"}`},
		{"builds", `{"pipeline":"web","branch":"a b"}`},
		{"build", `{"pipeline":"web","number":0}`},
		{"build", `{"pipeline":"","number":1}`},
		{"job_log", `{"pipeline":"web","number":12,"job":"../../x"}`},
		{"job_log", `{"pipeline":"web","number":12,"job":"` + jobID + `","lines":5000}`},
		{"rebuild", `{"pipeline":"web?x=1","number":12}`},
		{"cancel_build", `{"pipeline":"web","number":-1}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Organization: "acme", Token: "plain"}, {Organization: "../x", Token: "secret://bk"}, {Token: "secret://bk"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "refused the API token") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestBuildkiteRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Organization: "acme", Token: "secret://bk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bk": "bktok"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestBuildkiteRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		if a.Name == "rebuild" || a.Name == "cancel_build" {
			want = sdk.RiskDestructive
			if !a.DryRun {
				t.Errorf("%s has no preview", a.Name)
			}
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
		if (a.Name == "job_log") != a.Sensitive {
			t.Errorf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
}
