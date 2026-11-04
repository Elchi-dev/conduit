package teamcity

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

type fake struct {
	mu        sync.Mutex
	seen      []string
	state     string
	queued    map[string]any
	cancelled string
}

const btJSON = `{"id":"Web_Build","name":"Build","projectId":"Web","projectName":"Web","paused":false,"webUrl":"https://tc/bt","parameters":{"property":[
	{"name":"env","value":"staging","type":{"rawValue":"select data_1='staging' data_2='production' display='normal'"}},
	{"name":"run.tests","value":"yes","type":{"rawValue":"checkbox checkedValue='yes' uncheckedValue='no'"}},
	{"name":"deploy.password","value":"","type":{"rawValue":"password display='hidden'"}},
	{"name":"env.API_TOKEN","value":"tok-plain-123"},
	{"name":"note","value":"hello"}]}}`

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tctok" {
		w.WriteHeader(401)
		io.WriteString(w, "Authentication required")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	q := r.URL.Query()
	build := func(state string) string {
		return fmt.Sprintf(`{"id":42,"number":"17","status":"FAILURE","state":%q,"branchName":"main","buildTypeId":"Web_Build","statusText":"Tests failed: token=abcdef1234567890","queuedDate":"20261104T100000+0000","startDate":"20261104T100005+0000","webUrl":"https://tc/b/42","percentageComplete":40,
			"triggered":{"type":"user","user":{"username":"kim","email":"kim@example.com"}},"agent":{"name":"agent-1"},"revisions":{"revision":[{"version":"abcdef0123456789"}]}}`, state)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /app/rest/server":
		io.WriteString(w, `{"version":"2025.03 (build 186049)"}`)
	case "GET /app/rest/users/current":
		io.WriteString(w, `{"username":"ci-bot","email":"bot@example.com"}`)
	case "GET /app/rest/projects":
		io.WriteString(w, `{"count":2,"project":[{"id":"_Root","name":"<Root project>"},{"id":"Web","name":"Web","parentProjectId":"_Root","archived":true}]}`)
	case "GET /app/rest/buildTypes":
		if q.Get("locator") != "affectedProject:(id:Web)" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"buildType":[{"id":"Web_Build","name":"Build","projectId":"Web","projectName":"Web","paused":true}]}`)
	case "GET /app/rest/buildTypes/id:Web_Build":
		io.WriteString(w, btJSON)
	case "GET /app/rest/builds":
		if q.Get("locator") != "buildType:(id:Web_Build),branch:(default:any),state:finished,defaultFilter:false,count:20" {
			w.WriteHeader(400)
			io.WriteString(w, "bad locator "+q.Get("locator"))
			return
		}
		io.WriteString(w, `{"build":[`+build("finished")+`]}`)
	case "GET /app/rest/buildQueue":
		io.WriteString(w, `{"build":[{"id":43,"state":"queued","buildTypeId":"Web_Build","waitReason":"No agents"}]}`)
	case "GET /app/rest/builds/id:42":
		io.WriteString(w, build(f.state))
	case "GET /downloadBuildLog.html":
		if q.Get("buildId") != "42" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		var b strings.Builder
		for i := 1; i <= 300; i++ {
			fmt.Fprintf(&b, "[10:00:%02d]i: \x1b[32mline %d\x1b[0m\n", i%60, i)
		}
		b.WriteString("export PASSWORD=hunter2hunter2\n")
		io.WriteString(w, b.String())
	case "POST /app/rest/buildQueue":
		json.NewDecoder(r.Body).Decode(&f.queued)
		io.WriteString(w, `{"id":44,"state":"queued","webUrl":"https://tc/b/44"}`)
	case "POST /app/rest/builds/id:42", "POST /app/rest/buildQueue/id:42":
		f.cancelled = r.URL.Path
		io.WriteString(w, `{"id":42,"state":"finished"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, "Responding with error, status code: 404 (Not Found).\nDetails: no such thing")
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "finished"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tc": "tctok", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTeamCityReads(t *testing.T) {
	m, _ := setup(t, "secret://tc")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "signed in as ci-bot · TeamCity 2025.03 (build 186049)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"projects", `{}`, []string{`"id":"_Root"`, `"parent":"_Root"`, `"archived":true`}},
		{"build_configurations", `{"project":"Web"}`, []string{`"id":"Web_Build"`, `"paused":true`}},
		{"build_configuration", `{"buildType":"Web_Build"}`, []string{`"choices":["staging","production"]`, `"type":"password"`, `"default":"[hidden]"`, `"default":"hello"`}},
		{"builds", `{"buildType":"Web_Build","state":"finished"}`, []string{`"id":42`, `"number":"17"`, `"status":"FAILURE"`, `"triggeredBy":"kim"`, `"queued":"2026-11-04T10:00:00Z"`}},
		{"builds", `{"state":"queued"}`, []string{`"id":43`, `"waitReason":"No agents"`}},
		{"build", `{"build":42}`, []string{`"agent":"agent-1"`, `"revisions":["abcdef012345"]`}},
		{"build_log", `{"build":42,"lines":3}`, []string{`"lines":["[10:00:59]i: line 299","[10:00:00]i: line 300","export [redacted]"]`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		for _, leak := range []string{"tok-plain-123", "abcdef1234567890", "hunter2", "kim@example.com", "bot@example.com"} {
			if strings.Contains(string(r.Output), leak) {
				t.Fatalf("%s leaks %s: %s", c.action, leak, r.Output)
			}
		}
	}
}

func TestTeamCityTriggerCancel(t *testing.T) {
	m, f := setup(t, "secret://tc")
	in := `{"buildType":"Web_Build","branch":"main","parameters":{"env":"production","run.tests":false,"env.API_TOKEN":"x-secret-value"}}`
	p, err := invoke(m, "trigger_build", in, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Queue a build of Build (Web_Build) on main with parameters" || f.queued != nil {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if after := string(p.Plan.Changes[0].After); strings.Contains(after, "x-secret-value") || !strings.Contains(after, `"run.tests":"no"`) {
		t.Fatalf("preview: %s", after)
	}
	r, err := invoke(m, "trigger_build", in, false)
	if err != nil || !strings.Contains(string(r.Output), `"build":44`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if b, _ := json.Marshal(f.queued); !strings.Contains(string(b), `"branchName":"main"`) || !strings.Contains(string(b), `{"name":"env","value":"production"}`) {
		t.Fatalf("queued %s", b)
	}
	for _, bad := range []string{
		`{"buildType":"Web_Build","parameters":{"deploy.password":"x"}}`,
		`{"buildType":"Web_Build","parameters":{"undeclared":"x"}}`,
		`{"buildType":"Web_Build","parameters":{"env":"qa"}}`,
		`{"buildType":"Web_Build","parameters":{"note":{"a":1}}}`,
	} {
		f.queued = nil
		if _, err := invoke(m, "trigger_build", bad, false); err == nil || f.queued != nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	// A finished build has nothing to cancel.
	if r, err := invoke(m, "cancel_build", `{"build":42}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || f.cancelled != "" {
		t.Fatalf("%s %v", r.Output, err)
	}
	f.state = "running"
	if p, err := invoke(m, "cancel_build", `{"build":42}`, true); err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Stop build #17 (id 42) of Web_Build") || f.cancelled != "" {
		t.Fatalf("%+v %v", p, err)
	}
	if r, err := invoke(m, "cancel_build", `{"build":42}`, false); err != nil || f.cancelled != "/app/rest/builds/id:42" || !strings.Contains(string(r.Output), `"was":"running"`) {
		t.Fatalf("%s %v %s", r.Output, err, f.cancelled)
	}
	f.state, f.cancelled = "queued", ""
	if _, err := invoke(m, "cancel_build", `{"build":42}`, false); err != nil || f.cancelled != "/app/rest/buildQueue/id:42" {
		t.Fatal(err, f.cancelled)
	}
	if _, err := invoke(m, "build_log", `{"build":42}`, false); err == nil || !strings.Contains(err.Error(), "queued") {
		t.Fatal(err)
	}
}

func TestTeamCityValidation(t *testing.T) {
	m, f := setup(t, "secret://tc")
	for _, c := range []struct{ action, in string }{
		{"build_configurations", `{"project":"../x"}`},
		{"build_configuration", `{"buildType":"Web_Build/../x"}`},
		{"build_configuration", `{"buildType":""}`},
		{"builds", `{"buildType":"a,b:(c)"}`},
		{"builds", `{"state":"exploded"}`},
		{"builds", `{"branch":"a,b"}`},
		{"builds", `{"limit":500}`},
		{"build", `{"build":0}`},
		{"build_log", `{"build":-1}`},
		{"build_log", `{"build":42,"lines":5000}`},
		{"trigger_build", `{"buildType":"x?y"}`},
		{"trigger_build", `{"buildType":"Web_Build","branch":"a b"}`},
		{"trigger_build", `{"buildType":"Web_Build","parameters":{"a b":"x"}}`},
		{"cancel_build", `{}`},
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
		{URL: "https://tc.example.com", Token: "plain"},
		{URL: "https://user:pw@tc.example.com", Token: "secret://tc"},
		{URL: "https://tc.example.com?x=1", Token: "secret://tc"},
		{URL: "https://tc.example.com#x", Token: "secret://tc"},
		{URL: "ftp://tc.example.com", Token: "secret://tc"},
		{URL: "https://tc.example.com", Token: "secret://tc", Fingerprint: "zz"},
		{Token: "secret://tc"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused the access token") || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestTeamCityRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://tc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tc": "tctok"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestTeamCityRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		if a.Name == "trigger_build" || a.Name == "cancel_build" {
			want = sdk.RiskDestructive
			if !a.DryRun {
				t.Errorf("%s has no preview", a.Name)
			}
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
		if (a.Name == "build_log") != a.Sensitive {
			t.Errorf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
}
