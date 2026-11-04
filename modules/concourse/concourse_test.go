package concourse

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
	logins    int
	token     string
	paused    bool
	triggered bool
	changed   string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/sky/issuer/token" {
		r.ParseForm()
		if r.Header.Get("Authorization") != flyClient || r.PostForm.Get("grant_type") != "password" || r.PostForm.Get("username") != "ci" || r.PostForm.Get("password") != "pw-good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_client","error_description":"bad password pw-good"}`)
			return
		}
		f.logins++
		f.token = "tok" + strings.Repeat("x", f.logins)
		io.WriteString(w, `{"access_token":"`+f.token+`","token_type":"bearer","expires_in":86399,"id_token":"idtok"}`)
		return
	}
	if r.URL.Path == "/api/v1/info" && r.Header.Get("Authorization") == "" {
		w.WriteHeader(500)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token || f.token == "" {
		w.WriteHeader(401)
		io.WriteString(w, "not authorized")
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	pipe := `{"id":1,"name":"web","paused":false,"public":true,"archived":false,"team_name":"main","last_updated":1793786400}`
	if f.paused {
		pipe = `{"id":1,"name":"web","paused":true,"paused_by":"kim","paused_at":1793786400,"team_name":"main"}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/info":
		io.WriteString(w, `{"version":"7.12.0","worker_version":"2.5"}`)
	case "GET /api/v1/user":
		io.WriteString(w, `{"sub":"x","user_name":"ci","is_admin":false,"teams":{"main":["member"]}}`)
	case "GET /api/v1/teams":
		io.WriteString(w, `[{"id":1,"name":"main","auth":{"owner":{"users":["local:admin"]}}}]`)
	case "GET /api/v1/teams/main/pipelines":
		io.WriteString(w, "["+pipe+`,{"id":2,"name":"pr","instance_vars":{"branch":"x"},"archived":true}]`)
	case "GET /api/v1/teams/main/pipelines/web":
		io.WriteString(w, pipe)
	case "GET /api/v1/teams/main/pipelines/web/jobs":
		io.WriteString(w, `[{"name":"test","paused":false,"groups":["ci"],"has_new_inputs":true,"finished_build":{"id":9,"name":"5","status":"failed","job_name":"test","start_time":1793786400,"end_time":1793786460}}]`)
	case "GET /api/v1/teams/main/pipelines/web/jobs/test":
		io.WriteString(w, `{"name":"test","paused":false,"finished_build":{"id":9,"name":"5","status":"failed"}}`)
	case "GET /api/v1/teams/main/pipelines/web/jobs/test/builds", "GET /api/v1/teams/main/pipelines/web/builds":
		if r.URL.Query().Get("limit") != "20" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"id":8,"name":"4","status":"succeeded","job_name":"test","created_by":"kim"},{"id":9,"name":"5","status":"failed","job_name":"test","start_time":1793786400,"end_time":1793786460}]`)
	case "POST /api/v1/teams/main/pipelines/web/jobs/test/builds":
		f.triggered = true
		io.WriteString(w, `{"id":10,"name":"6","status":"pending","job_name":"test","created_by":"ci"}`)
	case "PUT /api/v1/teams/main/pipelines/web/pause":
		f.paused, f.changed = true, "pause"
	case "PUT /api/v1/teams/main/pipelines/web/unpause":
		f.paused, f.changed = false, "unpause"
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "ci", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cc": "pw-good\n", "secret://bad": "pw-bad"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestConcourseReads(t *testing.T) {
	m, f := setup(t, "secret://cc")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "signed in as ci · Concourse 7.12.0 · main: member" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"teams", `{}`, []string{`"name":"main"`, `"configured":true`}},
		{"pipelines", `{}`, []string{`"name":"web"`, `"public":true`, `"archived":true`, `"instanceVars":{"branch":"x"}`}},
		{"jobs", `{"pipeline":"web"}`, []string{`"name":"test"`, `"hasNewInputs":true`, `"duration":"1m0s"`, `"groups":["ci"]`}},
		{"builds", `{"pipeline":"web","job":"test"}`, []string{`"id":9`, `"number":"5"`, `"createdBy":"kim"`}},
		{"builds", `{"pipeline":"web"}`, []string{`"status":"failed"`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		if strings.Contains(string(r.Output), "local:admin") || strings.Contains(string(r.Output), "tokx") {
			t.Fatalf("%s leaks: %s", c.action, r.Output)
		}
	}
	if r, _ := invoke(m, "builds", `{"pipeline":"web"}`, false); !strings.HasPrefix(string(r.Output), `[{"duration":"1m0s"`) {
		t.Fatalf("not newest first: %s", r.Output)
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	// A token the server no longer accepts is replaced once.
	f.token = "revoked"
	if _, err := invoke(m, "teams", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
}

func TestConcourseTriggerPause(t *testing.T) {
	m, f := setup(t, "secret://cc")
	p, err := invoke(m, "trigger_job", `{"pipeline":"web","job":"test"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Start a new build of main/web/test (last: #5, failed)" || f.triggered {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err := invoke(m, "trigger_job", `{"pipeline":"web","job":"test"}`, false); err != nil || !f.triggered || !strings.Contains(string(r.Output), `"number":"6"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "unpause_pipeline", `{"pipeline":"web"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || f.changed != "" {
		t.Fatalf("%s %v", r.Output, err)
	}
	if p, err := invoke(m, "pause_pipeline", `{"pipeline":"web"}`, true); err != nil || p.Plan == nil || f.changed != "" {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "pause_pipeline", `{"pipeline":"web"}`, false)
	if err != nil || f.changed != "pause" || r.Undo == nil || r.Undo.Action != "unpause_pipeline" || string(r.Undo.Input) != `{"pipeline":"web","team":"main"}` {
		t.Fatalf("%+v %v", r, err)
	}
	f.triggered = false
	if _, err := invoke(m, "trigger_job", `{"pipeline":"web","job":"test"}`, false); err == nil || !strings.Contains(err.Error(), "paused") || f.triggered {
		t.Fatal(err)
	}
	r, err = invoke(m, "unpause_pipeline", `{"pipeline":"web"}`, false)
	if err != nil || f.changed != "unpause" || r.Undo == nil || r.Undo.Action != "pause_pipeline" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestConcourseValidation(t *testing.T) {
	m, f := setup(t, "secret://cc")
	for _, c := range []struct{ action, in string }{
		{"pipelines", `{"team":"../x"}`},
		{"jobs", `{"pipeline":"web/jobs"}`},
		{"jobs", `{}`},
		{"builds", `{"pipeline":"web","job":"a?b"}`},
		{"builds", `{"pipeline":"web","limit":500}`},
		{"trigger_job", `{"pipeline":"web"}`},
		{"trigger_job", `{"pipeline":"web","job":".."}`},
		{"pause_pipeline", `{"pipeline":"we b"}`},
		{"unpause_pipeline", `{"pipeline":"web","team":"a/b"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://ci.example.com", Username: "ci", Password: "plain"},
		{URL: "https://ci.example.com", Password: "secret://cc"},
		{URL: "https://u:p@ci.example.com", Username: "ci", Password: "secret://cc"},
		{URL: "https://ci.example.com/?x", Username: "ci", Password: "secret://cc"},
		{URL: "https://ci.example.com/#x", Username: "ci", Password: "secret://cc"},
		{URL: "https://ci.example.com", Username: "ci", Password: "secret://cc", Team: "a/b"},
		{URL: "https://ci.example.com", Username: "ci", Password: "secret://cc", Fingerprint: "xx"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") || strings.Contains(h.Message, "pw-") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestConcourseRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "ci", Password: "secret://cc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cc": "pw-good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestConcourseRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "trigger_job", "pause_pipeline", "unpause_pipeline":
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
