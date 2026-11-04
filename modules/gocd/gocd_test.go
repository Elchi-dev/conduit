package gocd

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
	paused    bool
	scheduled map[string]any
	pauseBody map[string]any
	unpaused  bool
}

const runJSON = `{"name":"web","counter":7,"label":"7","scheduled_date":1793786400000,"build_cause":{"trigger_message":"modified by kim <kim@example.com> token=abcdef1234567890","trigger_forced":true,"approver":"kim"},
	"stages":[{"name":"build","counter":"1","result":"Passed","status":"Passed","approval_type":"success","approved_by":"changes","jobs":[{"name":"compile","state":"Completed","result":"Passed","scheduled_date":1793786400000}]},
	{"name":"deploy","counter":"1","result":"Unknown","status":"Building","approval_type":"manual","jobs":[]}]}`

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer gotok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"You are not authenticated!"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	accept := r.Header.Get("Accept")
	if r.Method == http.MethodPost && r.Header.Get("X-GoCD-Confirm") != "true" {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"Missing X-GoCD-Confirm header"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /go/api/current_user":
		io.WriteString(w, `{"login_name":"ci-bot","display_name":"CI","email":"bot@example.com"}`)
	case "GET /go/api/version":
		io.WriteString(w, `{"version":"24.3.0","full_version":"24.3.0 (19261-abc)"}`)
	case "GET /go/api/dashboard":
		if accept != v4 {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"_embedded":{"pipeline_groups":[{"name":"apps","pipelines":["web"]}],"pipelines":[{"name":"web","locked":false,
			"pause_info":{"paused":true,"paused_by":"kim","pause_reason":"maintenance password=supersecret99"},
			"_embedded":{"instances":[{"label":"7","counter":7,"triggered_by":"changes","scheduled_at":"2026-11-04T10:00:00Z","_embedded":{"stages":[{"name":"build","status":"Passed"}]}}]}}]}}`)
	case "GET /go/api/pipelines/web/status":
		if f.paused {
			io.WriteString(w, `{"paused":true,"pausedCause":"maintenance","pausedBy":"kim","locked":false,"schedulable":false}`)
		} else {
			io.WriteString(w, `{"paused":false,"pausedCause":"","pausedBy":"","locked":false,"schedulable":true}`)
		}
	case "GET /go/api/pipelines/web/history":
		io.WriteString(w, `{"pipelines":[`+runJSON+`]}`)
	case "GET /go/api/pipelines/web/7":
		io.WriteString(w, runJSON)
	case "GET /go/api/admin/pipelines/web":
		io.WriteString(w, `{"name":"web","environment_variables":[{"name":"TARGET","secure":false,"value":"staging"},{"name":"DEPLOY_KEY","secure":true,"encrypted_value":"AES:enc-value-xyz"}]}`)
	case "POST /go/api/pipelines/web/schedule":
		json.NewDecoder(r.Body).Decode(&f.scheduled)
		w.WriteHeader(202)
		io.WriteString(w, `{"message":"Request to schedule pipeline web accepted"}`)
	case "POST /go/api/pipelines/web/pause":
		json.NewDecoder(r.Body).Decode(&f.pauseBody)
		f.paused = true
		io.WriteString(w, `{"message":"Pipeline 'web' paused successfully."}`)
	case "POST /go/api/pipelines/web/unpause":
		f.paused, f.unpaused = false, true
		io.WriteString(w, `{"message":"Pipeline 'web' unpaused successfully."}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Either the resource you requested was not found, or you are not authorized to perform this action."}`)
	}
}

func setup(t *testing.T, tok, path string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + path, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://go": "gotok", "secret://bad": "nope"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGoCDReads(t *testing.T) {
	m, _ := setup(t, "secret://go", "/go/")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "signed in as ci-bot · GoCD 24.3.0" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"pipelines", `{}`, []string{`"group":"apps"`, `"paused":true`, `"pausedBy":"kim"`, `"label":"7"`, `"status":"Passed"`}},
		{"pipeline_history", `{"pipeline":"web"}`, []string{`"counter":7`, `"forced":true`, `"result":"Passed"`, `"scheduled":"2026-11-04T`}},
		{"stages", `{"pipeline":"web"}`, []string{`"name":"compile"`, `"approval":"manual"`, `"pipeline":"web"`}},
		{"stages", `{"pipeline":"web","counter":7}`, []string{`"state":"Completed"`}},
	} {
		r, err := invoke(m, c.action, c.in, false)
		for _, w := range c.want {
			if err != nil || !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s %v", c.action, c.in, w, r.Output, err)
			}
		}
		for _, leak := range []string{"supersecret99", "abcdef1234567890", "bot@example.com"} {
			if strings.Contains(string(r.Output), leak) {
				t.Fatalf("%s leaks %s: %s", c.action, leak, r.Output)
			}
		}
	}
}

func TestGoCDTrigger(t *testing.T) {
	m, f := setup(t, "secret://go", "")
	p, err := invoke(m, "trigger_pipeline", `{"pipeline":"web","variables":{"TARGET":"production"}}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Run web now, checking its materials for new revisions first, with variables" || f.scheduled != nil {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "trigger_pipeline", `{"pipeline":"web","variables":{"TARGET":"production"},"updateMaterials":false}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"scheduled":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if b, _ := json.Marshal(f.scheduled); string(b) != `{"environment_variables":[{"name":"TARGET","secure":false,"value":"production"}],"update_materials_before_scheduling":false}` {
		t.Fatalf("scheduled %s", b)
	}
	for _, bad := range []string{
		`{"pipeline":"web","variables":{"DEPLOY_KEY":"x"}}`,
		`{"pipeline":"web","variables":{"UNDECLARED":"x"}}`,
		`{"pipeline":"web","variables":{"TARGET":["x"]}}`,
	} {
		f.scheduled = nil
		if _, err := invoke(m, "trigger_pipeline", bad, false); err == nil || f.scheduled != nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	f.paused = true
	if _, err := invoke(m, "trigger_pipeline", `{"pipeline":"web"}`, false); err == nil || !strings.Contains(err.Error(), "paused") || f.scheduled != nil {
		t.Fatal(err)
	}
}

func TestGoCDPauseUnpause(t *testing.T) {
	m, f := setup(t, "secret://go", "")
	if r, err := invoke(m, "unpause_pipeline", `{"pipeline":"web"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || f.unpaused {
		t.Fatalf("%s %v", r.Output, err)
	}
	if p, err := invoke(m, "pause_pipeline", `{"pipeline":"web","reason":"maintenance"}`, true); err != nil || p.Plan == nil || f.paused {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "pause_pipeline", `{"pipeline":"web","reason":"maintenance"}`, false)
	if err != nil || !f.paused || f.pauseBody["pause_cause"] != "maintenance" || r.Undo == nil || r.Undo.Action != "unpause_pipeline" || string(r.Undo.Input) != `{"pipeline":"web"}` {
		t.Fatalf("%+v %v %v", r, err, f.pauseBody)
	}
	if r, err := invoke(m, "pause_pipeline", `{"pipeline":"web"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "unpause_pipeline", `{"pipeline":"web"}`, false)
	if err != nil || !f.unpaused || f.paused || r.Undo == nil || r.Undo.Action != "pause_pipeline" || string(r.Undo.Input) != `{"pipeline":"web","reason":"maintenance"}` {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestGoCDValidation(t *testing.T) {
	m, f := setup(t, "secret://go", "")
	for _, c := range []struct{ action, in string }{
		{"pipeline_history", `{"pipeline":"../admin"}`},
		{"pipeline_history", `{"pipeline":"web","limit":500}`},
		{"stages", `{"pipeline":"web/x"}`},
		{"stages", `{"pipeline":"web","counter":-1}`},
		{"trigger_pipeline", `{"pipeline":""}`},
		{"trigger_pipeline", `{"pipeline":"web","variables":{"a b":"x"}}`},
		{"pause_pipeline", `{"pipeline":"web?x"}`},
		{"pause_pipeline", `{"pipeline":"web","reason":"a\nb"}`},
		{"unpause_pipeline", `{}`},
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
		{URL: "https://gocd.example.com", Token: "plain"},
		{URL: "https://u:p@gocd.example.com", Token: "secret://go"},
		{URL: "https://gocd.example.com/go?x=1", Token: "secret://go"},
		{URL: "https://gocd.example.com/#x", Token: "secret://go"},
		{URL: "gocd.example.com", Token: "secret://go"},
		{URL: "https://gocd.example.com", Token: "secret://go", Fingerprint: "nothex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || !strings.Contains(h.Message, "refused the access token") {
		t.Fatalf("%+v", h)
	}
	if h := New().Health(context.Background(), "none"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestGoCDRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://go"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://go": "gotok"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestGoCDRisks(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "trigger_pipeline", "pause_pipeline", "unpause_pipeline":
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
