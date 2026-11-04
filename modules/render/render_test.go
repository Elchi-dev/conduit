package render

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
	svc   = "srv-cj3k8h9gkuvsl3b2l5qg"
	other = "srv-zzzzzzzzzzzzzzzzzzzz"
	dep   = "dep-cj3k8h9gkuvsl3b2l5q1"
	team  = "tea-cj3k8h9gkuvsl3b2l5q0"
)

type fakeRender struct {
	mu        sync.Mutex
	seen      []string
	suspended bool
	deploys   int
}

func (f *fakeRender) service(id string) map[string]any {
	st := "not_suspended"
	if f.suspended {
		st = "suspended"
	}
	owner := team
	if id == other {
		owner = "tea-otherotherotherother"
	}
	return map[string]any{"id": id, "name": "api", "type": "web_service", "repo": "https://github.com/elchi/api", "branch": "main", "autoDeploy": "yes", "suspended": st, "ownerId": owner,
		"dashboardUrl": "https://dashboard.render.com/web/" + id, "serviceDetails": map[string]any{"url": "https://api.onrender.com", "region": "frankfurt", "plan": "starter", "runtime": "go"}}
}

func (f *fakeRender) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer rnd_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	d := map[string]any{"id": dep, "status": "live", "trigger": "new_commit", "commit": map[string]any{"id": "abc1234", "message": "fix login\n\nlong body"}, "createdAt": "2026-11-01T10:00:00Z", "finishedAt": "2026-11-01T10:02:30Z"}
	switch r.Method + " " + r.URL.Path {
	case "GET /owners":
		enc.Encode([]any{map[string]any{"cursor": "c", "owner": map[string]any{"id": team, "name": "Elchi", "email": "private@example.com"}}})
	case "GET /services":
		if r.URL.Query().Get("ownerId") != team {
			w.WriteHeader(400)
			return
		}
		enc.Encode([]any{map[string]any{"cursor": "c", "service": f.service(svc)}})
	case "GET /services/" + svc, "GET /services/" + other:
		enc.Encode(f.service(strings.TrimPrefix(r.URL.Path, "/services/")))
	case "GET /services/" + svc + "/deploys":
		enc.Encode([]any{map[string]any{"cursor": "c", "deploy": d}})
	case "GET /services/" + svc + "/deploys/" + dep:
		enc.Encode(d)
	case "GET /services/" + svc + "/events":
		io.WriteString(w, `[{"cursor":"c","event":{"id":"evt-1","type":"server_failed","timestamp":"2026-11-01T11:00:00Z","details":{"reason":{"nonZeroExit":1},"instanceId":"i1","secretish":"x"}}}]`)
	case "POST /services/" + svc + "/deploys":
		f.deploys++
		w.WriteHeader(201)
		io.WriteString(w, `{"id":"dep-newnewnewnewnewnew","status":"created"}`)
	case "POST /services/" + svc + "/suspend":
		f.suspended = true
		w.WriteHeader(202)
	case "POST /services/" + svc + "/resume":
		f.suspended = false
		w.WriteHeader(202)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeRender) {
	f := &fakeRender{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref, Workspace: team})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rn": "rnd_good", "secret://bad": "rnd_bad"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRenderReads(t *testing.T) {
	m, _ := setup(t, "secret://rn")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "workspace Elchi" {
		t.Fatalf("%+v", h)
	}
	in := `{"service":"` + svc + `"}`
	for _, c := range []struct{ action, in, want string }{
		{"services", `{}`, `"url":"https://api.onrender.com"`},
		{"service", in, `"suspended":false`},
		{"deploys", in, `"message":"fix login"`},
		{"deploys", in, `"seconds":150`},
		{"deploy", `{"service":"` + svc + `","deploy":"` + dep + `"}`, `"status":"live"`},
		{"events", in, `"type":"server_failed"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "private@") || strings.Contains(string(r.Output), "secretish") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if _, err := invoke(m, "service", `{"service":"`+other+`"}`, false); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatal(err)
	}
}

func TestRenderWrites(t *testing.T) {
	m, f := setup(t, "secret://rn")
	in := `{"service":"` + svc + `"}`
	r, err := invoke(m, "trigger_deploy", `{"service":"`+svc+`","clearCache":true}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Deploy api from its branch main with a clear build cache" || f.deploys != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "trigger_deploy", `{"service":"`+svc+`","commit":"ABC1234"}`, false)
	if err != nil || f.deploys != 1 || !strings.Contains(string(r.Output), `"deploy":"dep-newnewnewnewnewnew"`) || !strings.Contains(f.seen[len(f.seen)-1], `"commitId":"abc1234"`) {
		t.Fatalf("%s %v %v", r.Output, err, f.seen)
	}

	r, err = invoke(m, "suspend", in, true)
	if err != nil || r.Plan == nil || f.suspended {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "suspend", in, false)
	if err != nil || !f.suspended || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "trigger_deploy", in, false); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "suspend", in, false); err != nil || !strings.Contains(string(r.Output), "already suspended") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.suspended || r.Undo == nil || r.Undo.Action != "suspend" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "suspend" && (a.Risk != sdk.RiskDestructive || !a.Reversible || !a.DryRun) {
			t.Fatal("suspend must be destructive, undoable and previewed")
		}
	}
}

func TestRenderValidation(t *testing.T) {
	m, f := setup(t, "secret://rn")
	for _, c := range []struct{ action, in string }{
		{"service", `{"service":"../owners"}`},
		{"service", `{"service":"srv-abc"}`},
		{"deploys", `{"service":"srv-cj3k8h9gkuvsl3b2l5qg/../x"}`},
		{"deploy", `{"service":"` + svc + `","deploy":"../../x"}`},
		{"trigger_deploy", `{"service":"` + svc + `","commit":"main"}`},
		{"suspend", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "rnd_plain"}, {Token: "secret://rn", Workspace: "../x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestRenderRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rn": "rnd_good"}), "r", json.RawMessage(`{"token":"secret://rn"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
