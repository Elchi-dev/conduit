package terraformcloud

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
	wsID    = "ws-AAAAAAAAAAAAAAAA"
	runID   = "run-BBBBBBBBBBBBBBBB"
	planID  = "plan-CCCCCCCCCCCCCCCC"
	speckID = "run-SPECSPECSPECSPEC"
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	locked  bool
	status  string
	applied int
	actions []string
	ctype   string
	team    bool
}

func (f *fake) ws() map[string]any {
	rel := map[string]any{"current-run": map[string]any{"data": map[string]any{"id": runID, "type": "runs"}}}
	if f.locked {
		rel["locked-by"] = map[string]any{"data": map[string]any{"id": "user-x", "type": "users"}}
	}
	return map[string]any{"id": wsID, "type": "workspaces", "attributes": map[string]any{"name": "prod-network", "locked": f.locked, "execution-mode": "remote", "terraform-version": "1.9.8", "resource-count": 42,
		"vcs-repo": map[string]any{"identifier": "acme/infra", "branch": "main"}}, "relationships": rel}
}

func (f *fake) run() map[string]any {
	return map[string]any{"id": runID, "type": "runs", "attributes": map[string]any{"status": f.status, "message": "Merge #12", "source": "tfe-configuration-version", "has-changes": true,
		"actions": map[string]any{"is-confirmable": f.status == "planned", "is-discardable": f.status == "planned", "is-cancelable": f.status == "planning" || f.status == "applying"}},
		"relationships": map[string]any{"plan": map[string]any{"data": map[string]any{"id": planID, "type": "plans"}}, "workspace": map[string]any{"data": map[string]any{"id": wsID, "type": "workspaces"}}}}
}

func plan() map[string]any {
	return map[string]any{"id": planID, "type": "plans", "attributes": map[string]any{"status": "finished", "resource-additions": 3, "resource-changes": 1, "resource-destructions": 2, "resource-imports": 0}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tftok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"status":"401","title":"unauthorized"}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.Method == http.MethodPost {
		f.ctype = r.Header.Get("Content-Type")
	}
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/account/details":
		if f.team {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"data":{"attributes":{"username":"ana","email":"ana@example.com"}}}`)
	case "GET /api/v2/organizations":
		io.WriteString(w, `{"data":[{"id":"acme","attributes":{"name":"acme","email":"billing@example.com"}}]}`)
	case "GET /api/v2/organizations/acme/workspaces":
		enc.Encode(map[string]any{"data": []any{f.ws()}, "included": []any{f.run()}, "meta": map[string]any{"pagination": map[string]any{"next-page": nil}}})
	case "GET /api/v2/organizations/acme/workspaces/prod-network", "GET /api/v2/workspaces/" + wsID:
		enc.Encode(map[string]any{"data": f.ws()})
	case "GET /api/v2/workspaces/" + wsID + "/runs":
		enc.Encode(map[string]any{"data": []any{f.run()}, "included": []any{plan()}})
	case "GET /api/v2/runs/" + runID:
		enc.Encode(map[string]any{"data": f.run(), "included": []any{plan()}})
	case "POST /api/v2/runs":
		io.WriteString(w, `{"data":{"id":"`+speckID+`","attributes":{"status":"pending","plan-only":true}}}`)
	case "POST /api/v2/runs/" + runID + "/actions/apply":
		if f.status != "planned" {
			w.WriteHeader(409)
			io.WriteString(w, `{"errors":[{"status":"409","title":"transition not allowed"}]}`)
			return
		}
		f.status, f.applied = "apply_queued", f.applied+1
		w.WriteHeader(202)
	case "POST /api/v2/runs/" + runID + "/actions/discard", "POST /api/v2/runs/" + runID + "/actions/cancel":
		f.actions = append(f.actions, r.URL.Path)
		w.WriteHeader(202)
	case "POST /api/v2/workspaces/" + wsID + "/actions/lock":
		if f.locked {
			w.WriteHeader(409)
			io.WriteString(w, `{"errors":[{"status":"409","title":"conflict","detail":"Unable to lock workspace. The workspace is already locked."}]}`)
			return
		}
		f.locked = true
		enc.Encode(map[string]any{"data": f.ws()})
	case "POST /api/v2/workspaces/" + wsID + "/actions/unlock":
		f.locked = false
		enc.Encode(map[string]any{"data": f.ws()})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"status":"404","title":"not found"}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{status: "planned"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok, Organization: "acme"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tf": "tftok", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTerraformReads(t *testing.T) {
	m, f := setup(t, "secret://tf")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "signed in as ana on app.terraform.io" {
		t.Fatalf("%+v", h)
	}
	f.team = true
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || !strings.Contains(h.Message, "team token") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"organizations", `{}`, `"name":"acme"`},
		{"workspaces", `{"search":"prod"}`, `"currentRunStatus":"planned"`},
		{"workspace", `{"workspace":"prod-network"}`, `"plan":{"add":3,"change":1,"destroy":2,"import":0,"status":"finished"}`},
		{"workspace", `{"workspace":"` + wsID + `"}`, `"repo":"acme/infra"`},
		{"runs", `{"workspace":"prod-network"}`, `"canDo":["apply_run","discard_run"]`},
		{"run", `{"run":"` + runID + `"}`, `"workspace":"prod-network"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "@example.com") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestTerraformRuns(t *testing.T) {
	m, f := setup(t, "secret://tf")
	if r, err := invoke(m, "queue_plan", `{"workspace":"prod-network"}`, true); err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "plan-only") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err := invoke(m, "queue_plan", `{"workspace":"prod-network","message":"check drift"}`, false)
	if err != nil || !strings.Contains(string(r.Output), speckID) || f.ctype != "application/vnd.api+json" {
		t.Fatalf("%s %v %s", r.Output, err, f.ctype)
	}
	if last := f.seen[len(f.seen)-1]; !strings.Contains(last, `"plan-only":true`) || !strings.Contains(last, `"id":"`+wsID+`"`) {
		t.Fatal(last)
	}

	r, err = invoke(m, "apply_run", `{"run":"`+runID+`"}`, true)
	if err != nil || r.Plan == nil || f.applied != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.HasPrefix(r.Plan.Summary, "DESTROYS 2 resource(s). Apply "+runID+" on prod-network: 3 to add, 1 to change, 2 to destroy") || len(r.Plan.Changes) != 2 || r.Plan.Changes[1].Op != "destroy" {
		t.Fatalf("%+v", r.Plan)
	}
	if r, err := invoke(m, "apply_run", `{"run":"`+runID+`","comment":"ok"}`, false); err != nil || f.applied != 1 || !strings.Contains(string(r.Output), `"destroy":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "apply_run", `{"run":"`+runID+`"}`, false); err == nil || !strings.Contains(err.Error(), "isn't waiting for confirmation") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "discard_run", `{"run":"`+runID+`"}`, false); err == nil || !strings.Contains(err.Error(), "can't be discarded") {
		t.Fatal(err)
	}
	f.status = "applying"
	if r, err := invoke(m, "cancel_run", `{"run":"`+runID+`"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "stops part way") || len(f.actions) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "cancel_run", `{"run":"`+runID+`"}`, false); err != nil || len(f.actions) != 1 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "apply_run" && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatal("apply must be destructive with a preview")
		}
		if a.Name == "queue_plan" && a.Risk != sdk.RiskWrite {
			t.Fatal("plan-only runs are write")
		}
	}
}

func TestTerraformLock(t *testing.T) {
	m, f := setup(t, "secret://tf")
	if r, err := invoke(m, "lock_workspace", `{"workspace":"prod-network","reason":"freeze"}`, true); err != nil || r.Plan == nil || f.locked {
		t.Fatalf("%+v %v", r, err)
	}
	r, err := invoke(m, "lock_workspace", `{"workspace":"prod-network","reason":"freeze"}`, false)
	if err != nil || !f.locked || r.Undo == nil || r.Undo.Action != "unlock_workspace" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "lock_workspace", `{"workspace":"prod-network"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already locked") {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "unlock_workspace", `{"workspace":"prod-network"}`, true); err != nil || !strings.Contains(r.Plan.Summary, "locked by user user-x") {
		t.Fatalf("%+v %v", r, err)
	}
	u, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.locked || u.Undo == nil || u.Undo.Action != "lock_workspace" {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := invoke(m, u.Undo.Action, string(u.Undo.Input), false); err != nil || !f.locked {
		t.Fatal(err)
	}
}

func TestTerraformValidation(t *testing.T) {
	m, f := setup(t, "secret://tf")
	for _, c := range []struct{ action, in string }{
		{"workspaces", `{"organization":"../x"}`},
		{"workspaces", `{"search":"a b"}`},
		{"workspace", `{"workspace":"../runs"}`},
		{"workspace", `{"workspace":"a/b"}`},
		{"workspace", `{"workspace":"x","organization":"a?b"}`},
		{"run", `{"run":"run-short"}`},
		{"run", `{"run":"../runs/run-BBBBBBBBBBBBBBBB"}`},
		{"apply_run", `{"run":"ws-AAAAAAAAAAAAAAAA"}`},
		{"lock_workspace", `{"workspace":""}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {Token: "secret://tf", Host: "http://tfe.example.com"}, {Token: "secret://tf", Host: "tfe.example.com/x"}, {Token: "secret://tf", Organization: "a/b"}, {Token: "secret://tf", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Token: "secret://tf", Host: "https://TFE.example.com/"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
}

func TestTerraformRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://tf"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tf": "x"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
