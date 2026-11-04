package argocd

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

const rev3, rev2 = "3333333333333333333333333333333333333333", "2222222222222222222222222222222222222222"

type fakeArgo struct {
	mu         sync.Mutex
	seen       []string
	deployed   int64
	syncBody   map[string]any
	terminated bool
}

func (f *fakeArgo) app(name string) map[string]any {
	a := map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
		"spec": map[string]any{"project": "default",
			"source":      map[string]any{"repoURL": "https://github.com/elchi/deploy", "path": "web", "targetRevision": "main", "helm": map[string]any{"values": "password: hunter2"}},
			"destination": map[string]any{"server": "https://kubernetes.default.svc", "namespace": "web"}},
		"status": map[string]any{
			"sync":         map[string]any{"status": "OutOfSync", "revision": rev3},
			"health":       map[string]any{"status": "Healthy"},
			"reconciledAt": "2026-11-04T11:00:00Z",
			"summary":      map[string]any{"images": []string{"ghcr.io/elchi/web:1.4"}},
			"resources": []any{
				map[string]any{"group": "apps", "kind": "Deployment", "namespace": "web", "name": "web", "status": "OutOfSync", "health": map[string]any{"status": "Healthy"}},
				map[string]any{"kind": "ConfigMap", "namespace": "web", "name": "new-cm", "status": "OutOfSync", "health": map[string]any{"status": "Missing"}},
				map[string]any{"kind": "Service", "namespace": "web", "name": "web", "status": "Synced", "health": map[string]any{"status": "Healthy"}},
				map[string]any{"kind": "Secret", "namespace": "web", "name": "old", "status": "OutOfSync", "requiresPruning": true},
			},
			"history": []any{
				map[string]any{"id": 1, "revision": "1111111111111111111111111111111111111111", "deployedAt": "2026-11-01T10:00:00Z"},
				map[string]any{"id": 2, "revision": rev2, "deployedAt": "2026-11-02T10:00:00Z"},
				map[string]any{"id": 3, "revision": rev3, "deployedAt": "2026-11-03T10:00:00Z"},
			},
		},
	}
	st := a["status"].(map[string]any)
	switch name {
	case "creds":
		a["spec"].(map[string]any)["source"].(map[string]any)["repoURL"] = "https://bot:ghp_tok@github.com/elchi/deploy"
	case "api":
		a["spec"].(map[string]any)["syncPolicy"] = map[string]any{"automated": map[string]any{"prune": true, "selfHeal": true}}
		st["sync"] = map[string]any{"status": "Synced", "revision": rev3}
	case "jobs":
		a["metadata"].(map[string]any)["namespace"] = "team-a"
		st["operationState"] = map[string]any{"phase": "Running", "message": "waiting for healthy state of apps/Deployment/jobs", "startedAt": "2026-11-04T11:50:00Z",
			"operation": map[string]any{"initiatedBy": map[string]any{"username": "alice"}}}
		if f.terminated {
			st["operationState"].(map[string]any)["phase"] = "Terminating"
		}
	}
	return a
}

func (f *fakeArgo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer argotok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid session: token is malformed","code":16,"message":"invalid session: token is malformed"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /argocd/api/v1/session/userinfo":
		io.WriteString(w, `{"loggedIn":true,"username":"conduit","iss":"argocd"}`)
	case "GET /argocd/api/version":
		io.WriteString(w, `{"Version":"v3.1.0+abc"}`)
	case "GET /argocd/api/v1/applications":
		if q.Get("projects") != "" && q.Get("projects") != "default" {
			io.WriteString(w, `{"items":[]}`)
			return
		}
		enc.Encode(map[string]any{"items": []any{f.app("web"), f.app("api"), f.app("jobs")}})
	case "GET /argocd/api/v1/applications/web", "GET /argocd/api/v1/applications/api", "GET /argocd/api/v1/applications/creds":
		enc.Encode(f.app(strings.TrimPrefix(r.URL.Path, "/argocd/api/v1/applications/")))
	case "GET /argocd/api/v1/applications/jobs":
		if q.Get("appNamespace") != "team-a" {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"applications.argoproj.io \"jobs\" not found"}`)
			return
		}
		enc.Encode(f.app("jobs"))
	case "GET /argocd/api/v1/applications/web/resource-tree":
		io.WriteString(w, `{"nodes":[
			{"group":"apps","kind":"Deployment","namespace":"web","name":"web","health":{"status":"Healthy"}},
			{"group":"apps","kind":"ReplicaSet","namespace":"web","name":"web-abc","health":{"status":"Healthy"},"parentRefs":[{"kind":"Deployment"}]},
			{"kind":"Pod","namespace":"web","name":"web-abc-1","health":{"status":"Degraded","message":"CrashLoopBackOff"},"parentRefs":[{"kind":"ReplicaSet"}]},
			{"kind":"Service","namespace":"web","name":"web","health":{"status":"Healthy"}}]}`)
	case "POST /argocd/api/v1/applications/web/sync":
		f.syncBody = nil
		json.Unmarshal(body, &f.syncBody)
		enc.Encode(f.app("web"))
	case "POST /argocd/api/v1/applications/web/rollback":
		var b struct{ ID int64 }
		json.Unmarshal(body, &b)
		f.deployed = b.ID
		enc.Encode(f.app("web"))
	case "DELETE /argocd/api/v1/applications/jobs/operation":
		if q.Get("appNamespace") != "team-a" {
			w.WriteHeader(400)
			return
		}
		f.terminated = true
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeArgo) {
	f := &fakeArgo{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/argocd/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://a": "argotok", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestArgoReads(t *testing.T) {
	m, f := setup(t, "secret://a")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as conduit · Argo CD v3.1.0+abc" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"applications", `{}`, `"autoSync":true`},
		{"applications", `{"project":"default"}`, `"revision":"33333333"`},
		{"applications", `{}`, `"phase":"Running"`},
		{"application", `{"app":"web"}`, `"resource":"ConfigMap web/new-cm"`},
		{"application", `{"app":"web"}`, `"requiresPruning":true`},
		{"application", `{"app":"web"}`, `"history":[{"deployedAt":"2026-11-03T10:00:00Z","id":3`},
		{"application", `{"app":"team-a/jobs"}`, `"url":"`},
		{"resource_tree", `{"app":"web"}`, `"message":"CrashLoopBackOff"`},
		{"resource_tree", `{"app":"web"}`, `"kind":"Pod"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "hunter2") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "applications", `{"problems":true}`, false)
	if strings.Contains(string(r.Output), `"name":"api"`) || !strings.Contains(string(r.Output), `"name":"web"`) {
		t.Fatal(string(r.Output))
	}
	n := len(f.seen)
	if r, err := invoke(m, "refresh", `{"app":"web","hard":true}`, true); err != nil || r.Plan == nil || len(f.seen) != n {
		t.Fatalf("refresh preview: %+v %v", r, err)
	}
	if _, err := invoke(m, "refresh", `{"app":"web","hard":true}`, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], "refresh=hard") {
		t.Fatal(err, f.seen)
	}
}

func TestArgoWrites(t *testing.T) {
	m, f := setup(t, "secret://a")

	r, err := invoke(m, "sync", `{"app":"web"}`, true)
	if err != nil || r.Plan == nil || f.syncBody != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Plan.Summary != "Sync web to main: 2 resources out of sync" || len(r.Plan.Changes) != 3 || r.Plan.Changes[1].Op != "create" || !strings.HasPrefix(r.Plan.Changes[2].Op, "keep") {
		t.Fatalf("%+v", r.Plan)
	}
	r, _ = invoke(m, "sync_prune", `{"app":"web"}`, true)
	if !strings.Contains(r.Plan.Summary, "1 to delete") || r.Plan.Changes[2].Op != "prune (delete)" {
		t.Fatalf("%+v", r.Plan)
	}
	r, _ = invoke(m, "sync", `{"app":"web","resources":[{"kind":"ConfigMap","name":"new-cm","namespace":"web"}]}`, true)
	if len(r.Plan.Changes) != 1 || r.Plan.Changes[0].Target != "ConfigMap web/new-cm" {
		t.Fatalf("%+v", r.Plan)
	}
	if _, err := invoke(m, "sync_revision", `{"app":"web","prune":true,"revision":"v1.2.0"}`, false); err != nil || f.syncBody["prune"] != true || f.syncBody["revision"] != "v1.2.0" {
		t.Fatalf("%v %v", err, f.syncBody)
	}
	if _, err := invoke(m, "sync", `{"app":"team-a/jobs"}`, false); err == nil || !strings.Contains(err.Error(), "already has an operation") {
		t.Fatal(err)
	}

	// Rollback: the previous history entry, with undo rolling forward.
	r, err = invoke(m, "rollback", `{"app":"web"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Roll web back from 33333333 to 22222222 (deployed 2026-11-02T10:00:00Z)" || f.deployed != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "rollback", `{"app":"web"}`, false)
	if err != nil || f.deployed != 2 || r.Undo == nil || string(r.Undo.Input) != `{"app":"web","id":3}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rollback", `{"app":"api"}`, false); err == nil || !strings.Contains(err.Error(), "auto-sync") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rollback", `{"app":"web","id":9}`, false); err == nil || !strings.Contains(err.Error(), "no history entry 9") {
		t.Fatal(err)
	}

	// Terminate.
	if _, err := invoke(m, "terminate_operation", `{"app":"web"}`, false); err == nil || !strings.Contains(err.Error(), "no operation running") {
		t.Fatal(err)
	}
	r, err = invoke(m, "terminate_operation", `{"app":"team-a/jobs"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "by alice") || f.terminated {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "terminate_operation", `{"app":"team-a/jobs"}`, false); err != nil || !f.terminated {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "rollback" || a.Name == "terminate_operation") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s must be destructive", a.Name)
		}
	}
}

func TestArgoValidation(t *testing.T) {
	m, f := setup(t, "secret://a")
	for _, c := range []struct{ action, in string }{
		{"application", `{"app":"../session"}`},
		{"application", `{"app":"Web"}`},
		{"application", `{"app":"a/b/c"}`},
		{"resource_tree", `{"app":"web?x=1"}`},
		{"applications", `{"project":"../x"}`},
		{"applications", `{"selector":"a=b&x=y"}`},
		{"sync", `{"app":"web","revision":"main; rm"}`},
		{"sync", `{"app":"web","resources":[{"kind":"Pod/../x","name":"a"}]}`},
		{"refresh", `{"app":"web/../../x"}`},
		{"rollback", `{"app":""}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if _, err := invoke(m, "refresh", `{"app":"../x"}`, true); err == nil {
		t.Fatal("refresh preview accepted a bad name")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://argocd", Token: "plain"}, {URL: "argocd.local", Token: "secret://a"}, {URL: "https://argocd", Token: "secret://a", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://a"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://a": "argotok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// sync is write: it mustn't prune or deploy another revision (that's what
// the destructive rollback, sync_prune and sync_revision are for).
func TestArgoSyncWriteNeitherPrunesNorPicksRevision(t *testing.T) {
	m, f := setup(t, "secret://a")
	risk := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["sync"] != sdk.RiskWrite || risk["sync_prune"] != sdk.RiskDestructive || risk["sync_revision"] != sdk.RiskDestructive {
		t.Fatalf("%v", risk)
	}
	for _, in := range []string{
		`{"app":"web","prune":true}`,
		`{"app":"web","revision":"1111111111111111111111111111111111111111"}`,
		`{"app":"web","revision":"v1.2.0"}`,
	} {
		if _, err := invoke(m, "sync", in, false); err == nil {
			t.Fatalf("sync accepted %s", in)
		}
		if _, err := invoke(m, "sync", in, true); err == nil {
			t.Fatalf("sync previewed %s", in)
		}
	}
	if f.syncBody != nil {
		t.Fatalf("sent %v", f.syncBody)
	}
	if _, err := invoke(m, "sync_prune", `{"app":"web","revision":"v1.2.0"}`, false); err == nil {
		t.Fatal("sync_prune took a revision")
	}
	if _, err := invoke(m, "sync_revision", `{"app":"web"}`, false); err == nil {
		t.Fatal("sync_revision without a revision")
	}
	// The app's own target revision is fine at write risk.
	if _, err := invoke(m, "sync", `{"app":"web","revision":"main"}`, false); err != nil || f.syncBody["prune"] != false {
		t.Fatalf("%v %v", err, f.syncBody)
	}
	if _, err := invoke(m, "sync_prune", `{"app":"web"}`, false); err != nil || f.syncBody["prune"] != true || f.syncBody["revision"] != nil {
		t.Fatalf("%v %v", err, f.syncBody)
	}
}

func TestArgoStripsRepoCredentials(t *testing.T) {
	m, _ := setup(t, "secret://a")
	r, err := invoke(m, "application", `{"app":"creds"}`, false)
	if err != nil || strings.Contains(string(r.Output), "ghp_tok") || strings.Contains(string(r.Output), "bot") || !strings.Contains(string(r.Output), `"repo":"https://github.com/elchi/deploy"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}
