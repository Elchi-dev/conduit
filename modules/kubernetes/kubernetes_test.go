package kubernetes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeCluster struct {
	mu       sync.Mutex
	replicas int
	restart  string
	deleted  string
	patchCT  []string
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"kind":"Status","message":"Unauthorized"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /version":
		io.WriteString(w, `{"gitVersion":"v1.31.2"}`)
	case "GET /api/v1/namespaces":
		io.WriteString(w, `{"items":[{"metadata":{"name":"default"},"status":{"phase":"Active"}},{"metadata":{"name":"web"},"status":{"phase":"Active"}}]}`)
	case "GET /api/v1/namespaces/web/pods":
		if r.URL.Query().Get("labelSelector") != "app=web" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"metadata":{"name":"web-1","creationTimestamp":"2026-11-01T00:00:00Z"},"spec":{"nodeName":"n1","containers":[{},{}]},
			"status":{"phase":"Running","containerStatuses":[{"ready":true,"restartCount":2},{"ready":false,"restartCount":1,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}`)
	case "GET /api/v1/namespaces/web/pods/web-1":
		io.WriteString(w, `{"metadata":{"name":"web-1","ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9"}]},"spec":{"nodeName":"n1"},"status":{"phase":"Running"}}`)
	case "DELETE /api/v1/namespaces/web/pods/web-1":
		f.deleted = "web-1"
		io.WriteString(w, `{}`)
	case "GET /api/v1/namespaces/web/pods/web-1/log":
		if r.URL.Query().Get("tailLines") != "50" || r.URL.Query().Get("sinceSeconds") != "900" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "line one\nline two\n")
	case "GET /api/v1/namespaces/web/events":
		if r.URL.Query().Get("fieldSelector") != "type=Warning" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"type":"Warning","reason":"BackOff","message":"Back-off restarting","count":5,"lastTimestamp":"2026-11-03T08:00:00Z","involvedObject":{"kind":"Pod","name":"web-1"}},
			{"type":"Warning","reason":"Failed","message":"pull","count":1,"lastTimestamp":"2026-11-03T09:00:00Z","involvedObject":{"kind":"Pod","name":"web-2"}}]}`)
	case "GET /apis/apps/v1/namespaces/web/deployments":
		io.WriteString(w, `{"items":[{"metadata":{"name":"web"},"spec":{"replicas":3},"status":{"readyReplicas":2,"updatedReplicas":3,"availableReplicas":2}}]}`)
	case "GET /apis/apps/v1/namespaces/web/deployments/web":
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"name": "web"}, "spec": map[string]int{"replicas": f.replicas}})
	case "PATCH /apis/apps/v1/namespaces/web/deployments/web/scale":
		f.patchCT = append(f.patchCT, r.Header.Get("Content-Type"))
		var b struct {
			Spec struct {
				Replicas int `json:"replicas"`
			} `json:"spec"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.replicas = b.Spec.Replicas
		io.WriteString(w, `{}`)
	case "PATCH /apis/apps/v1/namespaces/web/deployments/web":
		f.patchCT = append(f.patchCT, r.Header.Get("Content-Type"))
		b, _ := io.ReadAll(r.Body)
		f.restart = string(b)
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"kind":"Status","message":"not found: `+r.URL.Path+`"}`)
	}
}

func setup(t *testing.T) (*Module, *fakeCluster) {
	t.Helper()
	f := &fakeCluster{replicas: 3}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.now = func() time.Time { return time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC) }
	host := fakehost.New(map[string]string{"secret://k8s": "tok\n"})
	cfg, _ := json.Marshal(Config{Server: srv.URL, Token: "secret://k8s", Namespace: "web"})
	if err := m.Configure(context.Background(), host, "c", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(t *testing.T, m *Module, action, input string, dry bool) sdk.Result {
	t.Helper()
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(input), DryRun: dry})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestReads(t *testing.T) {
	m, _ := setup(t)
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || !strings.Contains(h.Message, "v1.31.2") {
		t.Fatalf("health %+v", h)
	}
	var pods []map[string]any
	json.Unmarshal(call(t, m, "pods", `{"selector":"app=web"}`, false).Output, &pods)
	if len(pods) != 1 || pods[0]["ready"] != "1/2" || pods[0]["restarts"] != 3.0 || pods[0]["reason"] != "CrashLoopBackOff" || pods[0]["age"] != "2d" {
		t.Fatalf("pods %v", pods)
	}
	var deps []map[string]any
	json.Unmarshal(call(t, m, "deployments", `{}`, false).Output, &deps)
	if deps[0]["desired"] != 3.0 || deps[0]["ready"] != 2.0 {
		t.Fatalf("deployments %v", deps)
	}
	var logs map[string]string
	json.Unmarshal(call(t, m, "logs", `{"pod":"web-1","tailLines":50,"since":"15m"}`, false).Output, &logs)
	if !strings.Contains(logs["logs"], "line two") {
		t.Fatalf("logs %v", logs)
	}
	var evs []map[string]any
	json.Unmarshal(call(t, m, "events", `{}`, false).Output, &evs)
	if len(evs) != 2 || evs[0]["reason"] != "Failed" {
		t.Fatalf("events not newest first: %v", evs)
	}
	var nss []map[string]string
	json.Unmarshal(call(t, m, "namespaces", `{}`, false).Output, &nss)
	if len(nss) != 2 {
		t.Fatalf("namespaces %v", nss)
	}
}

func TestScaleRestartDelete(t *testing.T) {
	m, f := setup(t)
	plan := call(t, m, "scale", `{"deployment":"web","replicas":5}`, true).Plan
	if plan == nil || !strings.Contains(plan.Summary, "from 3 to 5") || f.replicas != 3 {
		t.Fatalf("dry run %+v, replicas %d", plan, f.replicas)
	}
	r := call(t, m, "scale", `{"deployment":"web","replicas":5}`, false)
	if f.replicas != 5 || r.Undo == nil {
		t.Fatalf("scale: %d %+v", f.replicas, r.Undo)
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input), false)
	if f.replicas != 3 {
		t.Fatalf("undo: %d", f.replicas)
	}
	if call(t, m, "restart", `{"deployment":"web"}`, true).Plan == nil || f.restart != "" {
		t.Fatal("restart dry run changed something")
	}
	call(t, m, "restart", `{"deployment":"web"}`, false)
	if !strings.Contains(f.restart, `"kubectl.kubernetes.io/restartedAt":"2026-11-03T10:00:00Z"`) {
		t.Fatalf("restart patch %s", f.restart)
	}
	if f.patchCT[0] != "application/merge-patch+json" || f.patchCT[len(f.patchCT)-1] != "application/strategic-merge-patch+json" {
		t.Fatalf("patch types %v", f.patchCT)
	}
	plan = call(t, m, "delete_pod", `{"pod":"web-1"}`, true).Plan
	if plan == nil || !strings.Contains(plan.Summary, "ReplicaSet web-7d9") || f.deleted != "" {
		t.Fatalf("delete dry run %+v", plan)
	}
	call(t, m, "delete_pod", `{"pod":"web-1"}`, false)
	if f.deleted != "web-1" {
		t.Fatal("not deleted")
	}
}

func TestValidation(t *testing.T) {
	m, _ := setup(t)
	ctx := context.Background()
	for _, in := range []string{`{"pod":"../../secrets"}`, `{"pod":"web-1","namespace":"Bad NS"}`, `{"pod":"web-1","since":"forever"}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "c", Action: "logs", Input: json.RawMessage(in)}); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "c", Action: "scale", Input: json.RawMessage(`{"deployment":"web","replicas":-1}`)}); err == nil {
		t.Error("negative replicas accepted")
	}
	host := fakehost.New(nil)
	for _, cfg := range []string{`{"server":"ftp://x","token":"secret://k"}`, `{"server":"https://x"}`, `{"server":"https://x","token":"secret://k","ca":"not pem"}`} {
		if err := New().Configure(ctx, host, "x", json.RawMessage(cfg)); err == nil {
			t.Errorf("config accepted: %s", cfg)
		}
	}
	// A wrong token gives the API's message.
	m2, _ := setup(t)
	m2.set.Put("bad", &conn{cfg: Config{Server: mustConn(t, m2).cfg.Server, Token: "secret://none", Namespace: "web"}, http: mustConn(t, m2).http, host: fakehost.New(map[string]string{"secret://none": "nope"})})
	if h := m2.Health(ctx, "bad"); h.Status != "down" || !strings.Contains(h.Message, "Unauthorized") {
		t.Fatalf("health with bad token %+v", h)
	}
}

func mustConn(t *testing.T, m *Module) *conn {
	c, err := m.set.Get("c")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
