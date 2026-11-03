package truenas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	mu    sync.Mutex
	snaps map[string]bool
	scrub string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer k3y" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Not authenticated"}`)
		return
	}
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v2.0")
	switch r.Method + " " + p {
	case "GET /system/info":
		io.WriteString(w, `{"version":"TrueNAS-SCALE-24.10.1","hostname":"nas","uptime_seconds":3600,"physmem":34359738368,"cores":8}`)
	case "GET /alert/list":
		io.WriteString(w, `[{"uuid":"a","level":"WARNING","formatted":"Pool tank is 85% full","dismissed":false,"datetime":{"$date":1762160000000}},{"uuid":"b","level":"CRITICAL","formatted":"old","dismissed":true}]`)
	case "GET /pool":
		io.WriteString(w, `[{"name":"tank","status":"ONLINE","healthy":true,"size":1000,"allocated":850,"free":150,"scan":{"function":"SCRUB","state":"FINISHED"}}]`)
	case "GET /pool/dataset":
		io.WriteString(w, `[{"id":"tank/media","used":{"parsed":700},"available":{"parsed":150}}]`)
	case "GET /zfs/snapshot":
		out := []map[string]any{}
		for s := range f.snaps {
			out = append(out, map[string]any{"name": s, "dataset": r.URL.Query().Get("dataset"), "properties": map[string]any{"used": map[string]any{"parsed": 10}}})
		}
		json.NewEncoder(w).Encode(out)
	case "POST /zfs/snapshot":
		var b struct{ Dataset, Name string }
		json.NewDecoder(r.Body).Decode(&b)
		f.snaps[b.Dataset+"@"+b.Name] = true
		io.WriteString(w, `{}`)
	case "DELETE /zfs/snapshot/id/tank%2Fmedia@before-upgrade":
		delete(f.snaps, "tank/media@before-upgrade")
		io.WriteString(w, `true`)
	case "POST /pool/scrub/run":
		var b struct{ Name string }
		json.NewDecoder(r.Body).Decode(&b)
		f.scrub = b.Name
		io.WriteString(w, `1`)
	case "GET /app":
		io.WriteString(w, `[{"name":"jellyfin","state":"RUNNING","version":"1.0"}]`)
	case "GET /vm":
		io.WriteString(w, `[{"id":1,"name":"win","status":{"state":"STOPPED"},"memory":4096,"vcpus":2}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"no route `+r.Method+" "+p+`"}`)
	}
}

func setup(t *testing.T) (*Module, *fake) {
	f := &fake{snaps: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://nas"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nas": "k3y"}), "n", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(t *testing.T, m *Module, action, input string) sdk.Result {
	t.Helper()
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(input)})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestTrueNAS(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || !strings.Contains(h.Message, "nas") {
		t.Fatalf("health %+v", h)
	}
	if out := string(call(t, m, "pools", "").Output); !strings.Contains(out, `"usedBytes":850`) || !strings.Contains(out, "scrub finished") {
		t.Fatalf("pools %s", out)
	}
	if out := string(call(t, m, "alerts", "").Output); !strings.Contains(out, "85% full") || strings.Contains(out, "old") {
		t.Fatalf("alerts %s", out)
	}
	call(t, m, "datasets", "")
	call(t, m, "apps", "")
	call(t, m, "vms", "")

	plan := call(t, m, "snapshot", `{"dataset":"tank/media","name":"before-upgrade"}`)
	_ = plan
	dry, _ := m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: "snapshot", DryRun: true, Input: json.RawMessage(`{"dataset":"tank/media","name":"x"}`)})
	if dry.Plan == nil || f.snaps["tank/media@x"] {
		t.Fatal("dry run changed something")
	}
	if !f.snaps["tank/media@before-upgrade"] {
		t.Fatal("snapshot not taken")
	}
	r := call(t, m, "snapshot", `{"dataset":"tank/media","name":"before-upgrade"}`)
	call(t, m, r.Undo.Action, string(r.Undo.Input))
	if f.snaps["tank/media@before-upgrade"] {
		t.Fatal("undo didn't delete the snapshot")
	}
	call(t, m, "scrub", `{"pool":"tank"}`)
	if f.scrub != "tank" {
		t.Fatal("scrub")
	}
	for _, bad := range []string{`{"dataset":"../etc","name":"x"}`, `{"dataset":"tank/media","name":"a/b"}`, `{"dataset":"tank//x","name":"x"}`} {
		if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: "snapshot", Input: json.RawMessage(bad)}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: "scrub", Input: json.RawMessage(`{"pool":"tank/../x"}`)}); err == nil {
		t.Fatal("bad pool accepted")
	}
}

func TestFingerprintPin(t *testing.T) {
	srv := httptest.NewTLSServer(&fake{snaps: map[string]bool{}})
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	host := fakehost.New(map[string]string{"secret://nas": "k3y"})
	m := New()
	cfg, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://nas", Fingerprint: hex.EncodeToString(sum[:])})
	if err := m.Configure(context.Background(), host, "ok", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "ok"); h.Status != "ok" {
		t.Fatalf("pinned: %+v", h)
	}
	bad, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://nas", Fingerprint: strings.Repeat("ab", 32)})
	_ = m.Configure(context.Background(), host, "bad", bad)
	if h := m.Health(context.Background(), "bad"); h.Status != "down" {
		t.Fatalf("wrong pin accepted: %+v", h)
	}
	none, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://nas"})
	_ = m.Configure(context.Background(), host, "none", none)
	if h := m.Health(context.Background(), "none"); h.Status != "down" {
		t.Fatalf("self-signed accepted without pin: %+v", h)
	}
}
