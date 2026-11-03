package proxmox

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

type fakePVE struct {
	mu     sync.Mutex
	status string
	snaps  []string
	calls  []string
}

func (f *fakePVE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "PVEAPIToken=root@pam!conduit=s3cret" {
		w.WriteHeader(401)
		return
	}
	data := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	f.calls = append(f.calls, r.Method+" "+p)
	switch r.Method + " " + p {
	case "GET /version":
		data(map[string]string{"version": "8.2.4"})
	case "GET /nodes":
		data([]map[string]any{{"node": "pve1", "status": "online", "cpu": 0.125, "maxcpu": 8, "mem": 4 << 30, "maxmem": 16 << 30, "uptime": 7200}})
	case "GET /cluster/resources":
		if r.URL.Query().Get("type") != "vm" {
			w.WriteHeader(400)
			return
		}
		data([]map[string]any{
			{"vmid": 105, "name": "media", "node": "pve1", "type": "lxc", "status": "running", "maxmem": 1 << 30, "mem": 1 << 29},
			{"vmid": 101, "name": "web", "node": "pve1", "type": "qemu", "status": f.status, "maxmem": 1 << 30},
		})
	case "POST /nodes/pve1/qemu/101/status/start":
		f.status = "running"
		data("UPID:pve1:start")
	case "POST /nodes/pve1/qemu/101/status/shutdown":
		f.status = "stopped"
		data("UPID:pve1:shutdown")
	case "GET /nodes/pve1/qemu/101/snapshot":
		out := []map[string]any{{"name": "current", "description": "You are here!"}}
		for _, s := range f.snaps {
			out = append(out, map[string]any{"name": s, "snaptime": 1762160000})
		}
		data(out)
	case "POST /nodes/pve1/qemu/101/snapshot":
		r.ParseForm()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(400)
			return
		}
		f.snaps = append(f.snaps, r.PostForm.Get("snapname"))
		data("UPID:pve1:snap")
	case "DELETE /nodes/pve1/qemu/101/snapshot/before-upgrade":
		f.snaps = nil
		data("UPID:pve1:delsnap")
	case "GET /nodes/pve1/storage":
		data([]map[string]any{{"storage": "local-lvm", "type": "lvmthin", "content": "images", "used": 75 << 30, "total": 100 << 30, "avail": 25 << 30, "active": 1}})
	default:
		w.WriteHeader(500)
		io.WriteString(w, `{"errors":{"path":"unknown `+p+`"}}`)
	}
}

func setup(t *testing.T) (*Module, *fakePVE, *httptest.Server) {
	t.Helper()
	f := &fakePVE{status: "stopped"}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	var fp []string
	for _, b := range sum {
		fp = append(fp, strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	m := New()
	cfg, _ := json.Marshal(Config{URL: srv.URL, TokenID: "root@pam!conduit", TokenSecret: "secret://pve", Fingerprint: strings.Join(fp, ":")})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pve": "s3cret"}), "p", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f, srv
}

func call(t *testing.T, m *Module, action, input string, dry bool) sdk.Result {
	t.Helper()
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(input), DryRun: dry})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestPinnedCertificate(t *testing.T) {
	m, _, srv := setup(t)
	ctx := context.Background()
	if h := m.Health(ctx, "p"); h.Status != "ok" || h.Message != "Proxmox VE 8.2.4" {
		t.Fatalf("health with the right pin %+v", h)
	}
	host := fakehost.New(map[string]string{"secret://pve": "s3cret"})
	wrong, _ := json.Marshal(Config{URL: srv.URL, TokenID: "root@pam!conduit", TokenSecret: "secret://pve", Fingerprint: strings.Repeat("ab", 32)})
	_ = m.Configure(ctx, host, "wrong", wrong)
	if h := m.Health(ctx, "wrong"); h.Status != "down" || !strings.Contains(h.Message, "fingerprint") {
		t.Fatalf("a wrong pin must fail: %+v", h)
	}
	none, _ := json.Marshal(Config{URL: srv.URL, TokenID: "root@pam!conduit", TokenSecret: "secret://pve"})
	_ = m.Configure(ctx, host, "none", none)
	if h := m.Health(ctx, "none"); h.Status != "down" {
		t.Fatalf("an unknown self-signed certificate must fail without a pin: %+v", h)
	}
}

func TestGuestsPowerSnapshots(t *testing.T) {
	m, f, _ := setup(t)
	var nodes []map[string]any
	json.Unmarshal(call(t, m, "nodes", ``, false).Output, &nodes)
	if nodes[0]["cpuPercent"] != 12.5 || nodes[0]["memPercent"] != 25.0 || nodes[0]["uptimeHours"] != 2.0 {
		t.Fatalf("nodes %v", nodes)
	}
	var gs []map[string]any
	json.Unmarshal(call(t, m, "guests", ``, false).Output, &gs)
	if len(gs) != 2 || gs[0]["vmid"] != 101.0 || gs[1]["kind"] != "container" {
		t.Fatalf("guests %v", gs)
	}

	plan := call(t, m, "start", `{"vmid":101}`, true).Plan
	if plan == nil || !strings.Contains(plan.Summary, "VM 101 (web) on pve1") || f.status != "stopped" {
		t.Fatalf("dry run %+v", plan)
	}
	r := call(t, m, "start", `{"vmid":101}`, false)
	if f.status != "running" || r.Undo == nil || r.Undo.Action != "shutdown" {
		t.Fatalf("start %s %+v", f.status, r.Undo)
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input), false)
	if f.status != "stopped" {
		t.Fatal("undo didn't shut it down")
	}
	// Already stopped: nothing is sent.
	n := len(f.calls)
	call(t, m, "shutdown", `{"vmid":101}`, false)
	if f.calls[len(f.calls)-1] != "GET /cluster/resources" || len(f.calls) != n+1 {
		t.Fatalf("shutdown of a stopped guest called %v", f.calls[n:])
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: "reboot", Input: json.RawMessage(`{"vmid":101}`)}); err == nil {
		t.Fatal("rebooting a stopped guest should fail")
	}

	r = call(t, m, "snapshot", `{"vmid":101,"name":"before-upgrade"}`, false)
	var ss []map[string]any
	json.Unmarshal(call(t, m, "snapshots", `{"vmid":101}`, false).Output, &ss)
	if len(ss) != 1 || ss[0]["name"] != "before-upgrade" || ss[0]["taken"] == nil {
		t.Fatalf("snapshots %v", ss)
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input), false)
	if len(f.snaps) != 0 {
		t.Fatal("undo didn't delete the snapshot")
	}

	var st []map[string]any
	json.Unmarshal(call(t, m, "storage", ``, false).Output, &st)
	if st[0]["usedPercent"] != 75.0 || st[0]["freeGiB"] != 25.0 {
		t.Fatalf("storage %v", st)
	}
}

func TestValidation(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	for _, in := range []string{`{"vmid":5}`, `{"vmid":999}`} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "stop", Input: json.RawMessage(in)}); err == nil {
			t.Errorf("stop accepted %s", in)
		}
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "p", Action: "snapshot", Input: json.RawMessage(`{"vmid":101,"name":"../x"}`)}); err == nil {
		t.Error("bad snapshot name accepted")
	}
	host := fakehost.New(nil)
	for _, cfg := range []string{
		`{"url":"http://pve:8006","tokenId":"root@pam!x","tokenSecret":"secret://p"}`,
		`{"url":"https://pve:8006","tokenId":"root","tokenSecret":"secret://p"}`,
		`{"url":"https://pve:8006","tokenId":"root@pam!x"}`,
		`{"url":"https://pve:8006","tokenId":"root@pam!x","tokenSecret":"secret://p","fingerprint":"zz"}`,
	} {
		if err := New().Configure(ctx, host, "x", json.RawMessage(cfg)); err == nil {
			t.Errorf("config accepted: %s", cfg)
		}
	}
}
