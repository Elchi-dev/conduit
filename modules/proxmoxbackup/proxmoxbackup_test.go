package proxmoxbackup

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

type fakePBS struct {
	mu       sync.Mutex
	seen     []string
	verified bool
	body     map[string]any
}

func (f *fakePBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "PBSAPIToken=root@pam!conduit:s3cret-value" {
		w.WriteHeader(401)
		io.WriteString(w, `{"data":null,"message":"authentication failed - invalid token"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(b))
	data := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	state := "failed"
	if f.verified {
		state = "ok"
	}
	switch r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api2/json") {
	case "GET /version":
		data(map[string]string{"version": "3.2", "release": "7", "repoid": "abc"})
	case "GET /admin/datastore":
		data([]map[string]any{{"store": "store1", "comment": "main"}, {"store": "offsite", "maintenance": "read-only"}})
	case "GET /status/datastore-usage":
		data([]map[string]any{{"store": "store1", "total": 1000 << 30, "used": 250 << 30, "avail": 750 << 30, "estimated-full-date": 1830000000, "history": []float64{0.1}},
			{"store": "offsite", "total": 100 << 30, "used": 10 << 30, "avail": 90 << 30}})
	case "GET /admin/datastore/store1/groups":
		data([]map[string]any{{"backup-type": "vm", "backup-id": "101", "backup-count": 2, "last-backup": 1762160000, "owner": "root@pam", "files": []string{"index.json.blob"}}})
	case "GET /admin/datastore/store1/snapshots":
		data([]map[string]any{
			{"backup-type": "vm", "backup-id": "101", "backup-time": 1762100000, "size": 2 << 30, "fingerprint": "ENCFP:aa:bb:cc", "verification": map[string]string{"state": state, "upid": "UPID:x"},
				"files": []map[string]any{{"filename": "drive-scsi0.img.fidx", "crypt-mode": "encrypt"}}},
			{"backup-type": "vm", "backup-id": "101", "backup-time": 1762160000, "size": 3 << 30, "protected": true, "verification": map[string]string{"state": "ok"}},
		})
	case "POST /admin/datastore/store1/verify":
		json.Unmarshal(b, &f.body)
		data("UPID:pbs:000012AB:0001:00000001:6729A000:verify:store1:root@pam!conduit:")
	case "GET /nodes/localhost/tasks/UPID:pbs:000012AB:0001:00000001:6729A000:verify:store1:root@pam%21conduit:/status",
		"GET /nodes/localhost/tasks/UPID:pbs:000012AB:0001:00000001:6729A000:verify:store1:root@pam!conduit:/status":
		data(map[string]any{"status": "running", "type": "verify"})
	case "GET /nodes/localhost/tasks":
		data([]map[string]any{
			{"upid": "UPID:a", "worker_type": "backup", "worker_id": "store1:vm/101", "user": "root@pam", "starttime": 1762160000, "endtime": 1762160100, "status": "OK"},
			{"upid": "UPID:b", "worker_type": "verify", "worker_id": "store1", "user": "root@pam", "starttime": 1762170000, "endtime": 1762170100, "status": "error: token=ABCDEFGHIJKLMNOPQRSTUVWXYZ leaked"},
		})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"data":null,"message":"not found"}`)
	}
}

func setup(t *testing.T, secret string) (*Module, *fakePBS) {
	f := &fakePBS{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: strings.Replace(srv.URL, "http://", "https://", 1), TokenID: "root@pam!conduit", TokenSecret: secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pbs": "s3cret-value", "secret://bad": "nope"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	// The fake speaks plain HTTP; the module only accepts https addresses.
	c, _ := m.set.Get("p")
	c.api.Base = srv.URL + "/api2/json"
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestProxmoxBackup(t *testing.T) {
	m, f := setup(t, "secret://pbs")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "Proxmox Backup Server 3.2.7, 2 datastores" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"datastores", `{}`, `"usedPercent":25`},
		{"datastores", `{}`, `"estimatedFull":"2027-12-28`},
		{"datastores", `{}`, `"maintenance":"read-only"`},
		{"groups", `{"store":"store1"}`, `"lastBackup":"2025-11-03T08:53:20Z"`},
		{"snapshots", `{"store":"store1"}`, `"encrypted":true`},
		{"snapshots", `{"store":"store1","type":"vm","id":"101"}`, `"verify":"failed"`},
		{"tasks", `{}`, `"target":"store1:vm/101"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "ENCFP") || strings.Contains(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || strings.Contains(out, "s3cret") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Newest first.
	r, _ := invoke(m, "snapshots", `{"store":"store1","limit":1}`, false)
	if !strings.Contains(string(r.Output), `"time":1762160000`) || !strings.Contains(string(r.Output), `"total":2`) {
		t.Fatal(string(r.Output))
	}

	// Verify: preview, run with read-back, then nothing to change.
	r, err := invoke(m, "verify", `{"store":"store1","type":"vm","id":"101"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Verify datastore store1, group vm/101 (1 of 2 snapshots)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "POST") {
			t.Fatal("the preview started a job")
		}
	}
	r, err = invoke(m, "verify", `{"store":"store1","type":"vm","id":"101"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"status":"running"`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if f.body["backup-type"] != "vm" || f.body["backup-id"] != "101" || f.body["ignore-verified"] != true {
		t.Fatal(f.body)
	}
	f.verified = true
	if r, err := invoke(m, "verify", `{"store":"store1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "verify", `{"store":"store1","type":"vm","id":"101","time":5}`, false); err == nil || !strings.Contains(err.Error(), "no snapshot") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk == sdk.RiskDestructive || strings.Contains(a.Name, "prune") || strings.Contains(a.Name, "delete") {
			t.Fatalf("%s shouldn't be offered", a.Name)
		}
	}
}

func TestProxmoxBackupValidation(t *testing.T) {
	m, f := setup(t, "secret://pbs")
	for _, c := range []struct{ action, in string }{
		{"groups", `{}`},
		{"groups", `{"store":"../access"}`},
		{"groups", `{"store":"st"}`},
		{"snapshots", `{"store":"store1","type":"disk"}`},
		{"snapshots", `{"store":"store1","type":"vm","id":"1/../x"}`},
		{"snapshots", `{"store":"store1","id":"101"}`},
		{"snapshots", `{"store":"store1","ns":"a//b"}`},
		{"tasks", `{"store":"x?y"}`},
		{"verify", `{"store":"store1","time":1762160000}`},
		{"verify", `{"store":"store 1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://pbs.lan:8007", TokenID: "root@pam!conduit", TokenSecret: "plain-secret"},
		{URL: "http://pbs.lan:8007", TokenID: "root@pam!conduit", TokenSecret: "secret://pbs"},
		{URL: "https://user:pw@pbs.lan:8007", TokenID: "root@pam!conduit", TokenSecret: "secret://pbs"},
		{URL: "https://pbs.lan:8007/?x=1", TokenID: "root@pam!conduit", TokenSecret: "secret://pbs"},
		{URL: "https://pbs.lan:8007/#x", TokenID: "root@pam!conduit", TokenSecret: "secret://pbs"},
		{URL: "https://pbs.lan:8007", TokenID: "root", TokenSecret: "secret://pbs"},
		{URL: "https://pbs.lan:8007", TokenID: "root@pam!conduit", TokenSecret: "secret://pbs", Fingerprint: "xyz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "p")
	if h.Status != "down" || h.Message != "Proxmox Backup Server refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestProxmoxBackupPinnedAndRedirect(t *testing.T) {
	f := &fakePBS{}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	host := fakehost.New(map[string]string{"secret://pbs": "s3cret-value"})
	cfg := func(fp string) json.RawMessage {
		raw, _ := json.Marshal(Config{URL: srv.URL, TokenID: "root@pam!conduit", TokenSecret: "secret://pbs", Fingerprint: fp})
		return raw
	}
	m := New()
	if err := m.Configure(context.Background(), host, "p", cfg(hex.EncodeToString(sum[:]))); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "ok" {
		t.Fatalf("pinned certificate refused: %+v", h)
	}
	if err := m.Configure(context.Background(), host, "p", cfg(strings.Repeat("ab", 32))); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "fingerprint") {
		t.Fatalf("wrong pin accepted: %+v", h)
	}

	var leaked string
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer redir.Close()
	m2 := New()
	raw, _ := json.Marshal(Config{URL: redir.URL, TokenID: "root@pam!conduit", TokenSecret: "secret://pbs", InsecureSkipVerify: true})
	if err := m2.Configure(context.Background(), host, "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m2.Health(context.Background(), "p"); h.Status != "down" || leaked != "" || !strings.Contains(h.Message, "another host") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
