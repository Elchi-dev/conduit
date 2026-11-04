package xenorchestra

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	web  = "770aa52a-fd42-8faf-f167-8c5c4a237cac"
	db   = "0fc14abc-ae7a-4209-79c4-d20ca1f0e567"
	pool = "b7569d99-30f8-178a-7d94-801de3e29b5b"
	host = "b61a5c92-700e-4966-a13b-00633f03eea8"
)

type fakeXO struct {
	mu           sync.Mutex
	seen         []string
	state        map[string]string
	haltOnReboot bool
}

func (f *fakeXO) vm(id string) map[string]any {
	return map[string]any{"id": id, "uuid": id, "type": "VM", "name_label": map[string]string{web: "web", db: "db"}[id], "power_state": f.state[id],
		"$pool": pool, "$container": host, "CPUs": map[string]int{"max": 4, "number": 2}, "memory": map[string]int64{"size": 4 << 30},
		"mainIpAddress": "10.0.0.5", "tags": []string{"prod"}, "os_version": map[string]string{"name": "Debian 12"}, "snapshots": []string{"s1"},
		"xenStoreData": map[string]string{"vm-data/cloud-init": "password: LEAKME"}, "other": map[string]string{"secret": "LEAKME"}}
}

func (f *fakeXO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Cookie") != "authenticationToken=KQxQdm2vMiv7jBIK0hgkmgxKzemd8wSJ7ugFGKFkTbs" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	enc := json.NewEncoder(w)
	switch p := strings.TrimPrefix(r.URL.Path, "/rest/v0"); {
	case r.Method == "GET" && p == "/pools":
		enc.Encode([]map[string]any{{"id": pool, "name_label": "Lab", "master": host, "HA_enabled": false, "platform_version": "3.4.0", "tags": []string{}}})
	case r.Method == "GET" && p == "/hosts":
		enc.Encode([]map[string]any{{"id": host, "name_label": "xcp1", "power_state": "Running", "enabled": true, "address": "10.0.0.2", "productBrand": "XCP-ng",
			"version": "8.3.0", "$pool": pool, "CPUs": map[string]string{"cpu_count": "16"}, "memory": map[string]int64{"usage": 8 << 30, "size": 32 << 30}, "startTime": time.Now().Add(-5 * time.Hour).Unix()}})
	case r.Method == "GET" && p == "/vms":
		if r.URL.Query().Get("fields") == "" {
			enc.Encode([]string{"/rest/v0/vms/" + web})
			return
		}
		enc.Encode([]map[string]any{f.vm(web), f.vm(db)})
	case r.Method == "GET" && (p == "/vms/"+web || p == "/vms/"+db):
		id := strings.TrimPrefix(p, "/vms/")
		enc.Encode(f.vm(id))
	case r.Method == "GET" && p == "/vms/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa":
		enc.Encode(f.vm(web)) // answers with another VM
	case r.Method == "POST" && strings.HasPrefix(p, "/vms/") && strings.Contains(p, "/actions/"):
		parts := strings.Split(p, "/")
		id, op := parts[2], parts[4]
		next := map[string]string{"start": "Running", "clean_shutdown": "Halted", "clean_reboot": "Running"}[op]
		if next == "" || f.state[id] == "" {
			w.WriteHeader(404)
			return
		}
		if op == "clean_reboot" && f.haltOnReboot {
			next = "Halted"
		}
		f.state[id] = next
		w.Header().Set("Location", "/rest/v0/tasks/0m7kl0j9l")
		w.WriteHeader(202)
		io.WriteString(w, `{"taskId":"0m7kl0j9l"}`)
	case r.Method == "GET" && p == "/vm-snapshots":
		enc.Encode([]map[string]any{{"id": "s1", "name_label": "before upgrade", "snapshot_time": 1762160000, "$snapshot_of": web},
			{"id": "s2", "name_label": "old", "snapshot_time": 1700000000, "$snapshot_of": db}})
	default:
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"error":"no such object %s"}`, p)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeXO) {
	pollEvery, waitFor = time.Millisecond, 50*time.Millisecond
	f := &fakeXO{state: map[string]string{web: "Running", db: "Halted"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: ref})
	h := fakehost.New(map[string]string{"secret://xo": "KQxQdm2vMiv7jBIK0hgkmgxKzemd8wSJ7ugFGKFkTbs", "secret://bad": "wrongwrongwrong", "secret://inject": "abc; admin=1\r\nX: y"})
	if err := m.Configure(context.Background(), h, "x", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "x", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestXenOrchestra(t *testing.T) {
	m, f := setup(t, "secret://xo")
	if h := m.Health(context.Background(), "x"); h.Status != "ok" || h.Message != "1 pools, 2 VMs, 1 running" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"pools", `{}`, `"master":"xcp1"`},
		{"hosts", `{}`, `"memPercent":25`},
		{"hosts", `{}`, `"cpus":16`},
		{"hosts", `{}`, `"uptimeHours":5`},
		{"vms", `{}`, `"os":"Debian 12"`},
		{"vms", `{}`, `"host":"xcp1"`},
		{"vms", `{"state":"Halted"}`, `"name":"db"`},
		{"snapshots", `{}`, `"vmName":"web"`},
		{"snapshots", `{"vm":"` + web + `"}`, `"taken":"2025-11-03T08:53:20Z"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "KQxQdm") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "vms", `{"state":"Halted"}`, false); strings.Contains(string(r.Output), `"name":"web"`) {
		t.Fatal(string(r.Output))
	}
	if r, _ := invoke(m, "snapshots", `{"vm":"`+web+`"}`, false); strings.Contains(string(r.Output), `"old"`) {
		t.Fatal(string(r.Output))
	}

	// Shut down: preview, real with read-back, undo, nothing to change.
	r, err := invoke(m, "shutdown", `{"vm":"`+web+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Shut down VM web ("+web+")" || f.state[web] != "Running" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "shutdown", `{"vm":"`+web+`"}`, false)
	if err != nil || f.state[web] != "Halted" || !strings.Contains(string(r.Output), `"powerState":"Halted"`) || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if !contains(f.seen, "POST /rest/v0/vms/"+web+"/actions/clean_shutdown") {
		t.Fatal(f.seen)
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state[web] != "Running" || r.Undo.Action != "shutdown" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "start", `{"vm":"`+web+`"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "reboot", `{"vm":"`+db+`"}`, false); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "reboot", `{"vm":"`+web+`"}`, false); err != nil || r.Undo != nil || !contains(f.seen, "POST /rest/v0/vms/"+web+"/actions/clean_reboot") ||
		!strings.Contains(string(r.Output), `"powerState":"Running"`) || f.seen[len(f.seen)-1] != "GET /rest/v0/vms/"+web {
		t.Fatalf("%s %v %v", r.Output, err, f.seen)
	}
	// A reboot that leaves the VM halted is reported, not hidden.
	f.mu.Lock()
	f.state[db], f.haltOnReboot = "Running", true
	f.mu.Unlock()
	if r, err := invoke(m, "reboot", `{"vm":"`+db+`"}`, false); err != nil || !strings.Contains(string(r.Output), `"powerState":"Halted"`) || !strings.Contains(string(r.Output), "check again") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "start", `{"vm":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}`, false); err == nil || !strings.Contains(err.Error(), "another VM") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start", `{"vm":"bbbbbbbb-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}`, false); err == nil || !strings.Contains(err.Error(), "no VM") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "shutdown" || a.Name == "reboot") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestXenOrchestraValidation(t *testing.T) {
	m, f := setup(t, "secret://xo")
	for _, c := range []struct{ action, in string }{
		{"start", `{}`},
		{"start", `{"vm":"../pools"}`},
		{"shutdown", `{"vm":"770aa52a-fd42-8faf-f167-8c5c4a237cac/actions/hard_shutdown"}`},
		{"reboot", `{"vm":"web"}`},
		{"snapshots", `{"vm":"x?y=1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://xo.lan", Token: "KQxQdm2vMiv7jBIK0hgkmgxKzemd8wSJ7ugFGKFkTbs"},
		{URL: "xo.lan", Token: "secret://xo"},
		{URL: "https://admin:pw@xo.lan", Token: "secret://xo"},
		{URL: "https://xo.lan/?a=b", Token: "secret://xo"},
		{URL: "https://xo.lan/#frag", Token: "secret://xo"},
		{URL: "https://xo.lan", Token: "secret://xo", Fingerprint: "nope"},
		{URL: "http://xo.lan", Token: "secret://xo", Fingerprint: strings.Repeat("ab", 32)},
		{URL: "http://xo.lan", Token: "secret://xo", InsecureSkipVerify: true},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "y", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "x"); h.Status != "down" || h.Message != "Xen Orchestra refused the authentication token" {
		t.Fatalf("%+v", h)
	}
	inj, fi := setup(t, "secret://inject")
	if h := inj.Health(context.Background(), "x"); h.Status != "down" || len(fi.seen) != 0 {
		t.Fatalf("sent a malformed token: %+v", h)
	}
}

func TestXenOrchestraRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Cookie") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://xo"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://xo": "KQxQdm2vMiv7jBIK0hgkmgxKzemd8wSJ7ugFGKFkTbs"}), "x", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "x"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "KQxQdm") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
