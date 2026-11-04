package pterodactyl

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

const bk = "3f1c2a44-1b2c-4d5e-8f90-a1b2c3d4e5f6"

type fakePanel struct {
	mu      sync.Mutex
	seen    []string
	state   string
	backups map[string]bool // uuid -> locked
}

func (f *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ptlc_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"code":"AuthenticationException","status":"401","detail":"Unauthenticated."}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	srv := `{"object":"server","attributes":{"identifier":"1a2b3c4d","uuid":"1a2b3c4d-0000-4000-8000-000000000000","name":"Survival","node":"node-1","description":"SMP","is_suspended":false,"is_installing":false,"limits":{"memory":4096,"disk":20480,"cpu":200}}}`
	backup := func(uuid string, locked bool) string {
		return `{"object":"backup","attributes":{"uuid":"` + uuid + `","name":"nightly","is_successful":true,"is_locked":` + map[bool]string{true: "true", false: "false"}[locked] + `,"bytes":10485760,"created_at":"2026-11-01T03:00:00+00:00","completed_at":"2026-11-01T03:01:00+00:00"}}`
	}
	base := "/api/client/servers/1a2b3c4d"
	switch r.Method + " " + r.URL.Path {
	case "GET /api/client/account":
		io.WriteString(w, `{"object":"user","attributes":{"username":"steve","admin":false}}`)
	case "GET /api/client":
		io.WriteString(w, `{"object":"list","data":[`+srv+`],"meta":{"pagination":{"total":1,"total_pages":1}}}`)
	case "GET " + base:
		io.WriteString(w, srv)
	case "GET " + base + "/resources":
		io.WriteString(w, `{"object":"stats","attributes":{"current_state":"`+f.state+`","is_suspended":false,"resources":{"memory_bytes":2147483648,"cpu_absolute":37.25,"disk_bytes":5368709120,"network_rx_bytes":1048576,"network_tx_bytes":2097152,"uptime":3600000}}}`)
	case "POST " + base + "/power":
		var b struct{ Signal string }
		json.Unmarshal(body, &b)
		f.state = map[string]string{"start": "running", "stop": "offline", "kill": "offline", "restart": "running"}[b.Signal]
		w.WriteHeader(204)
	case "POST " + base + "/command":
		if f.state != "running" {
			w.WriteHeader(502)
			io.WriteString(w, `{"errors":[{"code":"HttpException","status":"502","detail":"Server must be online in order to send commands."}]}`)
			return
		}
		w.WriteHeader(204)
	case "GET " + base + "/backups":
		var parts []string
		for u, l := range f.backups {
			parts = append(parts, backup(u, l))
		}
		io.WriteString(w, `{"object":"list","data":[`+strings.Join(parts, ",")+`]}`)
	case "POST " + base + "/backups":
		u := "9e8d7c6b-1111-4222-8333-444455556666"
		f.backups[u] = false
		io.WriteString(w, backup(u, false))
	case "GET " + base + "/files/list":
		io.WriteString(w, `{"object":"list","data":[{"object":"file_object","attributes":{"name":"server.properties","mode":"-rw-r--r--","size":1200,"is_file":true,"is_symlink":false,"mimetype":"text/plain","modified_at":"2026-11-01T00:00:00+00:00"}},{"object":"file_object","attributes":{"name":"plugins","mode":"drwxr-xr-x","size":4096,"is_file":false,"is_symlink":false}}]}`)
	default:
		for u, l := range f.backups {
			p := base + "/backups/" + u
			switch r.Method + " " + r.URL.Path {
			case "GET " + p:
				io.WriteString(w, backup(u, l))
				return
			case "DELETE " + p:
				delete(f.backups, u)
				w.WriteHeader(204)
				return
			case "POST " + p + "/restore":
				w.WriteHeader(204)
				return
			}
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"code":"NotFoundHttpException","status":"404","detail":"The requested resource could not be found on the server."}]}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakePanel) {
	f := &fakePanel{state: "offline", backups: map[string]bool{bk: false, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ptlc_good", "secret://bad": "ptlc_nope"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPterodactyl(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "steve · 1 servers" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "servers", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"memoryMB":2048`) || !strings.Contains(string(r.Output), `"cpu":37.2`) || !strings.Contains(string(r.Output), `"state":"offline"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	srv := `{"server":"1a2b3c4d"}`
	if r, err := invoke(m, "status", srv, false); err != nil || !strings.Contains(string(r.Output), `"uptime":"1h0m0s"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Power: preview, start with an undo that stops, and refusals.
	r, err = invoke(m, "start", srv, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Start server Survival") || f.state != "offline" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start", srv, false)
	if err != nil || f.state != "running" || r.Undo == nil || r.Undo.Action != "stop" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "start", srv, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	if !strings.Contains(f.seen[len(f.seen)-3], `{"signal":"start"}`) {
		t.Fatal(f.seen)
	}

	// Console command.
	cmd := `{"server":"1a2b3c4d","command":"whitelist add alex"}`
	if r, err := invoke(m, "command", cmd, true); err != nil || !strings.Contains(r.Plan.Summary, "whitelist add alex") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "command", cmd, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], `{"command":"whitelist add alex"}`) {
		t.Fatal(err, f.seen[len(f.seen)-1])
	}

	if r, err := invoke(m, "kill", srv, true); err != nil || !strings.Contains(r.Plan.Summary, "without saving") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "kill", srv, false)
	if err != nil || f.state != "offline" || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "command", cmd, false); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop", srv, false); err == nil || !strings.Contains(err.Error(), "already offline") {
		t.Fatal(err)
	}

	// Backups.
	if r, err := invoke(m, "backups", srv, false); err != nil || !strings.Contains(string(r.Output), `"sizeMB":10`) || !strings.Contains(string(r.Output), `"state":"done"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "create_backup", `{"server":"1a2b3c4d","name":"before update"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_backup" || !strings.Contains(f.seen[len(f.seen)-1], `{"name":"before update"}`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "delete_backup", string(r.Undo.Input), true); err != nil || r.Plan == nil || len(f.backups) != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.backups) != 2 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_backup", `{"server":"1a2b3c4d","backup":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}`, false); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal(err)
	}
	rb := `{"server":"1a2b3c4d","backup":"` + bk + `","truncate":true}`
	if r, err := invoke(m, "restore_backup", rb, true); err != nil || !strings.Contains(r.Plan.Summary, "Delete every file of Survival") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "restore_backup", rb, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], `/restore {"truncate":true}`) {
		t.Fatal(err, f.seen[len(f.seen)-1])
	}

	if r, err := invoke(m, "files", `{"server":"1a2b3c4d","directory":"/plugins dir"}`, false); err != nil || !strings.Contains(string(r.Output), `"type":"folder"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "directory=%2Fplugins+dir") {
		t.Fatal(f.seen[len(f.seen)-1])
	}
}

func TestPterodactylValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"status", `{}`},
		{"start", `{"server":"../../account"}`},
		{"stop", `{"server":"1a2b3c4d/power"}`},
		{"kill", `{"server":"1A2B3C4"}`},
		{"command", `{"server":"1a2b3c4d","command":"say hi\nop me"}`},
		{"command", `{"server":"1a2b3c4d","command":""}`},
		{"command", `{"server":"1a2b3c4d","command":"` + strings.Repeat("x", 501) + `"}`},
		{"delete_backup", `{"server":"1a2b3c4d","backup":"../../files"}`},
		{"restore_backup", `{"server":"1a2b3c4d"}`},
		{"create_backup", `{"server":"1a2b3c4d","name":"a\nb"}`},
		{"files", `{"server":"1a2b3c4d","directory":"/../../etc"}`},
		{"files", `{"server":"1a2b3c4d","directory":"plugins"}`},
		{"files", `{"server":1}`},
		{"nope", `{"server":"1a2b3c4d"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the panel: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://panel", APIKey: "ptlc_plain"}, {URL: "panel.example.com", APIKey: "secret://k"}, {URL: "https://u:p@panel", APIKey: "secret://k"}, {URL: "https://panel", APIKey: "secret://k", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "servers", `{}`, false); err == nil || strings.Contains(err.Error(), "ptlc_") {
		t.Fatal(err)
	}
}

// A redirect to another host must not be followed.
func TestPterodactylRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ptlc_good"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
