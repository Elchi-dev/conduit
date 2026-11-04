package crafty

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

const sid = "6a1f3e9c-2b4d-4c8e-9f00-112233445566"

type fakeCrafty struct {
	mu      sync.Mutex
	seen    []string
	running bool
}

func (f *fakeCrafty) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer crafty_good" {
		w.WriteHeader(403)
		io.WriteString(w, `{"status":"error","error":"NOT_AUTHORIZED","error_data":"Invalid token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	base := "/api/v2/servers/" + sid
	stats := func() string {
		if !f.running {
			return `{"status":"ok","data":{"running":false,"cpu":0,"mem":0,"mem_percent":0,"online":0,"max":20,"players":"False","version":"1.21.1","desc":"A Minecraft Server","world_name":"world","world_size":"120.5MB","server_port":25565}}`
		}
		return `{"status":"ok","data":{"running":true,"cpu":12.5,"mem":"1.8GB","mem_percent":22.4,"online":2,"max":20,"players":"['Steve', 'Alex']","version":"1.21.1","desc":"A Minecraft Server","world_name":"world","world_size":"120.5MB","server_port":25565,"started":"2026-11-04 10:00:00"}}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/servers":
		io.WriteString(w, `{"status":"ok","data":[{"server_id":"`+sid+`","server_name":"Survival","type":"minecraft-java","server_port":25565},{"server_id":7,"server_name":"Old","type":"minecraft-java"}]}`)
	case "GET " + base:
		io.WriteString(w, `{"status":"ok","data":{"server_id":"`+sid+`","server_name":"Survival","type":"minecraft-java"}}`)
	case "GET " + base + "/stats":
		io.WriteString(w, stats())
	case "GET /api/v2/servers/7/stats":
		io.WriteString(w, `{"status":"ok","data":{"running":false,"online":0,"max":10,"players":"[]"}}`)
	case "POST " + base + "/action/start_server":
		f.running = true
		io.WriteString(w, `{"status":"ok"}`)
	case "POST " + base + "/action/stop_server", "POST " + base + "/action/kill_server":
		f.running = false
		io.WriteString(w, `{"status":"ok"}`)
	case "POST " + base + "/action/restart_server", "POST " + base + "/action/backup_server", "POST " + base + "/action/backup_server/0b0b0b0b-1111-4222-8333-444455556666":
		io.WriteString(w, `{"status":"ok"}`)
	case "POST " + base + "/stdin":
		if r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"status":"ok"}`)
	case "GET " + base + "/backups":
		io.WriteString(w, `{"0b0b0b0b-1111-4222-8333-444455556666":{"backup_id":"0b0b0b0b-1111-4222-8333-444455556666","backup_name":"Nightly","max_backups":3,"shutdown":true,"default":true},"1c1c1c1c-1111-4222-8333-444455556666":{"backup_id":"1c1c1c1c-1111-4222-8333-444455556666","backup_name":"Keep all","max_backups":0,"shutdown":false,"default":false}}`)
	case "GET " + base + "/backups/backup/0b0b0b0b-1111-4222-8333-444455556666/files":
		io.WriteString(w, `{"total":3,"backups":["/crafty/backups/a.zip","/crafty/backups/b.zip","/crafty/backups/c.zip"]}`)
	case "GET " + base + "/logs":
		io.WriteString(w, `{"status":"ok","data":["[10:00:00] [Server thread/INFO]: Starting","[10:00:05] [Server thread/INFO]: Done","[10:01:00] Steve joined the game"]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"error","error":"NOT_FOUND"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeCrafty) {
	f := &fakeCrafty{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v2", Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "crafty_good", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCrafty(t *testing.T) {
	m, f := setup(t, "secret://c")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "2 servers" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "servers", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"id":"7"`) || !strings.Contains(string(r.Output), `"state":"stopped"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	srv := `{"server":"` + sid + `"}`
	r, err = invoke(m, "start", srv, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start server Survival" || f.running {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start", srv, false)
	if err != nil || !f.running || r.Undo == nil || r.Undo.Action != "stop" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "start", srv, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	r, err = invoke(m, "stats", srv, false)
	if err != nil || !strings.Contains(string(r.Output), `"online":["Steve","Alex"]`) || !strings.Contains(string(r.Output), `"memory":"1.8GB"`) || !strings.Contains(string(r.Output), `"cpu":12.5`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	if r, err := invoke(m, "stop", srv, true); err != nil || !strings.Contains(r.Plan.Summary, "2 players are disconnected") || !f.running {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	cmd := `{"server":"` + sid + `","command":"say Restart in 5 minutes"}`
	if r, err := invoke(m, "command", cmd, true); err != nil || !strings.Contains(r.Plan.Summary, "say Restart in 5 minutes") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "command", cmd, false); err != nil || !strings.HasSuffix(f.seen[len(f.seen)-1], "/stdin say Restart in 5 minutes") {
		t.Fatal(err, f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, "backup", `{"server":"`+sid+`","backupConfig":"0B0B0B0B-1111-4222-8333-444455556666"}`, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], "/action/backup_server/0b0b0b0b-1111-4222-8333-444455556666") {
		t.Fatal(err, f.seen[len(f.seen)-1])
	}
	if r, err := invoke(m, "logs", `{"server":"`+sid+`","lines":2}`, false); err != nil || strings.Contains(string(r.Output), "Starting") || !strings.Contains(string(r.Output), "Steve joined") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "restart", srv, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], "/action/restart_server") {
		t.Fatal(err)
	}
	r, err = invoke(m, "stop", srv, false)
	if err != nil || f.running || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "command", cmd, false); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "kill", srv, false); err == nil || !strings.Contains(err.Error(), "already stopped") {
		t.Fatal(err)
	}
	// Older Crafty numbers servers.
	if _, err := invoke(m, "stats", `{"server":7}`, false); err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Fatal(err)
	}
}

func TestCraftyValidation(t *testing.T) {
	m, f := setup(t, "secret://c")
	for _, c := range []struct{ action, in string }{
		{"stats", `{}`},
		{"start", `{"server":"../users"}`},
		{"stop", `{"server":"1/action"}`},
		{"kill", `{"server":{"id":1}}`},
		{"command", `{"server":1,"command":"op me\nstop"}`},
		{"command", `{"server":1,"command":"  "}`},
		{"backup", `{"server":1,"backupConfig":"../../x"}`},
		{"logs", `{"server":1,"lines":5000}`},
		{"nope", `{"server":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Crafty: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://crafty:8443", Token: "plain"}, {URL: "crafty:8443", Token: "secret://c"}, {URL: "https://crafty:8443?x=1", Token: "secret://c"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestCraftyRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + "|" + r.URL.Path
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "crafty_good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// backup is destructive: Crafty rotates out old backups and a configuration
// can shut the server down. The preview reads the configuration and says so.
func TestCraftyBackupPreview(t *testing.T) {
	m, f := setup(t, "secret://c")
	for _, a := range New().Manifest().Actions {
		if a.Name == "backup" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%+v", a)
		}
	}
	f.running = true
	r, err := invoke(m, "backup", `{"server":"`+sid+`"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, `"Nightly"`) || !strings.Contains(r.Plan.Summary, "keeps at most 3 and has 3 now, so Crafty deletes the 1 oldest") ||
		!strings.Contains(r.Plan.Summary, "shuts the server down while backing up, disconnecting 2 players") || !strings.Contains(string(r.Plan.Changes[0].Before), `"maxBackups":3`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "backup", `{"server":"`+sid+`","backupConfig":"1c1c1c1c-1111-4222-8333-444455556666"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "keeps every backup") || strings.Contains(r.Plan.Summary, "shuts") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "backup", `{"server":"`+sid+`","backupConfig":"2d2d2d2d-1111-4222-8333-444455556666"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "unknown") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "backup_server") {
			t.Fatalf("a preview ran a backup: %s", s)
		}
	}
}
