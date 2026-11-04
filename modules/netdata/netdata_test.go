package netdata

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

type fakeNetdata struct {
	mu     sync.Mutex
	seen   []string
	all    bool
	typ    string
	sils   []map[string]string
	noV2   bool
	bearer string
}

func (f *fakeNetdata) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bearer != "" && r.Header.Get("Authorization") != "Bearer "+f.bearer {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"bearer token required"}`)
		return
	}
	f.seen = append(f.seen, r.URL.RequestURI())
	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/v1/info":
		io.WriteString(w, `{"version":"v1.47.0","uid":"LEAKME-GUID","os_name":"Debian GNU/Linux","os_version":"12","kernel_name":"Linux","kernel_version":"6.1.0",
			"architecture":"x86_64","virtualization":"kvm","container":"none","cores_total":"8","ram_total":"17179869184","total_disk_space":"1099511627776",
			"mirrored_hosts":["web1","db1"],"mirrored_hosts_status":[{"hostname":"web1","reachable":true},{"hostname":"db1","reachable":false}],
			"alarms":{"normal":120,"warning":2,"critical":1},"collectors":[{"plugin":"proc.plugin"}],"host_labels":{"owner":"LEAKME"}}`)
	case "/api/v1/alarms":
		all := `,"system.cpu.ok":{"id":3,"name":"ok_alarm","chart":"system.cpu","status":"CLEAR","value_string":"1%","last_status_change":1762000000,"recipient":"LEAKME@example.com"}`
		if q.Get("all") == "" {
			all = ""
		}
		io.WriteString(w, `{"hostname":"web1","alarms":{
			"system.cpu.10min_cpu_usage":{"id":1,"name":"10min_cpu_usage","chart":"system.cpu","family":"cpu","status":"WARNING","value_string":"85.2%","units":"%","info":"average CPU","last_status_change":1762000000,"silenced":false,"recipient":"LEAKME@example.com"},
			"disk_space._.disk_space_usage":{"id":2,"name":"disk_space_usage","chart":"disk_space._","status":"CRITICAL","value_string":"97%","last_status_change":1762000100}`+all+`}}`)
	case "/api/v1/charts":
		io.WriteString(w, `{"hostname":"web1","charts":{"system.cpu":{"id":"system.cpu","title":"Total CPU utilization","units":"percentage","context":"system.cpu","family":"cpu","update_every":1},
			"disk_space._":{"id":"disk_space._","title":"Disk Space Usage","units":"GiB","context":"disk.space","family":"/"}}}`)
	case "/api/v1/chart":
		if q.Get("chart") != "system.cpu" {
			w.WriteHeader(404)
			io.WriteString(w, "Chart is not found: "+q.Get("chart"))
			return
		}
		io.WriteString(w, `{"id":"system.cpu","title":"Total CPU utilization","units":"percentage"}`)
	case "/api/v1/data":
		io.WriteString(w, `{"labels":["time","user","system"],"data":[[1762000000,12.34567,3.5]]}`)
	case "/api/v2/nodes":
		if f.noV2 {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"nodes":[{"mg":"LEAKME-GUID","nd":"6f3c-node","nm":"web1","ni":0,"v":"v1.47.0","state":"reachable"},{"nm":"db1","ni":1}]}`)
	case "/api/v1/manage/health":
		if r.Header.Get("X-Auth-Token") != "mgmkey" {
			w.WriteHeader(403)
			io.WriteString(w, "You are not allowed to access this resource.")
			return
		}
		switch q.Get("cmd") {
		case "LIST":
			json.NewEncoder(w).Encode(map[string]any{"all": f.all, "type": f.typ, "silencers": f.sils})
		case "SILENCE ALL":
			f.all, f.typ = true, "SILENCE"
			io.WriteString(w, "All alarm notifications are silenced")
		case "SILENCE":
			f.typ = "SILENCE"
			s := map[string]string{}
			for _, k := range []string{"alarm", "chart", "context", "host"} {
				if v := q.Get(k); v != "" {
					s[k] = v
				}
			}
			f.sils = append(f.sils, s)
			io.WriteString(w, "Alarm notifications silenced for the selectors")
		case "RESET":
			f.all, f.typ, f.sils = false, "None", nil
			io.WriteString(w, "All health checks and notifications are enabled")
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeNetdata) {
	f := &fakeNetdata{typ: "None"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mk": "mgmkey", "secret://bad": "wrong", "secret://tok": "nd-token"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNetdata(t *testing.T) {
	m, f := setup(t, Config{ManagementKey: "secret://mk"})
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "Netdata v1.47.0 · 1 critical, 2 warning alarms" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"info", `{}`, `"memoryGB":16`},
		{"info", `{}`, `"diskGB":1024`},
		{"alarms", `{}`, `"count":2`},
		{"alarms", `{}`, `"alarms":[{"chart":"disk_space._"`},
		{"alarms", `{"status":"CLEAR"}`, `"name":"ok_alarm"`},
		{"charts", `{"query":"disk"}`, `"total":1`},
		{"metric", `{"chart":"system.cpu"}`, `"values":{"system":3.5,"user":12.345}`},
		{"nodes", `{}`, `"state":"reachable"`},
		{"silencers", `{}`, `"type":"none"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if _, err := invoke(m, "metric", `{"chart":"nope.chart"}`, false); err == nil || !strings.Contains(err.Error(), "no chart") {
		t.Fatal(err)
	}
	f.noV2 = true
	if r, err := invoke(m, "nodes", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"reachable":false`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Silence everything: preview, real, nothing to change, undo.
	r, err := invoke(m, "silence", `{"all":true}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Silence all alarms" || f.all {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "silence", `{"all":true}`, false)
	if err != nil || !f.all || r.Undo == nil || r.Undo.Action != "unsilence" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "silence", `{"all":true}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.all || r.Undo == nil || string(r.Undo.Input) != `{"all":true}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "unsilence", `{}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// One silencer by selectors; unsilencing it can put it back.
	if _, err := invoke(m, "silence", `{"alarm":"*10min*","chart":"system.*"}`, false); err != nil || len(f.sils) != 1 || f.sils[0]["alarm"] != "*10min*" {
		t.Fatal(err, f.sils)
	}
	if r, _ := invoke(m, "silence", `{"chart":"system.*","alarm":"*10min*"}`, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}
	r, err = invoke(m, "unsilence", `{}`, false)
	if err != nil || len(f.sils) != 0 || r.Undo == nil || string(r.Undo.Input) != `{"alarm":"*10min*","chart":"system.*"}` {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "silence" && a.Risk != sdk.RiskDestructive {
			t.Fatal("silence isn't destructive")
		}
	}
}

func TestNetdataValidation(t *testing.T) {
	m, f := setup(t, Config{ManagementKey: "secret://mk"})
	for _, c := range []struct{ action, in string }{
		{"metric", `{}`}, {"metric", `{"chart":"../x"}`}, {"metric", `{"chart":"a&b=c"}`}, {"metric", `{"chart":"system.cpu","seconds":-5}`},
		{"silence", `{}`}, {"silence", `{"all":true,"alarm":"x"}`}, {"silence", `{"alarm":"a&cmd=RESET"}`}, {"silence", `{"chart":"x\ny"}`},
		{"alarms", `{"status":"bogus"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://x:19999", ManagementKey: "plainkey"}, {URL: "http://x:19999", Token: "plain"}, {URL: "x:19999"},
		{URL: "http://u:p@x:19999"}, {URL: "http://x:19999/?a=1"}, {URL: "http://x:19999/#a"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// No management key: silencing says what's missing without a request.
	nokey, f2 := setup(t, Config{})
	if _, err := invoke(nokey, "silence", `{"all":true}`, false); err == nil || !strings.Contains(err.Error(), "managementKey") || len(f2.seen) != 0 {
		t.Fatal(err)
	}
	// A wrong management key.
	bad, _ := setup(t, Config{ManagementKey: "secret://bad"})
	if _, err := invoke(bad, "silencers", `{}`, false); err == nil || err.Error() != "Netdata refused the management key" {
		t.Fatal(err)
	}
	// A bearer token is sent when set, and a wrong one is reported.
	tok, f3 := setup(t, Config{Token: "secret://tok"})
	f3.bearer = "nd-token"
	if h := tok.Health(context.Background(), "n"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	f3.bearer = "other"
	if h := tok.Health(context.Background(), "n"); h.Status != "down" || strings.Contains(h.Message, "nd-token") || !strings.Contains(h.Message, "bearer token") {
		t.Fatalf("%+v", h)
	}
}

func TestNetdataRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("X-Auth-Token")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://tok", ManagementKey: "secret://mk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tok": "nd-token", "secret://mk": "mgmkey"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: "silencers"}); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
