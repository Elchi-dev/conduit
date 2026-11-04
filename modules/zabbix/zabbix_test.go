package zabbix

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

type fakeZabbix struct {
	mu      sync.Mutex
	version string
	seen    []string
	acked   map[string]bool
	closed  map[string]bool
	maint   map[string]map[string]any
	lastAck map[string]any
	lastNew map[string]any
}

func (f *fakeZabbix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/zabbix/api_jsonrpc.php" {
		w.WriteHeader(404)
		return
	}
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Auth   string          `json:"auth"`
		ID     int             `json:"id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": v, "id": req.ID}) }
	fail := func(data string) {
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32602, "message": "Invalid params.", "data": data}, "id": req.ID})
	}
	if req.Method == "apiinfo.version" {
		if req.Auth != "" || r.Header.Get("Authorization") != "" {
			fail(`The "apiinfo.version" method must be called without the "auth" parameter.`)
			return
		}
		reply(f.version)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if f.version < "6.4" {
		if r.Header.Get("Authorization") != "" {
			fail("Not authorized.")
			return
		}
		tok = req.Auth
	} else if req.Auth != "" {
		fail(`Invalid parameter "/": unexpected parameter "auth".`)
		return
	}
	if tok != "zbx-good-token" {
		fail("Not authorized.")
		return
	}
	f.seen = append(f.seen, req.Method)
	var p map[string]any
	json.Unmarshal(req.Params, &p)
	switch req.Method {
	case "host.get":
		if p["countOutput"] == true {
			reply("2")
			return
		}
		gk := "hostgroups"
		if f.version < "6.2" {
			gk = "groups"
		}
		hosts := []map[string]any{
			{"hostid": "10084", "host": "zabbix-server", "name": "Zabbix server", "status": "0", "maintenance_status": "0", gk: []map[string]string{{"groupid": "4", "name": "Zabbix servers"}},
				"interfaces": []map[string]string{{"ip": "127.0.0.1", "dns": "", "useip": "1", "port": "10050", "type": "1", "main": "1", "available": "1"}}, "inventory": map[string]string{"contact": "LEAKME"}},
			{"hostid": "10100", "host": "web1", "name": "Web 1", "status": "1", "maintenance_status": "1", gk: []map[string]string{},
				"interfaces": []map[string]string{{"ip": "", "dns": "web1.lan", "useip": "0", "port": "161", "type": "2", "main": "1", "available": "2"}}},
		}
		if ids, ok := p["hostids"].([]any); ok {
			var out []map[string]any
			for _, h := range hosts {
				for _, id := range ids {
					if h["hostid"] == id {
						out = append(out, h)
					}
				}
			}
			reply(out)
			return
		}
		reply(hosts)
	case "hostgroup.get":
		reply([]map[string]string{{"groupid": "4", "name": "Zabbix servers"}})
	case "problem.get":
		if p["countOutput"] == true {
			reply("2")
			return
		}
		out := []map[string]string{}
		for _, id := range []string{"501", "500"} {
			if f.closed[id] {
				continue
			}
			sev := map[string]string{"501": "4", "500": "2"}[id]
			if sevs, ok := p["severities"].([]any); ok {
				match := false
				for _, s := range sevs {
					if s.(float64) == float64(sev[0]-'0') {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			out = append(out, map[string]string{"eventid": id, "objectid": "t" + id[2:], "name": "Problem " + id, "severity": sev, "clock": "1762000000",
				"acknowledged": map[bool]string{true: "1", false: "0"}[f.acked[id]], "suppressed": "0"})
		}
		for i := range out {
			out[i]["objectid"] = map[string]string{"501": "13001", "500": "13000"}[out[i]["eventid"]]
		}
		reply(out)
	case "trigger.get":
		reply([]map[string]any{{"triggerid": "13001", "hosts": []map[string]string{{"name": "Web 1"}}}, {"triggerid": "13000", "hosts": []map[string]string{{"name": "Zabbix server"}}}})
	case "event.get":
		out := []map[string]string{}
		for _, id := range p["eventids"].([]any) {
			s := id.(string)
			if s != "500" && s != "501" {
				continue
			}
			r := "0"
			if f.closed[s] {
				r = "900"
			}
			out = append(out, map[string]string{"eventid": s, "name": "Problem " + s, "acknowledged": map[bool]string{true: "1", false: "0"}[f.acked[s]], "r_eventid": r})
		}
		reply(out)
	case "event.acknowledge":
		f.lastAck = p
		a := int(p["action"].(float64))
		for _, id := range p["eventids"].([]any) {
			s := id.(string)
			switch {
			case a&2 != 0:
				f.acked[s] = true
			case a&16 != 0:
				f.acked[s] = false
			}
			if a&1 != 0 {
				f.closed[s] = true
			}
		}
		reply(map[string]any{"eventids": p["eventids"]})
	case "maintenance.get":
		out := []map[string]any{}
		for id, m := range f.maint {
			if flt, ok := p["filter"].(map[string]any); ok && flt["name"] != m["name"] {
				continue
			}
			if ids, ok := p["maintenanceids"].([]any); ok && ids[0] != id {
				continue
			}
			out = append(out, m)
		}
		reply(out)
	case "maintenance.create":
		f.lastNew = p
		f.maint["7"] = map[string]any{"maintenanceid": "7", "name": p["name"], "maintenance_type": "0", "active_since": "1", "active_till": "2", "hosts": []map[string]string{{"name": "Web 1"}}}
		reply(map[string]any{"maintenanceids": []string{"7"}})
	case "maintenance.delete":
		var ids []string
		json.Unmarshal(req.Params, &ids)
		for _, id := range ids {
			delete(f.maint, id)
		}
		reply(map[string]any{"maintenanceids": ids})
	default:
		fail("Incorrect method.")
	}
}

func setup(t *testing.T, version, tok string) (*Module, *fakeZabbix) {
	f := &fakeZabbix{version: version, acked: map[string]bool{"500": true}, closed: map[string]bool{},
		maint: map[string]map[string]any{"3": {"maintenanceid": "3", "name": "Patch night", "maintenance_type": "1", "active_since": "1762000000", "active_till": "1762003600",
			"hosts": []map[string]string{{"name": "Web 1"}}, "hostgroups": []map[string]string{{"name": "Linux"}}, "groups": []map[string]string{{"name": "Linux"}}}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Unix(1762000030, 0) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/zabbix/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://zbx": "zbx-good-token", "secret://bad": "zbx-wrong"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZabbix(t *testing.T) {
	for _, version := range []string{"7.0.3", "6.0.20"} {
		t.Run(version, func(t *testing.T) { testZabbix(t, version) })
	}
}

func testZabbix(t *testing.T, version string) {
	m, f := setup(t, version, "secret://zbx")
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "Zabbix "+version+" · 2 hosts, 2 problems" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"problems", `{}`, `"hosts":["Web 1"]`},
		{"problems", `{}`, `"severity":"high"`},
		{"problems", `{"minSeverity":"high"}`, `"event":"501"`},
		{"hosts", `{}`, `"groups":["Zabbix servers"]`},
		{"hosts", `{}`, `"address":"web1.lan","availability":"unavailable","main":true,"port":"161","type":"SNMP"`},
		{"hosts", `{"query":"web"}`, `"inMaintenance":true`},
		{"maintenances", `{}`, `"collectsData":false`},
		{"maintenances", `{}`, `"groups":["Linux"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "problems", `{"minSeverity":"high"}`, false); strings.Contains(string(r.Output), `"500"`) {
		t.Fatal(string(r.Output))
	}

	// Acknowledge: preview, real, undo; an acknowledged one is left alone.
	r, err := invoke(m, "acknowledge", `{"events":["500","501"]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || f.acked["501"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "acknowledge", `{"events":["500","501"],"message":"Looking into it"}`, false)
	if err != nil || !f.acked["501"] || f.lastAck["action"] != float64(6) || f.lastAck["message"] != "Looking into it" {
		t.Fatalf("%+v %v %v", r, err, f.lastAck)
	}
	if r.Undo == nil || r.Undo.Action != "unacknowledge" || string(r.Undo.Input) != `{"events":["501"]}` {
		t.Fatalf("%+v", r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.acked["501"] || !f.acked["500"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "unacknowledge", `{"events":["501"]}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "acknowledge", `{"events":["999"]}`, false); err == nil || !strings.Contains(err.Error(), "no problem event") {
		t.Fatal(err)
	}

	// Close.
	if r, err := invoke(m, "close_problems", `{"events":["501"]}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Close 1 problems" || f.closed["501"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "close_problems", `{"events":["501"]}`, false); err != nil || !f.closed["501"] || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := invoke(m, "close_problems", `{"events":["501"]}`, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}

	// Maintenance: preview, create, undo; a taken name is refused.
	in := `{"name":"Router swap","hosts":["10100"],"minutes":60,"collectData":true}`
	r, err = invoke(m, "create_maintenance", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Put Web 1 in maintenance for 60 minutes" || len(f.maint) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_maintenance", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_maintenance" || string(r.Undo.Input) != `{"maintenance":"7"}` {
		t.Fatalf("%+v %v", r, err)
	}
	tp := f.lastNew["timeperiods"].([]any)[0].(map[string]any)
	if f.lastNew["active_since"] != float64(1762000020) || f.lastNew["active_till"] != float64(1762003620) || tp["period"] != float64(3600) {
		t.Fatal(f.lastNew)
	}
	if version >= "6" {
		if _, ok := f.lastNew["hosts"]; !ok {
			t.Fatal(f.lastNew)
		}
	}
	if _, err := invoke(m, "create_maintenance", in, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.maint) != 1 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "delete_maintenance", `{"maintenance":"3"}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Delete the maintenance Patch night" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete_maintenance", `{"maintenance":"42"}`, false); err == nil || !strings.Contains(err.Error(), "no maintenance") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_maintenance", `{"name":"x","hosts":["999"],"minutes":60}`, false); err == nil || !strings.Contains(err.Error(), "no host 999") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "close_problems" || strings.HasSuffix(a.Name, "_maintenance")) && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestZabbixValidation(t *testing.T) {
	m, f := setup(t, "7.0.3", "secret://zbx")
	for _, c := range []struct{ action, in string }{
		{"acknowledge", `{}`}, {"acknowledge", `{"events":["1; DROP"]}`}, {"close_problems", `{"events":["abc"]}`},
		{"acknowledge", `{"events":["1"],"message":"` + strings.Repeat("x", 2049) + `"}`},
		{"problems", `{"minSeverity":"apocalyptic"}`}, {"problems", `{"hosts":["web1"]}`},
		{"hosts", `{"query":"a\nb"}`},
		{"create_maintenance", `{"name":"x","minutes":60}`}, {"create_maintenance", `{"name":"","hosts":["1"],"minutes":60}`},
		{"create_maintenance", `{"name":"x","hosts":["1"],"minutes":1}`}, {"create_maintenance", `{"name":"x","hosts":["1"],"minutes":100000}`},
		{"create_maintenance", `{"name":"a\nb","hosts":["1"],"minutes":60}`}, {"create_maintenance", `{"name":"x","groups":["../1"],"minutes":60}`},
		{"delete_maintenance", `{}`}, {"delete_maintenance", `{"maintenance":"3 OR 1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://z.example.com", Token: "zbx-plain"}, {URL: "z.example.com", Token: "secret://zbx"},
		{URL: "https://u:p@z.example.com", Token: "secret://zbx"}, {URL: "https://z.example.com/?a=1", Token: "secret://zbx"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, v := range []string{"7.0.3", "6.0.20"} {
		bad, _ := setup(t, v, "secret://bad")
		if h := bad.Health(context.Background(), "z"); h.Status != "down" || h.Message != "Zabbix refused the API token" {
			t.Fatalf("%s: %+v", v, h)
		}
	}
	old, _ := setup(t, "5.2.7", "secret://zbx")
	if h := old.Health(context.Background(), "z"); h.Status != "down" || !strings.Contains(h.Message, "5.4") {
		t.Fatalf("%+v", h)
	}
}

func TestZabbixRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://zbx"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://zbx": "zbx-good-token"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "z"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
