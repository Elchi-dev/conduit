package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	blockUUID = "11111111-2222-3333-4444-555555555555"
	extUUID   = "66666666-7777-8888-9999-000000000000"
	geoUUID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type fakeOPN struct {
	mu          sync.Mutex
	seen        []string
	block       []string // host alias content
	ext         []string // external alias table
	reconfigs   int
	rebooted    bool
	gatewayDown bool
}

func (f *fakeOPN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, _ := r.BasicAuth(); u != "k" || p != "s" {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":401,"message":"Authentication Failed"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.Method + " " + r.URL.Path {
	case "GET /api/core/firmware/status":
		io.WriteString(w, `{"product":{"product_name":"OPNsense","product_version":"25.1.4","product_check":{"last_check":"Mon Nov  2 10:00:00 UTC 2026"}},"status":"update","status_msg":"There are 3 updates available","updates":"3","needs_reboot":"0"}`)
	case "GET /api/routes/gateway/status":
		st := "none"
		if f.gatewayDown {
			st = "down"
		}
		io.WriteString(w, `{"items":[{"name":"WAN_DHCP","address":"203.0.113.1","status":"`+st+`","status_translated":"Online","loss":"0.0 %","delay":"2.1 ms","monitor":"203.0.113.1"}],"status":"ok"}`)
	case "GET /api/interfaces/overview/interfacesInfo":
		io.WriteString(w, `{"rows":[{"identifier":"lan","description":"LAN","device":"igb1","status":"up","enabled":true,"addr4":"192.168.1.1/24","macaddr":"00:11:22:33:44:55","link_type":"static"}]}`)
	case "GET /api/dhcpv4/leases/searchLease":
		w.WriteHeader(404)
	case "GET /api/kea/leases4/search":
		io.WriteString(w, `{"rows":[{"address":"192.168.1.50","hwaddr":"aa:bb:cc:dd:ee:ff","hostname":"laptop","expire":1800000000,"if_descr":"LAN"}],"total":1}`)
	case "GET /api/firewall/alias/searchItem":
		if r.URL.Query().Get("rowCount") != "-1" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, fmt.Sprintf(`{"rows":[{"uuid":%q,"name":"blocklist","type":"Host(s)","enabled":"1","content":%q},{"uuid":%q,"name":"crowdsec","type":"External (advanced)","enabled":"1","content":""},{"uuid":%q,"name":"countries","type":"GeoIP","enabled":"1","content":"NL,DE"}]}`,
			blockUUID, strings.Join(f.block, "\n"), extUUID, geoUUID))
	case "GET /api/firewall/alias/getItem/" + blockUUID:
		content := map[string]any{}
		for _, e := range f.block {
			content[e] = map[string]any{"value": e, "selected": 1}
		}
		reply(map[string]any{"alias": map[string]any{"type": map[string]any{"host": map[string]any{"value": "Host(s)", "selected": 1}, "network": map[string]any{"value": "Network(s)", "selected": 0}}, "content": content}})
	case "GET /api/firewall/alias/getItem/" + extUUID:
		reply(map[string]any{"alias": map[string]any{"type": map[string]any{"external": map[string]any{"selected": 1}}, "content": map[string]any{}}})
	case "GET /api/firewall/alias/getItem/" + geoUUID:
		reply(map[string]any{"alias": map[string]any{"type": map[string]any{"geoip": map[string]any{"selected": 1}}, "content": map[string]any{}}})
	case "POST /api/firewall/alias/setItem/" + blockUUID:
		var in struct {
			Alias struct {
				Content string `json:"content"`
			} `json:"alias"`
		}
		_ = json.Unmarshal(body, &in)
		f.block = strings.Split(in.Alias.Content, "\n")
		if in.Alias.Content == "" {
			f.block = nil
		}
		io.WriteString(w, `{"result":"saved"}`)
	case "POST /api/firewall/alias/reconfigure":
		f.reconfigs++
		io.WriteString(w, `{"status":"ok"}`)
	case "GET /api/firewall/alias_util/list/crowdsec":
		rows := []map[string]string{}
		for _, e := range f.ext {
			rows = append(rows, map[string]string{"ip": e})
		}
		reply(map[string]any{"rows": rows, "total": len(rows)})
	case "POST /api/firewall/alias_util/add/crowdsec", "POST /api/firewall/alias_util/delete/crowdsec":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		if strings.Contains(r.URL.Path, "/add/") {
			f.ext = append(f.ext, in["address"])
		} else {
			for i, e := range f.ext {
				if e == in["address"] {
					f.ext = append(f.ext[:i], f.ext[i+1:]...)
				}
			}
		}
		io.WriteString(w, `{"status":"done"}`)
	case "POST /api/core/system/reboot":
		f.rebooted = true
		io.WriteString(w, `{"status":"ok"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeOPN) {
	t.Helper()
	f := &fakeOPN{block: []string{"198.51.100.7"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Key: key, Secret: "secret://s"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "k", "secret://s": "s", "secret://bad": "x"}), "fw", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "fw", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOPNsense(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "fw"); h.Status != "ok" || h.Message != "OPNsense 25.1.4 · updates waiting" {
		t.Fatalf("%+v", h)
	}
	f.gatewayDown = true
	if h := m.Health(context.Background(), "fw"); h.Status != "degraded" || !strings.Contains(h.Message, "WAN_DHCP") {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{
		"firmware":   `"updates":"3"`,
		"gateways":   `"status":"down"`,
		"interfaces": `"ipv4":"192.168.1.1/24"`,
		"leases":     `"server":"kea"`,
		"aliases":    `"name":"crowdsec"`,
	} {
		r, err := invoke(m, action, `{}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}
	if r, _ := invoke(m, "leases", `{}`, false); !strings.Contains(string(r.Output), `"mac":"aa:bb:cc:dd:ee:ff"`) || !strings.Contains(string(r.Output), `"ends":"2027-01-15T08:00:00Z"`) {
		t.Fatalf("%s", r.Output)
	}

	// A host alias: edited in the configuration, then applied.
	r, err := invoke(m, "add_alias_entry", `{"alias":"blocklist","entry":"203.0.113.9"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add 203.0.113.9 to alias blocklist (host, 1 entries now)" || len(f.block) != 1 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_alias_entry", `{"alias":"blocklist","entry":"203.0.113.9"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "remove_alias_entry" || len(f.block) != 2 || f.reconfigs != 1 {
		t.Fatalf("%+v %v %v", r, err, f.block)
	}
	if _, err := invoke(m, "add_alias_entry", `{"alias":"blocklist","entry":"203.0.113.9"}`, false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.block) != 1 || f.block[0] != "198.51.100.7" || f.reconfigs != 2 {
		t.Fatalf("undo %v %v", err, f.block)
	}

	// An external alias: the live table.
	r, err = invoke(m, "add_alias_entry", `{"alias":"crowdsec","entry":"192.0.2.0/24"}`, false)
	if err != nil || len(f.ext) != 1 || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if e, _ := invoke(m, "alias_entries", `{"alias":"crowdsec"}`, false); !strings.Contains(string(e.Output), `"entries":["192.0.2.0/24"]`) {
		t.Fatalf("%s", e.Output)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.ext) != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "add_alias_entry", `{"alias":"countries","entry":"FR"}`, false); err == nil || !strings.Contains(err.Error(), "geoip") {
		t.Fatal(err)
	}

	if p, err := invoke(m, "reboot", `{}`, true); err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Restart OPNsense 25.1.4 at") || f.rebooted {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "reboot", `{}`, false); err != nil || !f.rebooted {
		t.Fatal(err)
	}
}

func TestOPNsenseValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, in := range []string{
		`{"alias":"../core/system/reboot","entry":"1.2.3.4"}`,
		`{"alias":"block list","entry":"1.2.3.4"}`,
		`{"alias":"blocklist","entry":"1.2.3.4\n0.0.0.0/0"}`,
		`{"alias":"blocklist","entry":"1.2.3.4,5.6.7.8"}`,
		`{"alias":"blocklist","entry":""}`,
	} {
		if _, err := invoke(m, "add_alias_entry", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the firewall: %v", f.seen)
	}
	// Entries that don't fit the alias type are refused before any change.
	for _, e := range []string{"10.0.0.0/8", "not a host", "-bad-.example"} {
		in, _ := json.Marshal(map[string]string{"alias": "blocklist", "entry": e})
		if _, err := invoke(m, "add_alias_entry", string(in), false); err == nil {
			t.Fatalf("accepted %q", e)
		}
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "POST") {
			t.Fatalf("changed something: %s", s)
		}
	}
	for typ, ok := range map[string][]string{"port": {"443", "8000:8080"}, "mac": {"00:11:22:33:44:55"}, "network": {"10.0.0.0/8", "nas.lan"}} {
		for _, e := range ok {
			if _, err := validEntry(typ, e); err != nil {
				t.Fatalf("%s %s: %v", typ, e, err)
			}
		}
	}
	if _, err := validEntry("port", "70000"); err == nil {
		t.Fatal("accepted port 70000")
	}
	for _, c := range []Config{{URL: "https://fw", Key: "plain", Secret: "secret://s"}, {URL: "fw.lan", Key: "secret://k", Secret: "secret://s"}, {URL: "https://fw/ui", Key: "secret://k", Secret: "secret://s"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "fw"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestEntries(t *testing.T) {
	got := entries(json.RawMessage(`{"b":{"value":"b","selected":1},"a":{"value":"a","selected":"1"},"c":{"value":"c","selected":0}}`))
	if !sort.StringsAreSorted(got) || strings.Join(got, ",") != "a,b" {
		t.Fatal(got)
	}
	if got := entries(json.RawMessage(`"x\ny,z"`)); strings.Join(got, ",") != "x,y,z" {
		t.Fatal(got)
	}
}
