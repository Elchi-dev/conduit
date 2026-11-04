package mikrotik

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeROS struct {
	mu       sync.Mutex
	seen     []string
	list     []map[string]string
	next     int
	rebooted bool
	cpu      string
	redirect string
}

func (f *fakeROS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, _ := r.BasicAuth(); u != "conduit" || p != "pw" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":401,"message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.Method + " " + r.URL.Path {
	case "GET /rest/system/resource":
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		io.WriteString(w, `{"uptime":"3d4h5m","version":"7.16.1 (stable)","board-name":"hAP ax3","architecture-name":"arm64","cpu-load":"`+f.cpu+`","cpu-count":"4","free-memory":"800000000","total-memory":"1073741824","free-hdd-space":"100000000","total-hdd-space":"134217728"}`)
	case "GET /rest/system/identity":
		io.WriteString(w, `{"name":"core-router"}`)
	case "GET /rest/interface":
		io.WriteString(w, `[{".id":"*1","name":"ether1","type":"ether","running":"true","disabled":"false","mac-address":"48:A9:8A:00:00:01","rx-byte":"123456","tx-byte":"654321","actual-mtu":"1500"},{".id":"*2","name":"wifi1","type":"wifi","running":"false","disabled":"true","rx-byte":"0","tx-byte":"0"}]`)
	case "GET /rest/ip/dhcp-server/lease":
		io.WriteString(w, `[{".id":"*A","address":"192.168.88.20","mac-address":"AA:BB:CC:DD:EE:FF","host-name":"laptop","status":"bound","server":"defconf","dynamic":"true","expires-after":"8m"}]`)
	case "GET /rest/ip/firewall/address-list":
		out := []map[string]string{}
		for _, e := range f.list {
			if l := r.URL.Query().Get("list"); l == "" || l == e["list"] {
				out = append(out, e)
			}
		}
		reply(out)
	case "PUT /rest/ip/firewall/address-list":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		for _, e := range f.list {
			if e["list"] == in["list"] && e["address"] == in["address"] {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":400,"message":"Bad Request","detail":"failure: already have such entry"}`)
				return
			}
		}
		f.next++
		in[".id"] = fmt.Sprintf("*%X", f.next+100)
		in["dynamic"] = "false"
		f.list = append(f.list, in)
		reply(in)
	case "POST /rest/system/reboot":
		f.rebooted = true
		io.WriteString(w, `[]`)
	case "GET /rest/interface/wifi/registration-table":
		io.WriteString(w, `[{"interface":"wifi1","mac-address":"11:22:33:44:55:66"},{"interface":"wifi2","mac-address":"11:22:33:44:55:67"},{"interface":"wifi1","mac-address":"11:22:33:44:55:68"}]`)
	case "GET /rest/caps-man/registration-table":
		io.WriteString(w, `[{"interface":"cap-1","mac-address":"11:22:33:44:55:69"}]`)
	default:
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/rest/ip/firewall/address-list/") {
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/firewall/address-list/")
			for i, e := range f.list {
				if e[".id"] == id {
					f.list = append(f.list[:i], f.list[i+1:]...)
					w.WriteHeader(204)
					return
				}
			}
		}
		w.WriteHeader(400)
		io.WriteString(w, `{"error":400,"message":"Bad Request","detail":"no such command"}`)
	}
}

func setup(t *testing.T, password string) (*Module, *fakeROS, *httptest.Server) {
	t.Helper()
	f := &fakeROS{cpu: "7", list: []map[string]string{
		{".id": "*1", "list": "blocked", "address": "198.51.100.7", "dynamic": "false", "comment": "scanner"},
		{".id": "*2", "list": "blocked", "address": "203.0.113.0/24", "dynamic": "true", "timeout": "23h"},
		{".id": "*3", "list": "trusted", "address": "192.168.88.0/24", "dynamic": "false"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Username: "conduit", Password: password})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, srv
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMikroTik(t *testing.T) {
	m, f, _ := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "core-router · RouterOS 7.16.1 (stable) · up 3d4h5m" {
		t.Fatalf("%+v", h)
	}
	f.cpu = "97"
	if h := m.Health(context.Background(), "r"); h.Status != "degraded" || !strings.Contains(h.Message, "CPU at 97%") {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{
		"system":           `"memoryTotalBytes":1073741824`,
		"interfaces":       `"rxBytes":123456`,
		"leases":           `"hostname":"laptop"`,
		"address_lists":    `{"list":"blocked","entries":2,"dynamic":1}`,
		"wireless_clients": `"total":4`,
	} {
		r, err := invoke(m, action, `{}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
	}
	if r, _ := invoke(m, "wireless_clients", `{}`, false); !strings.Contains(string(r.Output), `{"clients":2,"interface":"wifi1"}`) || !strings.Contains(string(r.Output), `"sources":["wifi","capsman"]`) {
		t.Fatalf("%s", r.Output)
	}
	r, err := invoke(m, "address_list_entries", `{"list":"blocked"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"comment":"scanner"`) || strings.Contains(string(r.Output), "trusted") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Preview, add, refuse a duplicate, undo.
	add := `{"list":"blocked","address":"192.0.2.5/32","comment":"brute force","timeout":"1d"}`
	r, err = invoke(m, "add_address_list_entry", add, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add 192.0.2.5 to address list blocked (2 entries now), for 1d" || len(f.list) != 3 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_address_list_entry", add, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "remove_address_list_entry" || len(f.list) != 4 || f.list[3]["timeout"] != "1d" {
		t.Fatalf("%+v %v %v", r, err, f.list)
	}
	if _, err := invoke(m, "add_address_list_entry", add, false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.list) != 3 {
		t.Fatalf("undo %v %v", err, f.list)
	}
	// Removing keeps the comment for the undo.
	r, err = invoke(m, "remove_address_list_entry", `{"list":"blocked","address":"198.51.100.7"}`, false)
	if err != nil || len(f.list) != 2 || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"comment":"scanner"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "remove_address_list_entry", `{"list":"blocked","address":"198.51.100.7"}`, false); err == nil || !strings.Contains(err.Error(), "isn't in") {
		t.Fatal(err)
	}

	if p, err := invoke(m, "reboot", `{}`, true); err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Restart core-router (RouterOS 7.16.1 (stable)) at http://") || f.rebooted {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "reboot", `{}`, false); err != nil || !f.rebooted {
		t.Fatal(err)
	}
	// Nothing that holds a password is ever asked for.
	for _, s := range f.seen {
		for _, bad := range []string{"/user", "/ppp", "security-profiles", "/certificate", "/export"} {
			if strings.Contains(s, bad) {
				t.Fatalf("asked for %s", s)
			}
		}
	}
}

func TestMikroTikValidation(t *testing.T) {
	m, f, srv := setup(t, "secret://pw")
	for _, in := range []string{
		`{"list":"../../system/reboot","address":"1.2.3.4"}`,
		`{"list":"block list","address":"1.2.3.4"}`,
		`{"list":"blocked","address":"1.2.3.4\n0.0.0.0/0"}`,
		`{"list":"blocked","address":"1.2.3.4,5.6.7.8"}`,
		`{"list":"blocked","address":""}`,
		`{"list":"blocked","address":"1.2.3.4-::1"}`,
		`{"list":"blocked","address":"1.2.3.4","timeout":"forever"}`,
		`{"list":"blocked","address":"1.2.3.4","comment":"a\nb"}`,
	} {
		if _, err := invoke(m, "add_address_list_entry", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "address_list_entries", `{"list":"x?y=1"}`, false); err == nil {
		t.Fatal("accepted a bad list name")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the router: %v", f.seen)
	}
	for in, want := range map[string]string{"10.1.2.3/8": "10.0.0.0/8", "10.0.0.1-10.0.0.9": "10.0.0.1-10.0.0.9", "Example.COM": "example.com", "2001:db8::1": "2001:db8::1"} {
		if got, err := validAddress(in); err != nil || got != want {
			t.Fatalf("%s: %s %v", in, got, err)
		}
	}
	for _, c := range []Config{
		{URL: "https://r", Username: "u", Password: "plain"},
		{URL: "192.168.88.1", Username: "u", Password: "secret://pw"},
		{URL: "https://r/webfig", Username: "u", Password: "secret://pw"},
		{URL: "https://u:p@r", Username: "u", Password: "secret://pw"},
		{URL: "https://r", Username: "", Password: "secret://pw"},
		{URL: "https://r", Username: "u", Password: "secret://pw", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}

	// A redirect to another host never carries the password there.
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer other.Close()
	f.redirect = other.URL + "/steal"
	_ = srv
	if h := m.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
