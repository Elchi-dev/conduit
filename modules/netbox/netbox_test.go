package netbox

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

type fakeNB struct {
	mu       sync.Mutex
	seen     []string
	ips      map[int]map[string]any
	nextIP   int
	status   string
	redirect string
}

func (f *fakeNB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a := r.Header.Get("Authorization"); a != "Token t0k" && a != "Bearer nbt_abc.def" {
		w.WriteHeader(403)
		io.WriteString(w, `{"detail":"Invalid v1 token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	pfx := map[string]any{"id": 7, "prefix": "10.0.20.0/24", "status": map[string]string{"value": "active"}, "site": map[string]any{"id": 1, "name": "HQ"}, "vlan": map[string]any{"id": 3, "vid": 20, "name": "servers"}, "custom_fields": map[string]any{"wifi_psk": "hunter2"}}
	dev := map[string]any{"id": 42, "name": "sw1", "status": map[string]string{"value": f.status}, "role": map[string]any{"name": "Core switch"}, "device_type": map[string]any{"model": "CRS326"}, "site": map[string]any{"name": "HQ"}, "primary_ip": map[string]any{"address": "10.0.20.2/24"}, "config_context": map[string]any{"snmp_community": "s3cret"}}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/status/":
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		io.WriteString(w, `{"netbox-version":"4.1.3","rq-workers-running":1}`)
	case "GET /api/dcim/sites/":
		reply(map[string]any{"count": 1, "results": []any{map[string]any{"id": 1, "name": "HQ", "slug": "hq", "status": map[string]string{"value": "active"}, "device_count": 12}}})
	case "GET /api/dcim/devices/":
		if n := r.URL.Query().Get("name"); n != "" && n != "sw1" {
			reply(map[string]any{"count": 0, "results": []any{}})
			return
		}
		reply(map[string]any{"count": 1, "results": []any{dev}})
	case "GET /api/dcim/devices/42/":
		reply(dev)
	case "PATCH /api/dcim/devices/42/":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		f.status = in["status"]
		dev["status"] = map[string]string{"value": f.status}
		reply(dev)
	case "GET /api/dcim/interfaces/":
		reply(map[string]any{"count": 1, "results": []any{map[string]any{"id": 1, "name": "ether1", "type": map[string]string{"value": "1000base-t"}, "enabled": true}}})
	case "GET /api/ipam/ip-addresses/":
		if n := r.URL.Query().Get("dns_name__ie"); n != "" {
			res := []any{}
			for _, ip := range f.ips {
				if strings.EqualFold(fmt.Sprint(ip["dns_name"]), n) {
					res = append(res, ip)
				}
			}
			if strings.EqualFold(n, "mail.example.com") {
				res = append(res, map[string]any{"id": 9, "address": "10.0.20.25/24", "dns_name": "Mail.example.com", "status": map[string]string{"value": "active"}})
			}
			reply(map[string]any{"count": len(res), "results": res})
			return
		}
		reply(map[string]any{"count": 1, "results": []any{map[string]any{"id": 5, "address": "10.0.20.2/24", "status": map[string]string{"value": "active"}, "assigned_object": map[string]any{"name": "ether1", "device": map[string]any{"name": "sw1"}}}}})
	case "GET /api/ipam/prefixes/":
		if p := r.URL.Query().Get("prefix"); p != "" && p != "10.0.20.0/24" {
			reply(map[string]any{"count": 0, "results": []any{}})
			return
		}
		reply(map[string]any{"count": 1, "results": []any{pfx}})
	case "GET /api/ipam/prefixes/7/":
		reply(pfx)
	case "GET /api/ipam/prefixes/7/available-ips/":
		reply([]any{map[string]any{"address": fmt.Sprintf("10.0.20.%d/24", f.nextIP), "family": 4}})
	case "POST /api/ipam/prefixes/7/available-ips/":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		id := 100 + f.nextIP
		ip := map[string]any{"id": id, "address": fmt.Sprintf("10.0.20.%d/24", f.nextIP), "status": map[string]string{"value": in["status"]}, "dns_name": in["dns_name"], "description": in["description"]}
		f.ips[id] = ip
		f.nextIP++
		w.WriteHeader(201)
		reply(ip)
	case "GET /api/ipam/vlans/":
		reply(map[string]any{"count": 1, "results": []any{map[string]any{"id": 3, "vid": 20, "name": "servers", "status": map[string]string{"value": "active"}}}})
	default:
		var id int
		if _, err := fmt.Sscanf(r.URL.Path, "/api/ipam/ip-addresses/%d/", &id); err == nil && f.ips[id] != nil {
			if r.Method == "DELETE" {
				delete(f.ips, id)
				w.WriteHeader(204)
				return
			}
			reply(f.ips[id])
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, token string) (*Module, *fakeNB) {
	t.Helper()
	f := &fakeNB{ips: map[int]map[string]any{}, nextIP: 10, status: "active"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "t0k", "secret://v2": "nbt_abc.def", "secret://bad": "nope"}), "nb", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "nb", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNetBox(t *testing.T) {
	m, f := setup(t, "secret://t")
	if h := m.Health(context.Background(), "nb"); h.Status != "ok" || h.Message != "NetBox 4.1.3 · 1 sites" {
		t.Fatalf("%+v", h)
	}
	if v2, _ := setup(t, "secret://v2"); v2.Health(context.Background(), "nb").Status != "ok" {
		t.Fatal("v2 token")
	}
	for action, want := range map[string]string{
		"search":        `"vlans":[{`,
		"devices":       `"role":"Core switch"`,
		"device":        `"addresses":["10.0.20.2/24"]`,
		"ip_addresses":  `"assignedTo":"sw1 ether1"`,
		"prefixes":      `"vlan":"20 servers"`,
		"available_ips": `"available":["10.0.20.10/24"]`,
		"sites":         `"devices":12`,
		"vlans":         `"vid":20`,
	} {
		r, err := invoke(m, action, `{"q":"sw","name":"sw1","prefix":"10.0.20.0/24"}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
		if s := string(r.Output); strings.Contains(s, "hunter2") || strings.Contains(s, "s3cret") {
			t.Fatalf("%s leaked free-form data: %s", action, s)
		}
	}

	// Reserve: preview, act, undo.
	r, err := invoke(m, "reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"nas.lan"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Reserve 10.0.20.10/24 in 10.0.20.0/24 (reserved)" || len(f.ips) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "reserve_ip", `{"prefix_id":7,"dns_name":"nas.lan"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_ip_address" || len(f.ips) != 1 || !strings.Contains(string(r.Output), `"status":"reserved"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || p.Plan.Summary != "Delete 10.0.20.10/24 from NetBox" {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.ips) != 0 {
		t.Fatal(err)
	}

	// Device status: preview, act, undo.
	r, err = invoke(m, "set_device_status_live", `{"name":"sw1","status":"offline"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Set sw1 from active to offline" || f.status != "active" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_device_status_live", `{"name":"sw1","status":"offline"}`, false)
	if err != nil || f.status != "offline" || r.Undo == nil || r.Undo.Action != "set_device_status_live" || string(r.Undo.Input) != `{"id":42,"status":"active"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "active" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_device_status_live", `{"name":"nope","status":"offline"}`, false); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatal(err)
	}
}

func TestNetBoxValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"search", `{"q":""}`},
		{"search", `{"q":"a\nb"}`},
		{"devices", `{"site":"../../users"}`},
		{"devices", `{"status":"gone"}`},
		{"device", `{"id":-1}`},
		{"device", `{}`},
		{"ip_addresses", `{"parent":"10.0.0.0"}`},
		{"available_ips", `{"prefix":"10.0.20.0/24?x=1"}`},
		{"vlans", `{"vid":5000}`},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","status":"bogus"}`},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"bad name"}`},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","description":"x\ny"}`},
		{"delete_ip_address", `{"id":0}`},
		{"set_device_status", `{"id":42,"status":"exploded"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached NetBox: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://nb", Token: "plain"}, {URL: "nb.lan", Token: "secret://t"}, {URL: "https://u:p@nb", Token: "secret://t"}, {URL: "https://nb?x", Token: "secret://t"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "nb"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	f.redirect = other.URL
	if h := m.Health(context.Background(), "nb"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}

// reserve_ip (write) only reserves, with a plain host name nobody else
// uses; live statuses go through assign_ip (destructive). A device's status
// moves at write only between pre-production states.
func TestNetBoxWriteLimits(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in, want string }{
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"*.example.com"}`, "host name"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"*evil.example.com"}`, "host name"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"_acme-challenge.example.com"}`, "host name"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"x._domainkey.example.com"}`, "host name"},
		{"assign_ip", `{"prefix":"10.0.20.0/24","status":"active","dns_name":"*.example.com"}`, "host name"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","status":"active"}`, "assign_ip"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","status":"dhcp"}`, "assign_ip"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","status":"slaac"}`, "assign_ip"},
		{"assign_ip", `{"prefix":"10.0.20.0/24"}`, "status"},
		{"reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"mail.example.com"}`, "already the DNS name"},
		{"assign_ip", `{"prefix":"10.0.20.0/24","status":"active","dns_name":"MAIL.example.com."}`, "already the DNS name"},
		{"set_device_status", `{"name":"sw1","status":"offline"}`, "set_device_status_live"},
		{"set_device_status", `{"name":"sw1","status":"planned"}`, "set_device_status_live"},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v (want %q)", c.action, c.in, err, c.want)
		}
	}
	if len(f.ips) != 0 || f.status != "active" {
		t.Fatalf("%v %s", f.ips, f.status)
	}
	risk := map[string]sdk.Risk{}
	for _, a := range New().Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["reserve_ip"] != sdk.RiskWrite || risk["assign_ip"] != sdk.RiskDestructive || risk["set_device_status"] != sdk.RiskWrite || risk["set_device_status_live"] != sdk.RiskDestructive {
		t.Fatal(risk)
	}

	// A name nobody uses is reserved at write; taking it a second time is refused.
	if _, err := invoke(m, "reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"nas.lan"}`, false); err != nil || len(f.ips) != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "reserve_ip", `{"prefix":"10.0.20.0/24","dns_name":"nas.lan"}`, false); err == nil || !strings.Contains(err.Error(), "already the DNS name") {
		t.Fatal(err)
	}
	r, err := invoke(m, "assign_ip", `{"prefix":"10.0.20.0/24","status":"dhcp","dns_name":"printer.lan"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Assign 10.0.20.11/24 in 10.0.20.0/24 (dhcp)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "assign_ip", `{"prefix":"10.0.20.0/24","status":"dhcp","dns_name":"printer.lan"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_ip_address" || !strings.Contains(string(r.Output), `"status":"dhcp"`) {
		t.Fatalf("%+v %v", r, err)
	}

	// Pre-production moves are write, with an undo at write.
	f.mu.Lock()
	f.status = "planned"
	f.mu.Unlock()
	r, err = invoke(m, "set_device_status", `{"id":42,"status":"staged"}`, false)
	if err != nil || f.status != "staged" || r.Undo == nil || r.Undo.Action != "set_device_status" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "set_device_status", `{"id":42,"status":"active"}`, false); err == nil || f.status != "staged" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "set_device_status_live", `{"id":42,"status":"active"}`, false); err != nil || f.status != "active" {
		t.Fatal(err)
	}
}
