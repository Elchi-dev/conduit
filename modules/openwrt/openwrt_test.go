package openwrt

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

const sess = "0123456789abcdef0123456789abcdef"

type fakeWrt struct {
	mu       sync.Mutex
	seen     []string
	up       map[string]bool
	rebooted bool
	logins   int
	expire   bool   // refuse the next call with the session, like an expired one
	wwanIP   string // the address on the wireless uplink
	noLuci   bool
}

func (f *fakeWrt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/ubus" {
		w.WriteHeader(404)
		return
	}
	var req struct {
		Params []json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Params) != 4 {
		w.WriteHeader(400)
		return
	}
	var session, object, method string
	json.Unmarshal(req.Params[0], &session)
	json.Unmarshal(req.Params[1], &object)
	json.Unmarshal(req.Params[2], &method)
	f.seen = append(f.seen, object+" "+method+" "+string(req.Params[3]))
	result := func(code int, data string) {
		if data == "" {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[%d]}`, code)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[%d,%s]}`, code, data)
	}
	if object == "session" && method == "login" {
		var a map[string]string
		json.Unmarshal(req.Params[3], &a)
		if session != noSession || a["username"] != "root" || a["password"] != "hunter2" {
			result(6, "")
			return
		}
		f.logins++
		result(0, `{"ubus_rpc_session":"`+sess+`","timeout":300,"expires":300}`)
		return
	}
	if session != sess || f.expire {
		f.expire = false
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Access denied"}}`)
		return
	}
	switch object + " " + method {
	case "system board":
		result(0, `{"kernel":"5.15.150","hostname":"gw","system":"ARMv7","model":"Linksys E8450","board_name":"linksys,e8450","release":{"distribution":"OpenWrt","version":"23.05.3","revision":"r23809","target":"mediatek/mt7622","description":"OpenWrt 23.05.3 r23809"}}`)
	case "system info":
		result(0, `{"localtime":1730700000,"uptime":3600,"load":[65536,32768,0],"memory":{"total":500000000,"free":200000000,"available":300000000,"buffered":1000}}`)
	case "network.interface dump":
		wwan := ""
		if f.wwanIP != "" {
			wwan = `,{"interface":"wwan","up":true,"proto":"dhcp","device":"phy0-sta0","l3_device":"phy0-sta0","ipv4-address":[{"address":"` + f.wwanIP + `","mask":24}]}`
		}
		result(0, `{"interface":[{"interface":"lan","up":true,"pending":false,"available":true,"proto":"static","device":"br-lan","l3_device":"br-lan","uptime":3500,"ipv4-address":[{"address":"192.168.1.1","mask":24}],"ipv6-address":[],"dns-server":[]},{"interface":"wan","up":true,"proto":"pppoe","device":"wan","l3_device":"pppoe-wan","ipv4-address":[{"address":"203.0.113.9","mask":32}],"dns-server":["1.1.1.1"]}`+wwan+`]}`)
	case "network.wireless status":
		result(0, fmt.Sprintf(`{"radio0":{"up":%t,"pending":false,"autostart":true,"disabled":false,"config":{"band":"2g","channel":"6","htmode":"HE20","country":"DE"},"interfaces":[{"section":"default_radio0","ifname":"phy0-ap0","config":{"mode":"ap","ssid":"Home","encryption":"sae-mixed","key":"WIFI-LEAKME-KEY","network":["lan"]}},{"section":"wwan","ifname":"phy0-sta0","config":{"mode":"sta","ssid":"Upstream","encryption":"psk2","key":"STA-LEAKME","network":["wwan"]}}]},
			"radio1":{"up":%t,"pending":false,"autostart":true,"disabled":false,"config":{"band":"5g","channel":36,"htmode":"HE80"},"interfaces":[{"section":"default_radio1","ifname":"phy1-ap0","config":{"mode":"ap","ssid":"Home-5G","encryption":"psk2","key":"WIFI-LEAKME-5","network":["lan"]}}]},
			"radio2":{"up":false,"disabled":true,"config":{"band":"6g","disabled":true},"interfaces":[]}}`, f.up["radio0"], f.up["radio1"]))
	case "network.wireless up", "network.wireless down":
		var a map[string]string
		json.Unmarshal(req.Params[3], &a)
		f.up[a["device"]] = method == "up"
		result(0, "")
	case "luci-rpc getDHCPLeases":
		if f.noLuci {
			result(4, "")
			return
		}
		result(0, `{"dhcp_leases":[{"expires":3000,"hostname":"laptop","macaddr":"AA:BB:CC:DD:EE:FF","ipaddr":"192.168.1.20"}],"dhcp6_leases":[{"expires":2000,"hostname":"phone","duid":"0001000126","ip6addr":"fd00::20"}]}`)
	case "file read":
		result(0, `{"data":"1730703600 aa:bb:cc:dd:ee:01 192.168.1.30 tv 01:aa\n1730703600 aa:bb:cc:dd:ee:02 192.168.1.31 * *\n"}`)
	case "system reboot":
		f.rebooted = true
		result(0, "")
	default:
		result(3, "")
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeWrt, *httptest.Server) {
	f := &fakeWrt{up: map[string]bool{"radio0": true, "radio1": false}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "root", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://wrt": "hunter2", "secret://bad": "nope"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, srv
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOpenWrt(t *testing.T) {
	m, f, _ := setup(t, "secret://wrt")
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || !strings.HasPrefix(h.Message, "gw · OpenWrt 23.05.3 r23809 · up 1h0m0s") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"system", `"model":"Linksys E8450"`},
		{"system", `"load":["1.00","0.50","0.00"]`},
		{"interfaces", `"ipv4":["192.168.1.1/24"]`},
		{"interfaces", `"device":"pppoe-wan"`},
		{"wireless", `"ssid":"Home-5G"`},
		{"wireless", `"encryption":"sae-mixed"`},
		{"leases", `"hostname":"laptop"`},
		{"leases", `"address":"fd00::20"`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "hunter2") || strings.Contains(out, sess) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	f.noLuci = true
	if r, err := invoke(m, "leases", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"hostname":"tv"`) || strings.Contains(string(r.Output), `"*"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Bring radio1 up: preview, real, undo.
	r, err := invoke(m, "wifi_up", `{"radio":"radio1"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Bring up radio radio1 (Home-5G)" || f.up["radio1"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "wifi_up", `{"radio":"radio1"}`, false)
	if err != nil || !f.up["radio1"] || r.Undo == nil || r.Undo.Action != "wifi_down" || string(r.Undo.Input) != `{"radio":"radio1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.up["radio1"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "wifi_down", `{"radio":"radio1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	if _, err := invoke(m, "wifi_up", `{"radio":"radio2"}`, false); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "wifi_up", `{"radio":"radio9"}`, false); err == nil || !strings.Contains(err.Error(), "no radio") {
		t.Fatal(err)
	}

	// An expired session signs in again once.
	logins := f.logins
	f.expire = true
	if _, err := invoke(m, "system", `{}`, false); err != nil || f.logins != logins+1 {
		t.Fatal(err, f.logins)
	}

	r, err = invoke(m, "reboot", `{}`, true)
	if err != nil || r.Plan == nil || f.rebooted || !strings.Contains(r.Plan.Summary, "gw (OpenWrt 23.05.3 r23809)") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reboot", `{}`, false); err != nil || !f.rebooted {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "reboot" || a.Name == "wifi_down") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		if a.Name == "leases" && !a.Sensitive {
			t.Fatal("leases isn't sensitive")
		}
	}
}

// A router reached over its wireless uplink refuses to bring that radio down.
func TestOpenWrtKeepsManagementRadio(t *testing.T) {
	f := &fakeWrt{up: map[string]bool{"radio0": true, "radio1": true}, wwanIP: "127.0.0.1"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "root", Password: "secret://wrt"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://wrt": "hunter2"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "wifi_down", `{"radio":"radio0"}`, false); err == nil || !strings.Contains(err.Error(), "cut off") || !f.up["radio0"] {
		t.Fatal(err)
	}
	if _, err := invoke(m, "wifi_down", `{"radio":"radio1"}`, false); err != nil || f.up["radio1"] {
		t.Fatal(err)
	}
}

func TestOpenWrtValidation(t *testing.T) {
	m, f, _ := setup(t, "secret://wrt")
	for _, in := range []string{`{}`, `{"radio":"radio0; reboot"}`, `{"radio":"../x"}`, `{"radio":"a b"}`, `{"radio":"` + strings.Repeat("r", 40) + `"}`} {
		if _, err := invoke(m, "wifi_down", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the router: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://192.168.1.1", Username: "root", Password: "hunter2"},
		{URL: "192.168.1.1", Username: "root", Password: "secret://wrt"},
		{URL: "https://root:pw@192.168.1.1", Username: "root", Password: "secret://wrt"},
		{URL: "https://192.168.1.1/?x=1", Username: "root", Password: "secret://wrt"},
		{URL: "https://192.168.1.1/#x", Username: "root", Password: "secret://wrt"},
		{URL: "https://192.168.1.1/cgi-bin/luci", Username: "root", Password: "secret://wrt"},
		{URL: "https://192.168.1.1", Username: "ro ot", Password: "secret://wrt"},
		{URL: "https://192.168.1.1", Username: "root", Password: "secret://wrt", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "w")
	if h.Status != "down" || h.Message != "OpenWrt refused the user name and password" || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestOpenWrtRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "root", Password: "secret://wrt"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://wrt": "hunter2"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "hunter2") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
