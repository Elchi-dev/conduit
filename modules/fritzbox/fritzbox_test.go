package fritzbox

import (
	"context"
	"crypto/md5" //nolint:gosec // digest authentication
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const desc = `<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
<serviceList>
<service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service>
<service><serviceType>urn:dslforum-org:service:Hosts:1</serviceType><controlURL>/upnp/control/hosts</controlURL></service>
<service><serviceType>urn:dslforum-org:service:X_AVM-DE_Evil:1</serviceType><controlURL>//evil.example.com/x</controlURL></service>
</serviceList>
<deviceList>
<device><serviceList>
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType><controlURL>/upnp/control/wlanconfig1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:2</serviceType><controlURL>/upnp/control/wlanconfig2</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WLANConfiguration:3</serviceType><controlURL>/upnp/control/wlanconfig3</controlURL></service>
</serviceList></device>
<device><serviceList>
<service><serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/wancommonifconfig1</controlURL></service>
</serviceList><deviceList><device><serviceList>
<service><serviceType>urn:dslforum-org:service:WANPPPConnection:1</serviceType><controlURL>/upnp/control/wanpppconn1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control/wanipconnection1</controlURL></service>
</serviceList></device></deviceList></device>
</deviceList></device></root>`

var paramRe = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^,\s]+))`)

type fakeFritz struct {
	mu          sync.Mutex
	seen        []string
	guest       bool
	terminated  bool
	noExtInfo   bool
	external    string
	bodies      []string
	nonce       int
	challenges  int
	hostListHit bool
}

func (f *fakeFritz) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Digest ") {
		return false
	}
	p := map[string]string{}
	for _, m := range paramRe.FindAllStringSubmatch(h, -1) {
		p[m[1]] = m[2] + m[3]
	}
	sum := func(s string) string { x := md5.Sum([]byte(s)); return hex.EncodeToString(x[:]) }
	ha1 := sum("conduit:F!Box SOAP-Auth:pa\"ss")
	ha2 := sum(r.Method + ":" + p["uri"])
	want := sum(ha1 + ":" + p["nonce"] + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + ha2)
	return p["username"] == "conduit" && p["nonce"] == fmt.Sprintf("N%d", f.nonce) && p["uri"] == r.URL.RequestURI() && p["response"] == want && p["qop"] == "auth"
}

func (f *fakeFritz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/tr64desc.xml" {
		io.WriteString(w, desc)
		return
	}
	if !f.authorized(r) {
		f.nonce++
		f.challenges++
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="F!Box SOAP-Auth", nonce="N%d", algorithm=MD5, qop="auth"`, f.nonce))
		w.WriteHeader(401)
		return
	}
	if r.URL.Path == "/devicehostlist.lua" {
		f.hostListHit = r.URL.Query().Get("sid") == "0123456789abcdef"
		io.WriteString(w, `<List><Item><Index>1</Index><IPAddress>192.168.178.20</IPAddress><MACAddress>AA:BB:CC:DD:EE:FF</MACAddress><Active>1</Active><HostName>laptop</HostName><InterfaceType>802.11</InterfaceType><X_AVM-DE_Speed>866</X_AVM-DE_Speed></Item>
			<Item><Index>2</Index><IPAddress>192.168.178.21</IPAddress><MACAddress>AA:BB:CC:DD:EE:01</MACAddress><Active>0</Active><HostName>old-phone</HostName><InterfaceType>802.11</InterfaceType></Item></List>`)
		return
	}
	action := r.Header.Get("SOAPAction")
	f.seen = append(f.seen, r.URL.Path+" "+action)
	f.bodies = append(f.bodies, string(body))
	resp := func(args string) {
		name := action[strings.Index(action, "#")+1:]
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:%sResponse xmlns:u="x">%s</u:%sResponse></s:Body></s:Envelope>`, name, args, name)
	}
	fault := func(code int, d string) {
		w.WriteHeader(500)
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, d)
	}
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	switch action {
	case "urn:dslforum-org:service:DeviceInfo:1#GetInfo":
		resp(`<NewManufacturerName>AVM</NewManufacturerName><NewModelName>FRITZ!Box 7590</NewModelName><NewSerialNumber>SERIAL-LEAKME</NewSerialNumber><NewProvisioningCode>PROV-LEAKME</NewProvisioningCode><NewSoftwareVersion>154.07.57</NewSoftwareVersion><NewHardwareVersion>FRITZ!Box 7590</NewHardwareVersion><NewUpTime>90000</NewUpTime><NewDeviceLog>LOG-LEAKME</NewDeviceLog>`)
	case "urn:dslforum-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties":
		resp(`<NewWANAccessType>DSL</NewWANAccessType><NewLayer1UpstreamMaxBitRate>40000000</NewLayer1UpstreamMaxBitRate><NewLayer1DownstreamMaxBitRate>100000000</NewLayer1DownstreamMaxBitRate><NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>`)
	case "urn:dslforum-org:service:WANPPPConnection:1#GetStatusInfo":
		resp(`<NewConnectionStatus>Connected</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>3600</NewUptime>`)
	case "urn:dslforum-org:service:WANPPPConnection:1#GetInfo":
		resp(`<NewUserName>PPPOE-LEAKME</NewUserName>`)
	case "urn:dslforum-org:service:WANIPConnection:1#GetStatusInfo":
		resp(`<NewConnectionStatus>Unconfigured</NewConnectionStatus><NewUptime>0</NewUptime>`)
	case "urn:dslforum-org:service:WANPPPConnection:1#GetExternalIPAddress":
		resp(`<NewExternalIPAddress>` + f.external + `</NewExternalIPAddress>`)
	case "urn:dslforum-org:service:WANPPPConnection:1#ForceTermination":
		f.terminated = true
		resp(``)
	case "urn:dslforum-org:service:Hosts:1#X_AVM-DE_GetHostListPath":
		resp(`<NewX_AVM-DE_HostListPath>/devicehostlist.lua?sid=0123456789abcdef</NewX_AVM-DE_HostListPath>`)
	case "urn:dslforum-org:service:WLANConfiguration:1#GetInfo", "urn:dslforum-org:service:WLANConfiguration:2#GetInfo":
		n := action[len("urn:dslforum-org:service:WLANConfiguration:")]
		resp(fmt.Sprintf(`<NewEnable>1</NewEnable><NewStatus>Up</NewStatus><NewSSID>Home%c</NewSSID><NewChannel>6</NewChannel><NewStandard>ax</NewStandard><NewBeaconType>11i</NewBeaconType><NewKeyPassphrase>WIFI-LEAKME</NewKeyPassphrase>`, n))
	case "urn:dslforum-org:service:WLANConfiguration:3#GetInfo":
		resp(fmt.Sprintf(`<NewEnable>%d</NewEnable><NewStatus>Disabled</NewStatus><NewSSID>Guests &amp; friends</NewSSID><NewChannel>6</NewChannel><NewStandard>ax</NewStandard><NewBeaconType>None</NewBeaconType>`, b(f.guest)))
	case "urn:dslforum-org:service:WLANConfiguration:1#X_AVM-DE_GetWLANExtInfo", "urn:dslforum-org:service:WLANConfiguration:2#X_AVM-DE_GetWLANExtInfo", "urn:dslforum-org:service:WLANConfiguration:3#X_AVM-DE_GetWLANExtInfo":
		if f.noExtInfo {
			fault(401, "Invalid Action")
			return
		}
		t := "normal"
		if strings.Contains(action, ":3#") {
			t = "guest"
		}
		resp(`<NewX_AVM-DE_APType>` + t + `</NewX_AVM-DE_APType>`)
	case "urn:dslforum-org:service:WLANConfiguration:3#SetEnable":
		var env struct {
			Enable string `xml:"Body>SetEnable>NewEnable"`
		}
		if err := xml.Unmarshal(body, &env); err != nil {
			fault(402, "Invalid Args")
			return
		}
		f.guest = env.Enable == "1"
		resp(``)
	default:
		fault(401, "Invalid Action")
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeFritz) {
	f := &fakeFritz{external: "203.0.113.7"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "conduit", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fb": `pa"ss`, "secret://bad": "wrong-pass"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFritzBox(t *testing.T) {
	m, f := setup(t, "secret://fb")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "FRITZ!Box 7590 · FRITZ!OS 154.07.57 · up 25h0m0s" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"device_info", `{}`, `"model":"FRITZ!Box 7590"`},
		{"wan_status", `{}`, `"connection":"ppp"`},
		{"wan_status", `{}`, `"externalIPv4":"203.0.113.7"`},
		{"wan_status", `{}`, `"accessType":"DSL"`},
		{"hosts", `{}`, `"speedMbps":866`},
		{"hosts", `{"all":true}`, `"name":"old-phone"`},
		{"wifi", `{}`, `"ssid":"Guests ` + "\\" + `u0026 friends"`},
		{"wifi", `{}`, `"security":"WPA2"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "pa\\\"ss") || strings.Contains(out, "0123456789abcdef") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if !f.hostListHit {
		t.Fatal("host list not read")
	}
	if r, _ := invoke(m, "hosts", `{}`, false); strings.Contains(string(r.Output), "old-phone") {
		t.Fatal(string(r.Output))
	}
	for _, s := range f.seen {
		if strings.Contains(s, "GetSecurityKeys") || strings.Contains(s, "WANPPPConnection:1#GetInfo") {
			t.Fatalf("asked for credentials: %s", s)
		}
	}
	// The challenge is answered once and reused.
	if f.challenges != 1 {
		t.Fatalf("%d challenges", f.challenges)
	}

	// Guest network on (it's open: the preview says so), undo turns it off.
	r, err := invoke(m, "guest_wifi_on", `{}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Turn on the guest network Guests & friends (open): it's open") || f.guest {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "guest_wifi_on", `{}`, false)
	if err != nil || !f.guest || r.Undo == nil || r.Undo.Action != "guest_wifi_off" {
		t.Fatalf("%+v %v", r, err)
	}
	last := f.bodies[len(f.bodies)-1]
	if !strings.Contains(last, `<u:SetEnable xmlns:u="urn:dslforum-org:service:WLANConfiguration:3"><NewEnable>1</NewEnable></u:SetEnable>`) {
		t.Fatal(last)
	}
	if r, err := invoke(m, "guest_wifi_on", `{}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.guest {
		t.Fatal(err)
	}
	// Without the extended info, the last network counts as the guest one.
	f.noExtInfo = true
	if r, err := invoke(m, "guest_wifi_on", `{}`, true); err != nil || !strings.Contains(r.Plan.Summary, "Guests & friends") {
		t.Fatal(err)
	}

	r, err = invoke(m, "reconnect", `{}`, true)
	if err != nil || r.Plan == nil || f.terminated || !strings.Contains(r.Plan.Summary, "ppp, Connected, up 1h0m0s") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reconnect", `{}`, false); err != nil || !f.terminated {
		t.Fatal(err)
	}
	// Reached over its public address: refused.
	f.terminated, f.external = false, "127.0.0.1"
	if _, err := invoke(m, "reconnect", `{}`, false); err == nil || !strings.Contains(err.Error(), "over the internet") || f.terminated {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "reconnect" || a.Name == "guest_wifi_off") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		if a.Name == "hosts" && !a.Sensitive {
			t.Fatal("hosts isn't sensitive")
		}
	}
}

func TestFritzBoxEnvelopeEscapes(t *testing.T) {
	b, err := envelope("urn:x:1", "SetX", []arg{{"NewValue", `</NewValue><Evil>"&'`}})
	if err != nil || !strings.Contains(string(b), `<NewValue>&lt;/NewValue&gt;&lt;Evil&gt;&#34;&amp;&#39;</NewValue>`) {
		t.Fatalf("%s %v", b, err)
	}
	for _, bad := range []string{"Set X", "<x>", "a/b"} {
		if _, err := envelope("urn:x:1", bad, nil); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, h := range []string{
		`Basic realm="x"`,
		`Digest realm="x\"y", nonce="n"`,
		`Digest realm="x", nonce="a` + "\r\n" + `b"`,
		`Digest realm="x", nonce="n", algorithm=MD5-sess`,
		`Digest realm="x", nonce="n", qop="auth-int"`,
		`Digest realm="x"`,
	} {
		if _, err := parseChallenge(h); err == nil {
			t.Fatalf("accepted %q", h)
		}
	}
}

func TestFritzBoxValidation(t *testing.T) {
	m, f := setup(t, "secret://fb")
	if _, err := invoke(m, "hosts", `{"all":"yes"}`, false); err == nil {
		t.Fatal("accepted a string for all")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the FRITZ!Box: %v", f.seen)
	}
	for _, c := range []Config{
		{Username: "conduit", Password: "plain"},
		{URL: "fritz.box:49000", Username: "conduit", Password: "secret://fb"},
		{URL: "http://u:p@fritz.box:49000", Username: "conduit", Password: "secret://fb"},
		{URL: "http://fritz.box:49000/?x=1", Username: "conduit", Password: "secret://fb"},
		{URL: "http://fritz.box:49000/#x", Username: "conduit", Password: "secret://fb"},
		{URL: "http://fritz.box:49000/upnp", Username: "conduit", Password: "secret://fb"},
		{Username: `con"duit`, Password: "secret://fb"},
		{Username: "conduit", Password: "secret://fb", Fingerprint: "xx"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "f")
	if h.Status != "down" || h.Message != "the FRITZ!Box refused the user name and password" || strings.Contains(h.Message, "wrong-pass") {
		t.Fatalf("%+v", h)
	}
}

func TestFritzBoxRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.URL.Path + r.Header.Get("Authorization")
		io.WriteString(w, desc)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "conduit", Password: "secret://fb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fb": "pw"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
