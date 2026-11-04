package omada

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

const ctrl = "c0ffee1234567890"

type fakeOmada struct {
	mu       sync.Mutex
	seen     []string
	blocked  map[string]bool
	rebooted string
	tokens   int
	expire   bool
	ctrlIP   string // a client with the controller's address
}

func (f *fakeOmada) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(result string) { fmt.Fprintf(w, `{"errorCode":0,"msg":"Success.","result":%s}`, result) }
	if r.URL.Path == "/openapi/authorize/token" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if r.Method != http.MethodPost || r.URL.Query().Get("grant_type") != "client_credentials" || b["omadacId"] != ctrl || b["client_id"] != "app1" || b["client_secret"] != "s3cret" {
			io.WriteString(w, `{"errorCode":-44106,"msg":"The client id or client secret is invalid."}`)
			return
		}
		f.tokens++
		ok(fmt.Sprintf(`{"accessToken":"AT-%d","tokenType":"bearer","expiresIn":7200,"refreshToken":"RT-LEAKME"}`, f.tokens))
		return
	}
	if r.Header.Get("Authorization") != fmt.Sprintf("AccessToken=AT-%d", f.tokens) || f.expire {
		f.expire = false
		io.WriteString(w, `{"errorCode":-44112,"msg":"The access token has expired."}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	base := "/openapi/v1/" + ctrl
	switch {
	case r.Method == "GET" && r.URL.Path == base+"/sites":
		ok(`{"totalRows":1,"currentPage":1,"currentSize":100,"data":[{"siteId":"site1","name":"Home","region":"Germany","timeZone":"Europe/Berlin","scenario":"Home"}]}`)
	case r.Method == "GET" && r.URL.Path == base+"/sites/site1/devices":
		ok(`{"totalRows":2,"data":[{"mac":"AA-BB-CC-00-00-01","name":"Gateway","type":"gateway","model":"ER605","ip":"192.168.0.1","status":14,"statusCategory":1,"uptime":"3day(s) 2h","firmwareVersion":"2.2.3","cpuUtil":5,"memUtil":40,"clientNum":12},
			{"mac":"AA-BB-CC-00-00-02","name":"Hall AP","type":"ap","model":"EAP653","ip":"192.168.0.3","statusCategory":0,"clientNum":0}]}`)
	case r.Method == "GET" && r.URL.Path == base+"/sites/site1/clients":
		ip2 := "192.168.0.51"
		if f.ctrlIP != "" {
			ip2 = f.ctrlIP
		}
		ok(fmt.Sprintf(`{"totalRows":2,"data":[{"mac":"11-22-33-44-55-66","name":"Laptop","hostName":"laptop","ip":"192.168.0.50","wireless":true,"ssid":"Home","apName":"Hall AP","signalLevel":80,"uptime":100,"trafficDown":1000,"trafficUp":200,"block":%t},
			{"mac":"11-22-33-44-55-77","name":"NAS","hostName":"nas","ip":%q,"wireless":false,"switchName":"SW","port":3,"block":false}]}`, f.blocked["11-22-33-44-55-66"], ip2))
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, base+"/sites/site1/devices/") && strings.HasSuffix(r.URL.Path, "/reboot"):
		f.rebooted = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, base+"/sites/site1/devices/"), "/reboot")
		ok(`null`)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, base+"/sites/site1/clients/"):
		rest := strings.TrimPrefix(r.URL.Path, base+"/sites/site1/clients/")
		mac, op, _ := strings.Cut(rest, "/")
		f.blocked[mac] = op == "block"
		ok(`null`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errorCode":-1,"msg":"not found"}`)
	}
}

func setup(t *testing.T, sec string) (*Module, *fakeOmada) {
	f := &fakeOmada{blocked: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, ControllerID: ctrl, ClientID: "app1", ClientSecret: sec})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://om": "s3cret", "secret://bad": "wrong"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOmada(t *testing.T) {
	m, f := setup(t, "secret://om")
	if h := m.Health(context.Background(), "o"); h.Status != "degraded" || h.Message != "Home: 2 devices, 1 not connected" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"sites", `{}`, `"timeZone":"Europe/Berlin"`},
		{"devices", `{}`, `"status":"disconnected"`},
		{"devices", `{"site":"home"}`, `"model":"ER605"`},
		{"clients", `{}`, `"accessPoint":"Hall AP"`},
		{"clients", `{"site":"site1"}`, `"switch":"SW"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "s3cret") || strings.Contains(out, "AT-") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if _, err := invoke(m, "devices", `{"site":"Office"}`, false); err == nil || !strings.Contains(err.Error(), "no site") {
		t.Fatal(err)
	}

	// Block a client: preview, real, undo.
	r, err := invoke(m, "block_client", `{"mac":"11:22:33:44:55:66"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Block client Laptop (11-22-33-44-55-66) in Home" || f.blocked["11-22-33-44-55-66"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "block_client", `{"mac":"11:22:33:44:55:66"}`, false)
	if err != nil || !f.blocked["11-22-33-44-55-66"] || r.Undo == nil || r.Undo.Action != "unblock_client" || string(r.Undo.Input) != `{"mac":"11-22-33-44-55-66","site":"site1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "block_client", `{"mac":"11-22-33-44-55-66"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.blocked["11-22-33-44-55-66"] {
		t.Fatal(err)
	}

	// An expired token is fetched again once.
	tokens := f.tokens
	f.expire = true
	if _, err := invoke(m, "sites", `{}`, false); err != nil || f.tokens != tokens+1 {
		t.Fatal(err, f.tokens)
	}

	r, err = invoke(m, "reboot_device", `{"mac":"aa:bb:cc:00:00:01"}`, true)
	if err != nil || r.Plan == nil || f.rebooted != "" || !strings.Contains(r.Plan.Summary, "gateway Gateway (ER605") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reboot_device", `{"mac":"aa:bb:cc:00:00:01"}`, false); err != nil || f.rebooted != "AA-BB-CC-00-00-01" {
		t.Fatal(err, f.rebooted)
	}
	if _, err := invoke(m, "reboot_device", `{"mac":"aa:bb:cc:00:00:09"}`, false); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "reboot_device" || a.Name == "block_client") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		if a.Name == "clients" && !a.Sensitive {
			t.Fatal("clients isn't sensitive")
		}
	}
}

func TestOmadaKeepsController(t *testing.T) {
	m, f := setup(t, "secret://om")
	f.ctrlIP = "127.0.0.1"
	if _, err := invoke(m, "block_client", `{"mac":"11-22-33-44-55-77"}`, false); err == nil || !strings.Contains(err.Error(), "cut Conduit off") || f.blocked["11-22-33-44-55-77"] {
		t.Fatal(err)
	}
}

func TestOmadaValidation(t *testing.T) {
	m, f := setup(t, "secret://om")
	for _, c := range []struct{ action, in string }{
		{"block_client", `{}`},
		{"block_client", `{"mac":"11-22-33-44-55"}`},
		{"block_client", `{"mac":"11-22-33-44-55-66/../../x"}`},
		{"unblock_client", `{"mac":"zz-22-33-44-55-66"}`},
		{"reboot_device", `{"mac":"aa:bb:cc:00:00:01?x=1"}`},
		{"devices", `{"site":"../sites"}`},
		{"clients", `{"site":"a/b"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.tokens != 0 {
		t.Fatalf("invalid input reached the controller: %v", f.seen)
	}
	good := Config{URL: "https://omada.example.com:8043", ControllerID: ctrl, ClientID: "app1", ClientSecret: "secret://om"}
	for _, mut := range []func(*Config){
		func(c *Config) { c.ClientSecret = "s3cret" },
		func(c *Config) { c.URL = "omada.example.com" },
		func(c *Config) { c.URL = "https://u:p@omada.example.com" },
		func(c *Config) { c.URL = "https://omada.example.com/?x=1" },
		func(c *Config) { c.URL = "https://omada.example.com/#f" },
		func(c *Config) { c.ControllerID = "../x" },
		func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.Site = "a/b" },
		func(c *Config) { c.Fingerprint = "zz" },
	} {
		c := good
		mut(&c)
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "refused the client id and secret") || strings.Contains(h.Message, "wrong") {
		t.Fatalf("%+v", h)
	}
}

func TestOmadaRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, ControllerID: ctrl, ClientID: "app1", ClientSecret: "secret://om"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://om": "s3cret"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// A controller set up by name is checked by what the name resolves to.
func TestOmadaKeepsControllerByName(t *testing.T) {
	f := &fakeOmada{blocked: map[string]bool{}, ctrlIP: "127.0.0.1"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), ControllerID: ctrl, ClientID: "app1", ClientSecret: "secret://om"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://om": "s3cret"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "block_client", `{"mac":"11-22-33-44-55-77"}`, false); err == nil || !strings.Contains(err.Error(), "cut Conduit off") || f.blocked["11-22-33-44-55-77"] {
		t.Fatal(err)
	}
}
