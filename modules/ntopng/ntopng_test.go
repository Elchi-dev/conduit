package ntopng

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

type fakeNtop struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeNtop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/lua/login.lua" {
		io.WriteString(w, `<html>login</html>`)
		return
	}
	if r.Header.Get("Authorization") != "Token tok-good" {
		http.Redirect(w, r, "/lua/login.lua?referer="+r.URL.Path, http.StatusFound)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	q := r.URL.Query()
	switch r.URL.Path {
	case "/ntop/lua/rest/v2/get/ntopng/interfaces.lua":
		io.WriteString(w, `{"rc":0,"rc_str":"OK","rsp":[{"ifid":2,"ifname":"eth1","name":"LAN"},{"ifid":0,"ifname":"eth0","name":"WAN"}]}`)
	case "/ntop/lua/rest/v2/get/interface/data.lua":
		io.WriteString(w, `{"rc":0,"rc_str":"OK","rsp":{"ifid":`+q.Get("ifid")+`,"throughput_bps":12345.5,"num_hosts":42,"num_local_hosts":20,"num_devices":30,"num_flows":900,"bytes":1000000,"packets":5000,"drops":0,"engaged_alerts":3,"alerted_flows":7,"speed":1000}}`)
	case "/ntop/lua/rest/v2/get/host/active.lua":
		if q.Get("ifid") != "0" || q.Get("sortColumn") != "traffic" {
			io.WriteString(w, `{"rc":-1,"rc_str":"INVALID_ARGUMENTS","rsp":{}}`)
			return
		}
		io.WriteString(w, `{"rc":0,"rc_str":"OK","rsp":{"data":[{"ip":"192.168.1.20","name":"laptop","bytes":{"total":5000,"sent":1000,"rcvd":4000},"thpt":{"bps":800},"num_flows":{"total":12},"score":10,"is_localhost":true,"country":"","mac":"AA:BB:CC:DD:EE:FF"},
			{"ip":"192.168.1.21","name":"nas","bytes":{"total":90000,"sent":80000,"rcvd":10000},"thpt":{"bps":5000},"num_flows":{"total":3},"score":0,"is_localhost":true}]}}`)
	case "/ntop/lua/rest/v2/get/host/alert/list.lua":
		if q.Get("status") != "engaged" && q.Get("status") != "historical" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"rc":0,"rc_str":"OK","rsp":[{"tstamp":{"value":"2026-11-04 10:00:00"},"severity":{"label":"Warning","value":4},"alert_id":{"label":"Blacklisted Host"},"score":100,"msg":{"descr":"Host contacted a blacklisted server token=abcdefghijklmnopqrstuvwxyz"},"ip":"192.168.1.20","name":"laptop"}]}`)
	case "/ntop/lua/rest/v2/get/system/alert/list.lua":
		io.WriteString(w, `{"rc":-2,"rc_str":"NOT_GRANTED","rsp":{}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNtop) {
	f := &fakeNtop{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/ntop", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nt": "tok-good", "secret://bad": "tok-bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in)})
}

func TestNtopng(t *testing.T) {
	m, _ := setup(t, "secret://nt")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "monitoring WAN, LAN" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"interfaces", `{}`, `"throughputBitsPerSecond":12345.5`},
		{"interfaces", `{}`, `"engagedAlerts":3`},
		{"top_hosts", `{}`, `"bytesReceived":4000`},
		{"top_hosts", `{"interface":0,"limit":5}`, `"throughputBitsPerSecond":5000`},
		{"alerts", `{}`, `"type":"Blacklisted Host"`},
		{"alerts", `{"engaged":false}`, `"status":"historical"`},
		{"alerts", `{}`, `"severity":"Warning"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "tok-good") || strings.Contains(out, "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	// Busiest first.
	r, _ := invoke(m, "top_hosts", `{}`)
	if strings.Index(string(r.Output), "nas") > strings.Index(string(r.Output), "laptop") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "alerts", `{"family":"system"}`); err == nil || !strings.Contains(err.Error(), "isn't allowed") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "top_hosts", `{"interface":7}`); err == nil || !strings.Contains(err.Error(), "no interface 7") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead || (a.Name != "interfaces" && !a.Sensitive) {
			t.Fatalf("%s: %s sensitive=%v", a.Name, a.Risk, a.Sensitive)
		}
	}
}

func TestNtopngValidation(t *testing.T) {
	m, f := setup(t, "secret://nt")
	for _, c := range []struct{ action, in string }{
		{"alerts", `{"family":"../../admin"}`},
		{"alerts", `{"family":"host/../x"}`},
		{"top_hosts", `{"interface":-5}`},
		{"top_hosts", `{"interface":"0; drop"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s", c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached ntopng: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://ntop:3000", Token: "plain"}, {URL: "ntop:3000", Token: "secret://nt"}, {URL: "http://u:p@ntop:3000", Token: "secret://nt"},
		{URL: "http://ntop:3000/?a=1", Token: "secret://nt"}, {URL: "http://ntop:3000/#a", Token: "secret://nt"}, {URL: "http://ntop:3000", Token: "secret://nt", Fingerprint: "x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "ntopng refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestNtopngRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://nt"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nt": "tok-good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
