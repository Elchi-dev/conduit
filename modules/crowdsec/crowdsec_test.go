package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeLAPI struct {
	mu        sync.Mutex
	seen      []string
	logins    int
	decisions map[int64][3]string // id → value, scope, duration
	simulated map[int64]bool
	next      int64
}

func (f *fakeLAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/v1/watchers/login" {
		var b map[string]any
		json.Unmarshal(body, &b)
		if b["machine_id"] != "conduit" || b["password"] != "pw-good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"code":401,"message":"incorrect Username or Password"}`)
			return
		}
		f.logins++
		io.WriteString(w, `{"code":200,"expire":"2099-01-01T00:00:00Z","token":"jwt-token-value"}`)
		return
	}
	bouncer := r.URL.Path == "/v1/decisions" && r.Method == "GET"
	if bouncer && r.Header.Get("X-Api-Key") != "bouncer-good" || !bouncer && r.Header.Get("Authorization") != "Bearer jwt-token-value" {
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"access forbidden"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	decs := func() string {
		var parts []string
		for id, d := range f.decisions {
			parts = append(parts, fmt.Sprintf(`{"id":%d,"origin":"cscli","type":"ban","scope":%q,"value":%q,"duration":%q,"scenario":"manual","simulated":%t}`, id, d[1], d[0], d[2], f.simulated[id]))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/decisions":
		io.WriteString(w, decs())
	case r.Method == "GET" && r.URL.Path == "/v1/alerts":
		fmt.Fprintf(w, `[{"id":7,"scenario":"crowdsecurity/http-probing","machine_id":"host1","events_count":11,"start_at":"2026-11-04T10:00:00Z","stop_at":"2026-11-04T10:00:03Z",
			"source":{"scope":"Ip","value":"198.51.100.9","ip":"198.51.100.9","cn":"NL","as_name":"Example AS"},"decisions":%s,
			"events":[{"timestamp":"t","meta":[{"key":"http_path","value":"/login?password=LEAKMEsecretvalue123"}]}]}]`, decs())
	case r.Method == "GET" && r.URL.Path == "/v1/alerts/7":
		io.WriteString(w, `{"id":7,"scenario":"crowdsecurity/http-probing","source":{"scope":"Ip","value":"198.51.100.9"},"meta":[{"key":"target_fqdn","value":"intranet.corp"}],
			"events":[{"timestamp":"2026-11-04T10:00:00Z","meta":[{"key":"http_path","value":"/x?token=LEAKMEsecretvalue123"},{"key":"user_agent","value":"evil\u0000\nagent`+strings.Repeat("A", 900)+`"}]}]}`)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/alerts/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/alerts/")
		fmt.Fprintf(w, `{"id":%s,"scenario":"x","decisions":[{"id":%s,"type":"ban","scope":"Ip","value":"203.0.113.7","duration":"4h"}]}`, id, id)
	case r.Method == "POST" && r.URL.Path == "/v1/alerts":
		var b []struct {
			Decisions []struct {
				Value    string `json:"value"`
				Scope    string `json:"scope"`
				Duration string `json:"duration"`
			} `json:"decisions"`
		}
		json.Unmarshal(body, &b)
		f.next++
		d := b[0].Decisions[0]
		f.decisions[f.next] = [3]string{d.Value, d.Scope, d.Duration}
		fmt.Fprintf(w, `["%d"]`, f.next)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/decisions/"):
		var id int64
		fmt.Sscan(strings.TrimPrefix(r.URL.Path, "/v1/decisions/"), &id)
		if _, ok := f.decisions[id]; !ok {
			io.WriteString(w, `{"nbDeleted":"0"}`)
			return
		}
		delete(f.decisions, id)
		io.WriteString(w, `{"nbDeleted":"1"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

var secrets = map[string]string{"secret://pw": "pw-good", "secret://bad": "pw-bad", "secret://bk": "bouncer-good", "secret://bkbad": "bouncer-bad"}

func setup(t *testing.T, cfg Config) (*Module, *fakeLAPI) {
	f := &fakeLAPI{decisions: map[int64][3]string{}, simulated: map[int64]bool{}, next: 100}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Local = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.200"), netip.MustParseAddr("127.0.0.1")}
	}
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCrowdSec(t *testing.T) {
	m, f := setup(t, Config{Machine: "conduit", Password: "secret://pw", BouncerKey: "secret://bk", Protect: []string{"198.51.100.0/24"}})
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "machine conduit signed in, bouncer key accepted" {
		t.Fatalf("%+v", h)
	}
	// Ban: preview, real, already banned, undo.
	r, err := invoke(m, "ban", `{"ip":"203.0.113.7","duration":"4h","reason":"brute force"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Ban 203.0.113.7 for 4h0m0s" || len(f.decisions) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "ban", `{"ip":"203.0.113.7","duration":"4h","reason":"brute force"}`, false)
	if err != nil || len(f.decisions) != 1 || r.Undo == nil || r.Undo.Action != "delete_decision" || string(r.Undo.Input) != `{"decision":101}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "ban", `{"ip":"203.0.113.7"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.decisions) != 1 {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "decisions", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"value":"203.0.113.7"`) || !strings.Contains(string(r.Output), `"total":1`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Deleting it offers a ban for the time left as its undo.
	r, err = invoke(m, "delete_decision", `{"decision":101}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "203.0.113.7") || len(f.decisions) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_decision", `{"decision":101}`, false)
	if err != nil || len(f.decisions) != 0 || r.Undo == nil || r.Undo.Action != "ban" || !strings.Contains(string(r.Undo.Input), `"ip":"203.0.113.7"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "delete_decision", `{"decision":101}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// A range.
	if r, err := invoke(m, "ban", `{"ip":"2001:db8:1234::/48","duration":"30m"}`, false); err != nil || !strings.Contains(string(r.Output), `"scope":"Range"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Alerts leave event details out; alert shows them redacted and clipped.
	r, err = invoke(m, "alerts", `{"since":"24h"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"country":"NL"`) || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "http_path") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "alert", `{"id":7}`, false)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, "intranet.corp") || strings.Contains(out, "LEAKME") || strings.Contains(out, `\u0000`) || len(out) > 2000 {
		t.Fatalf("%s %v", out, err)
	}
	if strings.Contains(out, "jwt-token-value") || strings.Contains(out, "bouncer-good") {
		t.Fatal("secret in output")
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	var sens bool
	for _, a := range m.Manifest().Actions {
		if (a.Name == "ban" || a.Name == "delete_decision") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		if a.Name == "alert" {
			sens = a.Sensitive
		}
	}
	if !sens {
		t.Fatal("alert isn't sensitive")
	}
}

func TestCrowdSecBanGuards(t *testing.T) {
	m, f := setup(t, Config{Machine: "conduit", Password: "secret://pw", Protect: []string{"198.51.100.0/24"}})
	for _, in := range []string{
		`{"ip":"203.0.113.200"}`, // this machine
		`{"ip":"203.0.0.0/16"}`,  // covers this machine
		`{"ip":"127.0.0.1"}`,     // loopback
		`{"ip":"192.168.1.20"}`,  // private
		`{"ip":"10.0.0.0/16"}`,   // private range
		`{"ip":"100.64.1.1"}`,    // CGNAT
		`{"ip":"fd00::1"}`,       // ULA
		`{"ip":"198.51.100.9"}`,  // protected
		`{"ip":"198.0.0.0/8"}`,   // wider than /16
		`{"ip":"0.0.0.0/0"}`,     // everything
		`{"ip":"2001:db8::/32"}`, // wider than /48
		`{"ip":"1.2.3.4/16"}`,    // not a network address
		`{"ip":"::ffff:1.2.3.4/120"}`,
		`{"ip":"::ffff:10.0.0.1"}`,      // IPv4-mapped private
		`{"ip":"::ffff:203.0.113.200"}`, // IPv4-mapped self
		`{"ip":"64:ff9b::a00:1"}`,       // NAT64 form of 10.0.0.1
		`{"ip":"64:ff9b::cb00:71c8"}`,   // NAT64 form of this machine
		`{"ip":"64:ff9b::/64"}`,         // every IPv4 address through NAT64
		`{"ip":"64:ff9b:1::1"}`,         // local-use NAT64
		`{"ip":"192.0.0.1"}`,            // IETF protocol assignments
		`{"ip":"169.254.169.254"}`,      // link-local (cloud metadata)
		`{"ip":"fe80::1"}`,              // link-local
		`{"ip":"::1"}`,                  // loopback
		`{"ip":"224.0.0.1"}`,            // multicast
		`{"ip":"fe80::1%eth0"}`,         // zone
		`{"ip":"example.com"}`,
		`{"ip":"1.2.3.4; rm"}`,
		`{"ip":""}`,
		`{"ip":"8.8.8.8","duration":"10s"}`,
		`{"ip":"8.8.8.8","duration":"10000h"}`,
		`{"ip":"8.8.8.8","duration":"forever"}`,
	} {
		if _, err := invoke(m, "ban", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, c := range []struct{ action, in string }{
		{"delete_decision", `{}`}, {"delete_decision", `{"decision":-1}`}, {"alert", `{"id":0}`},
		{"alerts", `{"ip":"x"}`}, {"alerts", `{"scenario":"a b"}`}, {"alerts", `{"since":"yesterday"}`}, {"decisions", `{"limit":5000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Allowed when the settings say so.
	m2, _ := setup(t, Config{Machine: "conduit", Password: "secret://pw", AllowPrivate: true})
	if _, err := invoke(m2, "ban", `{"ip":"192.168.1.20"}`, false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m2, "ban", `{"ip":"127.0.0.1"}`, false); err == nil {
		t.Fatal("banned this machine's loopback")
	}
}

func TestCrowdSecSettingsAndCredentials(t *testing.T) {
	for _, c := range []Config{
		{BouncerKey: "plainkey"},
		{Machine: "conduit", Password: "plain"},
		{Machine: "conduit"},
		{},
		{URL: "http://user:pw@127.0.0.1:8080", BouncerKey: "secret://bk"},
		{URL: "http://127.0.0.1:8080/?x=1", BouncerKey: "secret://bk"},
		{URL: "http://127.0.0.1:8080/#f", BouncerKey: "secret://bk"},
		{URL: "ftp://127.0.0.1", BouncerKey: "secret://bk"},
		{BouncerKey: "secret://bk", Protect: []string{"nope"}},
		{BouncerKey: "secret://bk", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Machine: "conduit", Password: "secret://bad"})
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused the machine login") || strings.Contains(h.Message, "pw-bad") {
		t.Fatalf("%+v", h)
	}
	badKey, _ := setup(t, Config{BouncerKey: "secret://bkbad"})
	if h := badKey.Health(context.Background(), "c"); h.Status != "down" || h.Message != "CrowdSec refused the bouncer key" {
		t.Fatalf("%+v", h)
	}
	// A bouncer key alone reads decisions but can't change anything.
	if _, err := invoke(badKey, "ban", `{"ip":"8.8.8.8"}`, false); err == nil || !strings.Contains(err.Error(), "machine login") {
		t.Fatal(err)
	}
}

func TestCrowdSecRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Api-Key") + r.Header.Get("Authorization")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, BouncerKey: "secret://bk"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestCrowdSecProtectsTheAPIHostName(t *testing.T) {
	f := &fakeLAPI{decisions: map[int64][3]string{}, simulated: map[int64]bool{}, next: 100}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	resolveErr := false
	m := New()
	m.Local = func() []netip.Addr { return nil }
	m.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "lapi.example" {
			t.Errorf("resolved %q", host)
		}
		if resolveErr {
			return nil, fmt.Errorf("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("::ffff:198.51.100.77")}, nil
	}
	// The name stands for the test server: requests go to it, the guard
	// looks the name up.
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1"+port)
	}}
	m.HTTP = &http.Client{Transport: tr}
	raw, _ := json.Marshal(Config{URL: "http://lapi.example" + port, Machine: "conduit", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "c", raw); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{`{"ip":"198.51.100.77"}`, `{"ip":"198.51.0.0/16"}`, `{"ip":"64:ff9b::c633:644d"}`} {
		if _, err := invoke(m, "ban", in, false); err == nil || !strings.Contains(err.Error(), "Local API") {
			t.Fatalf("accepted %s: %v", in, err)
		}
	}
	resolveErr = true
	if _, err := invoke(m, "ban", `{"ip":"203.0.113.9"}`, false); err == nil {
		t.Fatal("banned without knowing the Local API's address")
	}
	resolveErr = false
	if _, err := invoke(m, "ban", `{"ip":"203.0.113.9"}`, false); err != nil || len(f.decisions) != 1 {
		t.Fatal(err)
	}
}

func TestCrowdSecDeleteDecisionUndo(t *testing.T) {
	m, f := setup(t, Config{Machine: "conduit", Password: "secret://pw", BouncerKey: "secret://bk"})
	f.decisions[5] = [3]string{"203.0.113.8", "Ip", "2h30m40s"}
	f.decisions[6] = [3]string{"203.0.113.9", "Ip", "4h"}
	f.simulated[6] = true
	f.decisions[7] = [3]string{"203.0.113.10", "Ip", "30s"}
	// Undo bans again for no longer than the time left.
	r, err := invoke(m, "delete_decision", `{"decision":5}`, false)
	if err != nil || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"duration":"2h30m0s"`) {
		t.Fatalf("%+v %v", r, err)
	}
	// A simulated decision blocked nothing: no ban as its undo.
	if r, err := invoke(m, "delete_decision", `{"decision":6}`, false); err != nil || r.Undo != nil || len(f.decisions) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// Under a minute left: nothing to ban again.
	if r, err := invoke(m, "delete_decision", `{"decision":7}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	// An id that isn't an active local decision isn't sent to CrowdSec.
	f.seen = nil
	for _, dry := range []bool{true, false} {
		r, err := invoke(m, "delete_decision", `{"decision":4242}`, dry)
		if err != nil || r.Plan != nil || !strings.Contains(string(r.Output), "nothing to change") {
			t.Fatalf("%+v %v", r, err)
		}
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "DELETE") {
			t.Fatalf("deleted an unknown decision: %v", f.seen)
		}
	}
}
