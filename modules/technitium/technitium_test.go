package technitium

import (
	"context"
	"encoding/json"
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

type fakeTDNS struct {
	mu       sync.Mutex
	seen     []string
	blocked  map[string]bool
	allowed  map[string]bool
	blocking bool
	flushed  bool
	redirect string
}

func keys(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "\n")
}

func (f *fakeTDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ok := func(resp string) { io.WriteString(w, `{"status":"ok","response":`+resp+`}`) }
	if r.URL.RawQuery != "" {
		w.WriteHeader(400) // the token must never be in the URL
		return
	}
	_ = r.ParseForm()
	if r.PostForm.Get("token") != "t0k" {
		io.WriteString(w, `{"status":"invalid-token","errorMessage":"Invalid token or session expired."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.URL.Path+" "+r.PostForm.Get("domain"))
	d := r.PostForm.Get("domain")
	switch r.URL.Path {
	case "/api/dashboard/stats/get":
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		ok(`{"stats":{"totalQueries":1200,"totalBlocked":300,"totalCached":400,"totalNxDomain":12,"zones":3,"totalClients":9},"topClients":[{"name":"192.168.1.20","hits":500}],"topDomains":[{"name":"example.com","hits":90}],"topBlockedDomains":[{"name":"ads.example.net","hits":80}]}`)
	case "/api/settings/get":
		till := ""
		if !f.blocking {
			till = "2026-11-04T12:05:00Z"
		}
		ok(`{"enableBlocking":` + map[bool]string{true: "true", false: "false"}[f.blocking] + `,"temporaryDisableBlockingTill":"` + till + `","proxy":{"password":"proxy-secret"},"tsigKeys":[{"keyName":"k","sharedSecret":"tsig-secret"}]}`)
	case "/api/settings/set":
		f.blocking = r.PostForm.Get("enableBlocking") == "true"
		ok(`{"enableBlocking":true,"proxy":{"password":"proxy-secret"}}`)
	case "/api/settings/temporaryDisableBlocking":
		if r.PostForm.Get("minutes") != "10" {
			w.WriteHeader(400)
			return
		}
		f.blocking = false
		ok(`{"temporaryDisableBlockingTill":"2026-11-04T12:10:00Z"}`)
	case "/api/zones/list":
		ok(`{"zones":[{"name":"home.lan","type":"Primary","dnssecStatus":"Unsigned","soaSerial":7,"disabled":false},{"name":"0.in-addr.arpa","type":"Primary","internal":true}]}`)
	case "/api/zones/records/get":
		if r.PostForm.Get("zone") != "home.lan" {
			io.WriteString(w, `{"status":"error","errorMessage":"No such zone was found: x"}`)
			return
		}
		ok(`{"zone":{"name":"home.lan"},"records":[{"name":"nas.home.lan","type":"A","ttl":3600,"rData":{"ipAddress":"192.168.1.10"},"disabled":false},{"name":"corp.home.lan","type":"FWD","ttl":3600,"rData":{"forwarder":"10.0.0.53","proxyType":"Http","proxyUsername":"me","proxyPassword":"fwd-secret"}},{"name":"app.home.lan","type":"APP","ttl":60,"rData":{"appName":"Split Horizon","classPath":"SplitHorizon.SimpleAddress","data":"{\"apiKey\":\"app-cfg-secret\"}"},"comments":"api_key=hunter2hunter2hunter2"}]}`)
	case "/api/blocked/export":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, keys(f.blocked))
	case "/api/allowed/export":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, keys(f.allowed))
	case "/api/blocked/add":
		f.blocked[d] = true
		ok(`{}`)
	case "/api/blocked/delete":
		delete(f.blocked, d)
		ok(`{}`)
	case "/api/allowed/add":
		f.allowed[d] = true
		ok(`{}`)
	case "/api/allowed/delete":
		delete(f.allowed, d)
		ok(`{}`)
	case "/api/cache/flush":
		f.flushed = true
		ok(`{}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, token string) (*Module, *fakeTDNS) {
	t.Helper()
	f := &fakeTDNS{blocked: map[string]bool{"tracker.example.org": true}, allowed: map[string]bool{}, blocking: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "t0k", "secret://bad": "nope"}), "dns", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "dns", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTechnitium(t *testing.T) {
	m, f := setup(t, "secret://t")
	if h := m.Health(context.Background(), "dns"); h.Status != "ok" || h.Message != "1200 queries in the last hour, 300 blocked · 3 zones" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"stats", `{}`, `"totalBlocked":300`},
		{"stats", `{"period":"LastWeek"}`, `"topBlockedDomains":[{"name":"ads.example.net","hits":80}]`},
		{"zones", `{}`, `"name":"home.lan"`},
		{"records", `{"zone":"home.lan"}`, `"ipAddress":"192.168.1.10"`},
		{"records", `{"zone":"home.lan","domain":"nas.home.lan"}`, `"forwarder":"10.0.0.53"`},
		{"blocked", `{"search":"tracker"}`, `{"domains":["tracker.example.org"],"total":1}`},
		{"allowed", `{}`, `{"domains":[],"total":0}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
		if strings.Contains(string(r.Output), "secret") || strings.Contains(string(r.Output), "in-addr") {
			t.Fatalf("%s: %s", c.action, r.Output)
		}
	}

	// Block, refuse twice, undo.
	r, err := invoke(m, "block_domain", `{"domain":"Ads.Example.com."}`, false)
	if err != nil || !f.blocked["ads.example.com"] || r.Undo == nil || r.Undo.Action != "unblock_domain" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "block_domain", `{"domain":"ads.example.com"}`, false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.blocked["ads.example.com"] || r.Undo.Action != "block_domain" {
		t.Fatal(err)
	}

	// Allow: preview notes the block it overrides; undo drops it.
	r, err = invoke(m, "allow_domain", `{"domain":"tracker.example.org"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "allowing wins") || len(f.allowed) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "allow_domain", `{"domain":"tracker.example.org"}`, false)
	if err != nil || !f.allowed["tracker.example.org"] || r.Undo == nil || r.Undo.Action != "drop_allowed_domain" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.allowed) != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "drop_allowed_domain", `{"domain":"tracker.example.org"}`, false); err == nil || !strings.Contains(err.Error(), "isn't") {
		t.Fatal(err)
	}

	if _, err := invoke(m, "flush_cache", `{}`, false); err != nil || !f.flushed {
		t.Fatal(err)
	}

	// Pause blocking: preview, act (health degraded), undo.
	if p, err := invoke(m, "disable_blocking", `{"minutes":10}`, true); err != nil || p.Plan == nil || !f.blocking {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "disable_blocking", `{"minutes":10}`, false)
	if err != nil || f.blocking || !strings.Contains(string(r.Output), "2026-11-04T12:10:00Z") || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if h := m.Health(context.Background(), "dns"); h.Status != "degraded" || !strings.Contains(h.Message, "paused until") || strings.Contains(h.Message, "secret") {
		t.Fatalf("%+v", h)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.blocking || strings.Contains(string(r.Output), "secret") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestTechnitiumValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"stats", `{"period":"Forever"}`},
		{"records", `{"zone":"../settings"}`},
		{"records", `{"zone":"home.lan","domain":"evil.org"}`},
		{"blocked", `{"search":"a b"}`},
		{"block_domain", `{"domain":"ads example.com"}`},
		{"block_domain", `{"domain":"ads.example.com&token=x"}`},
		{"allow_domain", `{"domain":""}`},
		{"disable_blocking", `{"minutes":0}`},
		{"disable_blocking", `{"minutes":100000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Technitium: %v", f.seen)
	}
	if _, err := invoke(m, "records", `{"zone":"other.lan"}`, false); err == nil || !strings.Contains(err.Error(), "No such zone") {
		t.Fatal(err)
	}
	for _, c := range []Config{{URL: "http://dns:5380", Token: "plain"}, {URL: "dns:5380", Token: "secret://t"}, {URL: "http://u:p@dns:5380", Token: "secret://t"}, {URL: "http://dns:5380/?token=x", Token: "secret://t"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "dns"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		leaked = r.Form.Get("token")
	}))
	defer other.Close()
	f.redirect = other.URL
	if h := m.Health(context.Background(), "dns"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}

// Blocking is destructive (it can take down resolution), and names whose
// blocking reaches far beyond one site are refused at every risk.
func TestTechnitiumBlockingLimits(t *testing.T) {
	m, f := setup(t, "secret://t")
	f.allowed["home.lan"] = true
	f.allowed["co.uk"] = true
	for _, c := range []struct{ action, domain, want string }{
		{"block_domain", "com", "single label"},
		{"block_domain", "lan", "single label"},
		{"block_domain", "arpa", "single label"},
		{"block_domain", "in-addr.arpa", "public suffix"},
		{"block_domain", "co.uk", "public suffix"},
		{"block_domain", "github.io", "public suffix"},
		{"block_domain", "home.lan", "own zone"},
		{"block_domain", "nas.home.lan", "own zone"},
		{"block_domain", "1.0.in-addr.arpa", "own zone"},
		{"drop_allowed_domain", "home.lan", "own zone"},
		{"drop_allowed_domain", "co.uk", "public suffix"},
		{"allow_domain", "com", "single label"},
		{"allow_domain", "co.uk", "public suffix"},
	} {
		for _, dry := range []bool{true, false} {
			if _, err := invoke(m, c.action, `{"domain":"`+c.domain+`"}`, dry); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s %s: %v (want %q)", c.action, c.domain, err, c.want)
			}
		}
	}
	for _, s := range f.seen {
		if strings.HasSuffix(strings.Fields(s)[0], "/add") || strings.HasSuffix(strings.Fields(s)[0], "/delete") {
			t.Fatalf("reached Technitium: %s", s)
		}
	}
	for _, a := range New().Manifest().Actions {
		switch a.Name {
		case "block_domain", "unblock_domain", "allow_domain", "drop_allowed_domain":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Errorf("%s: %+v", a.Name, a)
			}
		}
	}
	r, err := invoke(m, "block_domain", `{"domain":"ads.example.com"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "stop resolving") || f.blocked["ads.example.com"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	// Records: a DNS app's configuration and secrets in comments stay out.
	r, err = invoke(m, "records", `{"zone":"home.lan"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "Split Horizon") || strings.Contains(string(r.Output), "app-cfg-secret") || strings.Contains(string(r.Output), "hunter2") {
		t.Fatalf("%s %v", r.Output, err)
	}
}
