package powerdns

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

type fakePDNS struct {
	mu       sync.Mutex
	seen     []string
	sets     []rrset
	notified bool
	redirect string
}

func (f *fakePDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "k3y" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	const base = "/api/v1/servers/localhost"
	switch r.Method + " " + r.URL.Path {
	case "GET " + base:
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		io.WriteString(w, `{"type":"Server","id":"localhost","daemon_type":"authoritative","version":"4.9.2"}`)
	case "GET " + base + "/zones":
		io.WriteString(w, `[{"id":"example.com.","name":"example.com.","kind":"Native","serial":2026110401,"dnssec":false},{"id":"sec.example.","name":"sec.example.","kind":"Slave","serial":1}]`)
	case "GET " + base + "/zones/example.com.":
		reply(map[string]any{"id": "example.com.", "name": "example.com.", "kind": "Native", "serial": 2026110401, "rrsets": f.sets})
	case "GET " + base + "/zones/sec.example.":
		reply(map[string]any{"id": "sec.example.", "name": "sec.example.", "kind": "Slave", "rrsets": []any{}})
	case "PATCH " + base + "/zones/example.com.":
		var in struct {
			RRsets []struct {
				rrset
				Changetype string `json:"changetype"`
			} `json:"rrsets"`
		}
		_ = json.Unmarshal(body, &in)
		for _, c := range in.RRsets {
			next := []rrset{}
			for _, s := range f.sets {
				if !(s.Name == c.Name && s.Type == c.Type) {
					next = append(next, s)
				}
			}
			if c.Changetype == "REPLACE" {
				next = append(next, c.rrset)
			}
			f.sets = next
		}
		w.WriteHeader(204)
	case "PUT " + base + "/zones/example.com./notify":
		f.notified = true
		io.WriteString(w, `{"result":"Notification queued"}`)
	case "PUT " + base + "/zones/example.com./rectify":
		w.WriteHeader(422)
		io.WriteString(w, `{"error":"Zone example.com. is not DNSSEC signed"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not Found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakePDNS) {
	t.Helper()
	f := &fakePDNS{sets: []rrset{
		{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []record{{Content: "ns1.example.com. hostmaster.example.com. 2026110401 10800 3600 604800 3600"}}},
		{Name: "www.example.com.", Type: "A", TTL: 300, Records: []record{{Content: "192.0.2.1"}, {Content: "192.0.2.2", Disabled: true}}, Comments: []comment{{Content: "web"}}},
		{Name: "blog.example.com.", Type: "CNAME", TTL: 3600, Records: []record{{Content: "www.example.com."}}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "k3y", "secret://bad": "x"}), "ns", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "ns", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func (f *fakePDNS) get(name, typ string) *rrset {
	for i, s := range f.sets {
		if s.Name == name && s.Type == typ {
			return &f.sets[i]
		}
	}
	return nil
}

func TestPowerDNS(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "ns"); h.Status != "ok" || h.Message != "PowerDNS Authoritative 4.9.2" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "zones", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"kind":"Native"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "records", `{"zone":"Example.com","name":"www"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"records":["192.0.2.1","192.0.2.2 (disabled)"]`) || strings.Contains(string(r.Output), "SOA") || !strings.Contains(string(r.Output), `"comments":["web"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Adding a new record: preview, add, undo.
	add := `{"zone":"example.com","name":"status","type":"TXT","content":"v=DMARC1; p=reject"}`
	r, err = invoke(m, "add_record", add, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Create status.example.com. TXT in example.com." || r.Plan.Changes[0].Before != nil || len(f.sets) != 3 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_record", add, false)
	if s := f.get("status.example.com.", "TXT"); err != nil || s == nil || s.Records[0].Content != `"v=DMARC1; p=reject"` || s.TTL != 3600 {
		t.Fatalf("%v %+v", err, f.sets)
	}
	if r.Undo == nil || r.Undo.Action != "delete_rrset" {
		t.Fatalf("%+v", r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.get("status.example.com.", "TXT") != nil {
		t.Fatal(err)
	}

	// An existing name and type is refused and pointed at replace.
	if _, err := invoke(m, "add_record", `{"zone":"example.com","name":"www","type":"A","content":"192.0.2.9"}`, false); err == nil || !strings.Contains(err.Error(), "replace_rrset") {
		t.Fatal(err)
	}
	// CNAME conflicts both ways.
	if _, err := invoke(m, "add_record", `{"zone":"example.com","name":"blog","type":"TXT","content":"x"}`, false); err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "add_record", `{"zone":"example.com","name":"www","type":"CNAME","content":"elsewhere.example.net"}`, false); err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Fatal(err)
	}

	// Replace: the preview shows old and new; undo puts the old ones back, disabled flag and TTL included.
	rep := `{"zone":"example.com","name":"www.example.com.","type":"A","contents":["198.51.100.1"],"ttl":120}`
	r, err = invoke(m, "replace_rrset", rep, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"records":["192.0.2.1","192.0.2.2 (disabled)"],"ttl":300}` || string(r.Plan.Changes[0].After) != `{"records":["198.51.100.1"],"ttl":120}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "replace_rrset", rep, false)
	if s := f.get("www.example.com.", "A"); err != nil || len(s.Records) != 1 || s.TTL != 120 || r.Undo == nil || r.Undo.Action != "replace_rrset" {
		t.Fatalf("%v %+v %+v", err, s, r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if s := f.get("www.example.com.", "A"); len(s.Records) != 2 || !s.Records[1].Disabled || s.TTL != 300 {
		t.Fatalf("%+v", s)
	}

	// Delete with preview and undo.
	r, err = invoke(m, "delete_rrset", `{"zone":"example.com","name":"blog","type":"CNAME"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Changes[0].Op != "delete" || f.get("blog.example.com.", "CNAME") == nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_rrset", `{"zone":"example.com","name":"blog","type":"CNAME"}`, false)
	if err != nil || f.get("blog.example.com.", "CNAME") != nil || r.Undo == nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.get("blog.example.com.", "CNAME") == nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_rrset", `{"zone":"example.com","name":"nope","type":"A"}`, false); err == nil {
		t.Fatal("deleted nothing")
	}

	if _, err := invoke(m, "notify", `{"zone":"example.com"}`, false); err != nil || !f.notified {
		t.Fatal(err)
	}
	if _, err := invoke(m, "rectify", `{"zone":"example.com"}`, false); err == nil || !strings.Contains(err.Error(), "not DNSSEC signed") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "add_record", `{"zone":"sec.example","name":"x","type":"A","content":"192.0.2.1"}`, false); err == nil || !strings.Contains(err.Error(), "Slave") {
		t.Fatal(err)
	}
}

func TestPowerDNSValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"records", `{"zone":"../../config"}`},
		{"records", `{"zone":"example.com","name":"evil.org."}`},
		{"add_record", `{"zone":"example.com","name":"@","type":"SOA","content":"x"}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"A","content":"::1"}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"A","content":"1.2.3.4\n5.6.7.8"}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"AAAA","content":"1.2.3.4"}`},
		{"add_record", `{"zone":"example.com","name":"a b","type":"A","content":"1.2.3.4"}`},
		{"add_record_any", `{"zone":"example.com","name":"a","type":"MX","content":"mail.example.com"}`},
		{"add_record_any", `{"zone":"example.com","name":"a","type":"SRV","content":"0 5 99999 sip.example.com"}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"CNAME","contents":["x.example.com","y.example.com"]}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"A"}`},
		{"add_record", `{"zone":"example.com","name":"a","type":"A","content":"1.2.3.4","ttl":5}`},
		{"add_record_any", `{"zone":"example.com","name":"a","type":"CAA","content":"0 issue letsencrypt.org"}`},
		{"replace_rrset", `{"zone":"example.com","name":"a","type":"A","contents":["1.2.3.4","1.2.3.4"]}`},
		{"delete_rrset", `{"zone":"example.com","name":"a","type":"A","content":"1.2.3.4"}`},
		{"notify", `{"zone":"example.com/../x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached PowerDNS: %v", f.seen)
	}
	for typ, c := range map[string][2]string{
		"MX":    {"10 Mail.Example.com", "10 mail.example.com."},
		"SRV":   {"0 5 5060 sip.example.com.", "0 5 5060 sip.example.com."},
		"CNAME": {"www.example.com", "www.example.com."},
		"TXT":   {`say "hi"`, `"say \"hi\""`},
		"CAA":   {`0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		"AAAA":  {"2001:DB8::1", "2001:db8::1"},
	} {
		if got, err := content(typ, c[0]); err != nil || got != c[1] {
			t.Fatalf("%s %s: %s %v", typ, c[0], got, err)
		}
	}
	long, _ := quoteTXT(strings.Repeat("a", 300))
	if long != `"`+strings.Repeat("a", 255)+`" "`+strings.Repeat("a", 45)+`"` {
		t.Fatal(long)
	}
	if n, err := owner("*.dev", "example.com."); err != nil || n != "*.dev.example.com." {
		t.Fatal(n, err)
	}
	for _, c := range []Config{{URL: "https://ns1", APIKey: "plain"}, {URL: "ns1:8081", APIKey: "secret://k"}, {URL: "https://ns1", APIKey: "secret://k", Server: "../x"}, {URL: "https://u:p@ns1", APIKey: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "ns"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-Key") }))
	defer other.Close()
	f.redirect = other.URL
	if h := m.Health(context.Background(), "ns"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}

// add_record (write) adds only A, AAAA, TXT and CNAME at a name nothing
// answers for; everything that could delegate, take mail, mint certificates
// or override a live answer needs add_record_any (destructive), whose
// preview says what it overrides.
func TestPowerDNSAddRecordLimits(t *testing.T) {
	m, f := setup(t, "secret://k")
	f.sets = append(f.sets,
		rrset{Name: "*.example.com.", Type: "A", TTL: 300, Records: []record{{Content: "192.0.2.50"}}},
		rrset{Name: "corp.example.com.", Type: "NS", TTL: 300, Records: []record{{Content: "ns.corp.example.net."}}},
		rrset{Name: "example.com.", Type: "NS", TTL: 300, Records: []record{{Content: "ns1.example.com."}}},
		rrset{Name: "mail.example.com.", Type: "MX", TTL: 300, Records: []record{{Content: "10 mx.example.com."}}},
	)
	for in, want := range map[string]string{
		`{"zone":"example.com","name":"corp2","type":"NS","content":"ns.attacker.net."}`:                 "add_record_any",
		`{"zone":"example.com","name":"x","type":"DS","content":"12345 13 2 abcdef"}`:                    "add_record_any",
		`{"zone":"example.com","name":"www","type":"HTTPS","content":"1 attacker.net. alpn=h2"}`:         "add_record_any",
		`{"zone":"example.com","name":"@","type":"MX","content":"0 mx.attacker.net."}`:                   "add_record_any",
		`{"zone":"example.com","name":"@","type":"CAA","content":"0 issue \"attacker-ca.net\""}`:         "add_record_any",
		`{"zone":"example.com","name":"@","type":"TXT","content":"v=spf1 include:attacker.net -all"}`:    "zone apex",
		`{"zone":"example.com","name":"admin","type":"A","content":"203.0.113.66"}`:                      "wildcard *.example.com.",
		`{"zone":"example.com","name":"a.b.c","type":"A","content":"203.0.113.66"}`:                      "wildcard *.example.com.",
		`{"zone":"example.com","name":"_acme-challenge.www","type":"TXT","content":"token"}`:             "_acme-challenge",
		`{"zone":"example.com","name":"_acme-challenge-x","type":"CNAME","content":"acme.attacker.net"}`: "_acme-challenge",
		`{"zone":"example.com","name":"sel._domainkey","type":"TXT","content":"v=DKIM1; p=AAAA"}`:        "DKIM",
		`{"zone":"example.com","name":"*.dev","type":"A","content":"203.0.113.66"}`:                      "wildcard",
		`{"zone":"example.com","name":"_dmarc","type":"TXT","content":"v=DMARC1; p=none"}`:               "service, policy or verification",
		`{"zone":"example.com","name":"_smtp._tls","type":"TXT","content":"v=TLSRPTv1"}`:                 "service, policy or verification",
		`{"zone":"example.com","name":"_atproto","type":"TXT","content":"did=did:plc:x"}`:                "service, policy or verification",
		`{"zone":"example.com","name":"mta-sts","type":"CNAME","content":"mta-sts.attacker.net."}`:       "mta-sts host",
		`{"zone":"example.com","name":"autodiscover","type":"CNAME","content":"ad.attacker.net."}`:       "autodiscover host",
		`{"zone":"example.com","name":"wpad.office","type":"A","content":"203.0.113.66"}`:                "wpad host",
		`{"zone":"example.com","name":"www","type":"AAAA","content":"2001:db8::66"}`:                     "already has A",
		`{"zone":"example.com","name":"mail","type":"A","content":"203.0.113.66"}`:                       "already has MX",
		`{"zone":"example.com","name":"corp","type":"A","content":"203.0.113.66"}`:                       "delegated",
		`{"zone":"example.com","name":"host.corp","type":"A","content":"203.0.113.66"}`:                  "delegated",
		`{"zone":"example.com","name":"deep.host.corp.example.com.","type":"TXT","content":"x"}`:         "delegated",
	} {
		if _, err := invoke(m, "add_record", in, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("add_record %s: %v (want %q)", in, err, want)
		}
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "PATCH") {
			t.Fatalf("add_record wrote: %s", s)
		}
	}
	m2 := &Module{}
	for _, a := range m2.Manifest().Actions {
		if a.Name == "add_record" && (a.Risk != sdk.RiskWrite || strings.Contains(string(a.Input), `"NS"`)) {
			t.Fatalf("%+v", a)
		}
		if a.Name == "add_record_any" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%+v", a)
		}
	}

	// Fresh names outside any wildcard's reach still work at write: a zone
	// without the wildcard.
	f.mu.Lock()
	f.sets = f.sets[:3]
	f.mu.Unlock()
	if _, err := invoke(m, "add_record", `{"zone":"example.com","name":"new","type":"A","content":"192.0.2.7"}`, false); err != nil || f.get("new.example.com.", "A") == nil {
		t.Fatal(err)
	}

	// add_record_any does the rest, and its preview names what it overrides.
	f.mu.Lock()
	f.sets = append(f.sets, rrset{Name: "*.example.com.", Type: "A", TTL: 300, Records: []record{{Content: "192.0.2.50"}}},
		rrset{Name: "corp.example.com.", Type: "NS", TTL: 300, Records: []record{{Content: "ns.corp.example.net."}}})
	f.mu.Unlock()
	r, err := invoke(m, "add_record_any", `{"zone":"example.com","name":"www","type":"AAAA","content":"2001:db8::66"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "already has A records") || !strings.Contains(string(r.Plan.Changes[0].After), "overrides") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_record_any", `{"zone":"example.com","name":"host.corp","type":"A","content":"192.0.2.8"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "corp.example.com. is delegated") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_record_any", `{"zone":"example.com","name":"admin","type":"A","content":"192.0.2.8"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "wildcard *.example.com.") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_record_any", `{"zone":"example.com","name":"@","type":"MX","content":"10 mx.example.com."}`, false)
	if err != nil || f.get("example.com.", "MX") == nil || r.Undo == nil || r.Undo.Action != "delete_rrset" {
		t.Fatalf("%v %+v", err, r.Undo)
	}
	// An existing name and type still goes through replace_rrset.
	if _, err := invoke(m, "add_record_any", `{"zone":"example.com","name":"www","type":"A","content":"192.0.2.9"}`, false); err == nil || !strings.Contains(err.Error(), "replace_rrset") {
		t.Fatal(err)
	}
}
