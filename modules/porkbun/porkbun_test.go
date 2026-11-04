package porkbun

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type rec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
	Prio    any    `json:"prio"`
	Notes   string `json:"notes"`
}

type fake struct {
	mu      sync.Mutex
	hits    int
	next    int
	records []rec
	created []map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	var b map[string]any
	json.NewDecoder(r.Body).Decode(&b)
	if r.Method != "POST" || b["apikey"] != "pk1_good" || b["secretapikey"] != "sk1_good" {
		w.WriteHeader(400)
		io.WriteString(w, `{"status":"ERROR","message":"Invalid API key. (002)"}`)
		return
	}
	enc := json.NewEncoder(w)
	switch p := r.URL.Path; {
	case p == "/ping":
		io.WriteString(w, `{"status":"SUCCESS","yourIp":"198.51.100.1"}`)
	case p == "/domain/listAll":
		io.WriteString(w, `{"status":"SUCCESS","domains":[
			{"domain":"example.com","status":"ACTIVE","tld":"com","createDate":"2020-11-20 00:00:00","expireDate":"2026-11-20 23:59:59","securityLock":"1","whoisPrivacy":"1","autoRenew":0,"notLocal":0},
			{"domain":"example.org","status":"ACTIVE","tld":"org","expireDate":"2027-06-01 23:59:59","securityLock":"1","whoisPrivacy":"1","autoRenew":"1"},
			{"domain":"example.net","status":"ACTIVE","tld":"net","expireDate":"2026-12-01 23:59:59","securityLock":"0","whoisPrivacy":"0","autoRenew":1}]}`)
	case p == "/dns/retrieve/example.com":
		enc.Encode(map[string]any{"status": "SUCCESS", "records": f.records})
	case p == "/dns/create/example.com":
		f.next++
		id := strconv.Itoa(1000 + f.next)
		name := "example.com"
		if b["name"] != "" {
			name = b["name"].(string) + ".example.com"
		}
		f.records = append(f.records, rec{ID: id, Name: name, Type: b["type"].(string), Content: b["content"].(string), TTL: b["ttl"].(string)})
		delete(b, "apikey")
		delete(b, "secretapikey")
		f.created = append(f.created, b)
		io.WriteString(w, `{"status":"SUCCESS","id":`+id+`}`)
	case strings.HasPrefix(p, "/dns/delete/example.com/"):
		id := strings.TrimPrefix(p, "/dns/delete/example.com/")
		for i, x := range f.records {
			if x.ID == id {
				f.records = append(f.records[:i], f.records[i+1:]...)
				io.WriteString(w, `{"status":"SUCCESS"}`)
				return
			}
		}
		w.WriteHeader(400)
		io.WriteString(w, `{"status":"ERROR","message":"Invalid record ID."}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"ERROR","message":"Not found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := &fake{records: []rec{
		{ID: "1", Name: "example.com", Type: "A", Content: "192.0.2.1", TTL: "600", Prio: "0", Notes: "private note"},
		{ID: "2", Name: "example.com", Type: "MX", Content: "mail.example.com", TTL: "600", Prio: "10"},
		{ID: "3", Name: "www.example.com", Type: "CNAME", Content: "example.com", TTL: "600", Prio: nil},
		{ID: "4", Name: "*.apps.example.com", Type: "A", Content: "192.0.2.2", TTL: "600"},
		{ID: "5", Name: "lab.example.com", Type: "NS", Content: "ns1.lab.example.net", TTL: "600"},
		{ID: "6", Name: "api.example.com", Type: "TXT", Content: "hello", TTL: "600"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{APIKey: key, SecretAPIKey: "secret://sk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pk": "pk1_good\n", "secret://sk": "sk1_good", "secret://bad": "pk1_bad"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPorkbunReads(t *testing.T) {
	m, _ := setup(t, "secret://pk")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"domains", `{}`, `{"domain":"example.com","status":"ACTIVE","expires":"2026-11-20 23:59:59","daysLeft":16,"autoRenew":false,"securityLock":true,"whoisPrivacy":true}`},
		{"domains", `{}`, `"domain":"example.org","status":"ACTIVE","expires":"2027-06-01 23:59:59","daysLeft":209,"autoRenew":true`},
		{"renewals", `{"days":30}`, `"notAutoRenewing":["example.com"],"within":30`},
		{"renewals", `{}`, `"expiring":[{"domain":"example.com"`},
		{"records", `{"domain":"Example.com."}`, `{"id":"2","name":"example.com","type":"MX","content":"mail.example.com","ttl":"600","prio":"10"}`},
		{"records", `{"domain":"example.com","name":"www"}`, `[{"id":"3","name":"www.example.com","type":"CNAME","content":"example.com","ttl":"600"}]`},
		{"records", `{"domain":"example.com","type":"txt"}`, `[{"id":"6"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"pk1_", "sk1_", "private note", "198.51.100.1"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %s", c.action, leak)
			}
		}
	}
	if r, _ := invoke(m, "renewals", `{"days":30}`, false); strings.Contains(string(r.Output), "example.org") {
		t.Fatalf("renewals beyond the window: %s", r.Output)
	}
}

// add_record mirrors PowerDNS's rules: only a fresh name, only A, AAAA,
// TXT and CNAME, never the apex, ACME or DKIM names, wildcards, names a
// wildcard covers or names under a delegation.
func TestPorkbunAddRecordRules(t *testing.T) {
	m, f := setup(t, "secret://pk")
	for _, c := range []struct{ in, why string }{
		{`{"domain":"example.com","name":"@","type":"TXT","content":"x"}`, "domain itself"},
		{`{"domain":"example.com","name":"","type":"A","content":"192.0.2.9"}`, "domain itself"},
		{`{"domain":"example.com","name":"_acme-challenge","type":"TXT","content":"tok"}`, "_acme-challenge"},
		{`{"domain":"example.com","name":"_acme-challenge.shop","type":"TXT","content":"tok"}`, "_acme-challenge"},
		{`{"domain":"example.com","name":"sel._domainkey","type":"TXT","content":"v=DKIM1"}`, "DKIM"},
		{`{"domain":"example.com","name":"*.dev","type":"A","content":"192.0.2.9"}`, "wildcard"},
		{`{"domain":"example.com","name":"_dmarc","type":"TXT","content":"v=DMARC1; p=reject"}`, "service, policy or verification"},
		{`{"domain":"example.com","name":"_mta-sts","type":"TXT","content":"v=STSv1; id=1"}`, "service, policy or verification"},
		{`{"domain":"example.com","name":"_smtp._tls","type":"TXT","content":"v=TLSRPTv1"}`, "service, policy or verification"},
		{`{"domain":"example.com","name":"_github-challenge-org","type":"TXT","content":"0123"}`, "service, policy or verification"},
		{`{"domain":"example.com","name":"_autodiscover._tcp","type":"TXT","content":"x"}`, "service, policy or verification"},
		{`{"domain":"example.com","name":"mta-sts","type":"CNAME","content":"mta-sts.attacker.example"}`, "mta-sts host"},
		{`{"domain":"example.com","name":"autodiscover","type":"CNAME","content":"ad.attacker.example"}`, "autodiscover host"},
		{`{"domain":"example.com","name":"autoconfig.shop","type":"A","content":"192.0.2.9"}`, "autoconfig host"},
		{`{"domain":"example.com","name":"wpad","type":"A","content":"192.0.2.9"}`, "wpad host"},
		{`{"domain":"example.com","name":"x.apps","type":"A","content":"192.0.2.9"}`, "*.apps.example.com"},
		{`{"domain":"example.com","name":"api","type":"A","content":"192.0.2.9"}`, "already has TXT"},
		{`{"domain":"example.com","name":"api.example.com","type":"TXT","content":"again"}`, "already has TXT"},
		{`{"domain":"example.com","name":"host.lab","type":"A","content":"192.0.2.9"}`, "delegated"},
		{`{"domain":"example.com","name":"lab","type":"TXT","content":"x"}`, "delegated"},
		{`{"domain":"example.com","name":"mx2","type":"MX","content":"mail.example.com","prio":5}`, "add_record_any"},
		{`{"domain":"example.com","name":"sub","type":"NS","content":"ns.example.net"}`, "add_record_any"},
	} {
		_, err := invoke(m, "add_record", c.in, false)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Fatalf("%s: %v", c.in, err)
		}
	}
	if len(f.created) != 0 {
		t.Fatalf("created %v", f.created)
	}
	// A fresh name works, previews, and undoes.
	in := `{"domain":"example.com","name":"status","type":"A","content":"192.0.2.50","ttl":900}`
	r, err := invoke(m, "add_record", in, true)
	if err != nil || r.Plan == nil || len(f.created) != 0 || r.Plan.Changes[0].Target != "status.example.com A" {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err = invoke(m, "add_record", in, false)
	if err != nil || len(f.created) != 1 || r.Undo == nil || r.Undo.Action != "delete_record" {
		t.Fatalf("add %+v %v", r, err)
	}
	if f.created[0]["name"] != "status" || f.created[0]["ttl"] != "900" || f.created[0]["content"] != "192.0.2.50" {
		t.Fatalf("sent %v", f.created[0])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.records) != 6 {
		t.Fatalf("undo %v %d", err, len(f.records))
	}
}

func TestPorkbunAddRecordAny(t *testing.T) {
	m, f := setup(t, "secret://pk")
	r, err := invoke(m, "add_record_any", `{"domain":"example.com","name":"_acme-challenge","type":"TXT","content":"tok123"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "overrides: it is an _acme-challenge name") {
		t.Fatalf("preview %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_record_any", `{"domain":"example.com","name":"@","type":"MX","content":"mx2.example.com.","prio":20}`, false)
	if err != nil || r.Undo == nil || f.created[0]["prio"] != "20" || f.created[0]["content"] != "mx2.example.com" || f.created[0]["name"] != "" {
		t.Fatalf("mx %+v %v %v", r, err, f.created)
	}
	for _, c := range []struct{ in, why string }{
		{`{"domain":"example.com","name":"www","type":"A","content":"192.0.2.9"}`, "is a CNAME"},
		{`{"domain":"example.com","name":"api","type":"CNAME","content":"x.example.net"}`, "CNAME can't sit"},
		{`{"domain":"example.com","name":"@","type":"A","content":"192.0.2.1"}`, "already has this record"},
		{`{"domain":"example.com","name":"@","type":"MX","content":"mx3.example.com"}`, "needs a priority"},
		{`{"domain":"example.com","name":"t","type":"TXT","content":"x","prio":1}`, "no priority"},
		{`{"domain":"example.com","name":"t","type":"SOA","content":"x"}`, "doesn't take"},
	} {
		if _, err := invoke(m, "add_record_any", c.in, false); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Fatalf("%s: %v", c.in, err)
		}
	}
	if len(f.created) != 1 {
		t.Fatalf("created %v", f.created)
	}
}

func TestPorkbunDeleteRecord(t *testing.T) {
	m, f := setup(t, "secret://pk")
	r, err := invoke(m, "delete_record", `{"domain":"example.com","id":"2"}`, true)
	if err != nil || r.Plan == nil || len(f.records) != 6 || !strings.Contains(r.Plan.Summary, "mail.example.com") {
		t.Fatalf("preview %+v %v", r, err)
	}
	r, err = invoke(m, "delete_record", `{"domain":"example.com","id":"2"}`, false)
	if err != nil || len(f.records) != 5 || r.Undo == nil || r.Undo.Action != "add_record_any" {
		t.Fatalf("delete %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.records) != 6 || f.created[0]["prio"] != "10" || f.created[0]["name"] != "" {
		t.Fatalf("undo %v %v", err, f.created)
	}
	if _, err := invoke(m, "delete_record", `{"domain":"example.com","id":"99"}`, false); err == nil {
		t.Fatal("deleted a missing record")
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "add_record":
			want = sdk.RiskWrite
		case "add_record_any", "delete_record":
			want = sdk.RiskDestructive
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestPorkbunBadInputNeverSent(t *testing.T) {
	m, f := setup(t, "secret://pk")
	for _, c := range []struct{ action, in string }{
		{"records", `{}`},
		{"records", `{"domain":"../domain/listAll"}`},
		{"records", `{"domain":"example.com/x"}`},
		{"records", `{"domain":"com"}`},
		{"records", `{"domain":"example.com","type":"BOGUS"}`},
		{"delete_record", `{"domain":"example.com","id":"../../ping"}`},
		{"delete_record", `{"domain":"example.com"}`},
		{"add_record", `{"domain":"example.com","name":"a b","type":"A","content":"192.0.2.1"}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"A","content":"2001:db8::1"}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"AAAA","content":"192.0.2.1"}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"CNAME","content":"not a host"}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"TXT","content":"two\nlines"}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"TXT","content":""}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"TXT","content":"x","ttl":60}`},
		{"add_record", `{"domain":"example.com","name":"x","type":"MX","content":"m.example.com","prio":1}`},
		{"renewals", `{"days":0.5}`},
		{"renewals", `{"days":5000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if f.hits != 0 {
		t.Fatalf("%d requests for bad input", f.hits)
	}
}

func TestPorkbunSettingsAndBadKey(t *testing.T) {
	for _, raw := range []string{
		`{"apiKey":"pk1_plain","secretApiKey":"secret://sk"}`,
		`{"apiKey":"secret://pk","secretApiKey":"sk1_plain"}`,
		`{}`,
	} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "p", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	m, _ := setup(t, "secret://bad")
	h := m.Health(context.Background(), "p")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API key pair") || strings.Contains(h.Message, "pk1") {
		t.Fatalf("%+v", h)
	}
}

func TestPorkbunRefusesCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	var got string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = string(b) + "hit"
		mu.Unlock()
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 307 resends the body, keys included.
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://pk", SecretAPIKey: "secret://sk"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pk": "pk1_good", "secret://sk": "sk1_good"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
	mu.Lock()
	defer mu.Unlock()
	if got != "" {
		t.Fatalf("keys reached another host: %s", got)
	}
}
