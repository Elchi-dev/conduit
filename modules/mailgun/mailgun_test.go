package mailgun

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

const goodKey = "key-faketestkeynotreal000000000000"

type fakeMailgun struct {
	mu      sync.Mutex
	seen    []string
	bounced map[string]bool
}

func (f *fakeMailgun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "api" || p != goodKey {
		w.WriteHeader(401)
		io.WriteString(w, "Forbidden")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+" "+r.URL.RawQuery)
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v4/domains":
		io.WriteString(w, `{"total_count":2,"items":[{"name":"mg.example.com","state":"active","type":"custom","created_at":"Mon, 01 Jan 2026 00:00:00 GMT","spam_action":"disabled","smtp_password":"hunter2"},{"name":"new.example.com","state":"unverified","type":"custom"}]}`)
	case "GET /v3/mg.example.com/stats/total":
		q := r.URL.Query()
		if q.Get("duration") != "3d" || len(q["event"]) != 4 || q.Get("resolution") != "day" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"start":"Sat, 01 Nov 2026 00:00:00 UTC","end":"Tue, 04 Nov 2026 00:00:00 UTC","stats":[
			{"time":"Sat, 01 Nov 2026 00:00:00 UTC","accepted":{"total":100},"delivered":{"total":95},"failed":{"permanent":{"bounce":3,"suppress-bounce":1,"total":4},"temporary":{"espblock":1,"total":1}},"complained":{"total":1}},
			{"time":"Sun, 02 Nov 2026 00:00:00 UTC","accepted":{"total":100},"delivered":{"total":99},"failed":{"permanent":{"bounce":1,"total":1},"temporary":{"total":0}}}]}`)
	case "GET /v3/mg.example.com/events":
		if r.URL.Query().Get("ascending") != "no" || r.URL.Query().Get("event") != "failed" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"id":"ev1","event":"failed","timestamp":1793000000.5,"recipient":"jane@example.org","severity":"permanent","reason":"bounce","message":{"headers":{"subject":"Your invoice","from":"billing@example.com","message-id":"abc@mg.example.com"}},"delivery-status":{"code":550,"message":"No such user","description":""},"storage":{"url":"https://storage.mailgun.net/secret","key":"k"}}],"paging":{"next":"https://evil.example/next"}}`)
	case "GET /v3/mg.example.com/bounces":
		io.WriteString(w, `{"items":[{"address":"jane@example.org","code":"550","error":"No such user","created_at":"Fri, 31 Oct 2026 10:00:00 UTC"}],"paging":{}}`)
	case "GET /v3/mg.example.com/unsubscribes":
		io.WriteString(w, `{"items":[{"address":"bob@example.org","tags":["*"],"created_at":"Fri, 31 Oct 2026 10:00:00 UTC"}]}`)
	case "GET /v3/mg.example.com/bounces/jane@example.org":
		if !f.bounced["jane@example.org"] {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Address not found in bounces table"}`)
			return
		}
		io.WriteString(w, `{"address":"jane@example.org","code":"550","error":"No such user","created_at":"Fri, 31 Oct 2026 10:00:00 UTC"}`)
	case "DELETE /v3/mg.example.com/bounces/jane@example.org":
		delete(f.bounced, "jane@example.org")
		io.WriteString(w, `{"message":"Bounced address has been removed","address":"jane@example.org"}`)
	case "GET /v3/mg.example.com/bounces/o%27brien+tag@example.org":
		io.WriteString(w, `{"address":"o'brien+tag@example.org","code":"550"}`)
	case "DELETE /v3/mg.example.com/bounces/o%27brien+tag@example.org":
		io.WriteString(w, `{"message":"Bounced address has been removed"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Domain not found"}`)
	}
}

var secrets = map[string]string{"secret://mg": goodKey, "secret://bad": "key-fakebadkeynotreal0000000000000", "secret://junk": "a b"}

func setup(t *testing.T, raw string) (*Module, *fakeMailgun) {
	t.Helper()
	f := &fakeMailgun{bounced: map[string]bool{"jane@example.org": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "m", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

const good = `{"key":"secret://mg","region":"eu","domain":"MG.example.com"}`

func TestMailgunReads(t *testing.T) {
	m, _ := setup(t, good)
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "connected (EU): 2 domains, mg.example.com active" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"domains", `{}`, `"state":"unverified"`},
		{"stats", `{"days":3}`, `"bounced":4,"complained":1,"delivered":194,"deliveredRate":"97.0%","failedPermanent":5,"failedTemporary":1,"suppressedBounces":1`},
		{"events", `{"event":"failed"}`, `"deliveryStatus":"550 No such user"`},
		{"suppressions", `{"list":"bounces"}`, `"address":"jane@example.org"`},
		{"suppressions", `{"list":"unsubscribes"}`, `"tags":["*"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, leak := range []string{"hunter2", "storage.mailgun.net", "evil.example"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %q: %s", c.action, leak, out)
			}
		}
		if (c.action == "domains" || c.action == "stats") && strings.Contains(out, "@") {
			t.Fatalf("%s returned an address: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		sens := a.Name == "events" || a.Name == "suppressions" || a.Name == "delete_suppression"
		if a.Sensitive != sens {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if a.Name == "delete_suppression" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatalf("%+v", a)
		}
	}
	other, _ := setup(t, `{"key":"secret://mg","domain":"gone.example.com"}`)
	if h := other.Health(context.Background(), "m"); h.Status != "degraded" || !strings.Contains(h.Message, "no domain gone.example.com") {
		t.Fatalf("%+v", h)
	}
}

func TestMailgunDeleteSuppression(t *testing.T) {
	m, f := setup(t, good)
	r, err := invoke(m, "delete_suppression", `{"list":"bounces","address":"jane@example.org"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Remove jane@example.org from the bounce list of mg.example.com") || !strings.Contains(string(r.Plan.Changes[0].Before), "No such user") || !f.bounced["jane@example.org"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"bounces","address":"jane@example.org"}`, false)
	if err != nil || f.bounced["jane@example.org"] || r.Undo != nil || !strings.Contains(string(r.Output), `"removed":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"bounces","address":"jane@example.org"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "isn't on the bounce list") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Addresses are escaped into the path.
	if _, err := invoke(m, "delete_suppression", `{"list":"bounces","address":"o'brien+tag@example.org"}`, false); err != nil {
		t.Fatal(err)
	}
	if last := f.seen[len(f.seen)-1]; last != "DELETE /v3/mg.example.com/bounces/o%27brien+tag@example.org " {
		t.Fatalf("%q", last)
	}
}

func TestMailgunValidation(t *testing.T) {
	m, f := setup(t, good)
	for _, c := range []struct{ action, in string }{
		{"stats", `{"domain":"../v4/domains"}`},
		{"stats", `{"domain":"mg.example.com/x"}`},
		{"events", `{"event":"everything"}`},
		{"events", `{"recipient":"a@b.com&limit=1"}`},
		{"suppressions", `{"list":"all"}`},
		{"suppressions", `{}`},
		{"delete_suppression", `{"list":"bounces","address":"../../v4/domains"}`},
		{"delete_suppression", `{"list":"bounces","address":"a/b@example.org"}`},
		{"delete_suppression", `{"list":"bounces","address":"*"}`},
		{"delete_suppression", `{"list":"lists","address":"jane@example.org"}`},
		{"delete_suppression", `{"list":"bounces"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
		if _, err := invoke(m, c.action, c.in, true); err == nil {
			t.Fatalf("%s previewed %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Mailgun: %v", f.seen)
	}
	nodom, fn := setup(t, `{"key":"secret://mg"}`)
	if _, err := invoke(nodom, "stats", `{}`, false); err == nil || !strings.Contains(err.Error(), "which domain") || len(fn.seen) != 0 {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"key":"` + goodKey + `"}`,
		`{"key":"secret://mg","region":"asia"}`,
		`{"key":"secret://mg","domain":"not a domain"}`,
		`{"key":"secret://mg","domain":"mg.example.com/../x"}`,
	} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted settings %s", raw)
		}
	}
	bad, _ := setup(t, `{"key":"secret://bad"}`)
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, `{"key":"secret://junk"}`)
	if _, err := invoke(junk, "domains", `{}`, false); err == nil || len(fj.seen) != 0 {
		t.Fatal(err)
	}
}

func TestMailgunRegions(t *testing.T) {
	for region, want := range map[string]string{"": "https://api.mailgun.net", "us": "https://api.mailgun.net", "EU": "https://api.eu.mailgun.net"} {
		m := New()
		if err := m.Configure(context.Background(), fakehost.New(secrets), "m", json.RawMessage(`{"key":"secret://mg","region":"`+region+`"}`)); err != nil {
			t.Fatal(err)
		}
		c, _ := m.set.Get("m")
		if c.api.Base != want || c.api.HTTP.Timeout == 0 || c.api.HTTP.CheckRedirect == nil {
			t.Fatalf("%s: %s", region, c.api.Base)
		}
	}
}

func TestMailgunRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "m", json.RawMessage(`{"key":"secret://mg"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
