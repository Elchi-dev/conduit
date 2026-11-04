package sendgrid

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	goodKey = "SG.abcdEFGH1234.ijklMNOP5678qrst"
	fullKey = "SG.fullFULL1234.ijklMNOP5678qrst"
)

type fakeSendGrid struct {
	mu      sync.Mutex
	seen    []string
	bounced bool
	unsub   bool
}

func (f *fakeSendGrid) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+goodKey && auth != "Bearer "+fullKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"field":null,"message":"authorization required"}]}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+" "+r.URL.RawQuery)
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v3/scopes":
		if auth == "Bearer "+fullKey {
			io.WriteString(w, `{"scopes":["stats.read","api_keys.create","templates.read"]}`)
			return
		}
		io.WriteString(w, `{"scopes":["stats.read","templates.read"]}`)
	case "GET /v3/stats":
		q := r.URL.Query()
		if q.Get("start_date") != "2026-11-02" || q.Get("end_date") != "2026-11-04" || q.Get("aggregated_by") != "day" {
			w.WriteHeader(400)
			io.WriteString(w, `{"errors":[{"message":"bad dates `+r.URL.RawQuery+`"}]}`)
			return
		}
		io.WriteString(w, `[{"date":"2026-11-02","stats":[{"metrics":{"requests":100,"delivered":96,"bounces":2,"blocks":1,"spam_reports":1,"opens":40}}]},{"date":"2026-11-03","stats":[{"metrics":{"requests":100,"delivered":98,"bounces":1}}]},{"date":"2026-11-04","stats":[]}]`)
	case "GET /v3/suppression/bounces":
		if r.URL.Query().Get("limit") != "10" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"created":1793000000,"email":"jane@example.org","reason":"550 5.1.1 No such user","status":"5.1.1"}]`)
	case "GET /v3/suppression/spam_reports":
		io.WriteString(w, `[{"created":1793000000,"email":"bob@example.org","ip":"10.0.0.1"}]`)
	case "GET /v3/suppression/bounces/jane@example.org":
		if !f.bounced {
			io.WriteString(w, `[]`)
			return
		}
		io.WriteString(w, `[{"created":1793000000,"email":"jane@example.org","reason":"550 No such user","status":"5.1.1"}]`)
	case "DELETE /v3/suppression/bounces/jane@example.org":
		f.bounced = false
		w.WriteHeader(204)
	case "GET /v3/asm/suppressions/global/bob@example.org":
		if !f.unsub {
			io.WriteString(w, `{}`)
			return
		}
		io.WriteString(w, `{"recipient_email":"bob@example.org"}`)
	case "DELETE /v3/asm/suppressions/global/bob@example.org":
		f.unsub = false
		w.WriteHeader(204)
	case "GET /v3/templates":
		if r.URL.Query().Get("generations") != "legacy,dynamic" || r.URL.Query().Get("page_size") != "50" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"result":[{"id":"d-123","name":"Welcome","generation":"dynamic","updated_at":"2026-10-01 10:00:00","versions":[{"id":"v1","name":"Old","active":0},{"id":"v2","name":"Current","active":1,"html_content":"<p>Hi {{name}}</p>","subject":"Hi"}]}],"_metadata":{"count":1}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"message":"resource not found"}]}`)
	}
}

var secrets = map[string]string{"secret://sg": goodKey, "secret://full": fullKey, "secret://bad": "SG.wrongWRONG123.wrongWRONG456", "secret://junk": "hello"}

func setup(t *testing.T, raw string) (*Module, *fakeSendGrid) {
	t.Helper()
	f := &fakeSendGrid{bounced: true, unsub: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC) }
	if err := m.Configure(context.Background(), fakehost.New(secrets), "s", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSendGridReads(t *testing.T) {
	m, _ := setup(t, `{"key":"secret://sg"}`)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "connected (2 permissions)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"stats", `{"days":3}`, `"blocks":1,`},
		{"stats", `{"days":3}`, `"delivered":194,"deliveredRate":"97.0%"`},
		{"suppressions", `{"list":"bounces","limit":10}`, `"reason":"550 5.1.1 No such user"`},
		{"suppressions", `{"list":"spam_reports"}`, `"email":"bob@example.org"`},
		{"templates", `{}`, `"activeVersion":{"id":"v2","name":"Current"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if strings.Contains(out, "10.0.0.1") || strings.Contains(out, "{{name}}") {
			t.Fatalf("%s leaked: %s", c.action, out)
		}
		if c.action != "suppressions" && strings.Contains(out, "@") {
			t.Fatalf("%s returned an address: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		sens := a.Name == "suppressions" || a.Name == "delete_suppression"
		if a.Sensitive != sens {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if a.Name == "delete_suppression" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatalf("%+v", a)
		}
	}
	full, _ := setup(t, `{"key":"secret://full"}`)
	if h := full.Health(context.Background(), "s"); !strings.Contains(h.Message, "restricted key is safer") {
		t.Fatalf("%+v", h)
	}
}

func TestSendGridDeleteSuppression(t *testing.T) {
	m, f := setup(t, `{"key":"secret://sg"}`)
	r, err := invoke(m, "delete_suppression", `{"list":"bounces","email":"jane@example.org"}`, true)
	if err != nil || r.Plan == nil || !strings.HasPrefix(r.Plan.Summary, "Remove jane@example.org from the bounce list") || !strings.Contains(string(r.Plan.Changes[0].Before), "No such user") || !f.bounced {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"bounces","email":"jane@example.org"}`, false)
	if err != nil || f.bounced || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"bounces","email":"jane@example.org"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "isn't on the bounce list") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"unsubscribes","email":"bob@example.org"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "global unsubscribe list") || !f.unsub {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete_suppression", `{"list":"unsubscribes","email":"bob@example.org"}`, false); err != nil || f.unsub {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_suppression", `{"list":"unsubscribes","email":"bob@example.org"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "isn't on") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestSendGridValidation(t *testing.T) {
	m, f := setup(t, `{"key":"secret://sg"}`)
	for _, c := range []struct{ action, in string }{
		{"suppressions", `{"list":"everything"}`},
		{"suppressions", `{}`},
		{"delete_suppression", `{"list":"bounces","email":"../../scopes"}`},
		{"delete_suppression", `{"list":"bounces","email":"a/b@example.org"}`},
		{"delete_suppression", `{"list":"bounces","email":"jane@example.org?x=1"}`},
		{"delete_suppression", `{"list":"bounces"}`},
		{"delete_suppression", `{"list":"lists","email":"jane@example.org"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached SendGrid: %v", f.seen)
	}
	for _, raw := range []string{`{"key":"` + goodKey + `"}`, `{"key":"secret://sg","region":"us"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted settings %s", raw)
		}
	}
	bad, _ := setup(t, `{"key":"secret://bad"}`)
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "SendGrid refused the API key" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, `{"key":"secret://junk"}`)
	if _, err := invoke(junk, "stats", `{}`, false); err == nil || !strings.Contains(err.Error(), "SG.") || len(fj.seen) != 0 {
		t.Fatal(err)
	}
	eu := New()
	if err := eu.Configure(context.Background(), fakehost.New(secrets), "e", json.RawMessage(`{"key":"secret://sg","region":"eu"}`)); err != nil {
		t.Fatal(err)
	}
	if c, _ := eu.set.Get("e"); c.api.Base != "https://api.eu.sendgrid.com" || c.api.HTTP.Timeout == 0 {
		t.Fatal(c.api.Base)
	}
}

func TestSendGridRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "s", json.RawMessage(`{"key":"secret://sg"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
