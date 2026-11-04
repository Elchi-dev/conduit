package resend

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
	goodKey  = "re_AbCdEf12_3456789xyz"
	sendKey  = "re_SendOnly_123456789"
	domainID = "4dd369bc-aa82-4ff3-97de-514ae3000ee0"
	audID    = "78261eea-8f8b-4381-83c6-79fa7120f1cf"
	c1       = "11111111-1111-4111-8111-111111111111"
	c2       = "22222222-2222-4222-8222-222222222222"
)

type fakeResend struct {
	mu        sync.Mutex
	seen      []string
	sent      []map[string]any
	idem      []string
	limited   bool // answer the next GET with 429
	contactsQ []string
}

func (f *fakeResend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Header.Get("Authorization") {
	case "Bearer " + goodKey:
	case "Bearer " + sendKey:
		w.WriteHeader(401)
		io.WriteString(w, `{"statusCode":401,"name":"restricted_api_key","message":"This API key is restricted to only send emails"}`)
		return
	default:
		w.WriteHeader(400)
		io.WriteString(w, `{"statusCode":400,"name":"validation_error","message":"API key is invalid"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if f.limited && r.Method == "GET" {
		f.limited = false
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		io.WriteString(w, `{"statusCode":429,"name":"rate_limit_exceeded","message":"Too many requests"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /domains":
		io.WriteString(w, `{"object":"list","data":[{"id":"`+domainID+`","name":"example.com","status":"verified","region":"us-east-1","created_at":"2026-01-01T00:00:00Z"},{"id":"x","name":"new.example.com","status":"pending","region":"eu-west-1"}]}`)
	case "GET /domains/" + domainID:
		io.WriteString(w, `{"id":"`+domainID+`","name":"example.com","status":"verified","region":"us-east-1","records":[{"record":"SPF","name":"send","type":"MX","ttl":"Auto","status":"verified","value":"feedback-smtp.us-east-1.amazonses.com","priority":10},{"record":"DKIM","name":"resend._domainkey","type":"TXT","status":"pending","value":"p=MIGf"}]}`)
	case "GET /emails":
		if r.URL.Query().Get("limit") != "5" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"object":"list","has_more":true,"data":[{"id":"`+c1+`","to":["jane@example.org"],"bcc":["hidden@example.org"],"from":"App <app@example.com>","subject":"Welcome","created_at":"2026-11-01T10:00:00Z","last_event":"delivered","html":"<p>secret body</p>"}]}`)
	case "GET /audiences":
		io.WriteString(w, `{"object":"list","data":[{"id":"`+audID+`","name":"Newsletter","created_at":"2026-01-01"}]}`)
	case "GET /audiences/" + audID + "/contacts":
		f.contactsQ = append(f.contactsQ, r.URL.RawQuery)
		if r.URL.Query().Get("after") == "" {
			io.WriteString(w, `{"object":"list","has_more":true,"data":[{"id":"`+c1+`","email":"a@example.org","unsubscribed":false},{"id":"`+c2+`","email":"b@example.org","unsubscribed":true}]}`)
			return
		}
		io.WriteString(w, `{"object":"list","has_more":false,"data":[{"id":"33333333-3333-4333-8333-333333333333","email":"c@example.org","unsubscribed":false}]}`)
	case "POST /emails":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		f.sent = append(f.sent, b)
		f.idem = append(f.idem, r.Header.Get("Idempotency-Key"))
		io.WriteString(w, `{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"statusCode":404,"name":"not_found","message":"Not found"}`)
	}
}

var secrets = map[string]string{"secret://rs": goodKey, "secret://send": sendKey, "secret://bad": "re_WrongWrongWrong1", "secret://junk": "not a key"}

func setup(t *testing.T, cfg Config) (*Module, *fakeResend) {
	t.Helper()
	f := &fakeResend{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Sleep = func(context.Context, time.Duration) error { return nil }
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

var good = Config{Key: "secret://rs", From: "Conduit <test@example.com>", TestRecipients: []string{"Me@Example.com", "team@example.com"}}

func TestResendReads(t *testing.T) {
	m, f := setup(t, good)
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "connected: 1 of 2 domains verified" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"domains", `{}`, `"verified":true`},
		{"domain", `{"id":"` + domainID + `"}`, `"recordsNotVerified":1`},
		{"emails", `{"limit":5}`, `"status":"delivered"`},
		{"emails", `{"limit":5}`, `"next":"` + c1 + `"`},
		{"audiences", `{}`, `"contacts":3,"created":"2026-01-01","id":"` + audID + `","name":"Newsletter","subscribed":2,"unsubscribed":1`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		if strings.Contains(out, "secret body") || strings.Contains(out, "hidden@") {
			t.Fatalf("%s leaked: %s", c.action, out)
		}
		if c.action != "emails" && strings.Contains(out, "@example.org") {
			t.Fatalf("%s returned an address: %s", c.action, out)
		}
	}
	if len(f.contactsQ) != 2 || f.contactsQ[1] != "after="+c2+"&limit=100" {
		t.Fatalf("contacts paging: %v", f.contactsQ)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "emails", "send_test_email":
			if !a.Sensitive {
				t.Fatalf("%s must be sensitive", a.Name)
			}
		default:
			if a.Sensitive || a.Risk != sdk.RiskRead {
				t.Fatalf("%s: %+v", a.Name, a)
			}
		}
	}
	// A rate-limited read is retried once.
	f.limited = true
	if _, err := invoke(m, "domains", `{}`, false); err != nil {
		t.Fatal(err)
	}
}

func TestResendSendTest(t *testing.T) {
	m, f := setup(t, good)
	r, err := invoke(m, "send_test_email", `{"to":"me@example.com"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Send a test email from Conduit <test@example.com> to me@example.com" || len(f.sent) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_test_email", `{"to":" ME@example.com ","subject":"Hello"}`, false)
	if err != nil || len(f.sent) != 1 || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	b := f.sent[0]
	if b["from"] != "Conduit <test@example.com>" || b["subject"] != "Hello" || len(b["to"].([]any)) != 1 || b["to"].([]any)[0] != "me@example.com" || b["text"] == "" {
		t.Fatalf("%v", b)
	}
	if !strings.HasPrefix(f.idem[0], "conduit-") {
		t.Fatalf("idempotency key: %v", f.idem)
	}
	for _, in := range []string{
		`{"to":"stranger@example.org"}`,
		`{"to":"me@example.com, stranger@example.org"}`,
		`{"to":"me@example.com\r\nBcc: x@example.org"}`,
		`{}`, // two recipients: must say which
		`{"to":"me@example.com","subject":"a\r\nBcc: x@example.org"}`,
		`{"to":"me@example.com","text":"` + strings.Repeat("a", 5001) + `"}`,
	} {
		if _, err := invoke(m, "send_test_email", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
		if _, err := invoke(m, "send_test_email", in, true); err == nil {
			t.Fatalf("previewed %s", in)
		}
	}
	if len(f.sent) != 1 {
		t.Fatalf("refused sends reached Resend: %v", f.sent)
	}
	one, f1 := setup(t, Config{Key: "secret://rs", From: "test@example.com", TestRecipients: []string{"me@example.com"}})
	if _, err := invoke(one, "send_test_email", `{}`, false); err != nil || f1.sent[0]["to"].([]any)[0] != "me@example.com" {
		t.Fatal(err)
	}
	none, f2 := setup(t, Config{Key: "secret://rs", From: "test@example.com"})
	if _, err := invoke(none, "send_test_email", `{"to":"me@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "test recipients") || len(f2.seen) != 0 {
		t.Fatal(err)
	}
}

func TestResendValidation(t *testing.T) {
	m, f := setup(t, good)
	for _, c := range []struct{ action, in string }{
		{"domain", `{"id":"../emails"}`},
		{"domain", `{}`},
		{"emails", `{"after":"x&limit=100"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Resend: %v", f.seen)
	}
	for _, raw := range []string{
		`{"key":"re_AbCdEf12_3456789xyz"}`,
		`{"key":"secret://rs","from":"not an address"}`,
		`{"key":"secret://rs","from":"a@example.com\r\nBcc: b@example.com"}`,
		`{"key":"secret://rs","testRecipients":["Me <me@example.com>"]}`,
		`{"key":"secret://rs","testRecipients":["a@example.com,b@example.com"]}`,
		`{"key":"secret://rs","testRecipients":["1@x.io","2@x.io","3@x.io","4@x.io","5@x.io","6@x.io","7@x.io","8@x.io","9@x.io","10@x.io","11@x.io"]}`,
	} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted settings %s", raw)
		}
	}
	bad, _ := setup(t, Config{Key: "secret://bad"})
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || !strings.Contains(h.Message, "API key is invalid") {
		t.Fatalf("%+v", h)
	}
	send, _ := setup(t, Config{Key: "secret://send"})
	if h := send.Health(context.Background(), "r"); h.Status != "degraded" || !strings.Contains(h.Message, "only send") {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, Config{Key: "secret://junk"})
	if _, err := invoke(junk, "domains", `{}`, false); err == nil || len(fj.seen) != 0 {
		t.Fatal(err)
	}
	if h := New().Health(context.Background(), "r"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestResendRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(secrets), "r", json.RawMessage(`{"key":"secret://rs"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
