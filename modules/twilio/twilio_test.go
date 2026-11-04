package twilio

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	sid       = "AC" + "0123456789abcdef0123456789abcdef"
	goodToken = "fedcba9876543210fedcba9876543210"
	acct      = "/2010-04-01/Accounts/" + sid
)

type fakeTwilio struct {
	mu   sync.Mutex
	seen []string
	sent []url.Values
}

func (f *fakeTwilio) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != sid || p != goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":20003,"message":"Authenticate","more_info":"https://www.twilio.com/docs/errors/20003","status":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.Path {
	case "GET " + acct + ".json":
		io.WriteString(w, `{"sid":"`+sid+`","friendly_name":"My first account","status":"active","type":"Trial","auth_token":"LEAKME"}`)
	case "GET " + acct + "/Balance.json":
		io.WriteString(w, `{"currency":"USD","balance":"14.25","account_sid":"`+sid+`"}`)
	case "GET " + acct + "/IncomingPhoneNumbers.json":
		io.WriteString(w, `{"incoming_phone_numbers":[{"sid":"PN1","phone_number":"+15005550006","friendly_name":"Support line","status":"in-use","capabilities":{"voice":true,"sms":true,"mms":false},"sms_url":"https://u:LEAKME@hooks.example/sms"}]}`)
	case "GET " + acct + "/Messages.json":
		q := r.URL.Query()
		if q.Get("To") != "" && q.Get("To") != "+4915112345678" {
			w.WriteHeader(400)
			return
		}
		if q.Get("Page") != "" && (q.Get("Page") != "1" || q.Get("PageToken") != "PASMabcdef0123456789") {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"messages":[{"sid":"SM1","from":"+15005550006","to":"+4915112345678","body":"Your code is 1234","status":"delivered","direction":"outbound-api","num_segments":"1","price":"-0.0790","price_unit":"USD","date_sent":"Wed, 04 Nov 2026 10:00:00 +0000","error_code":null}],
			"next_page_uri":"`+acct+`/Messages.json?To=%2B4915112345678&PageSize=20&Page=1&PageToken=PASMabcdef0123456789"}`)
	case "GET " + acct + "/Calls.json":
		io.WriteString(w, `{"calls":[{"sid":"CA1","from":"+4915112345678","to":"+15005550006","status":"completed","direction":"inbound","start_time":"Wed, 04 Nov 2026 09:00:00 +0000","duration":"42","price":"-0.0085","price_unit":"USD"}],"next_page_uri":null}`)
	case "POST " + acct + "/Messages.json":
		form, _ := url.ParseQuery(string(body))
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(415)
			return
		}
		if form.Get("To") == "+15005550001" {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":21211,"message":"The 'To' number +15005550001 is not a valid phone number.","status":400}`)
			return
		}
		f.sent = append(f.sent, form)
		w.WriteHeader(201)
		io.WriteString(w, `{"sid":"SM2","to":"`+form.Get("To")+`","from":"+15005550006","status":"queued","num_segments":"1","body":"`+form.Get("Body")+`"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":20404,"message":"The requested resource was not found","status":404}`)
	}
}

var secrets = map[string]string{"secret://tw": goodToken, "secret://bad": "00000000000000000000000000000000", "secret://junk": "hunter2"}

func setup(t *testing.T, c Config) (*Module, *fakeTwilio) {
	t.Helper()
	f := &fakeTwilio{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

var good = Config{AccountSID: sid, AuthToken: "secret://tw", From: "+15005550006"}

func TestTwilioReads(t *testing.T) {
	m, _ := setup(t, good)
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "connected: trial account, active" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"balance", `{}`, `"display":"14.25 USD"`},
		{"numbers", `{}`, `"sms":true`},
		{"messages", `{"to":"+4915112345678","since":"2026-11-01"}`, `"next":{"page":1,"pageToken":"PASMabcdef0123456789"}`},
		{"messages", `{"page":1,"pageToken":"PASMabcdef0123456789"}`, `"body":"Your code is 1234"`},
		{"calls", `{"status":"completed"}`, `"durationSeconds":"42"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if (c.action == "balance" || c.action == "numbers") && strings.Contains(out, "+49") {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		want := a.Name == "messages" || a.Name == "calls" || a.Name == "send_sms"
		if a.Sensitive != want {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
	}
}

func TestTwilioSend(t *testing.T) {
	m, f := setup(t, Config{AccountSID: sid, AuthToken: "secret://tw", From: "+15005550006", AllowedRecipients: []string{"+4915112345678", "+15005550001"}})
	r, err := invoke(m, "send_sms", `{"to":"+4915112345678","body":"Deploy finished"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Text +4915112345678 from +15005550006 (15 characters, about 1 SMS parts)" || len(f.sent) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_sms", `{"to":"+4915112345678","body":"Deploy finished"}`, false)
	if err != nil || len(f.sent) != 1 || f.sent[0].Get("From") != "+15005550006" || f.sent[0].Get("Body") != "Deploy finished" || r.Undo != nil || !strings.Contains(string(r.Output), `"sid":"SM2"`) {
		t.Fatalf("%s %v %v", r.Output, err, f.sent)
	}
	if _, err := invoke(m, "send_sms", `{"to":"+4915112345678","body":"x","from":"MG0123456789abcdef0123456789abcdef"}`, false); err != nil || f.sent[1].Get("MessagingServiceSid") == "" || f.sent[1].Get("From") != "" {
		t.Fatal(err, f.sent)
	}
	if _, err := invoke(m, "send_sms", `{"to":"+4915199999999","body":"x"}`, false); err == nil || !strings.Contains(err.Error(), "allowed recipients") {
		t.Fatal(err)
	}
	// Twilio's error quotes the number; it's scrubbed.
	if _, err := invoke(m, "send_sms", `{"to":"+15005550001","body":"x"}`, false); err == nil || strings.Contains(err.Error(), "5550001") || !strings.Contains(err.Error(), "not a valid phone number") {
		t.Fatal(err)
	}
	if n := segments(strings.Repeat("a", 161)); n != 2 {
		t.Fatal(n)
	}
	if n := segments("Grüße 👋"); n != 1 {
		t.Fatal(n)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "send_sms" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatalf("%+v", a)
		}
	}
}

func TestTwilioValidation(t *testing.T) {
	m, f := setup(t, Config{AccountSID: sid, AuthToken: "secret://tw"})
	for _, c := range []struct{ action, in string }{
		{"messages", `{"to":"015112345678"}`},
		{"messages", `{"from":"+1555&Body=x"}`},
		{"messages", `{"since":"last week"}`},
		{"messages", `{"status":"completed"}`},
		{"messages", `{"page":2}`},
		{"messages", `{"page":1,"pageToken":"../x"}`},
		{"calls", `{"status":"gone"}`},
		{"send_sms", `{"to":"+4915112345678","body":"no sender"}`},
		{"send_sms", `{"to":"4915112345678","body":"x","from":"+15005550006"}`},
		{"send_sms", `{"to":"+4915112345678","body":"   ","from":"+15005550006"}`},
		{"send_sms", `{"to":"+4915112345678","body":"` + strings.Repeat("x", 1601) + `","from":"+15005550006"}`},
		{"send_sms", `{"to":"+4915112345678","body":"x","from":"Acme"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Twilio: %v", f.seen)
	}
	for _, c := range []Config{
		{AccountSID: sid, AuthToken: goodToken},
		{AccountSID: "AC123", AuthToken: "secret://tw"},
		{AccountSID: sid + "/../x", AuthToken: "secret://tw"},
		{AccountSID: sid, AuthToken: "secret://tw", From: "Acme"},
		{AccountSID: sid, AuthToken: "secret://tw", AllowedRecipients: []string{"0151"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{AccountSID: sid, AuthToken: "secret://bad"})
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || h.Message != "Twilio refused the account SID and auth token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, Config{AccountSID: sid, AuthToken: "secret://junk"})
	if _, err := invoke(junk, "balance", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestTwilioRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(good)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
