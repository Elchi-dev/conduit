package pushover

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
	goodTok  = "azGDORePK8gMaC0QOYAMyEEuzJnyUi"
	goodUser = "uQiRzpo4DXghDmr9QzzfQu27cmVRsG"
)

type fake struct {
	mu   sync.Mutex
	seen []url.Values
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Form)
	if r.Form.Get("token") != goodTok {
		w.WriteHeader(400)
		io.WriteString(w, `{"token":"invalid","errors":["application token is invalid, see https://pushover.net/api"],"status":0,"request":"r1"}`)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/1/apps/limits.json":
		io.WriteString(w, `{"limit":10000,"remaining":7496,"reset":1793512800,"status":1,"request":"r2"}`)
	case r.Method == "POST" && r.URL.Path == "/1/users/validate.json":
		if r.Form.Get("user") != goodUser {
			w.WriteHeader(400)
			io.WriteString(w, `{"user":"invalid","errors":["user key is invalid"],"status":0,"request":"r3"}`)
			return
		}
		io.WriteString(w, `{"status":1,"group":0,"devices":["phone","desktop"],"licenses":["Android","Desktop"],"request":"r4"}`)
	case r.Method == "POST" && r.URL.Path == "/1/messages.json":
		if r.Form.Get("priority") == "2" {
			io.WriteString(w, `{"status":1,"request":"r5","receipt":"rcpt123"}`)
			return
		}
		io.WriteString(w, `{"status":1,"request":"r6"}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{AppToken: tok, UserKey: "secret://u"})
	h := fakehost.New(map[string]string{"secret://t": goodTok, "secret://u": goodUser, "secret://bad": "x" + goodTok[1:]})
	if err := m.Configure(context.Background(), h, "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noSecret(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, goodTok) || strings.Contains(s, goodUser) || strings.Contains(s, goodTok[1:]) {
		t.Fatalf("secret in output: %s", s)
	}
}

func TestPushover(t *testing.T) {
	m, f := setup(t, "secret://t")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "Pushover · 2 devices · 7496 messages left this month" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"validate_user", `"devices":["phone","desktop"]`},
		{"limits", `"remaining":7496`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
		noSecret(t, string(r.Output))
	}
	if r, _ := invoke(m, "validate_user", `{}`, false); !strings.Contains(string(r.Output), `"user":"uQiR…"`) {
		t.Fatal(string(r.Output))
	}
	n := len(f.seen)
	r, err := invoke(m, "send_notification", `{"message":"backup done","title":"NAS","priority":1,"device":"phone","url":"https://nas.example.com","urlTitle":"open"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "your device phone") || len(f.seen) != n {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	noSecret(t, string(r.Plan.Changes[0].After))
	r, err = invoke(m, "send_notification", `{"message":"backup done","title":"NAS","priority":1,"device":"phone"}`, false)
	if err != nil || string(r.Output) != `{"sent":true}` || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	last := f.seen[len(f.seen)-1]
	if last.Get("priority") != "1" || last.Get("device") != "phone" || last.Get("user") != goodUser {
		t.Fatal(last)
	}
	r, err = invoke(m, "send_emergency", `{"message":"server down","retry":60,"expire":3600}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "until acknowledged") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_emergency", `{"message":"server down","retry":60,"expire":3600}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"receipt":"rcpt123"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if last := f.seen[len(f.seen)-1]; last.Get("priority") != "2" || last.Get("retry") != "60" {
		t.Fatal(last)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "send_emergency") != (a.Risk == sdk.RiskDestructive) {
			t.Fatal(a.Name, a.Risk)
		}
	}
}

func TestPushoverValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"send_notification", `{}`}, {"send_notification", `{"message":" "}`},
		{"send_notification", `{"message":"x","priority":2}`}, {"send_notification", `{"message":"x","priority":-3}`},
		{"send_notification", `{"message":"` + strings.Repeat("x", maxMessage+1) + `"}`},
		{"send_notification", `{"message":"x","title":"` + strings.Repeat("t", maxTitle+1) + `"}`},
		{"send_notification", `{"message":"x","url":"javascript:alert(1)"}`}, {"send_notification", `{"message":"x","url":"https://u:p@x.example.com"}`},
		{"send_notification", `{"message":"x","url":"https://x.example.com/` + strings.Repeat("a", maxURL) + `"}`},
		{"send_notification", `{"message":"x","urlTitle":"no link"}`}, {"send_notification", `{"message":"x","device":"phone,tablet"}`},
		{"send_notification", `{"message":"x","sound":"a b"}`}, {"send_notification", `{"message":"x","retry":60,"expire":60}`},
		{"send_notification", `{"message":"x","ttl":-1}`},
		{"send_emergency", `{"message":"x"}`}, {"send_emergency", `{"message":"x","retry":10,"expire":60}`},
		{"send_emergency", `{"message":"x","retry":60,"expire":20000}`}, {"send_emergency", `{"message":"x","retry":60,"expire":600,"priority":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{}, {AppToken: "secret://t"}, {AppToken: goodTok, UserKey: "secret://u"}, {AppToken: "secret://t", UserKey: goodUser}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "p")
	if h.Status != "down" || h.Message != "Pushover refused the application token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "send_notification", `{"message":"x"}`, false); err == nil || err.Error() != "Pushover refused the application token" {
		t.Fatal(err)
	}
}

func TestPushoverRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.ParseForm(); leaked = r.Form.Get("token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{AppToken: "secret://t", UserKey: "secret://u"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": goodTok, "secret://u": goodUser}), "p", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "p")
	if h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	noSecret(t, h.Message)
	if _, err := invoke(m, "limits", `{}`, false); err == nil || leaked != "" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "limits", `{}`, false); err != nil {
		noSecret(t, err.Error())
	}
}

func TestPushoverTransportErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{AppToken: "secret://t", UserKey: "secret://u"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": goodTok, "secret://u": goodUser}), "p", raw); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "limits", `{}`, false)
	if err == nil {
		t.Fatal("no error")
	}
	noSecret(t, err.Error())
}
