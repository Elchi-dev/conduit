package googleworkspace

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	clientSecret = "GOCSPX-CLIENT-SECRET-LEAKME"
	refreshToken = "1//REFRESH-TOKEN-LEAKME"
)

type fakeGoogle struct {
	mu       sync.Mutex
	key      *rsa.PublicKey
	api      []string
	tokens   []url.Values
	claims   map[string]any
	issued   int
	valid    map[string]bool
	raw      string
	lastBody map[string]any
	lastQ    url.Values
	redirect string
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/token" {
		form, _ := url.ParseQuery(string(body))
		f.tokens = append(f.tokens, form)
		ok := false
		switch form.Get("grant_type") {
		case "refresh_token":
			ok = form.Get("client_secret") == clientSecret && form.Get("refresh_token") == refreshToken
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			parts := strings.Split(form.Get("assertion"), ".")
			if len(parts) == 3 {
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				c, _ := base64.RawURLEncoding.DecodeString(parts[1])
				f.claims = map[string]any{}
				json.Unmarshal(c, &f.claims)
				ok = rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig) == nil
			}
		}
		if !ok {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Bad token %s"}`, form.Get("refresh_token"))
			return
		}
		f.issued++
		tok := fmt.Sprintf("ya29.ACCESS-%d", f.issued)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599}`, tok)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`)
		return
	}
	f.api = append(f.api, r.Method+" "+r.URL.EscapedPath())
	f.lastQ = r.URL.Query()
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	if len(body) > 0 {
		f.lastBody = map[string]any{}
		json.Unmarshal(body, &f.lastBody)
	}
	enc := func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }
	p := r.URL.EscapedPath()
	switch {
	case p == "/gmail/v1/users/me/profile":
		io.WriteString(w, `{"emailAddress":"alex@example.com","messagesTotal":40,"threadsTotal":30}`)
	case p == "/gmail/v1/users/me/messages" && r.Method == "GET":
		io.WriteString(w, `{"messages":[{"id":"18c0ffee00000001"},{"id":"../../evil"}]}`)
	case p == "/gmail/v1/users/me/messages/18c0ffee00000001" && r.URL.Query().Get("format") == "metadata":
		io.WriteString(w, `{"id":"18c0ffee00000001","threadId":"t1","labelIds":["INBOX","UNREAD"],"snippet":"See you &amp; bye","payload":{"headers":[{"name":"From","value":"Kim <kim@example.com>"},{"name":"Subject","value":"Lunch"}]}}`)
	case p == "/gmail/v1/users/me/messages/18c0ffee00000001":
		fmt.Fprintf(w, `{"id":"18c0ffee00000001","payload":{"mimeType":"multipart/mixed","headers":[{"name":"Subject","value":"Lunch"}],"parts":[
			{"mimeType":"multipart/alternative","parts":[{"mimeType":"text/html","body":{"data":%q}}]},
			{"mimeType":"application/pdf","filename":"menu.pdf","body":{"size":4096,"attachmentId":"LEAKME"}}]}}`, enc("<p>Hello <b>there</b> &amp; welcome</p><script>x()</script>"))
	case p == "/gmail/v1/users/me/messages/send":
		f.raw, _ = f.lastBody["raw"].(string)
		io.WriteString(w, `{"id":"sent1","threadId":"t9"}`)
	case p == "/calendar/v3/calendars/primary/events" && r.Method == "GET":
		io.WriteString(w, `{"items":[{"id":"ev1","summary":"Standup","start":{"dateTime":"2026-11-05T09:00:00Z"},"end":{"dateTime":"2026-11-05T09:15:00Z"},"organizer":{"email":"alex@example.com"},"attendees":[{"email":"kim@example.com","responseStatus":"accepted"}]}]}`)
	case strings.HasPrefix(p, "/calendar/v3/calendars/") && strings.HasSuffix(p, "/events") && r.Method == "POST":
		io.WriteString(w, `{"id":"evnew1","summary":"Focus","start":{"dateTime":"2026-11-05T09:00:00Z"},"end":{"dateTime":"2026-11-05T10:00:00Z"}}`)
	case p == "/calendar/v3/calendars/primary/events/evnew1" && r.Method == "GET":
		io.WriteString(w, `{"id":"evnew1","status":"confirmed","summary":"Focus","start":{"dateTime":"2026-11-05T09:00:00Z"},"end":{"dateTime":"2026-11-05T10:00:00Z"},"attendees":[{"email":"kim@example.com"},{"email":"alex@example.com","self":true}]}`)
	case p == "/calendar/v3/calendars/primary/events/evnew1" && r.Method == "DELETE":
		w.WriteHeader(204)
	case p == "/calendar/v3/calendars/primary/events/evseries" && r.Method == "GET":
		io.WriteString(w, `{"id":"evseries","status":"confirmed","summary":"Weekly","recurrence":["RRULE:FREQ=WEEKLY"],"start":{"dateTime":"2026-11-05T09:00:00Z"},"end":{"dateTime":"2026-11-05T10:00:00Z"}}`)
	case p == "/calendar/v3/calendars/primary/events/evold" && r.Method == "GET":
		io.WriteString(w, `{"id":"evold","status":"cancelled"}`)
	case p == "/drive/v3/files":
		io.WriteString(w, `{"files":[{"id":"1abcdefghijk","name":"Budget","mimeType":"application/vnd.google-apps.spreadsheet","modifiedTime":"2026-11-01T00:00:00Z"},{"id":"1folderxxxxx","name":"Old","mimeType":"application/vnd.google-apps.folder","size":"12"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
	}
}

func saKey(t *testing.T) (string, *rsa.PublicKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "conduit@proj.iam.gserviceaccount.com", "private_key_id": "kid1",
		"private_key": pemKey, "token_uri": "https://evil.example/token"})
	return string(b), &k.PublicKey
}

func setup(t *testing.T, cfg Config) (*Module, *fakeGoogle) {
	t.Helper()
	key, pub := saKey(t)
	f := &fakeGoogle{valid: map[string]bool{}, key: pub}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.TokenURL = srv.URL, srv.URL+"/token"
	raw, _ := json.Marshal(cfg)
	h := fakehost.New(map[string]string{"secret://cs": clientSecret, "secret://rt": refreshToken, "secret://bad": "nope", "secret://sa": key})
	if err := m.Configure(context.Background(), h, "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

var oauthCfg = Config{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://cs", RefreshToken: "secret://rt"}

func call(m *Module, action string, in any, dry bool) (sdk.Result, error) {
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: b, DryRun: dry})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{clientSecret, refreshToken, "ya29.", "LEAKME", "PRIVATE KEY"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaks %q: %s", bad, s)
		}
	}
}

func TestSettingsRefused(t *testing.T) {
	m := New()
	for _, c := range []Config{
		{},
		{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "plain", RefreshToken: "secret://rt"},
		{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://cs", RefreshToken: "1//plain"},
		{ClientID: "bad id!", ClientSecret: "secret://cs", RefreshToken: "secret://rt"},
		{ServiceAccount: "{\"type\":\"service_account\"}", Subject: "a@example.com"},
		{ServiceAccount: "secret://sa"},
		{ServiceAccount: "secret://sa", Subject: "a@example.com", ClientID: "123-abc.apps.googleusercontent.com"},
		{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://cs", RefreshToken: "secret://rt", Subject: "a@example.com"},
		{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://cs", RefreshToken: "secret://rt", Calendar: "../x"},
	} {
		raw, _ := json.Marshal(c)
		if err := m.Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestOAuthMailAndCache(t *testing.T) {
	m, f := setup(t, oauthCfg)
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || !strings.Contains(h.Message, "40 messages") {
		t.Fatalf("%+v", h)
	}
	r, err := call(m, "mail_list", map[string]any{"query": "is:unread"}, false)
	if err != nil {
		t.Fatal(err)
	}
	out := string(r.Output)
	noLeak(t, out)
	if !strings.Contains(out, `"unread":true`) || !strings.Contains(out, `See you \u0026 bye`) || strings.Contains(out, "evil") {
		t.Fatal(out)
	}
	for _, a := range f.api {
		if strings.Contains(a, "evil") {
			t.Fatal("a server-sent id reached a path:", a)
		}
	}
	r, err = call(m, "mail_read", map[string]any{"id": "18c0ffee00000001"}, false)
	if err != nil {
		t.Fatal(err)
	}
	out = string(r.Output)
	noLeak(t, out)
	if !strings.Contains(out, `Hello there \u0026 welcome`) || strings.Contains(out, "x()") || !strings.Contains(out, "menu.pdf") {
		t.Fatal(out)
	}
	if len(f.tokens) != 1 {
		t.Fatalf("token not cached: %d", len(f.tokens))
	}
	// Google stops accepting it: refresh once and retry.
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
	if _, err := call(m, "events", nil, false); err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 2 {
		t.Fatalf("no refresh: %d", len(f.tokens))
	}
	c, _ := m.set.Get("g")
	c.tok.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := call(m, "events", nil, false); err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 3 {
		t.Fatalf("expired token kept: %d", len(f.tokens))
	}
}

func TestServiceAccountDelegation(t *testing.T) {
	m, f := setup(t, Config{ServiceAccount: "secret://sa", Subject: "alex@example.com"})
	if h := m.Health(context.Background(), "g"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	if f.claims["sub"] != "alex@example.com" || f.claims["iss"] != "conduit@proj.iam.gserviceaccount.com" || !strings.HasSuffix(f.claims["aud"].(string), "/token") ||
		!strings.Contains(f.claims["scope"].(string), "gmail.send") {
		t.Fatalf("claims %v", f.claims)
	}
}

func TestBadCredentials(t *testing.T) {
	m, f := setup(t, Config{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://bad", RefreshToken: "secret://rt"})
	h := m.Health(context.Background(), "g")
	if h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	noLeak(t, h.Message)
	if len(f.api) != 0 {
		t.Fatal(f.api)
	}
}

func TestSendMail(t *testing.T) {
	m, f := setup(t, oauthCfg)
	in := map[string]any{"to": []string{"kim@example.com"}, "cc": []string{"lee@example.com"}, "subject": "Hello", "body": "Hi Kim"}
	r, err := call(m, "send_mail", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Send "Hello" to 2 recipients` || len(f.api) != 0 {
		t.Fatalf("%v %+v %v", err, r.Plan, f.api)
	}
	r, err = call(m, "send_mail", in, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	b, _ := base64.RawURLEncoding.DecodeString(f.raw)
	if !strings.Contains(string(b), "To: <kim@example.com>\r\nCc: <lee@example.com>\r\nSubject: Hello\r\n") {
		t.Fatalf("%s", b)
	}
}

func TestInvalidInputNeverReachesGoogle(t *testing.T) {
	m, f := setup(t, oauthCfg)
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	later := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	for _, c := range []struct {
		action string
		in     map[string]any
	}{
		{"mail_read", map[string]any{"id": "../profile"}},
		{"mail_list", map[string]any{"query": "a\nb"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com"}, "subject": "x\r\nBcc: e@evil.example", "body": "b"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com\nBcc: e@evil.example"}, "subject": "x", "body": "b"}},
		{"events", map[string]any{"calendar": "../../users"}},
		{"create_event", map[string]any{"subject": "x", "start": soon, "end": later, "attendees": []string{"kim@example.com"}}},
		{"schedule_meeting", map[string]any{"subject": "x", "start": soon, "end": later}},
		{"schedule_meeting", map[string]any{"subject": "x\ny", "start": soon, "end": later, "attendees": []string{"kim@example.com"}}},
		{"delete_event", map[string]any{"id": "a/b"}},
		{"files", map[string]any{"folder": "x' or 'a"}},
		{"files", map[string]any{"name": "a\x00b"}},
	} {
		if _, err := call(m, c.action, c.in, false); err == nil {
			t.Errorf("%s %v accepted", c.action, c.in)
		}
	}
	if len(f.api) != 0 || len(f.tokens) != 0 {
		t.Fatal(f.api, f.tokens)
	}
}

func TestEventsAndFiles(t *testing.T) {
	m, f := setup(t, oauthCfg)
	r, err := call(m, "events", nil, false)
	if err != nil || !strings.Contains(string(r.Output), "kim@example.com (accepted)") {
		t.Fatalf("%v %s", err, r.Output)
	}
	in := map[string]any{"subject": "Focus", "start": "2026-11-05T10:00:00+01:00", "end": "2026-11-05T11:00:00+01:00"}
	r, err = call(m, "create_event", in, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.lastQ.Get("sendUpdates") != "none" || f.lastBody["attendees"] != nil {
		t.Fatal(f.lastQ, f.lastBody)
	}
	if r.Undo == nil || r.Undo.Action != "delete_event" || string(r.Undo.Input) != `{"calendar":"primary","id":"evnew1"}` {
		t.Fatalf("%+v", r.Undo)
	}
	in["attendees"] = []string{"kim@example.com"}
	in["online"] = true
	if _, err := call(m, "schedule_meeting", in, false); err != nil {
		t.Fatal(err)
	}
	if f.lastQ.Get("sendUpdates") != "all" || f.lastQ.Get("conferenceDataVersion") != "1" || f.lastBody["conferenceData"] == nil {
		t.Fatal(f.lastQ, f.lastBody)
	}
	p, err := call(m, "delete_event", map[string]any{"id": "evnew1"}, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "(1 attendees get a cancellation)") || strings.Contains(p.Plan.Summary, "Focus") {
		t.Fatalf("%v %+v", err, p.Plan)
	}
	if _, err := call(m, "delete_event", map[string]any{"id": "evnew1"}, false); err != nil || f.lastQ.Get("sendUpdates") != "all" {
		t.Fatal(err, f.lastQ)
	}
	r, err = call(m, "delete_event", map[string]any{"id": "evold"}, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%v %s", err, r.Output)
	}
	r, err = call(m, "files", map[string]any{"name": "Bud'get", "folder": "1folderxxxxx"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if q := f.lastQ.Get("q"); q != `trashed = false and '1folderxxxxx' in parents and name contains 'Bud\'get'` {
		t.Fatal(q)
	}
	if !strings.Contains(string(r.Output), `"folder":true`) || !strings.Contains(string(r.Output), `"size":12`) {
		t.Fatal(string(r.Output))
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	m, f := setup(t, oauthCfg)
	f.redirect = other.URL + "/x"
	if _, err := call(m, "files", nil, false); !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("followed")
	}
}

func TestEventPreviews(t *testing.T) {
	m, _ := setup(t, oauthCfg)
	in := map[string]any{"subject": "Review", "start": "2026-11-05T10:00:00+01:00", "end": "2026-11-05T11:00:00+01:00",
		"attendees": []string{"kim@example.com"}, "body": "Agenda: the numbers"}
	r, err := call(m, "schedule_meeting", in, true)
	if err != nil || !strings.Contains(string(r.Plan.Changes[0].After), "Agenda: the numbers") {
		t.Fatalf("%v %+v", err, r.Plan)
	}
	p, err := call(m, "delete_event", map[string]any{"id": "evseries"}, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "whole recurring series") || strings.Contains(p.Plan.Summary, "Weekly") {
		t.Fatalf("%v %+v", err, p.Plan)
	}
}
