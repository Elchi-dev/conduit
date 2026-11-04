package microsoft365

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	clientID     = "11111111-2222-3333-4444-555555555555"
	clientSecret = "CLIENT-SECRET-VALUE-LEAKME"
	refreshToken = "REFRESH-TOKEN-LEAKME"
)

type fakeGraph struct {
	mu        sync.Mutex
	api       []string // Graph requests
	tokens    []url.Values
	issued    int
	valid     map[string]bool // access tokens Graph accepts
	sent      string          // last sendMail body
	lastBody  map[string]any
	redirect  string
	badSecret bool
}

func (f *fakeGraph) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/token" {
		form, _ := url.ParseQuery(string(body))
		f.tokens = append(f.tokens, form)
		if form.Get("client_secret") != clientSecret || f.badSecret {
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret %s provided"}`, form.Get("client_secret"))
			return
		}
		if form.Get("grant_type") == "refresh_token" && !strings.HasPrefix(form.Get("refresh_token"), "REFRESH") {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		f.issued++
		tok := fmt.Sprintf("ACCESS-%d", f.issued)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"refresh_token":"REFRESH-ROTATED-%d"}`, tok, f.issued)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired"}}`)
		return
	}
	f.api = append(f.api, r.Method+" "+r.URL.EscapedPath())
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	if len(body) > 0 && r.Header.Get("Content-Type") == "application/json" {
		f.lastBody = map[string]any{}
		json.Unmarshal(body, &f.lastBody)
	}
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/v1.0")
	switch {
	case r.Method == "GET" && strings.HasSuffix(p, "/mailFolders/inbox"):
		io.WriteString(w, `{"totalItemCount":12,"unreadItemCount":3}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/mailFolders/inbox/messages"):
		io.WriteString(w, `{"value":[{"id":"AAMkAD1=","receivedDateTime":"2026-11-04T09:00:00Z","from":{"emailAddress":{"name":"Kim","address":"kim@example.com"}},"subject":"Lunch","bodyPreview":"Shall we","isRead":false,"hasAttachments":true}]}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/messages/AAMkAD1="):
		io.WriteString(w, `{"id":"AAMkAD1=","subject":"Lunch","from":{"emailAddress":{"address":"kim@example.com"}},"toRecipients":[{"emailAddress":{"address":"me@contoso.com"}}],"body":{"content":"Shall we eat?"},"hasAttachments":true}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/messages/AAMkAD1=/attachments"):
		io.WriteString(w, `{"value":[{"name":"menu.pdf","contentType":"application/pdf","size":20480,"contentBytes":"LEAKME"}]}`)
	case r.Method == "POST" && strings.HasSuffix(p, "/sendMail"):
		f.sent = string(body)
		w.WriteHeader(202)
	case r.Method == "GET" && strings.HasSuffix(p, "/calendarView"):
		io.WriteString(w, `{"value":[{"id":"EV1","subject":"Standup","start":{"dateTime":"2026-11-05T09:00:00.0000000","timeZone":"UTC"},"end":{"dateTime":"2026-11-05T09:15:00.0000000","timeZone":"UTC"},"attendees":[{"emailAddress":{"address":"kim@example.com"},"status":{"response":"accepted"}}]}]}`)
	case r.Method == "POST" && strings.HasSuffix(p, "/events"):
		io.WriteString(w, `{"id":"EVNEW1","subject":"Focus","start":{"dateTime":"2026-11-05T09:00:00.0000000","timeZone":"UTC"},"end":{"dateTime":"2026-11-05T10:00:00.0000000","timeZone":"UTC"}}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/events/EVNEW1"):
		io.WriteString(w, `{"id":"EVNEW1","isOrganizer":true,"start":{"dateTime":"2026-11-05T09:00:00.0000000","timeZone":"UTC"},"end":{"dateTime":"2026-11-05T10:00:00.0000000","timeZone":"UTC"},"attendees":[{"emailAddress":{"address":"kim@example.com"}}]}`)
	case r.Method == "DELETE" && strings.HasSuffix(p, "/events/EVNEW1"):
		w.WriteHeader(204)
	case r.Method == "POST" && strings.Contains(p, "/channels/"):
		io.WriteString(w, `{"id":"1730000000000","createdDateTime":"2026-11-04T10:00:00Z"}`)
	case r.Method == "GET" && strings.HasSuffix(p, "/drive/root:/Documents/Q%204:/children"):
		io.WriteString(w, `{"value":[{"id":"F1","name":"report.docx","size":1234,"file":{"mimeType":"application/vnd.openxmlformats"}},{"id":"F2","name":"old","folder":{"childCount":2}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":"ItemNotFound","message":"not found"}}`)
	}
}

func secrets() map[string]string {
	return map[string]string{"secret://cs": clientSecret, "secret://rt": refreshToken, "secret://bad": "WRONG"}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeGraph, *httptest.Server) {
	t.Helper()
	f := &fakeGraph{valid: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.TokenURL = srv.URL+"/v1.0", srv.URL+"/token"
	if cfg.Tenant == "" {
		cfg.Tenant = "contoso.onmicrosoft.com"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = clientID
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets()), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, srv
}

func call(m *Module, action string, in any, dry bool) (sdk.Result, error) {
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: b, DryRun: dry})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{clientSecret, refreshToken, "ACCESS-", "REFRESH-ROTATED", "LEAKME"} {
		if strings.Contains(s, bad) {
			t.Fatalf("output leaks %q: %s", bad, s)
		}
	}
}

func TestSettingsRefused(t *testing.T) {
	m := New()
	h := fakehost.New(nil)
	for _, c := range []Config{
		{Tenant: "contoso.com", ClientID: clientID, ClientSecret: "plain", User: "a@contoso.com"},
		{Tenant: "contoso.com", ClientID: clientID, ClientSecret: "secret://cs", RefreshToken: "plain"},
		{Tenant: "contoso.com", ClientID: "not-a-guid", ClientSecret: "secret://cs", User: "a@contoso.com"},
		{Tenant: "evil.com/../x", ClientID: clientID, ClientSecret: "secret://cs", User: "a@contoso.com"},
		{Tenant: "contoso.com", ClientID: clientID, ClientSecret: "secret://cs"},                                                     // app sign-in without a mailbox
		{Tenant: "contoso.com", ClientID: clientID, ClientSecret: "secret://cs", User: "a/../b"},                                     // not a user
		{Tenant: "contoso.com", ClientID: clientID, ClientSecret: "secret://cs", RefreshToken: "secret://rt", User: "a@contoso.com"}, // both
	} {
		raw, _ := json.Marshal(c)
		if err := m.Configure(context.Background(), h, "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestAppSignInMail(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", User: "alex@contoso.com"})
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || !strings.Contains(h.Message, "12 messages") {
		t.Fatalf("health %+v", h)
	}
	r, err := call(m, "mail_list", map[string]any{"unreadOnly": true}, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	if !strings.Contains(string(r.Output), "kim@example.com") {
		t.Fatal(string(r.Output))
	}
	r, err = call(m, "mail_read", map[string]any{"id": "AAMkAD1="}, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	if !strings.Contains(string(r.Output), "menu.pdf") || !strings.Contains(string(r.Output), "Shall we eat?") {
		t.Fatal(string(r.Output))
	}
	if g := f.tokens[0]; g.Get("grant_type") != "client_credentials" || g.Get("scope") != graphScope {
		t.Fatalf("token request %v", g)
	}
	if len(f.tokens) != 1 {
		t.Fatalf("token not cached: %d requests", len(f.tokens))
	}
	if !strings.HasPrefix(f.api[0], "GET /v1.0/users/alex@contoso.com/") {
		t.Fatal(f.api)
	}
	// Spec checks: everything returning personal data is sensitive.
	for _, a := range m.Manifest().Actions {
		if a.Name != "delete_event" && !a.Sensitive {
			t.Errorf("%s isn't sensitive", a.Name)
		}
	}
}

func TestBadCredentials(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://bad", User: "alex@contoso.com"})
	h := m.Health(context.Background(), "m")
	if h.Status != "down" || !strings.Contains(h.Message, "client id or secret") {
		t.Fatalf("health %+v", h)
	}
	noLeak(t, h.Message)
	_, err := call(m, "mail_list", nil, false)
	if err == nil || strings.Contains(err.Error(), "WRONG") {
		t.Fatalf("err %v", err)
	}
	if len(f.api) != 0 {
		t.Fatal("Graph was called without a token")
	}
}

func TestDelegatedRefreshAndRotation(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", RefreshToken: "secret://rt"})
	if _, err := call(m, "events", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := call(m, "events", nil, false); err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 1 || f.tokens[0].Get("refresh_token") != refreshToken || !strings.Contains(f.tokens[0].Get("scope"), "offline_access") {
		t.Fatalf("tokens %v", f.tokens)
	}
	// Graph stops accepting the token: one refresh with the rotated token.
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
	r, err := call(m, "events", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 2 || f.tokens[1].Get("refresh_token") != "REFRESH-ROTATED-1" {
		t.Fatalf("tokens %v", f.tokens)
	}
	if !strings.Contains(string(r.Output), `"start":"2026-11-05T09:00:00Z"`) || !strings.Contains(string(r.Output), "kim@example.com (accepted)") {
		t.Fatal(string(r.Output))
	}
	// An expired token is refreshed before use.
	c, _ := m.set.Get("m")
	c.tok.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := call(m, "events", nil, false); err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 3 {
		t.Fatalf("expired token not refreshed: %d", len(f.tokens))
	}
	if !strings.HasPrefix(f.api[0], "GET /v1.0/me/calendarView") {
		t.Fatal(f.api)
	}
}

func TestSendMail(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", User: "alex@contoso.com"})
	in := map[string]any{"to": []string{"Kim <kim@example.com>"}, "bcc": []string{"boss@example.com"}, "subject": "Grüße", "body": "Hello\nthere"}
	r, err := call(m, "send_mail", in, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan == nil || r.Plan.Summary != `Send "Grüße" to 2 recipients` || len(f.api) != 0 {
		t.Fatalf("plan %+v, api %v", r.Plan, f.api)
	}
	r, err = call(m, "send_mail", in, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	raw, err := base64.StdEncoding.DecodeString(f.sent)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"From: <alex@contoso.com>", "To: \"Kim\" <kim@example.com>", "Bcc: <boss@example.com>", "Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=", "Hello\r\nthere"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("message lacks %q:\n%s", want, raw)
		}
	}
}

func TestInvalidInputNeverReachesGraph(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", RefreshToken: "secret://rt"})
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	later := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	for _, c := range []struct {
		action string
		in     map[string]any
	}{
		{"mail_read", map[string]any{"id": "../users/other"}},
		{"mail_read", map[string]any{"id": ""}},
		{"mail_list", map[string]any{"folder": "inbox/../../x"}},
		{"delete_event", map[string]any{"id": "a/b"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com"}, "subject": "hi\r\nBcc: evil@example.net", "body": "x"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com\r\nBcc: evil@example.net"}, "subject": "hi", "body": "x"}},
		{"send_mail", map[string]any{"to": []string{}, "subject": "hi", "body": "x"}},
		{"create_event", map[string]any{"subject": "x", "start": soon, "end": later, "attendees": []string{"kim@example.com"}}},
		{"create_event", map[string]any{"subject": "x", "start": later, "end": soon}},
		{"create_event", map[string]any{"subject": "x", "start": "tomorrow", "end": later}},
		{"schedule_meeting", map[string]any{"subject": "x", "start": soon, "end": later}},
		{"schedule_meeting", map[string]any{"subject": "x", "start": soon, "end": later, "attendees": []string{"kim@example.com\nX: 1"}}},
		{"post_channel_message", map[string]any{"team": clientID, "channel": "19:abc@thread.tacv2", "message": "hey @channel look"}},
		{"post_channel_message", map[string]any{"team": clientID, "channel": "19:abc@thread.tacv2", "message": "hey @Team look"}},
		{"post_channel_message", map[string]any{"team": clientID, "channel": "19:abc@thread.tacv2", "message": "<at>everyone</at>"}},
		{"post_channel_message", map[string]any{"team": "x/../y", "channel": "19:abc@thread.tacv2", "message": "hi"}},
		{"post_channel_message", map[string]any{"team": clientID, "channel": "general", "message": "hi"}},
		{"files", map[string]any{"path": "Documents/../../other"}},
		{"files", map[string]any{"path": "a:b"}},
	} {
		if _, err := call(m, c.action, c.in, false); err == nil {
			t.Errorf("%s %v accepted", c.action, c.in)
		}
	}
	if len(f.api) != 0 || len(f.tokens) != 0 {
		t.Fatalf("requests made: %v %d", f.api, len(f.tokens))
	}
}

func TestEventsCreateUndo(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", RefreshToken: "secret://rt"})
	in := map[string]any{"subject": "Focus", "start": "2026-11-05T10:00:00+01:00", "end": "2026-11-05T11:00:00+01:00", "attendees": []string{"kim@example.com"}}
	r, err := call(m, "schedule_meeting", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Invite 1 people") {
		t.Fatalf("%v %+v", err, r.Plan)
	}
	r, err = call(m, "schedule_meeting", in, false)
	if err != nil {
		t.Fatal(err)
	}
	st := f.lastBody["start"].(map[string]any)
	if st["dateTime"] != "2026-11-05T09:00:00" || st["timeZone"] != "UTC" || f.lastBody["attendees"] == nil {
		t.Fatalf("body %v", f.lastBody)
	}
	if r.Undo == nil || r.Undo.Action != "delete_event" || string(r.Undo.Input) != `{"id":"EVNEW1"}` {
		t.Fatalf("undo %+v", r.Undo)
	}
	p, err := call(m, "delete_event", map[string]any{"id": "EVNEW1"}, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "1 attendees get a cancellation") || strings.Contains(p.Plan.Summary+string(p.Plan.Changes[0].Before), "kim@") {
		t.Fatalf("%v %+v", err, p.Plan)
	}
	if _, err := call(m, "delete_event", map[string]any{"id": "EVNEW1"}, false); err != nil {
		t.Fatal(err)
	}
	r, err = call(m, "delete_event", map[string]any{"id": "EVGONE"}, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%v %s", err, r.Output)
	}
}

func TestTeamsAndFiles(t *testing.T) {
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", RefreshToken: "secret://rt"})
	in := map[string]any{"team": clientID, "channel": "19:abc_def@thread.tacv2", "message": "Deploy done, thanks @bob (mail ops@example.com)"}
	r, err := call(m, "post_channel_message", in, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "@bob") {
		t.Fatalf("%v %+v", err, r.Plan)
	}
	if _, err := call(m, "post_channel_message", in, false); err != nil {
		t.Fatal(err)
	}
	if b := f.lastBody["body"].(map[string]any); b["contentType"] != "text" {
		t.Fatal(f.lastBody)
	}
	r, err = call(m, "files", map[string]any{"path": "/Documents/Q 4/"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Output), "report.docx") || !strings.Contains(string(r.Output), `"folder":true`) {
		t.Fatal(string(r.Output))
	}
	// App sign-in can't post to Teams.
	m2, f2, _ := setup(t, Config{ClientSecret: "secret://cs", User: "alex@contoso.com"})
	if _, err := call(m2, "post_channel_message", in, false); err == nil || !strings.Contains(err.Error(), "delegated") {
		t.Fatalf("err %v", err)
	}
	if len(f2.api) != 0 {
		t.Fatal(f2.api)
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	m, f, _ := setup(t, Config{ClientSecret: "secret://cs", User: "alex@contoso.com"})
	f.redirect = other.URL + "/steal"
	_, err := call(m, "mail_list", nil, false)
	if !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatalf("err %v", err)
	}
	if hits != 0 {
		t.Fatal("followed the redirect")
	}
}
