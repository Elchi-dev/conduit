package fastmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const token = "fmu1-TOKEN-LEAKME"

type fakeJMAP struct {
	mu        sync.Mutex
	srv       string
	apiHost   string // replaces the session's API host
	redirect  string
	requests  []string
	calls     [][]any
	uploaded  string
	rejected  bool
	wildFirst bool // a wildcard identity is listed first
}

func (f *fakeJMAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"about:blank","detail":"Bad token `+r.Header.Get("Authorization")+`"}`)
		return
	}
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch r.URL.Path {
	case "/jmap/session":
		host := f.srv
		if f.apiHost != "" {
			host = f.apiHost
		}
		fmt.Fprintf(w, `{"apiUrl":"%s/jmap/api/","uploadUrl":"%s/jmap/upload/{accountId}/","primaryAccounts":{"urn:ietf:params:jmap:mail":"u1a2b3"}}`, host, f.srv)
	case "/jmap/upload/u1a2b3/":
		f.uploaded = string(body)
		io.WriteString(w, `{"accountId":"u1a2b3","blobId":"Gblob1","type":"message/rfc822","size":10}`)
	case "/jmap/api/":
		var req struct {
			Using       []string `json:"using"`
			MethodCalls [][]any  `json:"methodCalls"`
		}
		json.Unmarshal(body, &req)
		var out []string
		for _, mc := range req.MethodCalls {
			f.calls = append(f.calls, mc)
			name, id := mc[0].(string), mc[2].(string)
			args := mc[1].(map[string]any)
			if args["accountId"] != "u1a2b3" {
				out = append(out, fmt.Sprintf(`["error",{"type":"accountNotFound"},%q]`, id))
				continue
			}
			var res string
			switch name {
			case "Mailbox/get":
				res = `{"list":[{"id":"P1","name":"Inbox","role":"inbox","totalEmails":9,"unreadEmails":2},{"id":"P2","name":"Drafts","role":"drafts"},{"id":"P3","name":"Sent","role":"sent"},{"id":"P4","name":"Receipts","parentId":"P1"}]}`
			case "Email/query":
				res = `{"ids":["M1"]}`
			case "Email/get":
				if _, ok := args["#ids"]; ok {
					res = `{"list":[{"id":"M1","threadId":"T1","receivedAt":"2026-11-04T08:00:00Z","from":[{"name":"Kim","email":"kim@example.com"}],"subject":"Hi","preview":"Hello","keywords":{}}]}`
				} else {
					res = `{"list":[{"id":"M1","subject":"Hi","from":[{"email":"kim@example.com"}],"keywords":{"$seen":true},"textBody":[{"partId":"1","type":"text/html"}],"bodyValues":{"1":{"value":"<p>Hello <b>you</b></p>"}},"attachments":[{"name":"a.pdf","type":"application/pdf","size":2048,"blobId":"LEAKME"}]}]}`
				}
			case "Identity/get":
				res = `{"list":[{"id":"I1","email":"me@fastmail.com","name":"Me"},{"id":"I2","email":"*@example.org"}]}`
				if f.wildFirst {
					res = `{"list":[{"id":"I2","email":"*@example.org"},{"id":"I1","email":"me@fastmail.com","name":"Me"}]}`
				}
			case "Email/import":
				res = `{"created":{"m":{"id":"Mnew","blobId":"Gblob1"}}}`
			case "EmailSubmission/set":
				if f.rejected {
					res = `{"notCreated":{"s":{"type":"forbiddenToSend","description":"LEAKME"}}}`
				} else {
					res = `{"created":{"s":{"id":"S1"}}}`
				}
			default:
				out = append(out, fmt.Sprintf(`["error",{"type":"unknownMethod"},%q]`, id))
				continue
			}
			out = append(out, fmt.Sprintf(`[%q,%s,%q]`, name, res, id))
		}
		fmt.Fprintf(w, `{"methodResponses":[%s],"sessionState":"x"}`, strings.Join(out, ","))
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeJMAP) {
	t.Helper()
	f := &fakeJMAP{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.srv = srv.URL
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fm": token, "secret://bad": "nope"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action string, in any, dry bool) (sdk.Result, error) {
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: b, DryRun: dry})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, "TOKEN") || strings.Contains(s, "LEAKME") || strings.Contains(s, "nope") {
		t.Fatalf("leak: %s", s)
	}
}

func TestSettingsRefused(t *testing.T) {
	for _, c := range []Config{{}, {Token: "fmu1-plain"}, {Token: "secret://fm", From: "a@b.c\r\nX: 1"}, {Token: "secret://fm", From: "Me <me@x.com>"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestMailboxesListRead(t *testing.T) {
	m, _ := setup(t, Config{Token: "secret://fm"})
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "Inbox: 9 messages, 2 unread" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "mailboxes", nil, false)
	if err != nil || !strings.Contains(string(r.Output), `"parent":"Inbox"`) {
		t.Fatalf("%v %s", err, r.Output)
	}
	r, err = invoke(m, "mail_list", map[string]any{"unreadOnly": true, "text": "hello"}, false)
	if err != nil || !strings.Contains(string(r.Output), `"unread":true`) || !strings.Contains(string(r.Output), "kim@example.com") {
		t.Fatalf("%v %s", err, r.Output)
	}
	r, err = invoke(m, "mail_read", map[string]any{"id": "M1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	if !strings.Contains(string(r.Output), `"text":"Hello you"`) || !strings.Contains(string(r.Output), "a.pdf") {
		t.Fatal(string(r.Output))
	}
}

func TestSend(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://fm", From: "news@example.org"})
	in := map[string]any{"to": []string{"kim@example.com"}, "bcc": []string{"hidden@example.com"}, "subject": "Hi", "body": "Hello"}
	r, err := invoke(m, "send_mail", in, true)
	// The dry run looks up the identity (to show the real From) but
	// uploads and submits nothing.
	if err != nil || r.Plan.Summary != `Send "Hi" to 2 recipients` || !strings.Contains(string(r.Plan.Changes[0].After), `"from":"news@example.org"`) || f.uploaded != "" || len(f.calls) != 2 {
		t.Fatalf("%v %+v %v", err, r.Plan, f.requests)
	}
	r, err = invoke(m, "send_mail", in, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	if !strings.Contains(f.uploaded, "From: <news@example.org>") || strings.Contains(f.uploaded, "hidden@") {
		t.Fatalf("message %s", f.uploaded)
	}
	sub := f.calls[len(f.calls)-1][1].(map[string]any)
	b, _ := json.Marshal(sub)
	for _, want := range []string{`"identityId":"I2"`, `"emailId":"#m"`, `hidden@example.com`, `"mailboxIds/P3":true`, `"mailboxIds/P2":null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("submission lacks %s: %s", want, b)
		}
	}
	f.rejected = true
	_, err = invoke(m, "send_mail", in, false)
	if err == nil || !strings.Contains(err.Error(), "forbiddenToSend") {
		t.Fatal(err)
	}
	noLeak(t, err.Error())
}

func TestDefaultIdentitySkipsWildcard(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://fm"})
	f.mu.Lock()
	f.wildFirst = true
	f.mu.Unlock()
	r, err := invoke(m, "send_mail", map[string]any{"to": []string{"kim@example.com"}, "subject": "Hi", "body": "Hello"}, true)
	if err != nil || !strings.Contains(string(r.Plan.Changes[0].After), `"from":"me@fastmail.com"`) {
		t.Fatalf("%v %+v", err, r.Plan)
	}
}

func TestInvalidInputNeverReachesServer(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://fm"})
	for _, c := range []struct {
		action string
		in     map[string]any
	}{
		{"mail_read", map[string]any{"id": "M1\"}"}},
		{"mail_list", map[string]any{"mailbox": "../x"}},
		{"mail_list", map[string]any{"text": "a\nb"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com"}, "subject": "x\r\nBcc: e@evil.example", "body": "b"}},
		{"send_mail", map[string]any{"to": []string{"kim@example.com\r\nBcc: e@evil.example"}, "subject": "x", "body": "b"}},
		{"send_mail", map[string]any{"subject": "x", "body": "b"}},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Errorf("%s %v accepted", c.action, c.in)
		}
	}
	if len(f.requests) != 0 {
		t.Fatal(f.requests)
	}
}

func TestBadTokenAndOtherHosts(t *testing.T) {
	m, _ := setup(t, Config{Token: "secret://bad"})
	h := m.Health(context.Background(), "f")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API token") {
		t.Fatalf("%+v", h)
	}
	noLeak(t, h.Message)

	// A session pointing the API at another host is refused.
	m, f := setup(t, Config{Token: "secret://fm"})
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	f.apiHost = other.URL
	if _, err := invoke(m, "mailboxes", nil, false); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatal(err)
	}
	// And so is a redirect.
	m, f = setup(t, Config{Token: "secret://fm"})
	f.redirect = other.URL + "/x"
	if _, err := invoke(m, "mailboxes", nil, false); !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("token sent to another host")
	}
}
