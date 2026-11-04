package mailcow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeMailcow struct {
	mu     sync.Mutex
	seen   []string
	active map[string]string
	flush  int
	// flushBody is the last /edit/mailq body.
	flushBody string
	aliasFail bool
}

func (f *fakeMailcow) box(addr string) string {
	local, dom, _ := strings.Cut(addr, "@")
	return fmt.Sprintf(`{"username":%q,"name":"Name %s","domain":%q,"local_part":%q,"active":%q,"quota":3221225472,"quota_used":1073741824,"percent_in_use":33,"messages":120,
		"password":"{BLF-CRYPT}$2y$10$LEAKMEhash","attributes":{"force_pw_update":"0","tfa_secret":"LEAKMETOTP"},"sender_acl":["LEAKME@x.example"]}`, addr, local, dom, local, f.active[addr])
}

func (f *fakeMailcow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "mck" {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"error","msg":"authentication failed"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch p := r.Method + " " + r.URL.EscapedPath(); {
	case p == "GET /api/v1/get/status/version":
		io.WriteString(w, `{"version":"2025-09"}`)
	case p == "GET /api/v1/get/status/containers":
		io.WriteString(w, `{"postfix-mailcow":{"container":"postfix-mailcow","image":"mailcow/postfix:1.80","started_at":"2026-11-01T00:00:00Z","state":"running","type":"info"},
			"dovecot-mailcow":{"container":"dovecot-mailcow","image":"mailcow/dovecot:2.3","state":"exited","type":"info"}}`)
	case p == "GET /api/v1/get/domain/all":
		io.WriteString(w, `[{"active":"1","aliases_in_domain":2,"backupmx":"0","bytes_total":"5076666944","description":"Main","domain_name":"example.com","mboxes_in_domain":3,
			"max_num_mboxes_for_domain":10,"max_num_aliases_for_domain":400,"max_quota_for_domain":10737418240,"quota_used_in_domain":"1073741824","msgs_total":"172440","relay_all_recipients":"0",
			"dkim_private":"-----BEGIN PRIVATE KEY-----LEAKME"}]`)
	case p == "GET /api/v1/get/mailbox/all", p == "GET /api/v1/get/mailbox/all/example.com":
		fmt.Fprintf(w, `[%s,%s,%s]`, f.box("jane@example.com"), f.box("bob@example.com"), f.box("postmaster@example.com"))
	case strings.HasPrefix(p, "GET /api/v1/get/mailbox/"):
		addr := strings.TrimPrefix(r.URL.Path, "/api/v1/get/mailbox/")
		if _, ok := f.active[addr]; !ok {
			io.WriteString(w, `{}`)
			return
		}
		io.WriteString(w, f.box(addr))
	case p == "GET /api/v1/get/alias/all" && f.aliasFail:
		w.WriteHeader(500)
	case p == "GET /api/v1/get/alias/all":
		io.WriteString(w, `[{"active":"1","address":"info@example.com","domain":"example.com","goto":"jane@example.com,bob@example.com","id":6,"is_catch_all":0},
			{"active":"0","address":"@other.org","domain":"other.org","goto":"jane@example.com","id":10,"is_catch_all":1},
			{"active":"1","address":"Abuse@other.org","domain":"other.org","goto":"x@far.example, CAROL@example.com","id":11,"is_catch_all":0}]`)
	case p == "GET /api/v1/get/quarantine/all":
		io.WriteString(w, `[{"created":1572688831,"id":33,"notified":1,"qid":"8224615004C1","rcpt":"jane@example.com","score":15.48,"sender":"bounces@spam.example.net","subject":"LEAKME subject","virus_flag":0,"msg":"LEAKME body"},
			{"created":1572688900,"id":34,"rcpt":"bob@example.com","score":3,"sender":"x@spam.example.net","subject":"LEAKME too","virus_flag":1}]`)
	case p == "GET /api/v1/get/mailq/all":
		io.WriteString(w, `[{"arrival_time":1570091234,"message_size":1848,"queue_id":"B98C6260CA1","queue_name":"deferred","recipients":["LEAKMErcpt@far.example.org"],"sender":"LEAKMEsender@example.com"},
			{"arrival_time":1570091000,"message_size":100,"queue_id":"B98C6260CA2","queue_name":"hold","recipients":[{"address":"x@far.example.org","delay_reason":"LEAKME"}],"sender":"y@example.com"}]`)
	case p == "POST /api/v1/edit/mailq":
		f.flush++
		f.flushBody = string(body)
		io.WriteString(w, `{"type":"success","msg":"Task completed"}`)
	case p == "POST /api/v1/edit/mailbox":
		var b struct {
			Items []string `json:"items"`
			Attr  struct {
				Active string `json:"active"`
			} `json:"attr"`
		}
		json.Unmarshal(body, &b)
		for _, it := range b.Items {
			f.active[it] = b.Attr.Active
		}
		io.WriteString(w, `[{"type":"success","log":["mailbox","edit","mailbox",{"password":"*"}],"msg":["mailbox_modified","x"]}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"type":"error","msg":"route not found"}`)
	}
}

func setup(t *testing.T, key string, allowAdmin bool) (*Module, *fakeMailcow) {
	f := &fakeMailcow{active: map[string]string{"jane@example.com": "1", "bob@example.com": "0", "postmaster@example.com": "1", "carol@example.com": "1", "dave@example.com": "2", "odd@example.com": "&#10004;"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", APIKey: key, AllowAdminAccounts: allowAdmin})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": "mck", "secret://bad": "nope"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMailcow(t *testing.T) {
	m, f := setup(t, "secret://mc", false)
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "mailcow 2025-09 · 1 domains" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"running":1`},
		{"domains", `{}`, `"maxMailboxes":10`},
		{"mailboxes", `{}`, `"usedBytes":1073741824`},
		{"mailboxes", `{"active":false}`, `"total":1`},
		{"mailboxes", `{"domain":"Example.com"}`, `"address":"jane@example.com"`},
		{"aliases", `{}`, `"goto":["jane@example.com","bob@example.com"]`},
		{"aliases", `{"domain":"other.org"}`, `"catchAll":true`},
		{"quarantine", `{}`, `"bySenderDomain":[{"count":2,"domain":"spam.example.net"}]`},
		{"quarantine", `{}`, `"virus":1`},
		{"queue", `{}`, `"byQueue":{"deferred":1,"hold":1}`},
		{"queue", `{}`, `"byRecipientDomain":[{"count":2,"domain":"far.example.org"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "$2y$") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		want := a.Name == "mailboxes" || a.Name == "aliases" || a.Name == "quarantine" || a.Name == "queue"
		if want != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_mailbox") && (a.Risk != sdk.RiskDestructive || !a.Reversible || !a.DryRun) {
			t.Fatalf("%s: %+v", a.Name, a)
		}
	}

	// Flush: a dry run doesn't call, the flush does.
	r, err := invoke(m, "flush_queue", `{}`, true)
	if err != nil || r.Plan == nil || f.flush != 0 || !strings.Contains(r.Plan.Summary, "1 queued") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err = invoke(m, "flush_queue", `{}`, false); err != nil || f.flush != 1 || !strings.Contains(string(r.Output), `"after":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// mailcow reads an edit's fields from "attr".
	var fb struct {
		Attr struct {
			Action string `json:"action"`
		} `json:"attr"`
	}
	if json.Unmarshal([]byte(f.flushBody), &fb) != nil || fb.Attr.Action != "flush" {
		t.Fatalf("flush body %s", f.flushBody)
	}

	r, err = invoke(m, "disable_mailbox", `{"mailbox":"Jane@Example.com"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable jane@example.com" || f.active["jane@example.com"] != "1" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "disable_mailbox", `{"mailbox":"jane@example.com"}`, false)
	if err != nil || f.active["jane@example.com"] != "0" || r.Undo == nil || r.Undo.Action != "enable_mailbox" || string(r.Undo.Input) != `{"mailbox":"jane@example.com"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.active["jane@example.com"] != "1" || r.Undo.Action != "disable_mailbox" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "disable_mailbox", `{"mailbox":"bob@example.com"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "disable_mailbox", `{"mailbox":"nobody@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "no mailbox") {
		t.Fatal(err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "disable_mailbox", `{"mailbox":"postmaster@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "allowAdminAccounts") || len(f.seen) != n {
		t.Fatalf("role account: %v", err)
	}
	// A +tag, a mailbox a role alias delivers to, an unreadable state, and
	// an alias list that can't be read are refused before any change.
	for _, c := range []struct{ in, want string }{
		{`{"mailbox":"Postmaster+x@example.com"}`, "role account"},
		{`{"mailbox":"carol@example.com"}`, "abuse@other.org"},
		{`{"mailbox":"odd@example.com"}`, "didn't say"},
	} {
		if _, err := invoke(m, "disable_mailbox", c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.in, err)
		}
	}
	f.aliasFail = true
	if _, err := invoke(m, "disable_mailbox", `{"mailbox":"jane@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("alias read failure: %v", err)
	}
	f.aliasFail = false
	if f.active["carol@example.com"] != "1" || f.active["jane@example.com"] != "1" || f.active["odd@example.com"] != "&#10004;" {
		t.Fatalf("changed: %v", f.active)
	}
	// Receive-only (active 2) is put back exactly by undo, both ways.
	r, err = invoke(m, "disable_mailbox", `{"mailbox":"dave@example.com"}`, false)
	if err != nil || f.active["dave@example.com"] != "0" || r.Undo == nil || r.Undo.Action != "enable_mailbox" || string(r.Undo.Input) != `{"mailbox":"dave@example.com","signIn":false}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.active["dave@example.com"] != "2" || r.Undo.Action != "disable_mailbox" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "enable_mailbox", `{"mailbox":"dave@example.com"}`, false)
	if err != nil || f.active["dave@example.com"] != "1" || r.Undo == nil || string(r.Undo.Input) != `{"mailbox":"dave@example.com","signIn":false}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.active["dave@example.com"] != "2" || string(r.Undo.Input) != `{"mailbox":"dave@example.com"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "disable_mailbox", `{"mailbox":"jane@example.com","signIn":false}`, false); err == nil {
		t.Fatal("signIn accepted for disable")
	}
	adm, af := setup(t, "secret://mc", true)
	if _, err := invoke(adm, "disable_mailbox", `{"mailbox":"postmaster@example.com"}`, false); err != nil || af.active["postmaster@example.com"] != "0" {
		t.Fatalf("allowed role account: %v", err)
	}
}

func TestMailcowValidation(t *testing.T) {
	m, f := setup(t, "secret://mc", false)
	for _, c := range []struct{ action, in string }{
		{"disable_mailbox", `{}`},
		{"disable_mailbox", `{"mailbox":"jane"}`},
		{"disable_mailbox", `{"mailbox":"../edit/mailbox@example.com"}`},
		{"enable_mailbox", `{"mailbox":"jane@example.com/../../x"}`},
		{"enable_mailbox", `{"mailbox":"jane@exa mple.com"}`},
		{"enable_mailbox", `{"mailbox":"ja?ne@example.com"}`},
		{"mailboxes", `{"domain":"example.com/../../edit"}`},
		{"aliases", `{"domain":"a\nb"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://mail.example.com", APIKey: "plain"},
		{URL: "mail.example.com", APIKey: "secret://mc"},
		{URL: "https://user:pw@mail.example.com", APIKey: "secret://mc"},
		{URL: "https://mail.example.com/?x=1", APIKey: "secret://mc"},
		{URL: "https://mail.example.com/#x", APIKey: "secret://mc"},
		{URL: "https://mail.example.com", APIKey: "secret://mc", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "mailboxes", `{}`, false); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

// A mailcow message that echoes a credential is redacted before it's cut.
func TestMailcowErrorRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"type":"danger","msg":["access to `+strings.Repeat("x", 190)+` token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}`)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://mc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": "mck"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "domains", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "AAAAAAAAAAAA") {
		t.Fatalf("%v", err)
	}
}

func TestMailcowRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-API-Key")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://mc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mc": "mck"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
