package stalwart

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

type fakeStalwart struct {
	old bool // a server before 0.16: no management capability
	// account is the session's primary account id ("b" when empty).
	account string
	forbid  string

	mu    sync.Mutex
	seen  []string
	calls []string
}

var objects = map[string]map[string]string{
	"Domain": {
		"d1": `{"id":"d1","name":"example.com","aliases":{"example.net":true},"enable":true,"createdAt":"2026-01-01T00:00:00Z","dkimManagement":{"@type":"Automatic","algorithms":{"Dkim1RsaSha256":true}},
			"certificateManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"},"catchAllAddress":"LEAKMEcatch@example.com","dnsZoneFile":"LEAKME zone","privateKey":"-----BEGIN PRIVATE KEY-----LEAKME"}`,
		"d2": `{"id":"d2","name":"other.org","enable":false,"dkimManagement":{"@type":"Manual"}}`,
	},
	"Account": {
		"a1": `{"id":"a1","@type":"User","name":"jane","domainId":"d1","emailAddress":"jane@example.com","usedDiskQuota":250,"quotas":{"maxDiskQuota":1000},"roles":{"@type":"Admin"},
			"memberGroupIds":{"a3":true},"aliases":{"0":{"name":"j","domainId":"d2","enable":true},"1":{"name":"old","domainId":"d1","enable":false}},
			"credentials":{"0":{"@type":"Password","secret":"$argon2id$v=19$LEAKMEhash","otpUrl":"otpauth://totp/LEAKME?secret=LEAKMETOTP"},"1":{"@type":"AppPassword","secret":"LEAKMEapp"}}}`,
		"a2": `{"id":"a2","@type":"User","name":"bob","domainId":"d2","emailAddress":"bob@other.org","usedDiskQuota":0,"roles":{"@type":"User"}}`,
		"a3": `{"id":"a3","@type":"Group","name":"staff","domainId":"d1","emailAddress":"staff@example.com","roles":{"@type":"Default"}}`,
	},
	"QueuedMessage": {
		"q1": `{"id":"q1","createdAt":"2026-11-04T08:00:00Z","nextRetry":"2026-11-04T09:00:00Z","returnPath":"LEAKMEsender@example.com","size":2048,"blobId":"LEAKMEblob","receivedFromIp":"192.0.2.1",
			"recipients":{"LEAKMErcpt@far.example.org":{"queueName":"remote","status":{"@type":"TemporaryFailure","errorMessage":"LEAKME 450 mailbox busy"}},"x@far.example.org":{"queueName":"remote","status":{"@type":"Scheduled"}}}}`,
		"q2": `{"id":"q2","createdAt":"2026-11-04T07:00:00Z","returnPath":"","size":100,"recipients":{"y@near.example.net":{"queueName":"local"}}}`,
	},
}

func (f *fakeStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, pw, basic := r.BasicAuth()
	if r.Header.Get("Authorization") != "Bearer API_good" && !(basic && user == "admin" && pw == "pw") {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"about:blank","status":401,"title":"Unauthorized","detail":"You have to authenticate first."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /jmap/session":
		caps := `"urn:ietf:params:jmap:core":{},"urn:stalwart:jmap":{}`
		if f.old {
			caps = `"urn:ietf:params:jmap:core":{}`
		}
		acct := f.account
		if acct == "" {
			acct = "b"
		}
		fmt.Fprintf(w, `{"capabilities":{%s},"username":"admin","primaryAccounts":{"urn:ietf:params:jmap:core":%q,"urn:stalwart:jmap":%q},"apiUrl":"https://evil.example/jmap/"}`, caps, acct, acct)
	case "POST /jmap/":
		var req struct {
			Using       []string            `json:"using"`
			MethodCalls [][]json.RawMessage `json:"methodCalls"`
		}
		json.Unmarshal(body, &req)
		var name string
		var args struct {
			AccountID  string   `json:"accountId"`
			IDs        []string `json:"ids"`
			Properties []string `json:"properties"`
		}
		json.Unmarshal(req.MethodCalls[0][0], &name)
		json.Unmarshal(req.MethodCalls[0][1], &args)
		f.calls = append(f.calls, name)
		obj, method, _ := strings.Cut(strings.TrimPrefix(name, "x:"), "/")
		if args.AccountID != "b" || len(req.Using) != 2 || req.Using[1] != "urn:stalwart:jmap" {
			io.WriteString(w, `{"methodResponses":[["error",{"type":"invalidArguments"},"c0"]]}`)
			return
		}
		if obj == f.forbid {
			io.WriteString(w, `{"methodResponses":[["error",{"type":"forbidden","description":"token=AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"c0"]]}`)
			return
		}
		objs := objects[obj]
		switch method {
		case "query":
			ids := []string{}
			for id := range objs {
				ids = append(ids, id)
			}
			out, _ := json.Marshal(map[string]any{"ids": ids, "total": len(ids), "accountId": "b"})
			fmt.Fprintf(w, `{"methodResponses":[[%q,%s,"c0"]]}`, name, out)
		case "get":
			if len(args.Properties) == 0 {
				io.WriteString(w, `{"methodResponses":[["error",{"type":"invalidArguments","description":"the test wants properties"},"c0"]]}`)
				return
			}
			var list []string
			for _, id := range args.IDs {
				if o, ok := objs[id]; ok {
					list = append(list, o)
				}
			}
			fmt.Fprintf(w, `{"methodResponses":[[%q,{"accountId":"b","list":[%s],"notFound":[]},"c0"]]}`, name, strings.Join(list, ","))
		default:
			io.WriteString(w, `{"methodResponses":[["error",{"type":"unknownMethod"},"c0"]]}`)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config, f *fakeStalwart) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL + cfg.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://key": "API_good", "secret://pw": "pw", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestStalwart(t *testing.T) {
	f := &fakeStalwart{}
	m := setup(t, Config{URL: "/jmap", Token: "secret://key"}, f)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "signed in as admin · 2 domains" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"domains", `{}`, `"aliases":["example.net"]`},
		{"domains", `{}`, `"dkim":"Automatic"`},
		{"domains", `{}`, `"catchAll":true`},
		{"accounts", `{}`, `"total":3`},
		{"accounts", `{}`, `"aliases":["j@other.org"]`},
		{"accounts", `{}`, `"percentUsed":25`},
		{"accounts", `{}`, `"role":"Admin"`},
		{"accounts", `{"type":"group"}`, `"name":"staff"`},
		{"queue", `{}`, `"recipientsByStatus":{"Scheduled":2,"TemporaryFailure":1}`},
		{"queue", `{}`, `"byRecipientDomain":[{"count":2,"domain":"far.example.org"},{"count":1,"domain":"near.example.net"}]`},
		{"queue", `{}`, `"oldest":"2026-11-04T07:00:00Z"`},
		{"queue", `{}`, `"totalBytes":2148`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "argon2") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	for _, s := range f.seen {
		if strings.Contains(s, "credentials") || strings.Contains(s, "blobId") || strings.Contains(s, "dnsZoneFile") {
			t.Fatalf("asked for secret material: %s", s)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "accounts" || a.Name == "queue") != a.Sensitive || a.Risk != sdk.RiskRead {
			t.Fatalf("%s: %+v", a.Name, a)
		}
	}

	basic := setup(t, Config{Username: "admin", Password: "secret://pw"}, &fakeStalwart{})
	if h := basic.Health(context.Background(), "s"); h.Status != "ok" {
		t.Fatalf("basic: %+v", h)
	}
	old := setup(t, Config{Token: "secret://key"}, &fakeStalwart{old: true})
	if _, err := invoke(old, "domains", `{}`); err == nil || !strings.Contains(err.Error(), "0.16") {
		t.Fatal(err)
	}
	ff := &fakeStalwart{forbid: "QueuedMessage"}
	forbidden := setup(t, Config{Token: "secret://key"}, ff)
	if _, err := invoke(forbidden, "queue", `{}`); err == nil || !strings.Contains(err.Error(), "sysQueuedMessageGet") || strings.Contains(err.Error(), "AAAA") {
		t.Fatal(err)
	}
}

func TestStalwartValidation(t *testing.T) {
	f := &fakeStalwart{}
	m := setup(t, Config{Token: "secret://key"}, f)
	for _, c := range []struct{ action, in string }{
		{"accounts", `{"search":"a\nb"}`},
		{"accounts", `{"type":"robot"}`},
		{"accounts", `{"limit":0}`},
		{"accounts", `{"limit":5000}`},
		{"delete_account", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://mail.example.com", Token: "plain"},
		{URL: "https://mail.example.com", Username: "admin", Password: "plain"},
		{URL: "https://mail.example.com", Username: "ad:min", Password: "secret://pw"},
		{URL: "https://mail.example.com", Token: "secret://key", Username: "admin", Password: "secret://pw"},
		{URL: "https://mail.example.com"},
		{URL: "mail.example.com", Token: "secret://key"},
		{URL: "https://u:p@mail.example.com", Token: "secret://key"},
		{URL: "https://mail.example.com?x=1", Token: "secret://key"},
		{URL: "https://mail.example.com#x", Token: "secret://key"},
		{URL: "https://mail.example.com", Token: "secret://key", Fingerprint: "nothex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad := setup(t, Config{Token: "secret://bad"}, &fakeStalwart{})
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Stalwart refused the credentials" {
		t.Fatalf("%+v", h)
	}
}

func TestStalwartRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// An account id that isn't a plain JMAP id is never sent.
func TestStalwartBadAccountID(t *testing.T) {
	f := &fakeStalwart{account: "../b"}
	m := setup(t, Config{Token: "secret://key"}, f)
	if _, err := invoke(m, "domains", `{}`); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatal(err)
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "POST") {
			t.Fatalf("called with a bad account: %s", s)
		}
	}
}
