package mailu

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

type fakeMailu struct {
	mu      sync.Mutex
	seen    []string
	enabled map[string]bool
	admins  map[string]bool
}

func (f *fakeMailu) user(addr string) string {
	return fmt.Sprintf(`{"email":%q,"password":"$bcrypt-sha256$v=2,t=2b,r=12$LEAKMEhash","comment":"","quota_bytes":1000000000,"quota_bytes_used":250000000,
		"global_admin":%v,"enabled":%v,"enable_imap":true,"enable_pop":false,"forward_enabled":true,"forward_destination":["LEAKME@elsewhere.example"],
		"reply_enabled":true,"reply_subject":"LEAKME subject","reply_body":"LEAKME body","displayed_name":"Name %s","spam_enabled":true,"spam_threshold":80}`,
		addr, f.admins[addr], f.enabled[addr], addr)
}

func (f *fakeMailu) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Authorization") {
	case "Bearer mut":
	case "":
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"A valid Authorization header is mandatory"}`)
		return
	default:
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"Invalid API token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch p := r.Method + " " + r.URL.EscapedPath(); {
	case p == "GET /api/v1/domain":
		io.WriteString(w, `[{"name":"example.com","comment":"main","managers":["jane@example.com"],"max_users":-1,"max_aliases":10,"max_quota_bytes":0,"signup_enabled":false,"alternatives":["example.net"],
			"dns_dkim":"dkim._domainkey IN TXT v=DKIM1; p=LEAKMEdkim","dkim_private":"-----BEGIN PRIVATE KEY-----LEAKME"}]`)
	case p == "GET /api/v1/user":
		fmt.Fprintf(w, `[%s,%s,%s]`, f.user("jane@example.com"), f.user("bob@other.org"), f.user("boss@example.com"))
	case strings.HasPrefix(p, "GET /api/v1/user/"):
		addr := strings.TrimPrefix(r.URL.Path, "/api/v1/user/")
		if _, ok := f.enabled[addr]; !ok {
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"code":404,"message":"User %s cannot be found"}`, addr)
			return
		}
		io.WriteString(w, f.user(addr))
	case strings.HasPrefix(p, "PATCH /api/v1/user/"):
		addr := strings.TrimPrefix(r.URL.Path, "/api/v1/user/")
		var b struct {
			Enabled *bool `json:"enabled"`
		}
		json.Unmarshal(body, &b)
		if b.Enabled != nil {
			f.enabled[addr] = *b.Enabled
		}
		fmt.Fprintf(w, `{"code":200,"message":"User %s has been updated"}`, addr)
	case p == "GET /api/v1/alias":
		io.WriteString(w, `[{"email":"info@example.com","destination":["jane@example.com"],"wildcard":false,"disabled":false,"comment":"front desk"},{"email":"x%@other.org","destination":["bob@other.org"],"wildcard":true}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string, allowAdmin bool) (*Module, *fakeMailu) {
	f := &fakeMailu{enabled: map[string]bool{"jane@example.com": true, "bob@other.org": false, "boss@example.com": true, "postmaster@example.com": true},
		admins: map[string]bool{"boss@example.com": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/admin", Token: tok, AllowAdminAccounts: allowAdmin})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mu": "mut", "secret://bad": "nope"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMailu(t *testing.T) {
	m, f := setup(t, "secret://mu", false)
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "1 domains" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"domains", `{}`, `"alternatives":["example.net"]`},
		{"domains", `{}`, `"managers":1`},
		{"users", `{}`, `"usedBytes":250000000`},
		{"users", `{}`, `"percentUsed":25`},
		{"users", `{"enabled":false}`, `"total":1`},
		{"users", `{"domain":"other.org"}`, `"email":"bob@other.org"`},
		{"aliases", `{}`, `"destination":["jane@example.com"]`},
		{"aliases", `{"domain":"other.org"}`, `"wildcard":true`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "bcrypt") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users" || a.Name == "aliases") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_user") && (a.Risk != sdk.RiskDestructive || !a.Reversible || !a.DryRun) {
			t.Fatalf("%s: %+v", a.Name, a)
		}
	}

	r, err := invoke(m, "disable_user", `{"email":"Jane@Example.com"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable jane@example.com" || !f.enabled["jane@example.com"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "disable_user", `{"email":"jane@example.com"}`, false)
	if err != nil || f.enabled["jane@example.com"] || r.Undo == nil || r.Undo.Action != "enable_user" || string(r.Undo.Input) != `{"email":"jane@example.com"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.enabled["jane@example.com"] || r.Undo.Action != "disable_user" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "enable_user", `{"email":"jane@example.com"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "disable_user", `{"email":"mallory@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "no user") {
		t.Fatal(err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "disable_user", `{"email":"postmaster@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "role account") || len(f.seen) != n {
		t.Fatalf("role account: %v", err)
	}
	if _, err := invoke(m, "disable_user", `{"email":"boss@example.com"}`, false); err == nil || !strings.Contains(err.Error(), "global administrator") || !f.enabled["boss@example.com"] {
		t.Fatalf("admin: %v", err)
	}
	adm, af := setup(t, "secret://mu", true)
	if _, err := invoke(adm, "disable_user", `{"email":"boss@example.com"}`, false); err != nil || af.enabled["boss@example.com"] {
		t.Fatalf("allowed admin: %v", err)
	}
}

func TestMailuValidation(t *testing.T) {
	m, f := setup(t, "secret://mu", false)
	for _, c := range []struct{ action, in string }{
		{"disable_user", `{}`},
		{"disable_user", `{"email":"jane"}`},
		{"disable_user", `{"email":"jane@example.com/../../domain"}`},
		{"enable_user", `{"email":"../alias@example.com"}`},
		{"enable_user", `{"email":"jane@example.com?x=1"}`},
		{"users", `{"domain":"example.com/../x"}`},
		{"aliases", `{"domain":"%2e%2e"}`},
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
		{URL: "https://mail.example.com", Token: "plain"},
		{URL: "ftp://mail.example.com", Token: "secret://mu"},
		{URL: "https://u:p@mail.example.com", Token: "secret://mu"},
		{URL: "https://mail.example.com/?a=b", Token: "secret://mu"},
		{URL: "https://mail.example.com/#f", Token: "secret://mu"},
		{URL: "https://mail.example.com", Token: "secret://mu", Fingerprint: "nothex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || h.Message != "Mailu refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestMailuRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://mu"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mu": "mut"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
