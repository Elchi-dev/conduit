package okta

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

type fakeOkta struct {
	mu     sync.Mutex
	seen   []string
	status map[string]string
}

var logins = map[string]string{"00uself000001": "svc@acme.test", "00ualice00001": "alice@acme.test", "00ubob0000001": "bob@acme.test", "00uadmin00001": "root@acme.test"}

func (f *fakeOkta) user(id string) string {
	return fmt.Sprintf(`{"id":%q,"status":%q,"created":"2026-01-01T00:00:00.000Z","lastLogin":"2026-11-03T08:00:00.000Z","profile":{"login":%q,"firstName":"First","lastName":"Last","email":%q},"credentials":{"password":{},"recovery_question":{"question":"pet","answer":"LEAKME"}}}`,
		id, f.status[id], logins[id], logins[id])
}

func (f *fakeOkta) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "SSWS otok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == "GET" && path == "/users/me":
		io.WriteString(w, f.user("00uself000001"))
	case r.Method == "GET" && path == "/users":
		if q.Get("after") == "" {
			w.Header().Set("Link", `<http://`+r.Host+`/api/v1/users?after=00ubob0000001&limit=200>; rel="next"`)
			fmt.Fprintf(w, "[%s,%s]", f.user("00ualice00001"), f.user("00uadmin00001"))
			return
		}
		fmt.Fprintf(w, "[%s]", f.user("00ubob0000001"))
	case r.Method == "GET" && path == "/groups":
		io.WriteString(w, `[{"id":"00g1","type":"BUILT_IN","profile":{"name":"Everyone","description":"All users"},"_embedded":{"stats":{"usersCount":4}}},{"id":"00g2","type":"OKTA_GROUP","profile":{"name":"Engineering"}}]`)
	case r.Method == "GET" && path == "/apps":
		io.WriteString(w, `[{"id":"0oa1","name":"oidc_client","label":"Grafana","status":"ACTIVE","signOnMode":"OPENID_CONNECT","credentials":{"oauthClient":{"client_id":"abc","client_secret":"LEAKME"},"signing":{"kid":"LEAKME"}}}]`)
	case r.Method == "GET" && strings.HasSuffix(path, "/roles"):
		if strings.Contains(path, "00uadmin00001") {
			io.WriteString(w, `[{"type":"SUPER_ADMIN","label":"Super Administrator"}]`)
			return
		}
		io.WriteString(w, `[]`)
	case r.Method == "GET" && strings.HasPrefix(path, "/users/"):
		key := strings.TrimPrefix(path, "/users/")
		for id, l := range logins {
			if id == key || l == key {
				io.WriteString(w, f.user(id))
				return
			}
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"errorCode":"E0000007","errorSummary":"Not found"}`)
	case r.Method == "POST" && strings.HasSuffix(path, "/lifecycle/suspend"):
		f.status[strings.Split(path, "/")[2]] = "SUSPENDED"
	case r.Method == "POST" && strings.HasSuffix(path, "/lifecycle/unsuspend"):
		f.status[strings.Split(path, "/")[2]] = "ACTIVE"
	case r.Method == "DELETE" && strings.HasSuffix(path, "/sessions"):
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string, allowAdmins bool) (*Module, *fakeOkta) {
	f := &fakeOkta{status: map[string]string{"00uself000001": "ACTIVE", "00ualice00001": "ACTIVE", "00ubob0000001": "SUSPENDED", "00uadmin00001": "ACTIVE"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{OrgURL: "https://acme-admin.okta.com/", Token: tok, AllowAdmins: allowAdmins})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://o": "otok", "secret://bad": "x"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOkta(t *testing.T) {
	m, f := setup(t, "secret://o", false)
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as svc@acme.test · acme.okta.com" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"users", `{}`, `"count":3`},
		{"users", `{}`, `"byStatus":{"active":2,"suspended":1}`},
		{"users", `{"status":"SUSPENDED","limit":5}`, `"count":1`},
		{"users", `{"includeEmail":true}`, `"email":"alice@acme.test"`},
		{"groups", `{}`, `"members":4`},
		{"groups", `{}`, `"type":"okta"`},
		{"apps", `{"search":"graf"}`, `"signOnMode":"OPENID_CONNECT"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "otok") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if r, _ := invoke(m, "users", `{}`, false); strings.Contains(string(r.Output), `"email"`) {
		t.Fatal("emails without being asked")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if (strings.Contains(a.Name, "_")) != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	// Suspend alice by login: preview, then for real, then undo.
	r, err := invoke(m, "suspend_user", `{"user":"alice@acme.test"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Suspend alice@acme.test" || f.status["00ualice00001"] != "ACTIVE" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "suspend_user", `{"user":"alice@acme.test"}`, false)
	if err != nil || f.status["00ualice00001"] != "SUSPENDED" || r.Undo == nil || r.Undo.Action != "unsuspend_user" || string(r.Undo.Input) != `{"user":"00ualice00001"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["00ualice00001"] != "ACTIVE" || r.Undo.Action != "suspend_user" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "unsuspend_user", `{"user":"00ualice00001"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	r, err = invoke(m, "reset_sessions", `{"user":"00ubob0000001","revokeTokens":true}`, false)
	if err != nil || !strings.Contains(f.seen[len(f.seen)-1], "DELETE /api/v1/users/00ubob0000001/sessions?oauthTokens=true") {
		t.Fatalf("%s %v %v", r.Output, err, f.seen)
	}
	// Refusals: the token's own user, an admin.
	for _, c := range []struct{ action, in, want string }{
		{"suspend_user", `{"user":"00uself000001"}`, "own user"},
		{"reset_sessions", `{"user":"svc@acme.test"}`, "own user"},
		{"suspend_user", `{"user":"root@acme.test"}`, "admin role"},
		{"reset_sessions", `{"user":"00uadmin00001"}`, "admin role"},
		{"suspend_user", `{"user":"mallory@acme.test"}`, "no user"},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s %s: %v", c.action, c.in, err)
		}
	}
	if f.status["00uadmin00001"] != "ACTIVE" {
		t.Fatal("admin suspended")
	}
	allow, af := setup(t, "secret://o", true)
	if _, err := invoke(allow, "suspend_user", `{"user":"root@acme.test"}`, false); err != nil || af.status["00uadmin00001"] != "SUSPENDED" {
		t.Fatalf("allowAdmins: %v", err)
	}
	if _, err := invoke(allow, "suspend_user", `{"user":"00uself000001"}`, false); err == nil {
		t.Fatal("suspended its own user")
	}
}

func TestOktaValidation(t *testing.T) {
	m, f := setup(t, "secret://o", false)
	for _, c := range []struct{ action, in string }{
		{"suspend_user", `{}`},
		{"suspend_user", `{"user":"../../groups"}`},
		{"suspend_user", `{"user":"a b"}`},
		{"unsuspend_user", `{"user":"x?y=1"}`},
		{"reset_sessions", `{"user":"x#y"}`},
		{"users", `{"status":"GONE"}`},
		{"users", `{"limit":1000}`},
		{"users", `{"search":"a\nb"}`},
		{"groups", `{"search":"` + strings.Repeat("a", 300) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{OrgURL: "https://acme.okta.com", Token: "plaintoken"},
		{OrgURL: "http://acme.okta.com", Token: "secret://o"},
		{OrgURL: "https://okta.com.evil.test", Token: "secret://o"},
		{OrgURL: "https://acme.okta.com.evil.test", Token: "secret://o"},
		{OrgURL: "https://evilokta.com", Token: "secret://o"},
		{OrgURL: "https://a.b.okta.com", Token: "secret://o"},
		{OrgURL: "https://okta.com", Token: "secret://o"},
		{OrgURL: "https://user:pw@acme.okta.com", Token: "secret://o"},
		{OrgURL: "https://acme.okta.com:8443", Token: "secret://o"},
		{OrgURL: "https://acme.okta.com/api/v1?x=1", Token: "secret://o"},
		{OrgURL: "https://acme.okta.com/#frag", Token: "secret://o"},
		{OrgURL: "https://acme.okta.com/path", Token: "secret://o"},
		{OrgURL: "", Token: "secret://o"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for in, want := range map[string]string{"acme.okta.com": "acme.okta.com", "https://ACME.oktapreview.com/": "acme.oktapreview.com", "dev-1-admin.okta.com": "dev-1.okta.com", "acme.okta-emea.com": "acme.okta-emea.com"} {
		if got, err := orgHost(in); err != nil || got != want {
			t.Fatalf("%s: %s %v", in, got, err)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Okta refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestOktaRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{OrgURL: "acme.okta.com", Token: "secret://o"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://o": "otok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
