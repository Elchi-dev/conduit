package auth0

import (
	"context"
	"encoding/json"
	"fmt"
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

type fakeAuth0 struct {
	mu      sync.Mutex
	seen    []string
	tokens  int
	blocked map[string]bool
}

var users = map[string]string{"auth0|alice": "Alice", "auth0|bob": "Bob", "auth0|root": "Root", "auth0|many": "Many"}

func (f *fakeAuth0) user(id string) string {
	return fmt.Sprintf(`{"user_id":%q,"name":%q,"nickname":"n","email":"%s@acme.test","blocked":%t,"logins_count":3,"identities":[{"provider":"auth0","connection":"Username-Password-Authentication","access_token":"LEAKME"}],"app_metadata":{"k":"LEAKME"}}`,
		id, users[id], strings.ToLower(users[id]), f.blocked[id])
}

func (f *fakeAuth0) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		form, _ := url.ParseQuery(string(body))
		if r.Method != "POST" || form.Get("client_secret") != "csecret" || form.Get("client_id") != "AbCdEfGh1234" || form.Get("audience") != "https://acme.eu.auth0.com/api/v2/" || form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"access_denied","error_description":"Unauthorized csecret"}`)
			return
		}
		f.tokens++
		io.WriteString(w, `{"access_token":"mgmt-token","expires_in":86400,"token_type":"Bearer"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer mgmt-token" {
		w.WriteHeader(401)
		io.WriteString(w, `{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	switch {
	case path == "/tenants/settings":
		io.WriteString(w, `{"friendly_name":"Acme"}`)
	case path == "/users" && r.Method == "GET":
		if strings.Contains(q.Get("fields"), "password") {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"total":3,"users":[%s,%s,%s]}`, f.user("auth0|alice"), f.user("auth0|bob"), f.user("auth0|root"))
	case path == "/users-by-email":
		for id, n := range users {
			if strings.ToLower(n)+"@acme.test" == q.Get("email") {
				fmt.Fprintf(w, "[%s]", f.user(id))
				return
			}
		}
		io.WriteString(w, "[]")
	case path == "/clients":
		io.WriteString(w, `{"total":1,"clients":[{"client_id":"cid1","name":"Web","app_type":"spa","is_first_party":true,"callbacks":["https://app.acme.test/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none","client_secret":"LEAKME","signing_keys":[{"cert":"LEAKME"}]}]}`)
	case path == "/logs":
		io.WriteString(w, `[{"date":"2026-11-04T10:00:00Z","type":"f","description":"Wrong email or password.","client_name":"Web","user_name":"alice@acme.test","ip":"203.0.113.9","details":{"request":{"body":{"password":"LEAKME"}}}}]`)
	case strings.HasSuffix(path, "/roles"):
		if strings.Contains(r.URL.EscapedPath(), "auth0%7Cmany") {
			if q.Get("page") == "1" {
				io.WriteString(w, `[{"id":"rol_x","name":"Super User"}]`)
				return
			}
			roles := make([]string, 100)
			for i := range roles {
				roles[i] = fmt.Sprintf(`{"id":"rol_v%d","name":"Viewer %d"}`, i, i)
			}
			io.WriteString(w, "["+strings.Join(roles, ",")+"]")
			return
		}
		if strings.Contains(r.URL.EscapedPath(), "auth0%7Croot") {
			io.WriteString(w, `[{"id":"rol_1","name":"Tenant Admin"}]`)
			return
		}
		io.WriteString(w, `[{"id":"rol_2","name":"Viewer"}]`)
	case strings.HasPrefix(path, "/users/"):
		id := strings.TrimPrefix(path, "/users/")
		if _, ok := users[id]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"statusCode":404,"error":"Not Found","message":"The user does not exist."}`)
			return
		}
		if r.Method == "PATCH" {
			var b struct {
				Blocked bool `json:"blocked"`
			}
			json.Unmarshal(body, &b)
			f.blocked[id] = b.Blocked
		}
		io.WriteString(w, f.user(id))
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, secret string, allowAdmins bool) (*Module, *fakeAuth0) {
	f := &fakeAuth0{blocked: map[string]bool{"auth0|bob": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Domain: "https://acme.eu.auth0.com/", ClientID: "AbCdEfGh1234", ClientSecret: secret, AllowAdmins: allowAdmins})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "csecret", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAuth0(t *testing.T) {
	m, f := setup(t, "secret://c", false)
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "tenant Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"users", `{}`, `"total":3`},
		{"users", `{}`, `"connections":["Username-Password-Authentication"]`},
		{"users", `{"includeEmail":true,"search":"ali-ce"}`, `"email":"alice@acme.test"`},
		{"clients", `{}`, `"clientId":"cid1"`},
		{"logs", `{"type":"f"}`, `"kind":"failed login"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "csecret") || strings.Contains(out, "mgmt-token") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if !strings.Contains(f.seen[3], `q=%28name%3Aali%5C-ce%2A+OR+nickname%3Aali%5C-ce%2A+OR+email%3Aali%5C-ce%2A%29`) {
		t.Fatalf("search not escaped: %s", f.seen[3])
	}
	if r, _ := invoke(m, "users", `{}`, false); strings.Contains(string(r.Output), `"email"`) {
		t.Fatal("emails without being asked")
	}
	if f.tokens != 1 {
		t.Fatalf("token fetched %d times", f.tokens)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users" || a.Name == "logs") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_user") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	r, err := invoke(m, "block_user", `{"email":"alice@acme.test"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Block Alice" || f.blocked["auth0|alice"] {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "block_user", `{"user":"auth0|alice"}`, false)
	if err != nil || !f.blocked["auth0|alice"] || r.Undo == nil || r.Undo.Action != "unblock_user" || string(r.Undo.Input) != `{"user":"auth0|alice"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `PATCH /api/v2/users/auth0%7Calice {"blocked":true}`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.blocked["auth0|alice"] || r.Undo.Action != "block_user" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "block_user", `{"user":"auth0|bob"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	for _, c := range []struct{ in, want string }{
		{`{"user":"auth0|root"}`, "Tenant Admin"},
		{`{"user":"auth0|many"}`, "Super User"},
		{`{"user":"auth0|mallory"}`, "no user"},
		{`{"email":"nobody@acme.test"}`, "no user"},
	} {
		if _, err := invoke(m, "block_user", c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.in, err)
		}
	}
	allow, af := setup(t, "secret://c", true)
	if _, err := invoke(allow, "block_user", `{"user":"auth0|root"}`, false); err != nil || !af.blocked["auth0|root"] {
		t.Fatalf("allowAdmins: %v", err)
	}
}

func TestAuth0Validation(t *testing.T) {
	m, f := setup(t, "secret://c", false)
	for _, c := range []struct{ action, in string }{
		{"block_user", `{}`},
		{"block_user", `{"user":"../clients"}`},
		{"block_user", `{"user":"auth0|a/../../x"}`},
		{"unblock_user", `{"email":"not-an-email"}`},
		{"users", `{"search":"a OR blocked:true"}`},
		{"users", `{"search":"x\"y"}`},
		{"users", `{"limit":5000}`},
		{"logs", `{"type":"f OR x"}`},
		{"logs", `{"user":"auth0|a\" OR \"b"}`},
		{"logs", `{"limit":500}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.tokens != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Domain: "acme.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "plain-secret"},
		{Domain: "acme.auth0.com.evil.test", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "auth0.com.evil.test", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "evilauth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "a.b.c.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "http://acme.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "https://x@acme.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "https://acme.auth0.com:444", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "https://acme.auth0.com/?a=b", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "https://acme.auth0.com/x", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "acme.auth0.com.", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "acme.\u0430uth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "evil.test#.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "evil.test\\.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "login.acme.test", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"},
		{Domain: "acme.auth0.com", ClientID: "bad id!", ClientSecret: "secret://c"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, d := range []string{"acme.auth0.com", "acme.us.auth0.com", "https://ACME.eu.auth0.com/api/v2/"} {
		if _, err := tenantDomain(d); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	h := bad.Health(context.Background(), "a")
	if h.Status != "down" || h.Message != "Auth0 refused the client credentials (access_denied)" || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestAuth0RefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Domain: "acme.auth0.com", ClientID: "AbCdEfGh1234", ClientSecret: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "csecret"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
