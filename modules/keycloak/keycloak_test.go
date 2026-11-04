package keycloak

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

const aliceID = "aaaaaaaa-1111-2222-3333-444444444444"

type fake struct {
	mu        sync.Mutex
	seen      []string
	tokens    int
	enabled   bool
	loggedOut bool
	expire    bool
	// attrs and actions are what a PUT without them would drop: the fake
	// replaces the stored user with what's sent, like Keycloak does.
	attrs   json.RawMessage
	actions json.RawMessage
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
		form, _ := url.ParseQuery(string(body))
		if r.Method != "POST" || form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "conduit" || form.Get("client_secret") != "kcsecret" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"unauthorized_client","error_description":"Invalid client or Invalid client credentials"}`)
			return
		}
		f.tokens++
		io.WriteString(w, `{"access_token":"at-1","expires_in":300,"token_type":"Bearer"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer at-1" || f.expire {
		f.expire = false
		w.WriteHeader(401)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	alice := map[string]any{"id": aliceID, "username": "alice", "email": "alice@example.com", "enabled": f.enabled, "createdTimestamp": 1700000000000, "credentials": []any{map[string]any{"value": "pw-hash"}},
		"attributes": f.attrs, "requiredActions": f.actions}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /admin/realms":
		io.WriteString(w, `[{"realm":"master","enabled":true},{"realm":"acme","displayName":"Acme","enabled":true}]`)
	case "GET /admin/realms/acme/users/count":
		io.WriteString(w, `17`)
	case "GET /admin/realms/acme/users":
		if q.Get("username") != "" {
			if q.Get("username") == "alice" && q.Get("exact") == "true" {
				enc.Encode([]any{alice})
			} else {
				io.WriteString(w, `[]`)
			}
			return
		}
		enc.Encode([]any{alice, map[string]any{"id": "b", "username": "bob", "enabled": true}})
	case "GET /admin/realms/acme/users/" + aliceID:
		enc.Encode(alice)
	case "PUT /admin/realms/acme/users/" + aliceID:
		var b struct {
			Enabled         *bool
			Attributes      json.RawMessage
			RequiredActions json.RawMessage
		}
		json.Unmarshal(body, &b)
		if b.Enabled != nil {
			f.enabled = *b.Enabled
		}
		f.attrs, f.actions = b.Attributes, b.RequiredActions
		w.WriteHeader(204)
	case "GET /admin/realms/acme/users/" + aliceID + "/sessions":
		io.WriteString(w, `[{"id":"s1","ipAddress":"203.0.113.9","start":1700000000000,"lastAccess":1700000100000,"clients":{"c1":"web"}},{"id":"s2","ipAddress":"203.0.113.9","clients":{}}]`)
	case "POST /admin/realms/acme/users/" + aliceID + "/logout":
		f.loggedOut = true
		w.WriteHeader(204)
	case "GET /admin/realms/acme/client-session-stats":
		io.WriteString(w, `[{"clientId":"web","active":"3","offline":"1"},{"clientId":"api","active":2,"offline":0}]`)
	case "GET /admin/realms/acme/clients":
		io.WriteString(w, `[{"id":"c1","clientId":"web","enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"cl-secret-123","redirectUris":["https://app/*"]}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, secret string) (*Module, *fake) {
	f := &fake{enabled: true, attrs: json.RawMessage(`{"department":["ops"]}`), actions: json.RawMessage(`["CONFIGURE_TOTP"]`)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Realm: "acme", AuthRealm: "master", ClientID: "conduit", ClientSecret: secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kc": "kcsecret", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKeycloakReads(t *testing.T) {
	m, f := setup(t, "secret://kc")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || !strings.Contains(h.Message, "2 realm(s)") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"realms", `{}`, `"displayName":"Acme"`},
		{"users", `{}`, `"count":17`},
		{"users", `{"search":"ali"}`, `"username":"alice"`},
		{"sessions", `{}`, `"active":5,"clients"`},
		{"sessions", `{"user":"alice"}`, `"sessions":2`},
		{"clients", `{}`, `"type":"confidential"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "cl-secret") || strings.Contains(out, "pw-hash") || strings.Contains(out, "203.0.113") || strings.Contains(out, "at-1") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "users", `{"countOnly":true}`, false); strings.Contains(string(r.Output), "alice") {
		t.Fatal(string(r.Output))
	}
	if f.tokens != 1 {
		t.Fatalf("signed in %d times; the token should be reused", f.tokens)
	}
	// An expired token is replaced once.
	f.expire = true
	if _, err := invoke(m, "realms", `{}`, false); err != nil || f.tokens != 2 {
		t.Fatalf("%v %d", err, f.tokens)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "users" && !a.Sensitive {
			t.Fatal("users must be sensitive")
		}
	}
}

func TestKeycloakUserChanges(t *testing.T) {
	m, f := setup(t, "secret://kc")
	r, err := invoke(m, "disable_user", `{"user":"alice"}`, true)
	if err != nil || r.Plan == nil || !f.enabled || !strings.Contains(r.Plan.Summary, "2 session(s) aren't ended") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "disable_user", `{"user":"alice"}`, false)
	if err != nil || f.enabled || r.Undo == nil || r.Undo.Action != "enable_user" {
		t.Fatalf("%+v %v", r, err)
	}
	// The PUT carries the full user, so attributes and required actions
	// survive, and never the credentials.
	put := f.seen[len(f.seen)-1]
	if !strings.HasPrefix(put, "PUT ") || !strings.Contains(put, `"enabled":false`) || !strings.Contains(put, `"username":"alice"`) || strings.Contains(put, "pw-hash") ||
		string(f.attrs) != `{"department":["ops"]}` || string(f.actions) != `["CONFIGURE_TOTP"]` {
		t.Fatal(put, string(f.attrs), string(f.actions))
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || !strings.Contains(p.Plan.Summary, "can sign in again") {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.enabled || r.Undo == nil || r.Undo.Action != "disable_user" || string(f.attrs) != `{"department":["ops"]}` {
		t.Fatalf("%+v %v %s", r, err, f.attrs)
	}
	r, err = invoke(m, "logout_user", `{"user":"`+aliceID+`"}`, true)
	if err != nil || r.Plan == nil || f.loggedOut || !strings.Contains(r.Plan.Summary, "all 2 session(s)") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "logout_user", `{"user":"`+aliceID+`"}`, false); err != nil || !f.loggedOut {
		t.Fatal(err)
	}
	if _, err := invoke(m, "disable_user", `{"user":"mallory"}`, false); err == nil || !strings.Contains(err.Error(), "no user mallory") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "disable_user", "enable_user":
			if a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible {
				t.Fatal(a.Name)
			}
		case "logout_user":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestKeycloakValidation(t *testing.T) {
	m, f := setup(t, "secret://kc")
	for _, c := range []struct{ action, in string }{
		{"users", `{"realm":"../master"}`},
		{"users", `{"realm":"acme/users"}`},
		{"users", `{"max":1000}`},
		{"users", `{"first":-1}`},
		{"users", `{"search":"a\nb"}`},
		{"clients", `{"search":"a b?"}`},
		{"disable_user", `{}`},
		{"disable_user", `{"user":"bad\u0000name"}`},
		{"logout_user", `{"realm":"a?b","user":"alice"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Address: "http://x", Realm: "acme", ClientID: "c", ClientSecret: "plain"},
		{Address: "http://x", Realm: "acme", ClientID: "c"},
		{Address: "ftp://x", Realm: "acme", ClientID: "c", ClientSecret: "secret://kc"},
		{Address: "http://u:p@x", Realm: "acme", ClientID: "c", ClientSecret: "secret://kc"},
		{Address: "http://x/a/../b", Realm: "acme", ClientID: "c", ClientSecret: "secret://kc"},
		{Address: "http://x", Realm: "a/b", ClientID: "c", ClientSecret: "secret://kc"},
		{Address: "http://x", Realm: "acme", AuthRealm: "..", ClientID: "c", ClientSecret: "secret://kc"},
		{Address: "http://x", Realm: "acme", ClientID: "", ClientSecret: "secret://kc"},
		{Address: "https://x", Realm: "acme", ClientID: "c", ClientSecret: "secret://kc", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Address: "https://sso.example.com/auth", Realm: "acme", ClientID: "c", ClientSecret: "secret://kc"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused the client credentials") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "realms", `{}`, false); err == nil || !strings.Contains(err.Error(), "client credentials") {
		t.Fatal(err)
	}
}

func TestKeycloakRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b) + "!"
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Realm: "acme", ClientID: "c", ClientSecret: "secret://kc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kc": "kcsecret"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "realms", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
