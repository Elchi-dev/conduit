package lldap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeLLDAP struct {
	mu      sync.Mutex
	seen    []string
	logins  int
	members map[int][]string
}

var groupNames = map[int]string{1: "lldap_admin", 2: "lldap_password_manager", 3: "family", 4: "media"}

func (f *fakeLLDAP) userJSON(id string) string {
	var gs []string
	for gid := 1; gid <= 4; gid++ {
		if slices.Contains(f.members[gid], id) {
			gs = append(gs, fmt.Sprintf(`{"id":%d,"displayName":%q}`, gid, groupNames[gid]))
		}
	}
	return fmt.Sprintf(`{"id":%q,"email":"%s@example.com","displayName":"%s D","creationDate":"2026-01-01T00:00:00Z","groups":[%s]}`, id, id, id, strings.Join(gs, ","))
}

func (f *fakeLLDAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/auth/simple/login" {
		var b struct{ Username, Password string }
		json.Unmarshal(body, &b)
		if b.Username != "conduit" || b.Password != "lpass" {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid username or password lpass")
			return
		}
		f.logins++
		io.WriteString(w, `{"token":"jwt-abc","refreshToken":"LEAKME"}`)
		return
	}
	if r.URL.Path != "/api/graphql" || r.Header.Get("Authorization") != "Bearer jwt-abc" {
		w.WriteHeader(401)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.Unmarshal(body, &req)
	f.seen = append(f.seen, req.Query)
	q := req.Query
	switch {
	case strings.Contains(q, "addUserToGroup"), strings.Contains(q, "removeUserFromGroup"):
		u, g := req.Variables["u"].(string), int(req.Variables["g"].(float64))
		if strings.Contains(q, "add") {
			f.members[g] = append(f.members[g], u)
		} else {
			f.members[g] = slices.DeleteFunc(f.members[g], func(x string) bool { return x == u })
		}
		io.WriteString(w, `{"data":{"x":{"ok":true}}}`)
	case strings.Contains(q, "user(userId"):
		id := req.Variables["id"].(string)
		if !slices.Contains([]string{"conduit", "alice", "bob", "root"}, id) {
			io.WriteString(w, `{"data":null,"errors":[{"message":"Entity not found: No such user: '`+id+`' token=abcdefghijklmnop"}]}`)
			return
		}
		fmt.Fprintf(w, `{"data":{"user":%s}}`, f.userJSON(id))
	case strings.HasPrefix(q, "query { users {") && strings.Contains(q, "groups {"):
		fmt.Fprintf(w, `{"data":{"users":[%s,%s,%s,%s]}}`, f.userJSON("conduit"), f.userJSON("bob"), f.userJSON("alice"), f.userJSON("root"))
	case strings.Contains(q, "users { id } }") && !strings.Contains(q, "groups"):
		io.WriteString(w, `{"data":{"users":[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"}]}}`)
	case strings.HasPrefix(q, "query { groups {"):
		var gs []string
		for gid := 1; gid <= 4; gid++ {
			var us []string
			for _, u := range f.members[gid] {
				us = append(us, fmt.Sprintf(`{"id":%q}`, u))
			}
			gs = append(gs, fmt.Sprintf(`{"id":%d,"displayName":%q,"creationDate":"2026-01-01T00:00:00Z","users":[%s]}`, gid, groupNames[gid], strings.Join(us, ",")))
		}
		fmt.Fprintf(w, `{"data":{"groups":[%s]}}`, strings.Join(gs, ","))
	default:
		io.WriteString(w, `{"errors":[{"message":"unknown"}]}`)
	}
}

func setup(t *testing.T, pw string, allowAdmins bool) (*Module, *fakeLLDAP) {
	f := &fakeLLDAP{members: map[int][]string{1: {"conduit", "root"}, 3: {"alice", "bob"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Username: "conduit", Password: pw, AllowAdmins: allowAdmins})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://l": "lpass", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLLDAP(t *testing.T) {
	m, f := setup(t, "secret://l", false)
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as conduit · 4 users" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"users", `{}`, `"count":4`},
		{"users", `{"search":"ALI"}`, `"groups":["family"]`},
		{"users", `{"includeEmail":true}`, `"email":"alice@example.com"`},
		{"groups", `{}`, `"admin":true,"created":"2026-01-01T00:00:00Z","id":1,"members":2,"name":"lldap_admin"`},
		{"groups", `{"search":"fam"}`, `"count":1`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "jwt-abc") || strings.Contains(out, "lpass") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "users", `{}`, false); strings.Contains(string(r.Output), "@example.com") {
		t.Fatal("emails without being asked")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_group") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	r, err := invoke(m, "add_to_group", `{"user":"alice","group":"media"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add alice to media" || string(r.Plan.Changes[0].After) != `{"groups":["family","media"]}` || len(f.members[4]) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_to_group", `{"user":"alice","group":4}`, false)
	if err != nil || !slices.Contains(f.members[4], "alice") || r.Undo == nil || r.Undo.Action != "remove_from_group" || string(r.Undo.Input) != `{"group":4,"user":"alice"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || slices.Contains(f.members[4], "alice") || r.Undo.Action != "add_to_group" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "remove_from_group", `{"user":"alice","group":"media"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	for _, c := range []struct{ action, in, want string }{
		{"remove_from_group", `{"user":"conduit","group":1}`, "signs in as"},
		{"add_to_group", `{"user":"CONDUIT","group":3}`, "signs in as"},
		{"add_to_group", `{"user":"alice","group":"lldap_admin"}`, "admin group"},
		{"add_to_group", `{"user":"bob","group":2}`, "admin group"},
		{"remove_from_group", `{"user":"root","group":3}`, "in lldap_admin"},
		{"add_to_group", `{"user":"mallory","group":3}`, "no user"},
		{"add_to_group", `{"user":"alice","group":99}`, "no group"},
	} {
		_, err := invoke(m, c.action, c.in, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s %s: %v", c.action, c.in, err)
		}
	}
	if slices.Contains(f.members[1], "alice") {
		t.Fatal("made alice an admin")
	}
	// User input travels only in variables.
	for _, q := range f.seen {
		if strings.Contains(q, "alice") || strings.Contains(q, "mallory") {
			t.Fatalf("value in query text: %s", q)
		}
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	allow, af := setup(t, "secret://l", true)
	if _, err := invoke(allow, "add_to_group", `{"user":"alice","group":"lldap_admin"}`, false); err != nil || !slices.Contains(af.members[1], "alice") {
		t.Fatalf("allowAdmins: %v", err)
	}
	if _, err := invoke(allow, "remove_from_group", `{"user":"conduit","group":1}`, false); err == nil {
		t.Fatal("changed its own groups")
	}
}

func TestLLDAPErrorRedacted(t *testing.T) {
	m, _ := setup(t, "secret://l", true)
	_, err := invoke(m, "add_to_group", `{"user":"mallory","group":3}`, false)
	if err == nil || strings.Contains(err.Error(), "abcdefghijklmnop") {
		t.Fatal(err)
	}
	c, _ := m.set.Get("a")
	err = c.gql(context.Background(), `query($id: String!) { user(userId: $id) { id } }`, map[string]any{"id": "ghost"}, nil)
	if err == nil || strings.Contains(err.Error(), "abcdefghijklmnop") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatal(err)
	}
}

func TestLLDAPValidation(t *testing.T) {
	m, f := setup(t, "secret://l", false)
	for _, c := range []struct{ action, in string }{
		{"add_to_group", `{}`},
		{"add_to_group", `{"user":"alice"}`},
		{"add_to_group", `{"user":"a b","group":3}`},
		{"add_to_group", `{"user":"alice\") { id } mutation {","group":3}`},
		{"remove_from_group", `{"user":"alice","group":0}`},
		{"remove_from_group", `{"user":"alice","group":2.5}`},
		{"remove_from_group", `{"user":"alice","group":"a\nb"}`},
		{"users", `{"search":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://ldap.example.com", Username: "admin", Password: "plain"},
		{URL: "ldap.example.com", Username: "admin", Password: "secret://l"},
		{URL: "https://u:p@ldap.example.com", Username: "admin", Password: "secret://l"},
		{URL: "https://ldap.example.com/?a=1", Username: "admin", Password: "secret://l"},
		{URL: "https://ldap.example.com/#x", Username: "admin", Password: "secret://l"},
		{URL: "https://ldap.example.com", Username: "bad user", Password: "secret://l"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "LLDAP refused the user name or password" {
		t.Fatalf("%+v", h)
	}
}

func TestLLDAPRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "conduit", Password: "secret://l"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://l": "lpass"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
