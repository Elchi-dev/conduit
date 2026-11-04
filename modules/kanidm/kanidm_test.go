package kanidm

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fakeKanidm struct {
	mu      sync.Mutex
	seen    []string
	expires map[string]string
}

var persons = map[string]string{
	"alice": `"memberof":["idm_all_persons@idm.test","family@idm.test"]`,
	"bob":   `"memberof":["idm_all_persons@idm.test"]`,
	"root":  `"memberof":["idm_admins@idm.test"]`,
	"carol": `"memberof":["idm_all_persons@idm.test","idm_oauth2_admins@idm.test"]`,
	"dave":  `"memberof":[]`,
}

func (f *fakeKanidm) entry(name, extra string) string {
	exp := ""
	if e := f.expires[name]; e != "" {
		exp = fmt.Sprintf(`,"account_expire":[%q]`, e)
	}
	return fmt.Sprintf(`{"attrs":{"name":[%q],"uuid":["00000000-0000-0000-0000-%012d"],"spn":["%s@idm.test"],"displayname":["%s D"],"mail":["%s@example.com"],"primary_credential":["LEAKME"],"passkeys":["LEAKME"],"radius_secret":["LEAKME"],%s%s}}`,
		name, len(name), name, name, name, extra, exp)
}

func (f *fakeKanidm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ktok" {
		w.WriteHeader(401)
		io.WriteString(w, `"notauthenticated"`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 1 {
		parts[1], _, _ = strings.Cut(parts[1], "@")
	}
	switch {
	case path == "/self":
		fmt.Fprintf(w, `{"youare":%s}`, f.entry("conduit", `"memberof":["idm_people_admins@idm.test"]`))
	case path == "/person":
		fmt.Fprintf(w, "[%s,%s,%s]", f.entry("bob", persons["bob"]), f.entry("alice", persons["alice"]), f.entry("root", persons["root"]))
	case path == "/service_account":
		fmt.Fprintf(w, "[%s]", f.entry("conduit", `"memberof":[]`))
	case path == "/group":
		io.WriteString(w, `[{"attrs":{"name":["idm_admins"],"member":["root@idm.test"]}},{"attrs":{"name":["family"],"description":["Us"],"member":["alice@idm.test","bob@idm.test"]}}]`)
	case len(parts) == 2 && parts[0] == "person" && r.Method == "GET":
		if x, ok := persons[parts[1]]; ok {
			io.WriteString(w, f.entry(parts[1], x))
			return
		}
		io.WriteString(w, "null")
	case len(parts) == 2 && parts[0] == "service_account" && r.Method == "GET":
		if parts[1] == "conduit" {
			io.WriteString(w, f.entry("conduit", `"memberof":[]`))
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, `"nomatchingentries"`)
	case len(parts) == 4 && parts[2] == "_attr" && parts[3] == "account_expire":
		switch r.Method {
		case "PUT":
			var v []string
			json.Unmarshal(body, &v)
			f.expires[parts[1]] = v[0]
		case "DELETE":
			delete(f.expires, parts[1])
		}
		io.WriteString(w, "null")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string, allowAdmins bool) (*Module, *fakeKanidm) {
	f := &fakeKanidm{expires: map[string]string{"bob": "2026-01-01T00:00:00Z"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: tok, AllowAdmins: allowAdmins})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ktok", "secret://bad": "x"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKanidm(t *testing.T) {
	m, f := setup(t, "secret://k", false)
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as conduit@idm.test" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"persons", `{}`, `"count":3`},
		{"persons", `{"search":"ALI"}`, `"groups":["family","idm_all_persons"]`},
		{"persons", `{"includeEmail":true}`, `"email":["alice@example.com"]`},
		{"groups", `{}`, `"admin":true,"members":1`},
		{"account_status", `{}`, `"counts":{"active":3,"expired":1}`},
		{"account_status", `{"account":"bob"}`, `"status":"expired"`},
		{"account_status", `{"account":"conduit"}`, `"kind":"service_account"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if r, _ := invoke(m, "persons", `{}`, false); strings.Contains(string(r.Output), "@example.com") {
		t.Fatal("emails without being asked")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "persons") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "lock_account") != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	r, err := invoke(m, "lock_account", `{"account":"alice"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Lock alice" || f.expires["alice"] != "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "lock_account", `{"account":"Alice@idm.test"}`, false)
	if err != nil || f.expires["alice"] != "2026-11-04T12:00:00Z" || r.Undo == nil || r.Undo.Action != "unlock_account" || string(r.Undo.Input) != `{"account":"alice"}` {
		t.Fatalf("%+v %v %v", r, err, f.expires)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `PUT /v1/person/alice/_attr/account_expire ["2026-11-04T12:00:00Z"]`) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.expires["alice"] != "" || r.Undo.Action != "lock_account" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "unlock_account", `{"account":"alice"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if r, err := invoke(m, "lock_account", `{"account":"bob"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	for _, c := range []struct{ action, in, want string }{
		{"lock_account", `{"account":"conduit"}`, "own service account"},
		{"lock_account", `{"account":"root"}`, "idm_admins"},
		{"lock_account", `{"account":"carol"}`, "idm_oauth2_admins"},
		{"lock_account", `{"account":"dave"}`, "couldn't read dave's groups"},
		{"lock_account", `{"account":"mallory"}`, "no account"},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s %s: %v", c.action, c.in, err)
		}
	}
	allow, af := setup(t, "secret://k", true)
	if _, err := invoke(allow, "lock_account", `{"account":"root"}`, false); err != nil || af.expires["root"] == "" {
		t.Fatalf("allowAdmins: %v", err)
	}
	if _, err := invoke(allow, "lock_account", `{"account":"conduit"}`, false); err == nil {
		t.Fatal("locked its own account")
	}
}

func TestKanidmValidation(t *testing.T) {
	m, f := setup(t, "secret://k", false)
	for _, c := range []struct{ action, in string }{
		{"lock_account", `{}`},
		{"lock_account", `{"account":"../group"}`},
		{"unlock_account", `{"account":"a b"}`},
		{"account_status", `{"account":"x?y"}`},
		{"persons", `{"search":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://idm.example.com", Token: "plain"},
		{URL: "idm.example.com", Token: "secret://k"},
		{URL: "https://u:p@idm.example.com", Token: "secret://k"},
		{URL: "https://idm.example.com/?x=1", Token: "secret://k"},
		{URL: "https://idm.example.com/#f", Token: "secret://k"},
		{URL: "ftp://idm.example.com", Token: "secret://k"},
		{URL: "https://idm.example.com", Token: "secret://k", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Kanidm refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestKanidmRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ktok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
