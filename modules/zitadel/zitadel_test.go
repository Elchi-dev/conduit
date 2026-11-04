package zitadel

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

type fakeZitadel struct {
	v2beta bool // like a server before 2.63

	mu     sync.Mutex
	seen   []string
	orgHdr string
	states map[string]string
}

var userNames = map[string]string{"100": "conduit-bot", "200": "alice", "300": "bob"}

func (f *fakeZitadel) user(id string) string {
	if id == "100" {
		return `{"id":"100","state":"USER_STATE_ACTIVE","userName":"conduit-bot","machine":{"name":"Conduit","description":"bot"}}`
	}
	return fmt.Sprintf(`{"id":%q,"details":{"changeDate":"2026-11-01T00:00:00Z","creationDate":"2026-01-01T00:00:00Z"},"state":%q,"userName":%q,
		"human":{"profile":{"displayName":"Name %s"},"email":{"email":"%s@example.com","isEmailVerified":true},"phone":{"phone":"+49LEAKME"}}}`,
		id, f.states[id], userNames[id], id, userNames[id])
}

func (f *fakeZitadel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer zpat" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":16,"message":"Errors.Token.Invalid (AUTH-7fs1e)"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	f.orgHdr = r.Header.Get("x-zitadel-orgid")
	switch p := r.Method + " " + r.URL.Path; {
	case p == "GET /management/v1/orgs/me":
		io.WriteString(w, `{"org":{"id":"42","state":"ORG_STATE_ACTIVE","name":"Acme","primaryDomain":"acme.zitadel.cloud"}}`)
	case p == "POST /v2/organizations/_search" && !f.v2beta, p == "POST /v2beta/organizations/_search" && f.v2beta:
		io.WriteString(w, `{"details":{"totalResult":"2"},"result":[{"id":"42","state":"ORGANIZATION_STATE_ACTIVE","name":"Acme","primaryDomain":"acme.zitadel.cloud"},{"id":"43","state":"ORGANIZATION_STATE_INACTIVE","name":"Old"}]}`)
	case p == "POST /management/v1/users/_search":
		var b struct {
			Queries []struct {
				UserNameQuery *struct {
					UserName string `json:"userName"`
					Method   string `json:"method"`
				} `json:"userNameQuery"`
			} `json:"queries"`
		}
		json.Unmarshal(body, &b)
		var out []string
		for _, id := range []string{"100", "200", "300"} {
			if len(b.Queries) > 0 && b.Queries[0].UserNameQuery != nil && b.Queries[0].UserNameQuery.Method == "TEXT_QUERY_METHOD_EQUALS" && b.Queries[0].UserNameQuery.UserName != userNames[id] {
				continue
			}
			out = append(out, f.user(id))
		}
		fmt.Fprintf(w, `{"details":{"totalResult":"%d"},"result":[%s]}`, len(out), strings.Join(out, ","))
	case p == "GET /management/v1/users/200", p == "GET /management/v1/users/300", p == "GET /management/v1/users/100":
		fmt.Fprintf(w, `{"user":%s}`, f.user(strings.TrimPrefix(r.URL.Path, "/management/v1/users/")))
	case p == "GET /auth/v1/users/me":
		io.WriteString(w, `{"user":{"id":"100","userName":"conduit-bot"}}`)
	case strings.HasPrefix(p, "POST /management/v1/users/") && (strings.HasSuffix(p, "/_deactivate") || strings.HasSuffix(p, "/_reactivate")):
		parts := strings.Split(r.URL.Path, "/")
		id := parts[4]
		if strings.HasSuffix(p, "_deactivate") {
			f.states[id] = "USER_STATE_INACTIVE"
		} else {
			f.states[id] = "USER_STATE_ACTIVE"
		}
		io.WriteString(w, `{"details":{}}`)
	case p == "POST /management/v1/projects/_search":
		io.WriteString(w, `{"result":[{"id":"500","name":"Portal","state":"PROJECT_STATE_ACTIVE","projectRoleAssertion":true}]}`)
	case p == "POST /management/v1/projects/500/apps/_search":
		io.WriteString(w, `{"result":[
			{"id":"501","name":"web","state":"APP_STATE_ACTIVE","oidcConfig":{"clientId":"501@portal","clientSecret":"LEAKME","appType":"OIDC_APP_TYPE_WEB","authMethodType":"OIDC_AUTH_METHOD_TYPE_BASIC","redirectUris":["https://portal.example.com/cb"],"grantTypes":["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"]}},
			{"id":"502","name":"api","state":"APP_STATE_ACTIVE","apiConfig":{"clientId":"502@portal","clientSecret":"LEAKME","authMethodType":"API_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT"}},
			{"id":"503","name":"saml","state":"APP_STATE_ACTIVE","samlConfig":{"metadataXml":"PExFQUtNRT4=LEAKME","metadataUrl":"https://sp.example.com/meta?token=LEAKME"}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":5,"message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string, v2beta bool) (*Module, *fakeZitadel) {
	f := &fakeZitadel{v2beta: v2beta, states: map[string]string{"200": "USER_STATE_ACTIVE", "300": "USER_STATE_LOCKED"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/ui/console", Token: tok, OrgID: "42"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://z": "zpat", "secret://bad": "nope"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZitadel(t *testing.T) {
	m, f := setup(t, "secret://z", false)
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "organization Acme" || f.orgHdr != "42" {
		t.Fatalf("%+v %q", h, f.orgHdr)
	}
	for _, c := range []struct{ action, in, want string }{
		{"orgs", `{}`, `"state":"inactive"`},
		{"users", `{}`, `"total":3`},
		{"users", `{}`, `"type":"machine"`},
		{"users", `{"includeEmail":true}`, `"email":"alice@example.com"`},
		{"projects", `{}`, `"clientId":"501@portal"`},
		{"projects", `{}`, `"authMethod":"private_key_jwt"`},
		{"projects", `{}`, `"metadataUrl":"https://sp.example.com/meta"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "users", `{}`, false); strings.Contains(string(r.Output), "@example.com") {
		t.Fatal("emails without being asked")
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "users") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.HasSuffix(a.Name, "_user") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}

	r, err := invoke(m, "deactivate_user", `{"userName":"alice"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Deactivate alice" || f.states["200"] != "USER_STATE_ACTIVE" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "deactivate_user", `{"userName":"alice"}`, false)
	if err != nil || f.states["200"] != "USER_STATE_INACTIVE" || r.Undo == nil || r.Undo.Action != "reactivate_user" || string(r.Undo.Input) != `{"id":"200"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.states["200"] != "USER_STATE_ACTIVE" || r.Undo.Action != "deactivate_user" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "reactivate_user", `{"id":"200"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "reactivate_user", `{"id":"300"}`, false); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "deactivate_user", `{"id":"100"}`, false); err == nil || !strings.Contains(err.Error(), "own service user") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "deactivate_user", `{"userName":"mallory"}`, false); err == nil || !strings.Contains(err.Error(), "no user") {
		t.Fatal(err)
	}

	old, _ := setup(t, "secret://z", true)
	if r, err := invoke(old, "orgs", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"name":"Old"`) {
		t.Fatalf("v2beta: %s %v", r.Output, err)
	}
}

func TestZitadelValidation(t *testing.T) {
	m, f := setup(t, "secret://z", false)
	for _, c := range []struct{ action, in string }{
		{"deactivate_user", `{}`},
		{"deactivate_user", `{"id":"200/_reactivate"}`},
		{"deactivate_user", `{"id":"../orgs/me"}`},
		{"reactivate_user", `{"userName":"a\nb"}`},
		{"users", `{"state":"deleted"}`},
		{"users", `{"type":"robot"}`},
		{"users", `{"limit":1000}`},
		{"projects", `{"search":"x\u0000"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://z.example.com", Token: "plain"}, {URL: "z.example.com", Token: "secret://z"}, {URL: "https://z.example.com", Token: "secret://z", OrgID: "42&x=1"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "z"); h.Status != "down" || h.Message != "Zitadel refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestZitadelRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("x-zitadel-orgid")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://z", OrgID: "42"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://z": "zpat"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "z"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
