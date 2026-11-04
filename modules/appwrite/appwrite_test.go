package appwrite

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeAppwrite struct {
	mu      sync.Mutex
	seen    []string
	queries []string
}

func (f *fakeAppwrite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-Appwrite-Key") != "standard_good" || r.Header.Get("X-Appwrite-Project") != "proj1" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"The current user or API key does not have the required scopes to access the requested resource.","code":401,"type":"general_unauthorized_scope"}`)
		return
	}
	switch r.URL.Path {
	case "/v1/databases":
		io.WriteString(w, `{"total":1,"databases":[{"$id":"main","name":"Main","enabled":true}]}`)
	case "/v1/databases/main/collections":
		io.WriteString(w, `{"total":1,"collections":[{"$id":"posts","name":"Posts","enabled":true,"documentSecurity":false,"attributes":[{"key":"title","type":"string","status":"available","required":true,"array":false},{"key":"email","type":"string","format":"email"}]}]}`)
	case "/v1/databases/main/collections/posts":
		io.WriteString(w, `{"$id":"posts","name":"Posts","attributes":[{"key":"title","type":"string"},{"key":"views","type":"integer"}]}`)
	case "/v1/databases/main/collections/posts/documents":
		f.queries = r.URL.Query()["queries[]"]
		io.WriteString(w, `{"total":1,"documents":[{"$id":"d1","$createdAt":"2026-11-01T00:00:00.000+00:00","$permissions":["read(\"any\")"],"$databaseId":"main","title":"Hello","views":3}]}`)
	case "/v1/functions":
		io.WriteString(w, `{"total":1,"functions":[{"$id":"fn1","name":"mailer","runtime":"node-18.0","enabled":true,"live":true,"schedule":"0 * * * *","events":[],"timeout":15,"deployment":"dep1","vars":[{"key":"SMTP_PASSWORD","value":"LEAKME"}]}]}`)
	case "/v1/functions/fn1/executions":
		io.WriteString(w, `{"total":1,"executions":[{"$id":"e1","$createdAt":"2026-11-04T00:00:00.000+00:00","trigger":"http","status":"failed","responseStatusCode":500,"duration":0.25,"requestMethod":"POST","requestPath":"/hook?token=LEAKME","requestHeaders":[{"name":"authorization","value":"LEAKME"}],"responseBody":"LEAKME","logs":"LEAKME","errors":"LEAKME"}]}`)
	case "/v1/users":
		io.WriteString(w, `{"total":42,"users":[{"$id":"u1","email":"LEAKME@example.com","password":"LEAKME"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Collection with the requested ID could not be found.","code":404}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeAppwrite) {
	f := &fakeAppwrite{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/v1"
	raw, _ := json.Marshal(Config{Project: "proj1", Key: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://aw": "standard_good", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in)})
}

func TestAppwrite(t *testing.T) {
	m, f := setup(t, "secret://aw")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "1 databases" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"databases", `{}`, `"name":"Main"`},
		{"collections", `{"database":"main"}`, `"format":"email"`},
		{"documents", `{"database":"main","collection":"posts","where":[{"field":"title","op":"eq","value":"a\"b"},{"field":"views","op":"empty"}],"sort":"-$createdAt","limit":5,"page":2}`, `"title":"Hello"`},
		{"functions", `{}`, `"schedule":"0 * * * *"`},
		{"executions", `{"function":"fn1"}`, `"path":"/hook"`},
		{"users_count", `{}`, `{"users":42}`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "$permissions") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	want := []string{`{"attribute":"title","method":"equal","values":["a\"b"]}`, `{"attribute":"views","method":"isNull"}`, `{"method":"limit","values":[5]}`, `{"method":"offset","values":[5]}`, `{"attribute":"$createdAt","method":"orderDesc"}`}
	if strings.Join(f.queries, "|") != strings.Join(want, "|") {
		t.Fatal(f.queries)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead || a.Sensitive != (a.Name == "documents") {
			t.Fatalf("%s: %s %v", a.Name, a.Risk, a.Sensitive)
		}
	}
}

func TestAppwriteValidation(t *testing.T) {
	m, f := setup(t, "secret://aw")
	for _, c := range []struct{ action, in string }{
		{"collections", `{}`},
		{"collections", `{"database":"../users"}`},
		{"documents", `{"database":"main","collection":"posts/../x"}`},
		{"documents", `{"database":"main","collection":"posts","where":[{"field":"title\"}","op":"eq","value":"x"}]}`},
		{"documents", `{"database":"main","collection":"posts","where":[{"field":"title","op":"regex","value":"x"}]}`},
		{"executions", `{"function":"fn 1"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Attributes are checked against the collection.
	if _, err := invoke(m, "documents", `{"database":"main","collection":"posts","where":[{"field":"password","op":"eq","value":"x"}]}`); err == nil {
		t.Fatal("filtered on an unknown attribute")
	}
	for _, p := range f.seen {
		if strings.HasSuffix(p, "/documents") {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	for _, c := range []Config{{Project: "proj1", Key: "standard_plain"}, {Project: "", Key: "secret://aw"}, {URL: "cloud.appwrite.io", Project: "p", Key: "secret://aw"},
		{URL: "https://cloud.appwrite.io/v1?x=1", Project: "p", Key: "secret://aw"}, {URL: "https://u:p@cloud.appwrite.io/v1", Project: "p", Key: "secret://aw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
}

func TestAppwriteRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Appwrite-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/v1", Project: "proj1", Key: "secret://aw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://aw": "standard_good"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
