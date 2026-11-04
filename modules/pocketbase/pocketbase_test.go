package pocketbase

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
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const postsJSON = `{"id":"pbc_posts","name":"posts","type":"base","system":false,"listRule":"","viewRule":null,"fields":[
	{"name":"id","type":"text","system":true},{"name":"title","type":"text","required":true},{"name":"views","type":"number"},
	{"name":"apiKey","type":"text","hidden":true},{"name":"cover","type":"file"},{"name":"created","type":"autodate"},{"name":"updated","type":"autodate"}]}`

type fakePB struct {
	mu      sync.Mutex
	seen    []string
	logins  int
	filter  string
	expired bool
	recs    map[string]map[string]any
}

func (f *fakePB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.URL.Path == "/api/collections/_superusers/auth-with-password" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if b["identity"] != "admin@example.com" || b["password"] != "pw-good-LEAKME" {
			w.WriteHeader(400)
			io.WriteString(w, `{"status":400,"message":"Failed to authenticate.","data":{}}`)
			return
		}
		f.logins++
		f.expired = false
		io.WriteString(w, `{"token":"tok-LEAKME","record":{"email":"admin@example.com"}}`)
		return
	}
	if r.Header.Get("Authorization") != "tok-LEAKME" || f.expired {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":401,"message":"The request requires valid record authorization token."}`)
		return
	}
	rec := strings.TrimPrefix(r.URL.Path, "/api/collections/posts/records/")
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/collections":
		io.WriteString(w, `{"page":1,"perPage":500,"totalItems":3,"items":[`+postsJSON+`,
			{"id":"_pb_users_auth_","name":"users","type":"auth","system":false,"fields":[{"name":"email","type":"email"}]},
			{"id":"pbc_su","name":"_superusers","type":"auth","system":true,"fields":[]}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/collections/posts":
		io.WriteString(w, postsJSON)
	case r.Method == "GET" && r.URL.Path == "/api/collections/users":
		io.WriteString(w, `{"id":"_pb_users_auth_","name":"users","type":"auth","fields":[{"name":"email","type":"email"},{"name":"password","type":"password","hidden":true}]}`)
	case r.Method == "GET" && r.URL.Path == "/api/collections/pbc_su":
		io.WriteString(w, `{"id":"pbc_su","name":"_superusers","type":"auth","system":true,"fields":[]}`)
	case r.Method == "GET" && r.URL.Path == "/api/collections/posts/records":
		f.filter = r.URL.Query().Get("filter")
		var items []map[string]any
		for _, x := range f.recs {
			items = append(items, x)
		}
		json.NewEncoder(w).Encode(map[string]any{"page": 1, "totalPages": 1, "totalItems": len(items), "items": items})
	case r.Method == "GET" && f.recs[rec] != nil:
		json.NewEncoder(w).Encode(f.recs[rec])
	case r.Method == "POST" && r.URL.Path == "/api/collections/posts/records":
		var b map[string]any
		json.Unmarshal(body, &b)
		b["id"], b["apiKey"] = "new1", "LEAKME"
		f.recs["new1"] = b
		json.NewEncoder(w).Encode(b)
	case r.Method == "PATCH" && f.recs[rec] != nil:
		var b map[string]any
		json.Unmarshal(body, &b)
		for k, v := range b {
			f.recs[rec][k] = v
		}
		json.NewEncoder(w).Encode(f.recs[rec])
	case r.Method == "DELETE" && f.recs[rec] != nil:
		delete(f.recs, rec)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":404,"message":"The requested resource wasn't found."}`)
	}
}

var secrets = map[string]string{"secret://pb": "pw-good-LEAKME", "secret://bad": "nope"}

func setup(t *testing.T, pass string) (*Module, *fakePB) {
	f := &fakePB{recs: map[string]map[string]any{"r1": {"id": "r1", "title": "Hello", "views": 3.0, "apiKey": "sk-LEAKME", "created": "2026-11-01 10:00:00.000Z", "updated": "2026-11-01 10:00:00.000Z"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "admin@example.com", Password: pass})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, r sdk.Result, err error) string {
	t.Helper()
	s := string(r.Output)
	if r.Plan != nil {
		b, _ := json.Marshal(r.Plan)
		s += string(b)
	}
	if err != nil {
		s += err.Error()
	}
	if strings.Contains(s, "LEAKME") {
		t.Fatalf("leaked: %s", s)
	}
	return s
}

func TestPocketBase(t *testing.T) {
	m, f := setup(t, "secret://pb")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "3 collections" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "collections", `{}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"records":"not available here`) {
		t.Fatal(out, err)
	}
	r, err = invoke(m, "schema", `{"collection":"posts"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"view":"superusers only"`) || !strings.Contains(out, `"list":"anyone"`) {
		t.Fatal(out, err)
	}
	r, err = invoke(m, "list_records", `{"collection":"posts","where":[{"field":"title","op":"eq","value":"O'Brien"},{"field":"views","op":"gte","value":2},{"field":"cover","op":"notempty"}],"sort":"-created"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"title":"Hello"`) {
		t.Fatal(out, err)
	}
	if f.filter != `title = 'O\'Brien' && views >= 2 && cover != null` {
		t.Fatal(f.filter)
	}
	r, err = invoke(m, "get_record", `{"collection":"posts","id":"r1"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"views":3`) {
		t.Fatal(out, err)
	}

	// Create: preview, real, undo.
	r, err = invoke(m, "create_record", `{"collection":"posts","data":{"title":"New"}}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Create a record in posts (title)" || f.recs["new1"] != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_record", `{"collection":"posts","data":{"title":"New"}}`, false)
	noLeak(t, r, err)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_record" || string(r.Undo.Input) != `{"collection":"posts","id":"new1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.recs["new1"] != nil {
		t.Fatal(err)
	}

	// Update: nothing to change, preview, real.
	if r, err := invoke(m, "update_record", `{"collection":"posts","id":"r1","data":{"title":"Hello"}}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	r, err = invoke(m, "update_record", `{"collection":"posts","id":"r1","data":{"title":"Hi","views":3}}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"title":"Hello"}` || string(r.Plan.Changes[0].After) != `{"title":"Hi"}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "update_record", `{"collection":"posts","id":"r1","data":{"title":"Hi"}}`, false); err != nil || f.recs["r1"]["title"] != "Hi" || r.Undo != nil {
		t.Fatal(err)
	}

	// Delete: the preview carries no values.
	r, err = invoke(m, "delete_record", `{"collection":"posts","id":"r1"}`, true)
	if out := noLeak(t, r, err); err != nil || strings.Contains(out, "Hi") || f.recs["r1"] == nil {
		t.Fatal(out, err)
	}
	if _, err := invoke(m, "delete_record", `{"collection":"posts","id":"r1"}`, false); err != nil || f.recs["r1"] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_record", `{"collection":"posts","id":"r1"}`, false); err == nil || !strings.Contains(err.Error(), "no record") {
		t.Fatal(err)
	}

	// An expired session signs in again.
	f.expired = true
	if _, err := invoke(m, "get_record", `{"collection":"posts","id":"nope"}`, false); err == nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}

	specs := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		specs[a.Name] = a
	}
	if !specs["list_records"].Sensitive || !specs["get_record"].Sensitive || specs["delete_record"].Risk != sdk.RiskDestructive || specs["delete_record"].Sensitive || specs["update_record"].Reversible {
		t.Fatal(specs)
	}
}

func TestPocketBaseRefusesAuthCollections(t *testing.T) {
	m, f := setup(t, "secret://pb")
	for _, in := range []string{`{"collection":"users"}`, `{"collection":"_superusers"}`, `{"collection":"pbc_su"}`} {
		r, err := invoke(m, "list_records", in, false)
		if err == nil || !strings.Contains(err.Error(), "system collection") && !strings.Contains(err.Error(), "auth or system") {
			t.Fatalf("%s: %s %v", in, r.Output, err)
		}
	}
	for _, p := range f.seen {
		if strings.Contains(p, "/records") {
			t.Fatalf("read an auth collection's records: %v", f.seen)
		}
	}
}

func TestPocketBaseValidation(t *testing.T) {
	m, f := setup(t, "secret://pb")
	for _, c := range []struct{ action, in string }{
		{"get_record", `{"collection":"posts","id":"../users"}`},
		{"get_record", `{"collection":"posts/x","id":"r1"}`},
		{"get_record", `{"collection":"posts","id":"a b"}`},
		{"list_records", `{"collection":"posts","where":[{"field":"title","op":"eq","value":"x\\' || 1=1"}]}`},
		{"list_records", `{"collection":"posts","where":[{"field":"title)||(1","op":"eq","value":"x"}]}`},
		{"list_records", `{"collection":"posts","where":[{"field":"title","op":"like","value":"x"}]}`},
		{"list_records", `{"collection":"posts","where":[{"field":"title","op":"eq","value":{"a":1}}]}`},
		{"list_records", `{"collection":"posts","where":[{"field":"title","op":"eq","value":"a\nb"}]}`},
		{"create_record", `{"collection":"posts"}`},
		{"update_record", `{"collection":"posts","id":"r1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Field names are checked against the collection: only its fields, and
	// never hidden ones.
	for _, c := range []struct{ action, in string }{
		{"list_records", `{"collection":"posts","where":[{"field":"apiKey","op":"eq","value":"x"}]}`},
		{"list_records", `{"collection":"posts","where":[{"field":"nope","op":"eq","value":"x"}]}`},
		{"list_records", `{"collection":"posts","sort":"-apiKey"}`},
		{"create_record", `{"collection":"posts","data":{"apiKey":"x"}}`},
		{"create_record", `{"collection":"posts","data":{"id":"x"}}`},
		{"create_record", `{"collection":"posts","data":{"created":"x"}}`},
		{"update_record", `{"collection":"posts","id":"r1","data":{"cover":[]}}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	for _, p := range f.seen {
		if strings.Contains(p, "/records") {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	for _, c := range []Config{
		{URL: "https://pb.example.com", Email: "a@b.c", Password: "plain"},
		{URL: "pb.example.com", Email: "a@b.c", Password: "secret://pb"},
		{URL: "https://u:p@pb.example.com", Email: "a@b.c", Password: "secret://pb"},
		{URL: "https://pb.example.com/?x=1", Email: "a@b.c", Password: "secret://pb"},
		{URL: "https://pb.example.com#x", Email: "a@b.c", Password: "secret://pb"},
		{URL: "https://pb.example.com", Email: "", Password: "secret://pb"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "PocketBase refused the superuser e-mail or password" {
		t.Fatalf("%+v", h)
	}
}

func TestPocketBaseFilter(t *testing.T) {
	for want, cs := range map[string][]records.Cond{
		`a = 'x' && b ~ 'y'`:        {{Field: "a", Op: "eq", Value: "x"}, {Field: "b", Op: "contains", Value: "y"}},
		`a != true && b < 1.5`:      {{Field: "a", Op: "ne", Value: true}, {Field: "b", Op: "lt", Value: 1.5}},
		`a = '\' || 1=1 || a = \''`: {{Field: "a", Op: "eq", Value: "' || 1=1 || a = '"}},
	} {
		if got := Filter(cs); got != want {
			t.Errorf("%s: %s", want, got)
		}
	}
}

func TestPocketBaseRefusesCrossHostRedirect(t *testing.T) {
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
	raw, _ := json.Marshal(Config{URL: srv.URL, Email: "admin@example.com", Password: "secret://pb"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
