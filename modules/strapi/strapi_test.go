package strapi

import (
	"context"
	"encoding/json"
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

const typesJSON = `{"data":[
	{"uid":"api::article.article","schema":{"kind":"collectionType","pluralName":"articles","displayName":"Article","draftAndPublish":true,"attributes":{
		"title":{"type":"string","required":true},"views":{"type":"integer"},"secretNote":{"type":"text","private":true},"author":{"type":"relation"}}}},
	{"uid":"api::page.page","schema":{"kind":"collectionType","pluralName":"pages","displayName":"Page","draftAndPublish":false,"attributes":{"title":{"type":"string"}}}},
	{"uid":"api::home.home","schema":{"kind":"singleType","pluralName":"homes","attributes":{}}},
	{"uid":"plugin::users-permissions.user","schema":{"kind":"collectionType","pluralName":"users","attributes":{"email":{"type":"email"},"password":{"type":"password","private":true}}}}]}`

// fakeStrapi is a Strapi 5 server, or a Strapi 4 one (v4).
type fakeStrapi struct {
	mu      sync.Mutex
	v4      bool
	seen    []string
	query   string
	drafts  map[string]map[string]any
	pub     map[string]map[string]any
	lastPut string
}

func (f *fakeStrapi) wrap(id string, e map[string]any) map[string]any {
	if !f.v4 {
		return e
	}
	a := map[string]any{}
	for k, v := range e {
		if k != "id" {
			a[k] = v
		}
	}
	return map[string]any{"id": e["id"], "attributes": a}
}

func (f *fakeStrapi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer st-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"data":null,"error":{"status":401,"name":"UnauthorizedError","message":"Missing or invalid credentials"}}`)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/articles/")
	status := r.URL.Query().Get("status")
	enc := json.NewEncoder(w)
	switch {
	case r.URL.Path == "/api/content-type-builder/content-types":
		io.WriteString(w, typesJSON)
	case r.Method == "GET" && r.URL.Path == "/api/articles":
		f.query = r.URL.RawQuery
		rows := []any{}
		for k, e := range f.drafts {
			rows = append(rows, f.wrap(k, e))
		}
		enc.Encode(map[string]any{"data": rows, "meta": map[string]any{"pagination": map[string]any{"page": 1, "pageCount": 1, "total": len(rows)}}})
	case r.Method == "GET" && r.URL.Path == "/api/articles/zzz": // answers with another entry
		enc.Encode(map[string]any{"data": f.drafts["abc123"]})
	case r.Method == "GET" && status == "published":
		if f.pub[id] == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"data":null,"error":{"status":404,"name":"NotFoundError","message":"Not Found"}}`)
			return
		}
		enc.Encode(map[string]any{"data": f.pub[id]})
	case r.Method == "GET" && f.drafts[id] != nil:
		enc.Encode(map[string]any{"data": f.wrap(id, f.drafts[id])})
	case r.Method == "POST" && r.URL.Path == "/api/articles":
		f.query = r.URL.RawQuery
		var b struct{ Data map[string]any }
		json.Unmarshal(body, &b)
		b.Data["documentId"], b.Data["id"], b.Data["secretNote"] = "new456", 9.0, "LEAKME"
		f.drafts["new456"] = b.Data
		enc.Encode(map[string]any{"data": b.Data})
	case r.Method == "PUT" && f.drafts[id] != nil:
		f.query, f.lastPut = r.URL.RawQuery, string(body)
		var b struct{ Data map[string]any }
		json.Unmarshal(body, &b)
		for k, v := range b.Data {
			f.drafts[id][k] = v
		}
		if status == "published" {
			cp := map[string]any{}
			for k, v := range f.drafts[id] {
				cp[k] = v
			}
			f.pub[id] = cp
		}
		enc.Encode(map[string]any{"data": f.drafts[id]})
	case r.Method == "DELETE" && f.drafts[id] != nil:
		delete(f.drafts, id)
		delete(f.pub, id)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"data":null,"error":{"status":404,"name":"NotFoundError","message":"Not Found"}}`)
	}
}

func setup(t *testing.T, tok string, v4 bool) (*Module, *fakeStrapi) {
	f := &fakeStrapi{v4: v4, pub: map[string]map[string]any{}, drafts: map[string]map[string]any{}}
	id := "abc123"
	e := map[string]any{"documentId": id, "id": 1.0, "title": "Hello", "views": 3.0, "secretNote": "LEAKME", "publishedAt": nil}
	if v4 {
		id = "1"
		delete(e, "documentId")
	}
	f.drafts[id] = e
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	ver := 5
	if v4 {
		ver = 4
	}
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api", Token: tok, Version: ver})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://st": "st-good", "secret://bad": "st-bad"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
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
	if strings.Contains(s, "LEAKME") || strings.Contains(s, "st-good") {
		t.Fatalf("leaked: %s", s)
	}
	return s
}

func TestStrapi(t *testing.T) {
	m, f := setup(t, "secret://st", false)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "2 content types" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "content_types", `{}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"type":"articles"`) || strings.Contains(out, "users") || strings.Contains(out, "homes") {
		t.Fatal(out, err)
	}
	r, err = invoke(m, "list_entries", `{"type":"articles","where":[{"field":"title","op":"contains","value":"a&b=c"},{"field":"views","op":"empty"}],"sort":"-views","status":"draft"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"title":"Hello"`) {
		t.Fatal(out, err)
	}
	if f.query != "filters%5B%24and%5D%5B0%5D%5Btitle%5D%5B%24containsi%5D=a%26b%3Dc&filters%5B%24and%5D%5B1%5D%5Bviews%5D%5B%24null%5D=true&pagination%5BpageSize%5D=25&pagination%5Bpage%5D=1&sort=views%3Adesc&status=draft" {
		t.Fatal(f.query)
	}
	r, err = invoke(m, "get_entry", `{"type":"articles","id":"abc123"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"views":3`) {
		t.Fatal(out, err)
	}

	// Create as a draft; undo deletes it.
	r, err = invoke(m, "create_entry", `{"type":"articles","data":{"title":"New"}}`, false)
	noLeak(t, r, err)
	if err != nil || f.query != "status=draft" || r.Undo == nil || r.Undo.Action != "delete_entry" || string(r.Undo.Input) != `{"id":"new456","type":"articles"}` {
		t.Fatalf("%+v %v %s", r, err, f.query)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.drafts["new456"] != nil {
		t.Fatal(err)
	}

	// Update the draft.
	if r, err := invoke(m, "update_entry", `{"type":"articles","id":"abc123","data":{"title":"Hello"}}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	r, err = invoke(m, "update_entry", `{"type":"articles","id":"abc123","data":{"title":"Hi"}}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"title":"Hello"}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "update_entry", `{"type":"articles","id":"abc123","data":{"title":"Hi"}}`, false); err != nil || f.query != "status=draft" || f.drafts["abc123"]["title"] != "Hi" || f.pub["abc123"] != nil {
		t.Fatal(err, f.query)
	}

	// Publish: preview, real, then nothing to change.
	r, err = invoke(m, "publish_entry", `{"type":"articles","id":"abc123"}`, true)
	if err != nil || r.Plan == nil || f.pub["abc123"] != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "publish_entry", `{"type":"articles","id":"abc123"}`, false)
	if err != nil || f.pub["abc123"] == nil || f.query != "status=published" || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "publish_entry", `{"type":"articles","id":"abc123"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "unpublish_entry", `{"type":"articles","id":"abc123"}`, false); err == nil || !strings.Contains(err.Error(), "can't unpublish") || len(f.seen) != n {
		t.Fatal(err)
	}
	if _, err := invoke(m, "publish_entry", `{"type":"pages","id":"abc123"}`, false); err == nil || !strings.Contains(err.Error(), "drafts") {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_entry", `{"type":"articles","id":"abc123"}`, true)
	if out := noLeak(t, r, err); err != nil || strings.Contains(out, "Hi") {
		t.Fatal(out, err)
	}
	if _, err := invoke(m, "delete_entry", `{"type":"articles","id":"abc123"}`, false); err != nil || f.drafts["abc123"] != nil {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (strings.HasPrefix(a.Name, "delete") || strings.Contains(a.Name, "publish")) && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestStrapi4PublishUnpublish(t *testing.T) {
	m, f := setup(t, "secret://st", true)
	r, err := invoke(m, "get_entry", `{"type":"articles","id":"1"}`, false)
	if out := noLeak(t, r, err); err != nil || !strings.Contains(out, `"title":"Hello"`) || strings.Contains(out, "attributes") {
		t.Fatal(out, err)
	}
	if f.query = ""; true {
		invoke(m, "list_entries", `{"type":"articles"}`, false)
		if !strings.Contains(f.query, "publicationState=preview") {
			t.Fatal(f.query)
		}
	}
	r, err = invoke(m, "publish_entry", `{"type":"articles","id":"1"}`, false)
	if err != nil || f.lastPut != `{"data":{"publishedAt":"2026-11-04T12:00:00Z"}}` || r.Undo == nil || r.Undo.Action != "unpublish_entry" {
		t.Fatalf("%+v %v %s", r, err, f.lastPut)
	}
	if r, err := invoke(m, "publish_entry", `{"type":"articles","id":"1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.lastPut != `{"data":{"publishedAt":null}}` || r.Undo == nil || r.Undo.Action != "publish_entry" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "create_entry", `{"type":"articles","data":{"title":"x"}}`, false); err != nil || f.drafts["new456"]["publishedAt"] != nil {
		t.Fatal(err)
	}
}

func TestStrapiValidation(t *testing.T) {
	m, f := setup(t, "secret://st", false)
	for _, c := range []struct{ action, in string }{
		{"list_entries", `{"type":"../admin"}`},
		{"list_entries", `{"type":"Articles"}`},
		{"get_entry", `{"type":"articles","id":"abc/../1"}`},
		{"get_entry", `{"type":"articles","id":"abc","status":"preview"}`},
		{"list_entries", `{"type":"articles","where":[{"field":"title][$ne","op":"eq","value":"x"}]}`},
		{"list_entries", `{"type":"articles","where":[{"field":"title","op":"$eq","value":"x"}]}`},
		{"create_entry", `{"type":"articles"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []struct{ action, in string }{
		{"list_entries", `{"type":"users"}`},
		{"get_entry", `{"type":"users","id":"1"}`},
		{"list_entries", `{"type":"articles","where":[{"field":"secretNote","op":"eq","value":"x"}]}`},
		{"list_entries", `{"type":"articles","where":[{"field":"author","op":"eq","value":"x"}]}`},
		{"create_entry", `{"type":"articles","data":{"secretNote":"x"}}`},
		{"create_entry", `{"type":"articles","data":{"publishedAt":"2026-01-01"}}`},
		{"create_entry", `{"type":"articles","data":{"nope":1}}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	for _, p := range f.seen {
		if p != "GET /api/content-type-builder/content-types" {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	if _, err := invoke(m, "delete_entry", `{"type":"articles","id":"zzz"}`, false); err == nil || f.drafts["abc123"] == nil {
		t.Fatal(err)
	}
	for _, c := range []Config{{URL: "https://cms.example.com", Token: "plain"}, {URL: "cms.example.com", Token: "secret://st"},
		{URL: "https://cms.example.com/?a=1", Token: "secret://st"}, {URL: "https://u:p@cms.example.com", Token: "secret://st"}, {URL: "https://cms.example.com", Token: "secret://st", Version: 3}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Strapi refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestStrapiRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://st"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://st": "st-good"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
