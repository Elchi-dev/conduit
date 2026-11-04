package directus

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

const (
	hookID   = "11111111-2222-3333-4444-555555555555"
	cronID   = "99999999-2222-3333-4444-555555555555"
	pausedID = "88888888-2222-3333-4444-555555555555"
)

type fakeDirectus struct {
	mu       sync.Mutex
	seen     []string
	filter   string
	items    map[string]map[string]any
	next     int
	hookBody string
}

func (f *fakeDirectus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer dx-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Invalid user credentials.","extensions":{"code":"INVALID_CREDENTIALS"}}]}`)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/items/articles/")
	switch {
	case r.URL.Path == "/collections":
		io.WriteString(w, `{"data":[{"collection":"articles","meta":{"note":"Blog","singleton":false,"hidden":false},"schema":{"name":"articles"}},{"collection":"directus_users","meta":null,"schema":{"name":"directus_users"}},{"collection":"folder1","meta":{},"schema":null}]}`)
	case r.URL.Path == "/fields/articles":
		io.WriteString(w, `{"data":[
			{"field":"id","type":"integer","schema":{"is_primary_key":true,"has_auto_increment":true}},
			{"field":"title","type":"string","meta":{"interface":"input","required":true}},
			{"field":"pin","type":"hash","meta":{"special":["hash"],"interface":"input-hash"}},
			{"field":"api_key","type":"string","meta":{"interface":"input","options":{"masked":true}}},
			{"field":"tags","type":"alias","meta":{"special":["o2m"]}},
			{"field":"author","type":"uuid","meta":{"special":["m2o"]}},
			{"field":"cover","type":"uuid","meta":{"special":["file"]}},
			{"field":"extra","type":"json","meta":{"special":["cast-json"]}},
			{"field":"date_created","type":"timestamp","meta":{"special":["date-created"]}}]}`)
	case r.Method == "GET" && r.URL.Path == "/items/articles":
		f.filter = r.URL.Query().Get("filter")
		rows := []map[string]any{}
		for _, x := range f.items {
			rows = append(rows, x)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": rows, "meta": map[string]any{"filter_count": len(rows)}})
	case r.Method == "GET" && f.items[id] != nil:
		json.NewEncoder(w).Encode(map[string]any{"data": f.items[id]})
	case r.Method == "GET" && r.URL.Path == "/items/articles/7": // answers with another item
		json.NewEncoder(w).Encode(map[string]any{"data": f.items["1"]})
	case r.Method == "POST" && r.URL.Path == "/items/articles":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.next++
		b["id"], b["pin"] = float64(f.next), "$argon2id$LEAKME"
		f.items[fmt.Sprint(f.next)] = b
		json.NewEncoder(w).Encode(map[string]any{"data": b})
	case r.Method == "PATCH" && f.items[id] != nil:
		var b map[string]any
		json.Unmarshal(body, &b)
		for k, v := range b {
			f.items[id][k] = v
		}
		json.NewEncoder(w).Encode(map[string]any{"data": f.items[id]})
	case r.Method == "DELETE" && f.items[id] != nil:
		delete(f.items, id)
		w.WriteHeader(204)
	case r.URL.Path == "/flows":
		io.WriteString(w, `{"data":[{"id":"`+hookID+`","name":"Notify","status":"active","trigger":"webhook","options":{"method":"POST"}},{"id":"`+cronID+`","name":"Nightly","status":"active","trigger":"schedule","options":{"cron":"0 0 * * *"}}]}`)
	case r.URL.Path == "/flows/"+hookID:
		io.WriteString(w, `{"data":{"id":"`+hookID+`","name":"Notify","status":"active","trigger":"webhook","options":{"method":"POST"}}}`)
	case r.URL.Path == "/flows/"+cronID:
		io.WriteString(w, `{"data":{"id":"`+cronID+`","name":"Nightly","status":"active","trigger":"schedule"}}`)
	case r.URL.Path == "/flows/"+pausedID:
		io.WriteString(w, `{"data":{"id":"`+pausedID+`","name":"Off","status":"inactive","trigger":"webhook"}}`)
	case r.Method == "POST" && r.URL.Path == "/flows/trigger/"+hookID:
		f.hookBody = string(body)
		io.WriteString(w, `{"sent":true}`)
	default:
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeDirectus) {
	f := &fakeDirectus{next: 1, items: map[string]map[string]any{"1": {"id": 1.0, "title": "Hello", "pin": "$argon2id$LEAKME", "api_key": "LEAKME", "date_created": "2026-11-01T00:00:00Z"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dx": "dx-good", "secret://bad": "dx-bad"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
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
	if strings.Contains(s, "LEAKME") || strings.Contains(s, "dx-good") {
		t.Fatalf("leaked: %s", s)
	}
	return s
}

func TestDirectus(t *testing.T) {
	m, f := setup(t, "secret://dx")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "2 collections" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"collections", `{}`, `"note":"Blog"`},
		{"fields", `{"collection":"articles"}`, `"secret":true,"type":"hash"`},
		{"list_items", `{"collection":"articles","where":[{"field":"title","op":"contains","value":"He\"l"},{"field":"date_created","op":"notempty"}],"sort":"-title"}`, `"title":"Hello"`},
		{"get_item", `{"collection":"articles","id":1}`, `"title":"Hello"`},
		{"flows", `{}`, `"method":"POST"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := noLeak(t, r, err); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "directus_users") || strings.Contains(out, "api_key\":") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.filter != `{"_and":[{"title":{"_contains":"He\"l"}},{"date_created":{"_nnull":true}}]}` {
		t.Fatal(f.filter)
	}

	r, err := invoke(m, "create_item", `{"collection":"articles","data":{"title":"New"}}`, true)
	if err != nil || r.Plan == nil || len(f.items) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_item", `{"collection":"articles","data":{"title":"New"}}`, false)
	noLeak(t, r, err)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"collection":"articles","id":"2"}` || r.Undo.Action != "delete_item" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.items["2"] != nil {
		t.Fatal(err)
	}

	if _, err := invoke(m, "update_item", `{"collection":"articles","id":"1","data":{"author":"`+hookID+`","extra":{"a":[1]}}}`, true); err != nil {
		t.Fatal(err)
	}
	if r, err := invoke(m, "update_item", `{"collection":"articles","id":"1","data":{"title":"Hello"}}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	r, err = invoke(m, "update_item", `{"collection":"articles","id":"1","data":{"title":"Hi"}}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"title":"Hello"}` || f.items["1"]["title"] != "Hello" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "update_item", `{"collection":"articles","id":"1","data":{"title":"Hi"}}`, false); err != nil || f.items["1"]["title"] != "Hi" || r.Undo != nil {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_item", `{"collection":"articles","id":"1"}`, true)
	if out := noLeak(t, r, err); err != nil || strings.Contains(out, "Hi") || f.items["1"] == nil {
		t.Fatal(out, err)
	}
	if _, err := invoke(m, "delete_item", `{"collection":"articles","id":"1"}`, false); err != nil || f.items["1"] != nil {
		t.Fatal(err)
	}

	// Flows.
	r, err = invoke(m, "trigger_flow", `{"flow":"`+hookID+`","payload":{"to":"ops"}}`, true)
	if err != nil || r.Plan == nil || f.hookBody != "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "trigger_flow", `{"flow":"`+hookID+`","payload":{"to":"ops"}}`, false); err != nil || f.hookBody != `{"to":"ops"}` || !strings.Contains(string(r.Output), `"sent":true`) {
		t.Fatal(string(r.Output), err)
	}
	for _, id := range []string{cronID, pausedID} {
		if _, err := invoke(m, "trigger_flow", `{"flow":"`+id+`"}`, false); err == nil {
			t.Fatalf("ran %s", id)
		}
	}
	specs := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		specs[a.Name] = a
	}
	if specs["trigger_flow"].Risk != sdk.RiskDestructive || !specs["trigger_flow"].Sensitive || specs["delete_item"].Risk != sdk.RiskDestructive || !specs["list_items"].Sensitive {
		t.Fatal(specs)
	}
}

func TestDirectusValidation(t *testing.T) {
	m, f := setup(t, "secret://dx")
	for _, c := range []struct{ action, in string }{
		{"list_items", `{"collection":"directus_users"}`},
		{"get_item", `{"collection":"DIRECTUS_sessions","id":"1"}`},
		{"list_items", `{"collection":"../users"}`},
		{"get_item", `{"collection":"articles","id":"1/../../users"}`},
		{"get_item", `{"collection":"articles","id":{"_eq":1}}`},
		{"list_items", `{"collection":"articles","where":[{"field":"user_created.email","op":"eq","value":"x"}]}`},
		{"list_items", `{"collection":"articles","where":[{"field":"title","op":"_eq","value":"x"}]}`},
		{"list_items", `{"collection":"articles","where":[{"field":"title","op":"eq","value":["x"]}]}`},
		{"create_item", `{"collection":"articles"}`},
		{"trigger_flow", `{"flow":"../flows"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []struct{ action, in string }{
		{"list_items", `{"collection":"articles","where":[{"field":"pin","op":"eq","value":"1234"}]}`},
		{"list_items", `{"collection":"articles","sort":"api_key"}`},
		{"create_item", `{"collection":"articles","data":{"pin":"1234"}}`},
		{"create_item", `{"collection":"articles","data":{"id":5}}`},
		{"create_item", `{"collection":"articles","data":{"date_created":"x"}}`},
		{"update_item", `{"collection":"articles","id":"1","data":{"tags":[1]}}`},
		// Nested writes reach the related collection (directus_users, directus_files).
		{"create_item", `{"collection":"articles","data":{"title":"x","author":{"email":"a@b.c","password":"p","role":"admin"}}}`},
		{"update_item", `{"collection":"articles","id":"1","data":{"author":{"id":"u1","password":"p"}}}`},
		{"update_item", `{"collection":"articles","id":"1","data":{"cover":{"id":"f1","title":"x"}}}`},
		{"update_item", `{"collection":"articles","id":"1","data":{"title":["x"]}}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	for _, p := range f.seen {
		if strings.HasPrefix(p, "GET /items") || strings.HasPrefix(p, "POST") || strings.HasPrefix(p, "PATCH") {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	// The item changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "delete_item", `{"collection":"articles","id":"7"}`, false); err == nil || f.items["1"] == nil {
		t.Fatal(err)
	}
	for _, c := range []Config{{URL: "https://d.example.com", Token: "plain"}, {URL: "d.example.com", Token: "secret://dx"},
		{URL: "https://d.example.com/?a=1", Token: "secret://dx"}, {URL: "https://u:p@d.example.com", Token: "secret://dx"}, {Token: "secret://dx"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "Directus refused the token" {
		t.Fatalf("%+v", h)
	}
}

func TestDirectusRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://dx"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dx": "dx-good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
