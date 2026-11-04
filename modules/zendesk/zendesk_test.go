package zendesk

import (
	"context"
	"encoding/base64"
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

type fake struct {
	mu       sync.Mutex
	seen     []string
	writes   []string
	status   string
	assignee any
}

var goodAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte("agent@example.com/token:zdtok"))

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := r.Header.Get("Authorization"); a != goodAuth && a != "Bearer oauthtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Couldn't authenticate you"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	enc := json.NewEncoder(w)
	tk := func() map[string]any {
		return map[string]any{"id": 1, "subject": "Printer on fire", "status": f.status, "priority": "high", "requester_id": 50, "assignee_id": f.assignee, "tags": []string{"hw"}, "updated_at": "2026-11-04T09:00:00Z", "via": map[string]any{"channel": "email"}}
	}
	users := []any{map[string]any{"id": 50, "name": "Jane Customer", "email": "jane@example.com", "role": "end-user"}, map[string]any{"id": 7, "name": "Sam Agent", "email": "sam@acme.test", "role": "agent"}}
	switch {
	case r.Method == "GET" && path == "/users/me.json":
		enc.Encode(map[string]any{"user": map[string]any{"id": 7, "name": "Sam Agent", "role": "agent"}})
	case r.Method == "GET" && path == "/views/active.json":
		enc.Encode(map[string]any{"views": []any{map[string]any{"id": 360, "title": "Unassigned"}}})
	case r.Method == "GET" && path == "/views/360/tickets.json":
		enc.Encode(map[string]any{"tickets": []any{tk()}})
	case r.Method == "GET" && path == "/search.json":
		t := tk()
		t["result_type"] = "ticket"
		enc.Encode(map[string]any{"results": []any{t, map[string]any{"id": 9, "result_type": "user"}}})
	case r.Method == "GET" && path == "/tickets/1.json":
		enc.Encode(map[string]any{"ticket": tk(), "users": users})
	case r.Method == "GET" && path == "/tickets/1/comments.json":
		enc.Encode(map[string]any{"comments": []any{
			map[string]any{"id": 3, "author_id": 7, "plain_body": "Checking", "public": false, "created_at": "2026-11-04T09:00:00Z"},
			map[string]any{"id": 2, "author_id": 50, "plain_body": "It's on fire", "public": true, "created_at": "2026-11-04T08:00:00Z"},
		}, "users": users})
	case r.Method == "GET" && path == "/users.json":
		enc.Encode(map[string]any{"users": users[1:]})
	case r.Method == "GET" && path == "/users/8.json":
		enc.Encode(map[string]any{"user": map[string]any{"id": 8, "name": "Robin Agent"}})
	case r.Method == "PUT" && path == "/tickets/1.json":
		f.writes = append(f.writes, string(body))
		var in struct {
			Ticket map[string]any `json:"ticket"`
		}
		json.Unmarshal(body, &in)
		if s, ok := in.Ticket["status"].(string); ok {
			f.status = s
		}
		if v, ok := in.Ticket["assignee_id"]; ok {
			f.assignee = v
		}
		enc.Encode(map[string]any{"ticket": tk()})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"RecordNotFound","description":"Not found"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "new", assignee: nil}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(cfg)
	hst := fakehost.New(map[string]string{"secret://zd": "zdtok", "secret://oauth": "oauthtok", "secret://bad": "nope"})
	if err := m.Configure(context.Background(), hst, "z", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

var good = Config{Subdomain: "acme", Email: "agent@example.com", Token: "secret://zd"}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZendeskReads(t *testing.T) {
	m, _ := setup(t, good)
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "Signed in as Sam Agent" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"views", `{}`, `"view":360`},
		{"tickets", `{"view":360}`, `"subject":"Printer on fire"`},
		{"tickets", `{}`, `"url":"http`},
		{"search", `{"query":"printer"}`, `"ticket":1`},
		{"ticket", `{"ticket":"#1"}`, `"requester":{"email":"jane@example.com","id":50,"name":"Jane Customer"}`},
		{"ticket", `{"ticket":1}`, `{"at":"2026-11-04T08:00:00Z","author":"Jane Customer","id":2,"kind":"public","text":"It's on fire"}`},
		{"agents", `{}`, `"name":"Sam Agent"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "search", `{"query":"printer"}`, false)
	if strings.Contains(string(r.Output), `"ticket":9`) {
		t.Fatal("a user result was listed as a ticket")
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	for _, n := range []string{"ticket", "tickets", "search", "reply"} {
		if !spec[n].Sensitive {
			t.Errorf("%s isn't sensitive", n)
		}
	}
	if spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || spec["set_status"].Risk != sdk.RiskWrite || !spec["set_status"].Reversible || !spec["assign"].Reversible {
		t.Fatalf("%+v", spec)
	}
}

func TestZendeskWrites(t *testing.T) {
	m, f := setup(t, Config{Subdomain: "https://acme.zendesk.com/", OAuthToken: "secret://oauth"})

	// Previews change nothing.
	r, err := invoke(m, "reply", `{"ticket":1,"text":"We're on it."}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "jane@example.com") || !strings.Contains(r.Plan.Summary, "can't be unsent") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "add_note", `{"ticket":1,"text":"Internal"}`, true); err != nil || r.Plan == nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a preview wrote: %v", f.writes)
	}

	if _, err := invoke(m, "add_note", `{"ticket":1,"text":"  Checked the logs  "}`, false); err != nil || f.writes[0] != `{"ticket":{"comment":{"body":"Checked the logs","public":false}}}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	if _, err := invoke(m, "reply", `{"ticket":1,"text":"Fixed"}`, false); err != nil || f.writes[1] != `{"ticket":{"comment":{"body":"Fixed","public":true}}}` {
		t.Fatalf("%v %v", err, f.writes)
	}

	r, err = invoke(m, "set_status", `{"ticket":1,"status":"solved"}`, true)
	if err != nil || r.Plan == nil || f.status != "new" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "set_status", `{"ticket":1,"status":"solved"}`, false)
	if err != nil || f.status != "solved" || r.Undo == nil || r.Undo.Action != "set_status" || !strings.Contains(string(r.Undo.Input), `"open"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "open" {
		t.Fatal(err, f.status)
	}

	r, err = invoke(m, "assign", `{"ticket":1,"assignee":8}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from nobody to Robin Agent") || f.assignee != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "assign", `{"ticket":1,"assignee":"8"}`, false)
	if err != nil || f.assignee != float64(8) || r.Undo == nil {
		t.Fatalf("%+v %v %v", r, err, f.assignee)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.assignee != nil {
		t.Fatal(err, f.assignee)
	}
}

func TestZendeskValidation(t *testing.T) {
	m, f := setup(t, good)
	for _, c := range []struct{ action, in string }{
		{"ticket", `{"ticket":"../users/me"}`},
		{"ticket", `{"ticket":"1.json?x"}`},
		{"ticket", `{"ticket":-1}`},
		{"ticket", `{"ticket":1.5}`},
		{"ticket", `{}`},
		{"ticket", `{"ticket":1,"comments":500}`},
		{"tickets", `{"view":"1/../2"}`},
		{"tickets", `{"limit":0.5}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"a\nb"}`},
		{"search", `{"query":"` + strings.Repeat("x", 501) + `"}`},
		{"add_note", `{"ticket":1,"text":"   "}`},
		{"reply", `{"ticket":1,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"reply", `{"ticket":1,"text":"bell\u0007"}`},
		{"set_status", `{"ticket":1,"status":"closed"}`},
		{"set_status", `{"ticket":1,"status":"new"}`},
		{"assign", `{"ticket":1}`},
		{"assign", `{"ticket":1,"assignee":"me"}`},
		{"assign", `{"ticket":1,"assignee":8,"unassign":true}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Subdomain: "acme", Email: "agent@example.com", Token: "plaintoken"},
		{Subdomain: "acme", OAuthToken: "plaintoken"},
		{Subdomain: "acme.evil.com", Email: "agent@example.com", Token: "secret://zd"},
		{Subdomain: "ac/me", Email: "agent@example.com", Token: "secret://zd"},
		{Subdomain: "acme", Token: "secret://zd"},
		{Subdomain: "acme", Email: "a:b@example.com", Token: "secret://zd"},
		{Subdomain: "acme", Email: "agent@example.com", Token: "secret://zd", OAuthToken: "secret://oauth"},
		{Subdomain: "acme"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Subdomain: "acme", Email: "agent@example.com", Token: "secret://bad"})
	if h := bad.Health(context.Background(), "z"); h.Status != "down" || !strings.Contains(h.Message, "refused the credentials") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "ticket", `{"ticket":1}`, false); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

func TestZendeskRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(good)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://zd": "zdtok"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "z"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
