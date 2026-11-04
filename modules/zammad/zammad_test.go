package zammad

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

type fake struct {
	mu       sync.Mutex
	seen     []string
	writes   []string
	state    string
	pending  any
	articles []map[string]any
	oldStyle bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Token token=zmtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Invalid token!"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	enc := json.NewEncoder(w)
	tk := func() map[string]any {
		return map[string]any{"id": 42, "number": "31001", "title": "VPN broken", "state": f.state, "priority": "2 normal", "group": "Users", "owner": "sam", "owner_id": 3,
			"customer": "jane@example.com", "customer_id": 9, "pending_time": f.pending, "updated_at": "2026-11-04T09:00:00Z"}
	}
	switch {
	case r.Method == "GET" && path == "/users/me":
		enc.Encode(map[string]any{"id": 3, "firstname": "Sam", "lastname": "Agent", "login": "sam"})
	case r.Method == "GET" && path == "/users/9":
		enc.Encode(map[string]any{"id": 9, "firstname": "Jane", "lastname": "Customer", "email": "jane@example.com"})
	case r.Method == "GET" && path == "/tickets/search":
		if f.oldStyle {
			enc.Encode(map[string]any{"tickets": []int{42}, "assets": map[string]any{"Ticket": map[string]any{"42": tk()}}})
			return
		}
		enc.Encode([]any{tk()})
	case path == "/tickets/42" && (r.Method == "GET" || r.Method == "PUT"):
		if r.Method == "PUT" {
			f.writes = append(f.writes, string(body))
			var in map[string]any
			json.Unmarshal(body, &in)
			f.state = in["state"].(string)
			f.pending = in["pending_time"]
		}
		enc.Encode(tk())
	case r.Method == "GET" && path == "/ticket_articles/by_ticket/42":
		enc.Encode(f.articles)
	case r.Method == "POST" && path == "/ticket_articles":
		f.writes = append(f.writes, string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		a := map[string]any{"id": 500 + len(f.articles), "ticket_id": 42, "body": in["body"], "internal": in["internal"], "type": in["type"], "sender": "Agent", "content_type": "text/plain"}
		f.articles = append(f.articles, a)
		w.WriteHeader(201)
		enc.Encode(a)
	case strings.HasPrefix(path, "/ticket_articles/"):
		for i, a := range f.articles {
			b, _ := json.Marshal(a["id"])
			if path != "/ticket_articles/"+string(b) {
				continue
			}
			if r.Method == "DELETE" {
				f.writes = append(f.writes, "DELETE "+path)
				f.articles = append(f.articles[:i], f.articles[i+1:]...)
				enc.Encode(map[string]any{})
				return
			}
			enc.Encode(a)
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not authorized"}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, token string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "open", articles: []map[string]any{
		{"id": 100, "ticket_id": 42, "from": "Jane Customer <jane@example.com>", "body": "<p>It&#39;s down</p><br>since 9", "content_type": "text/html", "internal": false, "type": "email", "sender": "Customer", "created_at": "2026-11-04T08:00:00Z"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL + "/", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://zm": "zmtok", "secret://bad": "nope"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "z", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestZammadReads(t *testing.T) {
	m, f := setup(t, "secret://zm")
	if h := m.Health(context.Background(), "z"); h.Status != "ok" || h.Message != "Signed in as Sam Agent" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"tickets", `{}`, `"title":"VPN broken"`},
		{"tickets", `{"mine":true}`, `"number":"31001"`},
		{"search", `{"query":"vpn"}`, `"customer":"jane@example.com"`},
		{"ticket", `{"ticket":42}`, `"text":"It's down\n\nsince 9"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.Contains(strings.Join(f.seen, " "), "owner_id%3A3") {
		t.Fatal(f.seen)
	}
	f.oldStyle = true
	if r, err := invoke(m, "tickets", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"ticket":42`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if !spec["ticket"].Sensitive || !spec["reply"].Sensitive || spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || !spec["set_state"].Reversible {
		t.Fatalf("%+v", spec)
	}
}

func TestZammadWrites(t *testing.T) {
	m, f := setup(t, "secret://zm")
	r, err := invoke(m, "reply", `{"ticket":42,"text":"Fixed it"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Jane Customer <jane@example.com>") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reply", `{"ticket":42,"text":"Fixed it"}`, false); err != nil ||
		f.writes[0] != `{"body":"Fixed it","content_type":"text/plain","internal":false,"subject":"VPN broken","ticket_id":42,"to":"jane@example.com","type":"email"}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	r, err = invoke(m, "add_note", `{"ticket":42,"text":"Router rebooted"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_note" || !strings.Contains(f.writes[1], `"internal":true`) {
		t.Fatalf("%+v %v", r, err)
	}
	for _, id := range []string{"100", "501"} { // the customer's email, the reply
		if _, err := invoke(m, "delete_note", `{"ticket":42,"note":`+id+`}`, false); err == nil {
			t.Fatalf("deleted article %s", id)
		}
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.articles) != 2 || f.writes[2] != "DELETE /ticket_articles/502" {
		t.Fatalf("%v %v", err, f.writes)
	}

	if r, err := invoke(m, "set_state", `{"ticket":42,"state":"closed"}`, true); err != nil || r.Plan == nil || f.state != "open" {
		t.Fatal(err)
	}
	r, err = invoke(m, "set_state", `{"ticket":42,"state":"pending reminder","pendingUntil":"2026-11-10T09:00:00+01:00"}`, false)
	if err != nil || f.state != "pending reminder" || f.pending != "2026-11-10T08:00:00Z" || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "set_state", `{"ticket":42,"state":"closed"}`, false)
	if err != nil || f.state != "closed" || r.Undo == nil || !strings.Contains(string(r.Undo.Input), `"pendingUntil":"2026-11-10T08:00:00Z"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "pending reminder" {
		t.Fatal(err, f.state)
	}
}

func TestZammadValidation(t *testing.T) {
	m, f := setup(t, "secret://zm")
	for _, c := range []struct{ action, in string }{
		{"ticket", `{"ticket":"../users/me"}`},
		{"ticket", `{"ticket":"42?expand=false"}`},
		{"ticket", `{}`},
		{"ticket", `{"ticket":42,"articles":0.5}`},
		{"tickets", `{"limit":101}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"a\nb"}`},
		{"add_note", `{"ticket":42,"text":""}`},
		{"reply", `{"ticket":42,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"delete_note", `{"ticket":42,"note":"x"}`},
		{"set_state", `{"ticket":42,"state":"merged"}`},
		{"set_state", `{"ticket":42,"state":"pending close"}`},
		{"set_state", `{"ticket":42,"state":"pending close","pendingUntil":"tomorrow"}`},
		{"set_state", `{"ticket":42,"state":"pending close","pendingUntil":"2099-01-01T00:00:00Z"}`},
		{"set_state", `{"ticket":42,"state":"open","pendingUntil":"2026-11-10T09:00:00Z"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Address: "https://support.example.com", Token: "plaintoken"},
		{Address: "", Token: "secret://zm"},
		{Address: "support.example.com", Token: "secret://zm"},
		{Address: "https://u:p@support.example.com", Token: "secret://zm"},
		{Address: "https://support.example.com", Token: "secret://zm", Fingerprint: "nothex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "z"); h.Status != "down" || h.Message != "Zammad refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestZammadRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: "secret://zm"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://zm": "zmtok"}), "z", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "z"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
