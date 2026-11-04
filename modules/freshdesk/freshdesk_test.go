package freshdesk

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
	mu        sync.Mutex
	seen      []string
	writes    []string
	status    int
	responder any
	convs     []map[string]any
}

var goodAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte("fdkey:X"))

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != goodAuth {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"invalid_credentials","message":"You have to be logged in to perform this action."}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	enc := json.NewEncoder(w)
	tk := func() map[string]any {
		return map[string]any{"id": 1, "subject": "Refund please", "status": f.status, "priority": 3, "requester_id": 50, "responder_id": f.responder, "tags": []string{"billing"}, "updated_at": "2026-11-04T09:00:00Z", "description_text": "I want my money back",
			"requester": map[string]any{"id": 50, "name": "Jane Customer", "email": "jane@example.com"}}
	}
	switch {
	case r.Method == "GET" && path == "/agents/me":
		enc.Encode(map[string]any{"id": 7, "contact": map[string]any{"name": "Sam Agent"}})
	case r.Method == "GET" && path == "/agents":
		enc.Encode([]any{map[string]any{"id": 7, "contact": map[string]any{"name": "Sam Agent", "email": "sam@acme.test"}}})
	case r.Method == "GET" && path == "/agents/8":
		enc.Encode(map[string]any{"id": 8, "contact": map[string]any{"name": "Robin Agent"}})
	case r.Method == "GET" && path == "/search/tickets":
		enc.Encode(map[string]any{"results": []any{tk()}, "total": 1})
	case r.Method == "GET" && path == "/tickets":
		enc.Encode([]any{tk()})
	case r.Method == "GET" && path == "/tickets/1":
		enc.Encode(tk())
	case r.Method == "GET" && path == "/tickets/1/conversations":
		enc.Encode(f.convs)
	case r.Method == "PUT" && path == "/tickets/1":
		f.writes = append(f.writes, r.Method+" "+path+" "+string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		if s, ok := in["status"].(float64); ok {
			f.status = int(s)
		}
		if v, ok := in["responder_id"]; ok {
			f.responder = v
		}
		enc.Encode(tk())
	case r.Method == "POST" && (path == "/tickets/1/notes" || path == "/tickets/1/reply"):
		f.writes = append(f.writes, r.Method+" "+path+" "+string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		c := map[string]any{"id": 900 + len(f.convs), "body_text": in["body"], "private": in["private"] == true, "source": 0}
		if path == "/tickets/1/notes" {
			c["source"] = 2
		}
		f.convs = append(f.convs, c)
		w.WriteHeader(201)
		enc.Encode(c)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/conversations/"):
		f.writes = append(f.writes, r.Method+" "+path)
		for i, c := range f.convs {
			if "/conversations/"+jsonNum(c["id"]) == path {
				f.convs = append(f.convs[:i], f.convs[i+1:]...)
				w.WriteHeader(204)
				return
			}
		}
		w.WriteHeader(404)
	default:
		w.WriteHeader(404)
	}
}

func jsonNum(v any) string { b, _ := json.Marshal(v); return string(b) }

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: 2, convs: []map[string]any{
		{"id": 100, "body_text": "Any update?", "incoming": true, "private": false, "source": 0, "from_email": "jane@example.com", "created_at": "2026-11-04T08:00:00Z"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Domain: "acme.freshdesk.com", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fd": "fdkey", "secret://bad": "nope"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFreshdeskReads(t *testing.T) {
	m, f := setup(t, "secret://fd")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "Signed in as Sam Agent" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"tickets", `{}`, `"status":"open"`},
		{"tickets", `{"filter":"watching","limit":5}`, `"priority":"high"`},
		{"search", `{"query":"tag:'billing' AND status:2"}`, `"subject":"Refund please"`},
		{"ticket", `{"ticket":1}`, `"requester":{"email":"jane@example.com","id":50,"name":"Jane Customer"}`},
		{"ticket", `{"ticket":"1"}`, `"kind":"customer"`},
		{"agents", `{}`, `"name":"Sam Agent"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	joined := strings.Join(f.seen, "\n")
	for _, want := range []string{"query=%22status%3A2+OR+status%3A3%22", "filter=watching", "query=%22tag%3A%27billing%27+AND+status%3A2%22"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%s not in %s", want, joined)
		}
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if !spec["ticket"].Sensitive || !spec["reply"].Sensitive || spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || spec["delete_note"].Risk != sdk.RiskDestructive ||
		!spec["add_note"].Sensitive || !spec["delete_note"].Sensitive || spec["set_status"].Risk != sdk.RiskWrite || spec["resolve"].Risk != sdk.RiskDestructive {
		t.Fatalf("%+v", spec)
	}
}

func TestFreshdeskWrites(t *testing.T) {
	m, f := setup(t, "secret://fd")
	r, err := invoke(m, "reply", `{"ticket":1,"text":"Refunded <b>today</b>"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "jane@example.com") || len(f.writes) != 0 {
		t.Fatalf("%+v %v %v", r.Plan, err, f.writes)
	}
	if _, err := invoke(m, "reply", `{"ticket":1,"text":"Refunded <b>today</b>\nThanks"}`, false); err != nil || !strings.HasPrefix(f.writes[0], "POST /tickets/1/reply ") {
		t.Fatalf("%v %v", err, f.writes)
	}
	var sent struct{ Body string }
	json.Unmarshal([]byte(strings.TrimPrefix(f.writes[0], "POST /tickets/1/reply ")), &sent)
	if sent.Body != "Refunded &lt;b&gt;today&lt;/b&gt;<br>Thanks" {
		t.Fatalf("body %q", sent.Body)
	}

	r, err = invoke(m, "add_note", `{"ticket":1,"text":"Checked Stripe"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_note" {
		t.Fatalf("%+v %v", r, err)
	}
	// The reply can't be deleted as a note.
	if _, err := invoke(m, "delete_note", `{"ticket":1,"note":901}`, false); err == nil {
		t.Fatal("deleted a reply")
	}
	if _, err := invoke(m, "delete_note", `{"ticket":1,"note":100}`, false); err == nil {
		t.Fatal("deleted a customer message")
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.convs) != 2 || f.writes[len(f.writes)-1] != "DELETE /conversations/902" {
		t.Fatalf("%v %v", err, f.writes)
	}

	if r, err := invoke(m, "resolve", `{"ticket":1}`, true); err != nil || r.Plan == nil || f.status != 2 || !strings.Contains(r.Plan.Summary, "may email the requester (satisfaction survey or resolution notice)") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "resolve", `{"ticket":1}`, false)
	if err != nil || f.status != 4 || r.Undo == nil || r.Undo.Action != "set_status" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != 2 {
		t.Fatal(err, f.status)
	}
	if _, err := invoke(m, "resolve", `{"ticket":1,"status":"closed"}`, false); err != nil || f.status != 5 {
		t.Fatal(err, f.status)
	}
	// Reopening a closed ticket undoes by closing it again.
	r, err = invoke(m, "set_status", `{"ticket":1,"status":"pending"}`, false)
	if err != nil || f.status != 3 || r.Undo == nil || r.Undo.Action != "resolve" || !strings.Contains(string(r.Undo.Input), `"closed"`) {
		t.Fatalf("%+v %v", r, err)
	}
	f.status = 2

	r, err = invoke(m, "assign", `{"ticket":1,"assignee":8}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "from nobody to Robin Agent") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "assign", `{"ticket":1,"assignee":8}`, false)
	if err != nil || f.responder != float64(8) || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.responder != nil {
		t.Fatal(err, f.responder)
	}
}

func TestFreshdeskValidation(t *testing.T) {
	m, f := setup(t, "secret://fd")
	for _, c := range []struct{ action, in string }{
		{"ticket", `{"ticket":"../agents/me"}`},
		{"ticket", `{"ticket":"1?x=1"}`},
		{"ticket", `{}`},
		{"ticket", `{"ticket":1,"conversations":101}`},
		{"tickets", `{"filter":"spam"}`},
		{"tickets", `{"limit":500}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"status:2\" OR \"x"}`},
		{"search", `{"query":"a\nb"}`},
		{"add_note", `{"ticket":1,"text":""}`},
		{"reply", `{"ticket":1,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"delete_note", `{"ticket":1,"note":"../tickets/1"}`},
		{"set_status", `{"ticket":1,"status":"deleted"}`},
		{"set_status", `{"ticket":1,"status":"resolved"}`},
		{"set_status", `{"ticket":1,"status":"closed"}`},
		{"resolve", `{"ticket":1,"status":"open"}`},
		{"assign", `{"ticket":1,"assignee":"sam"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Domain: "acme", APIKey: "plainkey"},
		{Domain: "acme.evil.com", APIKey: "secret://fd"},
		{Domain: "", APIKey: "secret://fd"},
		{Domain: "a@b", APIKey: "secret://fd"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || h.Message != "Freshdesk refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestFreshdeskRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Domain: "acme", APIKey: "secret://fd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fd": "fdkey"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log, events and webhooks as they are, so they hold numbers and
// statuses, never the ticket's subject, the requester or a note.
func TestFreshdeskPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://fd")
	f.convs = append(f.convs, map[string]any{"id": 101, "body_text": "Card ends 4242", "private": true, "source": 2})
	inputs := map[string]string{
		"set_status": `{"ticket":1,"status":"pending"}`,
		"resolve":    `{"ticket":1}`,
		"assign":     `{"ticket":1,"assignee":8}`,
	}
	private := []string{"Refund please", "Jane Customer", "jane@example.com", "money back", "4242"}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive || a.Risk == sdk.RiskRead {
			continue
		}
		in, ok := inputs[a.Name]
		if !ok {
			t.Fatalf("no input for %s", a.Name)
		}
		for _, dry := range []bool{true, false} {
			f.status, f.responder = 2, nil
			r, err := invoke(m, a.Name, in, dry)
			if err != nil {
				t.Fatalf("%s: %v", a.Name, err)
			}
			b, _ := json.Marshal(r)
			for _, p := range private {
				if strings.Contains(string(b), p) {
					t.Errorf("%s (dry run %v) shows %q: %s", a.Name, dry, p, b)
				}
			}
		}
	}
}
