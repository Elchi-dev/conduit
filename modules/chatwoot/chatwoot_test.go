package chatwoot

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
	status   string
	assignee map[string]any
	msgs     []map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("api_access_token") != "cwtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":["Invalid Access Token"]}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	path := strings.TrimPrefix(r.URL.Path, "/cw/api/v1")
	enc := json.NewEncoder(w)
	conv := func() map[string]any {
		var as any
		if f.assignee != nil {
			as = f.assignee
		}
		return map[string]any{"id": 42, "status": f.status, "inbox_id": 3, "unread_count": 1, "last_activity_at": 1762246800,
			"meta":     map[string]any{"sender": map[string]any{"id": 9, "name": "Jane Customer", "email": "jane@example.com"}, "assignee": as, "channel": "Channel::Email"},
			"messages": []any{map[string]any{"id": 1, "content": "Where is my order?", "message_type": 0}}}
	}
	switch {
	case r.Method == "GET" && path == "/profile":
		enc.Encode(map[string]any{"name": "Sam Agent", "accounts": []any{map[string]any{"id": 5, "name": "Acme"}}})
	case r.Method == "GET" && path == "/accounts/5/conversations":
		enc.Encode(map[string]any{"data": map[string]any{"payload": []any{conv()}}})
	case r.Method == "GET" && path == "/accounts/5/conversations/42":
		enc.Encode(conv())
	case r.Method == "GET" && path == "/accounts/5/conversations/42/messages":
		enc.Encode(map[string]any{"payload": f.msgs})
	case r.Method == "GET" && path == "/accounts/5/agents":
		enc.Encode([]any{map[string]any{"id": 7, "name": "Sam Agent", "role": "agent", "availability_status": "online"}})
	case r.Method == "POST" && path == "/accounts/5/conversations/42/messages":
		f.writes = append(f.writes, string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		msg := map[string]any{"id": 100 + len(f.msgs), "content": in["content"], "message_type": 1, "private": in["private"]}
		f.msgs = append(f.msgs, msg)
		enc.Encode(msg)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/accounts/5/conversations/42/messages/"):
		f.writes = append(f.writes, "DELETE "+path)
		for i, x := range f.msgs {
			b, _ := json.Marshal(x["id"])
			if strings.HasSuffix(path, "/"+string(b)) {
				f.msgs = append(f.msgs[:i], f.msgs[i+1:]...)
			}
		}
		enc.Encode(map[string]any{})
	case r.Method == "POST" && path == "/accounts/5/conversations/42/toggle_status":
		var in map[string]string
		json.Unmarshal(body, &in)
		f.status = in["status"]
		enc.Encode(map[string]any{"payload": map[string]any{"success": true, "current_status": f.status, "conversation_id": 42}})
	case r.Method == "POST" && path == "/accounts/5/conversations/42/assignments":
		var in map[string]any
		json.Unmarshal(body, &in)
		if in["assignee_id"] == nil {
			f.assignee = nil
			io.WriteString(w, "null")
			return
		}
		f.assignee = map[string]any{"id": in["assignee_id"], "name": "Robin Agent"}
		enc.Encode(f.assignee)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Resource could not be found"}`)
	}
}

func setup(t *testing.T, token string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "open", msgs: []map[string]any{
		{"id": 1, "content": "Where is my order?", "message_type": 0, "private": false, "created_at": 1762246800, "sender": map[string]any{"name": "Jane Customer"}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"address": srv.URL + "/cw/", "accountId": 5, "token": token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cw": "cwtok", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestChatwootReads(t *testing.T) {
	m, f := setup(t, "secret://cw")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "Sam Agent in Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"conversations", `{}`, `"lastMessage":"Where is my order?"`},
		{"conversations", `{"status":"all","assignee":"me"}`, `"contact":{"email":"jane@example.com","name":"Jane Customer"}`},
		{"messages", `{"conversation":42}`, `"kind":"contact"`},
		{"messages", `{"conversation":"42"}`, `"at":"2025-11-04T09:00:00Z"`},
		{"agents", `{}`, `"availability":"online"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.Contains(strings.Join(f.seen, " "), "assignee_type=me") {
		t.Fatal(f.seen)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if !spec["messages"].Sensitive || !spec["conversations"].Sensitive || !spec["reply"].Sensitive || spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || !spec["set_status"].Reversible ||
		!spec["add_note"].Sensitive || !spec["delete_note"].Sensitive || spec["resolve"].Risk != sdk.RiskDestructive || spec["set_status"].Risk != sdk.RiskWrite {
		t.Fatalf("%+v", spec)
	}
}

func TestChatwootWrites(t *testing.T) {
	m, f := setup(t, "secret://cw")
	r, err := invoke(m, "reply", `{"conversation":42,"text":"Shipped today"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Jane Customer via Email") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reply", `{"conversation":42,"text":"Shipped today"}`, false); err != nil || f.writes[0] != `{"content":"Shipped today","message_type":"outgoing","private":false}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	r, err = invoke(m, "add_note", `{"conversation":42,"text":"VIP"}`, false)
	if err != nil || f.writes[1] != `{"content":"VIP","message_type":"outgoing","private":true}` || r.Undo == nil || r.Undo.Action != "delete_note" {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}
	if _, err := invoke(m, "delete_note", `{"conversation":42,"note":101}`, false); err == nil {
		t.Fatal("deleted a reply as a note")
	}
	if _, err := invoke(m, "delete_note", `{"conversation":42,"note":1}`, false); err == nil {
		t.Fatal("deleted the contact's message")
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.msgs) != 2 || f.writes[2] != "DELETE /accounts/5/conversations/42/messages/102" {
		t.Fatalf("%v %v", err, f.writes)
	}

	if r, err := invoke(m, "resolve", `{"conversation":42}`, true); err != nil || r.Plan == nil || f.status != "open" || !strings.Contains(r.Plan.Summary, "satisfaction survey or resolution notice") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "resolve", `{"conversation":42}`, false)
	if err != nil || f.status != "resolved" || r.Undo == nil || r.Undo.Action != "set_status" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "open" {
		t.Fatal(err, f.status)
	}
	// Reopening a resolved conversation undoes by resolving it again.
	f.status = "resolved"
	r, err = invoke(m, "set_status", `{"conversation":42,"status":"pending"}`, false)
	if err != nil || f.status != "pending" || r.Undo == nil || r.Undo.Action != "resolve" {
		t.Fatalf("%+v %v", r, err)
	}
	f.status = "open"

	r, err = invoke(m, "assign", `{"conversation":42,"assignee":8}`, false)
	if err != nil || f.assignee == nil || r.Undo == nil || !strings.Contains(string(r.Output), `"to":"Robin Agent"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.assignee != nil {
		t.Fatal(err, f.assignee)
	}
}

func TestChatwootValidation(t *testing.T) {
	m, f := setup(t, "secret://cw")
	for _, c := range []struct{ action, in string }{
		{"messages", `{"conversation":"../../profile"}`},
		{"messages", `{"conversation":"42/messages"}`},
		{"messages", `{}`},
		{"conversations", `{"status":"closed"}`},
		{"conversations", `{"assignee":"someone"}`},
		{"conversations", `{"limit":101}`},
		{"add_note", `{"conversation":42,"text":" "}`},
		{"reply", `{"conversation":42,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"delete_note", `{"conversation":42,"note":"1/../2"}`},
		{"set_status", `{"conversation":42,"status":"snoozed"}`},
		{"set_status", `{"conversation":42,"status":"resolved"}`},
		{"assign", `{"conversation":42}`},
		{"assign", `{"conversation":42,"assignee":"x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"accountId": 5, "token": "plaintoken"},
		{"accountId": "five", "token": "secret://cw"},
		{"token": "secret://cw"},
		{"address": "ftp://chat.example.com", "accountId": 5, "token": "secret://cw"},
		{"address": "https://u:p@chat.example.com", "accountId": 5, "token": "secret://cw"},
		{"address": "https://chat.example.com/?x=1", "accountId": 5, "token": "secret://cw"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "Chatwoot refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestChatwootRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"address": srv.URL, "accountId": "5", "token": "secret://cw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cw": "cwtok"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log, events and webhooks as they are, so they hold numbers and
// statuses, never the contact or a message.
func TestChatwootPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://cw")
	inputs := map[string]string{
		"set_status": `{"conversation":42,"status":"pending"}`,
		"resolve":    `{"conversation":42}`,
		"assign":     `{"conversation":42,"assignee":8}`,
	}
	private := []string{"Jane Customer", "jane@example.com", "Where is my order"}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive || a.Risk == sdk.RiskRead {
			continue
		}
		in, ok := inputs[a.Name]
		if !ok {
			t.Fatalf("no input for %s", a.Name)
		}
		for _, dry := range []bool{true, false} {
			f.status, f.assignee = "open", nil
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
