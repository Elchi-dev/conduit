package intercom

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

type fake struct {
	mu     sync.Mutex
	seen   []string
	writes []string
	state  string
	until  int64
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer ictok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"error.list","errors":[{"code":"unauthorized","message":"Access Token Invalid"}]}`)
		return
	}
	if r.Header.Get("Intercom-Version") != apiVersion {
		w.WriteHeader(400)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	enc := json.NewEncoder(w)
	conv := func() map[string]any {
		return map[string]any{"id": "1001", "title": "Order", "state": f.state, "snoozed_until": f.until, "created_at": 1762246800, "updated_at": 1762250400, "admin_assignee_id": 7,
			"source": map[string]any{"type": "conversation", "body": "<p>Where is my order?</p>", "author": map[string]any{"type": "user", "id": "abc", "name": "Jane Customer", "email": "jane@example.com"}},
			"conversation_parts": map[string]any{"conversation_parts": []any{
				map[string]any{"id": "1", "part_type": "comment", "body": "Looking", "created_at": 1762250000, "author": map[string]any{"type": "admin", "name": "Sam Agent"}},
				map[string]any{"id": "2", "part_type": "note", "body": "VIP", "created_at": 1762250100, "author": map[string]any{"type": "admin", "name": "Sam Agent"}},
			}}}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /me":
		enc.Encode(map[string]any{"type": "admin", "id": "7", "name": "Sam Agent", "email": "sam@acme.test", "app": map[string]any{"name": "Acme"}})
	case "POST /conversations/search":
		f.writes = append(f.writes, "search "+string(body))
		enc.Encode(map[string]any{"conversations": []any{conv()}})
	case "GET /conversations/1001":
		enc.Encode(conv())
	case "POST /conversations/1001/reply":
		f.writes = append(f.writes, string(body))
		enc.Encode(conv())
	case "POST /conversations/1001/parts":
		f.writes = append(f.writes, string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		f.state = map[string]string{"open": "open", "close": "closed", "snoozed": "snoozed"}[in["message_type"].(string)]
		f.until = 0
		if u, ok := in["snoozed_until"].(float64); ok {
			f.until = int64(u)
		}
		enc.Encode(conv())
	case "POST /contacts/search":
		f.writes = append(f.writes, "contacts "+string(body))
		enc.Encode(map[string]any{"data": []any{map[string]any{"id": "abc", "role": "user", "name": "Jane Customer", "email": "jane@example.com", "last_seen_at": 1762246800}}})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"type":"error.list","errors":[{"code":"not_found","message":"Resource Not Found"}]}`)
	}
}

func setup(t *testing.T, token string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "open"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL
	raw, _ := json.Marshal(map[string]any{"region": "eu", "token": token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ic": "ictok", "secret://bad": "nope"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestIntercomReads(t *testing.T) {
	m, f := setup(t, "secret://ic")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" || h.Message != "Signed in as Sam Agent in Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"conversations", `{}`, `"message":"Where is my order?"`},
		{"conversations", `{"state":"all","limit":5}`, `"assigneeId":"7"`},
		{"conversation", `{"conversation":1001}`, `"kind":"internal note"`},
		{"conversation", `{"conversation":"1001"}`, `"kind":"reply"`},
		{"contacts", `{"query":"jane"}`, `"email":"jane@example.com"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.Contains(strings.Join(f.writes, " "), `"value":"open"`) {
		t.Fatal(f.writes)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if !spec["conversations"].Sensitive || !spec["conversation"].Sensitive || !spec["contacts"].Sensitive || !spec["reply"].Sensitive || !spec["add_note"].Sensitive ||
		spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || spec["close"].Risk != sdk.RiskDestructive ||
		spec["snooze"].Risk != sdk.RiskWrite || spec["open"].Risk != sdk.RiskWrite || !spec["close"].Reversible || spec["add_note"].Reversible {
		t.Fatalf("%+v", spec)
	}
}

func TestIntercomWrites(t *testing.T) {
	m, f := setup(t, "secret://ic")
	r, err := invoke(m, "reply", `{"conversation":1001,"text":"Shipped today"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Jane Customer <jane@example.com>") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reply", `{"conversation":1001,"text":"Shipped today"}`, false); err != nil || f.writes[0] != `{"admin_id":"7","body":"\u003cp\u003eShipped today\u003c/p\u003e","message_type":"comment","type":"admin"}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	r, err = invoke(m, "add_note", `{"conversation":1001,"text":"ask @kim"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "mentions @kim") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "add_note", `{"conversation":1001,"text":"VIP"}`, false); err != nil || r.Undo != nil || f.writes[1] != `{"admin_id":"7","body":"\u003cp\u003eVIP\u003c/p\u003e","message_type":"note","type":"admin"}` {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}

	if r, err := invoke(m, "open", `{"conversation":1001}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil || len(f.writes) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "close", `{"conversation":1001}`, true)
	if err != nil || r.Plan == nil || f.state != "open" || !strings.Contains(r.Plan.Summary, "rate it") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "close", `{"conversation":1001}`, false)
	if err != nil || f.state != "closed" || r.Undo == nil || r.Undo.Action != "open" {
		t.Fatalf("%+v %v %s", r, err, f.state)
	}
	if !strings.Contains(f.writes[2], `"message_type":"close"`) {
		t.Fatal(f.writes)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "open" {
		t.Fatal(err, f.state)
	}
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	r, err = invoke(m, "snooze", `{"conversation":1001,"until":"`+until+`"}`, false)
	if err != nil || f.state != "snoozed" || f.until == 0 || r.Undo == nil || r.Undo.Action != "open" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "snooze", `{"conversation":1001,"until":"`+until+`"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	// Reopening a snoozed conversation undoes by snoozing it to the same time.
	r, err = invoke(m, "open", `{"conversation":1001}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "snooze" || !strings.Contains(string(r.Undo.Input), until) {
		t.Fatalf("%+v %v", r, err)
	}
	// Reopening a closed one undoes by closing it.
	f.state = "closed"
	r, err = invoke(m, "open", `{"conversation":1001}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "close" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestIntercomValidation(t *testing.T) {
	m, f := setup(t, "secret://ic")
	for _, c := range []struct{ action, in string }{
		{"conversation", `{"conversation":"../me"}`},
		{"conversation", `{"conversation":"1001/parts"}`},
		{"conversation", `{}`},
		{"conversations", `{"state":"pending"}`},
		{"conversations", `{"limit":51}`},
		{"contacts", `{"query":""}`},
		{"contacts", `{"query":"a\nb"}`},
		{"add_note", `{"conversation":1001,"text":" "}`},
		{"add_note", `{"conversation":1001,"text":"heads up @all"}`},
		{"reply", `{"conversation":1001,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"reply", `{"conversation":1001,"text":"a\u0000b"}`},
		{"snooze", `{"conversation":1001}`},
		{"snooze", `{"conversation":1001,"until":"2020-01-01T00:00:00Z"}`},
		{"snooze", `{"conversation":1001,"until":"tomorrow"}`},
		{"close", `{"conversation":1001,"until":"2030-01-01T00:00:00Z"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"token": "plaintoken"},
		{},
		{"region": "mars", "token": "secret://ic"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "i")
	if h.Status != "down" || h.Message != "Intercom refused the access token" || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "conversation", `{"conversation":1}`, false); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

func TestIntercomRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL
	raw, _ := json.Marshal(map[string]any{"token": "secret://ic"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ic": "ictok"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "i"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log, events and webhooks as they are, so they hold ids and
// states, never the customer, a message or the token.
func TestIntercomPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://ic")
	until := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	inputs := map[string]string{
		"open":   `{"conversation":1001}`,
		"close":  `{"conversation":1001}`,
		"snooze": `{"conversation":1001,"until":"` + until + `"}`,
	}
	private := []string{"Jane Customer", "jane@example.com", "Where is my order", "ictok"}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive || a.Risk == sdk.RiskRead {
			continue
		}
		in, ok := inputs[a.Name]
		if !ok {
			t.Fatalf("no input for %s", a.Name)
		}
		for _, dry := range []bool{true, false} {
			f.state = "closed"
			if a.Name == "close" {
				f.state = "open"
			}
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

func TestIntercomBodyEscaped(t *testing.T) {
	m, f := setup(t, "secret://ic")
	in := `{"conversation":1001,"text":"Hi <a href=\"https://evil.test\">refund</a> & <img src=x>\r\nbye"}`
	if _, err := invoke(m, "reply", in, false); err != nil || len(f.writes) != 1 {
		t.Fatalf("%v %v", err, f.writes)
	}
	var got map[string]string
	json.Unmarshal([]byte(f.writes[0]), &got)
	if got["body"] != "<p>Hi &lt;a href=&#34;https://evil.test&#34;&gt;refund&lt;/a&gt; &amp; &lt;img src=x&gt;<br>bye</p>" {
		t.Fatal(got["body"])
	}
}
