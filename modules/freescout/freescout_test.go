package freescout

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
	mu     sync.Mutex
	seen   []string
	writes []string
	status string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-FreeScout-API-Key") != "fskey" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Invalid API key fskey-wrong"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	enc := json.NewEncoder(w)
	path := strings.TrimPrefix(r.URL.Path, "/help/api")
	conv := func() map[string]any {
		return map[string]any{"id": 42, "number": 1042, "subject": "Order", "status": f.status, "mailboxId": 1, "preview": "Where is my order?", "updatedAt": "2026-11-04T09:00:00Z",
			"customer": map[string]any{"id": 9, "firstName": "Jane", "lastName": "Customer", "email": "jane@example.com"},
			"assignee": map[string]any{"id": 2, "firstName": "Sam", "lastName": "Agent"},
			"_embedded": map[string]any{"threads": []any{
				map[string]any{"id": 1, "type": "customer", "body": "<div>Where is my order?</div>", "createdAt": "2026-11-04T08:00:00Z", "createdBy": map[string]any{"firstName": "Jane", "lastName": "Customer"}},
				map[string]any{"id": 2, "type": "note", "body": "VIP", "createdAt": "2026-11-04T08:30:00Z", "createdBy": map[string]any{"firstName": "Sam", "lastName": "Agent"}},
			}}}
	}
	switch r.Method + " " + path {
	case "GET /users/2":
		enc.Encode(map[string]any{"id": 2, "firstName": "Sam", "lastName": "Agent", "email": "sam@acme.test"})
	case "GET /mailboxes":
		enc.Encode(map[string]any{"_embedded": map[string]any{"mailboxes": []any{map[string]any{"id": 1, "name": "Support", "email": "support@acme.test"}}}})
	case "GET /conversations":
		enc.Encode(map[string]any{"_embedded": map[string]any{"conversations": []any{conv()}}})
	case "GET /conversations/42":
		enc.Encode(conv())
	case "POST /conversations/42/threads":
		f.writes = append(f.writes, string(body))
		w.WriteHeader(201)
	case "PUT /conversations/42":
		f.writes = append(f.writes, string(body))
		var in map[string]any
		json.Unmarshal(body, &in)
		f.status, _ = in["status"].(string)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "active"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"url": srv.URL + "/help/", "apiKey": key, "userId": "2"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fs": "fskey", "secret://bad": "nope"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFreeScoutReads(t *testing.T) {
	m, f := setup(t, "secret://fs")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "Acting as Sam Agent" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"mailboxes", `{}`, `"name":"Support"`},
		{"conversations", `{}`, `"preview":"Where is my order?"`},
		{"conversations", `{"status":"all","mailbox":1,"limit":5}`, `"customer":{"email":"jane@example.com","id":9,"name":"Jane Customer"}`},
		{"conversation", `{"conversation":42}`, `"kind":"internal note"`},
		{"conversation", `{"conversation":"42"}`, `"text":"Where is my order?"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	all := strings.Join(f.seen, " ")
	if !strings.Contains(all, "mailboxId=1") || !strings.Contains(f.seen[2], "status=active") || strings.Contains(f.seen[3], "status=") {
		t.Fatal(f.seen)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if spec["mailboxes"].Sensitive || !spec["conversations"].Sensitive || !spec["conversation"].Sensitive || !spec["reply"].Sensitive || !spec["add_note"].Sensitive ||
		spec["reply"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || spec["close"].Risk != sdk.RiskDestructive || spec["set_status"].Risk != sdk.RiskWrite ||
		!spec["close"].Reversible || !spec["set_status"].Reversible {
		t.Fatalf("%+v", spec)
	}
}

func TestFreeScoutWrites(t *testing.T) {
	m, f := setup(t, "secret://fs")
	r, err := invoke(m, "reply", `{"conversation":42,"text":"Shipped today"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Jane Customer <jane@example.com>") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reply", `{"conversation":42,"text":"Shipped today"}`, false); err != nil || f.writes[0] != `{"text":"Shipped today","type":"message","user":2}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	if r, err := invoke(m, "add_note", `{"conversation":42,"text":"VIP"}`, false); err != nil || r.Undo != nil || f.writes[1] != `{"text":"VIP","type":"note","user":2}` {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}
	if r, err := invoke(m, "set_status", `{"conversation":42,"status":"active"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.writes) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "close", `{"conversation":42}`, true); err != nil || r.Plan == nil || f.status != "active" || !strings.Contains(r.Plan.Summary, "may email the customer") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "close", `{"conversation":42}`, false)
	if err != nil || f.status != "closed" || f.writes[2] != `{"byUser":2,"status":"closed"}` || r.Undo == nil || r.Undo.Action != "set_status" {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "active" {
		t.Fatal(err, f.status)
	}
	f.status = "closed"
	r, err = invoke(m, "set_status", `{"conversation":42,"status":"pending"}`, false)
	if err != nil || f.status != "pending" || r.Undo == nil || r.Undo.Action != "close" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFreeScoutValidation(t *testing.T) {
	m, f := setup(t, "secret://fs")
	for _, c := range []struct{ action, in string }{
		{"conversation", `{"conversation":"../users/2"}`},
		{"conversation", `{"conversation":"42/threads"}`},
		{"conversation", `{}`},
		{"conversations", `{"status":"spam"}`},
		{"conversations", `{"mailbox":"1&x=1"}`},
		{"conversations", `{"limit":51}`},
		{"add_note", `{"conversation":42,"text":" "}`},
		{"add_note", `{"conversation":42,"text":"cc @all"}`},
		{"reply", `{"conversation":42,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"set_status", `{"conversation":42,"status":"closed"}`},
		{"set_status", `{"conversation":42,"status":"spam"}`},
		{"close", `{"conversation":42,"status":"active"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"url": "https://support.example.com", "apiKey": "fskey", "userId": 2},
		{"url": "https://support.example.com", "apiKey": "secret://fs"},
		{"url": "https://support.example.com", "apiKey": "secret://fs", "userId": "two"},
		{"apiKey": "secret://fs", "userId": 2},
		{"url": "ftp://support.example.com", "apiKey": "secret://fs", "userId": 2},
		{"url": "https://u:p@support.example.com", "apiKey": "secret://fs", "userId": 2},
		{"url": "https://support.example.com/?x=1", "apiKey": "secret://fs", "userId": 2},
		{"url": "https://support.example.com/a/../b", "apiKey": "secret://fs", "userId": 2},
		{"url": "https://support.example.com", "apiKey": "secret://fs", "userId": 2, "fingerprint": "not-hex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "f")
	if h.Status != "down" || h.Message != "FreeScout refused the API key" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "conversation", `{"conversation":42}`, false); err == nil || strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), "fskey") {
		t.Fatal(err)
	}
}

func TestFreeScoutRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(map[string]any{"url": srv.URL, "apiKey": "secret://fs", "userId": 2})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fs": "fskey"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log as they are, so they hold ids and statuses only.
func TestFreeScoutPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://fs")
	inputs := map[string]string{
		"set_status": `{"conversation":42,"status":"pending"}`,
		"close":      `{"conversation":42}`,
	}
	private := []string{"Jane", "jane@example.com", "Where is my order", "Order", "fskey"}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive || a.Risk == sdk.RiskRead {
			continue
		}
		in, ok := inputs[a.Name]
		if !ok {
			t.Fatalf("no input for %s", a.Name)
		}
		for _, dry := range []bool{true, false} {
			f.status = "active"
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
