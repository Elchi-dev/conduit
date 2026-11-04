package helpscout

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
	tokens int
	status string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	enc := json.NewEncoder(w)
	if r.URL.Path == "/v2/oauth2/token" {
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "app-1" || r.PostForm.Get("client_secret") != "hssecret" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_client","error_description":"bad client hssecret"}`)
			return
		}
		f.tokens++
		enc.Encode(map[string]any{"token_type": "bearer", "access_token": "hsaccess", "expires_in": 7200})
		return
	}
	if r.Header.Get("Authorization") != "Bearer hsaccess" {
		w.WriteHeader(401)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	conv := func() map[string]any {
		return map[string]any{"id": 501, "number": 77, "subject": "Order", "status": f.status, "mailboxId": 3, "preview": "Where is my order?", "userUpdatedAt": "2026-11-04T09:00:00Z",
			"primaryCustomer": map[string]any{"id": 9, "first": "Jane", "last": "Customer", "email": "jane@example.com"},
			"assignee":        map[string]any{"id": 4, "first": "Sam", "last": "Agent"},
			"tags":            []any{map[string]any{"tag": "billing"}},
			"_embedded": map[string]any{"threads": []any{
				map[string]any{"id": 1, "type": "customer", "body": "<p>Where is my order?</p>", "createdAt": "2026-11-04T08:00:00Z", "createdBy": map[string]any{"first": "Jane", "last": "Customer"}},
				map[string]any{"id": 2, "type": "note", "body": "VIP", "createdAt": "2026-11-04T08:30:00Z", "createdBy": map[string]any{"first": "Sam", "last": "Agent"}},
			}}}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v2/users/me":
		enc.Encode(map[string]any{"id": 4, "firstName": "Sam", "lastName": "Agent"})
	case "GET /v2/mailboxes":
		enc.Encode(map[string]any{"_embedded": map[string]any{"mailboxes": []any{map[string]any{"id": 3, "name": "Support", "email": "support@acme.test"}}}})
	case "GET /v2/conversations":
		enc.Encode(map[string]any{"_embedded": map[string]any{"conversations": []any{conv()}}, "page": map[string]any{"totalPages": 1}})
	case "GET /v2/conversations/501":
		enc.Encode(conv())
	case "POST /v2/conversations/501/reply", "POST /v2/conversations/501/notes":
		f.writes = append(f.writes, r.URL.Path+" "+string(body))
		w.WriteHeader(201)
	case "PATCH /v2/conversations/501":
		f.writes = append(f.writes, string(body))
		var in map[string]string
		json.Unmarshal(body, &in)
		f.status = in["value"]
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Resource not found"}`)
	}
}

func setup(t *testing.T, secret string) (*Module, *fake) {
	t.Helper()
	f := &fake{status: "active"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL+"/v2"
	raw, _ := json.Marshal(map[string]any{"appId": "secret://id", "appSecret": secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://id": "app-1", "secret://hs": "hssecret", "secret://bad": "nope"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHelpScoutReads(t *testing.T) {
	m, f := setup(t, "secret://hs")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "Signed in as Sam Agent" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"mailboxes", `{}`, `"name":"Support"`},
		{"conversations", `{}`, `"preview":"Where is my order?"`},
		{"conversations", `{"status":"all","mailbox":3,"limit":5}`, `"customer":{"email":"jane@example.com","id":9,"name":"Jane Customer"}`},
		{"conversation", `{"conversation":501}`, `"kind":"internal note"`},
		{"conversation", `{"conversation":"501"}`, `"text":"Where is my order?"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if f.tokens != 1 || !strings.Contains(strings.Join(f.seen, " "), "mailbox=3") {
		t.Fatal(f.tokens, f.seen)
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

func TestHelpScoutWrites(t *testing.T) {
	m, f := setup(t, "secret://hs")
	r, err := invoke(m, "reply", `{"conversation":501,"text":"Shipped today"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Jane Customer <jane@example.com>") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "reply", `{"conversation":501,"text":"Shipped today"}`, false); err != nil || f.writes[0] != `/v2/conversations/501/reply {"customer":{"id":9},"text":"Shipped today"}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	if r, err := invoke(m, "add_note", `{"conversation":501,"text":"VIP"}`, false); err != nil || r.Undo != nil || f.writes[1] != `/v2/conversations/501/notes {"text":"VIP"}` {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}
	if r, err := invoke(m, "set_status", `{"conversation":501,"status":"active"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.writes) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "close", `{"conversation":501}`, true); err != nil || r.Plan == nil || f.status != "active" || !strings.Contains(r.Plan.Summary, "may email the customer") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "close", `{"conversation":501}`, false)
	if err != nil || f.status != "closed" || f.writes[2] != `{"op":"replace","path":"/status","value":"closed"}` || r.Undo == nil || r.Undo.Action != "set_status" {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "active" {
		t.Fatal(err, f.status)
	}
	f.status = "closed"
	r, err = invoke(m, "set_status", `{"conversation":501,"status":"pending"}`, false)
	if err != nil || f.status != "pending" || r.Undo == nil || r.Undo.Action != "close" {
		t.Fatalf("%+v %v", r, err)
	}
	if f.tokens != 1 {
		t.Fatal("token not cached", f.tokens)
	}
}

func TestHelpScoutValidation(t *testing.T) {
	m, f := setup(t, "secret://hs")
	for _, c := range []struct{ action, in string }{
		{"conversation", `{"conversation":"../users/me"}`},
		{"conversation", `{"conversation":"501/notes"}`},
		{"conversation", `{}`},
		{"conversations", `{"status":"spam"}`},
		{"conversations", `{"mailbox":"3&x=1"}`},
		{"conversations", `{"limit":51}`},
		{"add_note", `{"conversation":501,"text":" "}`},
		{"add_note", `{"conversation":501,"text":"@here please look"}`},
		{"reply", `{"conversation":501,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"set_status", `{"conversation":501,"status":"closed"}`},
		{"set_status", `{"conversation":501,"status":"spam"}`},
		{"close", `{"conversation":501,"status":"active"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.tokens != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"appId": "app-1", "appSecret": "secret://hs"},
		{"appId": "secret://id", "appSecret": "hssecret"},
		{"appId": "secret://id"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "h")
	if h.Status != "down" || h.Message != "Help Scout refused the app id or secret" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "conversation", `{"conversation":501}`, false); err == nil || strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), "hssecret") {
		t.Fatal(err)
	}
}

func TestHelpScoutRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL+"/v2"
	raw, _ := json.Marshal(map[string]any{"appId": "secret://id", "appSecret": "secret://hs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://id": "app-1", "secret://hs": "hssecret"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log as they are, so they hold ids and statuses only.
func TestHelpScoutPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://hs")
	inputs := map[string]string{
		"set_status": `{"conversation":501,"status":"pending"}`,
		"close":      `{"conversation":501}`,
	}
	private := []string{"Jane", "jane@example.com", "Where is my order", "Order", "hssecret", "hsaccess"}
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

func TestHelpScoutBodyEscaped(t *testing.T) {
	m, f := setup(t, "secret://hs")
	in := `{"conversation":501,"text":"Hi <a href=\"https://evil.test\">refund</a> & <span style=\"display:none\">x</span>\nbye"}`
	for _, action := range []string{"reply", "add_note"} {
		if _, err := invoke(m, action, in, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range f.writes {
		var got map[string]any
		json.Unmarshal([]byte(w[strings.Index(w, " ")+1:]), &got)
		if got["text"] != "Hi &lt;a href=&#34;https://evil.test&#34;&gt;refund&lt;/a&gt; &amp; &lt;span style=&#34;display:none&#34;&gt;x&lt;/span&gt;<br>bye" {
			t.Fatal(w)
		}
	}
	if len(f.writes) != 2 {
		t.Fatal(f.writes)
	}
}
