package crisp

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

const (
	website = "8c842203-7ed8-4e29-a608-7cf78a7d2fcc"
	session = "session_700c65e1-85e2-465a-b9ac-ecb5ec2c9881"
)

type fake struct {
	mu     sync.Mutex
	seen   []string
	writes []string
	state  string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("ident-1:crkey")) || r.Header.Get("X-Crisp-Tier") != "plugin" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":true,"reason":"invalid_session","data":{}}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	ok := func(data any) {
		json.NewEncoder(w).Encode(map[string]any{"error": false, "reason": "resolved", "data": data})
	}
	conv := func() map[string]any {
		return map[string]any{"session_id": session, "state": f.state, "last_message": "Where is my order?", "updated_at": 1762246800000,
			"unread": map[string]any{"operator": 2}, "meta": map[string]any{"nickname": "Jane Customer", "email": "jane@example.com"}}
	}
	base := "/website/" + website
	switch r.Method + " " + r.URL.Path {
	case "GET " + base:
		ok(map[string]any{"website_id": website, "name": "Acme", "domain": "acme.test"})
	case "GET " + base + "/conversations/1":
		ok([]any{conv()})
	case "GET " + base + "/conversation/" + session:
		ok(conv())
	case "GET " + base + "/conversation/" + session + "/messages":
		ok([]any{
			map[string]any{"type": "text", "from": "user", "origin": "chat", "content": "Where is my order?", "timestamp": 1762246800000, "fingerprint": 11, "user": map[string]any{"nickname": "Jane Customer"}},
			map[string]any{"type": "note", "from": "operator", "origin": "chat", "content": "VIP", "timestamp": 1762246900000, "fingerprint": 12, "user": map[string]any{"nickname": "Sam"}},
			map[string]any{"type": "file", "from": "user", "origin": "chat", "content": map[string]any{"name": "a.png"}, "timestamp": 1762247000000, "fingerprint": 13},
		})
	case "POST " + base + "/conversation/" + session + "/message":
		f.writes = append(f.writes, string(body))
		ok(map[string]any{"fingerprint": 99})
	case "PATCH " + base + "/conversation/" + session + "/state":
		f.writes = append(f.writes, string(body))
		var in map[string]string
		json.Unmarshal(body, &in)
		f.state = in["state"]
		ok(map[string]any{})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":true,"reason":"not_found","data":{}}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "unresolved"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL
	raw, _ := json.Marshal(map[string]any{"websiteId": website, "identifier": "secret://id", "key": key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://id": "ident-1", "secret://key": "crkey", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCrispReads(t *testing.T) {
	m, f := setup(t, "secret://key")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "Website Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"conversations", `{}`, `"lastMessage":"Where is my order?"`},
		{"conversations", `{"state":"all","limit":5}`, `"visitor":{"email":"jane@example.com","name":"Jane Customer"}`},
		{"messages", `{"conversation":"` + session + `"}`, `"kind":"private note"`},
		{"messages", `{"conversation":"` + session + `"}`, `"kind":"visitor"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.Contains(f.seen[1], "filter_not_resolved=1") || strings.Contains(f.seen[2], "filter_") {
		t.Fatal(f.seen)
	}
	spec := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		spec[a.Name] = a
	}
	if !spec["conversations"].Sensitive || !spec["messages"].Sensitive || !spec["send_message"].Sensitive || !spec["add_note"].Sensitive ||
		spec["send_message"].Risk != sdk.RiskDestructive || spec["add_note"].Risk != sdk.RiskWrite || spec["resolve"].Risk != sdk.RiskDestructive ||
		spec["set_state"].Risk != sdk.RiskWrite || !spec["resolve"].Reversible || !spec["set_state"].Reversible {
		t.Fatalf("%+v", spec)
	}
}

func TestCrispWrites(t *testing.T) {
	m, f := setup(t, "secret://key")
	cv := `"conversation":"` + session + `"`
	r, err := invoke(m, "send_message", `{`+cv+`,"text":"Shipped today"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "to Jane Customer <jane@example.com>") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "send_message", `{`+cv+`,"text":"Shipped today"}`, false); err != nil || f.writes[0] != `{"content":"Shipped today","from":"operator","origin":"chat","type":"text"}` {
		t.Fatalf("%v %v", err, f.writes)
	}
	if r, err := invoke(m, "add_note", `{`+cv+`,"text":"VIP"}`, false); err != nil || r.Undo != nil || f.writes[1] != `{"content":"VIP","from":"operator","origin":"chat","type":"note"}` {
		t.Fatalf("%+v %v %v", r, err, f.writes)
	}

	if r, err := invoke(m, "set_state", `{`+cv+`,"state":"unresolved"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.writes) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "resolve", `{`+cv+`}`, true); err != nil || r.Plan == nil || f.state != "unresolved" || !strings.Contains(r.Plan.Summary, "rate it") {
		t.Fatal(err, r.Plan)
	}
	r, err = invoke(m, "resolve", `{`+cv+`}`, false)
	if err != nil || f.state != "resolved" || r.Undo == nil || r.Undo.Action != "set_state" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "unresolved" {
		t.Fatal(err, f.state)
	}
	f.state = "resolved"
	r, err = invoke(m, "set_state", `{`+cv+`,"state":"pending"}`, false)
	if err != nil || f.state != "pending" || r.Undo == nil || r.Undo.Action != "resolve" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestCrispValidation(t *testing.T) {
	m, f := setup(t, "secret://key")
	cv := `"conversation":"` + session + `"`
	for _, c := range []struct{ action, in string }{
		{"messages", `{"conversation":"../../website"}`},
		{"messages", `{"conversation":"session_x/messages"}`},
		{"messages", `{}`},
		{"conversations", `{"state":"pending"}`},
		{"conversations", `{"limit":51}`},
		{"add_note", `{` + cv + `,"text":" "}`},
		{"add_note", `{` + cv + `,"text":"@everyone look"}`},
		{"send_message", `{` + cv + `,"text":"` + strings.Repeat("x", maxText+1) + `"}`},
		{"set_state", `{` + cv + `,"state":"resolved"}`},
		{"set_state", `{` + cv + `,"state":"closed"}`},
		{"resolve", `{` + cv + `,"state":"pending"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []map[string]any{
		{"websiteId": website, "identifier": "ident-1", "key": "secret://key"},
		{"websiteId": website, "identifier": "secret://id", "key": "crkey"},
		{"websiteId": "acme", "identifier": "secret://id", "key": "secret://key"},
		{"identifier": "secret://id", "key": "secret://key"},
		{"websiteId": website + "/../x", "identifier": "secret://id", "key": "secret://key"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "c")
	if h.Status != "down" || h.Message != "Crisp refused the plugin token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "messages", `{`+cv+`}`, false); err == nil || strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), "ident-1") {
		t.Fatal(err)
	}
}

func TestCrispRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP, m.Base = srv.Client(), srv.URL
	raw, _ := json.Marshal(map[string]any{"websiteId": website, "identifier": "secret://id", "key": "secret://key"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://id": "ident-1", "secret://key": "crkey"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// The plans, results and undo tokens of actions that aren't sensitive go in
// the audit log as they are, so they hold ids and states only.
func TestCrispPlansHoldNoCustomerData(t *testing.T) {
	m, f := setup(t, "secret://key")
	cv := `"conversation":"` + session + `"`
	inputs := map[string]string{
		"set_state": `{` + cv + `,"state":"pending"}`,
		"resolve":   `{` + cv + `}`,
	}
	private := []string{"Jane Customer", "jane@example.com", "Where is my order", "crkey", "ident-1"}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive || a.Risk == sdk.RiskRead {
			continue
		}
		in, ok := inputs[a.Name]
		if !ok {
			t.Fatalf("no input for %s", a.Name)
		}
		for _, dry := range []bool{true, false} {
			f.state = "unresolved"
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

func TestCrispReasonRedacted(t *testing.T) {
	// A long credential-like reason is redacted before it's cut, so no part
	// of it survives the clip.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"error":true,"reason":"bad key abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ","data":{}}`)
	}))
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.HTTP = srv.URL, srv.Client()
	raw, _ := json.Marshal(map[string]any{"websiteId": website, "identifier": "secret://id", "key": "secret://key"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://id": "ident-1", "secret://key": "crkey"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "c")
	if h.Status != "down" || strings.Contains(h.Message, "abcdefghij") || !strings.Contains(h.Message, "[redacted]") {
		t.Fatal(h)
	}
}
