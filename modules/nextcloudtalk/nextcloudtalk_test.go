package nextcloudtalk

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

type fakeTalk struct {
	mu   sync.Mutex
	seen []string
	sent map[string]string // "token/id" -> text
}

func ocs(w http.ResponseWriter, status int, data string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"ocs":{"meta":{"status":"ok","statuscode":%d},"data":%s}}`, status, data)
}

func (f *fakeTalk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, pw, ok := r.BasicAuth(); !ok || u != "kim" || pw != "app-pw" || r.Header.Get("OCS-APIRequest") != "true" {
		w.WriteHeader(401)
		io.WriteString(w, `{"ocs":{"meta":{"status":"failure","statuscode":997,"message":"Current user is not logged in"},"data":[]}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery+" "+string(body))
	q := r.URL.Query()
	if q.Get("format") != "json" {
		w.WriteHeader(400)
		return
	}
	const base = "/ocs/v2.php/apps/spreed/api/"
	switch r.Method + " " + r.URL.Path {
	case "GET /ocs/v2.php/cloud/user":
		ocs(w, 200, `{"id":"kim","displayname":"Kim"}`)
	case "GET " + base + "v4/room":
		ocs(w, 200, `[{"token":"team1234","type":2,"displayName":"Team","unreadMessages":4,"unreadMention":true,"lastActivity":1793786400},`+
			`{"token":"dmsam567","type":1,"displayName":"Sam","unreadMessages":0,"lastActivity":1793780000},`+
			`{"token":"news0000","type":3,"displayName":"News","readOnly":1,"lastActivity":1793700000}]`)
	case "GET " + base + "v4/room/team1234":
		ocs(w, 200, `{"token":"team1234","type":2,"displayName":"Team"}`)
	case "GET " + base + "v4/room/news0000":
		ocs(w, 200, `{"token":"news0000","type":3,"displayName":"News","readOnly":1}`)
	case "GET " + base + "v1/chat/team1234":
		if q.Get("setReadMarker") != "0" || q.Get("lookIntoFuture") != "0" || q.Get("limit") != "30" {
			w.WriteHeader(400)
			return
		}
		ocs(w, 200, `[{"id":3,"actorDisplayName":"Sam","timestamp":1793786460,"message":"thanks {mention-user1}","messageType":"comment","messageParameters":{"mention-user1":{"type":"user","id":"kim","name":"Kim"}},"parent":{"id":2}},`+
			`{"id":2,"actorDisplayName":"Kim","timestamp":1793786400,"message":"deploy done","messageType":"comment","messageParameters":[]},`+
			`{"id":1,"actorDisplayName":"Kim","timestamp":1793786000,"message":"{actor} created the conversation","systemMessage":"conversation_created","messageType":"system","messageParameters":{"actor":{"type":"user","id":"kim","name":"Kim"}}}]`)
	case "POST " + base + "v1/chat/team1234":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.sent["team1234/77"] = in["message"].(string)
		ocs(w, 201, `{"id":77,"timestamp":1793786500,"message":"x"}`)
	case "DELETE " + base + "v1/chat/team1234/77":
		if _, ok := f.sent["team1234/77"]; !ok {
			ocs(w, 404, `[]`)
			return
		}
		delete(f.sent, "team1234/77")
		ocs(w, 200, `{"id":78,"messageType":"system"}`)
	default:
		ocs(w, 404, `[]`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeTalk) {
	t.Helper()
	f := &fakeTalk{sent: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	if cfg.User == "" {
		cfg.User = "kim"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nc": "app-pw", "secret://bad": "nope"}), "nc", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "nc", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTalk(t *testing.T) {
	m, f := setup(t, Config{AppPassword: "secret://nc", AllowedConversations: []string{"team1234", "news0000"}})
	if h := m.Health(context.Background(), "nc"); h.Status != "ok" || h.Message != "signed in as kim, 2 allowed conversations" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "conversations", `{}`, false)
	if err != nil || !strings.HasPrefix(string(r.Output), `[{"allowed":true,"conversation":"team1234","lastActivity":"2026-11-04T10:00:00Z","mentioned":true,"name":"Team","type":"group","unread":4}`) ||
		!strings.Contains(string(r.Output), `"readOnly":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "unread", `{}`, false)
	if err != nil || string(r.Output) != `[{"allowed":true,"conversation":"team1234","mentioned":true,"name":"Team","type":"group","unread":4}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "messages", `{"conversation":"team1234"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"from":"Sam","id":3,"replyTo":2,"text":"thanks Kim","when":"2026-11-04T10:01:00Z"}`) ||
		!strings.Contains(string(r.Output), `"system":"Kim created the conversation"`) || strings.Index(string(r.Output), `"id":1`) > strings.Index(string(r.Output), `"id":3`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "send_message", `{"conversation":"team1234","text":"hello"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Send a message to "Team" (team1234), a group conversation` || len(f.sent) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "send_message", `{"conversation":"news0000","text":"hello"}`, false); err == nil || len(f.sent) != 0 {
		t.Fatal("sent to a read-only conversation", err)
	}
	r, err = invoke(m, "send_message", `{"conversation":"team1234","text":"hello"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_message" || string(r.Undo.Input) != `{"conversation":"team1234","id":77}` || f.sent["team1234/77"] != "hello" {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, "delete_message", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || p.Plan.Summary != `Delete message 77 in "Team" (team1234)` || len(f.sent) != 1 {
		t.Fatalf("dry %+v %v", p.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.sent) != 0 {
		t.Fatal("not deleted", err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err == nil || !strings.Contains(err.Error(), "no message 77") {
		t.Fatal(err)
	}
}

func TestTalkValidation(t *testing.T) {
	m, f := setup(t, Config{AppPassword: "secret://nc", AllowedConversations: []string{"team1234"}})
	for _, in := range []string{
		`{"conversation":"dmsam567","text":"x"}`, // not allowed
		`{"conversation":"../../cloud","text":"x"}`,
		`{"conversation":"TEAM1234","text":"x"}`,
		`{"conversation":"team1234","text":"  "}`,
		`{"conversation":"team1234","text":"x","replyTo":-1}`,
		`{"conversation":"team1234","text":"` + strings.Repeat("a", maxText+1) + `"}`,
	} {
		if _, err := invoke(m, "send_message", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "messages", `{"conversation":"dmsam567"}`, false); err == nil {
		t.Fatal("read a conversation outside the allow-list")
	}
	for _, in := range []string{`{"conversation":"team1234","id":0}`, `{"conversation":"dmsam567","id":5}`, `{"conversation":"team1234","id":"1/../x"}`} {
		if _, err := invoke(m, "delete_message", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://cloud", User: "kim", AppPassword: "plain"},
		{URL: "cloud.example.com", User: "kim", AppPassword: "secret://nc"},
		{URL: "https://cloud", User: "a/b", AppPassword: "secret://nc"},
		{URL: "https://cloud", User: "kim", AppPassword: "secret://nc", AllowedConversations: []string{"../x"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	none, _ := setup(t, Config{AppPassword: "secret://nc"})
	if h := none.Health(context.Background(), "nc"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{AppPassword: "secret://bad"})
	if h := bad.Health(context.Background(), "nc"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestTalkRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, User: "kim", AppPassword: "secret://nc"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nc": "app-pw"}), "nc", raw)
	if h := m.Health(context.Background(), "nc"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}

// /commands and wildcard mentions are refused before anything is sent; the
// preview names who is mentioned.
func TestTalkCommandsAndMentions(t *testing.T) {
	m, f := setup(t, Config{AppPassword: "secret://nc", AllowedConversations: []string{"team1234"}})
	for _, text := range []string{"/help", "  /wiki secrets", "@all meeting", `@"all" now`, "hey @here"} {
		in, _ := json.Marshal(map[string]string{"conversation": "team1234", "text": text})
		if _, err := invoke(m, "send_message", string(in), false); err == nil {
			t.Fatalf("sent %q", text)
		}
	}
	if len(f.sent) != 0 {
		t.Fatal(f.sent)
	}
	r, err := invoke(m, "send_message", `{"conversation":"team1234","text":"ping @sam and @\"Kim Lee\", see a/b"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Send a message to "Team" (team1234), a group conversation; mentions @"Kim Lee", @sam (they're notified)` {
		t.Fatal(r.Plan, err)
	}
}
