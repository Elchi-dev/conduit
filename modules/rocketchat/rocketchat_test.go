package rocketchat

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
	uid    = "UUUUUUUUUUUUUUUUU"
	genID  = "GENERALroomid1234"
	opsID  = "OPSprivateroom123"
	msgID  = "MSGid000000000001"
	otherR = "OTHERroomid123456"
)

type fakeRC struct {
	mu    sync.Mutex
	seen  []string
	posts map[string]string
}

func (f *fakeRC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-User-Id") != uid || r.Header.Get("X-Auth-Token") != "rctok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":"error","message":"You must be logged in to do this."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery+" "+string(body))
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/me":
		io.WriteString(w, `{"_id":"`+uid+`","username":"conduit-bot","success":true}`)
	case "GET /api/v1/subscriptions.get":
		io.WriteString(w, `{"update":[{"rid":"`+genID+`","name":"general","t":"c","unread":3,"userMentions":1,"open":true},`+
			`{"rid":"`+opsID+`","name":"ops","fname":"Ops team","t":"p","unread":0,"open":true},`+
			`{"rid":"`+uid+`x","name":"kim","t":"d","unread":2,"open":true}],"remove":[],"success":true}`)
	case "GET /api/v1/rooms.info":
		switch q.Get("roomName") {
		case "general":
			io.WriteString(w, `{"room":{"_id":"`+genID+`","name":"general","t":"c"},"success":true}`)
		case "ops":
			io.WriteString(w, `{"room":{"_id":"`+opsID+`","name":"ops","t":"p"},"success":true}`)
		default:
			w.WriteHeader(400)
			io.WriteString(w, `{"success":false,"error":"error-room-not-found"}`)
		}
	case "GET /api/v1/channels.history":
		if q.Get("roomId") != genID || q.Get("count") != "30" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"messages":[{"_id":"m2","rid":"`+genID+`","msg":"thanks","ts":"2026-11-04T10:01:00.000Z","u":{"username":"kim"},"tmid":"m1"},`+
			`{"_id":"m1","rid":"`+genID+`","msg":"deploy done","ts":"2026-11-04T10:00:00.000Z","u":{"username":"sam"}},`+
			`{"_id":"m0","rid":"`+genID+`","msg":"sam","t":"uj","ts":{"$date":1793786400000},"u":{"username":"sam"}}],"success":true}`)
	case "GET /api/v1/groups.history":
		io.WriteString(w, `{"messages":[],"success":true}`)
	case "POST /api/v1/chat.sendMessage":
		var in struct {
			Message map[string]string `json:"message"`
		}
		_ = json.Unmarshal(body, &in)
		f.posts[msgID] = in.Message["rid"] + "|" + in.Message["msg"]
		fmt.Fprintf(w, `{"message":{"_id":%q,"rid":%q,"msg":%q,"ts":"2026-11-04T10:02:00.000Z","u":{"username":"conduit-bot"}},"success":true}`, msgID, in.Message["rid"], in.Message["msg"])
	case "GET /api/v1/chat.getMessage":
		v, ok := f.posts[q.Get("msgId")]
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"success":false,"error":"error-not-allowed"}`)
			return
		}
		rid, _, _ := strings.Cut(v, "|")
		fmt.Fprintf(w, `{"message":{"_id":%q,"rid":%q,"msg":"secret text","ts":"2026-11-04T10:02:00.000Z","u":{"username":"conduit-bot"}},"success":true}`, q.Get("msgId"), rid)
	case "POST /api/v1/chat.delete":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		delete(f.posts, in["msgId"])
		io.WriteString(w, `{"success":true}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"success":false,"error":"not found"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeRC) {
	t.Helper()
	f := &fakeRC{posts: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	if cfg.UserID == "" {
		cfg.UserID = uid
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rc": "rctok", "secret://bad": "nope"}), "rc", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "rc", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRocketChat(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://rc", AllowedRooms: []string{"#general", "ops"}})
	if h := m.Health(context.Background(), "rc"); h.Status != "ok" || h.Message != "signed in as conduit-bot, 2 allowed rooms" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "channels", `{}`, false)
	if err != nil || string(r.Output) != `[{"allowed":true,"name":"general","type":"channel"},{"allowed":true,"displayName":"Ops team","name":"ops","type":"private"}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "unread", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"total":5`) || !strings.Contains(string(r.Output), `{"allowed":true,"mentions":1,"room":"general","type":"channel","unread":3}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "messages", `{"room":"general"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"from":"sam","id":"m1","text":"deploy done","when":"2026-11-04T10:00:00Z"}`) ||
		!strings.Contains(string(r.Output), `"system":"uj"`) || !strings.Contains(string(r.Output), `"thread":"m1"`) ||
		strings.Index(string(r.Output), `"m1"`) > strings.Index(string(r.Output), `"m2"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "messages", `{"room":"ops"}`, false); err != nil {
		t.Fatal(err)
	}

	r, err = invoke(m, "send_message", `{"room":"general","text":"hello"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Send a message to #general" || len(f.posts) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "send_message", `{"room":"general","text":"hello"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_message" || f.posts[msgID] != genID+"|hello" {
		t.Fatalf("%+v %v", r, err)
	}
	if string(r.Undo.Input) != `{"id":"`+msgID+`","room":"general"}` {
		t.Fatalf("undo %s", r.Undo.Input)
	}
	p, err := invoke(m, "delete_message", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Delete conduit-bot's message from 2026-11-04T10:02:00Z in #general" || len(f.posts) != 1 {
		t.Fatalf("dry %+v %v", p.Plan, err)
	}
	if strings.Contains(string(p.Plan.Changes[0].Before), "secret text") {
		t.Fatal("the delete preview quotes the message")
	}
	if _, err := invoke(m, "delete_message", `{"room":"ops","id":"`+msgID+`"}`, false); err == nil || len(f.posts) != 1 {
		t.Fatal("deleted a message through another room", err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.posts) != 0 {
		t.Fatal("not deleted", err)
	}
}

func TestRocketChatValidation(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://rc", AllowedRooms: []string{"general"}})
	for _, in := range []string{
		`{"room":"random","text":"x"}`, // not allowed
		`{"room":"../me","text":"x"}`,
		`{"room":"general?x=1","text":"x"}`,
		`{"room":"general","text":"  "}`,
		`{"room":"general","text":"x","thread":"../x"}`,
		`{"room":"general","text":"` + strings.Repeat("a", maxText+1) + `"}`,
	} {
		if _, err := invoke(m, "send_message", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "messages", `{"room":"random"}`, false); err == nil {
		t.Fatal("read a room outside the allow-list")
	}
	if _, err := invoke(m, "delete_message", `{"room":"general","id":"../users"}`, false); err == nil {
		t.Fatal("accepted message id")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://chat", UserID: uid, Token: "plain"},
		{URL: "chat.example.com", UserID: uid, Token: "secret://rc"},
		{URL: "https://chat", UserID: "a/b", Token: "secret://rc"},
		{URL: "https://chat", UserID: uid, Token: "secret://rc", AllowedRooms: []string{"a/b"}},
		{URL: "https://chat", UserID: uid, Token: "secret://rc", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	none, _ := setup(t, Config{Token: "secret://rc"})
	if h := none.Health(context.Background(), "rc"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{Token: "secret://bad"})
	if h := bad.Health(context.Background(), "rc"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestRocketChatRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Auth-Token") }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, UserID: uid, Token: "secret://rc"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rc": "rctok"}), "rc", raw)
	if h := m.Health(context.Background(), "rc"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
