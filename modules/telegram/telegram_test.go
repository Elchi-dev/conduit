package telegram

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

const (
	goodToken = "123456:ABCdefGHIjklMNOpqrSTUvwxYZ012345"
	badToken  = "123456:XXXdefGHIjklMNOpqrSTUvwxYZ012345"
	allowed   = int64(-1001234567890)
	other     = int64(555)
)

type fakeBot struct {
	mu      sync.Mutex
	seen    []string
	offsets []any
	updates []map[string]any
	nextID  int64
	pinned  map[int64]bool
	texts   map[int64]string
	deleted []int64
}

func msg(chat, id int64, text string) map[string]any {
	return map[string]any{"message_id": id, "date": 1793000000 + id, "chat": map[string]any{"id": chat, "type": "supergroup", "title": "Ops"}, "from": map[string]any{"id": 9, "first_name": "Ana", "username": "ana"}, "text": text}
}

func (f *fakeBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": v}) }
	if !strings.HasPrefix(r.URL.Path, "/bot"+goodToken+"/") {
		w.WriteHeader(401)
		io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, "/bot"+goodToken+"/")
	var p map[string]any
	json.NewDecoder(r.Body).Decode(&p)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, method)
	switch method {
	case "getMe":
		reply(map[string]any{"id": 42, "is_bot": true, "first_name": "Conduit", "username": "conduit_bot", "can_join_groups": true})
	case "getUpdates":
		if p["timeout"] != float64(0) {
			w.WriteHeader(400)
			io.WriteString(w, `{"ok":false,"error_code":400,"description":"long poll"}`)
			return
		}
		f.offsets = append(f.offsets, p["offset"])
		off, _ := p["offset"].(float64)
		out := []any{}
		for _, u := range f.updates {
			if u["update_id"].(int64) >= int64(off) {
				out = append(out, u)
			}
		}
		reply(out)
	case "getChat":
		c := map[string]any{"id": p["chat_id"], "type": "supergroup", "title": "Ops", "description": "on-call room"}
		for id, on := range f.pinned {
			if on {
				c["pinned_message"] = msg(allowed, id, f.texts[id])
			}
		}
		reply(c)
	case "getChatMemberCount":
		reply(7)
	case "sendMessage":
		f.nextID++
		f.texts[f.nextID] = p["text"].(string)
		m := msg(int64(p["chat_id"].(float64)), f.nextID, p["text"].(string))
		m["from"] = map[string]any{"id": 42, "is_bot": true, "first_name": "Conduit"}
		reply(m)
	case "editMessageText":
		id := int64(p["message_id"].(float64))
		f.texts[id] = p["text"].(string)
		reply(msg(allowed, id, f.texts[id]))
	case "deleteMessage":
		id := int64(p["message_id"].(float64))
		if id == 999 {
			w.WriteHeader(400)
			io.WriteString(w, `{"ok":false,"error_code":400,"description":"Bad Request: message can't be deleted"}`)
			return
		}
		f.deleted = append(f.deleted, id)
		reply(true)
	case "pinChatMessage":
		f.pinned[int64(p["message_id"].(float64))] = true
		reply(true)
	case "unpinChatMessage":
		f.pinned[int64(p["message_id"].(float64))] = false
		reply(true)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

func setup(t *testing.T, ref string, chats string) (*Module, *fakeBot) {
	f := &fakeBot{pinned: map[int64]bool{}, texts: map[int64]string{}, nextID: 100}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw := []byte(`{"token":"` + ref + `","allowedChats":` + chats + `}`)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tg": goodToken, "secret://bad": badToken, "secret://junk": "../../x"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTelegramReads(t *testing.T) {
	m, f := setup(t, "secret://tg", `["-1001234567890"]`)
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "signed in as @conduit_bot" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "me", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"username":"conduit_bot"`) || !strings.Contains(string(r.Output), `"allowedChats":["-1001234567890"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	f.updates = []map[string]any{
		{"update_id": int64(10), "message": msg(allowed, 1, "deploy done")},
		{"update_id": int64(11), "message": msg(other, 2, "private stuff")},
		{"update_id": int64(12), "edited_message": msg(allowed, 1, "deploy done!")},
		{"update_id": int64(13), "message": msg(allowed, 3, "thanks")},
	}
	r, err = invoke(m, "messages", `{}`, false)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"text":"deploy done!"`) || !strings.Contains(out, `"text":"thanks"`) || strings.Contains(out, "private stuff") || !strings.Contains(out, `"ignoredChats":[{"id":"555","type":"supergroup"}]`) {
		t.Fatalf("%s %v", out, err)
	}
	if strings.Index(out, "deploy done!") > strings.Index(out, "thanks") {
		t.Fatalf("newest should be last: %s", out)
	}
	// The offset moves past what was seen, and the buffer still has the messages.
	f.updates = append(f.updates, map[string]any{"update_id": int64(14), "channel_post": msg(allowed, 4, "new post")})
	r, err = invoke(m, "messages", `{"chat":-1001234567890,"limit":2}`, false)
	if err != nil || !strings.Contains(string(r.Output), "new post") || !strings.Contains(string(r.Output), "thanks") || strings.Contains(string(r.Output), "deploy done") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if last := f.offsets[len(f.offsets)-1]; last != float64(14) {
		t.Fatalf("offset not kept: %v", f.offsets)
	}

	r, err = invoke(m, "chat", `{"chat":"-1001234567890"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"members":7`) || !strings.Contains(string(r.Output), `"description":"on-call room"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "messages" || a.Name == "chat") && !a.Sensitive {
			t.Fatalf("%s must be sensitive", a.Name)
		}
		if a.Name == "delete_message" && a.Risk != sdk.RiskDestructive {
			t.Fatal("delete must be destructive")
		}
	}
}

func TestTelegramWrites(t *testing.T) {
	m, f := setup(t, "secret://tg", `[-1001234567890]`)
	now := time.Unix(1793000101, 0)
	m.Now = func() time.Time { return now }

	r, err := invoke(m, "send_message", `{"chat":"-1001234567890","text":"hello","silent":true}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Send a message to chat -1001234567890 silently" || len(f.texts) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "send_message", `{"chat":"-1001234567890","text":"hello"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_message" || f.texts[101] != "hello" {
		t.Fatalf("%+v %v", r, err)
	}
	undo := r.Undo

	// Edit knows the old text, so it shows it and can be undone.
	r, err = invoke(m, "edit_message", `{"chat":"-1001234567890","message":101,"text":"hello!"}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"text":"hello"}` || f.texts[101] != "hello" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "edit_message", `{"chat":"-1001234567890","message":101,"text":"hello!"}`, false)
	if err != nil || r.Undo == nil || f.texts[101] != "hello!" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.texts[101] != "hello" {
		t.Fatal(err, f.texts)
	}
	// An unknown message can be edited but not undone.
	if r, err := invoke(m, "edit_message", `{"chat":"-1001234567890","message":50,"text":"x"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}

	// Pin, undo unpins.
	r, err = invoke(m, "pin_message", `{"chat":"-1001234567890","message":101}`, false)
	if err != nil || !f.pinned[101] || r.Undo == nil || r.Undo.Action != "unpin_message" {
		t.Fatalf("%+v %v", r, err)
	}
	// Unpin without a message finds the current pin; undo pins it again.
	r, err = invoke(m, "unpin_message", `{"chat":"-1001234567890"}`, false)
	if err != nil || f.pinned[101] || r.Undo == nil || r.Undo.Action != "pin_message" || !strings.Contains(string(r.Undo.Input), `"message":101`) {
		t.Fatalf("%+v %v", r, err)
	}

	// Undoing the send deletes the message.
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err != nil || len(f.deleted) != 1 || f.deleted[0] != 101 {
		t.Fatal(err, f.deleted)
	}
	// After 48 hours the undo is refused before reaching Telegram.
	now = now.Add(49 * time.Hour)
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err == nil || !strings.Contains(err.Error(), "48 hours") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_message", `{"chat":"-1001234567890","message":999}`, false); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatal(err)
	}
}

func TestTelegramValidation(t *testing.T) {
	m, f := setup(t, "secret://tg", `["-1001234567890"]`)
	for _, c := range []struct{ action, in string }{
		{"send_message", `{"chat":"555","text":"hi"}`},
		{"send_message", `{"chat":"@channel","text":"hi"}`},
		{"send_message", `{"chat":"-1001234567890","text":""}`},
		{"send_message", `{"chat":"-1001234567890","text":"` + strings.Repeat("a", 4097) + `"}`},
		{"send_message", `{"chat":"-1001234567890","text":"hi","parseMode":"Markdown2"}`},
		{"chat", `{"chat":"../getMe"}`},
		{"chat", `{}`},
		{"messages", `{"chat":555}`},
		{"edit_message", `{"chat":"-1001234567890","text":"x"}`},
		{"pin_message", `{"chat":"-1001234567890"}`},
		{"delete_message", `{"chat":555,"message":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Telegram: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"123:abc"}`, `{"token":"secret://tg","allowedChats":["@chan"]}`, `{"token":"secret://tg","allowedChats":"1"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad", `[]`)
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	none, _ := setup(t, "secret://tg", `[]`)
	if h := none.Health(context.Background(), "t"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(none, "messages", `{}`, false); err == nil {
		t.Fatal("read with no allowed chats")
	}
	junk, _ := setup(t, "secret://junk", `[]`)
	if _, err := invoke(junk, "me", `{}`, false); err == nil || strings.Contains(err.Error(), "../") {
		t.Fatal(err)
	}
}

func TestTelegramWebhookConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		io.WriteString(w, `{"ok":false,"error_code":409,"description":"Conflict: can't use getUpdates method while webhook is active"}`)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tg": goodToken}), "t", json.RawMessage(`{"token":"secret://tg","allowedChats":[1]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "messages", `{}`, false); err == nil || !strings.Contains(err.Error(), "webhook") {
		t.Fatal(err)
	}
}

func TestTelegramRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tg": goodToken}), "t", json.RawMessage(`{"token":"secret://tg"}`)); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "t")
	if h.Status != "down" || hit || strings.Contains(h.Message, goodToken) || strings.Contains(h.Message, "ABCdef") {
		t.Fatalf("followed the redirect or leaked the token: %+v", h)
	}
}
