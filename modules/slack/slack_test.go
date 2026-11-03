package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestSlack(t *testing.T) {
	var posted, hooked, deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hook/T1/B1/x" {
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			hooked = b["text"]
			io.WriteString(w, "ok")
			return
		}
		if r.Header.Get("Authorization") != "Bearer xoxb-1" {
			io.WriteString(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		var b map[string]any
		if r.Method == "POST" {
			json.NewDecoder(r.Body).Decode(&b)
		}
		switch r.URL.Path {
		case "/api/auth.test":
			io.WriteString(w, `{"ok":true,"team":"Acme","user":"conduit"}`)
		case "/api/chat.postMessage":
			if b["channel"] == "C0NOTIN00" {
				io.WriteString(w, `{"ok":false,"error":"not_in_channel"}`)
				return
			}
			posted = b["text"].(string)
			io.WriteString(w, `{"ok":true,"channel":"C0123ABCD","ts":"1730600000.000100"}`)
		case "/api/chat.delete":
			deleted = b["ts"].(string)
			io.WriteString(w, `{"ok":true}`)
		case "/api/conversations.list":
			io.WriteString(w, `{"ok":true,"channels":[{"id":"C0123ABCD","name":"ops","is_member":true,"num_members":5}]}`)
		case "/api/conversations.history":
			if r.URL.Query().Get("limit") != "2" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"ok":true,"messages":[{"ts":"1.1","user":"U1","text":"hi"},{"ts":"1.2","bot_id":"B9","text":"deploy done"}]}`)
		default:
			io.WriteString(w, `{"ok":false,"error":"unknown_method"}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://bot": "xoxb-1", "secret://hook": srv.URL + "/hook/T1/B1/x"})
	m := New()
	cfg, _ := json.Marshal(Config{BotToken: "secret://bot", Webhook: "secret://hook", Channel: "C0123ABCD", API: srv.URL + "/api"})
	if err := m.Configure(ctx, host, "s", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "s"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "send", Input: json.RawMessage(`{"message":"Backup done <!channel>"}`)})
	if err != nil || posted != "Backup done &lt;!channel>" {
		t.Fatalf("send %v %q", err, posted)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || deleted != "1730600000.000100" {
		t.Fatalf("undo %v %q", err, deleted)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "send", Input: json.RawMessage(`{"message":"x","channel":"C0NOTIN00"}`)}); err == nil {
		t.Fatal("ok:false must be an error")
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "s", Action: "history", Input: json.RawMessage(`{"limit":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	var hist []map[string]any
	json.Unmarshal(r.Output, &hist)
	if len(hist) != 2 || hist[1]["from"] != "bot B9" {
		t.Fatalf("history %s", r.Output)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "channels"}); err != nil {
		t.Fatal(err)
	}

	// Webhook only.
	cfg, _ = json.Marshal(Config{Webhook: "secret://hook"})
	if err := m.Configure(ctx, host, "w", cfg); err != nil {
		t.Fatal(err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "w", Action: "send", Input: json.RawMessage(`{"message":"<!here> up"}`)})
	if err != nil || hooked != "&lt;!here> up" || r.Undo != nil {
		t.Fatalf("webhook %v %q %+v", err, hooked, r.Undo)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "w", Action: "history"}); err == nil {
		t.Fatal("history without a bot must fail")
	}
	if err := m.Configure(ctx, host, "x", json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty settings accepted")
	}
	if err := m.Configure(ctx, host, "x", json.RawMessage(`{"botToken":"secret://bot","channel":"general"}`)); err == nil {
		t.Fatal("channel name accepted as id")
	}
}
