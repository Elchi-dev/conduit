package discord

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

func TestDiscord(t *testing.T) {
	var posted, deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/webhooks/1/abc":
			io.WriteString(w, `{"name":"alerts"}`)
		case "POST /api/webhooks/1/abc":
			if r.URL.Query().Get("wait") != "true" {
				w.WriteHeader(400)
				return
			}
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			posted = b["content"].(string)
			io.WriteString(w, `{"id":"222222222222","channel_id":"3"}`)
		case "DELETE /api/webhooks/1/abc/messages/222222222222":
			deleted = "222222222222"
			w.WriteHeader(204)
		case "GET /bot/guilds/111111111111":
			if r.Header.Get("Authorization") != "Bot tok" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"name":"Squad","approximate_member_count":40,"approximate_presence_count":9}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Unknown"}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://hook": srv.URL + "/api/webhooks/1/abc", "secret://bot": "tok"})
	m := New()
	cfg, _ := json.Marshal(Config{Webhook: "secret://hook", BotToken: "secret://bot", Guild: "111111111111", API: srv.URL + "/bot"})
	if err := m.Configure(ctx, host, "d", cfg); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "send", Input: json.RawMessage(`{"message":"Backup finished"}`)})
	if err != nil || posted != "Backup finished" {
		t.Fatalf("send %v %q", err, posted)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || deleted == "" {
		t.Fatalf("undo %v", err)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "d", Action: "server"})
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	json.Unmarshal(r.Output, &s)
	if s["online"] != 9.0 {
		t.Fatalf("server %v", s)
	}
	if err := m.Configure(ctx, host, "x", json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty settings accepted")
	}
}
