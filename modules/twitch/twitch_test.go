package twitch

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

func TestTwitch(t *testing.T) {
	var mu sync.Mutex
	title, game, gameName := "Old title", "509658", "Just Chatting"
	tokens := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "cs" || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(400)
				io.WriteString(w, `{"message":"invalid client secret"}`)
				return
			}
			tokens++
			io.WriteString(w, `{"access_token":"app-tok","expires_in":3600}`)
			return
		}
		if r.Header.Get("Client-Id") != "cid" {
			w.WriteHeader(401)
			return
		}
		auth := r.Header.Get("Authorization")
		switch r.Method + " " + r.URL.Path {
		case "GET /helix/streams":
			if auth != "Bearer app-tok" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"data":[{"user_login":"shroud","user_name":"shroud","title":"ranked","game_name":"Valorant","viewer_count":12000,"started_at":"2026-11-03T20:00:00Z"}]}`)
		case "GET /helix/users":
			if auth == "Bearer user-tok" && r.URL.Query().Get("login") == "" {
				io.WriteString(w, `{"data":[{"id":"42","login":"me","display_name":"Me"}]}`)
				return
			}
			io.WriteString(w, `{"data":[{"id":"7","login":"shroud","display_name":"shroud"}]}`)
		case "GET /helix/channels":
			id := r.URL.Query().Get("broadcaster_id")
			io.WriteString(w, `{"data":[{"broadcaster_id":"`+id+`","broadcaster_login":"me","broadcaster_name":"Me","title":"`+title+`","game_id":"`+game+`","game_name":"`+gameName+`"}]}`)
		case "GET /helix/games":
			if r.URL.Query().Get("name") == "Minecraft" {
				io.WriteString(w, `{"data":[{"id":"27471","name":"Minecraft"}]}`)
				return
			}
			io.WriteString(w, `{"data":[]}`)
		case "PATCH /helix/channels":
			if auth != "Bearer user-tok" || r.URL.Query().Get("broadcaster_id") != "42" {
				w.WriteHeader(401)
				return
			}
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if v, ok := b["title"]; ok {
				title = v
			}
			if v, ok := b["game_id"]; ok {
				game = v
				gameName = map[string]string{"27471": "Minecraft", "509658": "Just Chatting"}[v]
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://cs": "cs", "secret://ut": "oauth:user-tok"})
	cfg, _ := json.Marshal(Config{ClientID: "cid", ClientSecret: "secret://cs", UserToken: "secret://ut", Channels: []string{"shroud", "pokimane"},
		API: srv.URL + "/helix", Auth: srv.URL + "/token"})
	if err := m.Configure(ctx, h, "t", cfg); err != nil {
		t.Fatal(err)
	}
	call := func(action, in string, dry bool) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
	}
	r, err := call("streams", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"live":true`) || !strings.Contains(string(r.Output), `{"channel":"pokimane","live":false}`) {
		t.Fatalf("streams %s %v", r.Output, err)
	}
	if _, err := call("streams", `{"channels":["bad name!"]}`, false); err == nil {
		t.Fatal("bad channel accepted")
	}
	r, err = call("set_stream", `{"title":"New title","category":"Minecraft"}`, true)
	if err != nil || r.Plan == nil || title != "Old title" {
		t.Fatalf("dry run changed something: %v %q", err, title)
	}
	r, err = call("set_stream", `{"title":"New title","category":"Minecraft"}`, false)
	if err != nil || title != "New title" || game != "27471" || r.Undo == nil {
		t.Fatalf("set %v %q %q", err, title, game)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input), false); err != nil || title != "Old title" || game != "509658" {
		t.Fatalf("undo %v %q %q", err, title, game)
	}
	if _, err := call("set_stream", `{"category":"Nope"}`, false); err == nil {
		t.Fatal("unknown category accepted")
	}
	if tokens != 1 {
		t.Fatalf("app token fetched %d times, want 1 (cached)", tokens)
	}
	if hl := m.Health(ctx, "t"); hl.Status != "ok" {
		t.Fatalf("health %+v", hl)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"clientId":"a","clientSecret":"plain"}`)); err == nil {
		t.Fatal("plaintext secret accepted")
	}
}
