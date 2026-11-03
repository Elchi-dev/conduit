package spotify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestSpotify(t *testing.T) {
	var refreshes atomic.Int32
	playing, volume := false, 40
	active := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/accounts/api/token" {
			r.ParseForm()
			if r.Form.Get("refresh_token") != "rt" || !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid refresh token"}`)
				return
			}
			refreshes.Add(1)
			io.WriteString(w, `{"access_token":"at","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/me":
			io.WriteString(w, `{"display_name":"Ada","product":"premium"}`)
		case "GET /v1/me/player":
			if !active {
				w.WriteHeader(204)
				return
			}
			b, _ := json.Marshal(map[string]any{"is_playing": playing, "progress_ms": 61000, "device": map[string]any{"id": "dev12345", "name": "Desk", "volume_percent": volume},
				"item": map[string]any{"name": "Song", "uri": "spotify:track:4uLU6hMCjMI75M1A2tKUQC", "duration_ms": 200000, "artists": []any{map[string]string{"name": "Band"}}, "album": map[string]string{"name": "LP"}}})
			w.Write(b)
		case "GET /v1/me/player/devices":
			io.WriteString(w, `{"devices":[{"id":"dev12345","name":"Desk","type":"Computer","is_active":true,"volume_percent":40}]}`)
		case "PUT /v1/me/player/play":
			if !active {
				w.WriteHeader(404)
				io.WriteString(w, `{"error":{"status":404,"message":"Player command failed: No active device found"}}`)
				return
			}
			playing = true
			w.WriteHeader(204)
		case "PUT /v1/me/player/pause":
			playing = false
			w.WriteHeader(204)
		case "PUT /v1/me/player/volume":
			volume = atoi(r.URL.Query().Get("volume_percent"))
			w.WriteHeader(204)
		case "POST /v1/me/player/next", "POST /v1/me/player/queue":
			w.WriteHeader(204)
		case "GET /v1/search":
			io.WriteString(w, `{"tracks":{"items":[{"name":"Song","uri":"spotify:track:4uLU6hMCjMI75M1A2tKUQC","artists":[{"name":"Band"}],"album":{"name":"LP"}}]}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://cs": "csecret", "secret://rt": "rt"})
	m := New()
	cfg, _ := json.Marshal(Config{ClientID: "cid", ClientSecret: "secret://cs", RefreshToken: "secret://rt", API: srv.URL + "/v1", Accounts: srv.URL + "/accounts"})
	if err := m.Configure(ctx, host, "s", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "s"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	inv := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	r := inv("now_playing", `{}`)
	if !strings.Contains(string(r.Output), `"track":"Song"`) || !strings.Contains(string(r.Output), `"progressSeconds":61`) {
		t.Fatalf("now playing %s", r.Output)
	}
	r = inv("play", `{}`)
	if !playing || r.Undo.Action != "pause" {
		t.Fatal("play")
	}
	inv(r.Undo.Action, string(r.Undo.Input))
	if playing {
		t.Fatal("undo play")
	}
	r = inv("volume", `{"percent":80}`)
	if volume != 80 || r.Undo == nil {
		t.Fatalf("volume %d", volume)
	}
	inv(r.Undo.Action, string(r.Undo.Input))
	if volume != 40 {
		t.Fatalf("undo volume %d", volume)
	}
	inv("next", `{}`)
	inv("queue", `{"uri":"spotify:track:4uLU6hMCjMI75M1A2tKUQC"}`)
	inv("devices", `{}`)
	inv("search", `{"query":"song"}`)
	if refreshes.Load() != 1 {
		t.Fatalf("the access token should be cached: %d refreshes", refreshes.Load())
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "queue", Input: json.RawMessage(`{"uri":"https://evil"}`)}); err == nil {
		t.Fatal("bad uri accepted")
	}

	active = false
	r = inv("now_playing", `{}`)
	if string(r.Output) != `{"playing":false}` {
		t.Fatalf("idle %s", r.Output)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "s", Action: "play"}); err == nil || !strings.Contains(err.Error(), "no active Spotify device") {
		t.Fatalf("no device: %v", err)
	}

	bad, _ := json.Marshal(Config{ClientID: "cid", ClientSecret: "secret://cs", RefreshToken: "secret://cs", API: srv.URL + "/v1", Accounts: srv.URL + "/accounts"})
	_ = m.Configure(ctx, host, "b", bad)
	if h := m.Health(ctx, "b"); h.Status != "down" || !strings.Contains(h.Message, "refresh token") {
		t.Fatalf("bad token health %+v", h)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
