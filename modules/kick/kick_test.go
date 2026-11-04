package kick

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeKick struct {
	mu       sync.Mutex
	title    string
	catID    int64
	catName  string
	chat     []map[string]any
	calls    int
	refresh  string // the refresh token Kick accepts now
	redirect string
}

func (f *fakeKick) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "kickclient1" || r.Form.Get("client_secret") != "cs" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_client","error_description":"client authentication failed"}`)
			return
		}
		switch r.Form.Get("grant_type") {
		case "client_credentials":
			io.WriteString(w, `{"access_token":"app-tok","expires_in":3600}`)
		case "refresh_token":
			if r.Form.Get("refresh_token") != f.refresh {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token is invalid"}`)
				return
			}
			f.refresh = "rt2"
			io.WriteString(w, `{"access_token":"user-tok","refresh_token":"rt2","expires_in":7200}`)
		}
		return
	}
	f.calls++
	auth := r.Header.Get("Authorization")
	if auth != "Bearer app-tok" && auth != "Bearer user-tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
		return
	}
	q := r.URL.Query()
	me := func() string {
		t, _ := json.Marshal(f.title)
		return `{"broadcaster_user_id":42,"slug":"mychan","stream_title":` + string(t) + `,"channel_description":"hi","active_subscribers_count":12,"category":{"id":` + jsonInt(f.catID) + `,"name":"` + f.catName + `"},"stream":{"is_live":true,"viewer_count":99,"start_time":"2026-11-04T18:00:00Z","language":"en","key":"sk_live_SECRETSTREAMKEY","url":"rtmps://ingest.kick"}}`
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/users":
		if auth != "Bearer user-tok" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"data":[{"user_id":42,"name":"mychan","email":"me@example.com"}]}`)
	case "GET /v1/channels":
		var items []string
		if q.Get("broadcaster_user_id") == "42" {
			items = append(items, me())
		}
		for _, s := range q["slug"] {
			switch s {
			case "mychan":
				items = append(items, me())
			case "xqc":
				items = append(items, `{"broadcaster_user_id":7,"slug":"xqc","stream_title":"react","category":{"id":1,"name":"Just Chatting"},"stream":{"is_live":true,"viewer_count":50000,"start_time":"2026-11-04T12:00:00Z","key":""}}`)
			case "offline":
				items = append(items, `{"broadcaster_user_id":8,"slug":"offline","stream_title":"zzz","stream":{"is_live":false}}`)
			}
		}
		io.WriteString(w, `{"data":[`+strings.Join(items, ",")+`],"message":"OK"}`)
	case "GET /v1/categories":
		if strings.EqualFold(q.Get("q"), "minecraft") {
			io.WriteString(w, `{"data":[{"id":5,"name":"Minecraft Dungeons"},{"id":6,"name":"Minecraft"}]}`)
			return
		}
		io.WriteString(w, `{"data":[{"id":9,"name":"Something else"}]}`)
	case "PATCH /v1/channels":
		if auth != "Bearer user-tok" {
			w.WriteHeader(403)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if v, ok := b["stream_title"].(string); ok {
			f.title = v
		}
		if v, ok := b["category_id"].(float64); ok {
			f.catID = int64(v)
			f.catName = map[int64]string{1: "Just Chatting", 6: "Minecraft"}[f.catID]
		}
		w.WriteHeader(204)
	case "POST /v1/chat":
		if auth != "Bearer user-tok" {
			w.WriteHeader(403)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.chat = append(f.chat, b)
		io.WriteString(w, `{"data":{"is_sent":true,"message_id":"m1"},"message":"OK"}`)
	default:
		w.WriteHeader(404)
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

type writerHost struct {
	*fakehost.Host
	mu sync.Mutex
}

func (h *writerHost) SetSecret(_ context.Context, ref, v string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Secrets[ref] = v
	return nil
}

func (h *writerHost) Secret(ctx context.Context, ref string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Host.Secret(ctx, ref)
}

func setup(t *testing.T, refresh string) (*Module, *fakeKick, *writerHost) {
	t.Helper()
	f := &fakeKick{title: "Old title", catID: 1, catName: "Just Chatting", refresh: "rt"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL + "/v1", Auth: srv.URL + "/oauth/token"}
	h := &writerHost{Host: fakehost.New(map[string]string{"secret://cs": "cs", "secret://rt": refresh})}
	raw, _ := json.Marshal(Config{ClientID: "kickclient1", ClientSecret: "secret://cs", RefreshToken: "secret://rt", Channels: []string{"xqc", "offline"}})
	if err := m.Configure(context.Background(), h, "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, h
}

func call(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKick(t *testing.T) {
	m, f, h := setup(t, "rt")
	if hl := m.Health(context.Background(), "k"); hl.Status != "ok" || hl.Message != "kick.com/mychan" {
		t.Fatalf("health %+v", hl)
	}
	if h.Secrets["secret://rt"] != "rt2" {
		t.Fatal("the rotated refresh token wasn't saved")
	}
	r, err := call(m, "livestreams", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"viewers":50000`) || !strings.Contains(string(r.Output), `{"channel":"offline","live":false}`) {
		t.Fatalf("livestreams %s %v", r.Output, err)
	}
	r, err = call(m, "channel", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"channel":"mychan"`) || !strings.Contains(string(r.Output), `"subscribers":12`) {
		t.Fatalf("channel %s %v", r.Output, err)
	}
	for _, action := range []string{"channel", "livestreams"} {
		r, _ := call(m, action, `{"channel":"mychan","channels":["mychan"]}`, false)
		if strings.Contains(string(r.Output), "SECRETSTREAMKEY") || strings.Contains(string(r.Output), "ingest") || strings.Contains(string(r.Output), "@example.com") {
			t.Fatalf("%s leaks the stream key or email: %s", action, r.Output)
		}
	}

	r, err = call(m, "set_stream", `{"title":"New title","category":"minecraft"}`, true)
	if err != nil || r.Plan == nil || f.title != "Old title" || !strings.Contains(string(r.Plan.Changes[0].After), `"category":"Minecraft"`) {
		t.Fatalf("dry run %v %+v", err, r.Plan)
	}
	r, err = call(m, "set_stream", `{"title":"New title","category":"Minecraft"}`, false)
	if err != nil || f.title != "New title" || f.catID != 6 || r.Undo == nil {
		t.Fatalf("set %v %q %d", err, f.title, f.catID)
	}
	if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.title != "Old title" || f.catID != 1 {
		t.Fatalf("undo %v %q %d", err, f.title, f.catID)
	}
	if _, err := call(m, "set_stream", `{"category":"Minecraf"}`, false); err == nil || !strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("inexact category: %v", err)
	}

	r, err = call(m, "send_chat", `{"message":"gg"}`, true)
	if err != nil || r.Plan == nil || len(f.chat) != 0 {
		t.Fatalf("chat dry run %v", err)
	}
	if _, err := call(m, "send_chat", `{"message":"gg"}`, false); err != nil || len(f.chat) != 1 || f.chat[0]["content"] != "gg" || f.chat[0]["broadcaster_user_id"] != float64(42) {
		t.Fatalf("chat %v %v", err, f.chat)
	}

	// Bad input never reaches the server.
	f.mu.Lock()
	before := f.calls
	f.mu.Unlock()
	for _, c := range []struct{ action, in string }{
		{"channel", `{"channel":"../users"}`},
		{"livestreams", `{"channels":["ok","bad slug"]}`},
		{"set_stream", `{}`},
		{"set_stream", `{"title":"two\nlines"}`},
		{"set_stream", `{"title":"   "}`},
		{"set_stream", `{"title":"` + strings.Repeat("x", 141) + `"}`},
		{"set_stream", `{"category":"Minecraft","categoryId":6}`},
		{"set_stream", `{"categoryId":-1}`},
		{"send_chat", `{"message":""}`},
		{"send_chat", `{"message":"line\rbreak"}`},
		{"send_chat", `{"message":"` + strings.Repeat("x", 501) + `"}`},
	} {
		if _, err := call(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	f.mu.Lock()
	if f.calls != before {
		t.Fatalf("bad input reached the server (%d calls)", f.calls-before)
	}
	f.mu.Unlock()
}

func TestKickBadToken(t *testing.T) {
	m, f, _ := setup(t, "stale")
	hl := m.Health(context.Background(), "k")
	if hl.Status != "degraded" || !strings.Contains(hl.Message, "refresh token is invalid") || strings.Contains(hl.Message, "stale") {
		t.Fatalf("health %+v", hl)
	}
	if _, err := call(m, "send_chat", `{"message":"gg"}`, false); err == nil || len(f.chat) != 0 {
		t.Fatalf("chat with a bad token: %v", err)
	}
	// The app token still reads.
	if _, err := call(m, "livestreams", `{}`, false); err != nil {
		t.Fatal(err)
	}
}

func TestKickCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	stolen := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); stolen = true; mu.Unlock() }))
	defer other.Close()
	m, f, _ := setup(t, "rt")
	f.redirect = other.URL + "/x"
	_, err := call(m, "livestreams", `{}`, false)
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(err, rest.ErrCrossHostRedirect) || stolen {
		t.Fatalf("redirect followed: %v %v", err, stolen)
	}
}

func TestKickSettings(t *testing.T) {
	m := New()
	h := fakehost.New(nil)
	for _, raw := range []string{
		`{"clientId":"kickclient1","clientSecret":"plain"}`,
		`{"clientId":"kickclient1","clientSecret":"secret://cs","refreshToken":"plain"}`,
		`{"clientId":"","clientSecret":"secret://cs"}`,
		`{"clientId":"kickclient1","clientSecret":"secret://cs","channels":["no spaces"]}`,
	} {
		if err := m.Configure(context.Background(), h, "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	// Without a user token, writes are refused before any request.
	if err := m.Configure(context.Background(), h, "x", json.RawMessage(`{"clientId":"kickclient1","clientSecret":"secret://cs"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "x", Action: "send_chat", Input: json.RawMessage(`{"message":"hi"}`)}); err == nil {
		t.Fatal("chat without a user token")
	}
}
