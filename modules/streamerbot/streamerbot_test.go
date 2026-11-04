package streamerbot

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

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	idAlert = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
	idRaid  = "9f8e7d6c-5b4a-3920-1a2b-3c4d5e6f7a8b"
	idOff   = "00000000-0000-0000-0000-000000000001"
)

type fakeSB struct {
	mu       sync.Mutex
	calls    int
	ran      []map[string]any
	password string
	redirect string
}

func (f *fakeSB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "" {
		f.serveWS(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /GetActions":
		io.WriteString(w, `{"count":4,"actions":[
			{"id":"`+idAlert+`","name":"Welcome Alert","group":"Alerts","enabled":true,"subaction_count":3},
			{"id":"`+idRaid+`","name":"Raid Out","group":"Stream","enabled":true},
			{"id":"`+idOff+`","name":"Old","group":"Stream","enabled":false},
			{"id":"00000000-0000-0000-0000-000000000002","name":"Twin","group":"A"},
			{"id":"00000000-0000-0000-0000-000000000003","name":"Twin","group":"B"}]}`)
	case "POST /DoAction":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.ran = append(f.ran, b)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeSB) serveWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ctx := r.Context()
	send := func(v any) { b, _ := json.Marshal(v); _ = ws.Write(ctx, websocket.MessageText, b) }
	hello := map[string]any{"request": "Hello", "info": map[string]string{"name": "Streamer.bot"}}
	if f.password != "" {
		hello["authentication"] = map[string]string{"salt": "c2FsdA==", "challenge": "Y2hhbA=="}
	}
	send(hello)
	authed := f.password == ""
	for {
		_, b, err := ws.Read(ctx)
		if err != nil {
			return
		}
		var req map[string]any
		_ = json.Unmarshal(b, &req)
		id := req["id"]
		switch req["request"] {
		case "Authenticate":
			if req["authentication"] == Auth(f.password, "c2FsdA==", "Y2hhbA==") {
				authed = true
				send(map[string]any{"id": id, "status": "ok"})
			} else {
				send(map[string]any{"id": id, "status": "error", "error": "Authentication failed"})
			}
		case "GetGlobals":
			if !authed {
				send(map[string]any{"id": id, "status": "error", "error": "not authenticated"})
				continue
			}
			send(map[string]any{"timestamp": "x", "event": map[string]string{"source": "General"}}) // an unrelated event first
			if req["persisted"] == true {
				send(map[string]any{"id": id, "status": "ok", "count": 2, "variables": map[string]any{
					"deaths":     map[string]any{"name": "deaths", "value": 12, "lastWrite": "2026-11-04T10:00:00Z"},
					"lastRaider": map[string]any{"name": "lastRaider", "value": "bob"}}})
			} else {
				send(map[string]any{"id": id, "status": "ok", "count": 0, "variables": map[string]any{}})
			}
		}
	}
}

func setup(t *testing.T, password string, cfg Config) (*Module, *fakeSB, string) {
	t.Helper()
	f := &fakeSB{password: password}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{HTTP: srv.Client()}
	if cfg.URL == "" {
		cfg.URL = srv.URL
	}
	if cfg.WebSocket == "-" {
		cfg.WebSocket = ""
	} else if cfg.WebSocket == "" {
		cfg.WebSocket = "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "hunter2", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, srv.URL
}

func call(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestStreamerBot(t *testing.T) {
	m, f, _ := setup(t, "hunter2", Config{Password: "secret://pw"})
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "5 actions" {
		t.Fatalf("health %+v", h)
	}
	r, err := call(m, "actions", `{"group":"stream"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"name":"Raid Out"`) || strings.Contains(string(r.Output), "Welcome") {
		t.Fatalf("actions %s %v", r.Output, err)
	}

	r, err = call(m, "run_action", `{"action":"Welcome Alert","args":{"user":"bob","count":3}}`, true)
	if err != nil || r.Plan == nil || len(f.ran) != 0 || r.Plan.Changes[0].Target != "Alerts / Welcome Alert" {
		t.Fatalf("dry run %v %+v", err, r.Plan)
	}
	if _, err := call(m, "run_action", `{"action":"Welcome Alert","args":{"user":"bob","count":3}}`, false); err != nil || len(f.ran) != 1 {
		t.Fatalf("run %v", err)
	}
	if a, _ := f.ran[0]["action"].(map[string]any); a["id"] != idAlert || f.ran[0]["args"].(map[string]any)["user"] != "bob" {
		t.Fatalf("ran %v", f.ran[0])
	}
	if _, err := call(m, "run_action", `{"id":"`+strings.ToUpper(idRaid)+`"}`, false); err != nil || len(f.ran) != 2 {
		t.Fatalf("run by id %v", err)
	}

	r, err = call(m, "globals", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"name":"deaths","value":12,"lastWrite":"2026-11-04T10:00:00Z"}`) || !strings.Contains(string(r.Output), `"count":2`) {
		t.Fatalf("globals %s %v", r.Output, err)
	}
	if r, err := call(m, "globals", `{"persisted":false}`, false); err != nil || !strings.Contains(string(r.Output), `"count":0`) {
		t.Fatalf("temporary globals %s %v", r.Output, err)
	}

	// Bad input never reaches DoAction; unknown, disabled and ambiguous
	// actions are refused after the list is read.
	for _, in := range []string{
		`{}`,
		`{"action":"Raid Out","id":"` + idRaid + `"}`,
		`{"id":"not-a-guid"}`,
		`{"action":"two\nlines"}`,
		`{"action":"Raid Out","args":{"bad key":"x"}}`,
		`{"action":"Raid Out","args":{"nested":{"a":1}}}`,
		`{"action":"Raid Out","args":{"x":"` + strings.Repeat("y", 2001) + `"}}`,
		`{"action":"Nope"}`,
		`{"action":"Old"}`,
		`{"action":"Twin"}`,
	} {
		if _, err := call(m, "run_action", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.ran) != 2 {
		t.Fatalf("bad input ran an action: %v", f.ran)
	}
	f.mu.Lock()
	n := f.calls
	f.mu.Unlock()
	if _, err := call(m, "run_action", `{"id":"x"}`, false); err == nil || f.calls != n {
		t.Fatal("a malformed id reached the server")
	}
}

func TestStreamerBotBadPassword(t *testing.T) {
	m, _, _ := setup(t, "hunter2", Config{Password: "secret://bad"})
	if h := m.Health(context.Background(), "s"); h.Status != "degraded" || !strings.Contains(h.Message, "refused the WebSocket password") {
		t.Fatalf("health %+v", h)
	}
	if _, err := call(m, "globals", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("globals with a bad password: %v", err)
	}
	m2, _, _ := setup(t, "hunter2", Config{})
	if _, err := call(m2, "globals", `{}`, false); err == nil || !strings.Contains(err.Error(), "asks for a password") {
		t.Fatalf("globals without a password: %v", err)
	}
	m3, _, _ := setup(t, "", Config{WebSocket: "-"})
	if _, err := call(m3, "globals", `{}`, false); err == nil || !strings.Contains(err.Error(), "WebSocket server") {
		t.Fatalf("globals without a WebSocket address: %v", err)
	}
}

func TestStreamerBotCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hit = true; mu.Unlock() }))
	defer other.Close()
	m, f, _ := setup(t, "", Config{WebSocket: "-"})
	f.redirect = other.URL + "/GetActions"
	_, err := call(m, "actions", `{}`, false)
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(err, rest.ErrCrossHostRedirect) || hit {
		t.Fatalf("redirect followed: %v %v", err, hit)
	}
}

func TestStreamerBotSettings(t *testing.T) {
	m := New()
	for _, raw := range []string{
		`{"url":"ftp://127.0.0.1:7474"}`,
		`{"url":"http://user:pw@127.0.0.1:7474"}`,
		`{"url":"http://127.0.0.1:7474/?x=1"}`,
		`{"websocket":"http://127.0.0.1:8080/"}`,
		`{"websocket":"ws://127.0.0.1:8080/","password":"plain"}`,
		`{"password":"secret://pw"}`,
	} {
		if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}
