package chesscom

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

type fakeChess struct {
	mu      sync.Mutex
	seen    []string
	busy    int // answer 429 this many times
	agents  []string
	retried []time.Duration
}

func (f *fakeChess) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path)
	f.agents = append(f.agents, r.Header.Get("User-Agent"))
	busy := f.busy > 0
	if busy {
		f.busy--
	}
	f.mu.Unlock()
	if busy {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(429)
		return
	}
	switch r.URL.Path {
	case "/player/hikaru":
		io.WriteString(w, `{"avatar":"https://images.chesscomfiles.com/x.png","player_id":15448422,"url":"https://www.chess.com/member/Hikaru","name":"Hikaru Nakamura","username":"hikaru","title":"GM","followers":1200000,"country":"https://api.chess.com/pub/country/US","location":"Florida","last_online":1762000000,"joined":1389043258,"status":"premium","is_streamer":true,"verified":false,"league":"Legend"}`)
	case "/player/hikaru/stats":
		io.WriteString(w, `{"chess_daily":{"last":{"rating":2100,"date":1700000000,"rd":100},"best":{"rating":2200,"date":1600000000,"game":"https://www.chess.com/game/daily/1"},"record":{"win":10,"loss":2,"draw":3}},
			"chess_blitz":{"last":{"rating":3300,"date":1762000000,"rd":30},"best":{"rating":3400,"date":1700000000},"record":{"win":5000,"loss":1000,"draw":800}},
			"chess960_daily":{"last":{"rating":1900,"date":1700000000,"rd":200},"record":{"win":1,"loss":0,"draw":0}},
			"tactics":{"highest":{"rating":3000,"date":1},"lowest":{"rating":400,"date":1}},"puzzle_rush":{"best":{"total_attempts":40,"score":38}},"fide":2800}`)
	case "/player/hikaru/games/archives":
		io.WriteString(w, `{"archives":["https://api.chess.com/pub/player/hikaru/games/2026/09","https://api.chess.com/pub/player/hikaru/games/2026/10","https://evil.example/../x"]}`)
	case "/player/hikaru/games/2026/10":
		io.WriteString(w, `{"games":[
			{"url":"https://www.chess.com/game/live/1","pgn":"[Event \"Live\"] 1. e4 LEAKPGN","time_control":"180","end_time":1760000000,"rated":true,"time_class":"blitz","rules":"chess","accuracies":{"white":91.5,"black":80},"white":{"rating":3300,"result":"win","username":"Hikaru"},"black":{"rating":3200,"result":"resigned","username":"MagnusCarlsen"}},
			{"url":"https://www.chess.com/game/live/2","pgn":"LEAKPGN","time_control":"180","end_time":1760001000,"rated":true,"time_class":"blitz","rules":"chess","white":{"rating":3150,"result":"win","username":"someone"},"black":{"rating":3290,"result":"checkmated","username":"hikaru"}},
			{"url":"https://www.chess.com/game/live/3","time_control":"180","end_time":1760002000,"rated":true,"time_class":"blitz","rules":"chess","white":{"rating":3291,"result":"repetition","username":"hikaru"},"black":{"rating":3000,"result":"repetition","username":"x"}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":0,"message":"User \"nobody\" not found."}`)
	}
}

func setup(t *testing.T) (*Module, *fakeChess) {
	f := &fakeChess{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	m.sleep = func(_ context.Context, d time.Duration) error {
		f.mu.Lock()
		f.retried = append(f.retried, d)
		f.mu.Unlock()
		return nil
	}
	raw, _ := json.Marshal(Config{Username: "Hikaru"})
	if err := m.Configure(context.Background(), fakehost.New(nil), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in)})
}

func TestChessCom(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "hikaru" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"profile", `{}`, []string{`"title":"GM"`, `"country":"US"`, `"followers":1200000`, `"streamer":true`, `"joined":"2014-01-06`}},
		{"stats", `{}`, []string{`"blitz":{"best":3400,"date":`, `"win":5000`, `"960_daily":`, `"daily":`, `"puzzlesHighest":3000`, `"puzzleRushBest":38`, `"fide":2800`}},
		{"archives", `{"count":1}`, []string{`"total":2`, `"months":["2026-10"]`}},
		{"month", `{"month":"2026-10","count":2}`, []string{`"games":3`, `"blitz":{"draw":1,"games":3,"loss":1,"ratingChange":-9,"ratingEnd":3291,"ratingStart":3300,"win":1}`, `"latest":[{"color":"white"`, `"result":"draw"`, `"opponent":"someone"`}},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		out := string(r.Output)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Fatalf("%s: want %s in %s", c.action, w, out)
			}
		}
		for _, bad := range []string{"LEAKPGN", "Florida", "Hikaru Nakamura", "evil", "avatar"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s shows %s: %s", c.action, bad, out)
			}
		}
	}
	if r, _ := invoke(m, "month", `{"month":"2026-10","count":2}`); strings.Contains(string(r.Output), "MagnusCarlsen") {
		t.Fatalf("count not applied: %s", r.Output)
	}
	if _, err := invoke(m, "profile", `{"username":"nobody"}`); err == nil || !strings.Contains(err.Error(), "nothing for player nobody") {
		t.Fatal(err)
	}
	for _, ua := range f.agents {
		if !strings.Contains(ua, "Conduit") || strings.Contains(ua, "@") {
			t.Fatalf("user agent %q", ua)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestChessComRetriesOnce(t *testing.T) {
	m, f := setup(t)
	f.busy = 1
	if _, err := invoke(m, "profile", `{}`); err != nil || len(f.retried) != 1 || f.retried[0] != 2*time.Second {
		t.Fatalf("%v %v", err, f.retried)
	}
	f.busy = 5
	if _, err := invoke(m, "profile", `{}`); err == nil || !strings.Contains(err.Error(), "limiting") {
		t.Fatal(err)
	}
	if len(f.retried) != 2 {
		t.Fatalf("retried more than once: %v", f.retried)
	}
}

func TestChessComValidation(t *testing.T) {
	m, f := setup(t)
	for _, c := range []struct{ action, in string }{
		{"profile", `{"username":"../admin"}`},
		{"profile", `{"username":"a b"}`},
		{"stats", `{"username":"x?y=1"}`},
		{"month", `{"month":"2026-13"}`},
		{"month", `{"month":"2006-12"}`},
		{"month", `{"month":"2999-01"}`},
		{"month", `{"month":"26-1"}`},
		{"month", `{"count":500}`},
		{"archives", `{"count":0.5}`},
		{"archives", `{"count":1000}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Chess.com: %v", f.seen)
	}
	for _, raw := range []string{`{}`, `{"username":"a/b"}`, `{"username":"x"}`, `[]`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestChessComRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Username: "hikaru"})
	if err := m.Configure(context.Background(), fakehost.New(nil), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
