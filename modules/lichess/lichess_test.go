package lichess

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const tok = "lip_GOODTOKEN0123456789"

type fakeLichess struct {
	mu       sync.Mutex
	seen     []string
	busy     int
	inFlight atomic.Int32
	overlap  bool
	waits    []time.Duration
}

func (f *fakeLichess) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.inFlight.Add(1) > 1 {
		f.overlap = true
	}
	defer f.inFlight.Add(-1)
	time.Sleep(2 * time.Millisecond)
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+r.URL.RawQuery)
	busy := f.busy > 0
	if busy {
		f.busy--
	}
	f.mu.Unlock()
	if !strings.Contains(r.Header.Get("User-Agent"), "Conduit") || strings.Contains(r.Header.Get("User-Agent"), "@") {
		w.WriteHeader(400)
		return
	}
	if busy {
		w.WriteHeader(429)
		return
	}
	auth := r.Header.Get("Authorization")
	if auth != "" && auth != "Bearer "+tok {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"No such token"}`)
		return
	}
	user := `{"id":"magnus","username":"Magnus","title":"GM","createdAt":1262304000000,"seenAt":1762000000000,"playTime":{"total":720000,"tv":0},
		"perfs":{"blitz":{"games":1000,"rating":3000,"rd":45,"prog":12,"rank":3},"rapid":{"games":5,"rating":2100,"rd":150,"prog":0,"prov":true},"storm":{"runs":4,"score":80},"racer":{"runs":0,"score":0}},
		"profile":{"bio":"LEAKBIO","realName":"LEAKNAME","location":"LEAKLOC"},"count":{"all":1100,"rated":1000,"win":700,"loss":200,"draw":200,"playing":1,"bookmark":3,"import":0,"me":0},"url":"https://lichess.org/@/Magnus"}`
	switch r.URL.Path {
	case "/api/account":
		if auth == "" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, user)
	case "/api/user/magnus":
		io.WriteString(w, user)
	case "/api/games/user/magnus":
		if r.Header.Get("Accept") != "application/x-ndjson" || r.URL.Query().Get("pgnInJson") != "false" || r.URL.Query().Get("moves") != "false" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		io.WriteString(w, `{"id":"aaaaaaaa","rated":true,"variant":"standard","speed":"blitz","perf":"blitz","createdAt":1762000000000,"lastMoveAt":1762000300000,"status":"mate","winner":"white","players":{"white":{"user":{"name":"Magnus","id":"magnus"},"rating":3000,"ratingDiff":5,"analysis":{"inaccuracy":1,"mistake":0,"blunder":0,"acpl":10,"accuracy":95}},"black":{"user":{"name":"Hikaru","id":"hikaru","title":"GM"},"rating":2990,"ratingDiff":-5}},"opening":{"eco":"C20","name":"King's Pawn Game","ply":2},"moves":"e4 e5 LEAKMOVES","pgn":"LEAKPGN","clock":{"initial":180,"increment":2,"totalTime":260}}
{"id":"bbbbbbbb","rated":false,"variant":"chess960","speed":"rapid","perf":"chess960","createdAt":1761000000000,"lastMoveAt":1761000300000,"status":"resign","winner":"white","players":{"white":{"aiLevel":8},"black":{"user":{"name":"Magnus","id":"magnus"},"rating":2100}}}
{"id":"../evil","players":{}}
{"id":"cccccccc","rated":true,"variant":"standard","speed":"bullet","perf":"bullet","createdAt":1760000000000,"lastMoveAt":1760000100000,"status":"draw","players":{"white":{"user":{"name":"x","id":"x"},"rating":2500},"black":{"user":{"name":"Magnus","id":"magnus"},"rating":3100,"ratingDiff":0}}}
`)
	case "/api/account/playing":
		if auth == "" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"nbMyTurn":1,"nowPlaying":[{"fullId":"ddddddddLEAK","gameId":"dddddddd","fen":"rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1","color":"white","lastMove":"","source":"friend","variant":{"key":"standard","name":"Standard"},"speed":"correspondence","perf":"correspondence","rated":false,"rating":2000,"hasMoved":false,"opponent":{"id":"bob","username":"Bob","rating":1500},"isMyTurn":true,"secondsLeft":86000}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

func setup(t *testing.T, cfg Config, secret string) (*Module, *fakeLichess) {
	f := &fakeLichess{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	m.sleep = func(_ context.Context, d time.Duration) error {
		f.mu.Lock()
		f.waits = append(f.waits, d)
		f.mu.Unlock()
		return nil
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://l": secret}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in)})
}

func TestLichess(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://l"}, tok)
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "Magnus" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"profile", `{}`, []string{`"title":"GM"`, `"blitz":{"deviation":45,"games":1000,"progress":12,"rank":3,"rating":3000}`, `"provisional":true`, `"storm":{"best":80,"runs":4}`, `"hoursPlayed":200`, `"win":700`}},
		{"profile", `{"username":"Magnus"}`, []string{`"username":"Magnus"`}},
		{"games", `{"count":5,"days":30,"perfType":"blitz","rated":true}`, []string{`"opening":"King's Pawn Game"`, `"result":"win"`, `"ratingDiff":5`, `"accuracy":95`, `"opponent":"Stockfish level 8"`, `"opponentTitle":"GM"`, `"timeControl":"180+2"`, `"results":{"draw":1,"loss":1,"win":1}`, `"variant":"chess960"`}},
		{"ongoing", `{}`, []string{`"myTurn":1`, `"id":"dddddddd"`, `"opponent":"Bob"`, `"secondsLeft":86000`}},
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
		for _, bad := range []string{"LEAK", "GOODTOKEN", "evil", "rnbqkbnr"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s shows %s: %s", c.action, bad, out)
			}
		}
	}
	var q string
	for _, s := range f.seen {
		if strings.HasPrefix(s, "/api/games/user/") {
			q = s
		}
	}
	for _, w := range []string{"max=5", "perfType=blitz", "rated=true", "since=", "pgnInJson=false"} {
		if !strings.Contains(q, w) {
			t.Fatalf("want %s in %s", w, q)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestLichessWithoutToken(t *testing.T) {
	m, f := setup(t, Config{Username: "magnus"}, "")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "games", `{}`); err != nil {
		t.Fatal(err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "ongoing", `{}`); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatal(err)
	}
	if len(f.seen) != n {
		t.Fatal("ongoing without a token reached Lichess")
	}
	if _, err := invoke(m, "profile", `{"username":"nobody"}`); err == nil || !strings.Contains(err.Error(), "no player named nobody") {
		t.Fatal(err)
	}
}

// One request at a time, a 429 waits (a minute without Retry-After) and is
// retried once.
func TestLichessRateLimits(t *testing.T) {
	m, f := setup(t, Config{Username: "magnus"}, "")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); invoke(m, "profile", `{}`) }()
	}
	wg.Wait()
	if f.overlap {
		t.Fatal("requests ran in parallel")
	}
	f.busy = 1
	if _, err := invoke(m, "games", `{}`); err != nil || len(f.waits) != 1 || f.waits[0] != time.Minute {
		t.Fatalf("%v %v", err, f.waits)
	}
	f.busy = 3
	if _, err := invoke(m, "profile", `{}`); err == nil || !strings.Contains(err.Error(), "limiting") || len(f.waits) != 2 {
		t.Fatalf("%v %v", err, f.waits)
	}
	if d := pause(http.Header{"Retry-After": {"7"}}); d != 7*time.Second {
		t.Fatal(d)
	}
	if d := pause(http.Header{"Retry-After": {"3600"}}); d != time.Minute {
		t.Fatal(d)
	}
}

func TestLichessValidation(t *testing.T) {
	m, f := setup(t, Config{Username: "magnus", Token: "secret://l"}, tok)
	for _, c := range []struct{ action, in string }{
		{"profile", `{"username":"../api/account"}`},
		{"games", `{"username":"a"}`},
		{"games", `{"username":"magnus?x=1"}`},
		{"games", `{"count":51}`},
		{"games", `{"days":400}`},
		{"games", `{"perfType":"blitz,rapid"}`},
		{"ongoing", `{"count":-1}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Lichess: %v", f.seen)
	}
	for _, c := range []Config{{}, {Token: "lip_plain"}, {Username: "bad name"}, {Username: "x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Token: "secret://l"}, "lip_WRONGTOKEN123456789")
	h := bad.Health(context.Background(), "l")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the token") || strings.Contains(h.Message, "WRONG") {
		t.Fatalf("%+v", h)
	}
}

func TestLichessRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "x" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: "secret://l"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://l": tok}), "l", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "l")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "GOODTOKEN") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	if _, err := invoke(m, "games", `{"username":"magnus"}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}

// A caller waiting for the shared slot, or pausing after a 429 inside it,
// gives up when its context ends and never keeps the slot.
func TestLichessSlotHonoursCancellation(t *testing.T) {
	m, f := setup(t, Config{Username: "magnus"}, "")
	slot <- struct{}{} // another request holds the slot
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "profile", Input: json.RawMessage(`{}`)})
	cancel()
	<-slot
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waited past the deadline: %v", err)
	}
	c, _ := m.set.Get("l")
	c.sleep = wait // the real pause, a full minute without Retry-After
	f.busy = 1
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "l", Action: "profile", Input: json.RawMessage(`{}`)}); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("pause ignored cancellation: %v", err)
	}
	select {
	case slot <- struct{}{}:
		<-slot
	default:
		t.Fatal("the slot was kept after a cancelled pause")
	}
}
