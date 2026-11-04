package faceit

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
	key = "FACEITKEY-0123456789abcdef"
	pid = "5ea07280-2399-4c7e-88ab-f2f7db0c449f"
)

type fakeFaceit struct {
	mu    sync.Mutex
	seen  []string
	busy  int
	waits []time.Duration
}

func (f *fakeFaceit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Invalid API key `+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+`","code":"err_u0"}]}`)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+r.URL.RawQuery)
	busy := f.busy > 0
	if busy {
		f.busy--
	}
	f.mu.Unlock()
	if busy {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		return
	}
	pl := `{"player_id":"` + pid + `","nickname":"s1mple","avatar":"https://x/LEAKAVATAR.jpg","country":"ua","steam_id_64":"76561198034202275","friends_ids":["LEAKFRIEND"],"verified":true,
		"games":{"cs2":{"region":"EU","game_player_id":"76561198034202275","skill_level":10,"faceit_elo":3500,"game_player_name":"s1mple"},"dota2":{"region":"EU","skill_level":3,"faceit_elo":1100}},
		"settings":{"language":"en"},"infractions":{"LEAK":1}}`
	switch r.URL.Path {
	case "/players":
		if r.URL.Query().Get("nickname") != "s1mple" {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[{"message":"The resource was not found.","code":"err_nf0"}]}`)
			return
		}
		io.WriteString(w, pl)
	case "/players/" + pid:
		io.WriteString(w, pl)
	case "/players/" + pid + "/stats/cs2":
		io.WriteString(w, `{"player_id":"`+pid+`","game_id":"cs2","lifetime":{"Matches":"1200","Win Rate %":"61","Average K/D Ratio":"1.4","Recent Results":["1","0","1","1","1"],"Nested":{"x":1},"Bad\nKey":"LEAK","Clutch\u001b[2J":"LEAK","Longest Win Streak":"12\r\n","Empty":[{"x":"LEAK"}]},"segments":[{"label":"Mirage","stats":{"Matches":"300"}}]}`)
	case "/players/" + pid + "/history":
		io.WriteString(w, `{"items":[
			{"match_id":"1-aaaa-bbbb","game_id":"cs2","region":"EU","match_type":"","game_mode":"5v5","max_players":10,"competition_name":"CS2 5v5 PREMIUM","started_at":1762000000,"finished_at":1762002000,"status":"finished",
			 "teams":{"faction1":{"team_id":"t1","nickname":"team_s1mple","players":[{"player_id":"`+pid+`","nickname":"s1mple"}]},"faction2":{"team_id":"t2","nickname":"team_other","players":[{"player_id":"x","nickname":"other"}]}},
			 "results":{"winner":"faction1","score":{"faction1":13,"faction2":7}}},
			{"match_id":"1-cccc","game_id":"cs2","game_mode":"5v5","started_at":1761000000,"finished_at":1761002000,"status":"finished",
			 "teams":{"faction1":{"nickname":"a","players":[{"player_id":"y"}]},"faction2":{"nickname":"b","players":[{"player_id":"`+pid+`"}]}},"results":{"winner":"faction1","score":{"faction1":13,"faction2":11}}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"message":"The resource was not found.","code":"err_nf0"}]}`)
	}
}

func setup(t *testing.T, secret string) (*Module, *fakeFaceit) {
	f := &fakeFaceit{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	m.sleep = func(_ context.Context, d time.Duration) error { f.waits = append(f.waits, d); return nil }
	raw, _ := json.Marshal(Config{APIKey: "secret://f", Nickname: "s1mple"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://f": secret}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in)})
}

func TestFaceit(t *testing.T) {
	m, f := setup(t, key)
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "s1mple · cs2 level 10" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"player", `{}`, []string{`"playerId":"` + pid, `"country":"UA"`, `"cs2":{"elo":3500,"inGameName":"s1mple","level":10,"region":"EU"}`, `"dota2":`}},
		{"player", `{"playerId":"` + strings.ToUpper(pid) + `"}`, []string{`"nickname":"s1mple"`}},
		{"stats", `{}`, []string{`"Matches":"1200"`, `"Win Rate %":"61"`, `"Recent Results":["1","0","1","1","1"]`, `"Longest Win Streak":"12"`, `"Empty":[]`, `"elo":3500`}},
		{"matches", `{"count":5,"days":7}`, []string{`"results":{"loss":1,"win":1}`, `"score":{"faction1":13,"faction2":7}`, `"team":"team_s1mple"`, `"competition":"CS2 5v5 PREMIUM"`, `"started":"2025-11-01T12:26:40Z"`}},
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
		for _, bad := range []string{"LEAK", key, "Nested", "Mirage"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s shows %s: %s", c.action, bad, out)
			}
		}
	}
	last := f.seen[len(f.seen)-1]
	for _, w := range []string{"game=cs2", "limit=5", "from=", "to="} {
		if !strings.Contains(last, w) {
			t.Fatalf("want %s in %s", w, last)
		}
	}
	if _, err := invoke(m, "player", `{"nickname":"nobody"}`); err == nil || !strings.Contains(err.Error(), "no player named nobody") {
		t.Fatal(err)
	}
	f.busy = 1
	if _, err := invoke(m, "player", `{}`); err != nil || len(f.waits) != 1 || f.waits[0] != time.Second {
		t.Fatalf("%v %v", err, f.waits)
	}
	f.busy = 3
	if _, err := invoke(m, "player", `{}`); err == nil || !strings.Contains(err.Error(), "limiting") || len(f.waits) != 2 {
		t.Fatalf("%v %v", err, f.waits)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestFaceitValidation(t *testing.T) {
	m, f := setup(t, key)
	for _, c := range []struct{ action, in string }{
		{"player", `{"nickname":"a/b"}`},
		{"player", `{"nickname":"x&game=1"}`},
		{"player", `{"playerId":"../../games"}`},
		{"player", `{"playerId":"` + pid + `","nickname":"s1mple"}`},
		{"stats", `{"game":"CS2/../x"}`},
		{"matches", `{"count":100}`},
		{"matches", `{"days":365}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached FACEIT: %v", f.seen)
	}
	for _, c := range []Config{{APIKey: "plainkey", Nickname: "s1mple"}, {APIKey: "secret://f"}, {APIKey: "secret://f", Nickname: "a b"}, {APIKey: "secret://f", Nickname: "s1mple", Game: "CS 2"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "WRONGKEY-0123456789abcdef")
	h := bad.Health(context.Background(), "f")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API key") || strings.Contains(h.Message, "WRONGKEY") {
		t.Fatalf("%+v", h)
	}
}

func TestFaceitRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "x" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{APIKey: "secret://f", Nickname: "s1mple"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://f": key}), "f", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "f")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, key) {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
