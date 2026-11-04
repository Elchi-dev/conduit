package battlemetrics

import (
	"context"
	"encoding/json"
	"fmt"
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

const tok = "bmtoken.GOOD0123456789abcdef"

type fakeBM struct {
	mu    sync.Mutex
	seen  []string
	busy  int
	waits []time.Duration
}

func srv(id, name, status string, players int) string {
	return fmt.Sprintf(`{"type":"server","id":%q,"attributes":{"id":%q,"name":%q,"address":"play.example.com","ip":"203.0.113.9","port":28015,"players":%d,"maxPlayers":100,"rank":42,"status":%q,"country":"DE","updatedAt":"2026-11-04T10:00:00Z",
		"details":{"map":"Procedural Map","rust_type":"community","version":"2600","serverSteamId":"90000000000LEAK","rconActive":true,"rcon_ip":"LEAKIP","long":"%s","nested":{"x":"LEAK"},
		"minecraft_motd":"Join us at 198.51.100.7:25565","welcome":"steam://run/252490//+connect%%20LEAKHOST","alt":"play.LEAKHOST.net:28015","v6":"2001:db8::7:1","queryPort":28017,"pve":false,"mode":"Line one\nLine two"}},
		"relationships":{"game":{"data":{"type":"game","id":"rust"}}}}`, id, id, name, players, status, strings.Repeat("x", 200))
}

func (f *fakeBM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+tok {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"status":"401","title":"Unauthorized","detail":"Invalid access token `+r.Header.Get("Authorization")+`"}]}`)
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
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(429)
		return
	}
	switch r.URL.Path {
	case "/games":
		io.WriteString(w, `{"data":[{"type":"game","id":"rust"}]}`)
	case "/servers/111":
		io.WriteString(w, `{"data":`+srv("111", "Rust Main", "online", 80)+`}`)
	case "/servers/222":
		io.WriteString(w, `{"data":`+srv("222", "Rust Side", "offline", 0)+`}`)
	case "/servers/333": // answers with another server
		io.WriteString(w, `{"data":`+srv("111", "Rust Main", "online", 80)+`}`)
	case "/servers/111/player-count-history":
		q := r.URL.Query()
		start, err1 := time.Parse(time.RFC3339, q.Get("start"))
		stop, err2 := time.Parse(time.RFC3339, q.Get("stop"))
		if err1 != nil || err2 != nil || stop.Sub(start) > 721*time.Hour || q.Get("resolution") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"data":[{"type":"dataPoint","attributes":{"timestamp":"2026-11-04T09:00:00.000Z","value":60,"min":55,"max":70}},{"type":"dataPoint","attributes":{"timestamp":"2026-11-04T08:00:00.000Z","value":40}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"status":"404","title":"Not Found"}]}`)
	}
}

func setup(t *testing.T, secret string, servers ...string) (*Module, *fakeBM) {
	f := &fakeBM{}
	s := httptest.NewServer(f)
	t.Cleanup(s.Close)
	m := &Module{Base: s.URL}
	m.sleep = func(_ context.Context, d time.Duration) error { f.waits = append(f.waits, d); return nil }
	raw, _ := json.Marshal(Config{Token: "secret://bm", Servers: servers})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bm": secret}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in)})
}

func TestBattleMetrics(t *testing.T) {
	m, f := setup(t, tok, "222", "111", "111")
	if h := m.Health(context.Background(), "b"); h.Status != "degraded" || h.Message != "1 of 2 servers online · 80 players" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"servers", `{}`, []string{`"online":1`, `"total":2`, `"players":80`, `"servers":[{"country":"DE","game":"rust","id":"111"`, `"rank":42`, `"url":"https://www.battlemetrics.com/servers/rust/111"`}},
		{"server", `{"server":"111"}`, []string{`"details":{"map":"Procedural Map","mode":"Line one Line two","pve":false,"rust_type":"community","version":"2600"}`, `"updated":"2026-11-04T10:00:00Z"`}},
		{"player_history", `{"server":"111","hours":72}`, []string{`"low":40`, `"high":70`, `"average":50`, `"resolutionMinutes":60`, `"points":[{"time":"2026-11-04T08:00:00.000Z","players":40}`}},
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
		for _, bad := range []string{"LEAK", "203.0.113.9", "198.51.100", "2001:db8", "28017", "connect", "play.example.com", "GOOD0123", "xxxxxxxx"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s shows %s: %s", c.action, bad, out)
			}
		}
	}
	if _, err := invoke(m, "server", `{"server":"333"}`); err == nil {
		t.Fatal("accepted another server's answer")
	}
	if _, err := invoke(m, "server", `{"server":"999"}`); err == nil || !strings.Contains(err.Error(), "no server 999") {
		t.Fatal(err)
	}
	f.busy = 1
	if _, err := invoke(m, "server", `{"server":"111"}`); err != nil || len(f.waits) != 1 || f.waits[0] != 3*time.Second {
		t.Fatalf("%v %v", err, f.waits)
	}
	f.busy = 2
	if _, err := invoke(m, "server", `{"server":"111"}`); err == nil || !strings.Contains(err.Error(), "limiting") || len(f.waits) != 2 {
		t.Fatalf("%v %v", err, f.waits)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead || strings.Contains(strings.ToLower(a.Name), "rcon") {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
	none, _ := setup(t, tok)
	if h := none.Health(context.Background(), "b"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(none, "servers", `{}`); err == nil {
		t.Fatal("servers without any in the settings")
	}
}

func TestBattleMetricsHidesAddressesInText(t *testing.T) {
	for in, want := range map[string]string{
		"Rust Main":                          "Rust Main",
		"EU Main | 198.51.100.7:28015":       "EU Main | [address]",
		"Main [2001:db8::1]:28015 \x1b[31mx": "Main [address] [31mx",
		"Two\nlines":                         "Two lines",
		"v1.2.3 build 4":                     "v1.2.3 build 4",
	} {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanName(strings.Repeat("é", 100)); len(got) > 124 || !strings.HasSuffix(got, "…") {
		t.Errorf("long name kept: %q", got)
	}
}

func TestBattleMetricsValidation(t *testing.T) {
	m, f := setup(t, tok, "111")
	for _, c := range []struct{ action, in string }{
		{"server", `{}`},
		{"server", `{"server":"../games"}`},
		{"server", `{"server":"111?include=player"}`},
		{"player_history", `{"server":"111","hours":721}`},
		{"player_history", `{"server":"111","hours":-1}`},
		{"rcon", `{"command":"quit"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached BattleMetrics: %v", f.seen)
	}
	many := make([]string, 26)
	for i := range many {
		many[i] = fmt.Sprint(i + 1)
	}
	for _, c := range []Config{{Token: "plaintoken"}, {Token: "secret://bm", Servers: []string{"abc"}}, {Token: "secret://bm", Servers: many}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "bmtoken.WRONG0123456789abcdef", "111")
	h := bad.Health(context.Background(), "b")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the token") || strings.Contains(h.Message, "WRONG") {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(bad, "servers", `{}`); err != nil || strings.Contains(string(r.Output), "WRONG") || !strings.Contains(string(r.Output), "refused the token") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestBattleMetricsRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "x" }))
	defer evil.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer s.Close()
	m := &Module{Base: s.URL}
	raw, _ := json.Marshal(Config{Token: "secret://bm", Servers: []string{"111"}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bm": tok}), "b", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "b")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "GOOD") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
