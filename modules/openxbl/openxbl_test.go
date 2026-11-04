package openxbl

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

const xuid = "2533274800000001"

type fakeXBL struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeXBL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Authorization") != "xbl_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error_message":"Invalid API key"}`)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/account":
		io.WriteString(w, `{"profileUsers":[{"id":"`+xuid+`","settings":[{"id":"Gamertag","value":"MasterChief"},{"id":"Gamerscore","value":"12345"},{"id":"AccountTier","value":"Gold"},{"id":"XboxOneRep","value":"GoodPlayer"}]}]}`)
	case "/presence":
		io.WriteString(w, `[{"xuid":"`+xuid+`","state":"Online","devices":[{"type":"Scarlett","titles":[{"id":"750323071","name":"Home","placement":"Background","state":"Active"},{"id":"219630713","name":"Halo Infinite","placement":"Full","state":"Active"}]}]}]`)
	case "/friends":
		io.WriteString(w, `{"people":[
			{"xuid":"2533274800000002","gamertag":"Cortana","isFavorite":true,"presenceState":"Offline","presenceText":"Last seen 2h ago: Halo","gamerScore":"500"},
			{"xuid":"2533274800000003","gamertag":"Arbiter","presenceState":"Online","presenceText":"Playing Forza Horizon 5","gamerScore":"9000"}]}`)
	case "/achievements":
		io.WriteString(w, `{"xuid":"`+xuid+`","titles":[
			{"titleId":"1","name":"Old Game","devices":["XboxOne"],"achievement":{"currentAchievements":5,"totalAchievements":10,"currentGamerscore":100,"totalGamerscore":1000,"progressPercentage":10},"titleHistory":{"lastTimePlayed":"2020-01-01T00:00:00Z"}},
			{"titleId":"219630713","name":"Halo Infinite","devices":["XboxSeries","PC"],"achievement":{"currentAchievements":40,"totalAchievements":120,"currentGamerscore":800,"totalGamerscore":1600,"progressPercentage":50},"titleHistory":{"lastTimePlayed":"2026-11-03T20:00:00Z"}},
			{"titleId":"3","name":"Never Unlocked","achievement":{"currentAchievements":0},"titleHistory":{"lastTimePlayed":"2026-10-01T00:00:00Z"}}]}`)
	case "/achievements/player/" + xuid + "/219630713":
		io.WriteString(w, `{"achievements":[
			{"name":"Fun Guy","description":"Kill 5 Grunts","progressState":"Achieved","titleAssociations":[{"name":"Halo Infinite","id":219630713}],"progression":{"timeUnlocked":"2026-11-03T19:00:00Z"},"rewards":[{"type":"Gamerscore","value":"10"}],"rarity":{"currentCategory":"Common","currentPercentage":45.5}},
			{"name":"Legendary","progressState":"NotStarted","titleAssociations":[{"name":"Halo Infinite"}]}]}`)
	case "/achievements/player/" + xuid + "/1":
		io.WriteString(w, `{"achievements":[{"name":"First Steps","progressState":"Achieved","titleAssociations":[{"name":"Old Game"}],"progression":{"timeUnlocked":"2019-12-31T00:00:00Z"}}]}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeXBL) {
	f := &fakeXBL{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{API: srv.URL}
	raw, _ := json.Marshal(Config{APIKey: "secret://x"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://x": key}), "x", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "x", Action: action, Input: json.RawMessage(in)})
}

func TestOpenXBL(t *testing.T) {
	m, f := setup(t, "xbl_good")
	if h := m.Health(context.Background(), "x"); h.Status != "ok" || h.Message != "MasterChief" {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string][]string{
		"profile":      {`"gamerscore":12345`, `"playing":"Halo Infinite"`, `"presence":"Online"`, `"tier":"Gold"`},
		"friends":      {`"total":2`, `"online":1`, `"friends":[{"gamerscore":9000,"gamertag":"Arbiter"`, `"favorite":true`},
		"titles":       {`[{"achievements":40`, `"progress":50`},
		"achievements": {`[{"name":"Fun Guy","game":"Halo Infinite"`, `"gamerscore":10`, `"rarity":"Common (45.5%)"`, `"First Steps"`},
	} {
		r, err := invoke(m, action, `{}`)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		for _, w := range want {
			if !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s: want %s in %s", action, w, r.Output)
			}
		}
	}
	if strings.Contains(strings.Join(f.seen, " "), "/3") {
		t.Fatalf("asked for a game without achievements: %v", f.seen)
	}
	if r, err := invoke(m, "friends", `{"onlineOnly":true}`); err != nil || strings.Contains(string(r.Output), "Cortana") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "achievements", `{"titleId":"219630713","count":1}`); err != nil || strings.Contains(string(r.Output), "First Steps") || !strings.Contains(string(r.Output), "Fun Guy") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "titles", `{"count":1}`); err != nil || strings.Contains(string(r.Output), "Old Game") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
		if a.Name == "friends" && !a.Sensitive {
			t.Fatal("friends names other people; it must be sensitive")
		}
	}
}

func TestOpenXBLValidation(t *testing.T) {
	m, f := setup(t, "xbl_good")
	for _, c := range []struct{ action, in string }{
		{"achievements", `{"titleId":"../../account"}`},
		{"achievements", `{"titleId":"12a"}`},
		{"achievements", `{"count":51}`},
		{"titles", `{"count":-1}`},
		{"titles", `{"count":"x"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached OpenXBL: %v", f.seen)
	}
	raw, _ := json.Marshal(Config{APIKey: "plainkey"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain key")
	}
	bad, _ := setup(t, "xbl_bad")
	if h := bad.Health(context.Background(), "x"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not carry the X-Authorization key there.
func TestOpenXBLRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{API: srv.URL}
	raw, _ := json.Marshal(Config{APIKey: "secret://x"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://x": "xbl_good"}), "x", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "x"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
