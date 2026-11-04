package steam

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

const (
	me  = "76561198000000001"
	bob = "76561198000000002"
	eve = "76561198000000003"
)

type fakeSteam struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeSteam) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("key") != "STEAMKEY0123456789" {
		w.WriteHeader(403)
		io.WriteString(w, "<html><body><h1>Forbidden</h1>Access is denied. Retrying will not help. Please verify your <pre>key=</pre> parameter.</body></html>")
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+q.Get("steamid")+q.Get("steamids")+q.Get("appid"))
	f.mu.Unlock()
	switch r.URL.Path {
	case "/ISteamUser/GetPlayerSummaries/v2/":
		var ps []string
		for _, id := range strings.Split(q.Get("steamids"), ",") {
			switch id {
			case me:
				ps = append(ps, `{"steamid":"`+me+`","personaname":"gordon","profileurl":"https://steamcommunity.com/id/gordon/","personastate":1,"communityvisibilitystate":3,"timecreated":1262304000,"gameextrainfo":"Half-Life 3","gameid":"999","loccountrycode":"NL"}`)
			case bob:
				ps = append(ps, `{"steamid":"`+bob+`","personaname":"bob","personastate":0,"communityvisibilitystate":3,"lastlogoff":1762000000}`)
			case eve:
				ps = append(ps, `{"steamid":"`+eve+`","personaname":"eve","personastate":3,"communityvisibilitystate":3,"gameextrainfo":"Dota 2","gameid":"570"}`)
			}
		}
		io.WriteString(w, `{"response":{"players":[`+strings.Join(ps, ",")+`]}}`)
	case "/IPlayerService/GetSteamLevel/v1/":
		io.WriteString(w, `{"response":{"player_level":42}}`)
	case "/IPlayerService/GetOwnedGames/v1/":
		io.WriteString(w, `{"response":{"game_count":321}}`)
	case "/ISteamUser/GetFriendList/v1/":
		io.WriteString(w, `{"friendslist":{"friends":[{"steamid":"`+bob+`","relationship":"friend","friend_since":1500000000},{"steamid":"`+eve+`","relationship":"friend","friend_since":1600000000},{"steamid":"../x","relationship":"friend"}]}}`)
	case "/IPlayerService/GetRecentlyPlayedGames/v1/":
		io.WriteString(w, `{"response":{"total_count":1,"games":[{"appid":570,"name":"Dota 2","playtime_2weeks":125,"playtime_forever":60000}]}}`)
	case "/ISteamUserStats/GetPlayerAchievements/v1/":
		if q.Get("appid") == "4000" {
			w.WriteHeader(400)
			io.WriteString(w, `{"playerstats":{"error":"Requested app has no stats","success":false}}`)
			return
		}
		io.WriteString(w, `{"playerstats":{"steamID":"`+me+`","gameName":"Portal 2","success":true,"achievements":[
			{"apiname":"A","achieved":1,"unlocktime":1700000000,"name":"Wake Up Call","description":"Survive the manual override"},
			{"apiname":"B","achieved":1,"unlocktime":1760000000,"name":"You Monster","description":"Reunite with GLaDOS"},
			{"apiname":"C","achieved":0,"unlocktime":0,"name":"Lunacy","description":"Fall into the test chamber"}]}}`)
	case "/ISteamUserStats/GetNumberOfCurrentPlayers/v1/":
		io.WriteString(w, `{"response":{"player_count":712345,"result":1}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeSteam) {
	f := &fakeSteam{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{API: srv.URL}
	raw, _ := json.Marshal(Config{APIKey: "secret://s", SteamID: me})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://s": key}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestSteam(t *testing.T) {
	m, _ := setup(t, "STEAMKEY0123456789")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "gordon · online" {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string][]string{
		"profile":      {`"level":42`, `"ownedGames":321`, `"playing":"Half-Life 3"`, `"created":"2010-01-01T00:00:00Z"`},
		"friends":      {`"total":2`, `"online":1`, `"playing":1`, `"friends":[{"appId":"570"`, `"name":"bob"`, `"lastOnline":`},
		"recent":       {`"lastTwoWeeks":2`, `"hours":1000`},
		"owned_count":  {`"ownedGames":321`},
		"achievements": {`"unlocked":2`, `"total":3`, `"percent":66`, `"latest":[{"name":"You Monster"`, `"remaining":[{"name":"Lunacy"`},
		"player_count": {`"players":712345`},
	} {
		r, err := invoke(m, action, `{"appId":620}`)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		for _, w := range want {
			if !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s: want %s in %s", action, w, r.Output)
			}
		}
		if strings.Contains(string(r.Output), "STEAMKEY") {
			t.Fatalf("%s shows the key", action)
		}
	}
	if r, err := invoke(m, "friends", `{"onlineOnly":true}`); err != nil || strings.Contains(string(r.Output), `"name":"bob"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "achievements", `{"appId":4000}`); err == nil || !strings.Contains(err.Error(), "no stats") {
		t.Fatal(err)
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

func TestSteamValidation(t *testing.T) {
	m, f := setup(t, "STEAMKEY0123456789")
	for _, c := range []struct{ action, in string }{
		{"achievements", `{}`},
		{"achievements", `{"appId":-1}`},
		{"player_count", `{"appId":99999999999}`},
		{"player_count", `{"appId":"570&key=x"}`},
		{"recent", `{"count":500}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Steam: %v", f.seen)
	}
	for _, c := range []Config{{APIKey: "PLAINKEY", SteamID: me}, {APIKey: "secret://s", SteamID: "12345"}, {APIKey: "secret://s", SteamID: "gordon"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "WRONGKEY")
	h := bad.Health(context.Background(), "s")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API key") || strings.Contains(h.Message, "WRONGKEY") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "profile", `{}`); err == nil || strings.Contains(err.Error(), "WRONGKEY") {
		t.Fatal(err)
	}
}

// The key is in the query string: a redirect elsewhere must not be followed,
// and no error may show the URL.
func TestSteamRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{API: srv.URL}
	raw, _ := json.Marshal(Config{APIKey: "secret://s", SteamID: me})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://s": "STEAMKEY0123456789"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "s")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "STEAMKEY") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	// Unreachable: the error doesn't echo the URL either.
	srv.Close()
	if _, err := invoke(m, "profile", `{}`); err == nil || strings.Contains(err.Error(), "STEAMKEY") || strings.Contains(err.Error(), "http") {
		t.Fatal(err)
	}
}
