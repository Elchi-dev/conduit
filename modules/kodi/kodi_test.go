package kodi

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

type fakeKodi struct {
	mu      sync.Mutex
	playing bool
	active  bool
	volume  int
	muted   bool
	writes  []string
	calls   []string
}

var readOnly = map[string]bool{"Application.GetProperties": true, "Player.GetActivePlayers": true, "Player.GetProperties": true, "Player.GetItem": true,
	"VideoLibrary.GetRecentlyAddedMovies": true, "VideoLibrary.GetRecentlyAddedEpisodes": true}

func (f *fakeKodi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "kodi" || p != "pw" {
		w.WriteHeader(401)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/jsonrpc" {
		w.WriteHeader(404)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		ID     int             `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	f.calls = append(f.calls, req.Method)
	if !readOnly[req.Method] {
		f.writes = append(f.writes, req.Method+" "+string(req.Params))
	}
	var params map[string]any
	json.Unmarshal(req.Params, &params)
	reply := func(result string) { io.WriteString(w, `{"id":1,"jsonrpc":"2.0","result":`+result+`}`) }
	switch req.Method {
	case "Application.GetProperties":
		if strings.Contains(string(req.Params), "version") {
			reply(`{"name":"Kodi","version":{"major":21,"minor":1,"revision":"x","tag":"stable"}}`)
			return
		}
		b, _ := json.Marshal(map[string]any{"volume": f.volume, "muted": f.muted})
		reply(string(b))
	case "Player.GetActivePlayers":
		if !f.active {
			reply(`[]`)
			return
		}
		reply(`[{"playerid":1,"playertype":"internal","type":"video"}]`)
	case "Player.GetProperties":
		speed := 0
		if f.playing {
			speed = 1
		}
		b, _ := json.Marshal(map[string]any{"speed": speed, "time": map[string]int{"hours": 0, "minutes": 12, "seconds": 5}, "totaltime": map[string]int{"hours": 1, "minutes": 2, "seconds": 0}, "percentage": 19.4567, "shuffled": false, "repeat": "off"})
		reply(string(b))
	case "Player.GetItem":
		if strings.Contains(string(req.Params), `"file"`) {
			reply(`{"item":{"file":"smb://user:LEAKME@nas/x.mkv"}}`)
			return
		}
		reply(`{"item":{"type":"episode","label":"x.mkv","title":"Pilot","showtitle":"The Show","season":1,"episode":1,"artist":[]}}`)
	case "Player.PlayPause":
		f.playing = params["play"].(bool)
		if f.playing {
			reply(`{"speed":1}`)
		} else {
			reply(`{"speed":0}`)
		}
	case "Player.Stop":
		f.active = false
		reply(`"OK"`)
	case "Application.SetVolume":
		f.volume = int(params["volume"].(float64))
		reply(`1`)
	case "Application.SetMute":
		f.muted = params["mute"].(bool)
		reply(`true`)
	case "VideoLibrary.Scan", "AudioLibrary.Scan", "GUI.ShowNotification":
		reply(`"OK"`)
	case "VideoLibrary.GetRecentlyAddedMovies":
		if params["limits"].(map[string]any)["end"] != 3.0 {
			reply(`{"movies":[]}`)
			return
		}
		reply(`{"limits":{"end":1,"start":0,"total":1},"movies":[{"movieid":7,"label":"Film","title":"Film","year":2024,"rating":7.345,"runtime":6000,"dateadded":"2026-11-01 10:00:00","genre":["Drama"],"playcount":0}]}`)
	case "VideoLibrary.GetRecentlyAddedEpisodes":
		reply(`{"episodes":[{"episodeid":9,"title":"Pilot","showtitle":"The Show","season":1,"episode":1,"firstaired":"2026-10-30","dateadded":"2026-11-02 08:00:00","playcount":1,"runtime":2700}]}`)
	default:
		io.WriteString(w, `{"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found."}}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeKodi) {
	f := &fakeKodi{active: true, playing: true, volume: 40}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKodiRead(t *testing.T) {
	m, _ := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "Kodi 21.1" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"players", `{}`, `{"muted":false,"players":[{"item":{"episode":1,"name":"The Show S01E01 Pilot","season":1,"show":"The Show","title":"Pilot","type":"episode"},"length":"1:02:00","percent":19.5,"player":1,"playing":true,"position":"0:12:05","type":"video"}],"volume":40}`},
		{"recent_movies", `{"limit":3}`, `[{"added":"2026-11-01 10:00:00","genres":["Drama"],"id":7,"minutes":100,"rating":7.3,"title":"Film","watched":false,"year":2024}]`},
		{"recent_episodes", `{}`, `[{"added":"2026-11-02 08:00:00","aired":"2026-10-30","episode":1,"id":9,"minutes":45,"season":1,"show":"The Show","title":"Pilot","watched":true}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || string(r.Output) != c.want {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestKodiControl(t *testing.T) {
	m, f := setup(t, "secret://pw")
	p, err := invoke(m, "play_pause", `{}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Pause The Show S01E01 Pilot" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "play_pause", `{}`, false)
	if err != nil || f.playing || r.Undo == nil || string(r.Undo.Input) != `{"play":true,"player":1}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if r, err = invoke(m, "play_pause", `{"play":false}`, false); err != nil || !strings.Contains(string(r.Output), `"changed":false`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err = invoke(m, "play_pause", string(mustJSON(map[string]any{"player": 1, "play": true})), false); err != nil || !f.playing {
		t.Fatal(err)
	}

	p, err = invoke(m, "set_volume", `{"volume":70,"muted":true}`, true)
	if err != nil || string(p.Plan.Changes[0].Before) != `{"volume":40,"muted":false}` || string(p.Plan.Changes[0].After) != `{"volume":70,"muted":true}` || f.volume != 40 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "set_volume", `{"volume":70,"muted":true}`, false)
	if err != nil || f.volume != 70 || !f.muted || r.Undo == nil || r.Undo.Action != "set_volume" {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.volume != 40 || f.muted {
		t.Fatal(err, f.volume, f.muted)
	}

	before := len(f.writes)
	if _, err := invoke(m, "notify", `{"title":"Door","message":"Someone is at the door"}`, true); err != nil || len(f.writes) != before {
		t.Fatal(err)
	}
	if _, err := invoke(m, "notify", `{"title":"Door","message":"Someone is at the door","seconds":10}`, false); err != nil ||
		f.writes[len(f.writes)-1] != `GUI.ShowNotification {"displaytime":10000,"message":"Someone is at the door","title":"Door"}` {
		t.Fatal(err, f.writes)
	}
	if _, err := invoke(m, "scan_library", `{"library":"audio"}`, false); err != nil || f.writes[len(f.writes)-1] != `AudioLibrary.Scan {"showdialogs":false}` {
		t.Fatal(err, f.writes)
	}
	p, err = invoke(m, "stop", `{}`, true)
	if err != nil || p.Plan.Summary != "Stop The Show S01E01 Pilot at 0:12:05" || !f.active {
		t.Fatalf("%+v %v", p, err)
	}
	if r, err = invoke(m, "stop", `{"player":1}`, false); err != nil || f.active {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "stop", `{}`, false); err == nil || err.Error() != "nothing is playing" {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "recent") || a.Name == "players" {
			if a.Risk != sdk.RiskRead {
				t.Fatal(a.Name)
			}
		} else if a.Risk != sdk.RiskWrite || !a.DryRun {
			t.Fatal(a.Name)
		}
	}
}

func TestKodiRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || h.Message != "Kodi refused the username or password" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"play_pause", `{"player":5}`}, // not active
		{"play_pause", `{"player":-1}`},
		{"stop", `{"player":1000}`},
		{"set_volume", `{}`},
		{"set_volume", `{"volume":101}`},
		{"set_volume", `{"volume":-5}`},
		{"scan_library", `{"library":"clean"}`},
		{"notify", `{"title":"","message":"x"}`},
		{"notify", `{"title":"x","message":""}`},
		{"notify", `{"title":"x\u001b[2J","message":"y"}`},
		{"notify", `{"title":"x","message":"` + strings.Repeat("y", 501) + `"}`},
		{"notify", `{"title":"x","message":"y","seconds":600}`},
		{"recent_movies", `{"limit":1000}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("refused input reached Kodi: %v", f.writes)
	}
	for _, c := range []Config{{URL: "http://kodi:8080", Password: "plain"}, {URL: "kodi:8080"}, {URL: "http://kodi:pw@kodi:8080"}, {URL: "http://kodi:8080", Username: "a:b", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
