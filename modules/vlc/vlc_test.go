package vlc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeVLC struct {
	mu       sync.Mutex
	state    string
	volume   int
	item     int
	calls    int
	redirect string
}

var titles = []string{"Intro", "Main Theme", "Credits"}

func (f *fakeVLC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if u, p, ok := r.BasicAuth(); !ok || u != "" || p != "vlcpass" {
		w.Header().Set("WWW-Authenticate", `Basic realm="VLC stream"`)
		w.WriteHeader(401)
		io.WriteString(w, "<html><body>Error loading /requests/status.json: password required</body></html>")
		return
	}
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	switch r.URL.Path {
	case "/requests/status.json":
		q := r.URL.Query()
		switch q.Get("command") {
		case "":
		case "pl_forcepause":
			f.state = "paused"
		case "pl_forceresume", "pl_play":
			f.state = "playing"
		case "pl_next":
			f.item = (f.item + 1) % len(titles)
		case "pl_previous":
			f.item = (f.item + len(titles) - 1) % len(titles)
		case "volume":
			v, err := strconv.Atoi(q.Get("val"))
			if err != nil || v < 0 || v > 512 {
				w.WriteHeader(400)
				return
			}
			f.volume = v
		default:
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"state":%q,"volume":%d,"time":61,"length":200,"position":0.305,"random":false,"loop":true,"repeat":false,"fullscreen":0,"version":"3.0.21 Vetinari",
			"information":{"category":{"meta":{"title":%q,"artist":"Composer","album":"OST","filename":"track.flac","artwork_url":"file:///home/me/.cache/art.jpg"}}}}`,
			f.state, f.volume, titles[f.item])
	case "/requests/playlist.json":
		io.WriteString(w, `{"type":"node","id":"0","name":"","children":[
			{"type":"node","id":"1","name":"Playlist","children":[
				{"type":"leaf","id":"4","name":"Intro","duration":90,"uri":"smb://user:secretpw@nas/music/intro.flac","current":"current"},
				{"type":"node","id":"9","name":"Folder","children":[{"type":"leaf","id":"5","name":"Main Theme","duration":200,"uri":"file:///x"}]},
				{"type":"leaf","id":"6","name":"Credits","duration":-1,"uri":"file:///y"}]},
			{"type":"node","id":"2","name":"Media Library","children":[{"type":"leaf","id":"7","name":"Library item","uri":"file:///z"}]}]}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, password string) (*Module, *fakeVLC) {
	t.Helper()
	f := &fakeVLC{state: "playing", volume: 256}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{HTTP: srv.Client()}
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://vlc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://vlc": password}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestVLC(t *testing.T) {
	m, f := setup(t, "vlcpass")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || h.Message != "VLC 3.0.21 · playing: Intro" {
		t.Fatalf("health %+v", h)
	}
	r, err := call(m, "status", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"volume":100`) || !strings.Contains(string(r.Output), `"position":30.5`) {
		t.Fatalf("status %s %v", r.Output, err)
	}
	r, err = call(m, "now_playing", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"artist":"Composer"`) || strings.Contains(string(r.Output), "art.jpg") {
		t.Fatalf("now_playing %s %v", r.Output, err)
	}

	// Pause, then undo resumes.
	if r, err := call(m, "pause", `{}`, true); err != nil || r.Plan == nil || f.state != "playing" {
		t.Fatalf("dry run %v %q", err, f.state)
	}
	r, err = call(m, "pause", `{}`, false)
	if err != nil || f.state != "paused" || r.Undo == nil || r.Undo.Action != "play" {
		t.Fatalf("pause %v %q %+v", err, f.state, r.Undo)
	}
	r, err = call(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.state != "playing" || r.Undo == nil || r.Undo.Action != "pause" {
		t.Fatalf("resume %v %q", err, f.state)
	}
	if r, err := call(m, "play", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"unchanged":true`) || r.Undo != nil {
		t.Fatalf("play while playing %s %v", r.Output, err)
	}

	// Next, then undo goes back.
	r, err = call(m, "next", `{}`, false)
	if err != nil || f.item != 1 || !strings.Contains(string(r.Output), "Main Theme") || r.Undo.Action != "previous" {
		t.Fatalf("next %s %v", r.Output, err)
	}
	if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.item != 0 {
		t.Fatalf("undo next %v %d", err, f.item)
	}

	// Volume, then undo restores it.
	r, err = call(m, "set_volume", `{"percent":50}`, false)
	if err != nil || f.volume != 128 || !strings.Contains(string(r.Output), `"percent":50`) {
		t.Fatalf("volume %s %v %d", r.Output, err, f.volume)
	}
	if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.volume != 256 {
		t.Fatalf("undo volume %v %d", err, f.volume)
	}

	r, err = call(m, "playlist", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"total":3`) || !strings.Contains(string(r.Output), `{"id":"4","name":"Intro","duration":90,"current":true}`) {
		t.Fatalf("playlist %s %v", r.Output, err)
	}
	if strings.Contains(string(r.Output), "secretpw") || strings.Contains(string(r.Output), "Library item") {
		t.Fatalf("playlist shows a URI or the library: %s", r.Output)
	}

	f.mu.Lock()
	before := f.calls
	f.mu.Unlock()
	for _, c := range []struct{ action, in string }{
		{"set_volume", `{}`},
		{"set_volume", `{"percent":201}`},
		{"set_volume", `{"percent":-1}`},
		{"set_volume", `{"percent":"50&command=pl_stop"}`},
		{"playlist", `{"limit":10000}`},
	} {
		if _, err := call(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	f.mu.Lock()
	if f.calls != before {
		t.Fatalf("bad input reached VLC (%d calls)", f.calls-before)
	}
	f.mu.Unlock()
}

func TestVLCBadPassword(t *testing.T) {
	m, f := setup(t, "wrong")
	if h := m.Health(context.Background(), "v"); h.Status != "down" || h.Message != "VLC refused the password" {
		t.Fatalf("health %+v", h)
	}
	if _, err := call(m, "pause", `{}`, false); !rest.IsStatus(err, 401) || f.state != "playing" {
		t.Fatalf("pause with a bad password: %v", err)
	}
}

func TestVLCCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hit = true; mu.Unlock() }))
	defer other.Close()
	m, f := setup(t, "vlcpass")
	f.redirect = other.URL + "/requests/status.json"
	_, err := call(m, "status", `{}`, false)
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(err, rest.ErrCrossHostRedirect) || hit {
		t.Fatalf("redirect followed: %v %v", err, hit)
	}
}

func TestVLCSettings(t *testing.T) {
	m := New()
	for _, raw := range []string{
		`{"password":"plain"}`,
		`{}`,
		`{"url":"ftp://127.0.0.1:8080","password":"secret://vlc"}`,
		`{"url":"http://:pw@127.0.0.1:8080","password":"secret://vlc"}`,
		`{"url":"http://127.0.0.1:8080/?command=pl_stop","password":"secret://vlc"}`,
	} {
		if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"password":"secret://vlc"}`)); err != nil {
		t.Fatal(err)
	}
}
