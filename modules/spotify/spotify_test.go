package spotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	song  = "spotify:track:4uLU6hMCjMI75M1A2tKUQC"
	song2 = "spotify:track:7ouMYWpwJ422jRcDASZB7P"
	song3 = "spotify:track:0VjIjW4GlUZAMYd2vXMi3b"
	lp    = "spotify:album:1DFixLWuPkv3KT3TnV35m3"
	plist = "spotify:playlist:37i9dQZF1DXcBWIGoYBM5M"
)

// fakeAPI is a small stand-in for the Spotify Web API and accounts service.
type fakeAPI struct {
	t  *testing.T
	mu sync.Mutex

	premium    bool
	rotate     string // refresh token to hand out on the next refresh
	expiresIn  int
	refreshes  int
	tokens     int
	revoke     bool // the next API call answers 401 once
	playing    bool
	volume     int
	shuffle    bool
	repeat     string
	device     string
	progress   int
	ctxURI     string
	itemURI    string
	library    map[string]bool
	playlist   []string
	recent     []map[string]any
	lastPlay   map[string]any
	scope      string
	refreshTok string
}

func newFake(t *testing.T) *fakeAPI {
	return &fakeAPI{t: t, premium: true, expiresIn: 3600, volume: 40, repeat: "off", device: "dev12345", progress: 61000,
		itemURI: song, ctxURI: lp, playing: true, library: map[string]bool{}, playlist: []string{song, song2}, refreshTok: "rt",
		scope: strings.Join(Scopes, " ")}
}

func trackJSON(uri, name string, ms int) map[string]any {
	return map[string]any{"type": "track", "name": name, "uri": uri, "duration_ms": ms,
		"artists": []any{map[string]string{"name": "Band", "uri": "spotify:artist:0OdUWJ0sBjDrqHygGUXeCF"}},
		"album":   map[string]any{"name": "LP", "uri": lp, "release_date": "2020-01-01"}}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(v any) { b, _ := json.Marshal(v); w.Write(b) }
	if r.URL.Path == "/accounts/api/token" {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != f.refreshTok || r.Header.Get("Authorization") == "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid refresh token"}`)
			return
		}
		f.refreshes++
		f.tokens++
		out := map[string]any{"access_token": fmt.Sprintf("at%d", f.tokens), "expires_in": f.expiresIn, "scope": f.scope}
		if f.rotate != "" {
			out["refresh_token"] = f.rotate
			f.refreshTok, f.rotate = f.rotate, ""
		}
		write(out)
		return
	}
	if r.Header.Get("Authorization") != fmt.Sprintf("Bearer at%d", f.tokens) || f.revoke {
		f.revoke = false
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"status":401,"message":"The access token expired"}}`)
		return
	}
	premiumOnly := func() bool {
		if !f.premium {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"status":403,"message":"Player command failed: Premium required","reason":"PREMIUM_REQUIRED"}}`)
			return true
		}
		return false
	}
	var body map[string]any
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		if err := json.Unmarshal(b, &body); err != nil {
			f.t.Errorf("bad body for %s %s: %s", r.Method, r.URL.Path, b)
		}
	}
	q := r.URL.Query()
	switch r.Method + " " + strings.TrimPrefix(r.URL.Path, "/v1") {
	case "GET /me":
		write(map[string]any{"id": "ada", "display_name": "Ada"}) // no product: development-mode apps since 2026
	case "GET /me/player":
		if f.device == "" {
			w.WriteHeader(204)
			return
		}
		write(map[string]any{"is_playing": f.playing, "progress_ms": f.progress, "shuffle_state": f.shuffle, "repeat_state": f.repeat,
			"device":  map[string]any{"id": f.device, "name": "Desk", "volume_percent": f.volume},
			"context": map[string]any{"uri": f.ctxURI, "type": "album"},
			"item":    trackJSON(f.itemURI, "Song", 200000)})
	case "GET /me/player/devices":
		io.WriteString(w, `{"devices":[{"id":"dev12345","name":"Desk","type":"Computer","is_active":true,"volume_percent":40},{"id":"phone6789","name":"Phone","type":"Smartphone"}]}`)
	case "GET /me/player/queue":
		write(map[string]any{"currently_playing": trackJSON(song, "Song", 200000), "queue": []any{trackJSON(song2, "Next one", 180000)}})
	case "GET /me/player/recently-played":
		after := q.Get("after")
		var items []any
		for _, it := range f.recent {
			if after != "" {
				at, _ := time.Parse(time.RFC3339, it["played_at"].(string))
				var ms int64
				fmt.Sscan(after, &ms)
				if at.UnixMilli() <= ms {
					continue
				}
			}
			items = append(items, it)
		}
		write(map[string]any{"items": items})
	case "GET /me/top/tracks":
		if q.Get("time_range") != "short_term" {
			f.t.Errorf("time_range %s", q.Get("time_range"))
		}
		write(map[string]any{"items": []any{trackJSON(song, "Song", 200000)}})
	case "GET /me/top/artists":
		write(map[string]any{"items": []any{map[string]any{"name": "Band", "uri": "spotify:artist:0OdUWJ0sBjDrqHygGUXeCF", "genres": []string{"indie"}}}})
	case "GET /me/tracks":
		write(map[string]any{"total": 1, "items": []any{map[string]any{"added_at": "2026-01-01T00:00:00Z", "track": trackJSON(song, "Song", 200000)}}})
	case "GET /me/albums":
		write(map[string]any{"total": 1, "items": []any{map[string]any{"album": map[string]any{"name": "LP", "uri": lp, "artists": []any{map[string]string{"name": "Band"}}, "total_tracks": 10}}}})
	case "GET /me/playlists":
		write(map[string]any{"total": 1, "items": []any{map[string]any{"name": "Mix", "uri": plist, "owner": map[string]string{"id": "ada", "display_name": "Ada"}, "items": map[string]int{"total": len(f.playlist)}}}})
	case "GET /playlists/37i9dQZF1DXcBWIGoYBM5M":
		write(map[string]any{"name": "Mix", "uri": plist, "owner": map[string]string{"id": "ada"}})
	case "GET /playlists/37i9dQZF1DXcBWIGoYBM5M/items":
		var items []any
		for _, u := range f.playlist {
			items = append(items, map[string]any{"item": trackJSON(u, "T", 1000)})
		}
		write(map[string]any{"total": len(items), "items": items})
	case "POST /playlists/37i9dQZF1DXcBWIGoYBM5M/items":
		var add []string
		for _, u := range body["uris"].([]any) {
			add = append(add, u.(string))
		}
		pos := len(f.playlist)
		if p, ok := body["position"].(float64); ok {
			pos = int(p)
		}
		f.playlist = append(f.playlist[:pos], append(add, f.playlist[pos:]...)...)
		write(map[string]string{"snapshot_id": "s2"})
	case "DELETE /playlists/37i9dQZF1DXcBWIGoYBM5M/items":
		drop := map[string]bool{}
		for _, it := range body["items"].([]any) {
			drop[it.(map[string]any)["uri"].(string)] = true
		}
		var keep []string
		for _, u := range f.playlist {
			if !drop[u] {
				keep = append(keep, u)
			}
		}
		f.playlist = keep
		write(map[string]string{"snapshot_id": "s3"})
	case "PUT /playlists/37i9dQZF1DXcBWIGoYBM5M/items":
		s, b, n := int(body["range_start"].(float64)), int(body["insert_before"].(float64)), int(body["range_length"].(float64))
		moved := append([]string{}, f.playlist[s:s+n]...)
		rest := append(append([]string{}, f.playlist[:s]...), f.playlist[s+n:]...)
		if b > s {
			b -= n
		}
		f.playlist = append(rest[:b], append(moved, rest[b:]...)...)
		write(map[string]string{"snapshot_id": "s4"})
	case "POST /me/playlists":
		write(map[string]any{"id": "37i9dQZF1DXcBWIGoYBM5M", "uri": plist, "name": body["name"]})
	case "GET /me/library/contains":
		var out []bool
		for _, u := range strings.Split(q.Get("uris"), ",") {
			out = append(out, f.library[u])
		}
		write(out)
	case "PUT /me/library", "DELETE /me/library":
		for _, u := range strings.Split(q.Get("uris"), ",") {
			f.library[u] = r.Method == "PUT"
		}
		w.WriteHeader(200)
	case "GET /search":
		if q.Get("limit") != "1" && q.Get("limit") != "5" {
			f.t.Errorf("search limit %s", q.Get("limit"))
		}
		write(map[string]any{"tracks": map[string]any{"items": []any{trackJSON(song3, "Found", 1000)}}, "playlists": map[string]any{"items": []any{nil}}})
	case "GET /tracks/4uLU6hMCjMI75M1A2tKUQC", "GET /tracks/0VjIjW4GlUZAMYd2vXMi3b":
		write(trackJSON(song, "Song", 200000))
	case "GET /albums/1DFixLWuPkv3KT3TnV35m3":
		write(map[string]any{"name": "LP", "uri": lp, "artists": []any{map[string]string{"name": "Band"}}, "tracks": map[string]any{"items": []any{trackJSON(song, "Song", 200000)}}})
	case "PUT /me/player/play":
		if premiumOnly() {
			return
		}
		if f.device == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"status":404,"message":"Player command failed: No active device found","reason":"NO_ACTIVE_DEVICE"}}`)
			return
		}
		f.playing, f.lastPlay = true, body
		if body != nil {
			if u, ok := body["uris"].([]any); ok {
				f.itemURI, f.ctxURI = u[0].(string), ""
			}
			if c, ok := body["context_uri"].(string); ok {
				f.ctxURI = c
			}
			if o, ok := body["offset"].(map[string]any); ok {
				f.itemURI = o["uri"].(string)
			}
			if p, ok := body["position_ms"].(float64); ok {
				f.progress = int(p)
			}
		}
		w.WriteHeader(204)
	case "PUT /me/player/pause":
		if premiumOnly() {
			return
		}
		f.playing = false
		w.WriteHeader(204)
	case "PUT /me/player/volume":
		if premiumOnly() {
			return
		}
		fmt.Sscan(q.Get("volume_percent"), &f.volume)
		w.WriteHeader(204)
	case "PUT /me/player/seek":
		fmt.Sscan(q.Get("position_ms"), &f.progress)
		w.WriteHeader(204)
	case "PUT /me/player/shuffle":
		f.shuffle = q.Get("state") == "true"
		w.WriteHeader(204)
	case "PUT /me/player/repeat":
		f.repeat = q.Get("state")
		w.WriteHeader(204)
	case "PUT /me/player":
		f.device = body["device_ids"].([]any)[0].(string)
		w.WriteHeader(204)
	case "POST /me/player/next", "POST /me/player/previous", "POST /me/player/queue":
		if premiumOnly() {
			return
		}
		w.WriteHeader(204)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
	}
}

// writerHost can store a rotated refresh token back in the vault.
type writerHost struct {
	*fakehost.Host
	mu    sync.Mutex
	saved map[string]string
}

func (h *writerHost) SetSecret(_ context.Context, ref, v string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saved[ref] = v
	h.Secrets[ref] = v
	return nil
}

type fakeLocal struct {
	mu   sync.Mutex
	log  []string
	fail error
}

func (l *fakeLocal) rec(s string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log = append(l.log, s)
	return l.fail
}
func (l *fakeLocal) Name() string { return "fake" }
func (l *fakeLocal) Status(context.Context) (*localStatus, error) {
	if l.fail != nil {
		return nil, l.fail
	}
	return &localStatus{State: "playing", Track: "Local song", Artists: "Band", URI: song2}, nil
}
func (l *fakeLocal) Command(_ context.Context, c string) error { return l.rec(c) }
func (l *fakeLocal) Open(_ context.Context, u string) error    { return l.rec("open " + u) }
func (l *fakeLocal) Seek(_ context.Context, ms int) error      { return l.rec(fmt.Sprint("seek ", ms)) }
func (l *fakeLocal) Volume(_ context.Context, p int) error     { return l.rec(fmt.Sprint("volume ", p)) }
func (l *fakeLocal) Shuffle(_ context.Context, on bool) error {
	return l.rec(fmt.Sprint("shuffle ", on))
}
func (l *fakeLocal) last() string { l.mu.Lock(); defer l.mu.Unlock(); return l.log[len(l.log)-1] }

type env struct {
	t     *testing.T
	f     *fakeAPI
	m     *Module
	host  *writerHost
	local *fakeLocal
}

func setup(t *testing.T, extra map[string]any) *env {
	f := newFake(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	e := &env{t: t, f: f, host: &writerHost{Host: fakehost.New(map[string]string{"secret://cs": "csecret", "secret://rt": "rt"}), saved: map[string]string{}}, local: &fakeLocal{}}
	e.m = New()
	e.m.Dir = t.TempDir()
	e.m.Local = func() localPlayer { return e.local }
	cfg := map[string]any{"clientId": "cid", "clientSecret": "secret://cs", "refreshToken": "secret://rt", "api": srv.URL + "/v1", "accounts": srv.URL + "/accounts", "history": false}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, _ := json.Marshal(cfg)
	if err := e.m.Configure(context.Background(), e.host, "s", raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.m.Close("s") })
	return e
}

func (e *env) try(action string, in any, dry bool) (sdk.Result, error) {
	raw, _ := json.Marshal(in)
	if in == nil {
		raw = nil
	}
	return e.m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: raw, DryRun: dry})
}

func (e *env) call(action string, in any) sdk.Result {
	e.t.Helper()
	r, err := e.try(action, in, false)
	if err != nil {
		e.t.Fatalf("%s: %v", action, err)
	}
	return r
}

func (e *env) out(action string, in any) map[string]any {
	e.t.Helper()
	var v map[string]any
	if err := json.Unmarshal(e.call(action, in).Output, &v); err != nil {
		e.t.Fatalf("%s: %v", action, err)
	}
	return v
}

func (e *env) undo(r sdk.Result) sdk.Result {
	e.t.Helper()
	if r.Undo == nil {
		e.t.Fatalf("no undo: %s", r.Output)
	}
	return e.call(r.Undo.Action, json.RawMessage(r.Undo.Input))
}

func TestReads(t *testing.T) {
	e := setup(t, nil)
	np := e.out("now_playing", nil)
	if np["track"] != "Song" || np["progressSeconds"] != float64(61) || np["context"] != lp || np["repeat"] != "off" {
		t.Fatalf("now playing %v", np)
	}
	e.f.recent = []map[string]any{{"played_at": "2026-11-03T10:00:00Z", "track": trackJSON(song, "Song", 200000), "context": map[string]string{"uri": lp}}}
	var recent []map[string]any
	json.Unmarshal(e.call("recently_played", map[string]any{"limit": 10}).Output, &recent)
	if len(recent) != 1 || recent[0]["playedAt"] == "" || recent[0]["context"] != lp {
		t.Fatalf("recent %v", recent)
	}
	var top []Track
	json.Unmarshal(e.call("top_tracks", map[string]any{"range": "short"}).Output, &top)
	if len(top) != 1 || top[0].Artists != "Band" || top[0].Duration != 200 {
		t.Fatalf("top %v", top)
	}
	if _, err := e.try("top_tracks", map[string]any{"range": "forever"}, false); err == nil {
		t.Fatal("bad range accepted")
	}
	var ta []Artist
	json.Unmarshal(e.call("top_artists", map[string]any{"range": "medium"}).Output, &ta)
	if len(ta) != 1 || ta[0].Genres[0] != "indie" {
		t.Fatalf("top artists %v", ta)
	}
	if v := e.out("saved_tracks", nil); v["total"] != float64(1) {
		t.Fatalf("saved %v", v)
	}
	if v := e.out("saved_albums", nil); v["total"] != float64(1) {
		t.Fatalf("albums %v", v)
	}
	pls := e.out("playlists", nil)
	if p := pls["playlists"].([]any)[0].(map[string]any); p["mine"] != true || p["tracks"] != float64(2) {
		t.Fatalf("playlists %v", pls)
	}
	pt := e.out("playlist_tracks", map[string]any{"playlist": "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M?si=abc"})
	if len(pt["tracks"].([]any)) != 2 {
		t.Fatalf("playlist tracks %v", pt)
	}
	s := e.out("search", map[string]any{"query": "found", "types": []string{"track", "playlist"}})
	if len(s["tracks"].([]any)) != 1 || len(s["playlists"].([]any)) != 0 {
		t.Fatalf("search %v", s)
	}
	if a := e.out("album", map[string]any{"uri": lp}); len(a["trackList"].([]any)) != 1 {
		t.Fatalf("album %v", a)
	}
	if tr := e.out("track", map[string]any{"uri": "https://open.spotify.com/intl-de/track/4uLU6hMCjMI75M1A2tKUQC"}); tr["name"] != "Song" {
		t.Fatalf("track %v", tr)
	}
	if q := e.out("queue", nil); len(q["next"].([]any)) != 1 {
		t.Fatalf("queue %v", q)
	}
	if _, err := e.try("queue", map[string]any{"uri": song}, false); err == nil {
		t.Fatal("queue with a uri must point to add_to_queue")
	}
	var devs []map[string]any
	json.Unmarshal(e.call("devices", nil).Output, &devs)
	if len(devs) != 2 {
		t.Fatalf("devices %v", devs)
	}
	if u := e.out("auth_url", nil); !strings.Contains(u["url"].(string), "user-read-recently-played") || !strings.Contains(u["url"].(string), "client_id=cid") {
		t.Fatalf("auth url %v", u)
	}
	if h := e.m.Health(context.Background(), "s"); h.Status != "ok" || !strings.Contains(h.Message, "Signed in as Ada") || !strings.Contains(h.Message, "Web API") {
		t.Fatalf("health %+v", h)
	}
}

func TestTokenRefresh(t *testing.T) {
	e := setup(t, nil)
	e.call("devices", nil)
	e.call("devices", nil)
	if e.f.refreshes != 1 {
		t.Fatalf("the access token should be cached: %d refreshes", e.f.refreshes)
	}
	// Spotify revokes the access token early: one 401, a refresh, a retry.
	e.f.revoke = true
	e.call("devices", nil)
	if e.f.refreshes != 2 {
		t.Fatalf("401 should refresh: %d", e.f.refreshes)
	}
	// A short-lived token is refreshed before it expires.
	e.f.expiresIn = 30
	c, _ := e.m.set.Get("s")
	c.dropToken()
	e.call("devices", nil)
	e.call("devices", nil)
	if e.f.refreshes != 4 {
		t.Fatalf("near-expiry token should be refreshed: %d", e.f.refreshes)
	}
	// A rotated refresh token is written back to the vault.
	e.f.expiresIn = 3600
	e.f.rotate = "rt2"
	c.dropToken()
	e.call("devices", nil)
	if e.host.saved["secret://rt"] != "rt2" {
		t.Fatalf("rotated token not saved: %v", e.host.saved)
	}
	c.dropToken()
	e.call("devices", nil) // uses rt2 now
	// Missing scopes show in Health.
	e.f.scope = "user-read-playback-state"
	c.dropToken()
	if h := e.m.Health(context.Background(), "s"); h.Status != "degraded" || !strings.Contains(h.Message, "user-top-read") {
		t.Fatalf("scope health %+v", h)
	}

}

func TestRevokedRefreshToken(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	m.Dir = t.TempDir()
	raw, _ := json.Marshal(map[string]any{"clientId": "cid", "clientSecret": "secret://cs", "refreshToken": "secret://cs", "api": srv.URL + "/v1", "accounts": srv.URL + "/accounts", "history": false, "playback": "web"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cs": "csecret"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	defer m.Close("b")
	if h := m.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "refresh token") {
		t.Fatalf("bad token health %+v", h)
	}
}

func TestPlaybackPremium(t *testing.T) {
	e := setup(t, nil)
	// play an album from a given track; undo goes back to what played before
	e.f.itemURI, e.f.ctxURI, e.f.progress = song2, plist, 5000
	plan := func(action string, in any) *sdk.Plan {
		r, err := e.try(action, in, true)
		if err != nil || r.Plan == nil {
			t.Fatalf("%s dry run: %v", action, err)
		}
		return r.Plan
	}
	if p := plan("play", map[string]any{"uri": lp}); !strings.Contains(p.Summary, "LP") || e.f.lastPlay != nil {
		t.Fatalf("play plan %+v", p)
	}
	r := e.call("play", map[string]any{"uri": "https://open.spotify.com/album/1DFixLWuPkv3KT3TnV35m3", "startAt": song, "device": "dev12345"})
	if e.f.lastPlay["context_uri"] != lp || e.f.lastPlay["offset"].(map[string]any)["uri"] != song {
		t.Fatalf("play body %v", e.f.lastPlay)
	}
	e.undo(r)
	if e.f.ctxURI != plist || e.f.itemURI != song2 || e.f.progress != 5000 {
		t.Fatalf("undo play: %s %s %d", e.f.ctxURI, e.f.itemURI, e.f.progress)
	}
	// play the top search result
	e.call("play", map[string]any{"query": "found"})
	if e.f.lastPlay["uris"].([]any)[0] != song3 {
		t.Fatalf("search play %v", e.f.lastPlay)
	}
	r = e.call("pause", nil)
	if e.f.playing {
		t.Fatal("pause")
	}
	e.undo(r)
	if !e.f.playing {
		t.Fatal("undo pause")
	}
	r = e.call("volume", map[string]any{"percent": 80})
	if e.f.volume != 80 {
		t.Fatal("volume")
	}
	e.undo(r)
	if e.f.volume != 40 {
		t.Fatalf("undo volume %d", e.f.volume)
	}
	e.f.progress = 10000
	r = e.call("seek", map[string]any{"seconds": 90})
	if e.f.progress != 90000 {
		t.Fatal("seek")
	}
	e.undo(r)
	if e.f.progress != 10000 {
		t.Fatal("undo seek")
	}
	r = e.call("shuffle", map[string]any{"on": true})
	e.undo(r)
	if e.f.shuffle {
		t.Fatal("undo shuffle")
	}
	r = e.call("repeat", map[string]any{"mode": "track"})
	if e.f.repeat != "track" {
		t.Fatal("repeat")
	}
	e.undo(r)
	if e.f.repeat != "off" {
		t.Fatal("undo repeat")
	}
	e.call("next", nil)
	e.call("add_to_queue", map[string]any{"uri": song})
	if _, err := e.try("add_to_queue", map[string]any{"uri": "https://evil.example/x"}, false); err == nil {
		t.Fatal("bad uri accepted")
	}
	r = e.call("transfer", map[string]any{"device": "phone6789"})
	if e.f.device != "phone6789" {
		t.Fatal("transfer")
	}
	e.undo(r)
	if e.f.device != "dev12345" {
		t.Fatal("undo transfer")
	}
	if _, err := e.try("pause", map[string]any{"device": "bad id!"}, false); err == nil {
		t.Fatal("bad device accepted")
	}
	e.f.device = ""
	if _, err := e.try("play", map[string]any{"uri": song}, false); err == nil || !strings.Contains(err.Error(), "no active Spotify device") {
		t.Fatalf("no device: %v", err)
	}
	if len(e.local.log) != 0 {
		t.Fatalf("Premium playback must not touch the local app: %v", e.local.log)
	}
}

func TestPremiumRequiredFallsBackToApp(t *testing.T) {
	e := setup(t, nil)
	e.f.premium = false
	r := e.call("play", map[string]any{"uri": lp})
	if e.local.last() != "open "+lp || !strings.Contains(string(r.Output), "Spotify app") {
		t.Fatalf("fallback: %v %s", e.local.log, r.Output)
	}
	// From now on the app is used directly; reads still use the Web API.
	e.call("pause", nil)
	e.call("next", nil)
	if strings.Join(e.local.log, ",") != "open "+lp+",pause,next" {
		t.Fatalf("local log %v", e.local.log)
	}
	if _, err := e.try("add_to_queue", map[string]any{"uri": song}, false); err == nil {
		t.Fatal("the app can't queue; should say so")
	}
	if np := e.out("now_playing", nil); np["track"] != "Song" {
		t.Fatalf("now playing on a free account still reads the Web API: %v", np)
	}
	if h := e.m.Health(context.Background(), "s"); !strings.Contains(h.Message, "Spotify app on this computer (fake)") {
		t.Fatalf("health should say the app is used: %+v", h)
	}

	// With playback "web" there is no fallback: the error explains.
	w := setup(t, map[string]any{"playback": "web"})
	w.f.premium = false
	if _, err := w.try("pause", nil, false); !errors.Is(err, errNoPremium) {
		t.Fatalf("PREMIUM_REQUIRED: %v", err)
	}
	if h := w.m.Health(context.Background(), "s"); h.Status != "degraded" || !strings.Contains(h.Message, "needs Premium") {
		t.Fatalf("health %+v", h)
	}
}

func TestLocalOnly(t *testing.T) {
	m := New()
	l := &fakeLocal{}
	m.Local = func() localPlayer { return l }
	if err := m.Configure(context.Background(), fakehost.New(nil), "app", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	defer m.Close("app")
	np, err := m.Invoke(context.Background(), sdk.Call{Instance: "app", Action: "now_playing"})
	if err != nil || !strings.Contains(string(np.Output), "Local song") {
		t.Fatalf("local now playing %s %v", np.Output, err)
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "app", Action: "play", Input: json.RawMessage(`{"uri":"` + song + `"}`)}); err != nil || l.last() != "open "+song {
		t.Fatalf("local play %v %v", err, l.log)
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "app", Action: "top_tracks"}); err == nil || !strings.Contains(err.Error(), "Web API") {
		t.Fatalf("reads need the Web API: %v", err)
	}
	if h := m.Health(context.Background(), "app"); h.Status != "ok" || !strings.Contains(h.Message, "Spotify app on this computer") {
		t.Fatalf("health %+v", h)
	}
	l.fail = errors.New("the Spotify app isn't running")
	if h := m.Health(context.Background(), "app"); h.Status != "degraded" || !strings.Contains(h.Message, "isn't running") {
		t.Fatalf("health %+v", h)
	}
}

func TestLibraryAndPlaylists(t *testing.T) {
	e := setup(t, nil)
	dry := func(action string, in any) *sdk.Plan {
		r, err := e.try(action, in, true)
		if err != nil || r.Plan == nil {
			t.Fatalf("%s dry run: %v", action, err)
		}
		return r.Plan
	}
	e.f.library[song] = true
	if p := dry("save", map[string]any{"uris": []string{song, lp}}); len(p.Changes) != 1 || p.Changes[0].Target != lp {
		t.Fatalf("save plan should skip what's saved: %+v", p)
	}
	r := e.call("save", map[string]any{"uris": []string{song, lp}})
	if !e.f.library[lp] {
		t.Fatal("save")
	}
	e.undo(r)
	if e.f.library[lp] || !e.f.library[song] {
		t.Fatalf("undo save must only remove what it added: %v", e.f.library)
	}

	// add a track that's already there: undo restores the playlist exactly
	before := strings.Join(e.f.playlist, ",")
	if p := dry("playlist_add", map[string]any{"playlist": plist, "uris": []string{song, song3}, "position": 0}); !strings.Contains(p.Summary, "1 already there") {
		t.Fatalf("add plan %+v", p)
	}
	r = e.call("playlist_add", map[string]any{"playlist": plist, "uris": []string{song, song3}, "position": 0})
	if strings.Join(e.f.playlist, ",") != strings.Join([]string{song, song3, song, song2}, ",") {
		t.Fatalf("add %v", e.f.playlist)
	}
	e.undo(r)
	if strings.Join(e.f.playlist, ",") != before {
		t.Fatalf("undo add: %v, want %s", e.f.playlist, before)
	}

	e.f.playlist = []string{song, song2, song3, song2}
	before = strings.Join(e.f.playlist, ",")
	if p := dry("playlist_remove", map[string]any{"playlist": plist, "uris": []string{song2}}); len(p.Changes) != 2 {
		t.Fatalf("remove plan %+v", p)
	}
	r = e.call("playlist_remove", map[string]any{"playlist": plist, "uris": []string{song2}})
	if strings.Join(e.f.playlist, ",") != song+","+song3 {
		t.Fatalf("remove %v", e.f.playlist)
	}
	e.undo(r)
	if strings.Join(e.f.playlist, ",") != before {
		t.Fatalf("undo remove: %v", e.f.playlist)
	}

	for _, mv := range [][2]int{{0, 3}, {3, 0}, {1, 4}} {
		e.f.playlist = []string{"a", "b", "c", "d"}
		r = e.call("playlist_reorder", map[string]any{"playlist": plist, "rangeStart": mv[0], "insertBefore": mv[1]})
		e.undo(r)
		if strings.Join(e.f.playlist, "") != "abcd" {
			t.Fatalf("reorder %v and back: %v", mv, e.f.playlist)
		}
	}

	if p := dry("create_playlist", map[string]any{"name": "Road trip", "uris": []string{song}}); !strings.Contains(p.Summary, "private playlist \"Road trip\" with 1") {
		t.Fatalf("create plan %+v", p)
	}
	e.f.playlist = nil
	r = e.call("create_playlist", map[string]any{"name": "Road trip", "uris": []string{song}})
	if len(e.f.playlist) != 1 || r.Undo.Action != "unsave" {
		t.Fatalf("create %v %+v", e.f.playlist, r.Undo)
	}
}

func TestHistoryAndStats(t *testing.T) {
	e := setup(t, map[string]any{"timezone": "UTC"})
	now := time.Now().UTC()
	at := func(daysAgo int, h, m int) string {
		d := now.AddDate(0, 0, -daysAgo)
		return time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, time.UTC).Format(time.RFC3339)
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	todayPlay := dayStart.Add(now.Sub(dayStart) / 2).Truncate(time.Second) // today, and already past
	other := func(uri, name, artist string, ms int) map[string]any {
		t := trackJSON(uri, name, ms)
		t["artists"] = []any{map[string]string{"name": artist}}
		return t
	}
	e.f.recent = []map[string]any{
		{"played_at": at(2, 10, 3), "track": trackJSON(song, "Song", 180000)},
		{"played_at": at(2, 10, 4), "track": trackJSON(song2, "Skipped", 240000)}, // only a minute after the last: skipped
		{"played_at": at(1, 9, 0), "track": other(song3, "Other", "Solo", 120000)},
	}
	c, _ := e.m.set.Get("s")
	if n, err := c.sync(context.Background()); err != nil || n != 3 {
		t.Fatalf("sync %d %v", n, err)
	}
	// later polls only add what's new, beyond Spotify's 50
	e.f.recent = append(e.f.recent, map[string]any{"played_at": todayPlay.Format(time.RFC3339), "track": trackJSON(song, "Song", 180000)})
	if n, _ := c.sync(context.Background()); n != 1 {
		t.Fatalf("second sync %d", n)
	}
	e.f.recent = e.f.recent[3:] // Spotify forgot the older ones
	h := e.out("history", map[string]any{"limit": 10})
	plays := h["plays"].([]any)
	if len(plays) != 4 || plays[0].(map[string]any)["name"] != "Song" || h["logged"] != float64(4) {
		t.Fatalf("history %v", h)
	}
	if h := e.out("history", map[string]any{"artist": "solo"}); len(h["plays"].([]any)) != 1 {
		t.Fatalf("history by artist %v", h)
	}
	st := e.out("listening_stats", map[string]any{"days": 7})
	if st["plays"] != float64(4) {
		t.Fatalf("stats %v", st)
	}
	// 3 + 1 (skipped after a minute) + 2 + 3 minutes
	if st["minutes"] != float64(9) {
		t.Fatalf("minutes %v", st["minutes"])
	}
	top := st["topArtists"].([]any)[0].(map[string]any)
	if top["name"] != "Band" || top["plays"] != float64(3) {
		t.Fatalf("top artist %v", st["topArtists"])
	}
	days := st["minutesPerDay"].([]any)
	if len(days) != 7 || days[6].(map[string]any)["minutes"] != float64(3) || days[4].(map[string]any)["minutes"] != float64(4) {
		t.Fatalf("per day %v", days)
	}
	// the log survives a restart
	b, err := os.ReadFile(filepath.Join(e.m.Dir, "s.history.jsonl"))
	if err != nil || strings.Count(string(b), "\n") != 4 {
		t.Fatalf("history file: %v %q", err, b)
	}
	if hh := e.m.Health(context.Background(), "s"); !strings.Contains(hh.Message, "history: 4 plays") {
		t.Fatalf("health %+v", hh)
	}
}

func TestRefs(t *testing.T) {
	for in, want := range map[string]string{
		song: song,
		"https://open.spotify.com/track/4uLU6hMCjMI75M1A2tKUQC?si=x":        song,
		"https://open.spotify.com/intl-de/album/1DFixLWuPkv3KT3TnV35m3":     lp,
		"spotify:user:ada:playlist:37i9dQZF1DXcBWIGoYBM5M":                  plist,
		"https://open.spotify.com/user/ada/playlist/37i9dQZF1DXcBWIGoYBM5M": plist,
	} {
		r, err := parseRef(in)
		if err != nil || r.URI() != want {
			t.Errorf("parseRef(%q) = %v %v", in, r, err)
		}
	}
	for _, bad := range []string{"spotify:track:short", "https://evil.example/track/4uLU6hMCjMI75M1A2tKUQC", `spotify:track:4uLU6hMCjMI75M1A2tKUQC" & do shell script "x`} {
		if _, err := parseRef(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := parseKind(lp, "track"); err == nil {
		t.Error("album accepted as a track")
	}
}

func TestAppleScript(t *testing.T) {
	var scripts []string
	a := &appleScript{run: func(_ context.Context, s string) (string, error) {
		scripts = append(scripts, s)
		if strings.Contains(s, "player state") {
			return "playing\nSong\nBand\nLP\nspotify:track:4uLU6hMCjMI75M1A2tKUQC\n61,5\n200000\n70\nfalse", nil
		}
		return "", nil
	}}
	ctx := context.Background()
	st, err := a.Status(ctx)
	if err != nil || st.State != "playing" || st.URI != song || st.Progress != 61 || st.Duration != 200 || *st.Volume != 70 {
		t.Fatalf("status %+v %v", st, err)
	}
	a.Open(ctx, lp)
	a.Command(ctx, "next")
	a.Volume(ctx, 30)
	all := strings.Join(scripts, "\n---\n")
	for _, w := range []string{`play track "` + lp + `"`, "next track", "set sound volume to 30", `if application "Spotify" is running`} {
		if !strings.Contains(all, w) {
			t.Fatalf("scripts lack %q:\n%s", w, all)
		}
	}
	if err := a.Open(ctx, `x" & do shell script "rm`); err == nil {
		t.Fatal("unsafe uri reached the script")
	}
	a.run = func(context.Context, string) (string, error) { return "not running", nil }
	if _, err := a.Status(ctx); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatalf("not running: %v", err)
	}
}

func TestCollectorRunsAndStops(t *testing.T) {
	e := setup(t, map[string]any{"history": true})
	e.f.mu.Lock()
	e.f.recent = []map[string]any{{"played_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "track": trackJSON(song, "Song", 180000)}}
	e.f.mu.Unlock()
	// Reconfiguring restarts the collector, which collects at once.
	raw, _ := json.Marshal(map[string]any{"clientId": "cid", "clientSecret": "secret://cs", "refreshToken": "secret://rt", "api": e.m.mustAPI(t), "accounts": strings.TrimSuffix(e.m.mustAPI(t), "/v1") + "/accounts"})
	if err := e.m.Configure(context.Background(), e.host, "s", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := e.m.set.Get("s")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := c.hist.stats(); n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the collector didn't store the play")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := e.m.Close("s"); err != nil {
		t.Fatal(err)
	}
}

func (m *Module) mustAPI(t *testing.T) string {
	c, err := m.set.Get("s")
	if err != nil {
		t.Fatal(err)
	}
	return c.cfg.API
}
