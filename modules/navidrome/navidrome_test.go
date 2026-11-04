package navidrome

import (
	"context"
	"crypto/md5" //nolint:gosec // the API's token
	"encoding/hex"
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

type fakeServer struct {
	mu       sync.Mutex
	scanning bool
	scans    []string
	seen     []string
	salts    map[string]bool
}

func ok(w io.Writer, body string) {
	if body != "" {
		body = "," + body
	}
	io.WriteString(w, `{"subsonic-response":{"status":"ok","version":"1.16.1","type":"navidrome","serverVersion":"0.53.3","openSubsonic":true`+body+`}}`)
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	sum := md5.Sum([]byte("pw" + q.Get("s"))) //nolint:gosec
	if q.Get("u") != "alice" || q.Get("t") != hex.EncodeToString(sum[:]) || q.Get("v") != "1.16.1" || q.Get("f") != "json" || q.Get("p") != "" || len(q.Get("s")) < 8 {
		io.WriteString(w, `{"subsonic-response":{"status":"failed","version":"1.16.1","error":{"code":40,"message":"Wrong username or password"}}}`)
		return
	}
	if f.salts[q.Get("s")] {
		w.WriteHeader(400) // a salt is never reused
		return
	}
	f.salts[q.Get("s")] = true
	method := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/music/rest/"), ".view")
	f.seen = append(f.seen, method)
	switch method {
	case "ping":
		ok(w, "")
	case "getNowPlaying":
		ok(w, `"nowPlaying":{"entry":[{"id":"s1","title":"Song","artist":"Band","album":"Record","year":2020,"duration":201,"username":"bob","playerName":"Feishin","minutesAgo":2}]}`)
	case "getAlbumList2":
		if q.Get("type") != "newest" || q.Get("size") != "5" {
			ok(w, `"albumList2":{}`)
			return
		}
		ok(w, `"albumList2":{"album":[{"id":"al1","name":"Record","artist":"Band","year":2020,"songCount":10,"duration":2400,"created":"2026-11-01T10:00:00Z","genre":"Rock"}]}`)
	case "search3":
		if q.Get("query") != "band & co" || q.Get("songCount") != "3" {
			ok(w, `"searchResult3":{}`)
			return
		}
		ok(w, `"searchResult3":{"artist":[{"id":"ar1","name":"Band","albumCount":2}],"album":[{"id":"al1","name":"Record","artist":"Band","songCount":10,"duration":2400}],"song":[{"id":"s1","title":"Song","artist":"Band","album":"Record","duration":201}]}`)
	case "getPlaylists":
		ok(w, `"playlists":{"playlist":[{"id":"pl1","name":"Mix","owner":"alice","public":true,"songCount":1,"duration":201,"changed":"2026-11-02T00:00:00Z"}]}`)
	case "getPlaylist":
		if q.Get("id") != "pl1" {
			io.WriteString(w, `{"subsonic-response":{"status":"failed","version":"1.16.1","error":{"code":70,"message":"playlist not found"}}}`)
			return
		}
		ok(w, `"playlist":{"id":"pl1","name":"Mix","owner":"alice","public":true,"songCount":1,"duration":201,"changed":"2026-11-02T00:00:00Z","entry":[{"id":"s1","title":"Song","artist":"Band","album":"Record","duration":201,"path":"/srv/music/secret.flac"}]}`)
	case "getScanStatus":
		if f.scanning {
			ok(w, `"scanStatus":{"scanning":true,"count":12}`)
			return
		}
		ok(w, `"scanStatus":{"scanning":false,"count":1234,"folderCount":50,"lastScan":"2026-11-03T22:00:00Z"}`)
	case "startScan":
		f.scans = append(f.scans, q.Get("fullScan"))
		f.scanning = true
		ok(w, `"scanStatus":{"scanning":true,"count":0}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeServer) {
	f := &fakeServer{salts: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/music/", Username: "alice", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNavidromeRead(t *testing.T) {
	m, _ := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "signed in as alice · Navidrome 0.53.3 (Subsonic API 1.16.1)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"now_playing", `{}`, `"minutesAgo":2,"player":"Feishin","seconds":201,"title":"Song","user":"bob","year":2020`},
		{"albums", `{"limit":5}`, `"albums":[{"added":"2026-11-01T10:00:00Z","artist":"Band","genre":"Rock","id":"al1","name":"Record","seconds":2400,"songs":10,"year":2020}],"type":"newest"`},
		{"search", `{"query":"band & co","limit":3}`, `"artists":[{"albums":2,"id":"ar1","name":"Band"}]`},
		{"search", `{"query":"band & co","limit":3}`, `"songs":[{"album":"Record","artist":"Band","id":"s1","seconds":201,"title":"Song"}]`},
		{"playlists", `{}`, `[{"changed":"2026-11-02T00:00:00Z","id":"pl1","name":"Mix","owner":"alice","public":true,"seconds":201,"songs":1}]`},
		{"playlist", `{"id":"pl1"}`, `"entries":[{"album":"Record","artist":"Band","id":"s1","seconds":201,"title":"Song"}]`},
		{"scan_status", `{}`, `{"count":1234,"folders":50,"lastScan":"2026-11-03T22:00:00Z","scanning":false}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "/srv/music") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if _, err := invoke(m, "playlist", `{"id":"nope"}`, false); err == nil || err.Error() != "there's no playlist nope" {
		t.Fatal(err)
	}
}

func TestNavidromeScan(t *testing.T) {
	m, f := setup(t, "secret://pw")
	p, err := invoke(m, "start_scan", `{"fullScan":true}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Rescan every file in the library" || len(f.scans) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "start_scan", `{"fullScan":true}`, false)
	if err != nil || string(r.Output) != `{"count":0,"scanning":true}` || len(f.scans) != 1 || f.scans[0] != "true" {
		t.Fatalf("%s %v %v", r.Output, err, f.scans)
	}
	if _, err := invoke(m, "start_scan", `{}`, false); err == nil || !strings.Contains(err.Error(), "already running") || len(f.scans) != 1 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "start_scan") != (a.Risk == sdk.RiskWrite) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestNavidromeRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "the server refused the username or password" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"playlist", `{"id":"../ping"}`},
		{"playlist", `{"id":"a&u=admin"}`},
		{"playlist", `{"id":""}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"` + strings.Repeat("a", 300) + `"}`},
		{"search", `{"query":"a","limit":500}`},
		{"albums", `{"type":"byGenre"}`},
		{"albums", `{"limit":101}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("refused input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://music.example.com", Username: "alice", Password: "plain"},
		{URL: "https://music.example.com", Password: "secret://pw"},
		{URL: "music.example.com", Username: "alice", Password: "secret://pw"},
		{URL: "https://u:p@music.example.com", Username: "alice", Password: "secret://pw"},
		{URL: "https://music.example.com/?x=1", Username: "alice", Password: "secret://pw"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}

	// A redirect to another host would carry the token in its query.
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path+"?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "alice", Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	h := rm.Health(context.Background(), "n")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "t=") || !strings.Contains(h.Message, "another host") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	// Network errors don't show the request URL (and its token).
	srv.Close()
	if h := rm.Health(context.Background(), "n"); h.Status != "down" || strings.Contains(h.Message, "t=") || strings.Contains(h.Message, "s=") {
		t.Fatalf("%+v", h)
	}
}
