package qbittorrent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccc" // appears when a URL is added
	hashM = "dddddddddddddddddddddddddddddddddddddddd" // the test magnet
)

type fakeQbt struct {
	api      string // webapiVersion
	mu       sync.Mutex
	seen     []string
	sessions int
	state    map[string]string // hash -> state
	dl, up   int64
	expire   bool // next request finds the session expired
	host     string
}

func (f *fakeQbt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// CSRF: a Referer or Origin from another host is refused.
	for _, h := range []string{r.Header.Get("Referer"), r.Header.Get("Origin")} {
		if h != "" && !strings.HasPrefix(h, "http://"+f.host) {
			w.WriteHeader(401)
			return
		}
	}
	if r.Header.Get("Origin") == "" || r.Header.Get("Referer") == "" {
		w.WriteHeader(401)
		return
	}
	if r.URL.Path == "/qbt/api/v2/auth/login" {
		r.ParseForm()
		if r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "pw" {
			io.WriteString(w, "Fails.")
			return
		}
		f.sessions++
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: fmt.Sprintf("s%d", f.sessions), HttpOnly: true})
		io.WriteString(w, "Ok.")
		return
	}
	ck, err := r.Cookie("SID")
	if err != nil || ck.Value != fmt.Sprintf("s%d", f.sessions) || f.expire {
		f.expire = false
		w.WriteHeader(403)
		io.WriteString(w, "Forbidden")
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		r.ParseMultipartForm(1 << 20)
	} else {
		r.ParseForm()
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+r.Form.Encode())
	switch strings.TrimPrefix(r.URL.Path, "/qbt/api/v2") {
	case "/app/version":
		io.WriteString(w, "v5.0.2")
	case "/app/webapiVersion":
		io.WriteString(w, f.api)
	case "/transfer/info":
		fmt.Fprintf(w, `{"dl_info_speed":2097152,"dl_info_data":1073741824,"up_info_speed":1024,"up_info_data":0,"dl_rate_limit":%d,"up_rate_limit":%d,"dht_nodes":300,"connection_status":"connected"}`, f.dl, f.up)
	case "/transfer/speedLimitsMode":
		io.WriteString(w, "0")
	case "/transfer/downloadLimit":
		fmt.Fprint(w, f.dl)
	case "/transfer/uploadLimit":
		fmt.Fprint(w, f.up)
	case "/transfer/setDownloadLimit":
		fmt.Sscan(r.PostForm.Get("limit"), &f.dl)
	case "/transfer/setUploadLimit":
		fmt.Sscan(r.PostForm.Get("limit"), &f.up)
	case "/torrents/info":
		want := map[string]bool{}
		for _, h := range strings.Split(r.Form.Get("hashes"), "|") {
			want[h] = true
		}
		var hs []string
		for h := range f.state {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		var out []string
		for _, h := range hs {
			if r.Form.Get("hashes") != "" && !want[h] {
				continue
			}
			if fl := r.Form.Get("filter"); fl == "stopped" && !strings.HasPrefix(f.state[h], "stopped") {
				continue
			}
			out = append(out, fmt.Sprintf(`{"hash":%q,"name":"Linux ISO %s","size":4294967296,"progress":0.5,"dlspeed":1048576,"state":%q,"eta":600,"ratio":0.25,"category":"iso","tags":"a, b","added_on":1767225600,"magnet_uri":"magnet:?xt=urn:btih:%s&tr=https://t/announce?passkey=LEAKME"}`, h, h[:2], f.state[h], h))
		}
		io.WriteString(w, "["+strings.Join(out, ",")+"]")
	case "/torrents/stop", "/torrents/start", "/torrents/pause", "/torrents/resume":
		v5 := strings.HasPrefix(f.api, "2.11")
		if v5 != (strings.HasSuffix(r.URL.Path, "stop") || strings.HasSuffix(r.URL.Path, "start")) {
			w.WriteHeader(404)
			return
		}
		st := "stoppedDL"
		if strings.HasSuffix(r.URL.Path, "start") || strings.HasSuffix(r.URL.Path, "resume") {
			st = "downloading"
		}
		for _, h := range strings.Split(r.PostForm.Get("hashes"), "|") {
			f.state[h] = st
		}
	case "/torrents/add":
		for _, u := range strings.Split(r.MultipartForm.Value["urls"][0], "\n") {
			if strings.HasPrefix(u, "magnet:") {
				f.state[hashM] = "metaDL"
			} else {
				f.state[hashC] = "downloading"
			}
		}
		io.WriteString(w, "Ok.")
	case "/torrents/delete":
		for _, h := range strings.Split(r.PostForm.Get("hashes"), "|") {
			delete(f.state, h)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, api, secret string) (*Module, *fakeQbt) {
	f := &fakeQbt{api: api, state: map[string]string{hashA: "downloading", hashB: "stoppedUP"}, dl: 1024 * 1024}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.host = strings.TrimPrefix(srv.URL, "http://")
	m := New()
	m.AddWait = 2 * time.Second
	raw, _ := json.Marshal(Config{URL: srv.URL + "/qbt/", Username: "admin", Password: secret})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "nope"}), "q", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "q", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestQbittorrent(t *testing.T) {
	m, f := setup(t, "2.11.2", "secret://pw")
	if h := m.Health(context.Background(), "q"); h.Status != "ok" || h.Message != "qBittorrent v5.0.2" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "transfer", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"downKiBs":2048`) || !strings.Contains(string(r.Output), `"downLimitKiBs":1024`) || !strings.Contains(string(r.Output), `"upLimitKiBs":"unlimited"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "torrents", `{"filter":"paused"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"total":1`) || !strings.Contains(string(r.Output), hashB) || strings.Contains(string(r.Output), "LEAKME") || !strings.Contains(string(r.Output), `"tags":["a","b"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Pause: b is already stopped, so only a changes, and undo resumes only a.
	r, err = invoke(m, "pause", fmt.Sprintf(`{"hashes":[%q,%q]}`, hashA, strings.ToUpper(hashB)), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Pause 1 torrents" || f.state[hashA] != "downloading" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", fmt.Sprintf(`{"hashes":[%q,%q]}`, hashA, hashB), false)
	if err != nil || r.Undo == nil || r.Undo.Action != "resume" || string(r.Undo.Input) != fmt.Sprintf(`{"hashes":[%q]}`, hashA) || f.state[hashA] != "stoppedDL" {
		t.Fatalf("%+v %v %v", r, err, f.state)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.state[hashA] != "downloading" || f.state[hashB] != "stoppedUP" || r.Undo.Action != "pause" {
		t.Fatalf("%+v %v %v", r, err, f.state)
	}

	// The session expires: the module signs in again and carries on.
	f.expire = true
	if _, err := invoke(m, "transfer", `{}`, false); err != nil || f.sessions != 2 {
		t.Fatalf("%v sessions=%d", err, f.sessions)
	}

	// Add a magnet (hash known) and a URL (hash found after the fetch).
	magnet := "magnet:?xt=urn:btih:" + hashM + "&dn=Debian"
	in := fmt.Sprintf(`{"urls":[%q,"https://tracker.example/dl/1.torrent?passkey=LEAKME"],"category":"iso","tags":["x"]}`, magnet)
	r, err = invoke(m, "add", in, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || r.Plan.Changes[0].Target != "magnet Debian" || strings.Contains(fmt.Sprint(r.Plan), "LEAKME") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete" || string(r.Undo.Input) != fmt.Sprintf(`{"deleteFiles":false,"hashes":[%q,%q]}`, hashC, hashM) {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-2], "category=iso") || !strings.Contains(f.seen[len(f.seen)-2], "tags=x") {
		t.Fatal(f.seen)
	}
	// Adding the magnet again is a no-op: the undo must not delete it.
	if r, err := invoke(m, "add", fmt.Sprintf(`{"urls":[%q]}`, magnet), false); err != nil || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete", string(r.Undo.Input), false); err != nil || f.state[hashM] != "" || f.state[hashC] != "" || !strings.Contains(f.seen[len(f.seen)-1], "deleteFiles=false") {
		t.Fatalf("%v %v", err, f.state)
	}
	r, err = invoke(m, "delete", fmt.Sprintf(`{"hashes":[%q],"deleteFiles":true}`, hashA), true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Delete 1 torrents and their files" || f.state[hashA] == "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete", fmt.Sprintf(`{"hashes":[%q]}`, hashC), false); err == nil || !strings.Contains(err.Error(), "no torrent") {
		t.Fatal(err)
	}

	// Speed limits with undo.
	r, err = invoke(m, "set_speed_limits", `{"downloadKiB":0,"uploadKiB":512}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || f.up != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_speed_limits", `{"downloadKiB":0,"uploadKiB":512}`, false)
	if err != nil || f.dl != 0 || f.up != 512*1024 || r.Undo == nil || string(r.Undo.Input) != `{"downloadKiB":1024,"uploadKiB":0}` {
		t.Fatalf("%+v %v dl=%d up=%d", r, err, f.dl, f.up)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.dl != 1024*1024 || f.up != 0 {
		t.Fatalf("%v dl=%d up=%d", err, f.dl, f.up)
	}
}

func TestQbittorrent4UsesPause(t *testing.T) {
	m, f := setup(t, "2.9.3", "secret://pw")
	if _, err := invoke(m, "pause", fmt.Sprintf(`{"hashes":[%q]}`, hashA), false); err != nil || f.state[hashA] != "stoppedDL" {
		t.Fatalf("%v %v", err, f.state)
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "/torrents/pause") {
		t.Fatal(f.seen)
	}
}

func TestQbittorrentValidation(t *testing.T) {
	m, f := setup(t, "2.11.2", "secret://pw")
	many, _ := json.Marshal(map[string]any{"hashes": make([]string, 101)})
	for _, c := range []struct{ action, in string }{
		{"pause", `{"hashes":[]}`},
		{"pause", `{"hashes":["all"]}`},
		{"resume", `{"hashes":["../../app/shutdown"]}`},
		{"delete", string(many)},
		{"add", `{"urls":[]}`},
		{"add", `{"urls":["file:///etc/passwd"]}`},
		{"add", `{"urls":["magnet:?dn=nohash"]}`},
		{"add", `{"urls":["magnet:?xt=urn:btih:` + hashA + `"],"category":"a\nb"}`},
		{"add", `{"urls":["magnet:?xt=urn:btih:` + hashA + `"],"tags":["a,b"]}`},
		{"set_speed_limits", `{}`},
		{"set_speed_limits", `{"downloadKiB":-1}`},
		{"torrents", `{"filter":"evil&x=1"}`},
		{"torrents", `{"sort":"hash"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:8080", Username: "admin", Password: "plain"}, {URL: "nas:8080", Username: "a", Password: "secret://pw"}, {URL: "http://nas:8080", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "2.11.2", "secret://bad")
	if h := bad.Health(context.Background(), "q"); h.Status != "down" || h.Message != errLogin.Error() {
		t.Fatalf("%+v", h)
	}
}

func TestQbittorrentRefusesCrossHostRedirect(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		leaked = r.PostForm.Get("password") != "" || r.Header.Get("Cookie") != ""
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect) // 307 keeps the body
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "q", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "q"); h.Status != "down" || leaked {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

func TestMagnetHash(t *testing.T) {
	for in, want := range map[string]string{
		"magnet:?xt=urn:btih:" + strings.ToUpper(hashA):              hashA,
		"magnet:?xt=urn:btih:MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U":       "6162636465666768696a6b6c6d6e6f7071727374",
		"magnet:?xt=urn:btmh:1220" + hashB[:20]:                      "",
		"magnet:?xt=urn:btmh:1220" + hashB + strings.Repeat("e", 24): hashB,
	} {
		u, _ := url.Parse(in)
		if got := magnetHash(u); got != want {
			t.Fatalf("%s: %q, want %q", in, got, want)
		}
	}
}
