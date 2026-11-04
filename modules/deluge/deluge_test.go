package deluge

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
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashM = "dddddddddddddddddddddddddddddddddddddddd" // the test magnet
	hashU = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" // from the test URL
)

type fakeDeluge struct {
	mu        sync.Mutex
	seen      []string
	sessions  int
	connected bool
	expire    bool
	state     map[string]string // hash -> state
	maxDown   float64
	logins    int
}

func (f *fakeDeluge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/json" {
		w.WriteHeader(404)
		return
	}
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
		ID     int               `json:"id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"result": v, "error": nil, "id": req.ID}) }
	fail := func(code int, msg string) {
		json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": map[string]any{"message": msg, "code": code}, "id": req.ID})
	}
	if req.Method == "auth.login" {
		var pw string
		json.Unmarshal(req.Params[0], &pw)
		f.logins++
		if pw != "deluge" {
			reply(false)
			return
		}
		f.sessions++
		http.SetCookie(w, &http.Cookie{Name: "_session_id", Value: "s" + string(rune('0'+f.sessions))})
		reply(true)
		return
	}
	ck, err := r.Cookie("_session_id")
	if err != nil || ck.Value != "s"+string(rune('0'+f.sessions)) || f.expire {
		f.expire = false
		fail(1, "Not authenticated")
		return
	}
	f.seen = append(f.seen, req.Method)
	hashes := func(i int) []string {
		var hs []string
		json.Unmarshal(req.Params[i], &hs)
		return hs
	}
	switch req.Method {
	case "web.connected":
		reply(f.connected)
	case "web.get_hosts":
		reply([][]any{{"c3a5e1d2f4b6", "127.0.0.1", 58846, "localclient"}})
	case "web.connect":
		f.connected = true
		reply([]string{"core.get_torrents_status"})
	case "daemon.get_version":
		reply("2.1.1")
	case "core.get_session_status":
		reply(map[string]any{"download_rate": 2048.0 * 1024, "upload_rate": 0, "dht_nodes": 300, "has_incoming_connections": true})
	case "core.get_config_values":
		reply(map[string]any{"max_download_speed": f.maxDown, "max_upload_speed": -1.0, "download_location": "/downloads"})
	case "core.set_config":
		var cfg map[string]float64
		json.Unmarshal(req.Params[0], &cfg)
		if v, ok := cfg["max_download_speed"]; ok {
			f.maxDown = v
		}
		reply(nil)
	case "core.get_free_space":
		reply(float64(100 << 30))
	case "core.get_torrents_status":
		var filter struct {
			ID []string `json:"id"`
		}
		json.Unmarshal(req.Params[0], &filter)
		want := map[string]bool{}
		for _, h := range filter.ID {
			want[h] = true
		}
		out := map[string]any{}
		for h, st := range f.state {
			if len(want) > 0 && !want[h] {
				continue
			}
			out[h] = map[string]any{"hash": h, "name": "linux-" + h[:4] + ".iso", "state": st, "progress": 55.55, "download_payload_rate": 4096.0,
				"ratio": 0.5, "total_size": 1 << 30, "eta": 120, "time_added": 1762000000.5, "label": "iso", "save_path": "/downloads",
				"message": "Error: https://tracker.example/announce?passkey=LEAKMELEAKMELEAKMELEAKME", "tracker": "https://tracker.example/LEAKME/announce"}
		}
		reply(out)
	case "core.pause_torrents", "core.resume_torrents":
		for _, h := range hashes(0) {
			f.state[h] = map[string]string{"core.pause_torrents": "Paused", "core.resume_torrents": "Downloading"}[req.Method]
		}
		reply(nil)
	case "core.remove_torrents":
		for _, h := range hashes(0) {
			delete(f.state, h)
		}
		reply([]any{})
	case "core.add_torrent_magnet":
		f.state[hashM] = "Downloading"
		reply(hashM)
	case "core.add_torrent_url":
		f.state[hashU] = "Downloading"
		reply(hashU)
	default:
		fail(2, "Unknown method\nTraceback (most recent call last): password=LEAKMELEAKME")
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeDeluge) {
	f := &fakeDeluge{state: map[string]string{hashA: "Downloading", hashB: "Paused"}, maxDown: -1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dl": "deluge", "secret://bad": "nope"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestDeluge(t *testing.T) {
	m, f := setup(t, "secret://dl")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "Deluge 2.1.1" {
		t.Fatalf("%+v", h)
	}
	if !f.connected {
		t.Fatal("didn't connect the Web UI to its only daemon")
	}
	f.expire = true // the next request finds the session expired
	for _, c := range []struct{ action, in, want string }{
		{"session", `{}`, `"downKiBs":2048`},
		{"session", `{}`, `"freeSpaceGB":100`},
		{"session", `{}`, `"upLimitKiBs":"unlimited"`},
		{"torrents", `{}`, `"progress":55.5`},
		{"torrents", `{"state":"paused"}`, `"total":1`},
		{"torrents", `{"label":"ISO","query":"bbbb"}`, hashB},
		{"torrents", `{"state":"error"}`, `"total":0`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if f.sessions != 2 {
		t.Fatalf("didn't sign in again: %d", f.sessions)
	}

	// Pause: preview, real, undo, nothing to change.
	r, err := invoke(m, "pause", `{"hashes":["`+hashA+`","`+hashB+`"]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || f.state[hashA] != "Downloading" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", `{"hashes":["`+hashA+`"]}`, false)
	if err != nil || f.state[hashA] != "Paused" || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state[hashA] != "Downloading" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "resume", `{"hashes":["`+hashA+`"]}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Add a magnet and a URL; the preview hides the URL's query.
	in := `{"urls":["magnet:?xt=urn:btih:` + hashM + `&dn=Debian","https://tracker.example/dl/1.torrent?passkey=LEAKME"]}`
	r, err = invoke(m, "add", in, true)
	if b, _ := json.Marshal(r.Plan); err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || strings.Contains(string(b), "LEAKME") {
		t.Fatalf("%s %v", b, err)
	}
	r, err = invoke(m, "add", in, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"deleteFiles":false,"hashes":["`+hashM+`","`+hashU+`"]}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "add", `{"urls":["magnet:?xt=urn:btih:`+hashM+`"]}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.state) != 2 {
		t.Fatal(err, f.state)
	}

	// Delete.
	if r, err := invoke(m, "delete", `{"hashes":["`+hashB+`"],"deleteFiles":true}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Delete 1 torrents and their files" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete", `{"hashes":["`+hashB+`"]}`, false); err != nil || len(f.state) != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete", `{"hashes":["`+hashB+`"]}`, false); err == nil || !strings.Contains(err.Error(), "no torrent") {
		t.Fatal(err)
	}

	// Speed limits.
	r, err = invoke(m, "set_speed_limits", `{"downloadKiB":800}`, false)
	if err != nil || f.maxDown != 800 || r.Undo == nil || string(r.Undo.Input) != `{"downloadKiB":0}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.maxDown != -1 {
		t.Fatal(err, f.maxDown)
	}
	if r, _ := invoke(m, "set_speed_limits", `{"downloadKiB":0}`, false); r.Undo != nil {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "pause" || a.Name == "delete") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestDelugeValidation(t *testing.T) {
	m, f := setup(t, "secret://dl")
	for _, c := range []struct{ action, in string }{
		{"pause", `{}`}, {"pause", `{"hashes":["../x"]}`}, {"delete", `{"hashes":["abc"]}`},
		{"add", `{"urls":["file:///etc/passwd"]}`}, {"add", `{"urls":["magnet:?dn=nohash"]}`}, {"add", `{}`},
		{"set_speed_limits", `{}`}, {"set_speed_limits", `{"uploadKiB":-5}`},
		{"torrents", `{"state":"bogus"}`}, {"torrents", `{"sort":"bogus"}`}, {"torrents", `{"label":"a\nb"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:8112", Password: "deluge"}, {URL: "nas:8112", Password: "secret://dl"},
		{URL: "http://u:p@nas:8112", Password: "secret://dl"}, {URL: "http://nas:8112/?a=1", Password: "secret://dl"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || h.Message != "Deluge refused the Web UI password" {
		t.Fatalf("%+v", h)
	}
	// Error text from Deluge loses its traceback and anything secret-looking.
	if _, err := m.set.Get("d"); err != nil {
		t.Fatal(err)
	}
	c, _ := m.set.Get("d")
	if err := c.call(context.Background(), "core.nope", nil, nil); err == nil || strings.Contains(err.Error(), "LEAKME") || strings.Contains(err.Error(), "Traceback") {
		t.Fatal(err)
	}
}

func TestDelugeRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://dl"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dl": "deluge"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "d"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
