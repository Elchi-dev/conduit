package transmission

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

type fakeTr struct {
	mu        sync.Mutex
	seen      []string
	sid       string
	handshake int
	status    map[string]int // hash -> status
	down      int64
	downOn    bool
	lastSet   map[string]any
}

func (f *fakeTr) torrent(h string) map[string]any {
	return map[string]any{"id": len(f.status), "hashString": h, "name": "linux-" + h[:4] + ".iso", "status": f.status[h], "percentDone": 0.5,
		"rateDownload": 2000000, "rateUpload": 0, "uploadRatio": 1.234, "totalSize": 4 << 30, "eta": 600, "addedDate": 1762000000,
		"error": 2, "errorString": "Tracker gave an error: https://tracker.example/announce?passkey=LEAKMELEAKMELEAKMELEAKME", "downloadDir": "/downloads",
		"peersConnected": 7, "trackers": []map[string]string{{"announce": "https://tracker.example/LEAKME/announce"}}}
}

func (f *fakeTr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/transmission/rpc" {
		w.WriteHeader(404)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
		w.WriteHeader(401)
		io.WriteString(w, "<h1>401: Unauthorized</h1>")
		return
	}
	if r.Header.Get("X-Transmission-Session-Id") != f.sid {
		f.handshake++
		w.Header().Set("X-Transmission-Session-Id", f.sid)
		w.WriteHeader(409)
		return
	}
	var req struct {
		Method    string         `json:"method"`
		Arguments map[string]any `json:"arguments"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)
	f.seen = append(f.seen, req.Method)
	ok := func(args any) {
		json.NewEncoder(w).Encode(map[string]any{"result": "success", "arguments": args})
	}
	ids := func() []string {
		var out []string
		for _, v := range req.Arguments["ids"].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	switch req.Method {
	case "session-get":
		ok(map[string]any{"version": "4.0.6 (38c164933e)", "rpc-version": 17, "speed-limit-down": f.down, "speed-limit-down-enabled": f.downOn,
			"speed-limit-up": 100, "speed-limit-up-enabled": false, "alt-speed-enabled": true, "download-dir": "/downloads"})
	case "session-stats":
		ok(map[string]any{"activeTorrentCount": 1, "pausedTorrentCount": 1, "torrentCount": len(f.status), "downloadSpeed": 2000000})
	case "session-set":
		f.lastSet = req.Arguments
		if v, ok := req.Arguments["speed-limit-down"].(float64); ok {
			f.down = int64(v)
		}
		if v, ok := req.Arguments["speed-limit-down-enabled"].(bool); ok {
			f.downOn = v
		}
		ok(map[string]any{})
	case "torrent-get":
		list := []map[string]any{}
		want := map[string]bool{}
		if req.Arguments["ids"] != nil {
			for _, h := range ids() {
				want[h] = true
			}
		}
		for _, h := range []string{hashA, hashB, hashM, hashU} {
			if _, has := f.status[h]; has && (len(want) == 0 || want[h]) {
				list = append(list, f.torrent(h))
			}
		}
		ok(map[string]any{"torrents": list})
	case "torrent-stop", "torrent-start":
		for _, h := range ids() {
			f.status[h] = map[string]int{"torrent-stop": 0, "torrent-start": 4}[req.Method]
		}
		ok(map[string]any{})
	case "torrent-remove":
		for _, h := range ids() {
			delete(f.status, h)
		}
		ok(map[string]any{})
	case "torrent-add":
		name := req.Arguments["filename"].(string)
		h := hashU
		if strings.HasPrefix(name, "magnet:") {
			h = hashM
		}
		if _, has := f.status[h]; has {
			ok(map[string]any{"torrent-duplicate": map[string]any{"hashString": h}})
			return
		}
		f.status[h] = 4
		ok(map[string]any{"torrent-added": map[string]any{"id": 9, "hashString": h, "name": "new"}})
	default:
		json.NewEncoder(w).Encode(map[string]any{"result": "method name not recognized"})
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeTr) {
	f := &fakeTr{sid: "abc123XYZ", status: map[string]int{hashA: 4, hashB: 0}, down: 500, downOn: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tr": "pw", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTransmission(t *testing.T) {
	m, f := setup(t, "secret://tr")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "Transmission 4.0.6 · 2 torrents, 1 active" {
		t.Fatalf("%+v", h)
	}
	if f.handshake != 1 {
		t.Fatalf("session handshakes: %d", f.handshake)
	}
	// A new session id (the daemon restarted) is picked up again.
	f.sid = "newSession42"
	for _, c := range []struct{ action, in, want string }{
		{"session", `{}`, `"downLimitKBs":500`},
		{"session", `{}`, `"alternativeLimits":true`},
		{"torrents", `{}`, `"status":"downloading"`},
		{"torrents", `{"status":"stopped"}`, `"total":1`},
		{"torrents", `{"query":"LINUX-bbbb"}`, hashB},
		{"torrents", `{}`, `"error":"Tracker gave an error`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if f.handshake != 2 {
		t.Fatalf("session handshakes: %d", f.handshake)
	}

	// Pause: preview, real, undo, nothing to change.
	r, err := invoke(m, "pause", `{"hashes":["`+hashA+`","`+hashB+`"]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || f.status[hashA] != 4 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", `{"hashes":["`+strings.ToUpper(hashA)+`"]}`, false)
	if err != nil || f.status[hashA] != 0 || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status[hashA] != 4 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "resume", `{"hashes":["`+hashA+`"]}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Add: a magnet and a URL with a passkey; the preview hides the query.
	in := `{"urls":["magnet:?xt=urn:btih:` + hashM + `&dn=Debian","https://tracker.example/dl/1.torrent?passkey=LEAKME"]}`
	r, err = invoke(m, "add", in, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if b, _ := json.Marshal(r.Plan); strings.Contains(string(b), "LEAKME") {
		t.Fatal(string(b))
	}
	r, err = invoke(m, "add", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete" || !strings.Contains(string(r.Undo.Input), hashM) || !strings.Contains(string(r.Undo.Input), hashU) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "add", `{"urls":["magnet:?xt=urn:btih:`+hashM+`"]}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.status) != 2 {
		t.Fatal(err, f.status)
	}

	// Delete.
	if r, err := invoke(m, "delete", `{"hashes":["`+hashB+`"],"deleteFiles":true}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Delete 1 torrents and their files" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete", `{"hashes":["`+hashB+`"]}`, false); err != nil || len(f.status) != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete", `{"hashes":["`+hashB+`"]}`, false); err == nil || !strings.Contains(err.Error(), "no torrent") {
		t.Fatal(err)
	}

	// Speed limits: change, undo, nothing to change.
	r, err = invoke(m, "set_speed_limits", `{"downloadKBs":0}`, false)
	if err != nil || f.downOn || r.Undo == nil || string(r.Undo.Input) != `{"downloadKBs":500}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.downOn || f.down != 500 {
		t.Fatal(err)
	}
	if r, _ := invoke(m, "set_speed_limits", `{"downloadKBs":500}`, false); r.Undo != nil {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "pause" || a.Name == "delete") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestTransmissionValidation(t *testing.T) {
	m, f := setup(t, "secret://tr")
	for _, c := range []struct{ action, in string }{
		{"pause", `{}`}, {"pause", `{"hashes":["../x"]}`}, {"delete", `{"hashes":["abc"]}`},
		{"add", `{"urls":["file:///etc/passwd"]}`}, {"add", `{"urls":["magnet:?dn=nohash"]}`}, {"add", `{}`},
		// Transmission would read these as paths on its disk.
		{"add", `{"urls":["HTTP://tracker.example/1.torrent"]}`}, {"add", `{"urls":["http://tracker.example/a b.torrent"]}`},
		{"add", `{"urls":["MAGNET:?xt=urn:btih:` + strings.Repeat("a", 40) + `"]}`},
		{"set_speed_limits", `{}`}, {"set_speed_limits", `{"downloadKBs":-1}`},
		{"torrents", `{"status":"bogus"}`}, {"torrents", `{"sort":"bogus"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "http://nas:9091", Username: "admin", Password: "plain"},
		{URL: "nas:9091"},
		{URL: "http://u:p@nas:9091"},
		{URL: "http://nas:9091/?x=1"},
		{URL: "http://nas:9091#x"},
		{URL: "http://nas:9091", Username: "admin"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "t")
	if h.Status != "down" || h.Message != "Transmission refused the username or password" || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestTransmissionRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("X-Transmission-Session-Id")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://tr"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tr": "pw"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "pw") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
