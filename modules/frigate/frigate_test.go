package frigate

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

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeFrigate struct {
	mu       sync.Mutex
	detect   bool
	record   bool
	recordOK bool // whether record is enabled in the config (so it can be switched on)
	retained bool
	logins   int
	token    string
	auth     bool
	seen     []string
}

func (f *fakeFrigate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/nvr")
	if path == "/api/login" && r.Method == "POST" {
		var b struct{ User, Password string }
		json.NewDecoder(r.Body).Decode(&b)
		if b.User != "admin" || b.Password != "pw" {
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"Login failed"}`)
			return
		}
		f.logins++
		f.token = fmt.Sprintf("jwt%d", f.logins)
		http.SetCookie(w, &http.Cookie{Name: "frigate_token", Value: f.token, HttpOnly: true})
		io.WriteString(w, `{}`)
		return
	}
	if f.auth {
		if ck, _ := r.Cookie("frigate_token"); ck == nil || ck.Value != f.token {
			w.WriteHeader(401)
			return
		}
	}
	f.seen = append(f.seen, r.Method+" "+path)
	switch r.Method + " " + path {
	case "GET /ws":
		f.mu.Unlock()
		ws, err := websocket.Accept(w, r, nil)
		f.mu.Lock()
		if err != nil {
			return
		}
		f.mu.Unlock()
		_, msg, err := ws.Read(context.Background())
		f.mu.Lock()
		if err != nil {
			return
		}
		var m struct{ Topic, Payload string }
		json.Unmarshal(msg, &m)
		f.seen = append(f.seen, "WS "+m.Topic+" "+m.Payload)
		switch m.Topic {
		case "front_door/detect/set":
			f.detect = m.Payload == "ON"
		case "front_door/recordings/set":
			if f.recordOK || m.Payload == "OFF" {
				f.record = m.Payload == "ON"
			}
		}
		ws.Close(websocket.StatusNormalClosure, "")
	case "GET /api/config":
		fmt.Fprintf(w, `{"cameras":{"front_door":{"enabled":true,"detect":{"enabled":%t},"record":{"enabled":%t},"snapshots":{"enabled":true},"audio":{"enabled":false},
			"objects":{"track":["person","car"]},"zones":{"porch":{},"driveway":{}},"ffmpeg":{"inputs":[{"path":"rtsp://admin:LEAKME@10.0.0.5/stream"}]}},
			"garage":{"detect":{"enabled":false},"record":{"enabled":false},"ffmpeg":{"inputs":[{"path":"rtsp://u:LEAKME@10.0.0.6"}]}}},
			"mqtt":{"password":"LEAKME"}}`, f.detect, f.record)
	case "GET /api/stats":
		io.WriteString(w, `{"cameras":{"front_door":{"camera_fps":5.0,"process_fps":5.1,"skipped_fps":0,"detection_fps":1.234567,"detection_enabled":1},
			"garage":{"camera_fps":0,"process_fps":0,"skipped_fps":0,"detection_fps":0}},
			"detectors":{"coral":{"inference_speed":8.91234,"pid":10}},"detection_fps":1.2,
			"service":{"uptime":3600,"version":"0.14.1-f4f3cfa","latest_version":"0.14.1","storage":{"/media/frigate/recordings":{"total":1000,"used":250,"free":750,"mount_type":"ext4"}},"temperatures":{"coral":41.5}},
			"gpu_usages":{"intel-vaapi":{"gpu":"3.2%","mem":"-"}}}`)
	case "GET /api/events":
		q := r.URL.Query()
		if q.Get("include_thumbnails") != "0" || q.Get("cameras") != "front_door" || q.Get("labels") != "person" || q.Get("limit") != "5" || q.Get("has_snapshot") != "1" || q.Get("after") == "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"message":"bad query `+r.URL.RawQuery+`"}`)
			return
		}
		io.WriteString(w, `[{"id":"1762250000.1-abc","camera":"front_door","label":"person","sub_label":["Alice",0.9],"start_time":1762250000.1,"end_time":1762250012.6,"zones":["porch"],"has_clip":true,"has_snapshot":true,"retain_indefinitely":false,"data":{"top_score":0.87654,"score":0.8}},
			{"id":"1762250100.2-def","camera":"front_door","label":"person","sub_label":null,"start_time":1762250100.2,"end_time":null,"zones":[],"has_clip":false,"has_snapshot":true,"top_score":0.71,"thumbnail":"LEAKME"}]`)
	case "GET /api/events/1762250000.1-abc":
		fmt.Fprintf(w, `{"id":"1762250000.1-abc","camera":"front_door","label":"person","start_time":1762250000.1,"end_time":1762250012.6,"zones":["porch"],"has_clip":true,"has_snapshot":true,"retain_indefinitely":%t,"plus_id":null,
			"data":{"top_score":0.87654,"score":0.8,"box":[0.1,0.2,0.3,0.4],"region":[0,0,0.5,0.5],"attributes":[],"type":"object"},"thumbnail":"LEAKME"}`, f.retained)
	case "POST /api/events/1762250000.1-abc/retain":
		f.retained = true
		io.WriteString(w, `{"success":true}`)
	case "DELETE /api/events/1762250000.1-abc/retain":
		f.retained = false
		io.WriteString(w, `{"success":true}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, cfg Config, auth bool) (*Module, *fakeFrigate) {
	f := &fakeFrigate{detect: true, record: false, auth: auth}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL + "/nvr/"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "x"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := m.set.Get("f")
	c.settle = 300 * time.Millisecond
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFrigateRead(t *testing.T) {
	m, f := setup(t, Config{Username: "admin", Password: "secret://pw"}, true)
	if h := m.Health(context.Background(), "f"); h.Status != "degraded" || h.Message != "Frigate 0.14.1-f4f3cfa · 2 cameras · no frames from garage" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"overview", `{}`, `"detectors":[{"inferenceMs":8.912,"name":"coral"}]`},
		{"overview", `{}`, `"usedPercent":25`},
		{"cameras", `{}`, `"objects":["person","car"],"record":false,"snapshots":true,"zones":["driveway","porch"]`},
		{"stats", `{}`, `"detectionFps":1.235`},
		{"stats", `{}`, `"temperatures":{"coral":41.5}`},
		{"events", `{"camera":"front_door","label":"person","limit":5,"hasSnapshot":true,"hours":24}`, `"subLabel":"Alice","topScore":0.877`},
		{"events", `{"camera":"front_door","label":"person","limit":5,"hasSnapshot":true,"hours":24}`, `"inProgress":true`},
		{"event", `{"id":"1762250000.1-abc"}`, `"media":{"clip":"/api/events/1762250000.1-abc/clip.mp4","snapshot":"/api/events/1762250000.1-abc/snapshot.jpg"}`},
		{"event", `{"id":"1762250000.1-abc"}`, `"box":[0.1,0.2,0.3,0.4]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "rtsp") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "events", `{"camera":"front_door","label":"person","limit":5,"hasSnapshot":true,"hours":24}`, false)
	if i, j := strings.Index(string(r.Output), "def"), strings.Index(string(r.Output), "abc"); i < 0 || i > j {
		t.Fatalf("not newest first: %s", r.Output)
	}
	if f.logins != 1 {
		t.Fatalf("logged in %d times", f.logins)
	}
	// The session expires: the module logs in again once.
	f.token = "rotated"
	if _, err := invoke(m, "stats", `{}`, false); err != nil || f.logins != 2 {
		t.Fatalf("%v %d", err, f.logins)
	}
}

func TestFrigateSwitches(t *testing.T) {
	m, f := setup(t, Config{Username: "admin", Password: "secret://pw"}, true)
	p, err := invoke(m, "set_detection", `{"camera":"front_door","enabled":false}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Turn detection off for camera front_door (until Frigate restarts)" || !f.detect {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "set_detection", `{"camera":"front_door","enabled":false}`, false)
	if err != nil || f.detect || r.Undo == nil || r.Undo.Action != "set_detection" || string(r.Undo.Input) != `{"camera":"front_door","enabled":true}` {
		t.Fatalf("%+v %v %v", r, err, f.seen)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.detect || string(r.Undo.Input) != `{"camera":"front_door","enabled":false}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "set_detection", `{"camera":"front_door","enabled":true}`, false); err == nil || !strings.Contains(err.Error(), "already on") {
		t.Fatal(err)
	}
	// Recording that isn't enabled in the config can't be switched on.
	if _, err := invoke(m, "set_recording", `{"camera":"front_door","enabled":true}`, false); err == nil || !strings.Contains(err.Error(), "must be enabled") {
		t.Fatal(err)
	}
	f.recordOK = true
	if r, err = invoke(m, "set_recording", `{"camera":"front_door","enabled":true}`, false); err != nil || !f.record || r.Undo.Action != "set_recording" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "set_detection", `{"camera":"porch","enabled":true}`, false); err == nil || !strings.Contains(err.Error(), "no camera porch (cameras: front_door, garage)") {
		t.Fatal(err)
	}

	p, err = invoke(m, "retain_event", `{"id":"1762250000.1-abc"}`, true)
	if err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Keep the person on front_door at 2025-11-04T") || f.retained {
		t.Fatalf("%+v %v", p, err)
	}
	r, err = invoke(m, "retain_event", `{"id":"1762250000.1-abc"}`, false)
	if err != nil || !f.retained || r.Undo == nil || r.Undo.Action != "unretain_event" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.retained || r.Undo.Action != "retain_event" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFrigateRefusals(t *testing.T) {
	bad, _ := setup(t, Config{Username: "admin", Password: "secret://bad"}, true)
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") {
		t.Fatalf("%+v", h)
	}
	noauth, _ := setup(t, Config{}, true)
	if _, err := invoke(noauth, "stats", `{}`, false); err == nil || !strings.Contains(err.Error(), "asks for a login") {
		t.Fatal(err)
	}
	m, f := setup(t, Config{}, false)
	for _, c := range []struct{ action, in string }{
		{"event", `{"id":"../config"}`},
		{"event", `{"id":"a/b"}`},
		{"event", `{"id":""}`},
		{"retain_event", `{"id":"..%2f"}`},
		{"set_detection", `{"camera":"front_door/../x","enabled":true}`},
		{"set_detection", `{"camera":"front_door"}`},
		{"events", `{"camera":"a&b=c"}`},
		{"events", `{"limit":1000}`},
		{"events", `{"hours":-1}`},
		{"events", `{"label":"<x>"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://f", Username: "admin", Password: "plain"}, {URL: "http://f", Password: "secret://pw"}, {URL: "frigate:5000"}, {URL: "http://u:p@f"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked += r.Header.Get("Cookie")
		b, _ := io.ReadAll(r.Body)
		leaked += string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "f"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
