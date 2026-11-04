package tautulli

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeTautulli struct {
	mu         sync.Mutex
	cmds       []string
	terminated []string
	newAuth    bool // answer a bad key with 401 (newer Tautulli) instead of 200
}

func ok(w io.Writer, data string) {
	io.WriteString(w, `{"response":{"result":"success","message":null,"data":`+data+`}}`)
}

func (f *fakeTautulli) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.URL.Path != "/tautulli/api/v2" {
		w.WriteHeader(404)
		return
	}
	if q.Get("apikey") != "k3y" {
		if f.newAuth {
			w.WriteHeader(401)
		}
		io.WriteString(w, `{"response":{"result":"error","message":"Invalid apikey","data":{}}}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	q.Del("apikey")
	f.cmds = append(f.cmds, q.Encode())
	switch q.Get("cmd") {
	case "server_status":
		ok(w, `{"connected":true}`)
	case "get_activity":
		ok(w, `{"stream_count":"2","stream_count_direct_play":1,"stream_count_direct_stream":0,"stream_count_transcode":1,"total_bandwidth":25400,"lan_bandwidth":4400,"wan_bandwidth":21000,
			"sessions":[{"session_key":"42","session_id":"abc123def","user":"alice@example.com","friendly_name":"Alice","ip_address":"203.0.113.9","location":"wan","full_title":"The Show - Pilot","media_type":"episode",
			"state":"playing","progress_percent":"37","player":"Living Room TV","platform":"Roku","product":"Plex for Roku","quality_profile":"4 Mbps 720p","transcode_decision":"transcode","video_decision":"transcode","bandwidth":"21000","library_name":"TV"},
			{"session_key":"43","session_id":"","user":"bob","friendly_name":"","ip_address":"192.168.1.30","location":"lan","full_title":"A Movie","media_type":"movie","state":"paused","progress_percent":80,
			"player":"iPad","platform":"iOS","product":"Plex for iOS","transcode_decision":"direct play","bandwidth":4400}]}`)
	case "get_history":
		ok(w, `{"recordsFiltered":120,"recordsTotal":900,"data":[{"date":1730700000,"user":"alice@example.com","friendly_name":"Alice","full_title":"The Show - Pilot","media_type":"episode","platform":"Roku","player":"Living Room TV",
			"ip_address":"203.0.113.9","duration":2700,"paused_counter":60,"percent_complete":98,"watched_status":1,"transcode_decision":"transcode"},
			{"date":"1730600000","user":"bob","friendly_name":"Bob","full_title":"A Movie","media_type":"movie","platform":"iOS","player":"iPad","ip_address":"","duration":"1200","paused_counter":0,"percent_complete":"40","watched_status":0.5,"transcode_decision":"direct play"}]}`)
	case "get_home_stats":
		ok(w, `[{"stat_id":"top_movies","stat_title":"Most Watched Movies","rows":[{"title":"A Movie","total_plays":12,"total_duration":40000,"rating_key":1,"thumb":"/x"}]},
			{"stat_id":"top_users","stat_title":"Most Active Users","rows":[{"friendly_name":"Alice","user":"alice@example.com","total_plays":50,"total_duration":90000,"title":""}]},
			{"stat_id":"most_concurrent","stat_title":"Most Concurrent Streams","rows":[{"title":"Concurrent Streams","count":4,"started":"2026-10-01 20:00"}]}]`)
	case "get_server_info":
		ok(w, `{"pms_name":"Basement","pms_version":"1.41.2.9200","pms_platform":"Linux","pms_plexpass":1,"pms_is_remote":0,"pms_ssl":"1","pms_ip":"10.0.0.2","pms_url":"https://10-0-0-2.abc.plex.direct:32400"}`)
	case "get_tautulli_info":
		ok(w, `{"tautulli_version":"v2.15.0"}`)
	case "terminate_session":
		f.terminated = append(f.terminated, q.Get("session_id")+"|"+q.Get("session_key")+"|"+q.Get("message"))
		ok(w, `null`)
	default:
		io.WriteString(w, `{"response":{"result":"error","message":"Unknown command","data":{}}}`)
	}
}

func setup(t *testing.T, f *fakeTautulli, key string) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/tautulli/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "k3y", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTautulliRead(t *testing.T) {
	f := &fakeTautulli{}
	m := setup(t, f, "secret://k")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "Plex connected · 2 stream(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"activity", `{}`, `"bandwidthMbps":25.4,"directPlay":1,"directStream":0,"lanMbps":4.4`},
		{"activity", `{}`, `{"bandwidthMbps":21,"decision":"transcode","ip":"203.0.113.9","library":"TV","location":"wan","mediaType":"episode","platform":"Roku","player":"Living Room TV","product":"Plex for Roku","progressPercent":37,"quality":"4 Mbps 720p","sessionId":"abc123def","sessionKey":42,"state":"playing","title":"The Show - Pilot","user":"Alice","videoDecision":"transcode"}`},
		{"activity", `{}`, `"user":"bob"`},
		{"history", `{"days":7,"user":"alice@example.com","mediaType":"episode","limit":2}`, `{"at":"2024-11-04T06:00:00Z","decision":"transcode","durationSeconds":2700,"ip":"203.0.113.9","mediaType":"episode","pausedSeconds":60,"percentComplete":98,"platform":"Roku","player":"Living Room TV","title":"The Show - Pilot","user":"Alice","watched":"watched"}`},
		{"history", `{}`, `"watched":"partial"`},
		{"history", `{}`, `"total":120`},
		{"top", `{"days":7,"count":3,"by":"duration"}`, `{"id":"top_movies","rows":[{"durationSeconds":40000,"plays":12,"title":"A Movie"}],"title":"Most Watched Movies"}`},
		{"top", `{}`, `{"id":"top_users","rows":[{"durationSeconds":90000,"plays":50,"user":"Alice"}]`},
		{"top", `{}`, `{"at":"2026-10-01 20:00","streams":4,"title":"Concurrent Streams"}`},
		{"server", `{}`, `{"connected":true,"name":"Basement","platform":"Linux","plexPass":true,"remote":false,"ssl":true,"tautulliVersion":"v2.15.0","version":"1.41.2.9200"}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "k3y") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	found := false
	for _, c := range f.cmds {
		if c == "after=2026-10-28&cmd=get_history&length=2&media_type=episode&order_column=date&order_dir=desc&user=alice%40example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal(f.cmds)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "activity" || a.Name == "history" || a.Name == "top") != a.Sensitive {
			t.Fatal(a.Name, "sensitive")
		}
		if (a.Name == "terminate") != (a.Risk == sdk.RiskDestructive) {
			t.Fatal(a.Name, "risk")
		}
	}
}

func TestTautulliTerminate(t *testing.T) {
	f := &fakeTautulli{}
	m := setup(t, f, "secret://k")
	p, err := invoke(m, "terminate", `{"sessionKey":42,"message":"Bandwidth needed"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Stop The Show - Pilot on Living Room TV" || len(f.terminated) != 0 ||
		string(p.Plan.Changes[0].After) != `{"message":"Bandwidth needed","state":"stopped"}` || strings.Contains(p.Plan.Summary+string(p.Plan.Changes[0].Before), "Alice") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "terminate", `{"sessionKey":42,"message":"Bandwidth needed"}`, false)
	if err != nil || r.Undo != nil || f.terminated[0] != "abc123def||Bandwidth needed" || strings.Contains(string(r.Output), "Alice") || strings.Contains(string(r.Output), "203.0.113") {
		t.Fatalf("%s %v %v", r.Output, err, f.terminated)
	}
	if _, err := invoke(m, "terminate", `{"sessionKey":43}`, false); err != nil || f.terminated[1] != "|43|" {
		t.Fatal(err, f.terminated)
	}
	if _, err := invoke(m, "terminate", `{"sessionId":"abc123def"}`, false); err != nil || f.terminated[2] != "abc123def||" {
		t.Fatal(err, f.terminated)
	}
	if _, err := invoke(m, "terminate", `{"sessionKey":99}`, false); err == nil || !strings.Contains(err.Error(), "no such stream") || len(f.terminated) != 3 {
		t.Fatal(err)
	}
}

func TestTautulliRefusals(t *testing.T) {
	for _, newAuth := range []bool{false, true} {
		bad := setup(t, &fakeTautulli{newAuth: newAuth}, "secret://bad")
		if h := bad.Health(context.Background(), "t"); h.Status != "down" || h.Message != "Tautulli refused the API key" {
			t.Fatalf("%+v", h)
		}
	}
	f := &fakeTautulli{}
	m := setup(t, f, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"terminate", `{}`},
		{"terminate", `{"sessionKey":42,"sessionId":"abc123def"}`},
		{"terminate", `{"sessionKey":0}`},
		{"terminate", `{"sessionId":"abc&cmd=delete_all"}`},
		{"terminate", `{"sessionId":"../x"}`},
		{"terminate", `{"sessionKey":42,"message":"line\nbreak"}`},
		{"terminate", `{"sessionKey":42,"message":"` + strings.Repeat("x", 201) + `"}`},
		{"history", `{"limit":0}`},
		{"history", `{"limit":201}`},
		{"history", `{"days":0}`},
		{"history", `{"mediaType":"photo"}`},
		{"history", `{"user":"a\u0000b"}`},
		{"top", `{"count":26}`},
		{"top", `{"by":"rating"}`},
		{"delete_history", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.cmds) != 0 {
		t.Fatalf("refused input reached Tautulli: %v", f.cmds)
	}
	for _, c := range []Config{{URL: "http://t:8181", APIKey: "plainkey"}, {URL: "t:8181", APIKey: "secret://k"}, {URL: "http://u:p@t:8181", APIKey: "secret://k"}, {URL: "http://t:8181/?apikey=x", APIKey: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// A cross-host redirect is refused, and the key never shows in errors.
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/api/v2", http.StatusFound)
	}))
	defer srv.Close()
	hosts := fakehost.New(map[string]string{"secret://k": "k3y-SECRET"})
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	rm.Configure(context.Background(), hosts, "t", raw)
	if h := rm.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "another host") || strings.Contains(h.Message, "SECRET") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	dm := New()
	raw, _ = json.Marshal(Config{URL: "http://" + dead, APIKey: "secret://k"})
	dm.Configure(context.Background(), hosts, "t", raw)
	if _, err := invoke(dm, "activity", `{}`, false); err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "apikey") {
		t.Fatalf("key in error: %v", err)
	}
}
