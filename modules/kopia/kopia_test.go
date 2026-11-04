package kopia

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

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeKopia checks basic auth everywhere and, on the API, the session
// cookie and CSRF token its web page hands out, as kopia server does.
type fakeKopia struct {
	mu       sync.Mutex
	seen     []string
	session  string
	pages    int
	uploaded []string
}

func (f *fakeKopia) token() string { return "csrf-" + f.session }

func (f *fakeKopia) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "kopia" || p != "kpass" {
		w.WriteHeader(401)
		io.WriteString(w, "not authenticated\n")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/" {
		f.pages++
		http.SetCookie(w, &http.Cookie{Name: "Kopia-Session-Cookie", Value: f.session})
		http.SetCookie(w, &http.Cookie{Name: "Kopia-Auth", Value: "jwt"})
		fmt.Fprintf(w, `<html><head><meta name="kopia-csrf-token" content="%s" /></head><body></body></html>`, f.token())
		return
	}
	ck, err := r.Cookie("Kopia-Session-Cookie")
	if err != nil || ck.Value != f.session || r.Header.Get("X-Kopia-Csrf-Token") != f.token() {
		w.WriteHeader(403)
		io.WriteString(w, `{"code":"ACCESS_DENIED","error":"invalid or missing CSRF token"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/repo/status":
		io.WriteString(w, `{"connected":true,"configFile":"/root/.config/kopia/LEAKME.config","formatVersion":3,"hash":"BLAKE2B-256-128","encryption":"AES256-GCM-HMAC-SHA256","splitter":"DYNAMIC-4M-BUZHASH","storage":"b2","apiServerURL":"https://u:LEAKME@x","description":"Home","username":"kopia","hostname":"nas"}`)
	case "GET /api/v1/sources":
		io.WriteString(w, `{"localUsername":"root","localHost":"nas","multiUser":true,"sources":[
			{"source":{"host":"nas","userName":"root","path":"/home"},"status":"IDLE","nextSnapshotTime":"2026-11-05T02:00:00Z","lastSnapshot":{"startTime":"2026-11-04T02:00:00Z","endTime":"2026-11-04T02:05:00Z","stats":{"totalSize":4096,"fileCount":12,"errorCount":0},"rootEntry":{"summ":{"size":4096,"files":12,"dirs":3,"errors":0}}}},
			{"source":{"host":"nas","userName":"root","path":"/etc"},"status":"FAILED","lastSnapshot":{"startTime":"2026-11-04T03:00:00Z","stats":{"totalSize":10,"fileCount":1,"errorCount":2}}}]}`)
	case "GET /api/v1/snapshots":
		if q.Get("userName") == "" || q.Get("host") == "" || q.Get("path") == "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":"MALFORMED_REQUEST","error":"missing source"}`)
			return
		}
		io.WriteString(w, `{"snapshots":[{"id":"k1","description":"","startTime":"2026-11-03T02:00:00Z","endTime":"2026-11-03T02:01:00Z","summary":{"size":100,"files":2,"dirs":1,"errors":0},"rootID":"kLEAKME","retention":["daily-2"]},
			{"id":"k2","startTime":"2026-11-04T02:00:00Z","endTime":"2026-11-04T02:01:00Z","summary":{"size":200,"files":3,"dirs":1,"errors":0},"retention":["latest-1","daily-1"],"pins":["keep"]}]}`)
	case "GET /api/v1/policies":
		io.WriteString(w, `{"policies":[{"id":"p1","target":{},"policy":{"retention":{"keepLatest":10,"keepDaily":7},"scheduling":{"intervalSeconds":86400},"actions":{"beforeSnapshotRoot":{"script":"curl -H 'Authorization: LEAKME'"}}}},
			{"id":"p2","target":{"userName":"root","host":"nas","path":"/home"},"policy":{"compression":{"compressorName":"zstd"}}}]}`)
	case "GET /api/v1/tasks":
		io.WriteString(w, `{"tasks":[{"id":"1","kind":"Snapshot","description":"Snapshot","status":"SUCCESS","startTime":"2026-11-04T02:00:00Z"},
			{"id":"2","kind":"Maintenance","description":"Quick maintenance","status":"SUCCESS","startTime":"2026-11-04T01:00:00Z","endTime":"2026-11-04T01:00:30Z"},
			{"id":"3","kind":"Maintenance","description":"Full maintenance","status":"FAILED","startTime":"2026-11-04T04:00:00Z","endTime":"2026-11-04T04:10:00Z","errorMessage":"unable to delete blob"}]}`)
	case "POST /api/v1/sources/upload":
		key := q.Get("userName") + "@" + q.Get("host") + ":" + q.Get("path")
		f.uploaded = append(f.uploaded, key)
		fmt.Fprintf(w, `{"sources":{%q:{"success":true}}}`, key)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"NOT_FOUND","error":"not found"}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeKopia) {
	f := &fakeKopia{session: "s1"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kpass", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in)})
}

func TestKopia(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "k"); h.Status != "degraded" || h.Message != "last snapshot failed or had errors: /etc" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"storage":"b2"`},
		{"sources", `{}`, `"status":"failed"`},
		{"sources", `{}`, `"dirs":3`},
		{"snapshots", `{}`, `"source":"root@nas:/etc"`},
		{"snapshots", `{"userName":"root","host":"nas","path":"/home","limit":1}`, `"id":"k2"`},
		{"policies", `{}`, `"target":"global"`},
		{"policies", `{}`, `"target":"root@nas:/home"`},
		{"policies", `{}`, `"keepDaily":7`},
		{"maintenance", `{}`, `"lastStatus":"failed"`},
		{"maintenance", `{}`, `"seconds":30`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "snapshots", `{"userName":"root","host":"nas","path":"/home","limit":1}`); strings.Contains(string(r.Output), `"k1"`) {
		t.Fatal(string(r.Output))
	}
	if r, _ := invoke(m, "maintenance", `{}`); strings.Contains(string(r.Output), "Snapshot") {
		t.Fatal(string(r.Output))
	}
	if f.pages != 1 {
		t.Fatalf("loaded the page %d times", f.pages)
	}

	if _, err := invoke(m, "start_snapshot", `{"userName":"root","host":"nas","path":"/home"}`); err != nil || len(f.uploaded) != 1 || f.uploaded[0] != "root@nas:/home" {
		t.Fatal(err, f.uploaded)
	}
	if _, err := invoke(m, "start_snapshot", `{"userName":"root","host":"nas","path":"/srv"}`); err == nil || !strings.Contains(err.Error(), "isn't one of") || len(f.uploaded) != 1 {
		t.Fatal(err)
	}

	// The server restarted: a new session, picked up once.
	f.mu.Lock()
	f.session = "s2"
	f.mu.Unlock()
	if _, err := invoke(m, "status", `{}`); err != nil || f.pages != 2 {
		t.Fatal(err, f.pages)
	}
	for _, a := range m.Manifest().Actions {
		if want := map[bool]sdk.Risk{true: sdk.RiskWrite, false: sdk.RiskRead}[a.Name == "start_snapshot"]; a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestKopiaValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"start_snapshot", `{}`}, // would snapshot every source
		{"start_snapshot", `{"userName":"root","host":"nas"}`},
		{"start_snapshot", `{"userName":"root&all=1","host":"nas","path":"/home"}`},
		{"start_snapshot", `{"userName":"root","host":"nas","path":"relative"}`},
		{"snapshots", `{"userName":"root","host":"nas","path":"/a\nb"}`},
		{"snapshots", `{"limit":0}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://k.example.com", Password: "plain"}, {URL: "k.example.com", Password: "secret://k"}, {URL: "https://k.example.com", Username: "a b", Password: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || h.Message != "Kopia refused the username or password" {
		t.Fatalf("%+v", h)
	}
}

func TestKopiaRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked += r.Header.Get("Authorization") + r.Header.Get("X-Kopia-Csrf-Token") + r.Header.Get("Cookie")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "Kopia-Session-Cookie", Value: "s"})
			io.WriteString(w, `<meta name="kopia-csrf-token" content="tok">`)
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kpass"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
