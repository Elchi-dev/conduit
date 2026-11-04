package audiobookshelf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeABS struct {
	mu     sync.Mutex
	admin  bool
	seen   []string
	writes []string
}

func (f *fakeABS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/status" {
		io.WriteString(w, `{"isInit":true,"serverVersion":"2.17.2"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		io.WriteString(w, "Unauthorized")
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.RequestURI())
	}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/me":
		io.WriteString(w, `{"id":"u1","username":"reader","type":"admin","token":"LEAKME-TOKEN","mediaProgress":[
			{"libraryItemId":"li1","episodeId":"","duration":36000,"progress":0.25,"currentTime":9000,"isFinished":false,"lastUpdate":1762250000000},
			{"libraryItemId":"li2","episodeId":"ep9","duration":3600,"progress":0.5,"currentTime":1800,"isFinished":false,"lastUpdate":1762240000000}]}`)
	case "GET /api/libraries":
		io.WriteString(w, `{"libraries":[{"id":"lib-books","name":"Audiobooks","mediaType":"book","folders":[{"id":"f1","fullPath":"/audiobooks"}]},{"id":"lib-pods","name":"Podcasts","mediaType":"podcast","folders":[]}]}`)
	case "GET /api/me/items-in-progress":
		if q.Get("limit") != "5" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"libraryItems":[{"id":"li1","libraryId":"lib-books","mediaType":"book","progressLastUpdate":1762250000000,"media":{"metadata":{"title":"Dune","authorName":"Frank Herbert","seriesName":"Dune #1"}}},
			{"id":"li2","libraryId":"lib-pods","mediaType":"podcast","media":{"metadata":{"title":"Some Show","author":"Host"}},"recentEpisode":{"id":"ep9","title":"Episode 9"}}]}`)
	case "GET /api/me/listening-stats":
		io.WriteString(w, `{"totalTime":7200.4,"today":600,"days":{"2026-11-04":600,"2026-11-02":1200,"2026-10-01":99},"dayOfWeek":{},
			"items":{"li1":{"id":"li1","timeListening":5000,"mediaMetadata":{"title":"Dune","authorName":"Frank Herbert"}},"li2":{"id":"li2","timeListening":2200,"mediaMetadata":{"title":"Some Show"}}}}`)
	case "GET /api/me/listening-sessions":
		if q.Get("itemsPerPage") != "2" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"total":1,"sessions":[{"id":"s1","libraryItemId":"li1","mediaType":"book","displayTitle":"Dune","displayAuthor":"Frank Herbert","duration":36000,"timeListening":600,"startTime":8400,"currentTime":9000,
			"startedAt":1762249400000,"updatedAt":1762250000000,"mediaPlayer":"html5","deviceInfo":{"clientName":"Abs Web","clientVersion":"2.17.2","osName":"Linux","browserName":"Firefox","ipAddress":"203.0.113.7"}}]}`)
	case "POST /api/libraries/lib-books/scan":
		if !f.admin {
			w.WriteHeader(403)
			io.WriteString(w, "Forbidden")
			return
		}
		io.WriteString(w, "OK")
	default:
		w.WriteHeader(404)
		io.WriteString(w, "Not found")
	}
}

func setup(t *testing.T, token string) (*Module, *fakeABS) {
	f := &fakeABS{admin: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok", "secret://bad": "x"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := m.set.Get("a")
	c.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAudiobookshelfRead(t *testing.T) {
	m, _ := setup(t, "secret://t")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "signed in as reader (admin) · Audiobookshelf 2.17.2" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"libraries", `{}`, `{"folders":["/audiobooks"],"id":"lib-books","mediaType":"book","name":"Audiobooks"}`},
		{"in_progress", `{"limit":5}`, `{"author":"Frank Herbert","durationSeconds":36000,"id":"li1","lastListened":"2025-11-04T09:53:20Z","leftSeconds":27000,"libraryId":"lib-books","mediaType":"book","percent":25,"positionSeconds":9000,"series":"Dune #1","title":"Dune"}`},
		{"in_progress", `{"limit":5}`, `"episode":"Episode 9","episodeId":"ep9"`},
		{"in_progress", `{"limit":5}`, `"percent":50`},
		{"listening_stats", `{"days":3}`, `"days":[{"date":"2026-11-02","seconds":1200},{"date":"2026-11-03","seconds":0},{"date":"2026-11-04","seconds":600}]`},
		{"listening_stats", `{}`, `"mostListened":[{"author":"Frank Herbert","id":"li1","seconds":5000,"title":"Dune"},{"id":"li2","seconds":2200,"title":"Some Show"}],"todaySeconds":600,"totalSeconds":7200`},
		{"sessions", `{"limit":2}`, `"client":"Abs Web 2.17.2","device":"Firefox Linux","durationSeconds":36000,"fromSecond":8400`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") || strings.Contains(string(r.Output), "203.0.113.7") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
}

func TestAudiobookshelfScan(t *testing.T) {
	m, f := setup(t, "secret://t")
	p, err := invoke(m, "scan_library", `{"library":"audiobooks","force":true}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Rescan every item in Audiobooks" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "scan_library", `{"library":"lib-books","force":true}`, false)
	if err != nil || string(r.Output) != `{"force":true,"library":"Audiobooks","scanStarted":true}` || len(f.writes) != 1 || f.writes[0] != "POST /api/libraries/lib-books/scan?force=1" {
		t.Fatalf("%s %v %v", r.Output, err, f.writes)
	}
	f.admin = false
	if _, err := invoke(m, "scan_library", `{"library":"Audiobooks"}`, false); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "scan_library", `{"library":"Comics"}`, false); err == nil || !strings.Contains(err.Error(), "libraries: Audiobooks, Podcasts") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "scan_library") != (a.Risk == sdk.RiskWrite) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestAudiobookshelfRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Audiobookshelf refused the API token" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"scan_library", `{"library":"../../api/users"}`},
		{"scan_library", `{"library":""}`},
		{"in_progress", `{"limit":1000}`},
		{"sessions", `{"limit":-1}`},
		{"listening_stats", `{"days":365}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	for _, s := range f.seen {
		if s != "GET /api/libraries" {
			t.Fatalf("refused input reached the server: %v", f.seen)
		}
	}
	for _, c := range []Config{{URL: "https://abs.example.com", Token: "plaintok"}, {URL: "abs:13378", Token: "secret://t"}, {URL: "http://u:p@abs", Token: "secret://t"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://t"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
