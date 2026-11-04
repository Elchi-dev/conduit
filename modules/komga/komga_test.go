package komga

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

const bookJSON = `{"id":"B1","seriesId":"S1","seriesTitle":"Saga","libraryId":"L1","name":"Saga 001","created":"2026-11-01T10:00:00Z","media":{"pagesCount":40},"metadata":{"title":"Chapter One","number":"1"},"readProgress":{"page":10,"completed":false,"readDate":"2026-11-03T20:00:00Z"}}`

type fakeKomga struct {
	mu      sync.Mutex
	seen    []string
	scanned []string
	admin   bool
}

func (f *fakeKomga) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, basic := r.BasicAuth()
	if r.Header.Get("X-API-Key") != "kk_good" && !(basic && u == "me@example.com" && p == "pw") {
		w.WriteHeader(401)
		io.WriteString(w, `{"timestamp":"x","status":401,"error":"Unauthorized","path":"/api"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/api/v2/users/me":
		io.WriteString(w, `{"id":"U1","email":"me@example.com","roles":["ADMIN"]}`)
	case r.URL.Path == "/api/v1/libraries":
		io.WriteString(w, `[{"id":"L1","name":"Comics","root":"/data/comics","unavailable":false},{"id":"L2","name":"Manga","root":"/data/manga","unavailable":true}]`)
	case r.URL.Path == "/api/v1/libraries/L1":
		io.WriteString(w, `{"id":"L1","name":"Comics","root":"/data/comics"}`)
	case r.URL.Path == "/api/v1/libraries/L1/scan" && r.Method == "POST":
		if !f.admin {
			w.WriteHeader(403)
			return
		}
		f.scanned = append(f.scanned, q.Get("deep"))
		w.WriteHeader(202)
	case r.URL.Path == "/api/v1/series" && q.Get("size") != "":
		io.WriteString(w, `{"content":[{"id":"S1","libraryId":"L1","name":"saga","booksCount":10,"booksReadCount":2,"booksUnreadCount":7,"booksInProgressCount":1,"metadata":{"title":"Saga","status":"ONGOING"}}],"totalElements":1}`)
	case r.URL.Path == "/api/v1/books/latest", r.URL.Path == "/api/v1/books/ondeck",
		r.URL.Path == "/api/v1/books" && q.Get("read_status") == "IN_PROGRESS":
		io.WriteString(w, `{"content":[`+bookJSON+`],"totalElements":1}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":404,"error":"Not Found"}`)
	}
}

func setup(t *testing.T, c Config) (*Module, *fakeKomga) {
	f := &fakeKomga{admin: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	c.URL = srv.URL
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kk_good", "secret://pw": "pw", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKomga(t *testing.T) {
	for _, cfg := range []Config{{APIKey: "secret://k"}, {Username: "me@example.com", Password: "secret://pw"}} {
		m, f := setup(t, cfg)
		if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "signed in as me@example.com" {
			t.Fatalf("%+v", h)
		}
		for _, c := range []struct{ action, in, want string }{
			{"libraries", `{}`, `"unavailable":true`},
			{"series", `{"library":"L1","search":"saga"}`, `"title":"Saga","unread":7`},
			{"recent", `{"limit":5}`, `"title":"Chapter One"`},
			{"on_deck", `{}`, `"percent":25`},
			{"on_deck", `{}`, `"onDeck":[{`},
		} {
			r, err := invoke(m, c.action, c.in, false)
			if err != nil || !strings.Contains(string(r.Output), c.want) {
				t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
			}
		}
		r, err := invoke(m, "scan_library", `{"library":"L1","deep":true}`, true)
		if err != nil || r.Plan == nil || r.Plan.Summary != `Deep scan library "Comics"` || len(f.scanned) != 0 {
			t.Fatalf("%+v %v", r.Plan, err)
		}
		if _, err := invoke(m, "scan_library", `{"library":"L1"}`, false); err != nil || strings.Join(f.scanned, ",") != "false" {
			t.Fatal(err, f.scanned)
		}
		f.admin = false
		if _, err := invoke(m, "scan_library", `{"library":"L1"}`, false); err == nil || !strings.Contains(err.Error(), "admin") {
			t.Fatal(err)
		}
		if _, err := invoke(m, "scan_library", `{"library":"L9"}`, false); err == nil || !strings.Contains(err.Error(), "no library L9") {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(f.seen, "\n"), "library_id=L1") {
			t.Fatal(f.seen)
		}
	}
}

func TestKomgaValidation(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://k"})
	for _, c := range []struct{ action, in string }{
		{"series", `{"library":"../v2/users"}`},
		{"recent", `{"library":"L1?x=1"}`},
		{"series", `{"search":"` + strings.Repeat("x", 201) + `"}`},
		{"scan_library", `{}`},
		{"scan_library", `{"library":"L1/../L2"}`},
		{"scan_library", `{"library":1}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://komga.example.com"},
		{URL: "https://komga.example.com", APIKey: "kk_plain"},
		{URL: "https://komga.example.com", Username: "me@example.com", Password: "pw"},
		{URL: "https://komga.example.com", Username: "", Password: "secret://pw"},
		{URL: "https://komga.example.com", Username: "a:b", Password: "secret://pw"},
		{URL: "https://komga.example.com", APIKey: "secret://k", Username: "me@example.com", Password: "secret://pw"},
		{URL: "komga.example.com", APIKey: "secret://k"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, cfg := range []Config{{APIKey: "secret://bad"}, {Username: "me@example.com", Password: "secret://bad"}} {
		bad, _ := setup(t, cfg)
		if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
			t.Fatalf("%+v", h)
		}
	}
}

func TestKomgaRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "kk_good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
