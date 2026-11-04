package miniflux

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

type fakeEntry struct {
	status  string
	starred bool
}

type fakeMiniflux struct {
	mu       sync.Mutex
	seen     []string
	entries  map[int64]*fakeEntry
	refreshd []string
}

func (f *fakeMiniflux) entry(id int64) string {
	e := f.entries[id]
	return fmt.Sprintf(`{"id":%d,"feed_id":1,"status":%q,"title":"Post %d","url":"https://blog.example.com/%d","published_at":"2026-11-01T10:00:00Z","starred":%v,"reading_time":3,"feed":{"id":1,"title":"Example blog"}}`, id, e.status, id, id, e.starred)
}

func (f *fakeMiniflux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != "mf_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error_message":"Access Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	q := r.URL.Query()
	list := func(keep func(*fakeEntry) bool) {
		var items []string
		for _, id := range []int64{1, 2, 3} {
			if e := f.entries[id]; e != nil && keep(e) {
				items = append(items, f.entry(id))
			}
		}
		fmt.Fprintf(w, `{"total":%d,"entries":[%s]}`, len(items), strings.Join(items, ","))
	}
	switch {
	case path == "/me":
		io.WriteString(w, `{"id":1,"username":"elchi"}`)
	case path == "/feeds" && r.Method == "GET":
		io.WriteString(w, `[{"id":1,"title":"Example blog","site_url":"https://blog.example.com","feed_url":"https://blog.example.com/feed","checked_at":"2026-11-04T07:00:00Z","parsing_error_count":0,"parsing_error_message":"","category":{"id":1,"title":"Tech"}},
			{"id":2,"title":"Dead site","site_url":"https://dead.example.com","feed_url":"https://dead.example.com/rss","checked_at":"2026-11-04T07:00:00Z","parsing_error_count":4,"parsing_error_message":"404 Not Found","category":{"id":1,"title":"Tech"}}]`)
	case path == "/feeds/counters":
		io.WriteString(w, `{"reads":{"1":10},"unreads":{"1":2}}`)
	case path == "/feeds/1":
		io.WriteString(w, `{"id":1,"title":"Example blog"}`)
	case path == "/feeds/1/entries" && q.Get("status") == "unread":
		list(func(e *fakeEntry) bool { return e.status == "unread" })
	case path == "/entries" && r.Method == "GET" && q.Get("status") == "unread" && q.Get("direction") == "desc":
		list(func(e *fakeEntry) bool { return e.status == "unread" })
	case path == "/entries" && r.Method == "GET" && q.Get("starred") == "true":
		list(func(e *fakeEntry) bool { return e.starred })
	case path == "/entries" && r.Method == "PUT":
		var b struct {
			IDs    []int64 `json:"entry_ids"`
			Status string  `json:"status"`
		}
		json.Unmarshal(body, &b)
		for _, id := range b.IDs {
			f.entries[id].status = b.Status
		}
		w.WriteHeader(204)
	case path == "/feeds/refresh" && r.Method == "PUT", path == "/feeds/1/refresh" && r.Method == "PUT":
		f.refreshd = append(f.refreshd, path)
		w.WriteHeader(204)
	case strings.HasPrefix(path, "/entries/"):
		rest := strings.TrimPrefix(path, "/entries/")
		ids, sub, _ := strings.Cut(rest, "/")
		var id int64
		fmt.Sscan(ids, &id)
		e := f.entries[id]
		if e == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error_message":"Not Found"}`)
			return
		}
		switch {
		case sub == "" && r.Method == "GET":
			io.WriteString(w, f.entry(id))
		case sub == "bookmark" && r.Method == "PUT":
			e.starred = !e.starred
			w.WriteHeader(204)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error_message":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeMiniflux) {
	f := &fakeMiniflux{entries: map[int64]*fakeEntry{1: {status: "unread"}, 2: {status: "read"}, 3: {status: "unread", starred: true}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "mf_good", "secret://bad": "nope"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMiniflux(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "signed in as elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"feeds", `{}`, `"unread":2`},
		{"feeds", `{"errorsOnly":true}`, `"error":"404 Not Found"`},
		{"unread", `{}`, `"title":"Post 3"`},
		{"unread", `{"feed":1,"limit":5}`, `"url":"https://blog.example.com/1"`},
		{"starred", `{}`, `"starred":true`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if r, _ := invoke(m, "feeds", `{"errorsOnly":true}`, false); strings.Contains(string(r.Output), "Example blog") {
		t.Fatalf("errorsOnly kept a healthy feed: %s", r.Output)
	}

	// mark_read changes only unread entries, and its undo only those.
	r, err := invoke(m, "mark_read", `{"entries":[1,2,1]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || !strings.Contains(r.Plan.Changes[0].Target, "Post 1") || f.entries[1].status != "unread" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "mark_read", `{"entries":[1,2]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "mark_unread" || string(r.Undo.Input) != `{"entries":[1]}` || f.entries[1].status != "read" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.entries[1].status != "unread" || f.entries[2].status != "read" || r.Undo == nil || r.Undo.Action != "mark_read" {
		t.Fatalf("%+v %v", r, err)
	}
	n := len(f.seen)
	if r, err := invoke(m, "mark_unread", `{"entries":[1,3]}`, false); err != nil || r.Undo != nil || strings.Contains(strings.Join(f.seen[n:], "\n"), "PUT") {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	// Star only toggles when needed.
	r, err = invoke(m, "star", `{"entry":1}`, false)
	if err != nil || !f.entries[1].starred || r.Undo == nil || r.Undo.Action != "unstar" || string(r.Undo.Input) != `{"entry":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "star", `{"entry":1}`, false); err != nil || r.Undo != nil || !f.entries[1].starred {
		t.Fatalf("star twice toggled: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.entries[1].starred {
		t.Fatal(err)
	}
	if r, err := invoke(m, "unstar", `{"entry":3}`, true); err != nil || r.Plan == nil || !f.entries[3].starred {
		t.Fatalf("%+v %v", r, err)
	}

	if _, err := invoke(m, "refresh_feeds", `{}`, false); err != nil {
		t.Fatal(err)
	}
	if r, err := invoke(m, "refresh_feeds", `{"feed":1}`, false); err != nil || !strings.Contains(string(r.Output), "Example blog") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if fmt.Sprint(f.refreshd) != "[/feeds/refresh /feeds/1/refresh]" {
		t.Fatal(f.refreshd)
	}
	if _, err := invoke(m, "star", `{"entry":99}`, false); err == nil || !strings.Contains(err.Error(), "no entry 99") {
		t.Fatal(err)
	}
}

func TestMinifluxValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprint(i + 1)
	}
	for _, c := range []struct{ action, in string }{
		{"unread", `{"feed":-1}`},
		{"unread", `{"feed":"1/../../me"}`},
		{"mark_read", `{}`},
		{"mark_read", `{"entries":[]}`},
		{"mark_read", `{"entries":[0]}`},
		{"mark_unread", `{"entries":[-4]}`},
		{"mark_read", `{"entries":[` + strings.Join(many, ",") + `]}`},
		{"mark_read", `{"entries":["1"]}`},
		{"star", `{}`},
		{"unstar", `{"entry":1.5}`},
		{"star", `{"entry":9007199254740993}`},
		{"refresh_feeds", `{"feed":0.5}`},
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
		{URL: "https://reader.example.com", Token: "plain-key"},
		{URL: "reader.example.com", Token: "secret://k"},
		{URL: "https://u:p@reader.example.com", Token: "secret://k"},
		{URL: "ftp://reader.example.com", Token: "secret://k"},
		{URL: "https://reader.example.com", Token: "secret://k", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "unread", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	if h := New().Health(context.Background(), "m"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestMinifluxRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Auth-Token") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "mf_good"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
