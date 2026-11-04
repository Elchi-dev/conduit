package linkding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/urlguard"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Tests never use the network: names resolve to a public test address.
func init() {
	urlguard.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "rebind.example.com" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
}

type mark struct {
	url      string
	tags     []string
	archived bool
}

type fakeLinkding struct {
	mu    sync.Mutex
	seen  []string
	marks map[int]*mark
	n     int
}

func (f *fakeLinkding) json(id int) string {
	m := f.marks[id]
	tags, _ := json.Marshal(m.tags)
	if m.tags == nil {
		tags = []byte("[]")
	}
	return fmt.Sprintf(`{"id":%d,"url":%q,"title":"","description":"","notes":"my private note","website_title":"Page %d","is_archived":%v,"unread":false,"shared":false,"tag_names":%s,"date_added":"2026-11-01T10:00:00Z"}`, id, m.url, id, m.archived, tags)
}

func (f *fakeLinkding) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	list := func(archived bool) {
		var ids []int
		for id, m := range f.marks {
			if m.archived == archived {
				ids = append(ids, id)
			}
		}
		sort.Ints(ids)
		var items []string
		for _, id := range ids {
			items = append(items, f.json(id))
		}
		fmt.Fprintf(w, `{"count":%d,"next":null,"previous":null,"results":[%s]}`, len(ids), strings.Join(items, ","))
	}
	switch {
	case path == "/bookmarks/" && r.Method == "GET":
		list(false)
	case path == "/bookmarks/archived/":
		list(true)
	case path == "/tags/":
		io.WriteString(w, `{"count":2,"next":null,"results":[{"id":1,"name":"go"},{"id":2,"name":"Reading"}]}`)
	case path == "/bookmarks/check/":
		for id, m := range f.marks {
			if m.url == r.URL.Query().Get("url") {
				fmt.Fprintf(w, `{"bookmark":%s,"metadata":{}}`, f.json(id))
				return
			}
		}
		io.WriteString(w, `{"bookmark":null,"metadata":{"title":"x"}}`)
	case path == "/bookmarks/" && r.Method == "POST":
		var b struct {
			URL    string   `json:"url"`
			Tags   []string `json:"tag_names"`
			Shared bool     `json:"shared"`
		}
		json.Unmarshal(body, &b)
		if b.Shared {
			w.WriteHeader(400)
			return
		}
		f.n++
		id := 100 + f.n
		f.marks[id] = &mark{url: b.URL, tags: b.Tags}
		w.WriteHeader(201)
		io.WriteString(w, f.json(id))
	case strings.HasPrefix(path, "/bookmarks/"):
		parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/bookmarks/"), "/"), "/")
		id, _ := strconv.Atoi(parts[0])
		m := f.marks[id]
		if m == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"Not found."}`)
			return
		}
		switch {
		case len(parts) == 1 && r.Method == "GET":
			io.WriteString(w, f.json(id))
		case len(parts) == 1 && r.Method == "DELETE":
			delete(f.marks, id)
			w.WriteHeader(204)
		case len(parts) == 2 && parts[1] == "archive" && r.Method == "POST":
			m.archived = true
			w.WriteHeader(204)
		case len(parts) == 2 && parts[1] == "unarchive" && r.Method == "POST":
			m.archived = false
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeLinkding) {
	f := &fakeLinkding{marks: map[int]*mark{1: {url: "https://go.dev/", tags: []string{"go"}}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLinkding(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "1 bookmarks" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"search", `{"query":"#go"}`, `"title":"Page 1"`},
		{"recent", `{}`, `"url":"https://go.dev/"`},
		{"recent", `{"archived":true}`, `"bookmarks":[]`},
		{"tags", `{}`, `"tags":["go","Reading"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "private note") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	if !strings.Contains(f.seen[1], "q=%23go") {
		t.Fatalf("search query: %v", f.seen)
	}

	// Saving: a preview, then a new bookmark that's never shared, undone by
	// deleting it.
	r, err := invoke(m, "add_bookmark", `{"url":"https://example.com/a","tags":["#reading","Reading"]}`, true)
	if err != nil || r.Plan == nil || len(f.marks) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "add_bookmark", `{"url":"https://example.com/a","title":"A","tags":["#reading","Reading"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_bookmark" || string(r.Undo.Input) != `{"bookmark":101}` {
		t.Fatalf("%+v %v", r, err)
	}
	if fmt.Sprint(f.marks[101].tags) != "[reading]" || !strings.Contains(f.seen[len(f.seen)-1], `"shared":false`) {
		t.Fatalf("%v %v", f.marks[101].tags, f.seen)
	}
	// A saved link is left alone: no POST (which would overwrite it), no undo.
	n := len(f.seen)
	if r, err := invoke(m, "add_bookmark", `{"url":"https://go.dev/","title":"changed"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already saved") {
		t.Fatalf("existing: %+v %v", r, err)
	}
	if strings.Contains(strings.Join(f.seen[n:], "\n"), "POST") {
		t.Fatalf("overwrote: %v", f.seen[n:])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.marks[101] != nil {
		t.Fatal(err)
	}

	// Archive and its undo.
	r, err = invoke(m, "archive_bookmark", `{"bookmark":1}`, true)
	if err != nil || r.Plan == nil || f.marks[1].archived {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "archive_bookmark", `{"bookmark":1}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "unarchive_bookmark" || !f.marks[1].archived {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "archive_bookmark", `{"bookmark":1}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.marks[1].archived {
		t.Fatal(err)
	}

	r, err = invoke(m, "delete_bookmark", `{"bookmark":1}`, true)
	if err != nil || r.Plan == nil || f.marks[1] == nil || strings.Contains(string(r.Plan.Changes[0].Before), "private") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_bookmark", `{"bookmark":1}`, false); err != nil || len(f.marks) != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "archive_bookmark", `{"bookmark":1}`, false); err == nil || !strings.Contains(err.Error(), "no bookmark") {
		t.Fatal(err)
	}
}

func TestLinkdingValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, a := range m.Manifest().Actions {
		if strings.Contains(string(a.Input), "shared") || strings.Contains(string(a.Input), `"notes"`) {
			t.Fatalf("%s offers sharing or notes", a.Name)
		}
		if a.Name == "delete_bookmark" && a.Risk != sdk.RiskDestructive {
			t.Fatal("delete must be destructive")
		}
	}
	for _, c := range []struct{ action, in string }{
		{"search", `{"query":" "}`},
		{"search", `{"query":"` + strings.Repeat("x", 1001) + `"}`},
		{"archive_bookmark", `{}`},
		{"archive_bookmark", `{"bookmark":"1/../../tags"}`},
		{"delete_bookmark", `{"bookmark":-1}`},
		{"add_bookmark", `{"url":"javascript:alert(1)"}`},
		{"add_bookmark", `{"url":"example.com"}`},
		{"add_bookmark", `{"url":"https://user:pw@example.com/"}`},
		{"add_bookmark", `{"url":"https://example.com/","tags":["two words"]}`},
		{"add_bookmark", `{"url":"https://example.com/","title":"` + strings.Repeat("x", 513) + `"}`},
		// linkding fetches what it saves: nothing on the local network.
		{"add_bookmark", `{"url":"http://127.0.0.1:8080/admin"}`},
		{"add_bookmark", `{"url":"http://192.168.1.1/"}`},
		{"add_bookmark", `{"url":"http://169.254.169.254/latest/meta-data/"}`},
		{"add_bookmark", `{"url":"http://[::1]/"}`},
		{"add_bookmark", `{"url":"http://2130706433/"}`},
		{"add_bookmark", `{"url":"http://localhost:3000/"}`},
		{"add_bookmark", `{"url":"http://nas/"}`},
		{"add_bookmark", `{"url":"http://printer.local/"}`},
		{"add_bookmark", `{"url":"http://127.0.0.1.nip.io/"}`},
		{"add_bookmark", `{"url":"http://rebind.example.com/"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://links.example.com", Token: "plain"}, {URL: "links.example.com", Token: "secret://k"}, {URL: "https://u:p@links.example.com", Token: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestLinkdingRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
