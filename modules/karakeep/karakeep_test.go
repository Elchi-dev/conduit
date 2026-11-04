package karakeep

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeKarakeep struct {
	mu    sync.Mutex
	seen  []string
	marks map[string][]string // id -> tags
	urls  map[string]string   // id -> url
	n     int
}

func (f *fakeKarakeep) mark(id string) string {
	tags := []string{}
	for _, t := range f.marks[id] {
		tags = append(tags, fmt.Sprintf(`{"id":"t-%s","name":%q,"attachedBy":"human"}`, t, t))
	}
	return fmt.Sprintf(`{"id":%q,"createdAt":"2026-11-01T10:00:00.000Z","title":null,"archived":false,"favourited":true,"note":"my private note","tags":[%s],"content":{"type":"link","url":%q,"title":"Page %s","description":"About it"}}`, id, strings.Join(tags, ","), f.urls[id], id)
}

func (f *fakeKarakeep) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ak_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"UNAUTHORIZED","message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	q := r.URL.Query()
	list := func() {
		var ids []string
		for id := range f.marks {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var items []string
		for _, id := range ids {
			items = append(items, f.mark(id))
		}
		fmt.Fprintf(w, `{"bookmarks":[%s],"nextCursor":null}`, strings.Join(items, ","))
	}
	switch {
	case path == "/users/me":
		io.WriteString(w, `{"id":"u1","name":"Elchi","email":"e@example.com"}`)
	case path == "/bookmarks/search" && q.Get("includeContent") == "false" && q.Get("q") != "":
		list()
	case path == "/bookmarks" && r.Method == "GET" && q.Get("archived") == "false":
		list()
	case path == "/lists/l1/bookmarks":
		list()
	case path == "/lists":
		io.WriteString(w, `{"lists":[{"id":"l1","name":"Read later","icon":"📚","parentId":null,"type":"manual"},{"id":"l2","name":"Go","icon":"🐹","parentId":"l1","type":"smart","query":"#go"}]}`)
	case path == "/bookmarks" && r.Method == "POST":
		var b struct{ URL string }
		json.Unmarshal(body, &b)
		for id, u := range f.urls {
			if u == b.URL {
				w.WriteHeader(200)
				io.WriteString(w, strings.Replace(f.mark(id), `{"id"`, `{"alreadyExists":true,"id"`, 1))
				return
			}
		}
		f.n++
		id := fmt.Sprintf("new%d", f.n)
		f.marks[id], f.urls[id] = nil, b.URL
		w.WriteHeader(201)
		io.WriteString(w, f.mark(id))
	case strings.HasPrefix(path, "/bookmarks/"):
		rest := strings.TrimPrefix(path, "/bookmarks/")
		id, sub, _ := strings.Cut(rest, "/")
		if _, ok := f.marks[id]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"NOT_FOUND","message":"Bookmark not found"}`)
			return
		}
		switch {
		case sub == "" && r.Method == "GET":
			io.WriteString(w, f.mark(id))
		case sub == "" && r.Method == "DELETE":
			delete(f.marks, id)
			delete(f.urls, id)
			w.WriteHeader(204)
		case sub == "tags":
			var b struct{ Tags []struct{ TagName string } }
			json.Unmarshal(body, &b)
			for _, t := range b.Tags {
				if r.Method == "POST" {
					f.marks[id] = append(f.marks[id], t.TagName)
				} else {
					var keep []string
					for _, x := range f.marks[id] {
						if x != t.TagName {
							keep = append(keep, x)
						}
					}
					f.marks[id] = keep
				}
			}
			io.WriteString(w, `{"attached":[]}`)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeKarakeep) {
	f := &fakeKarakeep{marks: map[string][]string{"bm1": {"go"}}, urls: map[string]string{"bm1": "https://go.dev/"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ak_good", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKarakeep(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "signed in as Elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"search", `{"query":"#go"}`, `"title":"Page bm1"`},
		{"recent", `{}`, `"url":"https://go.dev/"`},
		{"recent", `{"list":"l1"}`, `"tags":["go"]`},
		{"lists", `{}`, `"smart":true`},
		{"bookmark", `{"bookmark":"bm1"}`, `"note":"my private note"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || (c.action != "bookmark" && strings.Contains(string(r.Output), "private note")) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}

	// Saving a new link can be undone; saving one that's there can't.
	r, err := invoke(m, "add_bookmark", `{"url":"https://example.com/a"}`, true)
	if err != nil || r.Plan == nil || len(f.marks) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "add_bookmark", `{"url":"https://example.com/a","title":"A"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_bookmark" || string(r.Undo.Input) != `{"bookmark":"new1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "add_bookmark", `{"url":"https://go.dev/"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already saved") {
		t.Fatalf("existing: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.urls["new1"] != "" {
		t.Fatal(err)
	}

	// Tag adds only new tags, undo removes only those.
	r, err = invoke(m, "tag", `{"bookmark":"bm1","tags":["Go","#reading","reading"]}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Tag "Page bm1": reading` || len(f.marks["bm1"]) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "tag", `{"bookmark":"bm1","tags":["Go","#reading"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "untag" || string(r.Undo.Input) != `{"bookmark":"bm1","tags":["reading"]}` || fmt.Sprint(f.marks["bm1"]) != "[go reading]" {
		t.Fatalf("%+v %v %v", r, err, f.marks)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || r.Undo == nil || r.Undo.Action != "tag" || fmt.Sprint(f.marks["bm1"]) != "[go]" {
		t.Fatalf("%+v %v %v", r, err, f.marks)
	}
	n := len(f.seen)
	if r, err := invoke(m, "untag", `{"bookmark":"bm1","tags":["nope"]}`, false); err != nil || r.Undo != nil || strings.Contains(strings.Join(f.seen[n:], "\n"), "DELETE") {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	r, err = invoke(m, "delete_bookmark", `{"bookmark":"bm1"}`, true)
	if err != nil || r.Plan == nil || f.marks["bm1"] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_bookmark", `{"bookmark":"bm1"}`, false); err != nil || len(f.marks) != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "bookmark", `{"bookmark":"bm1"}`, false); err == nil || !strings.Contains(err.Error(), "no bookmark") {
		t.Fatal(err)
	}
}

func TestKarakeepValidation(t *testing.T) {
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"search", `{"query":" "}`},
		{"recent", `{"list":"../users/me"}`},
		{"bookmark", `{"bookmark":"bm1/../../users"}`},
		{"bookmark", `{}`},
		{"add_bookmark", `{"url":"javascript:alert(1)"}`},
		{"add_bookmark", `{"url":"example.com"}`},
		{"add_bookmark", `{"url":"https://user:pw@example.com/"}`},
		{"tag", `{"bookmark":"bm1","tags":[]}`},
		{"tag", `{"bookmark":"bm1","tags":["  "]}`},
		{"tag", `{"bookmark":"bm 1","tags":["x"]}`},
		{"untag", `{"bookmark":"bm1","tags":["` + strings.Repeat("x", 101) + `"]}`},
		{"delete_bookmark", `{"bookmark":""}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://bookmarks.example.com", Token: "ak_plain"}, {URL: "bookmarks.example.com", Token: "secret://k"}} {
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

func TestKarakeepRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "ak_good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
