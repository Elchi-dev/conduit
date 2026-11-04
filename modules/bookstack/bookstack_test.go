package bookstack

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

type fakeBookStack struct {
	mu    sync.Mutex
	seen  []string
	pages map[int]map[string]any
	next  int
}

func (f *fakeBookStack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token abc:xyz" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"The API token is invalid"}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var id int
	if strings.HasPrefix(r.URL.Path, "/wiki/api/pages/") {
		fmt.Sscanf(r.URL.Path, "/wiki/api/pages/%d", &id)
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/wiki/api/books":
		io.WriteString(w, `{"data":[{"id":1,"name":"Ops","slug":"ops","description":"Runbooks"}],"total":1}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/system":
		io.WriteString(w, `{"version":"v25.02","app_name":"Wiki"}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/shelves":
		io.WriteString(w, `{"data":[{"id":3,"name":"Infra","slug":"infra"}],"total":1}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/shelves/3":
		io.WriteString(w, `{"id":3,"name":"Infra","books":[{"id":1,"name":"Ops","slug":"ops"}]}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/books/1":
		io.WriteString(w, `{"id":1,"name":"Ops","description":"Runbooks","tags":[],"contents":[{"id":5,"name":"Backups","type":"chapter","url":"http://x/books/ops/chapter/backups","pages":[{"id":10,"name":"Restore","type":"page"}]},{"id":11,"name":"Intro","type":"page"}]}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/chapters/5":
		io.WriteString(w, `{"id":5,"name":"Backups","book_id":1,"pages":[{"id":10,"name":"Restore"}]}`)
	case r.Method == "GET" && r.URL.Path == "/wiki/api/search":
		io.WriteString(w, `{"data":[{"id":10,"name":"Restore","type":"page","url":"http://x/books/ops/page/restore","book":{"id":1,"name":"Ops"},"preview_html":{"content":"secret preview text"},"tags":[]}],"total":1}`)
	case r.Method == "POST" && r.URL.Path == "/wiki/api/pages":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.next++
		b["id"] = f.next
		f.pages[f.next] = b
		json.NewEncoder(w).Encode(b)
	case id > 0:
		pg, ok := f.pages[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":404,"message":"Page not found"}}`)
			return
		}
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/export/markdown"):
			io.WriteString(w, "# "+pg["name"].(string)+"\n\n"+fmt.Sprint(pg["markdown"]))
		case r.Method == "GET":
			json.NewEncoder(w).Encode(pg)
		case r.Method == "PUT":
			var b map[string]any
			json.Unmarshal(body, &b)
			for k, v := range b {
				pg[k] = v
			}
			pg["revision_count"] = 2
			json.NewEncoder(w).Encode(pg)
		case r.Method == "DELETE":
			delete(f.pages, id)
			w.WriteHeader(204)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"Not found"}}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeBookStack) {
	f := &fakeBookStack{pages: map[int]map[string]any{10: {"id": 10, "name": "Restore", "book_id": 1, "chapter_id": 5, "markdown": "Run restic restore.", "editor": "markdown", "revision_count": 1, "tags": []any{}}}, next: 20}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/wiki/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://b": "abc:xyz", "secret://bad": "abc:nope", "secret://malformed": "justone"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBookStack(t *testing.T) {
	m, f := setup(t, "secret://b")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "1 books · BookStack v25.02" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"shelves", `{}`, `"name":"Infra"`},
		{"books", `{}`, `"description":"Runbooks"`},
		{"books", `{"shelf":3}`, `"shelf":"Infra"`},
		{"book", `{"id":1}`, `"pages":[{"id":10,"name":"Restore","type":"page"}]`},
		{"chapter", `{"id":5}`, `"name":"Restore"`},
		{"search", `{"query":"restore"}`, `"book":"Ops"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "secret preview") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, err := invoke(m, "read_page", `{"id":10}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"markdown":"# Restore\n\nRun restic restore."`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "read_page") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}

	// Create, then undo deletes it.
	r, err = invoke(m, "create_page", `{"chapter":5,"name":"Rotate keys","markdown":"Steps"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Create page "Rotate keys" in chapter "Backups"` || len(f.pages) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_page", `{"chapter":5,"name":"Rotate keys","markdown":"Steps"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_page" || string(r.Undo.Input) != `{"id":21}` || f.pages[21]["chapter_id"] != float64(5) {
		t.Fatalf("%+v %v %v", r, err, f.pages)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.pages[21] != nil {
		t.Fatal(err, f.pages)
	}

	// A content change has no undo: the old content would sit in the audit
	// log. BookStack's revisions keep it.
	r, err = invoke(m, "update_page", `{"id":10,"markdown":"New text"}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"chars":19}` || f.pages[10]["markdown"] != "Run restic restore." {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "update_page", `{"id":10,"name":"Restore v2","markdown":"New text"}`, false)
	if err != nil || r.Undo != nil || f.pages[10]["markdown"] != "New text" || !strings.Contains(string(r.Output), "revisions") || strings.Contains(string(r.Output), "restic") {
		t.Fatalf("%+v %v", r, err)
	}
	// Name (and tags) alone: undo puts the old ones back.
	r, err = invoke(m, "update_page", `{"id":10,"name":"Restore v3"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "update_page" || string(r.Undo.Input) != `{"id":10,"name":"Restore v2"}` {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.pages[10]["name"] != "Restore v2" {
		t.Fatal(err, f.pages[10])
	}

	r, err = invoke(m, "delete_page", `{"id":10}`, true)
	if err != nil || r.Plan == nil || f.pages[10] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_page", `{"id":10}`, false); err != nil || f.pages[10] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "read_page", `{"id":10}`, false); err == nil || !strings.Contains(err.Error(), "no page 10") {
		t.Fatal(err)
	}
}

func TestBookStackValidation(t *testing.T) {
	m, f := setup(t, "secret://b")
	long := strings.Repeat("x", 256)
	for _, c := range []struct{ action, in string }{
		{"book", `{"id":0}`},
		{"chapter", `{"id":-2}`},
		{"read_page", `{"id":"1/../../users"}`},
		{"books", `{"shelf":-1}`},
		{"search", `{"query":"  "}`},
		{"create_page", `{"name":"x"}`},
		{"create_page", `{"book":1,"chapter":5,"name":"x"}`},
		{"create_page", `{"book":1}`},
		{"create_page", `{"book":1,"name":"  "}`},
		{"create_page", `{"book":1,"name":"` + long + `"}`},
		{"create_page", `{"book":1,"name":"x","markdown":"a","html":"<p>a</p>"}`},
		{"create_page", `{"book":1,"name":"x","tags":[{"name":""}]}`},
		{"update_page", `{"id":10}`},
		{"update_page", `{"name":"x"}`},
		{"delete_page", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://wiki.example.com", Token: "abc:xyz"}, {URL: "wiki.example.com", Token: "secret://b"}, {URL: "https://u:p@wiki.example.com", Token: "secret://b"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	mal, mf := setup(t, "secret://malformed")
	if h := mal.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "<token id>:<token secret>") || len(mf.seen) != 0 {
		t.Fatalf("%+v", h)
	}
}

func TestBookStackRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://b"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://b": "abc:xyz"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
