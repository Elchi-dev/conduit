package wikijs

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

const key = "eyJhbGciOiJSUzI1NiJ9.wikijskey.signature"

type version struct {
	id   int
	page map[string]any
	at   string
}

type fakeWiki struct {
	mu      sync.Mutex
	seen    []string
	queries []string
	pages   map[int]map[string]any
	history []version // newest last
	clock   int
	// edit runs before an update, to simulate someone else saving.
	edit func()
}

func (f *fakeWiki) tick() string {
	f.clock++
	return fmt.Sprintf("2026-11-04T10:%02d:00.000Z", f.clock)
}

func clone(p map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range p {
		c[k] = v
	}
	return c
}

func (f *fakeWiki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	if r.URL.Path != "/wiki/graphql" || r.Method != http.MethodPost {
		w.WriteHeader(404)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.Unmarshal(body, &req)
	f.queries = append(f.queries, req.Query)
	v := req.Variables
	reply := func(d any) { json.NewEncoder(w).Encode(map[string]any{"data": d}) }
	fail := func(msg string) {
		json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"message": msg}}, "data": nil})
	}
	guest := r.Header.Get("Authorization") != "Bearer "+key
	q := req.Query
	num := func(k string) int { n, _ := v[k].(float64); return int(n) }
	switch {
	case strings.Contains(q, "profile"):
		if guest {
			fail("You must be logged in.")
			return
		}
		reply(map[string]any{"users": map[string]any{"profile": map[string]any{"id": 1}}})
	case guest:
		fail("Forbidden")
	case strings.Contains(q, "list("):
		out := []any{}
		for _, p := range f.pages {
			out = append(out, map[string]any{"id": p["id"], "path": p["path"], "locale": "en", "title": p["title"], "description": p["description"], "isPublished": p["isPublished"], "updatedAt": p["updatedAt"], "tags": []string{"ops"}})
		}
		reply(map[string]any{"pages": map[string]any{"list": out}})
	case strings.Contains(q, "search("):
		reply(map[string]any{"pages": map[string]any{"search": map[string]any{"results": []any{map[string]any{"id": "1", "title": "Backups", "description": "How", "path": "ops/backups", "locale": "en"}}, "suggestions": []any{}, "totalHits": 1}}})
	case strings.Contains(q, "singleByPath("):
		for _, p := range f.pages {
			if p["path"] == v["path"] && v["locale"] == "en" {
				reply(map[string]any{"pages": map[string]any{"singleByPath": p}})
				return
			}
		}
		fail("This page does not exist.")
	case strings.Contains(q, "single("):
		if p, ok := f.pages[num("id")]; ok {
			reply(map[string]any{"pages": map[string]any{"single": p}})
			return
		}
		fail("This page does not exist.")
	case strings.Contains(q, "checkConflicts("):
		if f.edit != nil {
			f.edit()
			f.edit = nil
		}
		reply(map[string]any{"pages": map[string]any{"checkConflicts": f.pages[num("id")]["updatedAt"] != v["at"]}})
	case strings.Contains(q, "history("):
		trail := []any{}
		for i := len(f.history) - 1; i >= 0; i-- {
			if f.history[i].page["id"] == float64(num("id")) || f.history[i].page["id"] == num("id") {
				trail = append(trail, map[string]any{"versionId": f.history[i].id, "versionDate": f.history[i].at})
			}
		}
		reply(map[string]any{"pages": map[string]any{"history": map[string]any{"trail": trail, "total": len(trail)}}})
	case strings.Contains(q, "version("):
		for _, h := range f.history {
			if h.id == num("versionId") {
				p := clone(h.page)
				p["pageId"], p["versionId"] = num("pageId"), h.id
				reply(map[string]any{"pages": map[string]any{"version": p}})
				return
			}
		}
		reply(map[string]any{"pages": map[string]any{"version": nil}})
	case strings.Contains(q, "create("):
		if strings.TrimSpace(v["content"].(string)) == "" {
			reply(map[string]any{"pages": map[string]any{"create": map[string]any{"responseResult": map[string]any{"succeeded": false, "message": "Page content cannot be empty."}}}})
			return
		}
		id := 100 + len(f.pages)
		p := map[string]any{"id": id, "path": v["path"], "locale": v["locale"], "title": v["title"], "description": v["description"], "content": v["content"], "isPublished": v["isPublished"], "isPrivate": false, "editor": "markdown", "tags": []any{}, "updatedAt": f.tick()}
		f.pages[id] = p
		reply(map[string]any{"pages": map[string]any{"create": map[string]any{"responseResult": map[string]any{"succeeded": true, "message": "ok"}, "page": p}}})
	case strings.Contains(q, "update("):
		p, ok := f.pages[num("id")]
		if !ok {
			reply(map[string]any{"pages": map[string]any{"update": map[string]any{"responseResult": map[string]any{"succeeded": false, "message": "Invalid Page Id"}}}})
			return
		}
		// Wiki.js keeps the old page as a version, dated with its updatedAt.
		f.history = append(f.history, version{id: 500 + len(f.history), page: clone(p), at: p["updatedAt"].(string)})
		for _, k := range []string{"content", "title", "description", "isPublished", "path", "locale", "editor"} {
			if x, ok := v[k]; ok && x != nil {
				p[k] = x
			}
		}
		p["updatedAt"] = f.tick()
		reply(map[string]any{"pages": map[string]any{"update": map[string]any{"responseResult": map[string]any{"succeeded": true, "message": "ok"}}}})
	default:
		w.WriteHeader(400)
	}
}

func setup(t *testing.T, tok string, public bool) (*Module, *fakeWiki) {
	f := &fakeWiki{pages: map[int]map[string]any{
		1: {"id": 1, "path": "ops/backups", "locale": "en", "title": "Backups", "description": "How", "content": "# Backups\nRun restic.\nKeep the key safe.\n", "isPublished": true, "isPrivate": false, "editor": "markdown", "contentType": "markdown", "tags": []any{map[string]any{"tag": "ops"}}, "updatedAt": "2026-11-04T09:00:00.000Z", "scriptCss": "", "scriptJs": ""},
		2: {"id": 2, "path": "drafts/plan", "locale": "en", "title": "Plan", "description": "", "content": "draft", "isPublished": false, "isPrivate": false, "editor": "markdown", "tags": []any{}, "updatedAt": "2026-11-04T09:30:00.000Z"},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/wiki/", Token: tok, Public: &public})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://w": key, "secret://bad": "nope.nope.nope"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestWikiJS(t *testing.T) {
	m, f := setup(t, "secret://w", false)
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "2 pages" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"pages", `{}`, `"path":"ops/backups"`},
		{"search", `{"query":"backup"}`, `"total":1`},
		{"read_page", `{"id":1}`, `"content":"# Backups\nRun restic.\nKeep the key safe.\n"`},
		{"read_page", `{"path":"/ops/backups/"}`, `"title":"Backups"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "read_page") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}

	// The preview shows a diff, never the old lines.
	r, err := invoke(m, "update_page", `{"id":1,"content":"# Backups\nRun restic check.\nKeep the key safe.\nDone.\n"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"added":2,"removed":1`) ||
		!strings.Contains(string(r.Plan.Changes[0].After), `"text":"Run restic check."`) || strings.Contains(string(r.Plan.Changes[0].After)+string(r.Plan.Changes[0].Before), "Run restic.") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if f.pages[1]["content"] != "# Backups\nRun restic.\nKeep the key safe.\n" {
		t.Fatal("dry run wrote")
	}
	// Same content: nothing to change, nothing sent.
	n := len(f.queries)
	r, err = invoke(m, "update_page", `{"id":1,"content":"# Backups\nRun restic.\nKeep the key safe.\n"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil || len(f.queries) != n+1 {
		t.Fatalf("%s %v %d", r.Output, err, len(f.queries)-n)
	}

	// Edit, then undo restores the old content by its version id.
	r, err = invoke(m, "update_page", `{"id":1,"title":"Backups v2","content":"new text"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "restore_version" || f.pages[1]["content"] != "new text" {
		t.Fatalf("%+v %v", r, err)
	}
	if strings.Contains(string(r.Undo.Input), "restic") || strings.Contains(string(r.Output), "restic") {
		t.Fatalf("old content in the undo or output: %s %s", r.Undo.Input, r.Output)
	}
	// Every write sent all fields back (Wiki.js's update replaces them).
	last := ""
	for _, s := range f.seen {
		if strings.Contains(s, "update(") {
			last = s
		}
	}
	for _, k := range []string{`"isPublished":true`, `"tags":["ops"]`, `"path":"ops/backups"`, `"editor":"markdown"`} {
		if !strings.Contains(last, k) {
			t.Fatalf("update lacks %s: %s", k, last)
		}
	}
	undo := *r.Undo
	r, err = invoke(m, undo.Action, string(undo.Input), true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, `Put back page "Backups v2"`) {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, undo.Action, string(undo.Input), false)
	if err != nil || f.pages[1]["content"] != "# Backups\nRun restic.\nKeep the key safe.\n" || f.pages[1]["title"] != "Backups" || r.Undo == nil {
		t.Fatalf("%s %v %v", r.Output, err, f.pages[1])
	}
	// The same undo again: the page has moved on, so it's refused.
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err == nil || !strings.Contains(err.Error(), "edited again") {
		t.Fatal(err)
	}

	// Create on a private wiki: published.
	r, err = invoke(m, "create_page", `{"path":"ops/keys","title":"Keys","content":"Rotate."}`, false)
	if err != nil || f.pages[102] == nil || f.pages[102]["isPublished"] != true || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestWikiJSPublic(t *testing.T) {
	m, f := setup(t, "secret://w", true)
	// A published page on a public wiki: update_page refuses, the
	// destructive update_public_page goes ahead.
	if _, err := invoke(m, "update_page", `{"id":1,"content":"x"}`, false); err == nil || !strings.Contains(err.Error(), "update_public_page") {
		t.Fatal(err)
	}
	// Publishing a draft is too.
	if _, err := invoke(m, "update_page", `{"id":2,"published":true}`, false); err == nil || !strings.Contains(err.Error(), "update_public_page") {
		t.Fatal(err)
	}
	// An unpublished draft can be edited, and a page unpublished, as write.
	if r, err := invoke(m, "update_page", `{"id":2,"content":"draft 2"}`, false); err != nil || f.pages[2]["content"] != "draft 2" {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "update_public_page", `{"id":1,"content":"public text"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "guests can read it") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "update_public_page", `{"id":1,"content":"public text"}`, false); err != nil || r.Undo == nil || f.pages[1]["content"] != "public text" {
		t.Fatalf("%+v %v", r, err)
	}
	// New pages start unpublished on a public wiki.
	r, err = invoke(m, "create_page", `{"path":"new/page","title":"New","content":"Hello"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "unpublished") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, p := range f.pages {
		if p["path"] == "new/page" && p["isPublished"] != false {
			t.Fatal("published on a public wiki")
		}
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskWrite
		switch a.Name {
		case "pages", "search", "read_page":
			want = sdk.RiskRead
		case "update_public_page":
			want = sdk.RiskDestructive
		}
		if a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestWikiJSEditConflict(t *testing.T) {
	m, f := setup(t, "secret://w", false)
	f.edit = func() { f.pages[1]["content"], f.pages[1]["updatedAt"] = "theirs", f.tick() }
	if _, err := invoke(m, "update_page", `{"id":1,"content":"mine"}`, false); err == nil || !strings.Contains(err.Error(), "in the meantime") {
		t.Fatal(err)
	}
	if f.pages[1]["content"] != "theirs" {
		t.Fatal("overwrote another edit")
	}
	// An undo after someone else's edit is refused.
	r, err := invoke(m, "update_page", `{"id":1,"content":"mine"}`, false)
	if err != nil || r.Undo == nil {
		t.Fatal(err)
	}
	f.pages[1]["content"], f.pages[1]["updatedAt"] = "later", f.tick()
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err == nil || f.pages[1]["content"] != "later" {
		t.Fatal(err)
	}
}

func TestWikiJSValidation(t *testing.T) {
	m, f := setup(t, "secret://w", false)
	big := strings.Repeat("x", 1<<20+1)
	for _, c := range []struct{ action, in string }{
		{"read_page", `{}`},
		{"read_page", `{"id":1,"path":"a"}`},
		{"read_page", `{"path":"../etc"}`},
		{"read_page", `{"path":"a b"}`},
		{"read_page", `{"path":"a//b"}`},
		{"read_page", `{"path":"ok","locale":"en\"}"}`},
		{"search", `{"query":" "}`},
		{"search", `{"query":"x","path":"a?b"}`},
		{"create_page", `{"path":"a","title":"t"}`},
		{"create_page", `{"path":"a","title":"t","content":"   "}`},
		{"create_page", `{"path":"a","title":"","content":"x"}`},
		{"create_page", `{"path":"a.b","title":"t","content":"x"}`},
		{"create_page", `{"path":"a","title":"t","content":"` + big + `"}`},
		{"update_page", `{"id":1}`},
		{"update_page", `{"id":1,"content":""}`},
		{"update_page", `{"id":-1,"content":"x"}`},
		{"restore_version", `{"id":1,"version":5}`},
		{"restore_version", `{"id":1,"at":"x"}`},
		{"pages", `{"locale":"../x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %.80s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	// Values travel as variables, never inside the query.
	invoke(m, "search", `{"query":"\") { evil } #"}`, false)
	for _, q := range f.queries {
		if strings.Contains(q, "evil") {
			t.Fatalf("input in the query: %s", q)
		}
	}
	for _, c := range []Config{
		{URL: "https://wiki.example.com", Token: key},
		{URL: "wiki.example.com", Token: "secret://w"},
		{URL: "https://u:p@wiki.example.com", Token: "secret://w"},
		{URL: "https://wiki.example.com?x=1", Token: "secret://w"},
		{URL: "https://wiki.example.com#f", Token: "secret://w"},
		{URL: "https://wiki.example.com", Token: "secret://w", Locale: "e n"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, bf := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "w"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "read_page", `{"id":1}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	if len(bf.seen) == 0 {
		t.Fatal("no request")
	}
}

func TestWikiJSNoSecretInOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A server that echoes the credential in its error.
		json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"message": "bad token " + r.Header.Get("Authorization")}}})
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://w"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://w": key}), "w", raw); err != nil {
		t.Fatal(err)
	}
	_, err := m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: "pages", Input: json.RawMessage(`{}`)})
	h := m.Health(context.Background(), "w")
	if err == nil || strings.Contains(err.Error(), "wikijskey") || strings.Contains(h.Message, "wikijskey") {
		t.Fatalf("%v %+v", err, h)
	}
}

func TestWikiJSRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://w"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://w": key}), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
