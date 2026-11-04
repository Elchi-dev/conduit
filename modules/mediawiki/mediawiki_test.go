package mediawiki

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const botPass = "s3cr3tb0tpassw0rdvalue1234567890"

type rev struct {
	id, parent int
	text, ts   string
}

type fakeWiki struct {
	mu       sync.Mutex
	seen     []string
	public   bool
	revs     []rev // of page 7, oldest first
	logins   int
	lag      int // answer maxlag this many times
	waits    []time.Duration
	tokens   int
	expire   bool // drop the session once
	conflict bool // someone edits just before ours
}

func (f *fakeWiki) latest() rev { return f.revs[len(f.revs)-1] }

func (f *fakeWiki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RawQuery+" "+r.PostForm.Encode())
	if r.URL.Path != "/w/api.php" {
		w.WriteHeader(404)
		return
	}
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	fail := func(code, info string) { reply(map[string]any{"error": map[string]any{"code": code, "info": info}}) }
	if r.Form.Get("maxlag") != "5" || r.Form.Get("formatversion") != "2" {
		w.WriteHeader(400)
		return
	}
	if f.lag > 0 {
		f.lag--
		w.Header().Set("Retry-After", "2")
		w.Header().Set("MediaWiki-API-Error", "maxlag")
		fail("maxlag", "Waiting for db1: 7 seconds lagged.")
		return
	}
	c, _ := r.Cookie("session")
	in := c != nil && c.Value == "ok"
	if f.expire && in && r.Form.Get("action") != "login" {
		f.expire = false
		in = false
	}
	if a := r.Form.Get("assert"); a != "" && !in {
		fail("assert"+a+"failed", "You are no longer logged in")
		return
	}
	switch r.Form.Get("action") {
	case "login":
		if r.Method != http.MethodPost || r.PostForm.Get("lgtoken") != `LT+\` {
			reply(map[string]any{"login": map[string]any{"result": "WrongToken"}})
			return
		}
		if r.PostForm.Get("lgname") != "Elchi@conduit" || r.PostForm.Get("lgpassword") != botPass {
			reply(map[string]any{"login": map[string]any{"result": "Failed", "reason": "Incorrect username or password entered. " + r.PostForm.Get("lgpassword")}})
			return
		}
		f.logins++
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
		reply(map[string]any{"login": map[string]any{"result": "Success", "lgusername": "Elchi"}})
	case "query":
		switch {
		case r.Form.Get("meta") == "tokens" && r.Form.Get("type") == "login":
			reply(map[string]any{"query": map[string]any{"tokens": map[string]any{"logintoken": `LT+\`}}})
		case r.Form.Get("meta") == "tokens":
			f.tokens++
			t := `+\`
			if in {
				t = "CSRF" + strconv.Itoa(f.tokens) + `+\`
			}
			reply(map[string]any{"query": map[string]any{"tokens": map[string]any{"csrftoken": t}}})
		case r.Form.Get("siprop") == "usergroups":
			rights := []string{"createaccount"}
			if f.public {
				rights = append(rights, "read", "edit")
			}
			reply(map[string]any{"query": map[string]any{"usergroups": []any{map[string]any{"name": "*", "rights": rights}, map[string]any{"name": "user", "rights": []string{"read", "edit"}}}}})
		case strings.Contains(r.Form.Get("meta"), "userinfo"):
			reply(map[string]any{"query": map[string]any{"userinfo": map[string]any{"id": 3, "name": "Elchi"}, "general": map[string]any{"sitename": "Lab Wiki", "generator": "MediaWiki 1.42.3"}}})
		case r.Form.Get("list") == "search":
			reply(map[string]any{"query": map[string]any{"searchinfo": map[string]any{"totalhits": 1}, "search": []any{map[string]any{"ns": 12, "title": "Help:Backups", "pageid": 7, "size": 40, "wordcount": 6, "timestamp": "2026-11-01T10:00:00Z", "snippet": "secret snippet"}}}})
		case r.Form.Get("revids") != "":
			id, _ := strconv.Atoi(r.Form.Get("revids"))
			for _, x := range f.revs {
				if x.id == id {
					reply(map[string]any{"query": map[string]any{"pages": []any{map[string]any{"pageid": 7, "title": "Help:Backups", "revisions": []any{map[string]any{"revid": x.id, "parentid": x.parent, "slots": map[string]any{"main": map[string]any{"content": x.text}}}}}}}})
					return
				}
			}
			reply(map[string]any{"query": map[string]any{"badrevids": map[string]any{}}})
		case r.Form.Get("prop") == "revisions|info":
			if r.Form.Get("titles") != "Help:Backups" && r.Form.Get("pageids") != "7" {
				reply(map[string]any{"curtimestamp": "2026-11-04T12:00:00Z", "query": map[string]any{"pages": []any{map[string]any{"ns": 0, "title": r.Form.Get("titles"), "missing": true}}}})
				return
			}
			l := f.latest()
			rv := map[string]any{"revid": l.id, "parentid": l.parent, "timestamp": l.ts, "size": len(l.text)}
			if strings.Contains(r.Form.Get("rvprop"), "content") {
				rv["slots"] = map[string]any{"main": map[string]any{"contentmodel": "wikitext", "content": l.text}}
			}
			reply(map[string]any{"curtimestamp": "2026-11-04T12:00:00Z", "query": map[string]any{"pages": []any{map[string]any{"pageid": 7, "ns": 12, "title": "Help:Backups", "lastrevid": l.id, "revisions": []any{rv}}}}})
		default:
			w.WriteHeader(400)
		}
	case "edit":
		p := r.PostForm
		if r.Method != http.MethodPost || p.Get("token") != "CSRF"+strconv.Itoa(f.tokens)+`+\` || !strings.HasSuffix(mustBody(r), "token="+url.QueryEscape(p.Get("token"))) {
			fail("badtoken", "Invalid CSRF token.")
			return
		}
		if p.Get("nocreate") != "1" || p.Get("pageid") != "7" || p.Get("starttimestamp") == "" || p.Get("basetimestamp") == "" {
			w.WriteHeader(400)
			return
		}
		if f.conflict {
			f.conflict = false
			l := f.latest()
			f.revs = append(f.revs, rev{id: l.id + 1, parent: l.id, text: "theirs", ts: "2026-11-04T12:30:00Z"})
		}
		l := f.latest()
		if p.Get("baserevid") != strconv.Itoa(l.id) {
			fail("editconflict", "Edit conflict.")
			return
		}
		n := rev{id: l.id + 1, parent: l.id, text: strings.TrimRight(p.Get("text"), " \n"), ts: "2026-11-04T13:00:00Z"}
		f.revs = append(f.revs, n)
		reply(map[string]any{"edit": map[string]any{"result": "Success", "pageid": 7, "title": "Help:Backups", "oldrevid": l.id, "newrevid": n.id, "newtimestamp": n.ts}})
	default:
		w.WriteHeader(400)
	}
}

// mustBody is the raw request body (ParseForm doesn't keep the order of the
// fields), saved by keepBody.
func mustBody(r *http.Request) string { return r.Header.Get("X-Raw-Body") }

type keepBody struct{ h http.Handler }

func (k keepBody) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	r.Header.Set("X-Raw-Body", string(b))
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	k.h.ServeHTTP(w, r)
}

func setup(t *testing.T, pass string, public bool) (*Module, *fakeWiki) {
	f := &fakeWiki{public: public, revs: []rev{{id: 100, text: "== Backups ==\nRun restic.\nKeep the key safe.", ts: "2026-11-01T10:00:00Z"}}}
	srv := httptest.NewServer(keepBody{f})
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Wait = func(_ context.Context, d time.Duration) error { f.waits = append(f.waits, d); return nil }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/w/api.php", Username: "Elchi@conduit", Password: pass})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mw": botPass, "secret://bad": "wrongwrongwrongwrongwrong"}), "mw", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "mw", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMediaWiki(t *testing.T) {
	m, f := setup(t, "secret://mw", false)
	if h := m.Health(context.Background(), "mw"); h.Status != "ok" || h.Message != "signed in as Elchi · Lab Wiki (MediaWiki 1.42.3)" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "search", `{"query":"backups"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"title":"Help:Backups"`) || strings.Contains(string(r.Output), "secret snippet") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "read_page", `{"title":"Help:Backups"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"wikitext":"== Backups ==\nRun restic.\nKeep the key safe."`) || !strings.Contains(string(r.Output), `"revid":100`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "read_page") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
	if f.logins != 1 {
		t.Fatalf("%d logins", f.logins)
	}

	// Preview: a diff, never the old lines.
	r, err = invoke(m, "edit_page", `{"title":"Help:Backups","text":"== Backups ==\nRun restic check.\nKeep the key safe.\n","summary":"fix"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(string(r.Plan.Changes[0].After), `"added":1,"removed":1`) || strings.Contains(string(r.Plan.Changes[0].After), "Run restic.") || len(f.revs) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	// Same text (MediaWiki drops trailing whitespace): nothing to change.
	r, err = invoke(m, "edit_page", `{"pageid":7,"text":"== Backups ==\nRun restic.\nKeep the key safe.\n\n"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") || len(f.revs) != 1 {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "edit_page", `{"title":"Help:Backups","text":"new text","summary":"fix"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "restore_revision" || string(r.Undo.Input) != `{"current":101,"pageid":7,"revision":100}` || f.latest().text != "new text" {
		t.Fatalf("%+v %v", r, err)
	}
	if strings.Contains(string(r.Output), "restic") {
		t.Fatalf("old text in output: %s", r.Output)
	}
	undo := *r.Undo
	r, err = invoke(m, undo.Action, string(undo.Input), false)
	if err != nil || f.latest().text != "== Backups ==\nRun restic.\nKeep the key safe." || r.Undo == nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Again: the page moved on, so nothing happens.
	if _, err := invoke(m, undo.Action, string(undo.Input), false); err == nil || !strings.Contains(err.Error(), "edited again") || len(f.revs) != 3 {
		t.Fatal(err)
	}
	// Each edit fetched its own CSRF token; every signed-in request asserted.
	for _, s := range f.seen {
		if strings.Contains(s, "action=edit") && !strings.Contains(s, "assert=user") {
			t.Fatalf("edit without assert: %s", s)
		}
	}
	if f.tokens != 2 {
		t.Fatalf("%d tokens", f.tokens)
	}
	// Edits never create pages.
	if _, err := invoke(m, "edit_page", `{"title":"Nope","text":"x"}`, false); err == nil || !strings.Contains(err.Error(), "no such page") {
		t.Fatal(err)
	}
}

func TestMediaWikiPublic(t *testing.T) {
	m, f := setup(t, "secret://mw", true)
	if _, err := invoke(m, "edit_page", `{"pageid":7,"text":"x"}`, false); err == nil || !strings.Contains(err.Error(), "edit_public_page") || len(f.revs) != 1 {
		t.Fatal(err)
	}
	r, err := invoke(m, "edit_public_page", `{"pageid":7,"text":"x"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "anyone can read") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "edit_public_page", `{"pageid":7,"text":"x"}`, false); err != nil || r.Undo == nil || f.latest().text != "x" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskWrite
		switch a.Name {
		case "search", "read_page":
			want = sdk.RiskRead
		case "edit_public_page":
			want = sdk.RiskDestructive
		}
		if a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestMediaWikiConflictLagAndSession(t *testing.T) {
	m, f := setup(t, "secret://mw", false)
	// Someone saves between our read and our edit: refused, theirs kept.
	f.conflict = true
	if _, err := invoke(m, "edit_page", `{"pageid":7,"text":"mine"}`, false); err == nil || !strings.Contains(err.Error(), "in the meantime") || f.latest().text != "theirs" {
		t.Fatal(err, f.latest())
	}
	// maxlag: waits for Retry-After, then goes ahead.
	f.lag = 2
	if _, err := invoke(m, "read_page", `{"pageid":7}`, false); err != nil || len(f.waits) != 2 || f.waits[0] != 2*time.Second {
		t.Fatal(err, f.waits)
	}
	// Gives up after a few tries.
	f.lag = 10
	if _, err := invoke(m, "read_page", `{"pageid":7}`, false); err == nil || !strings.Contains(err.Error(), "maxlag") {
		t.Fatal(err)
	}
	f.lag = 0
	// A lapsed session: signs in again once.
	f.expire = true
	if _, err := invoke(m, "read_page", `{"pageid":7}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
}

func TestMediaWikiValidation(t *testing.T) {
	m, f := setup(t, "secret://mw", false)
	big := strings.Repeat("x", 1<<20+1)
	for _, c := range []struct{ action, in string }{
		{"read_page", `{}`},
		{"read_page", `{"title":"A","pageid":7}`},
		{"read_page", `{"title":"A|B"}`},
		{"read_page", `{"title":"A[[x]]"}`},
		{"read_page", `{"title":"` + strings.Repeat("a", 256) + `"}`},
		{"read_page", `{"pageid":-1}`},
		{"search", `{"query":"  "}`},
		{"search", `{"query":"x","namespace":-1}`},
		{"edit_page", `{"pageid":7}`},
		{"edit_page", `{"pageid":7,"text":"` + big + `"}`},
		{"edit_page", `{"pageid":7,"text":"x","summary":"a\nb"}`},
		{"edit_public_page", `{"title":"<x>","text":"x"}`},
		{"restore_revision", `{"pageid":7,"revision":100}`},
		{"restore_revision", `{"pageid":7,"revision":100,"current":100}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %.80s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://wiki.example.com/w/api.php", Username: "Elchi@conduit", Password: botPass},
		{URL: "https://wiki.example.com/w/", Username: "Elchi@conduit", Password: "secret://mw"},
		{URL: "https://u:p@wiki.example.com/w/api.php", Username: "Elchi@conduit", Password: "secret://mw"},
		{URL: "https://wiki.example.com/w/api.php?x=1", Username: "Elchi@conduit", Password: "secret://mw"},
		{URL: "https://wiki.example.com/w/api.php#x", Username: "Elchi@conduit", Password: "secret://mw"},
		{URL: "https://wiki.example.com/w/api.php", Username: "Elchi", Password: "secret://mw"},
		{URL: "https://wiki.example.com/w/api.php", Username: "Elchi@conduit", Password: "secret://mw", Assert: "anon"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	h := bad.Health(context.Background(), "mw")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the bot password") || strings.Contains(h.Message, "wrongwrong") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "read_page", `{"pageid":7}`, false); err == nil || strings.Contains(err.Error(), "wrongwrong") {
		t.Fatal(err)
	}
}

func TestMediaWikiNoSecretInErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("type") == "login" {
			io.WriteString(w, `{"query":{"tokens":{"logintoken":"LT+\\"}}}`)
			return
		}
		// Echoes the password in an error.
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "internal_api_error", "info": "failed for password=" + r.PostForm.Get("lgpassword")}})
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api.php", Username: "Elchi@conduit", Password: "secret://mw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mw": botPass}), "mw", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "mw")
	if h.Status != "down" || strings.Contains(h.Message, botPass) || strings.Contains(h.Message, "s3cr3t") {
		t.Fatalf("%+v", h)
	}
}

func TestMediaWikiRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/w/api.php", Username: "Elchi@conduit", Password: "secret://mw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mw": botPass}), "mw", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "mw"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
