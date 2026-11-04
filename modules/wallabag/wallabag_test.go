package wallabag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeEntry struct {
	url      string
	archived int
	starred  bool
}

type fakeWallabag struct {
	mu      sync.Mutex
	seen    []string
	grants  int
	token   string
	entries map[int64]*fakeEntry
	next    int64
}

func (f *fakeWallabag) entry(id int64) string {
	e := f.entries[id]
	return fmt.Sprintf(`{"id":%d,"title":"Article %d","url":%q,"domain_name":"example.com","is_archived":%d,"is_starred":%v,"created_at":"2026-11-01T10:00:00+0000","reading_time":7,"tags":[{"id":1,"label":"go","slug":"go"}]}`, id, id, e.url, e.archived, e.starred)
}

func (f *fakeWallabag) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth/v2/token" {
		f.seen = append(f.seen, "token")
		form, _ := url.ParseQuery(string(body))
		if r.Method != "POST" || form.Get("grant_type") != "password" || form.Get("client_id") != "1_client" || form.Get("client_secret") != "csecret" ||
			form.Get("username") != "elchi" || form.Get("password") != "pw" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid username and password combination"}`)
			return
		}
		f.grants++
		f.token = fmt.Sprintf("tok%d", f.grants)
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"token_type":"bearer","refresh_token":"r"}`, f.token)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token || f.token == "" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"The access token provided is invalid."}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	q := r.URL.Query()
	switch {
	case path == "/user.json":
		io.WriteString(w, `{"id":1,"username":"elchi","email":"e@example.com"}`)
	case path == "/entries.json" && r.Method == "GET":
		var items []string
		for _, id := range []int64{1, 2} {
			e := f.entries[id]
			if e == nil || (q.Get("archive") != "" && q.Get("archive") != fmt.Sprint(e.archived)) || (q.Get("starred") == "1" && !e.starred) {
				continue
			}
			items = append(items, f.entry(id))
		}
		fmt.Fprintf(w, `{"page":1,"limit":20,"pages":1,"total":%d,"_embedded":{"items":[%s]}}`, len(items), strings.Join(items, ","))
	case path == "/entries/exists.json":
		for id, e := range f.entries {
			if e.url == q.Get("url") {
				fmt.Fprintf(w, `{"exists":%d}`, id)
				return
			}
		}
		io.WriteString(w, `{"exists":null}`)
	case path == "/entries.json" && r.Method == "POST":
		var b struct{ URL string }
		json.Unmarshal(body, &b)
		f.next++
		f.entries[f.next] = &fakeEntry{url: b.URL}
		io.WriteString(w, f.entry(f.next))
	case strings.HasPrefix(path, "/entries/") && strings.HasSuffix(path, ".json"):
		var id int64
		fmt.Sscan(strings.TrimSuffix(strings.TrimPrefix(path, "/entries/"), ".json"), &id)
		e := f.entries[id]
		if e == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
			return
		}
		switch r.Method {
		case "GET":
			io.WriteString(w, f.entry(id))
		case "PATCH":
			var b map[string]int
			json.Unmarshal(body, &b)
			if v, ok := b["archive"]; ok {
				e.archived = v
			}
			if v, ok := b["starred"]; ok {
				e.starred = v == 1
			}
			io.WriteString(w, f.entry(id))
		case "DELETE":
			io.WriteString(w, f.entry(id))
			delete(f.entries, id)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeWallabag) {
	f := &fakeWallabag{entries: map[int64]*fakeEntry{1: {url: "https://go.dev/blog"}, 2: {url: "https://example.com/old", archived: 1, starred: true}}, next: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, ClientID: "secret://cid", ClientSecret: "secret://cs", Username: "elchi", Password: pw})
	h := fakehost.New(map[string]string{"secret://cid": "1_client", "secret://cs": "csecret", "secret://pw": "pw", "secret://bad": "nope"})
	if err := m.Configure(context.Background(), h, "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestWallabag(t *testing.T) {
	m, f := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "signed in as elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want, not string }{
		{"entries", `{}`, `"title":"Article 1"`, "Article 2"},
		{"entries", `{"status":"archived"}`, `"archived":true`, "Article 1"},
		{"entries", `{"status":"starred","tag":"go"}`, `"starred":true`, "Article 1"},
		{"entries", `{"status":"all","limit":5}`, `"readingMinutes":7`, "nothing"},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), c.not) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}

	// Saving a new link is undone by deleting it; an existing one isn't saved again.
	r, err := invoke(m, "save_url", `{"url":"https://example.org/new","tags":["later"]}`, true)
	if err != nil || r.Plan == nil || len(f.entries) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "save_url", `{"url":"https://example.org/new","title":"New","tags":["later","go"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_entry" || string(r.Undo.Input) != `{"entry":3}` || f.entries[3] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), `"tags":"later,go"`) {
		t.Fatalf("tags not sent: %v", f.seen)
	}
	n := len(f.seen)
	if r, err := invoke(m, "save_url", `{"url":"https://go.dev/blog"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "already saved") || strings.Contains(strings.Join(f.seen[n:], "\n"), "POST") {
		t.Fatalf("existing: %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.entries[3] != nil {
		t.Fatal(err)
	}

	// Archive and star, each with its undo.
	r, err = invoke(m, "archive", `{"entry":1}`, true)
	if err != nil || r.Plan == nil || f.entries[1].archived != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "archive", `{"entry":1}`, false)
	if err != nil || f.entries[1].archived != 1 || r.Undo == nil || r.Undo.Action != "unarchive" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.entries[1].archived != 0 {
		t.Fatal(err)
	}
	r, err = invoke(m, "star", `{"entry":1}`, false)
	if err != nil || !f.entries[1].starred || r.Undo == nil || r.Undo.Action != "unstar" || string(r.Undo.Input) != `{"entry":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.entries[1].starred {
		t.Fatal(err)
	}
	if r, err := invoke(m, "unstar", `{"entry":1}`, false); err != nil || r.Undo != nil {
		t.Fatalf("no-op: %+v %v", r, err)
	}

	r, err = invoke(m, "delete_entry", `{"entry":2}`, true)
	if err != nil || r.Plan == nil || f.entries[2] == nil || !strings.Contains(r.Plan.Summary, "Article 2") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_entry", `{"entry":2}`, false); err != nil || f.entries[2] != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "star", `{"entry":2}`, false); err == nil || !strings.Contains(err.Error(), "no entry 2") {
		t.Fatal(err)
	}

	// A revoked token is renewed once; the token is reused otherwise.
	if f.grants != 1 {
		t.Fatalf("signed in %d times", f.grants)
	}
	f.mu.Lock()
	f.token = "revoked"
	f.mu.Unlock()
	if _, err := invoke(m, "entries", `{}`, false); err != nil || f.grants != 2 {
		t.Fatalf("%v %d", err, f.grants)
	}
	c, _ := m.set.Get("w")
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := invoke(m, "entries", `{}`, false); err != nil || f.grants != 3 {
		t.Fatalf("expired token not renewed: %v %d", err, f.grants)
	}
}

func TestWallabagValidation(t *testing.T) {
	m, f := setup(t, "secret://pw")
	for _, c := range []struct{ action, in string }{
		{"entries", `{"status":"deleted"}`},
		{"entries", `{"tag":"a,b"}`},
		{"archive", `{}`},
		{"archive", `{"entry":0}`},
		{"star", `{"entry":-1}`},
		{"unstar", `{"entry":"1/../../user"}`},
		{"delete_entry", `{"entry":9007199254740993}`},
		{"save_url", `{"url":"javascript:alert(1)"}`},
		{"save_url", `{"url":"example.com"}`},
		{"save_url", `{"url":"https://user:pw@example.com/"}`},
		{"save_url", `{"url":"https://example.com/","tags":["a,b"]}`},
		{"save_url", `{"url":"https://example.com/","tags":[" "]}`},
		// wallabag fetches what it saves: nothing on the local network.
		{"save_url", `{"url":"http://127.0.0.1:8080/admin"}`},
		{"save_url", `{"url":"http://10.0.0.5/"}`},
		{"save_url", `{"url":"http://192.168.1.1/"}`},
		{"save_url", `{"url":"http://169.254.169.254/latest/meta-data/"}`},
		{"save_url", `{"url":"http://100.100.100.100/"}`},
		{"save_url", `{"url":"http://[::1]/"}`},
		{"save_url", `{"url":"http://[fd00::1]/"}`},
		{"save_url", `{"url":"http://[::ffff:127.0.0.1]/"}`},
		{"save_url", `{"url":"http://0.0.0.0/"}`},
		{"save_url", `{"url":"http://2130706433/"}`},
		{"save_url", `{"url":"http://0x7f.1/"}`},
		{"save_url", `{"url":"http://127.1/"}`},
		{"save_url", `{"url":"http://localhost:3000/"}`},
		{"save_url", `{"url":"http://nas/"}`},
		{"save_url", `{"url":"http://printer.local/"}`},
		{"save_url", `{"url":"http://grafana.corp.internal/"}`},
		{"save_url", `{"url":"http://router.lan/"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, ok := range []string{"example.com", "1.1.1.1", "sub.example.co.uk", "2606:4700::1111"} {
		if err := localHost(ok); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
	good := Config{URL: "https://wallabag.example.com", ClientID: "1_x", ClientSecret: "secret://cs", Username: "elchi", Password: "secret://pw"}
	for _, mod := range []func(*Config){
		func(c *Config) { c.Password = "pw" },
		func(c *Config) { c.ClientSecret = "csecret" },
		func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.Username = "" },
		func(c *Config) { c.URL = "wallabag.example.com" },
		func(c *Config) { c.URL = "https://u:p@wallabag.example.com" },
	} {
		c := good
		mod(&c)
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, bf := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "w"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "entries", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	if strings.Join(bf.seen, ",") != "token,token" {
		t.Fatalf("went past a failed sign-in: %v", bf.seen)
	}
}

func TestWallabagRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect) // 307 replays the password
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, ClientID: "1_x", ClientSecret: "secret://cs", Username: "elchi", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cs": "c", "secret://pw": "p"}), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
