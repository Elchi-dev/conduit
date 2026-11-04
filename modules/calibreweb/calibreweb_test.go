package calibreweb

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

const books = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:opds="http://opds-spec.org/2010/catalog">
  <title>Calibre-Web</title>
  <link rel="next" href="/books/opds/new?offset=60"/>
  <entry>
    <title>Dune</title>
    <id>urn:uuid:1234</id>
    <updated>2026-11-01T10:00:00+00:00</updated>
    <author><name>Frank Herbert</name></author>
    <publisher><name>Ace</name></publisher>
    <dcterms:language>en</dcterms:language>
    <category scheme="http://www.bisg.org/standards/bisac_subject/index.html" term="Science Fiction" label="Science Fiction"/>
    <link type="image/jpeg" href="/books/opds/cover/12" rel="http://opds-spec.org/image"/>
    <link type="application/epub+zip" href="/books/opds/download/12/epub/" rel="http://opds-spec.org/acquisition" length="1000"/>
    <link type="application/pdf" href="/books/opds/download/12/pdf/" rel="http://opds-spec.org/acquisition"/>
  </entry>
  <entry>
    <title>Navigation entry</title>
    <id>/opds/books</id>
    <link type="application/atom+xml;profile=opds-catalog" href="/books/opds/books"/>
  </entry>
</feed>`

const shelves = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Shelves</title>
  <entry><title>To read</title><id>/books/opds/shelf/3</id><link type="application/atom+xml;profile=opds-catalog" href="/books/opds/shelf/3"/></entry>
  <entry><title>Favourites</title><id>urn:x</id><link href="/books/opds/shelf/5"/></entry>
</feed>`

type fakeCW struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeCW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "reader" || p != "pw_good" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Login Required"`)
		w.WriteHeader(401)
		io.WriteString(w, "Could not verify your access level for that URL.")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath())
	w.Header().Set("Content-Type", "application/atom+xml")
	switch r.URL.EscapedPath() {
	case "/books/opds", "/books/opds/new", "/books/opds/shelf/3", "/books/opds/search/frank%20herbert":
		io.WriteString(w, books)
	case "/books/opds/shelfindex":
		io.WriteString(w, shelves)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeCW) {
	f := &fakeCW{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/books/opds", Username: "reader", Password: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cw": "pw_good", "secret://bad": "pw_bad"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in)})
}

func TestCalibreWeb(t *testing.T) {
	m, _ := setup(t, "secret://cw")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "Calibre-Web · catalog reachable as reader" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"recent", `{}`, `"formats":["epub","pdf"]`},
		{"recent", `{}`, `"publisher":"Ace"`},
		{"recent", `{}`, `"languages":["en"]`},
		{"search", `{"query":"frank herbert"}`, `"authors":["Frank Herbert"]`},
		{"shelf", `{"shelf":3}`, `"id":12`},
		{"shelves", `{}`, `{"id":5,"name":"Favourites"`},
		{"shelves", `{}`, `/books/shelf/3"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "pw_good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Navigation entries aren't books.
	if r, _ := invoke(m, "recent", `{}`); strings.Contains(string(r.Output), "Navigation") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "shelf", `{"shelf":9}`); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestCalibreWebValidation(t *testing.T) {
	m, f := setup(t, "secret://cw")
	for _, c := range []struct{ action, in string }{
		{"search", `{}`}, {"search", `{"query":"  "}`}, {"search", `{"query":"a\nb"}`}, {"search", `{"query":"` + strings.Repeat("x", 201) + `"}`},
		{"shelf", `{}`}, {"shelf", `{"shelf":0}`}, {"shelf", `{"shelf":"3/../../admin"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://b.example.com", Username: "u", Password: "plain"}, {URL: "b.example.com", Username: "u", Password: "secret://cw"},
		{URL: "https://u:p@b.example.com", Username: "u", Password: "secret://cw"}, {URL: "https://b.example.com/?q=1", Username: "u", Password: "secret://cw"},
		{URL: "https://b.example.com", Password: "secret://cw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "Calibre-Web refused the user name or password" {
		t.Fatalf("%+v", h)
	}
}

func TestCalibreWebRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "reader", Password: "secret://cw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cw": "pw_good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
