package kavita

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

type fakeKavita struct {
	mu      sync.Mutex
	seen    []string
	logins  int
	expired bool // the next request with the token is refused once
}

func (f *fakeKavita) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.URL.Path == "/api/Plugin/authenticate" {
		if r.URL.Query().Get("apiKey") != "kv_good" {
			w.WriteHeader(401)
			return
		}
		f.logins++
		io.WriteString(w, `{"username":"reader","email":"LEAKME@example.com","token":"jwt-LEAKME","refreshToken":"LEAKME","apiKey":"kv_good"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer jwt-LEAKME" || f.expired {
		f.expired = false
		w.WriteHeader(401)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/Library/libraries":
		io.WriteString(w, `[{"id":1,"name":"Manga","type":0,"lastScanned":"2026-11-01T10:00:00","folders":["/manga"]},{"id":2,"name":"Books","type":2,"lastScanned":"0001-01-01T00:00:00","folders":["/books"]}]`)
	case "POST /api/Series/all-v2":
		w.Header().Set("Pagination", `{"currentPage":1,"itemsPerPage":20,"totalItems":57,"totalPages":3}`)
		io.WriteString(w, `[{"id":7,"name":"Berserk","localizedName":"ベルセルク","pages":200,"pagesRead":50,"format":1,"libraryId":1,"libraryName":"Manga","lastChapterAdded":"2026-10-30T00:00:00"}]`)
	case "POST /api/Series/recently-added-v2":
		io.WriteString(w, `[{"id":9,"name":"Dune","pages":0,"format":3,"libraryId":2}]`)
	case "GET /api/Search/search":
		io.WriteString(w, `{"series":[{"seriesId":7,"name":"Berserk","libraryId":1,"libraryName":"Manga","format":1},{"seriesId":8,"name":"Berserk novel","libraryId":2,"format":3}]}`)
	case "POST /api/Library/scan":
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeKavita) {
	f := &fakeKavita{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kv": "kv_good", "secret://bad": "kv_bad"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestKavita(t *testing.T) {
	m, f := setup(t, "secret://kv")
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "signed in as reader · 2 libraries" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"libraries", `{}`, `"type":"manga"`},
		{"series", `{}`, `"total":57`},
		{"series", `{"library":1}`, `"percentRead":25`},
		{"series", `{"search":"berserk","library":1}`, `"name":"Berserk"`},
		{"recent", `{}`, `"format":"epub"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "series", `{"search":"berserk","library":1}`, false); strings.Contains(string(r.Output), "novel") {
		t.Fatal(string(r.Output))
	}
	if r, _ := invoke(m, "libraries", `{}`, false); strings.Contains(string(r.Output), "0001-") {
		t.Fatal(string(r.Output))
	}
	if f.logins != 1 {
		t.Fatalf("logged in %d times", f.logins)
	}
	// A refused token is replaced once.
	f.expired = true
	if _, err := invoke(m, "libraries", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
	// The library filter is sent as Kavita's filter.
	f.seen = nil
	invoke(m, "series", `{"library":2}`, false)
	if len(f.seen) != 1 || !strings.Contains(f.seen[0], `"field":19`) || !strings.Contains(f.seen[0], `"value":"2"`) {
		t.Fatal(f.seen)
	}

	f.seen = nil
	r, err := invoke(m, "scan_library", `{"library":1,"force":true}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Force scan library "Manga"` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if strings.Contains(s, "scan") {
			t.Fatal("the preview scanned")
		}
	}
	if r, err := invoke(m, "scan_library", `{"library":1}`, false); err != nil || !strings.Contains(string(r.Output), `"scanning":"Manga"`) {
		t.Fatal(string(r.Output), err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.HasPrefix(last, "POST /api/Library/scan?force=false&libraryId=1") {
		t.Fatal(last)
	}
	if _, err := invoke(m, "scan_library", `{"library":5}`, false); err == nil || !strings.Contains(err.Error(), "no library 5") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "scan_library" && a.Risk != sdk.RiskWrite {
			t.Fatal(a.Risk)
		}
	}
}

func TestKavitaValidation(t *testing.T) {
	m, f := setup(t, "secret://kv")
	for _, c := range []struct{ action, in string }{
		{"scan_library", `{}`},
		{"scan_library", `{"library":0}`},
		{"scan_library", `{"library":-3}`},
		{"scan_library", `{"library":"1/../users"}`},
		{"series", `{"search":"a\nb"}`},
		{"series", `{"search":"` + strings.Repeat("x", 201) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://k.example.com", APIKey: "kv_plain"}, {URL: "k.example.com", APIKey: "secret://kv"},
		{URL: "https://u:p@k.example.com", APIKey: "secret://kv"}, {URL: "https://k.example.com/?x=1", APIKey: "secret://kv"}, {URL: "https://k.example.com/#x", APIKey: "secret://kv"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "k")
	if h.Status != "down" || h.Message != "Kavita refused the API key" || strings.Contains(h.Message, "kv_bad") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "libraries", `{}`, false); err == nil || strings.Contains(err.Error(), "kv_bad") {
		t.Fatal(err)
	}
}

func TestKavitaRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery + r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://kv"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://kv": "kv_good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "k")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "kv_good") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
