package photoprism

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakePhotoPrism struct {
	mu      sync.Mutex
	seen    []string
	slow    chan struct{}
	indexed []string
}

const photos = `[
 {"UID":"p1","Type":"image","TakenAt":"2026-11-01T09:00:00Z","TakenAtLocal":"2026-11-01T10:00:00Z","Title":"Brandenburger Tor / Berlin / 2026","Caption":"With Ada","Favorite":true,"Lat":52.5163,"Lng":13.3777,"PlaceID":"de:abc","PlaceLabel":"Mitte, Berlin, Germany","PlaceCity":"Berlin","PlaceState":"Berlin","PlaceCountry":"de","FileName":"2026/11/IMG_1.jpg"},
 {"UID":"p2","Type":"image","TakenAt":"2026-10-30T09:00:00Z","Title":"Sunset at Wannsee","Lat":52.4,"Lng":13.1,"PlaceID":"de:def","PlaceLabel":"Wannsee, Berlin, Germany","PlaceCity":"Berlin","PlaceCountry":"de"},
 {"UID":"p3","Type":"video","TakenAt":"2026-10-29T09:00:00Z","Title":"Birthday cake","Lat":48.1,"Lng":11.5,"PlaceID":"de:ghi","PlaceLabel":"Munich, Bavaria, Germany","PlaceCity":"Munich","PlaceState":"Bavaria","PlaceCountry":"de"},
 {"UID":"p4","Type":"image","TakenAt":"2026-10-28T09:00:00Z","Title":"Cat","PlaceID":"zz"}
]`

func (f *fakePhotoPrism) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer app-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	q := r.URL.Query()
	switch {
	case path == "/config":
		io.WriteString(w, `{"version":"250101-abc","siteTitle":"Photos","count":{"all":120,"photos":100,"videos":20,"albums":3,"places":40,"countries":5,"states":9,"review":2,"people":4}}`)
	case path == "/photos":
		if q.Get("count") == "" || q.Get("order") != "newest" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, photos)
	case path == "/albums":
		if q.Get("count") == "" || q.Get("type") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"UID":"a1","Title":"Holidays","Type":"album","PhotoCount":42,"Favorite":true,"UpdatedAt":"2026-10-01T00:00:00Z"}]`)
	case path == "/index" && r.Method == "POST":
		f.mu.Lock()
		f.indexed = append(f.indexed, string(body))
		f.mu.Unlock()
		if f.slow != nil {
			<-f.slow
		}
		io.WriteString(w, `{"code":200,"message":"Indexing completed in 3 s"}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string, f *fakePhotoPrism) *Module {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.IndexWait = 200 * time.Millisecond
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "app-good", "secret://bad": "nope"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "k", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPhotoPrism(t *testing.T) {
	f := &fakePhotoPrism{}
	m := setup(t, "secret://k", f)
	if h := m.Health(context.Background(), "k"); h.Status != "ok" || h.Message != "PhotoPrism 250101-abc" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "library_stats", `{}`, false)
	if err != nil || string(r.Output) != `{"albums":3,"all":120,"people":4,"photos":100,"review":2,"version":"250101-abc","videos":20}` {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Recent photos: no place, coordinates, file names or captions, and
	// no title that names the place.
	r, err = invoke(m, "recent_photos", `{"query":"year:2026","limit":4}`, false)
	if err != nil {
		t.Fatal(err)
	}
	out := string(r.Output)
	for _, leak := range []string{"Berlin", "Wannsee", "Munich", "52.5", "13.3", "Mitte", "IMG_1", "Ada", `"de"`} {
		if strings.Contains(out, leak) {
			t.Fatalf("recent_photos leaks %q: %s", leak, out)
		}
	}
	for _, want := range []string{`"title":"Birthday cake"`, `"title":"Cat"`, `"taken":"2026-11-01T10:00:00"`, `"favorite":true`, `"type":"video"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s: %s", want, out)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "photo_places" || a.Name == "folders") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
		if strings.Contains(a.Name, "share") {
			t.Fatal("sharing isn't offered")
		}
	}
	r, err = invoke(m, "photo_places", `{"query":"city:berlin"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"lat":52.5163`) || !strings.Contains(string(r.Output), `"city":"Berlin"`) || !strings.Contains(string(r.Output), `"title":"Brandenburger Tor / Berlin / 2026"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "albums", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `{"favorite":true,"photos":42,"title":"Holidays","uid":"a1","updated":"2026-10-01T00:00:00Z"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "folders", `{"query":"Italy"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"folders":[`) || !strings.Contains(f.seen[len(f.seen)-1], "type=folder") {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "start_index", `{"path":"2026/11"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Index new and changed files in originals/2026/11" || len(f.indexed) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_index", `{"path":"/2026/11/","rescan":true}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"done":true`) || f.indexed[0] != `{"cleanup":false,"path":"/2026/11","rescan":true}` {
		t.Fatalf("%s %v %v", r.Output, err, f.indexed)
	}
}

// PhotoPrism only answers when indexing is done; a long run is reported as
// started, not as an error.
func TestPhotoPrismIndexInBackground(t *testing.T) {
	f := &fakePhotoPrism{slow: make(chan struct{})}
	m := setup(t, "secret://k", f)
	defer close(f.slow)
	r, err := invoke(m, "start_index", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"done":false`) || !strings.Contains(string(r.Output), "still indexing") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestPhotoPrismValidation(t *testing.T) {
	f := &fakePhotoPrism{}
	m := setup(t, "secret://k", f)
	for _, c := range []struct{ action, in string }{
		// Place filters would show where photos were taken.
		{"recent_photos", `{"query":"near:p1"}`},
		{"recent_photos", `{"query":"cat country:de"}`},
		{"recent_photos", `{"query":"lat:52.5 lng:13.3 dist:2"}`},
		{"recent_photos", `{"query":"` + strings.Repeat("x", 501) + `"}`},
		{"albums", `{"type":"state"}`},
		{"albums", `{"type":"moment"}`},
		{"albums", `{"type":"folder"}`},
		{"start_index", `{"path":"../../etc"}`},
		{"start_index", `{"path":"2026/../.."}`},
		{"start_index", `{"path":".hidden"}`},
		{"start_index", `{"path":"a\\b"}`},
		{"start_index", `{"path":"2026//11"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://photos.example.com", Token: "app-plain"}, {URL: "photos.example.com", Token: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad := setup(t, "secret://bad", &fakePhotoPrism{})
	if h := bad.Health(context.Background(), "k"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	// A refused index is an error, not "started".
	if _, err := invoke(bad, "start_index", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

func TestPhotoPrismRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "app-good"}), "k", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "k"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// recent_photos reads a search the way PhotoPrism does and takes only
// filters that can't find photos by place; albums takes no filters.
func TestPhotoPrismRecentQuery(t *testing.T) {
	f := &fakePhotoPrism{}
	m := setup(t, "secret://k", f)
	for _, c := range []struct{ action, q string }{
		{"recent_photos", "label:cat\vcountry:de"},      // \v: a space to PhotoPrism
		{"recent_photos", "label:cat\u00a0near:p1"},     // no-break space
		{"recent_photos", "label:cat\u2003city:Berlin"}, // em space
		{"recent_photos", `c\"ountry\":de`},             // PhotoPrism drops quotes from keys
		{"recent_photos", `\"lat\":52.5 \"lng\":13.4`},
		{"recent_photos", "COUNTRY:de"},
		{"recent_photos", "alt:30-40"},
		{"recent_photos", "category:airport"},
		{"recent_photos", "keywords:berlin"},
		{"recent_photos", "path:2026/Italy-trip"},
		{"recent_photos", "title:Berlin"},
		{"recent_photos", "Berlin"},
		{"recent_photos", "label:cat Berlin"},
		{"recent_photos", "label:"},
		{"recent_photos", "label:cat\u200bcountry:de"}, // zero-width space (format character)
		{"recent_photos", "label:cat\u0085year:2025"},
		{"photo_places", "near:p1\u202e"},
		{"albums", "type:moment"},
		{"albums", `\"type\":moment`},
		{"albums", "title:x"},
		{"albums", "Rome\u200d"},
	} {
		if _, err := invoke(m, c.action, `{"query":"`+c.q+`"}`, false); err == nil {
			t.Errorf("%s accepted %q", c.action, c.q)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("refused searches reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "recent_photos", `{"query":" Label:cat   YEAR:2025 \"favorite\":true type:video|live"}`, false); err != nil {
		t.Fatal(err)
	}
	if got := f.seen[len(f.seen)-1]; !strings.Contains(got, "q=label%3Acat+year%3A2025+favorite%3Atrue+type%3Avideo%7Clive") {
		t.Fatalf("sent %s", got)
	}
	if _, err := invoke(m, "albums", `{"query":"Summer holidays"}`, false); err != nil {
		t.Fatal(err)
	}
}
