package plausible

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

type fake struct {
	mu        sync.Mutex
	seen      []string
	sitesAPI  bool // the key may use the Sites API
	lastQuery map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer plkey" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Invalid API key or site ID. Please make sure you're using a valid API key"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /stats/api/v1/sites":
		if !f.sitesAPI {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Invalid API key"}`)
			return
		}
		if r.URL.Query().Get("after") == "" {
			io.WriteString(w, `{"sites":[{"domain":"example.com","timezone":"Europe/Berlin"},{"domain":"other.org","timezone":"UTC"}],"meta":{"after":"cur1"}}`)
		} else {
			io.WriteString(w, `{"sites":[{"domain":"blog.example.com","timezone":"UTC"}],"meta":{"after":null}}`)
		}
	case "GET /stats/api/v1/stats/realtime/visitors":
		if r.URL.Query().Get("site_id") != "example.com" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Invalid API key or site ID"}`)
			return
		}
		io.WriteString(w, "17")
	case "POST /stats/api/v2/query":
		var q map[string]any
		json.Unmarshal(body, &q)
		f.lastQuery = q
		if q["site_id"] != "example.com" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"Site not found"}`)
			return
		}
		if _, ok := q["dimensions"]; ok {
			io.WriteString(w, `{"results":[{"metrics":[120,300],"dimensions":["/"]},{"metrics":[40,55],"dimensions":["/pricing"]}],"meta":{}}`)
			return
		}
		io.WriteString(w, `{"results":[{"metrics":[1000,1300,4200,3.2,41.5,95],"dimensions":[]}],"meta":{}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

func setup(t *testing.T, cfg Config, sitesAPI bool) (*Module, *fake) {
	t.Helper()
	f := &fake{sitesAPI: sitesAPI}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.Address = srv.URL + "/stats"
	if cfg.APIKey == "" {
		cfg.APIKey = "secret://pl"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pl": "plkey", "secret://bad": "nope"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in)})
}

func TestPlausibleReads(t *testing.T) {
	m, f := setup(t, Config{}, true)
	if h := m.Health(context.Background(), "p"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"sites", `{}`, `"domain":"blog.example.com"`},
		{"realtime", `{"site":"Example.com"}`, `"visitors":17`},
		{"aggregate", `{"site":"example.com","period":"7d"}`, `"bounceRate":41.5`},
		{"aggregate", `{"site":"example.com"}`, `"pageviews":4200`},
		{"aggregate", `{"site":"example.com","from":"2026-10-01","to":"2026-10-31"}`, `"period":"2026-10-01 to 2026-10-31"`},
		{"breakdown", `{"site":"example.com","by":"page","limit":5}`, `{"page":"/pricing","pageviews":55,"visitors":40}`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if dims := f.lastQuery["dimensions"].([]any); dims[0] != "event:page" {
		t.Fatalf("%v", f.lastQuery)
	}
	if pg := f.lastQuery["pagination"].(map[string]any); pg["limit"] != float64(5) {
		t.Fatalf("%v", f.lastQuery)
	}
	if _, err := invoke(m, "breakdown", `{"site":"example.com","by":"country","from":"2026-10-01","to":"2026-10-02"}`); err != nil {
		t.Fatal(err)
	}
	if f.lastQuery["dimensions"].([]any)[0] != "visit:country_name" || f.lastQuery["date_range"].([]any)[1] != "2026-10-02" {
		t.Fatalf("%v", f.lastQuery)
	}
}

func TestPlausibleSiteAllowList(t *testing.T) {
	m, f := setup(t, Config{Sites: []string{"example.com"}}, false)
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || !strings.Contains(h.Message, "17 visitors") {
		t.Fatalf("%+v", h)
	}
	// The key can't list sites: the settings' list is returned.
	r, err := invoke(m, "sites", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"domain":"example.com"`) || !strings.Contains(string(r.Output), "from the settings") {
		t.Fatalf("%s %v", r.Output, err)
	}
	n := len(f.seen)
	if _, err := invoke(m, "aggregate", `{"site":"other.org"}`); err == nil || !strings.Contains(err.Error(), "isn't one of") {
		t.Fatal(err)
	}
	if len(f.seen) != n {
		t.Fatal("a site outside the allow list reached the server")
	}
	// With the Sites API, listing is narrowed to the allowed sites.
	m2, _ := setup(t, Config{Sites: []string{"example.com"}}, true)
	r, err = invoke(m2, "sites", `{}`)
	if err != nil || strings.Contains(string(r.Output), "other.org") || !strings.Contains(string(r.Output), "example.com") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestPlausibleValidation(t *testing.T) {
	m, f := setup(t, Config{}, true)
	for _, c := range []struct{ action, in string }{
		{"realtime", `{"site":"../api/v1/sites"}`},
		{"realtime", `{"site":"a b"}`},
		{"realtime", `{}`},
		{"aggregate", `{"site":"example.com","period":"forever"}`},
		{"aggregate", `{"site":"example.com","from":"2026-10-01"}`},
		{"aggregate", `{"site":"example.com","from":"2026-10-05","to":"2026-10-01"}`},
		{"aggregate", `{"site":"example.com","from":"2026-13-01","to":"2026-14-01"}`},
		{"aggregate", `{"site":"example.com","period":"7d","from":"2026-10-01","to":"2026-10-02"}`},
		{"breakdown", `{"site":"example.com","by":"event:props"}`},
		{"breakdown", `{"site":"example.com","by":"page","limit":1000}`},
		{"breakdown", `{"site":"example.com?x=1","by":"page"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{APIKey: "plainkey"},
		{APIKey: "secret://pl", Address: "ftp://plausible.io"},
		{APIKey: "secret://pl", Address: "https://user:pw@plausible.io"},
		{APIKey: "secret://pl", Address: "https://plausible.io/a/../b"},
		{APIKey: "secret://pl", Sites: []string{"https://example.com"}},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{APIKey: "secret://bad", Sites: []string{"example.com"}}, true)
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "aggregate", `{"site":"example.com"}`); err == nil || !strings.Contains(err.Error(), "refused the API key") || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestPlausibleRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, APIKey: "secret://pl", Sites: []string{"example.com"}})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pl": "plkey"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "aggregate", `{"site":"example.com"}`); err == nil || hit {
		t.Fatalf("followed the redirect: %v", err)
	}
}
