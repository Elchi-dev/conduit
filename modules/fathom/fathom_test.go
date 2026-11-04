package fathom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const key = "fathom-api-key-LEAKME"

type fake struct {
	mu       sync.Mutex
	seen     []string
	lastQ    url.Values
	redirect string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthenticated. Bearer `+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+`"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.lastQ = r.URL.Query()
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/sites":
		if r.URL.Query().Get("starting_after") == "" {
			io.WriteString(w, `{"object":"list","has_more":true,"data":[{"id":"CDBUGS","object":"site","name":"Acme","sharing":"none"}]}`)
		} else {
			io.WriteString(w, `{"object":"list","has_more":false,"data":[{"id":"BLOG1","object":"site","name":"Blog","sharing":"public"}]}`)
		}
	case "GET /v1/aggregations":
		if r.URL.Query().Get("entity_id") == "NOPE" {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":"Forbidden"}`)
			return
		}
		io.WriteString(w, `[{"visits":"120","uniques":"100","pathname":"/"},{"visits":40,"uniques":"30","pathname":"/pricing"},{"visits":"1","uniques":"1","pathname":"/x"}]`)
	case "GET /v1/current_visitors":
		io.WriteString(w, `{"total":3,"content":[{"hostname":"acme.com","pathname":"/","total":"2"}],"referrers":[{"referrer_hostname":"google.com","referrer_pathname":"/","total":"1"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.HTTP = srv.URL, srv.Client()
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fa": key, "secret://bad": "wrong-key-LEAKME-123456"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in)})
}

func TestFathomReads(t *testing.T) {
	m, f := setup(t, "secret://fa")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "1+ sites" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "sites", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"site":"BLOG1"`) || !strings.Contains(string(r.Output), `"site":"CDBUGS"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "aggregation", `{"site":"CDBUGS","aggregates":["visits","uniques"],"groupBy":["pathname"],"limit":2,"days":7}`)
	if err != nil || !strings.Contains(string(r.Output), `{"pathname":"/pricing","uniques":30,"visits":40}`) || strings.Contains(string(r.Output), `"/x"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	today := time.Now().UTC()
	if f.lastQ.Get("date_from") != today.AddDate(0, 0, -6).Format("2006-01-02")+" 00:00:00" || f.lastQ.Get("field_grouping") != "pathname" ||
		f.lastQ.Get("sort_by") != "visits:desc" || f.lastQ.Get("aggregates") != "visits,uniques" || f.lastQ.Get("entity") != "pageview" || f.lastQ.Get("limit") != "2" {
		t.Fatal(f.lastQ)
	}
	if _, err := invoke(m, "aggregation", `{"site":"CDBUGS","dateGrouping":"day","from":"2026-01-01","to":"2026-12-31"}`); err != nil {
		t.Fatal(err)
	}
	if f.lastQ.Get("date_grouping") != "day" || f.lastQ.Get("date_to") != "2026-12-31 23:59:59" || f.lastQ.Get("sort_by") != "timestamp:asc" || len(strings.Split(f.lastQ.Get("aggregates"), ",")) != 5 {
		t.Fatal(f.lastQ)
	}
	r, err = invoke(m, "current_visitors", `{"site":"CDBUGS"}`)
	if err != nil || !strings.Contains(string(r.Output), `"visitors":3`) || !strings.Contains(string(r.Output), `"hostname":"google.com"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "aggregation", `{"site":"NOPE"}`); err == nil || !strings.Contains(err.Error(), "may not read") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestFathomBadKey(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	h := m.Health(context.Background(), "f")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the API key") || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "aggregation", `{"site":"CDBUGS"}`); err == nil || strings.Contains(err.Error(), "LEAKME") {
		t.Fatal(err)
	}
}

func TestFathomValidation(t *testing.T) {
	m, f := setup(t, "secret://fa")
	for _, c := range []struct{ action, in string }{
		{"aggregation", `{}`},
		{"aggregation", `{"site":"../sites"}`},
		{"aggregation", `{"site":"AB&entity=event"}`},
		{"aggregation", `{"site":"CDBUGS","aggregates":["revenue"]}`},
		{"aggregation", `{"site":"CDBUGS","aggregates":["visits","visits"]}`},
		{"aggregation", `{"site":"CDBUGS","groupBy":["ip"]}`},
		{"aggregation", `{"site":"CDBUGS","groupBy":["pathname","hostname","browser","country_code"]}`},
		{"aggregation", `{"site":"CDBUGS","dateGrouping":"minute"}`},
		{"aggregation", `{"site":"CDBUGS","limit":1001}`},
		{"aggregation", `{"site":"CDBUGS","days":367}`},
		{"aggregation", `{"site":"CDBUGS","from":"2025-01-01","to":"2026-01-02"}`},
		{"aggregation", `{"site":"CDBUGS","from":"2026-01-02","to":"2026-01-01"}`},
		{"aggregation", `{"site":"CDBUGS","to":"2026-01-01"}`},
		{"aggregation", `{"site":"CDBUGS","days":3,"from":"2026-01-01","to":"2026-01-02"}`},
		{"current_visitors", `{"site":"a b"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Errorf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"plainkey"}`, `[`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestFathomRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	m, f := setup(t, "secret://fa")
	f.redirect = evil.URL + "/v1/sites"
	if _, err := invoke(m, "sites", `{}`); !errors.Is(err, rest.ErrCrossHostRedirect) || hit {
		t.Fatalf("followed the redirect: %v", err)
	}
}
