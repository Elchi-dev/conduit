package meilisearch

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
	mu      sync.Mutex
	seen    []string
	deleted []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		io.WriteString(w, `{"status":"available"}`)
		return
	}
	switch r.Header.Get("Authorization") {
	case "Bearer mkey":
	case "":
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"The Authorization header is missing.","code":"missing_authorization_header","type":"auth"}`)
		return
	default:
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"The provided API key is invalid.","code":"invalid_api_key","type":"auth"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /version":
		io.WriteString(w, `{"pkgVersion":"1.11.0"}`)
	case "GET /stats":
		io.WriteString(w, `{"databaseSize":4096000,"lastUpdate":"2026-11-04T10:00:00Z","indexes":{"movies":{"numberOfDocuments":31944,"isIndexing":false}}}`)
	case "GET /indexes":
		io.WriteString(w, `{"results":[{"uid":"movies","primaryKey":"id","createdAt":"2026-01-01T00:00:00Z"}],"total":1}`)
	case "GET /indexes/movies":
		io.WriteString(w, `{"uid":"movies","primaryKey":"id"}`)
	case "GET /indexes/movies/stats":
		io.WriteString(w, `{"numberOfDocuments":31944,"isIndexing":false}`)
	case "POST /indexes/movies/search":
		io.WriteString(w, `{"hits":[{"id":1,"title":"Carol"}],"estimatedTotalHits":1,"processingTimeMs":2,"query":"carol"}`)
	case "GET /tasks":
		io.WriteString(w, `{"results":[{"uid":7,"indexUid":"movies","status":"failed","type":"documentAdditionOrUpdate","enqueuedAt":"2026-11-04T10:00:00Z","error":{"message":"Document doesn't have a id attribute: {\"title\":\"x\",\"apiKey\":\"abcdefghijklmnopqrstuvwxyz\"}","code":"missing_document_id"}}]}`)
	case "GET /keys":
		io.WriteString(w, `{"results":[{"uid":"6062abda-a5aa-4414-ac91-ecd7944c0f8d","key":"d0552b41536279a0ad88bd595327b96f01176a60c2243e906c52ac02375f9bc4","name":"Default Search API Key","actions":["search"],"indexes":["*"],"expiresAt":null}]}`)
	case "DELETE /indexes/movies":
		f.deleted = append(f.deleted, "movies")
		w.WriteHeader(202)
		io.WriteString(w, `{"taskUid":12,"indexUid":"movies","status":"enqueued","type":"indexDeletion"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Index not found.","code":"index_not_found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://m": "mkey", "secret://s": "skey"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestReads(t *testing.T) {
	m, f := setup(t, "secret://m")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "Meilisearch 1.11.0" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"health", `{}`, `"databaseBytes":4096000`},
		{"indexes", `{}`, `"documents":31944`},
		{"search", `{"index":"movies","q":"carol","filter":"year > 2000","sort":["year:desc"],"attributes":["title"],"limit":5}`, `"hits":[{"id":1,"title":"Carol"}]`},
		{"tasks", `{"status":"failed","index":"movies"}`, `"errorCode":"missing_document_id"`},
		{"keys", `{}`, `"name":"Default Search API Key"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
		if strings.Contains(string(r.Output), "d0552b41") || strings.Contains(string(r.Output), "abcdefghijklmnop") {
			t.Fatalf("%s returned a key: %s", c.action, r.Output)
		}
	}
	var search, tasks string
	for _, s := range f.seen {
		if strings.Contains(s, "/search") {
			search = s
		}
		if strings.Contains(s, "/tasks") {
			tasks = s
		}
	}
	if !strings.Contains(search, `"limit":5`) || !strings.Contains(search, `"attributesToRetrieve":["title"]`) || !strings.Contains(tasks, "statuses=failed") || !strings.Contains(tasks, "indexUids=movies") {
		t.Fatal(search, tasks)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "search", "tasks":
			if !a.Sensitive || a.Risk != sdk.RiskRead {
				t.Fatal(a.Name)
			}
		case "keys":
			if a.Sensitive || a.Risk != sdk.RiskRead {
				t.Fatal(a.Name)
			}
		case "delete_index":
			if a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestDeleteIndex(t *testing.T) {
	m, f := setup(t, "secret://m")
	r, err := invoke(m, "delete_index", `{"index":"movies"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "31944 documents") || !strings.Contains(r.Plan.Summary, "no undo") || len(f.deleted) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_index", `{"index":"movies"}`, false)
	if err != nil || len(f.deleted) != 1 || !strings.Contains(string(r.Output), `"taskUid":12`) || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "delete_index", `{"index":"books"}`, false); err == nil || !strings.Contains(err.Error(), "no index books") {
		t.Fatal(err)
	}
}

func TestValidation(t *testing.T) {
	m, f := setup(t, "secret://m")
	for _, c := range []struct{ action, in string }{
		{"search", `{"index":"../keys"}`},
		{"search", `{"index":"movies/documents"}`},
		{"search", `{"index":"movies?x"}`},
		{"search", `{"index":""}`},
		{"search", `{"index":"movies","limit":1000}`},
		{"search", `{"index":"movies","limit":0}`},
		{"search", `{"index":"movies","offset":-1}`},
		{"search", `{"index":"movies","sort":["year"]}`},
		{"search", `{"index":"movies","attributes":["a b"]}`},
		{"tasks", `{"status":"weird"}`},
		{"tasks", `{"limit":500}`},
		{"tasks", `{"index":"a/b"}`},
		{"delete_index", `{"index":"*"}`},
		{"delete_index", `{"index":"../keys"}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal(f.seen)
	}
	for _, c := range []Config{{URL: "ftp://x"}, {URL: "http://u:p@x"}, {URL: "http://x", APIKey: "plain"}, {URL: "https://x", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	search, _ := setup(t, "secret://s")
	if h := search.Health(context.Background(), "s"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	none, _ := setup(t, "")
	if _, err := invoke(none, "keys", `{}`, false); err == nil || !strings.Contains(err.Error(), "API key is needed") {
		t.Fatal(err)
	}
}

func TestRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://m"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://m": "mkey"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "keys", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
