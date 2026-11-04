package elasticsearch

import (
	"context"
	"encoding/base64"
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
	auth    string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != f.auth {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"type":"security_exception","reason":"missing authentication credentials"},"status":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /_cluster/health":
		io.WriteString(w, `{"cluster_name":"prod","status":"yellow","number_of_nodes":3,"unassigned_shards":2}`)
	case "GET /_cat/nodes":
		io.WriteString(w, `[{"name":"n1","ip":"10.0.0.1","node.role":"cdfhilmrstw","master":"*","heap.percent":"41","cpu":"7","load_1m":"0.5","disk.used_percent":"63.2","version":"8.15.0"}]`)
	case "GET /_cat/indices":
		io.WriteString(w, `[{"index":"logs-2026.11","health":"green","status":"open","docs.count":"1200","store.size":"52000","pri":"1","rep":"1"},{"index":".kibana_1","health":"green","status":"open","docs.count":"9","store.size":"100"}]`)
	case "GET /_cat/indices/logs-2026.11", "GET /_cat/indices/hid":
		name := strings.TrimPrefix(r.URL.Path, "/_cat/indices/")
		io.WriteString(w, `[{"index":"`+name+`","health":"green","status":"open","docs.count":"1200","store.size":"52000","pri":"1","rep":"1"}]`)
	case "GET /_cat/indices/alias1":
		io.WriteString(w, `[{"index":"logs-a"},{"index":"logs-b"}]`)
	case "GET /_cat/indices/missing":
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"type":"index_not_found_exception"},"status":404}`)
	case "GET /logs-2026.11/_settings/index.hidden":
		io.WriteString(w, `{}`)
	case "GET /hid/_settings/index.hidden":
		io.WriteString(w, `{"hid":{"settings":{"index":{"hidden":"true"}}}}`)
	case "POST /logs-*,-.*/_search", "POST /logs-2026.11/_search":
		io.WriteString(w, `{"took":3,"timed_out":false,"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_index":"logs-2026.11","_id":"a1","_score":1.5,"_source":{"message":"timeout talking to db","email":"ann@example.com"}}]},"aggregations":{"by":{"buckets":[]}}}`)
	case "DELETE /logs-2026.11":
		f.deleted = append(f.deleted, r.URL.Path+"?"+r.URL.RawQuery)
		io.WriteString(w, `{"acknowledged":true}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"no handler"}`)
	}
}

func setup(t *testing.T, cfg Config, auth string) (*Module, *fake) {
	f := &fake{auth: auth}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "a2V5", "secret://pw": "hunter2"}), "e", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "e", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestReads(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://k"}, "ApiKey a2V5")
	if h := m.Health(context.Background(), "e"); h.Status != "degraded" || !strings.Contains(h.Message, "prod: yellow, 3 nodes, 2 unassigned") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"health", `{}`, `"status":"yellow"`},
		{"nodes", `{}`, `"diskUsedPercent":63.2`},
		{"indices", `{}`, `"bytes":52000,"docs":1200`},
		{"search", `{"index":"logs-*","query":{"match":{"message":"timeout"}},"size":5}`, `"id":"a1"`},
		{"search", `{"index":"logs-2026.11","q":"message:timeout"}`, `"total":1`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "indices", `{}`, false)
	if strings.Contains(string(r.Output), "kibana") {
		t.Fatal("hidden index listed", string(r.Output))
	}
	if r, _ := invoke(m, "indices", `{"includeHidden":true}`, false); !strings.Contains(string(r.Output), "kibana") {
		t.Fatal(string(r.Output))
	}
	var search string
	for _, s := range f.seen {
		if strings.Contains(s, "_search") && strings.Contains(s, "match") {
			search = s
		}
	}
	if !strings.Contains(search, `"size":5`) || !strings.Contains(search, `"timeout":"10s"`) || !strings.Contains(search, "expand_wildcards=open") {
		t.Fatal(search)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "search" && (!a.Sensitive || a.Risk != sdk.RiskRead) {
			t.Fatal("search must be a sensitive read")
		}
		if a.Name == "delete_index" && (a.Risk != sdk.RiskDestructive || !a.DryRun || a.Reversible) {
			t.Fatal("delete_index must be destructive with a preview")
		}
	}
}

func TestBasicAuth(t *testing.T) {
	m, _ := setup(t, Config{Username: "elastic", Password: "secret://pw"}, "Basic ZWxhc3RpYzpodW50ZXIy")
	if h := m.Health(context.Background(), "e"); h.Status != "degraded" {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{Username: "elastic", Password: "secret://pw"}, "Basic other")
	if _, err := invoke(bad, "health", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused the credentials") || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestSearchRefusals(t *testing.T) {
	m, f := setup(t, Config{}, "")
	for _, in := range []string{
		`{"index":"logs","query":{"script":{"script":{"source":"doc['a'].value > 1"}}}}`,
		`{"index":"logs","query":{"bool":{"filter":[{"script":{"script":"1"}}]}}}`,
		`{"index":"logs","query":{"function_score":{"script_score":{"script":"x"}}}}`,
		`{"index":"logs","aggs":{"x":{"scripted_metric":{"map_script":"x"}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","Script":"x"}}}}`,
		`{"index":"logs","sort":[{"_script":{"type":"number","script":"x"}}]}`,
		`{"index":"logs","query":{"terms":{"user":{"index":".security","id":"1","path":"x"}}}}`,
		`{"index":"logs","query":{"more_like_this":{"like":[{"_index":".tasks","_id":"1"}]}}}`,
		`{"index":"logs","query":{"x":{"lang":"painless"}}}`,
		`{"index":"logs","query":{"match_all":{}},"q":"a"}`,
		`{"index":"logs","size":1000}`,
		`{"index":"logs","from":9999,"size":10}`,
		`{"index":"logs","query":"not json`,
		`{"index":".security"}`,
		`{"index":"logs,.security"}`,
		`{"index":"_all"}`,
		`{"index":"logs/_update_by_query"}`,
		`{"index":"logs/_delete_by_query"}`,
		`{"index":"_delete_by_query"}`,
		`{"index":"remote:logs"}`,
		`{"index":"Logs"}`,
		`{"index":"logs?x=1"}`,
		`{"index":""}`,
		`{"index":"logs","query":` + strings.Repeat(`{"bool":{"must":[`, 20) + `{}` + strings.Repeat(`]}}`, 20) + `}`,
	} {
		if _, err := invoke(m, "search", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("refused searches reached the server: %v", f.seen)
	}
	// A word in a match query is fine, even "painless" or "script" as text.
	if _, err := invoke(m, "search", `{"index":"logs-2026.11","query":{"match":{"message":"a script error"}}}`, false); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteIndex(t *testing.T) {
	m, f := setup(t, Config{}, "")
	r, err := invoke(m, "delete_index", `{"index":"logs-2026.11"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "1200 documents, 52000 bytes") || !strings.Contains(r.Plan.Summary, "no undo") || len(f.deleted) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "delete_index", `{"index":"logs-2026.11"}`, false)
	if err != nil || len(f.deleted) != 1 || !strings.Contains(f.deleted[0], "expand_wildcards=none") || r.Undo != nil {
		t.Fatalf("%v %v %v", f.deleted, err, r)
	}
	for in, want := range map[string]string{
		`{"index":"logs-*"}`:       "exact index name",
		`{"index":"*"}`:            "",
		`{"index":"a,b"}`:          "exact index name",
		`{"index":".kibana_1"}`:    "system",
		`{"index":".ds-logs-1"}`:   "system",
		`{"index":"_all"}`:         "isn't an index",
		`{"index":"alias1"}`:       "alias",
		`{"index":"hid"}`:          "hidden",
		`{"index":"missing"}`:      "no index missing",
		`{"index":"a/../b"}`:       "",
		`{"index":"logs-2026.1?"}`: "",
	} {
		_, err := invoke(m, "delete_index", in, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", in, err)
		}
	}
	if len(f.deleted) != 1 {
		t.Fatal(f.deleted)
	}
}

func TestConfigure(t *testing.T) {
	for _, c := range []Config{
		{URL: "ftp://x"},
		{URL: "http://u:p@x:9200"},
		{URL: "http://x:9200?x=1"},
		{URL: "http://x:9200", APIKey: "plain"},
		{URL: "http://x:9200", Username: "u", Password: "plain"},
		{URL: "http://x:9200", Username: "u"},
		{URL: "http://x:9200", APIKey: "secret://k", Username: "u", Password: "secret://p"},
		{URL: "https://x:9200", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if h := New().Health(context.Background(), "nope"); h.Status != "unconfigured" {
		t.Fatal(h)
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
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "a2V5"}), "e", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "health", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}

// A wrapper query (base64 DSL), date math or another cluster in a lookup
// index, duplicate keys and oversized aggregations are refused.
func TestSearchRefusalsWrapperLookupAggs(t *testing.T) {
	inner := `{"script":{"script":{"source":"int i=0; while(i<1000000){i++} return true"}}}`
	enc := base64.StdEncoding.EncodeToString([]byte(inner))
	m, f := setup(t, Config{}, "")
	for _, in := range []string{
		`{"index":"logs","query":{"wrapper":{"query":"` + enc + `"}}}`,
		`{"index":"logs","query":{"bool":{"must":[{"WRAPPER":{"query":"` + enc + `"}}]}}}`,
		`{"index":"logs","query":{"terms":{"user":{"index":"<.security-{now/d}>","id":"1","path":"x"}}}}`,
		`{"index":"logs","query":{"terms":{"user":{"index":"%3C.security%3E","id":"1","path":"x"}}}}`,
		`{"index":"logs","query":{"terms":{"user":{"index":"other:.security","id":"1","path":"x"}}}}`,
		`{"index":"logs","query":{"terms":{"user":{"index":"users,.security","id":"1","path":"x"}}}}`,
		`{"index":"logs","query":{"more_like_this":{"like":[{"_index":" .tasks","_id":"1"}]}}}`,
		`{"index":"logs","query":{"bool":{"filter":[{"script":{"script":"1"}}],"filter":[]}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","size":1001}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","size":"50000"}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","shard_size":100000}}}}`,
		`{"index":"logs","aggs":{"x":{"top_hits":{"size":101}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","size":1000},"aggs":{"y":{"terms":{"field":"b","size":100}}}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","size":500},"aggs":{"y":{"terms":{"field":"b"},"aggs":{"z":{"composite":{"sources":[]}}}}}}}}`,
		`{"index":"logs","aggs":{"x":{"terms":{"field":"a","size":"lots"}}}}`,
		`{"index":"logs","aggs":[1]}`,
		`{"index":"logs","query":{"nested":{"path":"p","query":{"match_all":{}},"inner_hits":{"size":5000}}}}`,
	} {
		if _, err := invoke(m, "search", in, false); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("refused searches reached the server: %v", f.seen)
	}
	for _, in := range []string{
		`{"index":"logs-2026.11","aggs":{"x":{"terms":{"field":"a","size":100},"aggs":{"y":{"terms":{"field":"b","size":100},"aggs":{"top":{"top_hits":{"size":3}}}}}}}}`,
		`{"index":"logs-2026.11","aggs":{"h":{"date_histogram":{"field":"@timestamp","calendar_interval":"day"},"aggs":{"s":{"terms":{"field":"status"}}}}}}`,
		`{"index":"logs-2026.11","query":{"terms":{"user":{"index":"users","id":"1","path":"x"}}}}`,
		`{"index":"logs-2026.11","query":{"term":{"size":5000}}}`,
	} {
		if _, err := invoke(m, "search", in, false); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}
