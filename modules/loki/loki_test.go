package loki

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

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fakeLoki struct {
	mu   sync.Mutex
	seen []*http.Request
}

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer loki-good" || r.Header.Get("X-Scope-OrgID") != "team-a" {
		w.WriteHeader(401)
		io.WriteString(w, "no org id")
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/loki/api/v1/labels":
		io.WriteString(w, `{"status":"success","data":["job","app","level"]}`)
	case "/loki/api/v1/label/app/values":
		io.WriteString(w, `{"status":"success","data":["nginx","api"]}`)
	case "/loki/api/v1/status/buildinfo":
		io.WriteString(w, `{"version":"3.2.0"}`)
	case "/loki/api/v1/query_range":
		q := r.URL.Query().Get("query")
		switch {
		case strings.HasPrefix(q, "sum"):
			io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"level":"error"},"values":[[1762257600,"3"],[1762257660,"5"]]}]}}`)
		case strings.Contains(q, "bad"):
			w.WriteHeader(400)
			io.WriteString(w, "parse error at line 1, col 5: syntax error")
		default:
			long := strings.Repeat("x", 3000)
			io.WriteString(w, `{"status":"success","data":{"resultType":"streams","result":[
				{"stream":{"app":"nginx"},"values":[["1762257600000000000","GET / 200"],["1762257720000000000","`+long+`"]]},
				{"stream":{"app":"api"},"values":[["1762257660000000000","error: db down"]]}]}}`)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeLoki) {
	f := &fakeLoki{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL, Tenant: "team-a", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://loki": "loki-good", "secret://bad": "loki-bad"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in)})
}

func TestLoki(t *testing.T) {
	m, f := setup(t, "secret://loki")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "Loki 3.2.0 · 3 labels in the last hour" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "labels", `{}`)
	if err != nil || string(r.Output) != `{"truncated":false,"values":["app","job","level"]}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "label_values", `{"label":"app"}`); err != nil || !strings.Contains(string(r.Output), `["api","nginx"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// A log query: lines merged newest first, long ones cut, limit kept.
	r, err = invoke(m, "query", `{"query":"{app=~\".+\"}","limit":2,"sinceMinutes":30}`)
	if err != nil {
		t.Fatal(err)
	}
	var logs struct {
		Lines []struct {
			Line string `json:"line"`
			Cut  bool   `json:"cut"`
		} `json:"lines"`
		Truncated bool `json:"truncated"`
	}
	json.Unmarshal(r.Output, &logs)
	if len(logs.Lines) != 2 || !logs.Lines[0].Cut || len(logs.Lines[0].Line) > maxLine+4 || logs.Lines[1].Line != "error: db down" || !logs.Truncated {
		t.Fatalf("%s", r.Output)
	}
	last := f.seen[len(f.seen)-1].URL.Query()
	if last.Get("limit") != "2" || last.Get("direction") != "backward" || last.Get("start") != ns(now.Add(-30*time.Minute)) || last.Get("step") != "7.2" {
		t.Fatal(last)
	}
	// A metric query.
	if r, err := invoke(m, "query", `{"query":"sum by (level) (count_over_time({app=\"api\"}[1m]))"}`); err != nil || !strings.Contains(string(r.Output), `"type":"metric"`) || !strings.Contains(string(r.Output), `["2025-11-04T12:00:00Z","3"]`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "query", `{"query":"{app=\"bad\"} |"}`); err == nil || !strings.Contains(err.Error(), "couldn't run the query") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "query" && !a.Sensitive {
			t.Fatal("log queries must be sensitive")
		}
	}
}

func TestLokiValidation(t *testing.T) {
	m, f := setup(t, "secret://loki")
	for _, c := range []struct{ action, in string }{
		{"query", `{}`},
		{"query", `{"query":"   "}`},
		{"query", `{"query":"{a=\"b\"}\u0000"}`},
		{"query", `{"query":"` + strings.Repeat("a", maxQuery+1) + `"}`},
		{"query", `{"query":"{a=\"b\"}","sinceMinutes":20000}`},
		{"query", `{"query":"{a=\"b\"}","limit":5000}`},
		{"query", `{"query":"{a=\"b\"}","direction":"sideways"}`},
		{"query", `{"query":"{a=\"b\"}","sinceMinutes":10080,"stepSeconds":1}`},
		{"query", `{"query":"{a=\"b\"}","stepSeconds":36028797018963968}`},
		{"query", `{"query":"count_over_time({a=\"b\"}[30d])"}`},
		{"label_values", `{"label":"../labels"}`},
		{"label_values", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %d requests", len(f.seen))
	}
	for _, c := range []Config{
		{URL: "http://loki:3100", Token: "plain"},
		{URL: "http://loki:3100", Username: "123", Password: "glc_plain"},
		{URL: "http://loki:3100", Password: "secret://p"},
		{URL: "http://loki:3100", Tenant: "a b"},
		{URL: "loki:3100"},
		{URL: "http://u:p@loki:3100"},
		{URL: "http://loki:3100?x=1"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || h.Message != "Loki refused the credentials" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "labels", `{}`); err == nil || strings.Contains(err.Error(), "loki-bad") {
		t.Fatal(err)
	}
}

func TestLokiRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "u", Password: "secret://p"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "pw"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestLokiBoundsLookback(t *testing.T) {
	for _, q := range []string{
		`count_over_time({a="b"}[8d])`,
		`count_over_time({a="b"}[1y])`,
		`count_over_time({a="b"}[169h])`,
		`count_over_time({a="b"}[5m] offset 7d)`,
		`count_over_time({a="b"}[5m] OFFSET -30d)`,
		`count_over_time({a="b"}[6d]) / count_over_time({a="b"}[1h] offset 2d)`,
		`count_over_time({a="b"}[$__range])`,
		`count_over_time({a="b"}[5m`,
		`count_over_time({a="b"}[99999999999999999999y])`,
		`count_over_time({a="b"} |= "x # [" [30d])`,
		`{a="b} [1m]`,
		"count_over_time({a=\"b\"} # \" hidden\n[30d])",
	} {
		if err := CheckQuery(q); err == nil {
			t.Errorf("accepted %s", q)
		}
	}
	for _, q := range []string{
		`{app="nginx"} |= "error"`,
		`{app="nginx"} |~ "[0-9]+ [a-z]{3}" | json offset="x"`,
		"{app=\"nginx\"} |= `[30d]`",
		`sum by (level) (count_over_time({app="nginx"} | logfmt [5m]))`,
		`rate({a="b"}[1h30m] offset 1d)`,
		`count_over_time({a="b"}[7d])`,
		`count_over_time({a="b"}[1.5h]) # a comment [30d]`,
		`{a="b"} | offset > 5`,
	} {
		if err := CheckQuery(q); err != nil {
			t.Errorf("refused %s: %v", q, err)
		}
	}
}
