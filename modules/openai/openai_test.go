package openai

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

const adminKey = "sk-admin-goodgoodgoodgoodgoodgood"
const apiKey = "sk-proj-goodgoodgoodgoodgoodgoodgood"

type fake struct {
	mu   sync.Mutex
	seen []string
}

// 2026-11-02, 2026-11-03 and 2026-11-04 00:00 UTC.
const d2, d3, d4 = "1793577600", "1793664000", "1793750400"

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+adminKey && auth != "Bearer "+apiKey {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided: sk-nope****nope.","type":"invalid_request_error","code":"invalid_api_key"}}`)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/organization/") && auth != "Bearer "+adminKey {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":{"message":"You have insufficient permissions for this operation. Missing scopes: api.usage.read."}}`)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/organization/usage/completions":
		if q.Get("start_time") != d2 || q.Get("end_time") != d4 || q.Get("bucket_width") != "1d" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"bad range"}}`)
			return
		}
		if q.Get("page") == "" {
			io.WriteString(w, `{"object":"page","data":[{"object":"bucket","start_time":`+d2+`,"end_time":`+d3+`,"results":[
				{"object":"organization.usage.completions.result","input_tokens":1000,"input_cached_tokens":400,"output_tokens":500,"num_model_requests":5,"model":"gpt-6","project_id":null,"user_id":"user-abc","api_key_id":"key_abcdefghijklmnopqrstuvwxyz"},
				{"object":"organization.usage.completions.result","input_tokens":10,"input_cached_tokens":0,"output_tokens":5,"num_model_requests":1,"model":"gpt-6-mini","project_id":"proj_abc"}]}],
				"has_more":true,"next_page":"page_AAAAAGdGxdEiJdKOAAAAAGcqsYA="}`)
			return
		}
		io.WriteString(w, `{"object":"page","data":[{"object":"bucket","start_time":`+d3+`,"end_time":`+d4+`,"results":[
			{"object":"organization.usage.completions.result","input_tokens":2000,"input_cached_tokens":0,"output_tokens":100,"num_model_requests":2,"model":"gpt-6","project_id":"proj_abc"}]}],
			"has_more":false,"next_page":null}`)
	case "/organization/costs":
		if q.Get("limit") == "1" {
			io.WriteString(w, `{"object":"page","data":[],"has_more":false,"next_page":null}`)
			return
		}
		io.WriteString(w, `{"object":"page","data":[
			{"object":"bucket","start_time":`+d2+`,"end_time":`+d3+`,"results":[
				{"object":"organization.costs.result","amount":{"value":0.06,"currency":"usd"},"line_item":"gpt-6, input","project_id":"proj_abc"},
				{"object":"organization.costs.result","amount":{"value":1.2345678,"currency":"usd"},"line_item":"gpt-6, output","project_id":null}]},
			{"object":"bucket","start_time":`+d3+`,"end_time":`+d4+`,"results":[
				{"object":"organization.costs.result","amount":{"value":0.04,"currency":"usd"},"line_item":"gpt-6, input","project_id":"proj_abc"}]}],
			"has_more":false,"next_page":null}`)
	case "/models":
		io.WriteString(w, `{"object":"list","data":[{"id":"gpt-6","object":"model","created":1793577600,"owned_by":"openai"},{"id":"whisper-1","object":"model","created":1677532384,"owned_by":"openai-internal"}]}`)
	default:
		w.WriteHeader(404)
	}
}

var secrets = map[string]string{"secret://admin": adminKey, "secret://api": apiKey, "secret://bad": "sk-nopenopenopenopenopenope"}

func setup(t *testing.T, cfg Config) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in)})
}

func TestOpenAIReads(t *testing.T) {
	m, _ := setup(t, Config{AdminKey: "secret://admin", APIKey: "secret://api"})
	if h := m.Health(context.Background(), "o"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	rng := `"from":"2026-11-02","to":"2026-11-03"`
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"usage", `{` + rng + `}`, []string{`"total":{"inputTokens":3010,"cachedInputTokens":400,"outputTokens":605,"requests":8}`,
			`"groups":[{"model":"gpt-6","inputTokens":3000`, `"groupCount":2`, `{"date":"2026-11-03","inputTokens":2000`}},
		{"usage", `{` + rng + `,"groupBy":["project","model"]}`, []string{`"project":"default"`, `"project":"proj_abc"`, `"groupCount":3`}},
		{"usage", `{` + rng + `,"groupBy":["batch"]}`, []string{`"batch":false`, `"groupCount":1`}},
		{"costs", `{` + rng + `}`, []string{`"totals":{"USD":"1.334568"}`, `{"lineItem":"gpt-6, output","currency":"USD","amount":"1.234568"}`, `{"lineItem":"gpt-6, input","currency":"USD","amount":"0.10"}`, `{"date":"2026-11-03","totals":{"USD":"0.04"}}`}},
		{"costs", `{` + rng + `,"groupBy":["project"]}`, []string{`"project":"proj_abc","currency":"USD","amount":"0.10"`, `"project":"default"`}},
		{"models", `{"search":"gpt"}`, []string{`{"id":"gpt-6","ownedBy":"openai","created":"2026-11-02"}`, `"matching":1`}},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil {
			t.Fatalf("%s %s: %v", c.action, c.in, err)
		}
		out := string(r.Output)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Fatalf("%s %s: want %s in %s", c.action, c.in, w, out)
			}
		}
		for _, s := range []string{adminKey, apiKey, "user-abc", "key_abcdefghijklmnopqrstuvwxyz"} {
			if strings.Contains(out, s) {
				t.Fatalf("output has %q: %s", s, out)
			}
		}
	}
}

func TestOpenAIRefusals(t *testing.T) {
	m, f := setup(t, Config{AdminKey: "secret://admin"})
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"usage", `{"from":"2026-01-01","to":"2026-11-03"}`},
		{"usage", `{"to":"2026-11-05"}`},
		{"usage", `{"from":"2026-11-02T00:00:00Z"}`},
		{"usage", `{"groupBy":["user_id"]}`},
		{"usage", `{"groupBy":["api_key_id"]}`},
		{"costs", `{"groupBy":["model"]}`},
		{"models", `{}`},
		{"models", `{"search":"a&b=c"}`},
		{"delete_admin_key", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	wrong, _ := setup(t, Config{AdminKey: "secret://api"})
	if h := wrong.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "need an Admin key") {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{AdminKey: "secret://bad", APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "refused the Admin key") || strings.Contains(h.Message, "sk-") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "models", ``); err == nil || !strings.Contains(err.Error(), "refused the API key") {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"adminKey":"` + adminKey + `"}`, `{"adminKey":"secret://admin","apiKey":"` + apiKey + `"}`, `[`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestOpenAIRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{AdminKey: "secret://admin"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
