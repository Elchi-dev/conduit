package openrouter

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
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if auth != "Bearer sk-or-v1-good" && auth != "Bearer sk-or-v1-plain" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"No auth credentials found","code":401}}`)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	switch r.URL.Path {
	case "/key":
		io.WriteString(w, `{"data":{"label":"sk-or-v1-abc...def","limit":20,"limit_remaining":12.5,"usage":7.5,"usage_daily":0.25,"usage_weekly":1.5,"usage_monthly":7.5,"is_free_tier":false,"is_provisioning_key":false}}`)
	case "/credits":
		io.WriteString(w, `{"data":{"total_credits":50,"total_usage":12.25}}`)
	case "/models":
		io.WriteString(w, `{"data":[
			{"id":"openai/gpt-4o","name":"OpenAI: GPT-4o","context_length":128000,"pricing":{"prompt":"0.0000025","completion":"0.00001"},"architecture":{"input_modalities":["text","image"],"output_modalities":["text"]}},
			{"id":"meta-llama/llama-3.3-70b-instruct:free","name":"Llama 3.3 70B (free)","context_length":131072,"pricing":{"prompt":"0","completion":"0"}},
			{"id":"anthropic/claude-sonnet-4.5","name":"Anthropic: Claude Sonnet 4.5","context_length":200000,"pricing":{"prompt":"0.000003","completion":"0.000015"}}]}`)
	case "/activity":
		if auth != "Bearer sk-or-v1-good" {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"message":"Only provisioning keys can fetch activity"}}`)
			return
		}
		if d := r.URL.Query().Get("date"); d != "" && d != "2026-11-03" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		io.WriteString(w, `{"data":[
			{"date":"2026-11-03","model":"openai/gpt-4o","provider_name":"OpenAI","usage":0.5,"requests":10,"prompt_tokens":1000,"completion_tokens":200},
			{"date":"2026-11-02","model":"openai/gpt-4o","provider_name":"Azure","usage":0.25,"requests":4,"prompt_tokens":500,"completion_tokens":100},
			{"date":"2026-11-03","model":"anthropic/claude-sonnet-4.5","provider_name":"Anthropic","usage":1,"requests":2,"prompt_tokens":3000,"completion_tokens":800}]}`)
	default:
		w.WriteHeader(404)
	}
}

var secrets = map[string]string{"secret://or": "sk-or-v1-good", "secret://plain": "sk-or-v1-plain", "secret://bad": "nope"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in)})
}

func TestOpenRouterReads(t *testing.T) {
	m, _ := setup(t, "secret://or")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || !strings.Contains(h.Message, "sk-or-v1-abc...def") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"credits", ``, `"left":37.75`},
		{"key_info", ``, `"usageToday":0.25`},
		{"models", `{"sort":"price"}`, `"id":"meta-llama/llama-3.3-70b-instruct:free"`},
		{"models", `{"search":"gpt"}`, `"inputPerMillion":2.5,"outputPerMillion":10`},
		{"models", `{"free":true}`, `"matching":1`},
		{"activity", ``, `"spend":1.75`},
		{"activity", `{"date":"2026-11-03"}`, `"byModel":[{"model":"anthropic/claude-sonnet-4.5","spend":1}`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "sk-or-v1-good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "models", `{"sort":"price"}`)
	if s := string(r.Output); strings.Index(s, "llama") > strings.Index(s, "gpt-4o") {
		t.Fatalf("not cheapest first: %s", s)
	}
}

func TestOpenRouterRefusals(t *testing.T) {
	m, f := setup(t, "secret://or")
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"models", `{"search":"a&b=c"}`},
		{"models", `{"sort":"random"}`},
		{"activity", `{"date":"2026-13-45"}`},
		{"activity", `{"date":"yesterday"}`},
		{"buy_credits", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	// A regular key can't read activity.
	p, _ := setup(t, "secret://plain")
	if _, err := invoke(p, "activity", ``); err == nil || !strings.Contains(err.Error(), "provisioning key") {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"sk-or-v1-good"}`} {
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

func TestOpenRouterRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://or"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
