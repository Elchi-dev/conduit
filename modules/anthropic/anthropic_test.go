package anthropic

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

const adminKey = "sk-ant-admin01-goodgoodgoodgoodgood"
const apiKey = "sk-ant-api03-goodgoodgoodgoodgoodgood"

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	key := r.Header.Get("x-api-key")
	if r.Header.Get("anthropic-version") == "" || (key != adminKey && key != apiKey) {
		w.WriteHeader(401)
		io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	admin := strings.HasPrefix(r.URL.Path, "/v1/organizations/")
	if admin && key != adminKey {
		w.WriteHeader(403)
		io.WriteString(w, `{"type":"error","error":{"type":"permission_error","message":"admin key required"}}`)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/v1/organizations/me":
		io.WriteString(w, `{"id":"12345678-1234-5678-1234-567812345678","name":"Acme","type":"organization"}`)
	case "/v1/organizations/usage_report/messages":
		if q.Get("starting_at") != "2026-11-02T00:00:00Z" || q.Get("ending_at") != "2026-11-04T00:00:00Z" || q.Get("bucket_width") != "1d" {
			w.WriteHeader(400)
			io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"bad range `+r.URL.RawQuery+`"}}`)
			return
		}
		byWS := len(q["group_by[]"]) == 2
		if q.Get("page") == "" {
			ws := ``
			if byWS {
				ws = `,"workspace_id":null`
			}
			io.WriteString(w, `{"data":[{"starting_at":"2026-11-02T00:00:00Z","ending_at":"2026-11-03T00:00:00Z","results":[
				{"uncached_input_tokens":100,"cache_creation":{"ephemeral_1h_input_tokens":10,"ephemeral_5m_input_tokens":5},"cache_read_input_tokens":50,"output_tokens":40,"server_tool_use":{"web_search_requests":1},"model":"claude-opus-5-5","api_key_id":"apikey_01Rj2N8SVvo6BePZj99NhmiT"`+ws+`},
				{"uncached_input_tokens":10,"cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0},"cache_read_input_tokens":0,"output_tokens":5,"server_tool_use":{"web_search_requests":0},"model":"claude-haiku-4-5"`+ws+`}]}],
				"has_more":true,"next_page":"page_Mg=="}`)
			return
		}
		io.WriteString(w, `{"data":[{"starting_at":"2026-11-03T00:00:00Z","ending_at":"2026-11-04T00:00:00Z","results":[
			{"uncached_input_tokens":200,"cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0},"cache_read_input_tokens":0,"output_tokens":60,"server_tool_use":{"web_search_requests":0},"model":"claude-opus-5-5","workspace_id":"wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"}]}],
			"has_more":false,"next_page":null}`)
	case "/v1/organizations/cost_report":
		io.WriteString(w, `{"data":[
			{"starting_at":"2026-11-02T00:00:00Z","ending_at":"2026-11-03T00:00:00Z","results":[
				{"amount":"123.78912","currency":"USD","cost_type":"tokens","description":"Claude Opus 5.5 Usage - Input Tokens","model":"claude-opus-5-5","token_type":"uncached_input_tokens"},
				{"amount":"40","currency":"USD","cost_type":"web_search","description":"Web Search Usage","model":null,"token_type":null}]},
			{"starting_at":"2026-11-03T00:00:00Z","ending_at":"2026-11-04T00:00:00Z","results":[
				{"amount":"6.21088","currency":"USD","cost_type":"tokens","description":"Claude Opus 5.5 Usage - Input Tokens","model":"claude-opus-5-5","token_type":"uncached_input_tokens"}]}],
			"has_more":false,"next_page":null}`)
	case "/v1/models":
		if q.Get("after_id") == "" {
			io.WriteString(w, `{"data":[{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-09-01T00:00:00Z","max_input_tokens":1000000}],"has_more":true,"first_id":"claude-opus-5-5","last_id":"claude-opus-5-5"}`)
			return
		}
		io.WriteString(w, `{"data":[{"type":"model","id":"claude-haiku-4-5-20251001","display_name":"Claude Haiku 4.5","created_at":"2025-10-01T00:00:00Z"}],"has_more":false,"first_id":"x","last_id":"claude-haiku-4-5-20251001"}`)
	default:
		w.WriteHeader(404)
	}
}

var secrets = map[string]string{"secret://admin": adminKey, "secret://api": apiKey, "secret://bad": "sk-ant-nopenopenopenopenope"}

func setup(t *testing.T, cfg Config) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in)})
}

func clean(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{adminKey, apiKey, "apikey_01Rj2N8SVvo6BePZj99NhmiT", "sk-ant"} {
		if strings.Contains(out, s) {
			t.Fatalf("output has %q: %s", s, out)
		}
	}
}

func TestAnthropicReads(t *testing.T) {
	m, _ := setup(t, Config{AdminKey: "secret://admin", APIKey: "secret://api"})
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || !strings.Contains(h.Message, "Acme") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"usage", `{"from":"2026-11-02","to":"2026-11-03"}`, []string{`"total":{"inputTokens":310,"cacheWriteTokens":15,"cacheReadTokens":50,"outputTokens":105,"webSearches":1}`,
			`"groups":[{"model":"claude-opus-5-5","inputTokens":300`, `"groupCount":2`, `{"date":"2026-11-03","inputTokens":200`}},
		{"usage", `{"from":"2026-11-02","to":"2026-11-03","groupBy":["workspace","model"]}`, []string{`"workspace":"default"`, `"workspace":"wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"`, `"groupCount":3`}},
		{"costs", `{"from":"2026-11-02","to":"2026-11-03"}`, []string{`"totals":{"USD":"1.70"}`, `"amount":"1.30"`, `"model":"claude-opus-5-5"`, `{"date":"2026-11-02","totals":{"USD":"1.6378912"}},{"date":"2026-11-03","totals":{"USD":"0.0621088"}}`}},
		{"models", `{"search":"haiku"}`, []string{`"id":"claude-haiku-4-5-20251001"`, `"matching":1`}},
		{"models", ``, []string{`"maxInputTokens":1000000`, `"matching":2`}},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil {
			t.Fatalf("%s %s: %v", c.action, c.in, err)
		}
		for _, w := range c.want {
			if !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s %s: want %s in %s", c.action, c.in, w, r.Output)
			}
		}
		clean(t, string(r.Output))
	}
}

func TestAnthropicMoneyIsExact(t *testing.T) {
	m, _ := setup(t, Config{AdminKey: "secret://admin"})
	r, err := invoke(m, "costs", `{"from":"2026-11-02","to":"2026-11-03"}`)
	if err != nil {
		t.Fatal(err)
	}
	// 123.78912 + 40 + 6.21088 cents = 170 cents.
	if !strings.Contains(string(r.Output), `"totals":{"USD":"1.70"}`) {
		t.Fatal(string(r.Output))
	}
}

func TestAnthropicRefusals(t *testing.T) {
	m, f := setup(t, Config{AdminKey: "secret://admin"})
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"usage", `{"from":"2026-01-01","to":"2026-11-03"}`},
		{"usage", `{"from":"2026-11-03","to":"2026-11-02"}`},
		{"usage", `{"to":"2026-11-05"}`},
		{"usage", `{"from":"2026-11-02&group_by[]=api_key_id"}`},
		{"usage", `{"groupBy":["api_key_id"]}`},
		{"costs", `{"groupBy":["model"]}`},
		{"models", `{}`}, // no API key configured
		{"models", `{"search":"a&b=c"}`},
		{"create_api_key", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	// A regular key in the admin slot is refused with an explanation.
	wrong, _ := setup(t, Config{AdminKey: "secret://api"})
	if h := wrong.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "Admin API key") {
		t.Fatalf("%+v", h)
	}
	bad, _ := setup(t, Config{AdminKey: "secret://bad", APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused the Admin API key") {
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

func TestAnthropicRefusesCrossHostRedirect(t *testing.T) {
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
	if err := m.Configure(context.Background(), fakehost.New(secrets), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || hit || strings.Contains(h.Message, adminKey) {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// hostile answers a cost report with body.
func hostile(t *testing.T, body string) *Module {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/organizations/me" {
			io.WriteString(w, `{"name":"Acme jane@example.com‮"}`)
			return
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	if err := m.Configure(context.Background(), fakehost.New(secrets), "a", json.RawMessage(`{"adminKey":"secret://admin"}`)); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAnthropicHostileCosts(t *testing.T) {
	row := func(amount, currency, desc string) string {
		return `{"data":[{"starting_at":"2026-11-03T00:00:00Z","results":[{"amount":"` + amount + `","currency":"` + currency + `","description":"` + desc + `"}]}],"has_more":false}`
	}
	for _, body := range []string{row("0x10", "USD", "x"), row("1/3", "USD", "x"), row("1e999999", "USD", "x"), row("1", "US dollars", "x")} {
		if res, err := invoke(hostile(t, body), "costs", `{}`); err == nil {
			t.Errorf("%s accepted: %s", body, res.Output)
		}
	}
	res, err := invoke(hostile(t, row("12.5", "usd", `Usage by jane@example.com via sk-ant-api03-abcdefghijklmnop\nnext line`)), "costs", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if strings.Contains(out, "jane@") || strings.Contains(out, "sk-ant") || strings.Contains(out, `\n`) || !strings.Contains(out, `"amount":"0.125"`) {
		t.Fatal(out)
	}
	if h := hostile(t, "{}").Health(context.Background(), "a"); strings.Contains(h.Message, "jane@") || strings.Contains(h.Message, "‮") {
		t.Fatalf("%+v", h)
	}
}
