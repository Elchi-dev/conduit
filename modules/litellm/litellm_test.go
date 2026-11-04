package litellm

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

var (
	hashA = strings.Repeat("a1", 32)
	hashB = strings.Repeat("b2", 32)
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	blocked map[string]bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	if r.URL.Path == "/health/readiness" {
		io.WriteString(w, `{"status":"healthy","db":"connected","litellm_version":"1.79.0"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer sk-master" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Authentication Error, Invalid proxy server token passed. Received API Key = sk-...ster","type":"auth_error"}}`)
		return
	}
	enc := json.NewEncoder(w)
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /model/info":
		io.WriteString(w, `{"data":[{"model_name":"gpt-4o","litellm_params":{"model":"azure/gpt-4o","api_base":"https://my.openai.azure.com/openai/deployments/x?api-key=leak","api_key":"sk-provider-secret"},"model_info":{"id":"dep-1","litellm_provider":"azure","mode":"chat","max_input_tokens":128000,"input_cost_per_token":0.0000025,"output_cost_per_token":0.00001}}]}`)
	case "GET /key/list":
		keys := []map[string]any{
			{"token": hashA, "key_name": "sk-...Ab12", "key_alias": "ci-bot", "spend": 4.5, "max_budget": 10, "team_id": "team-web", "blocked": f.blocked[hashA], "models": []string{"gpt-4o"}, "metadata": map[string]any{"note": "secret-ish"}},
			{"token": hashB, "key_name": "sk-...Cd34", "key_alias": "dup", "spend": 0, "blocked": f.blocked[hashB]},
			{"token": strings.Repeat("c3", 32), "key_name": "sk-...Ef56", "key_alias": "dup", "spend": 0},
		}
		if t := q.Get("team_id"); t != "" {
			keys = keys[:1]
		}
		enc.Encode(map[string]any{"keys": keys, "total_count": len(keys), "current_page": 1, "total_pages": 1})
	case "GET /key/info":
		k := q.Get("key")
		if k != hashA && k != hashB {
			w.WriteHeader(404)
			io.WriteString(w, `{"detail":"key not found"}`)
			return
		}
		enc.Encode(map[string]any{"key": k, "info": map[string]any{"key_name": "sk-...Ab12", "key_alias": "ci-bot", "spend": 4.5, "blocked": f.blocked[k], "team_id": "team-web"}})
	case "POST /key/block", "POST /key/unblock":
		var b struct {
			Key string `json:"key"`
		}
		_ = json.Unmarshal(body, &b)
		f.blocked[b.Key] = r.URL.Path == "/key/block"
		io.WriteString(w, `{}`)
	case "GET /user/daily/activity", "GET /team/daily/activity":
		if q.Get("start_date") == "" || q.Get("end_date") == "" {
			w.WriteHeader(400)
			return
		}
		page := q.Get("page")
		res := map[string]any{"date": q.Get("start_date"), "metrics": map[string]any{"spend": 1.5, "total_tokens": 1000, "api_requests": 10, "failed_requests": 1},
			"breakdown": map[string]any{
				"models":    map[string]any{"gpt-4o": map[string]any{"metrics": map[string]any{"spend": 1.0, "api_requests": 6}}, "claude": map[string]any{"metrics": map[string]any{"spend": 0.5, "api_requests": 4}}},
				"api_keys":  map[string]any{hashA: map[string]any{"metrics": map[string]any{"spend": 1.5}, "metadata": map[string]any{"key_alias": "ci-bot"}}},
				"providers": map[string]any{"azure": map[string]any{"metrics": map[string]any{"spend": 1.5}}},
				"entities":  map[string]any{"team-web": map[string]any{"metrics": map[string]any{"spend": 1.5}, "metadata": map[string]any{"team_alias": "Web"}}},
			}}
		enc.Encode(map[string]any{"results": []any{res}, "metadata": map[string]any{"has_more": page == "1"}})
	case "GET /budget/list":
		io.WriteString(w, `[{"budget_id":"monthly-100","max_budget":100,"budget_duration":"30d","rpm_limit":60}]`)
	case "GET /team/list":
		io.WriteString(w, `[{"team_id":"team-web","team_alias":"Web","spend":45,"max_budget":50,"budget_duration":"30d"}]`)
	case "GET /health":
		io.WriteString(w, `{"healthy_endpoints":[{"model":"azure/gpt-4o","api_base":"https://my.openai.azure.com/x","api_key":"sk-provider-secret"}],"unhealthy_endpoints":[{"model":"anthropic/claude","api_key":"sk-provider-secret","error":"AuthenticationError: invalid x-api-key sk-ant-api03-abcdefghijklmnopqrstuvwxyz\nTraceback (most recent call last): ..."}],"healthy_count":1,"unhealthy_count":1}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not Found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{blocked: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{URL: srv.URL, MasterKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://m": "sk-master", "secret://bad": "sk-nope"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLiteLLMReads(t *testing.T) {
	m, f := setup(t, "secret://m")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || !strings.Contains(h.Message, "1.79.0") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"models", ``, `"inputPerMillion":2.5`},
		{"spend", ``, `"end":"2026-11-04","failed":2,"requests":20,"spend":3,"start":"2026-11-04"`},
		{"spend", `{"period":"month"}`, `"start":"2026-11-01"`},
		{"spend", `{"period":"month","by":"model"}`, `{"name":"gpt-4o","spend":2,"requests":12,"tokens":0}`},
		{"spend", `{"by":"key"}`, `"alias":"ci-bot","spend":3`},
		{"spend", `{"by":"team"}`, `"name":"team-web","alias":"Web"`},
		{"spend", `{"period":"custom","start":"2026-10-01","end":"2026-10-31","by":"provider"}`, `"name":"azure"`},
		{"keys", `{"search":"ci"}`, `"masked":"sk-...Ab12"`},
		{"keys", `{"team":"team-web"}`, `"percentUsed":45`},
		{"budgets", ``, `"percentUsed":90`},
		{"deployment_health", ``, `"unhealthyCount":1`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "sk-provider-secret") || strings.Contains(out, "leak") ||
			strings.Contains(out, "sk-ant-api03") || strings.Contains(out, "Traceback") || strings.Contains(out, "secret-ish") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	// Spend reads every page and adds them up (two pages of 1.5).
	r, _ := invoke(m, "spend", ``, false)
	if !strings.Contains(string(r.Output), `"spend":3,`) {
		t.Fatal(string(r.Output))
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "GET /team/daily/activity") {
		t.Fatal("team spend didn't use team activity")
	}
}

func TestLiteLLMBlock(t *testing.T) {
	m, f := setup(t, "secret://m")
	r, err := invoke(m, "block_key", `{"key":"`+hashA+`"}`, true)
	if err != nil || r.Plan == nil || f.blocked[hashA] || !strings.Contains(r.Plan.Summary, "ci-bot") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "block_key", `{"alias":"ci-bot"}`, false)
	if err != nil || !f.blocked[hashA] || r.Undo == nil || r.Undo.Action != "unblock_key" {
		t.Fatalf("%+v %v", r, err)
	}
	// Blocking again changes nothing and offers no undo.
	if r, err := invoke(m, "block_key", `{"key":"`+hashA+`"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"unchanged":true`) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.blocked[hashA] {
		t.Fatal(err)
	}
	risk := map[string]sdk.ActionSpec{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a
	}
	for _, n := range []string{"block_key", "unblock_key"} {
		if a := risk[n]; a.Risk != sdk.RiskDestructive || !a.DryRun || a.Sensitive {
			t.Fatalf("%+v", a)
		}
	}
	if risk["deployment_health"].Risk != sdk.RiskWrite {
		t.Fatal("deployment_health must be write: it calls every provider")
	}
}

func TestLiteLLMRefusals(t *testing.T) {
	m, f := setup(t, "secret://m")
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"block_key", `{"key":"sk-1234567890abcdef"}`},
		{"block_key", `{"alias":"sk-1234567890abcdef"}`},
		{"block_key", `{"key":"../../key/delete"}`},
		{"block_key", `{}`},
		{"unblock_key", `{"key":"` + strings.ToUpper(hashA) + `"}`},
		{"spend", `{"period":"week"}`},
		{"spend", `{"period":"custom","start":"2026-11-05","end":"2026-11-01"}`},
		{"spend", `{"period":"custom","start":"2026-02-30","end":"2026-03-01"}`},
		{"spend", `{"by":"user"}`},
		{"keys", `{"team":"a&b"}`},
		{"delete_key", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	if _, err := invoke(m, "block_key", `{"alias":"dup"}`, false); err == nil || !strings.Contains(err.Error(), "2 keys") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "block_key", `{"key":"`+strings.Repeat("0", 64)+`"}`, false); err == nil {
		t.Fatal("unknown key blocked")
	}
	for _, raw := range []string{`{"url":"http://h:4000"}`, `{"url":"http://h:4000","masterKey":"sk-master"}`, `{"url":"ftp://h","masterKey":"secret://m"}`, `{"url":"http://u:p@h","masterKey":"secret://m"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "l"); h.Status != "down" || !strings.Contains(h.Message, "refused the master key") {
		t.Fatalf("%+v", h)
	}
}

func TestLiteLLMRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, MasterKey: "secret://m"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://m": "sk-master"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "keys", ``, false); err == nil || hit {
		t.Fatal("followed the redirect")
	}
}
