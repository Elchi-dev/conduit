package openaicompat

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
	mu     sync.Mutex
	seen   []string
	bodies []map[string]any
	key    string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if f.key != "" && r.Header.Get("Authorization") != "Bearer "+f.key {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Invalid API key"}}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/models":
		io.WriteString(w, `{"object":"list","data":[{"id":"qwen2.5-7b-instruct","object":"model","owned_by":"organization_owner"},{"id":"llama-3.2-3b"}]}`)
	case "POST /v1/chat/completions":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.bodies = append(f.bodies, b)
		io.WriteString(w, `{"model":"qwen2.5-7b-instruct","choices":[{"message":{"role":"assistant","content":"Hello there!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config, key string) (*Module, *fake) {
	f := &fake{key: key}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg.URL = srv.URL + "/v1/"
	m := New()
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "sk-local", "secret://bad": "wrong"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestOpenAICompat(t *testing.T) {
	m, f := setup(t, Config{APIKey: "secret://k", MaxTokens: 300}, "sk-local")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || !strings.Contains(h.Message, "2 model(s)") {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "models", ``); err != nil || !strings.Contains(string(r.Output), `{"id":"qwen2.5-7b-instruct","ownedBy":"organization_owner"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "chat", `{"model":"qwen2.5-7b-instruct","prompt":"Say hello","system":"Be brief","temperature":0.2}`)
	if err != nil || !strings.Contains(string(r.Output), `"answer":"Hello there!"`) || !strings.Contains(string(r.Output), `"totalTokens":15`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	b := f.bodies[0]
	if b["max_tokens"] != float64(300) || b["stream"] != false || b["temperature"] != 0.2 || len(b["messages"].([]any)) != 2 {
		t.Fatalf("%v", b)
	}
	if _, err := invoke(m, "chat", `{"model":"qwen2.5-7b-instruct","prompt":"hi","maxTokens":100}`); err != nil || f.bodies[1]["max_tokens"] != float64(100) {
		t.Fatal(err, f.bodies[1])
	}
	var chat sdk.ActionSpec
	for _, a := range m.Manifest().Actions {
		if a.Name == "chat" {
			chat = a
		}
	}
	if chat.Risk != sdk.RiskWrite || !chat.Sensitive || chat.Reversible {
		t.Fatalf("%+v", chat)
	}
}

func TestOpenAICompatRefusesBadInput(t *testing.T) {
	m, f := setup(t, Config{MaxTokens: 256}, "")
	n := len(f.seen)
	for _, in := range []string{
		`{"model":"qwen","prompt":"hi","maxTokens":257}`,
		`{"model":"qwen","prompt":"hi","maxTokens":-1}`,
		`{"model":"qwen","prompt":"   "}`,
		`{"model":"qwen","prompt":"` + strings.Repeat("a", maxPrompt+1) + `"}`,
		`{"model":"qwen","prompt":"hi","system":"` + strings.Repeat("a", maxSystem+1) + `"}`,
		`{"model":"http://evil.example/x","prompt":"hi"}`,
		`{"model":"../models","prompt":"hi"}`,
		`{"model":"","prompt":"hi"}`,
		`{"model":"qwen","prompt":"hi","temperature":3}`,
	} {
		if _, err := invoke(m, "chat", in); err == nil {
			t.Fatalf("%.80s accepted", in)
		}
	}
	if _, err := invoke(m, "embed", `{}`); err == nil {
		t.Fatal("unknown action accepted")
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
}

func TestOpenAICompatSettings(t *testing.T) {
	for _, raw := range []string{
		`{"url":"ftp://h/v1"}`,
		`{"url":"http://user:pw@h:1/v1"}`,
		`{"url":"http://h:1/v1?key=abc"}`,
		`{"url":"http://h:1/v1/chat/completions"}`,
		`{"url":"http://h:1/v1","apiKey":"sk-plain"}`,
		`{"url":"http://h:1/v1","maxTokens":9000}`,
		`{"url":"http://h:1/v1","maxTokens":-5}`,
		`{"url":"http://h:1/v1","timeoutSeconds":1}`,
	} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	m, _ := setup(t, Config{APIKey: "secret://bad"}, "sk-local")
	if h := m.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "chat", `{"model":"qwen","prompt":"hi"}`); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatal(err)
	}
	// The default cap applies when none is set.
	d, f := setup(t, Config{}, "")
	if _, err := invoke(d, "chat", `{"model":"llama-3.2-3b","prompt":"hi"}`); err != nil || f.bodies[0]["max_tokens"] != float64(defaultMaxTokens) {
		t.Fatal(err, f.bodies)
	}
	for _, raw := range []string{`{"url":"http://h:1/v1","models":["../x"]}`, `{"url":"http://h:1/v1","models":[""]}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
}

// chat uses only the models the instance allows; with none set, only those
// the server lists, and never a routing variant such as :online (a paid web
// search on every call) unless the settings name it.
func TestOpenAICompatModelAllowList(t *testing.T) {
	m, f := setup(t, Config{}, "")
	for _, model := range []string{"gpt-4o", "llama-3.2-3b:online", "qwen2.5-7b-instruct:nitro", "qwen2.5-7b-instruct:ONLINE"} {
		if _, err := invoke(m, "chat", `{"model":"`+model+`","prompt":"hi"}`); err == nil {
			t.Fatalf("%s accepted", model)
		}
	}
	if len(f.bodies) != 0 {
		t.Fatalf("a refused model reached the server: %v", f.bodies)
	}
	if _, err := invoke(m, "chat", `{"model":"llama-3.2-3b","prompt":"hi"}`); err != nil {
		t.Fatal(err)
	}

	al, f := setup(t, Config{Models: []string{"llama-3.2-3b:online", "unlisted-model"}}, "")
	for _, model := range []string{"llama-3.2-3b", "qwen2.5-7b-instruct"} {
		if _, err := invoke(al, "chat", `{"model":"`+model+`","prompt":"hi"}`); err == nil || !strings.Contains(err.Error(), "don't allow") {
			t.Fatalf("%s: %v", model, err)
		}
	}
	for _, model := range []string{"llama-3.2-3b:online", "unlisted-model"} {
		if _, err := invoke(al, "chat", `{"model":"`+model+`","prompt":"hi"}`); err != nil {
			t.Fatalf("%s: %v", model, err)
		}
	}
	if len(f.bodies) != 2 || f.bodies[0]["model"] != "llama-3.2-3b:online" {
		t.Fatal(f.bodies)
	}
}

func TestOpenAICompatRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/v1", APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "sk-local"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "chat", `{"model":"qwen","prompt":"secret plans"}`); err == nil || hit {
		t.Fatalf("followed the redirect: %v", err)
	}
}
