package groq

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

const key = "gsk_goodgoodgoodgoodgoodgoodgood"

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Invalid API Key","type":"invalid_request_error","code":"invalid_api_key"}}`)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/models" {
		w.WriteHeader(404)
		return
	}
	io.WriteString(w, `{"object":"list","data":[
		{"id":"llama-3.1-8b-instant","object":"model","created":1693721698,"owned_by":"Meta","active":true,"context_window":131072,"public_apps":null,"max_completion_tokens":131072},
		{"id":"whisper-large-v3","object":"model","created":1693721698,"owned_by":"OpenAI","active":true,"context_window":448,"public_apps":null},
		{"id":"gemma2-9b-it","object":"model","created":1693721698,"owned_by":"Google","active":false,"context_window":8192,"public_apps":null}]}`)
}

var secrets = map[string]string{"secret://g": key, "secret://bad": "gsk_nopenopenopenopenopenope"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in)})
}

func TestGroqModels(t *testing.T) {
	m, _ := setup(t, "secret://g")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || !strings.Contains(h.Message, "3 models") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ in, want string }{
		{``, `"matching":3`},
		{`{"search":"llama"}`, `{"id":"llama-3.1-8b-instant","ownedBy":"Meta","active":true,"contextWindow":131072,"maxCompletionTokens":131072,"created":"2023-09-03"}`},
		{`{"search":"openai"}`, `"id":"whisper-large-v3"`},
		{`{"active":false}`, `"id":"gemma2-9b-it","ownedBy":"Google","active":false`},
		{`{"active":true,"limit":1}`, `"matching":2`},
	} {
		r, err := invoke(m, "models", c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), key) {
			t.Fatalf("%s: %s %v", c.in, r.Output, err)
		}
	}
}

func TestGroqRefusals(t *testing.T) {
	m, f := setup(t, "secret://g")
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"models", `{"search":"a&b=c"}`},
		{"models", `{"active":"yes"}`},
		{"chat", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"` + key + `"}`, `[`} {
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

func TestGroqRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://g"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
