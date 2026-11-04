package mistral

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

const key = "mistralgoodgoodgoodgoodgoodgood"

type fake struct {
	mu   sync.Mutex
	seen []string
	bare bool
}

const cards = `[
	{"id":"mistral-large-latest","object":"model","created":1756746619,"owned_by":"mistralai","name":"mistral-large-2411","max_context_length":131072,"aliases":["mistral-large-2411"],"deprecation":null,"type":"base",
	 "capabilities":{"completion_chat":true,"completion_fim":false,"function_calling":true,"fine_tuning":true,"vision":false}},
	{"id":"open-mistral-7b","object":"model","created":1756746619,"owned_by":"mistralai","max_context_length":32768,"aliases":[],"deprecation":"2026-12-31T00:00:00Z","deprecation_replacement_model":"ministral-8b-latest","type":"base",
	 "capabilities":{"completion_chat":true}},
	{"id":"ft:open-mistral-7b:abc:20260101:x1","object":"model","created":1756746619,"owned_by":"org-123","job":"job-1","root":"open-mistral-7b","max_context_length":32768,"type":"fine-tuned","archived":false,
	 "capabilities":{"completion_chat":true,"fine_tuning":false}}]`

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+key {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized","request_id":"abc"}`)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/models" {
		w.WriteHeader(404)
		return
	}
	if f.bare {
		io.WriteString(w, cards)
		return
	}
	io.WriteString(w, `{"object":"list","data":`+cards+`}`)
}

var secrets = map[string]string{"secret://m": key, "secret://bad": "nopenopenopenopenopenope"}

func setup(t *testing.T, ref string, bare bool) (*Module, *fake) {
	f := &fake{bare: bare}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in)})
}

func TestMistralModels(t *testing.T) {
	for _, bare := range []bool{false, true} {
		m, _ := setup(t, "secret://m", bare)
		if h := m.Health(context.Background(), "m"); h.Status != "ok" || !strings.Contains(h.Message, "3 models") {
			t.Fatalf("%+v", h)
		}
		for _, c := range []struct{ in, want string }{
			{``, `"matching":3`},
			{`{"search":"large"}`, `"capabilities":["completion_chat","fine_tuning","function_calling"],"aliases":["mistral-large-2411"]`},
			{`{"search":"7b","type":"base"}`, `"deprecation":"2026-12-31","replacement":"ministral-8b-latest"`},
			{`{"type":"fine-tuned"}`, `"type":"fine-tuned","ownedBy":"org-123"`},
			{`{"limit":1}`, `"matching":3`},
		} {
			r, err := invoke(m, "models", c.in)
			if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), key) || strings.Contains(string(r.Output), "job-1") {
				t.Fatalf("%s: %s %v", c.in, r.Output, err)
			}
		}
	}
}

func TestMistralRefusals(t *testing.T) {
	m, f := setup(t, "secret://m", false)
	n := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"models", `{"search":"a&b=c"}`},
		{"models", `{"type":"custom"}`},
		{"models", `{"search":"` + strings.Repeat("a", 101) + `"}`},
		{"chat", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != n {
		t.Fatalf("bad input reached the server: %v", f.seen[n:])
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
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

func TestMistralRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://m"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
