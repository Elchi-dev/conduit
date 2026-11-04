package elevenlabs

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

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Header.Get("xi-api-key") != "sk_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":{"status":"invalid_api_key","message":"Invalid API key"}}`)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	switch r.URL.Path {
	case "/v1/user/subscription":
		io.WriteString(w, `{"tier":"creator","status":"active","character_count":12000,"character_limit":100000,"can_extend_character_limit":true,"next_character_count_reset_unix":1767225600,
			"voice_slots_used":3,"voice_limit":30,"professional_voice_limit":1,"currency":"usd","billing_period":"monthly_period","next_invoice":{"amount_due_cents":2200,"next_payment_attempt_unix":1767225600}}`)
	case "/v1/usage/character-stats":
		if r.URL.Query().Get("aggregation_interval") != "day" || r.URL.Query().Get("start_unix") == "" {
			w.WriteHeader(422)
			return
		}
		io.WriteString(w, `{"time":[1762128000000,1762214400000],"usage":{"All":[1500,250]}}`)
	case "/v1/voices":
		io.WriteString(w, `{"voices":[{"voice_id":"21m00Tcm4TlvDq8ikWAM","name":"Rachel","category":"premade","labels":{"accent":"american"},"preview_url":"https://storage.example.com/LEAKME.mp3"},
			{"voice_id":"Clone1abc","name":"My voice","category":"cloned","description":"me","samples":[{"sample_id":"s1","file_name":"LEAKME.wav"}],"fine_tuning":{"verification_attempts":[{"recording":"LEAKME"}]},"is_owner":true}]}`)
	case "/v1/history":
		if r.URL.Query().Get("page_size") != "2" {
			w.WriteHeader(422)
			return
		}
		io.WriteString(w, `{"history":[{"history_item_id":"h1","voice_id":"Clone1abc","voice_name":"My voice","model_id":"eleven_multilingual_v2","text":"Hi Jane, your appointment is at 3pm","date_unix":1762200000,
			"character_count_change_from":100,"character_count_change_to":136,"source":"TTS","settings":{},"feedback":null}],"has_more":true,"last_history_item_id":"h1"}`)
	default:
		w.WriteHeader(404)
	}
}

var secrets = map[string]string{"secret://el": "sk_good", "secret://bad": "sk_bad"}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "e", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "e", Action: action, Input: json.RawMessage(in)})
}

func TestElevenLabs(t *testing.T) {
	m, _ := setup(t, "secret://el")
	if h := m.Health(context.Background(), "e"); h.Status != "ok" || h.Message != "creator plan, 12000 of 100000 characters used" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"subscription", ``, `"charactersLeft":88000`},
		{"subscription", ``, `"amount":22,"currency":"USD"`},
		{"usage", `{"days":7}`, `"total":1750`},
		{"usage", ``, `"date":"2025-11-03"`},
		{"voices", `{}`, `"name":"Rachel"`},
		{"voices", `{"category":"cloned"}`, `"yours":true`},
		{"history", `{"limit":2}`, `"characters":36`},
		{"history", `{"limit":2}`, `"next":"h1"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "sk_good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "voices", `{"category":"cloned"}`); strings.Contains(string(r.Output), "Rachel") {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead || (a.Name == "history") != a.Sensitive {
			t.Fatalf("%s is %s sensitive=%v", a.Name, a.Risk, a.Sensitive)
		}
	}
}

func TestElevenLabsValidation(t *testing.T) {
	m, f := setup(t, "secret://el")
	for _, c := range []struct{ action, in string }{
		{"usage", `{"days":400}`},
		{"usage", `{"days":-1}`},
		{"voices", `{"category":"x&y"}`},
		{"history", `{"limit":1000}`},
		{"history", `{"voice":"a/../b"}`},
		{"history", `{"after":"x&page_size=999"}`},
		{"text_to_speech", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{}`, `{"apiKey":"sk_good"}`, `"x"`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "e"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") || strings.Contains(h.Message, "sk_bad") {
		t.Fatalf("%+v", h)
	}
}

func TestElevenLabsRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("xi-api-key") + "hit" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://el"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "e", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "e"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
