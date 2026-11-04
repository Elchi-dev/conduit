package doppler

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
	if r.Header.Get("Authorization") != "Bearer dp.pt.good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"messages":["Invalid Auth token"],"success":false}`)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/v3/me":
		io.WriteString(w, `{"type":"personal","name":"laptop","slug":"x","token_preview":"dp.pt.goo...","created_at":"2026-01-01","workplace":{"name":"Acme","slug":"acme"}}`)
	case "/v3/projects":
		io.WriteString(w, `{"projects":[{"id":"backend","slug":"backend","name":"Backend","description":"api"}],"page":1}`)
	case "/v3/configs":
		if q.Get("project") != "backend" {
			w.WriteHeader(404)
			io.WriteString(w, `{"messages":["Could not find requested project"]}`)
			return
		}
		io.WriteString(w, `{"configs":[{"name":"prd","environment":"prd","root":true,"locked":true,"last_fetch_at":"2026-11-01"}]}`)
	case "/v3/configs/config/secrets/names":
		if q.Get("project") != "backend" || q.Get("config") != "prd" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"names":["STRIPE_KEY","DB_PASSWORD"]}`)
	case "/v3/configs/config/secret":
		switch q.Get("name") {
		case "DB_PASSWORD":
			io.WriteString(w, `{"name":"DB_PASSWORD","value":{"raw":"${OTHER}","computed":"hunter2","note":"n0te-secret"}}`)
		case "STRIPE_KEY":
			io.WriteString(w, `{"name":"STRIPE_KEY","value":{"raw":"sk_live_abc","computed":"sk_live_abc"}}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"messages":["Could not find requested secret"]}`)
		}
	case "/v3/logs":
		io.WriteString(w, `{"logs":[{"id":"l1","text":"Alice updated DB_PASSWORD in prd","created_at":"2026-11-03","enclave_project":"backend","enclave_config":"prd","user":{"name":"Alice","email":"alice@example.com"}},
			{"id":"l2","text":"Bob created token dp.st.prd.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enclave_project":"web","user":{"name":"Bob"}}],"page":1}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref, Project: "backend", Config: "prd"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dp": "dp.pt.good", "secret://bad": "dp.pt.nope"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in)})
}

func TestDopplerReads(t *testing.T) {
	m, _ := setup(t, "secret://dp")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || !strings.Contains(h.Message, "personal laptop · Acme") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"me", `{}`, `"workplace":"Acme"`},
		{"projects", `{}`, `"slug":"backend"`},
		{"configs", `{}`, `"locked":true`},
		{"secret_names", `{}`, `"names":["DB_PASSWORD","STRIPE_KEY"]`},
		{"activity", `{}`, `"user":"Alice"`},
		{"activity", `{"project":"backend"}`, `"config":"prd"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, s := range []string{"hunter2", "sk_live", "n0te-secret", "dp.pt.goo", "AAAAAAAAAAAAAAAAAAAA", "alice@example.com"} {
			if strings.Contains(out, s) {
				t.Fatalf("%s leaks %s: %s", c.action, s, out)
			}
		}
	}
	r, _ := invoke(m, "activity", `{"project":"backend"}`)
	if strings.Contains(string(r.Output), "Bob") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, "configs", `{"project":"nope"}`); err == nil || !strings.Contains(err.Error(), "there's no project nope") {
		t.Fatal(err)
	}
}

func TestDopplerReveal(t *testing.T) {
	m, f := setup(t, "secret://dp")
	r, err := invoke(m, "reveal_secret", `{"names":["DB_PASSWORD","NOPE"]}`)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"values":{"DB_PASSWORD":"hunter2"}`) || !strings.Contains(out, `"missing":["NOPE"]`) || strings.Contains(out, "sk_live") || strings.Contains(out, "n0te") || strings.Contains(out, "OTHER") {
		t.Fatalf("%s %v", out, err)
	}
	before := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"reveal_secret", `{}`},
		{"reveal_secret", `{"names":["A-B"]}`},
		{"reveal_secret", `{"names":["A&name=B"]}`},
		{"reveal_secret", `{"names":["A","B","C","D","E","F","G","H","I","J","K"]}`},
		{"reveal_secret", `{"names":["A"],"project":"a/b"}`},
		{"secret_names", `{"config":"x y"}`},
		{"activity", `{"perPage":500}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != before {
		t.Fatalf("invalid input reached the server: %v", f.seen[before:])
	}
	for _, a := range m.Manifest().Actions {
		switch {
		case a.Name == "reveal_secret":
			if a.Risk != sdk.RiskDestructive || !a.Sensitive {
				t.Fatal("reveal_secret must be sensitive and destructive")
			}
		case a.Risk != sdk.RiskRead:
			t.Fatalf("%s must be a read", a.Name)
		}
	}
}

func TestDopplerConfigAndToken(t *testing.T) {
	for _, c := range []Config{{Token: "dp.pt.plain"}, {Token: "secret://dp", Project: "a b"}, {Token: "secret://dp", Config: "x/y"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "d"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestDopplerRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://dp"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://dp": "dp.pt.good"}), "d", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "me", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
