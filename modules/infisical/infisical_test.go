package infisical

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

const (
	clientID = "6f1c2a10-0000-4000-8000-000000000001"
	projID   = "9a0b0c0d-0000-4000-8000-000000000002"
	secID    = "5ec00000-0000-4000-8000-000000000003"
)

type fake struct {
	mu     sync.Mutex
	logins int
	expire bool // answer the next API call with 401
	seen   []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if r.URL.Path == "/api/v1/auth/universal-auth/login" {
		var b struct{ ClientID, ClientSecret string }
		json.Unmarshal(body, &b)
		if b.ClientID != clientID || b.ClientSecret != "cs-good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"Invalid credentials"}`)
			return
		}
		f.logins++
		io.WriteString(w, `{"accessToken":"at-`+string(rune('0'+f.logins))+`","expiresIn":7200,"tokenType":"Bearer"}`)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") || f.expire {
		f.expire = false
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Token expired"}`)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/status":
		io.WriteString(w, `{"date":"2026-11-04T00:00:00Z","message":"Ok","emailConfigured":true,"redisConfigured":true}`)
	case "/api/v1/workspace":
		io.WriteString(w, `{"workspaces":[{"id":"`+projID+`","name":"Backend","slug":"backend","environments":[{"id":"e1","name":"Development","slug":"dev"},{"id":"e2","name":"Production","slug":"prod"}]}]}`)
	case "/api/v1/folders":
		io.WriteString(w, `{"folders":[{"id":"f1","name":"db"}]}`)
	case "/api/v3/secrets/raw":
		if q.Get("workspaceId") != projID || q.Get("environment") != "prod" || q.Get("viewSecretValue") != "false" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"secrets":[{"id":"`+secID+`","secretKey":"DB_PASSWORD","secretValue":"hunter2","secretComment":"old pw was c0mment-secret","version":3,"type":"shared","tags":[{"slug":"db"}]},
			{"id":"x2","secretKey":"API_KEY","secretValue":"sk-live-xyz","version":1,"type":"shared"}],"imports":[]}`)
	case "/api/v3/secrets/raw/DB_PASSWORD":
		if q.Get("secretPath") != "/" || q.Get("type") != "shared" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"secret":{"secretKey":"DB_PASSWORD","secretValue":"hunter2","secretComment":"c0mment-secret","version":3}}`)
	case "/api/v1/secret/" + secID + "/secret-versions":
		io.WriteString(w, `{"secretVersions":[{"version":1,"secretKey":"DB_PASSWORD","secretValue":"old-pass","createdAt":"2026-01-01"},{"version":3,"secretValue":"hunter2","createdAt":"2026-03-01","actor":{"actorType":"identity","name":"ci"}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Secret not found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, ClientID: clientID, ClientSecret: ref, Project: "backend", Environment: "prod"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://inf": "cs-good", "secret://bad": "nope"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in)})
}

func TestInfisicalReads(t *testing.T) {
	m, f := setup(t, "secret://inf")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" || !strings.Contains(h.Message, "1 project") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"message":"Ok"`},
		{"projects", `{}`, `"environments":["dev","prod"]`},
		{"environments", `{"project":"` + projID + `"}`, `"name":"Production"`},
		{"secrets", `{}`, `"key":"DB_PASSWORD"`},
		{"secrets", `{}`, `"folders":["db"]`},
		{"versions", `{"key":"DB_PASSWORD"}`, `"actor":"identity ci"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		for _, s := range []string{"hunter2", "sk-live-xyz", "c0mment-secret", "old-pass", "cs-good", "at-1"} {
			if strings.Contains(out, s) {
				t.Fatalf("%s leaks %s: %s", c.action, s, out)
			}
		}
	}
	if f.logins != 1 {
		t.Fatalf("logged in %d times", f.logins)
	}
	// An expired session logs in again once.
	f.expire = true
	if _, err := invoke(m, "projects", `{}`); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
}

func TestInfisicalReveal(t *testing.T) {
	m, f := setup(t, "secret://inf")
	r, err := invoke(m, "reveal_secret", `{"keys":["DB_PASSWORD","NOPE"]}`)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"values":{"DB_PASSWORD":"hunter2"}`) || !strings.Contains(out, `"missing":["NOPE"]`) || strings.Contains(out, "c0mment") || strings.Contains(out, "sk-live") {
		t.Fatalf("%s %v", out, err)
	}
	before := len(f.seen)
	for _, c := range []struct{ action, in string }{
		{"reveal_secret", `{}`},
		{"reveal_secret", `{"keys":["a/b"]}`},
		{"reveal_secret", `{"keys":["../x"]}`},
		{"reveal_secret", `{"keys":["a?b"]}`},
		{"reveal_secret", `{"keys":["1","2","3","4","5","6","7","8","9","10","11"]}`},
		{"reveal_secret", `{"keys":["A"],"path":"../x"}`},
		{"reveal_secret", `{"keys":["A"],"environment":"pr od"}`},
		{"secrets", `{"project":"a/b"}`},
		{"secrets", `{"path":"a//../b"}`},
		{"versions", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != before {
		t.Fatalf("invalid input reached the server: %v", f.seen[before:])
	}
	if _, err := invoke(m, "secrets", `{"environment":"staging"}`); err == nil || !strings.Contains(err.Error(), "no environment") {
		t.Fatal(err)
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

func TestInfisicalConfigAndLogin(t *testing.T) {
	for _, c := range []Config{{ClientID: clientID, ClientSecret: "plain"}, {ClientSecret: "secret://inf"}, {URL: "ftp://x", ClientID: clientID, ClientSecret: "secret://inf"},
		{URL: "https://u:p@x", ClientID: clientID, ClientSecret: "secret://inf"}, {ClientID: clientID, ClientSecret: "secret://inf", Environment: "a b"}, {ClientID: "x/y", ClientSecret: "secret://inf"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "refused") || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
}

func TestInfisicalRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b) + "!"
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, ClientID: clientID, ClientSecret: "secret://inf"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://inf": "cs-good"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "projects", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
