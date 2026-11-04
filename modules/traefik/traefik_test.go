package traefik

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

type fakeTraefik struct {
	mu   sync.Mutex
	seen []string
	auth bool
}

func (f *fakeTraefik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.auth {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	switch strings.TrimPrefix(r.URL.EscapedPath(), "/traefik/api") {
	case "/version":
		io.WriteString(w, `{"Version":"3.1.2","Codename":"comte","startDate":"2026-11-01T00:00:00Z"}`)
	case "/overview":
		io.WriteString(w, `{"http":{"routers":{"total":3,"warnings":0,"errors":1},"services":{"total":2,"warnings":1,"errors":0},"middlewares":{"total":1,"warnings":0,"errors":0}},
			"tcp":{"routers":{"total":0},"services":{"total":0},"middlewares":{"total":0}},"udp":{"routers":{"total":0},"services":{"total":0}},
			"features":{"tracing":"","metrics":"prometheus","accessLog":true},"providers":["Docker","File"]}`)
	case "/http/routers":
		if q.Get("per_page") != "100" {
			w.WriteHeader(400)
			return
		}
		if q.Get("page") == "1" {
			w.Header().Set("X-Next-Page", "2")
			io.WriteString(w, `[{"name":"app@docker","rule":"Host(`+"`app.example.com`"+`)","service":"app","entryPoints":["websecure"],"middlewares":["auth@file"],"status":"enabled","provider":"docker","tls":{"certResolver":"le"}},
				{"name":"broken@docker","rule":"Host(`+"`x`"+`)","service":"missing","status":"disabled","provider":"docker","error":["the service \"missing@docker\" does not exist"]}]`)
			return
		}
		w.Header().Set("X-Next-Page", "1")
		io.WriteString(w, `[{"name":"api@internal","rule":"PathPrefix(`+"`/api`"+`)","service":"api@internal","status":"enabled","provider":"internal"}]`)
	case "/http/routers/app@docker":
		io.WriteString(w, `{"name":"app@docker","rule":"Host(`+"`app.example.com`"+`)","service":"app","status":"enabled","provider":"docker","using":["websecure"]}`)
	case "/http/services":
		io.WriteString(w, `[{"name":"app@docker","type":"loadbalancer","status":"warning","provider":"docker","usedBy":["app@docker"],
			"loadBalancer":{"servers":[{"url":"http://172.18.0.5:80"},{"url":"http://172.18.0.6:80"}]},"serverStatus":{"http://172.18.0.5:80":"UP","http://172.18.0.6:80":"DOWN"}}]`)
	case "/http/middlewares":
		io.WriteString(w, `[{"name":"auth@file","type":"basicauth","status":"enabled","provider":"file","usedBy":["app@docker"],"basicAuth":{"users":["admin:$apr1$LEAKME"]}}]`)
	case "/entrypoints":
		io.WriteString(w, `[{"name":"web","address":":80","http":{"redirections":{"entryPoint":{"to":"websecure","scheme":"https"}}}},{"name":"websecure","address":":443","http":{"tls":{"certResolver":"le"}}}]`)
	case "/tcp/routers", "/tcp/services", "/tcp/middlewares", "/udp/routers", "/udp/services":
		io.WriteString(w, `[]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `404 page not found`)
	}
}

func setup(t *testing.T, cfg Config, auth bool) (*Module, *fakeTraefik) {
	f := &fakeTraefik{auth: auth}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL + "/traefik/dashboard/"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "x"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in)})
}

func TestTraefik(t *testing.T) {
	m, _ := setup(t, Config{Username: "admin", Password: "secret://pw"}, true)
	if h := m.Health(context.Background(), "t"); h.Status != "degraded" || h.Message != "Traefik 3.1.2 · 1 routers, services or middlewares with errors" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"overview", `{}`, `"providers":["Docker","File"]`},
		{"routers", `{}`, `"name":"api@internal"`},
		{"routers", `{}`, `"tls":{"certResolver":"le"}`},
		{"routers", `{"provider":"docker"}`, `"broken@docker"`},
		{"router", `{"name":"app@docker"}`, `"using":["websecure"]`},
		{"services", `{}`, `{"address":"http://172.18.0.6:80","status":"DOWN"}`},
		{"middlewares", `{}`, `"type":"basicauth"`},
		{"entrypoints", `{}`, `"redirectsTo":"websecure"`},
		{"errors", `{}`, `does not exist`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, _ := invoke(m, "routers", `{"provider":"docker"}`)
	if strings.Contains(string(r.Output), "api@internal") {
		t.Fatal(string(r.Output))
	}
	r, _ = invoke(m, "errors", `{}`)
	var e struct {
		Count int
		Items []struct{ Kind, Name, Status string }
	}
	json.Unmarshal(r.Output, &e)
	if e.Count != 2 || e.Items[0].Name != "broken@docker" || e.Items[0].Kind != "http router" || e.Items[1].Kind != "http service" {
		t.Fatalf("%s", r.Output)
	}
	if _, err := invoke(m, "router", `{"name":"nope@docker"}`); err == nil || !strings.Contains(err.Error(), "no http router") {
		t.Fatal(err)
	}
}

func TestTraefikValidation(t *testing.T) {
	m, f := setup(t, Config{}, false)
	for _, c := range []struct{ action, in string }{
		{"router", `{"name":"../overview"}`},
		{"router", `{"name":"a/b"}`},
		{"router", `{"name":""}`},
		{"routers", `{"protocol":"ftp"}`},
		{"routers", `{"status":"broken"}`},
		{"middlewares", `{"protocol":"udp"}`},
		{"router", `{"name":"x","protocol":"../../"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://t", Username: "admin", Password: "plain"}, {URL: "t:8080"}, {URL: "http://t", Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Username: "admin", Password: "secret://bad"}, true)
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	// Without auth configured, a protected API is refused too.
	noauth, _ := setup(t, Config{}, true)
	if _, err := invoke(noauth, "routers", `{}`); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

func TestTraefikRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// Traefik's default certificate is self-signed; a pinned fingerprint trusts
// exactly that certificate.
func TestTraefikPinnedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(&fakeTraefik{})
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	for fp, want := range map[string]string{hex.EncodeToString(sum[:]): "ok", strings.Repeat("ab", 32): "down", "": "down"} {
		m := New()
		raw, _ := json.Marshal(Config{URL: srv.URL + "/traefik", Fingerprint: fp})
		if err := m.Configure(context.Background(), fakehost.New(nil), "t", raw); err != nil {
			t.Fatal(err)
		}
		if h := m.Health(context.Background(), "t"); !strings.HasPrefix(h.Status, want) && !(want == "ok" && h.Status == "degraded") {
			t.Fatalf("fingerprint %q: %+v", fp, h)
		}
	}
}
