package caddy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// A config with secrets in places Caddy keeps them: a DNS provider token, a
// basic auth hash, an EAB key, a loaded private key, a header value.
const config = `{
 "admin":{"listen":"localhost:2019"},
 "apps":{
  "http":{"servers":{"srv0":{"listen":[":443"],"routes":[
   {"match":[{"host":["app.example.com"]}],"handle":[{"handler":"subroute","routes":[
     {"match":[{"path":["/api/*"]}],"handle":[{"handler":"authentication","providers":{"http_basic":{"accounts":[{"username":"admin","password":"$2a$14$HASHHASHHASHHASHHASHHASH"}]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:8080"},{"dial":"10.0.0.6:8080"}]}]},
     {"handle":[{"handler":"headers","response":{"set":{"X-Token":["hdr-secret-value"]}}},{"handler":"file_server","root":"/srv/app"}]}
   ]}],"terminal":true},
   {"match":[{"host":["*.example.com"]}],"handle":[{"handler":"static_response","status_code":404}]}
  ]}}},
  "tls":{"automation":{"policies":[{"subjects":["*.example.com"],"issuers":[{"module":"acme","ca":"https://acme-v02.api.letsencrypt.org/directory","email":"me@example.com","external_account":{"key_id":"kid","mac_key":"eab-mac-secret"},"challenges":{"dns":{"provider":{"name":"cloudflare","api_token":"cf-api-token-secret"}}}}]}]},
         "certificates":{"automate":["extra.example.com"],"load_pem":[{"certificate":"-----BEGIN CERTIFICATE-----","key":"-----BEGIN PRIVATE KEY-----pem-key-secret"}]}}
 }}`

func cert(t *testing.T, cn string) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(240 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeCaddy struct {
	mu       sync.Mutex
	seen     []string
	fails    int
	root     string
	redirect string
	auth     bool
}

func (f *fakeCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth {
		if u, p, _ := r.BasicAuth(); u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	switch r.URL.Path {
	case "/config/":
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusFound)
			return
		}
		io.WriteString(w, config)
	case "/reverse_proxy/upstreams":
		_ = json.NewEncoder(w).Encode([]map[string]any{{"address": "10.0.0.6:8080", "num_requests": 2, "fails": f.fails}, {"address": "10.0.0.5:8080", "num_requests": 0, "fails": 0}})
	case "/pki/ca/local":
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "local", "name": "Caddy Local Authority", "root_certificate": f.root, "intermediate_certificate": f.root})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"unknown object path"}`)
	}
}

func setup(t *testing.T, c Config, f *fakeCaddy) *Module {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	c.URL = srv.URL
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://bad": "no"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in)})
}

func TestCaddy(t *testing.T) {
	f := &fakeCaddy{root: cert(t, "Caddy Local Authority - 2026 ECC Root")}
	m := setup(t, Config{}, f)
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "1 servers · 2 hosts" {
		t.Fatalf("%+v", h)
	}
	f.fails = 3
	if h := m.Health(context.Background(), "c"); h.Status != "degraded" || !strings.Contains(h.Message, "10.0.0.6:8080") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"summary", `{}`, `"hosts":["*.example.com","app.example.com"]`},
		{"summary", `{}`, `"upstreams":2`},
		{"routes", `{}`, `"paths":["/api/*"],"handlers":["authentication","reverse_proxy"],"upstreams":["10.0.0.5:8080","10.0.0.6:8080"]`},
		{"routes", `{"host":"app.example.com"}`, `"fileRoots":["/srv/app"]`},
		{"routes", `{"host":"other.example.com"}`, `"staticStatus":"404"`},
		{"upstreams", `{}`, `{"address":"10.0.0.5:8080","numRequests":0,"fails":0}`},
		{"tls", `{}`, `"challenge":"dns (cloudflare)"`},
		{"tls", `{}`, `"managedNames":["*.example.com","app.example.com","extra.example.com"]`},
		{"tls", `{}`, `"issuers":["acme (acme-v02.api.letsencrypt.org)"]`},
		{"pki_ca", `{}`, `"commonName":"Caddy Local Authority - 2026 ECC Root"`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
		for _, secret := range []string{"HASH", "hdr-secret", "eab-mac", "cf-api-token", "pem-key", "BEGIN", "me@example.com"} {
			if strings.Contains(string(r.Output), secret) {
				t.Fatalf("%s leaked %s: %s", c.action, secret, r.Output)
			}
		}
	}
	if r, _ := invoke(m, "routes", `{"host":"other.example.org"}`); string(r.Output) != `[]` {
		t.Fatalf("%s", r.Output)
	}
	if _, err := invoke(m, "routes", `{"server":"srv9"}`); err == nil || !strings.Contains(err.Error(), "srv0") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "pki_ca", `{"id":"other"}`); err == nil || !strings.Contains(err.Error(), "no CA") {
		t.Fatal(err)
	}
	for _, s := range f.seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Fatalf("changed something: %s", s)
		}
	}
}

func TestCaddyValidation(t *testing.T) {
	f := &fakeCaddy{auth: true}
	m := setup(t, Config{Username: "admin", Password: "secret://pw"}, f)
	if h := m.Health(context.Background(), "c"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	f.seen = nil
	for _, c := range []struct{ action, in string }{
		{"routes", `{"server":"../load"}`},
		{"routes", `{"host":"a b"}`},
		{"pki_ca", `{"id":"local/../../load"}`},
		{"load", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Caddy: %v", f.seen)
	}
	bad := setup(t, Config{Username: "admin", Password: "secret://bad"}, f)
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []Config{{URL: "127.0.0.1:2019"}, {URL: "http://u:p@127.0.0.1:2019"}, {URL: "http://127.0.0.1:2019?x=1"}, {Username: "a", Password: "plain"}, {Password: "secret://pw"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// The default address is used when none is given.
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	f.redirect = other.URL
	if h := m.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}

// Route paths can hold tokens, so routes is sensitive (kept out of the
// audit log's values).
func TestCaddyRoutesSensitive(t *testing.T) {
	for _, a := range New().Manifest().Actions {
		if a.Name == "routes" && (!a.Sensitive || a.Risk != sdk.RiskRead) {
			t.Fatalf("%+v", a)
		}
	}
}
