package searchconsole

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeGoogle struct {
	mu       sync.Mutex
	key      *rsa.PublicKey
	api      []string
	tokens   int
	claims   map[string]any
	valid    map[string]bool
	lastBody map[string]any
	redirect string
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/token" {
		form, _ := url.ParseQuery(string(body))
		f.tokens++
		ok := false
		if form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			parts := strings.Split(form.Get("assertion"), ".")
			if len(parts) == 3 {
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				c, _ := base64.RawURLEncoding.DecodeString(parts[1])
				f.claims = map[string]any{}
				json.Unmarshal(c, &f.claims)
				ok = rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig) == nil
			}
		}
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
			return
		}
		tok := fmt.Sprintf("ya29.ACCESS-%d", f.tokens)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599}`, tok)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`)
		return
	}
	f.api = append(f.api, r.Method+" "+r.URL.EscapedPath())
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
		return
	}
	f.lastBody = nil
	if len(body) > 0 {
		f.lastBody = map[string]any{}
		json.Unmarshal(body, &f.lastBody)
	}
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /webmasters/v3/sites":
		io.WriteString(w, `{"siteEntry":[{"siteUrl":"sc-domain:example.com","permissionLevel":"siteFullUser"},{"siteUrl":"https://blog.example.com/","permissionLevel":"siteRestrictedUser"}]}`)
	case "POST /webmasters/v3/sites/sc-domain:example.com/searchAnalytics/query":
		io.WriteString(w, `{"rows":[{"keys":["conduit"],"clicks":12,"impressions":300,"ctr":0.04,"position":3.2},{"keys":["control plane"],"clicks":5,"impressions":90,"ctr":0.055,"position":7.1},{"keys":["x"],"clicks":1,"impressions":1,"ctr":1,"position":1}],"responseAggregationType":"byProperty"}`)
	case "GET /webmasters/v3/sites/https:%2F%2Fblog.example.com%2F/sitemaps":
		io.WriteString(w, `{"sitemap":[{"path":"https://blog.example.com/sitemap.xml","type":"sitemap","lastSubmitted":"2026-10-01T00:00:00Z","isPending":false,"warnings":"0","errors":"1","contents":[{"type":"web","submitted":"42"}]}]}`)
	case "GET /webmasters/v3/sites/sc-domain:other.org/sitemaps":
		w.WriteHeader(403)
		io.WriteString(w, `{"error":{"code":403,"message":"User does not have sufficient permission for site 'sc-domain:other.org'."}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
	}
}

func saKey(t *testing.T) (string, *rsa.PublicKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "conduit@proj.iam.gserviceaccount.com", "private_key_id": "kid1",
		"private_key": pemKey, "token_uri": "https://evil.example/token"})
	return string(b), &k.PublicKey
}

func setup(t *testing.T, ref string) (*Module, *fakeGoogle) {
	t.Helper()
	key, pub := saKey(t)
	other, _ := saKey(t)
	f := &fakeGoogle{valid: map[string]bool{}, key: pub}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.TokenURL = srv.URL, srv.URL+"/token"
	raw, _ := json.Marshal(Config{ServiceAccount: ref})
	h := fakehost.New(map[string]string{"secret://sa": key, "secret://other": other, "secret://junk": "not json LEAKME"})
	if err := m.Configure(context.Background(), h, "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{"ya29.", "LEAKME", "PRIVATE KEY", "assertion"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaks %q: %s", bad, s)
		}
	}
}

func TestJWTExchangeAndReads(t *testing.T) {
	m, f := setup(t, "secret://sa")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "2 sites" {
		t.Fatalf("%+v", h)
	}
	if f.claims["iss"] != "conduit@proj.iam.gserviceaccount.com" || f.claims["scope"] != Scope || !strings.HasSuffix(f.claims["aud"].(string), "/token") {
		t.Fatalf("claims %v", f.claims)
	}
	r, err := call(m, "sites", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"permission":"siteRestrictedUser"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = call(m, "search_analytics", `{"site":"sc-domain:Example.com","dimensions":["query"],"limit":2,"days":7}`)
	if err != nil || !strings.Contains(string(r.Output), `"query":"control plane"`) || strings.Contains(string(r.Output), `"query":"x"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	today := time.Now().UTC()
	if f.lastBody["startDate"] != today.AddDate(0, 0, -6).Format("2006-01-02") || f.lastBody["endDate"] != today.Format("2006-01-02") || f.lastBody["rowLimit"] != float64(2) || f.lastBody["type"] != "web" {
		t.Fatalf("%v", f.lastBody)
	}
	if _, err := call(m, "search_analytics", `{"site":"sc-domain:example.com","from":"2025-07-01","to":"2026-10-31","type":"image"}`); err != nil {
		t.Fatal(err)
	}
	if f.lastBody["dimensions"] != nil || f.lastBody["type"] != "image" {
		t.Fatalf("%v", f.lastBody)
	}
	r, err = call(m, "sitemaps", `{"site":"https://blog.example.com/"}`)
	if err != nil || !strings.Contains(string(r.Output), `"errors":"1"`) || !strings.Contains(string(r.Output), `"submitted":"42"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := call(m, "sitemaps", `{"site":"sc-domain:other.org"}`); err == nil || !strings.Contains(err.Error(), "add the service account") {
		t.Fatal(err)
	}
	if f.tokens != 1 {
		t.Fatalf("token not cached: %d", f.tokens)
	}
}

func TestBadCredentials(t *testing.T) {
	for _, ref := range []string{"secret://other", "secret://junk", "secret://missing"} {
		m, f := setup(t, ref)
		h := m.Health(context.Background(), "s")
		if h.Status != "down" {
			t.Fatalf("%s: %+v", ref, h)
		}
		noLeak(t, h.Message)
		if _, err := call(m, "sites", `{}`); err == nil {
			t.Fatal(ref)
		} else {
			noLeak(t, err.Error())
		}
		if len(f.api) != 0 {
			t.Fatal(f.api)
		}
	}
}

func TestSettingsRefused(t *testing.T) {
	for _, raw := range []string{`{}`, `{"serviceAccount":"{\"type\":\"service_account\"}"}`, `[`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestInvalidInputNeverReachesGoogle(t *testing.T) {
	m, f := setup(t, "secret://sa")
	for _, c := range []struct{ action, in string }{
		{"sitemaps", `{}`},
		{"sitemaps", `{"site":"example.com"}`},
		{"sitemaps", `{"site":"sc-domain:../x"}`},
		{"sitemaps", `{"site":"https://example.com/?x=1"}`},
		{"sitemaps", `{"site":"https://u:p@example.com/"}`},
		{"sitemaps", `{"site":"https://example.com/a/../b/"}`},
		{"sitemaps", `{"site":"ftp://example.com/"}`},
		{"sitemaps", `{"site":"https://example.com:/"}`},
		{"search_analytics", `{"site":"sc-domain:example.com","dimensions":["userId"]}`},
		{"search_analytics", `{"site":"sc-domain:example.com","dimensions":["query","query"]}`},
		{"search_analytics", `{"site":"sc-domain:example.com","dimensions":["query","page","country","device"]}`},
		{"search_analytics", `{"site":"sc-domain:example.com","type":"all"}`},
		{"search_analytics", `{"site":"sc-domain:example.com","limit":1001}`},
		{"search_analytics", `{"site":"sc-domain:example.com","days":481}`},
		{"search_analytics", `{"site":"sc-domain:example.com","from":"2025-01-01","to":"2026-05-02"}`},
		{"search_analytics", `{"site":"sc-domain:example.com","from":"2026-01-02","to":"2026-01-01"}`},
		{"search_analytics", `{"site":"sc-domain:example.com","to":"2026-01-01"}`},
	} {
		if _, err := call(m, c.action, c.in); err == nil {
			t.Errorf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.api) != 0 {
		t.Fatalf("invalid input reached Google: %v", f.api)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	m, f := setup(t, "secret://sa")
	f.redirect = other.URL + "/x"
	if _, err := call(m, "sites", `{}`); !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("followed")
	}
}
