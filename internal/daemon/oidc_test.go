package daemon

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/elchi-dev/conduit/internal/vault"
)

// fakeIdP is a minimal OpenID Connect provider.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]fakeCode
	claims map[string]any // claims for the next authorization
	nonce  string         // overrides the nonce when set
}

type fakeCode struct {
	challenge, redirect, nonce string
	claims                     map[string]any
}

func newIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k, codes: map[string]fakeCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, sec, ok := r.BasicAuth()
		if !ok {
			id, sec = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if id != "conduit" || sec != "s3cret-from-vault" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		f.mu.Lock()
		c, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.Form.Get("redirect_uri") != c.redirect {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "conduit", "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": c.nonce}
		for k, v := range c.claims {
			claims[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": f.sign(t, claims)})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

// authorize plays the provider's sign-in page: it takes the authorization
// URL the daemon redirected to and returns the callback URL.
func (f *fakeIdP) authorize(t *testing.T, authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorization request without PKCE or nonce: %s", authURL)
	}
	code := randomToken()
	nonce := q.Get("nonce")
	if f.nonce != "" {
		nonce = f.nonce
	}
	f.mu.Lock()
	f.codes[code] = fakeCode{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), nonce: nonce, claims: f.claims}
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

type browser struct {
	t *testing.T
	c *http.Client
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) get(u string) *http.Response {
	b.t.Helper()
	res, err := b.c.Get(u)
	if err != nil {
		b.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// signIn runs the whole flow and returns where the daemon sent the browser.
func (b *browser) signIn(base string, idp *fakeIdP) string {
	b.t.Helper()
	res := b.get(base + "/api/v1/auth/oidc/start")
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), idp.srv.URL+"/auth") {
		b.t.Fatalf("start: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res = b.get(idp.authorize(b.t, res.Header.Get("Location")))
	return res.Header.Get("Location")
}

func TestOIDC(t *testing.T) {
	app, c, _, _ := setup(t)
	ctx := context.Background()
	if err := app.Vault.Setup(ctx, "a long vault passphrase"); err != nil {
		t.Fatal(err)
	}
	_ = app.Vault.Put(ctx, vault.Meta{Name: "sso/client", Kind: vault.KindToken}, "s3cret-from-vault")
	idp := newIdP(t)

	var pub map[string]any
	c.do("GET", "/api/v1/auth/oidc", nil, &pub)
	if pub["enabled"] != false {
		t.Fatalf("enabled before setup: %v", pub)
	}
	settings := map[string]any{"enabled": true, "issuer": idp.srv.URL, "clientId": "conduit", "clientSecret": "plain-secret",
		"label": "Example SSO", "allowedDomains": []string{"example.com"}, "autoCreate": true, "newUserRole": "member"}
	if code := c.do("PUT", "/api/v1/auth/oidc", settings, nil); code != 400 {
		t.Fatalf("plaintext secret accepted: %d", code)
	}
	settings["newUserRole"] = "owner"
	settings["clientSecret"] = "secret://sso/client"
	if code := c.do("PUT", "/api/v1/auth/oidc", settings, nil); code != 400 {
		t.Fatalf("owner role for new accounts accepted: %d", code)
	}
	settings["newUserRole"] = "member"
	var got map[string]any
	if code := c.do("PUT", "/api/v1/auth/oidc", settings, &got); code != 200 {
		t.Fatalf("save settings: %d %v", code, got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "s3cret-from-vault") || !strings.HasSuffix(got["redirectUri"].(string), "/api/v1/auth/oidc/callback") {
		t.Fatalf("settings: %s", raw)
	}
	c.do("GET", "/api/v1/auth/oidc", nil, &pub)
	if pub["enabled"] != true || pub["label"] != "Example SSO" {
		t.Fatalf("public: %v", pub)
	}

	// Success: a verified address in an allowed domain gets a member account.
	idp.claims = map[string]any{"email": "sam@example.com", "email_verified": true, "name": "Sam"}
	b := newBrowser(t)
	if loc := b.signIn(c.base, idp); loc != "/" {
		t.Fatalf("signed in to %q", loc)
	}
	u, _ := url.Parse(c.base)
	var sess string
	for _, ck := range b.c.Jar.Cookies(u) {
		if ck.Name == SessionCookie {
			sess = ck.Value
		}
	}
	me := client{t: t, base: c.base, token: sess}
	var who sessionResp
	if code := me.do("GET", "/api/v1/me", nil, &who); code != 200 || who.User.Email != "sam@example.com" || who.User.Role != "member" {
		t.Fatalf("me: %d %+v", code, who.User)
	}

	fail := func(name, want string) {
		t.Helper()
		loc := newBrowser(t).signIn(c.base, idp)
		if loc != "/?signin_error="+want {
			t.Fatalf("%s: redirected to %q, want error %s", name, loc, want)
		}
	}
	idp.claims = map[string]any{"email": "sam@example.com", "email_verified": false}
	fail("unverified email", "unverified")
	idp.claims = map[string]any{"email": "eve@elsewhere.org", "email_verified": true}
	fail("other domain", "domain")
	idp.claims = map[string]any{"email": "sam@example.com", "email_verified": true}
	idp.nonce = "not-the-nonce"
	fail("wrong nonce", "token")
	idp.nonce = ""

	// A state can't be completed in another browser, or used twice.
	b1 := newBrowser(t)
	res := b1.get(c.base + "/api/v1/auth/oidc/start")
	cb := idp.authorize(t, res.Header.Get("Location"))
	if loc := newBrowser(t).get(cb).Header.Get("Location"); loc != "/?signin_error=state" {
		t.Fatalf("callback in another browser: %q", loc)
	}
	if loc := b1.get(cb).Header.Get("Location"); loc != "/" {
		t.Fatalf("callback in the right browser: %q", loc)
	}
	if loc := b1.get(cb).Header.Get("Location"); loc != "/?signin_error=state" && loc != "/?signin_error=expired" {
		t.Fatalf("replayed callback: %q", loc)
	}

	// Disabled accounts stay out.
	if _, err := app.Store.DB.Exec(`UPDATE users SET disabled = 1 WHERE email = ?`, "sam@example.com"); err != nil {
		t.Fatal(err)
	}
	fail("disabled user", "disabled")

	// Without auto-create, unknown addresses are refused.
	settings["autoCreate"] = false
	c.do("PUT", "/api/v1/auth/oidc", settings, nil)
	idp.claims = map[string]any{"email": "new@example.com", "email_verified": true}
	fail("no account", "no_account")

	// Settings are people-only.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ci", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	key := client{t: t, base: c.base, token: k.Secret}
	if code := key.do("GET", "/api/v1/auth/oidc/settings", nil, nil); code != 403 {
		t.Fatalf("key read settings: %d", code)
	}
}
