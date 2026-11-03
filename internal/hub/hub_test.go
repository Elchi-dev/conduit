package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type captureMailer struct {
	mu   sync.Mutex
	sent []string
}

func (m *captureMailer) Name() string { return "capture" }
func (m *captureMailer) Send(_ context.Context, to, subject, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to+"\n"+subject+"\n"+text)
	return nil
}

var tokenInMail = regexp.MustCompile(`\?token=([0-9a-z]+)`)

// lastToken returns the token from the newest mail to an address.
func (m *captureMailer) lastToken(t *testing.T, to string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if strings.HasPrefix(m.sent[i], to+"\n") {
			if mm := tokenInMail.FindStringSubmatch(m.sent[i]); mm != nil {
				return mm[1]
			}
		}
	}
	t.Fatalf("no mail with a token to %s", to)
	return ""
}

type harness struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	mail *captureMailer
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	cfg := Config{DatabaseURL: filepath.Join(t.TempDir(), "hub.db"), PublicURL: "https://hub.test", Name: "Test hub", OpenRegistration: true, AdminEmail: "root@example.com"}
	// CI also runs these tests against PostgreSQL.
	if pg := os.Getenv("CONDUIT_HUB_TEST_POSTGRES"); pg != "" {
		resetPostgres(t, pg)
		cfg.DatabaseURL = pg
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	m := &captureMailer{}
	s.mail = m
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return &harness{t: t, srv: s, ts: ts, mail: m}
}

func resetPostgres(t *testing.T, url string) {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) do(method, path, tok string, body any, want int) map[string]any {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		h.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.StatusCode, want, raw)
	}
	out := map[string]any{}
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	} else if len(raw) > 0 && raw[0] == '[' {
		var arr []any
		_ = json.Unmarshal(raw, &arr)
		out["items"] = arr
	}
	return out
}

// signup registers, verifies and signs in, returning a session token.
func (h *harness) signup(email string) string {
	h.do("POST", "/v1/accounts", "", map[string]string{"email": email, "password": "correct horse battery"}, 202)
	h.do("POST", "/v1/accounts/verify", "", map[string]string{"token": h.mail.lastToken(h.t, email)}, 200)
	res := h.do("POST", "/v1/sessions", "", map[string]string{"email": email, "password": "correct horse battery"}, 200)
	return res["token"].(string)
}

func TestAccounts(t *testing.T) {
	h := newHarness(t, nil)
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "nope", "password": "correct horse battery"}, 400)
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "a@example.com", "password": "short"}, 400)

	tok := h.signup("a@example.com")
	me := h.do("GET", "/v1/me", tok, nil, 200)
	acct := me["account"].(map[string]any)
	if acct["verified"] != true || acct["admin"] != false {
		t.Fatalf("account: %v", acct)
	}

	// Registering again doesn't reveal that the address exists.
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "a@example.com", "password": "another password"}, 202)
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "a@example.com", "password": "another password"}, 401)
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "ghost@example.com", "password": "whatever123"}, 401)

	// A verification link works once.
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "b@example.com", "password": "correct horse battery"}, 202)
	vt := h.mail.lastToken(t, "b@example.com")
	h.do("POST", "/v1/accounts/verify", "", map[string]string{"token": vt}, 200)
	h.do("POST", "/v1/accounts/verify", "", map[string]string{"token": vt}, 400)

	// Password reset ends every session.
	h.do("POST", "/v1/accounts/password-reset", "", map[string]string{"email": "a@example.com"}, 202)
	h.do("POST", "/v1/accounts/password-reset", "", map[string]string{"email": "ghost@example.com"}, 202)
	h.do("POST", "/v1/accounts/password-reset/confirm", "", map[string]string{"token": h.mail.lastToken(t, "a@example.com"), "password": "a brand new password"}, 200)
	h.do("GET", "/v1/me", tok, nil, 401)
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "a@example.com", "password": "a brand new password"}, 200)

	// The admin address becomes an admin.
	root := h.signup("root@example.com")
	if h.do("GET", "/v1/me", root, nil, 200)["account"].(map[string]any)["admin"] != true {
		t.Fatal("admin email should be admin")
	}
}

func TestClosedRegistration(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OpenRegistration = false })
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "x@example.com", "password": "correct horse battery"}, 403)
	h.signup("root@example.com")
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < 20; i++ {
		h.do("POST", "/v1/sessions", "", map[string]string{"email": "a@example.com", "password": "x"}, 401)
	}
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "a@example.com", "password": "x"}, 429)
}

func TestOrgs(t *testing.T) {
	h := newHarness(t, nil)
	alice := h.signup("alice@example.com")
	bob := h.signup("bob@example.com")
	org := h.do("POST", "/v1/orgs", alice, map[string]string{"name": "Acme"}, 201)
	id := org["id"].(string)

	h.do("POST", "/v1/orgs/"+id+"/invites", bob, map[string]string{"email": "bob@example.com"}, 403)
	h.do("POST", "/v1/orgs/"+id+"/invites", alice, map[string]string{"email": "bob@example.com", "role": "admin"}, 202)
	inv := h.mail.lastToken(t, "bob@example.com")
	carol := h.signup("carol@example.com")
	h.do("POST", "/v1/invites/accept", carol, map[string]string{"token": inv}, 403)
	h.do("POST", "/v1/invites/accept", bob, map[string]string{"token": inv}, 200)
	h.do("POST", "/v1/invites/accept", bob, map[string]string{"token": inv}, 400)

	members := h.do("GET", "/v1/orgs/"+id+"/members", bob, nil, 200)["items"].([]any)
	if len(members) != 2 {
		t.Fatalf("members: %v", members)
	}
	h.do("GET", "/v1/orgs/"+id+"/members", carol, nil, 404)

	me := h.do("GET", "/v1/me", alice, nil, 200)["account"].(map[string]any)["id"].(string)
	// The last owner can't leave.
	h.do("DELETE", "/v1/orgs/"+id+"/members/"+me, alice, nil, 409)
	// An admin can't remove the owner.
	h.do("DELETE", "/v1/orgs/"+id+"/members/"+me, bob, nil, 403)
}

func pairDaemon(h *harness, tok string) (string, string) {
	code := h.do("POST", "/v1/pairing-codes", tok, nil, 201)["code"].(string)
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	res := h.do("POST", "/v1/devices/pair", "", map[string]string{"code": code, "name": "desk", "kind": "daemon", "publicKey": pub}, 201)
	h.do("POST", "/v1/devices/pair", "", map[string]string{"code": code, "name": "again", "kind": "daemon", "publicKey": pub}, 400)
	return res["device"].(map[string]any)["id"].(string), res["token"].(string)
}

func TestDevicesAndRelay(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.signup("a@example.com")
	devID, devTok := pairDaemon(h, tok)

	// Device tokens can't do person things.
	h.do("POST", "/v1/orgs", devTok, map[string]string{"name": "x"}, 403)
	h.do("POST", "/v1/keys", devTok, map[string]any{"scopes": []string{"sync"}}, 403)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(h.ts.URL, "http")

	// Clients can't reach an offline daemon.
	if _, _, err := websocket.Dial(ctx, wsURL+"/v1/relay/connect/"+devID, nil); err == nil {
		t.Fatal("dial to offline daemon should fail")
	}
	// Only daemon device tokens may offer an endpoint.
	if _, _, err := websocket.Dial(ctx, wsURL+"/v1/relay/daemon", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}}}); err == nil {
		t.Fatal("a session token must not open a daemon socket")
	}

	d, _, err := websocket.Dial(ctx, wsURL+"/v1/relay/daemon", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + devTok}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.CloseNow()
	// Echo server: reverse each frame back on the same stream.
	go func() {
		for {
			typ, b, err := d.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageBinary {
				out := append([]byte{}, b[:4]...)
				for i := len(b) - 1; i >= 4; i-- {
					out = append(out, b[i])
				}
				_ = d.Write(ctx, websocket.MessageBinary, out)
			}
		}
	}()
	waitFor(t, func() bool { return h.srv.relay.online(devID) })

	devs := h.do("GET", "/v1/devices", tok, nil, 200)["items"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["online"] != true {
		t.Fatalf("devices: %v", devs)
	}

	c1, _, err := websocket.Dial(ctx, wsURL+"/v1/relay/connect/"+devID, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := websocket.Dial(ctx, wsURL+"/v1/relay/connect/"+devID, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range []*websocket.Conn{c1, c2} {
		msg := []byte("abc" + string(rune('0'+i)))
		if err := c.Write(ctx, websocket.MessageBinary, msg); err != nil {
			t.Fatal(err)
		}
		_, got, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(rune('0'+i))+"cba" {
			t.Fatalf("client %d got %q", i, got)
		}
	}
	c1.Close(websocket.StatusNormalClosure, "")
	c2.Close(websocket.StatusNormalClosure, "")

	// Revoking the device drops its relay connection.
	h.do("DELETE", "/v1/devices/"+devID, tok, nil, 204)
	waitFor(t, func() bool { return !h.srv.relay.online(devID) })
	h.do("GET", "/v1/me", devTok, nil, 401)
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestSyncAndKeys(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.signup("a@example.com")
	key := h.do("POST", "/v1/keys", tok, map[string]any{"name": "ci", "scopes": []string{"sync"}}, 201)
	secret := key["secret"].(string)
	h.do("POST", "/v1/keys", tok, map[string]any{"scopes": []string{"releases:publish"}}, 403)
	h.do("POST", "/v1/keys", tok, map[string]any{"scopes": []string{"nope"}}, 400)

	h.do("PUT", "/v1/sync/settings", secret, map[string]any{"version": 0, "data": "ct1"}, 200)
	h.do("PUT", "/v1/sync/settings", secret, map[string]any{"version": 0, "data": "ct-race"}, 409)
	h.do("PUT", "/v1/sync/settings", tok, map[string]any{"version": 1, "data": "ct2"}, 200)
	conflict := h.do("PUT", "/v1/sync/settings", secret, map[string]any{"version": 1, "data": "stale"}, 409)
	if conflict["current"].(map[string]any)["version"].(float64) != 2 {
		t.Fatalf("conflict: %v", conflict)
	}
	got := h.do("GET", "/v1/sync/settings", secret, nil, 200)
	if got["data"] != "ct2" {
		t.Fatalf("blob: %v", got)
	}
	h.do("PUT", "/v1/sync/Bad Key", secret, map[string]any{"data": "x"}, 400)
	// A sync key can't read orgs.
	h.do("GET", "/v1/orgs", secret, nil, 403)

	// Other accounts see nothing.
	other := h.signup("b@example.com")
	h.do("GET", "/v1/sync/settings", other, nil, 404)

	id := key["key"].(map[string]any)["id"].(string)
	h.do("DELETE", "/v1/keys/"+id, tok, nil, 204)
	h.do("GET", "/v1/sync", secret, nil, 401)
}

func signed(t *testing.T, priv ed25519.PrivateKey, v any) map[string]string {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))}
}

func TestRegistry(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.signup("a@example.com")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.do("POST", "/v1/registry/authors", tok, map[string]string{"handle": "acme", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 201)
	other := h.signup("b@example.com")
	h.do("POST", "/v1/registry/authors", other, map[string]string{"handle": "acme", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 409)

	name := url.PathEscape("acme/weather")
	payload := VersionPayload{Name: "acme/weather", Version: "1.0.0", Description: "Forecasts", Manifest: json.RawMessage(`{"id":"weather"}`),
		Artifacts: []Artifact{{Platform: "linux-amd64", URL: "https://example.com/w", SHA256: strings.Repeat("a", 64)}}}
	h.do("POST", "/v1/registry/packages/"+name+"/versions", tok, signed(t, priv, payload), 201)
	h.do("POST", "/v1/registry/packages/"+name+"/versions", tok, signed(t, priv, payload), 409)

	// A wrong key is refused.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	payload.Version = "1.1.0"
	h.do("POST", "/v1/registry/packages/"+name+"/versions", tok, signed(t, wrong, payload), 400)
	h.do("POST", "/v1/registry/packages/"+name+"/versions", tok, signed(t, priv, payload), 201)
	payload.Version = "2.0.0-beta.1"
	h.do("POST", "/v1/registry/packages/"+name+"/versions", tok, signed(t, priv, payload), 201)

	// Someone else's namespace is refused.
	h.do("POST", "/v1/registry/authors", other, map[string]string{"handle": "bob", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 201)
	h.do("POST", "/v1/registry/packages/"+name+"/versions", other, signed(t, priv, payload), 403)

	pkg := h.do("GET", "/v1/registry/packages/"+name, "", nil, 200)
	if pkg["package"].(map[string]any)["latest"] != "1.1.0" {
		t.Fatalf("latest should skip the pre-release: %v", pkg["package"])
	}
	if len(pkg["versions"].([]any)) != 3 {
		t.Fatalf("versions: %v", pkg["versions"])
	}
	h.do("POST", "/v1/registry/packages/"+name+"/versions/1.1.0/yank", tok, nil, 204)
	if l := h.do("GET", "/v1/registry/packages/"+name, "", nil, 200)["package"].(map[string]any)["latest"]; l != "1.0.0" {
		t.Fatalf("after yank latest = %v", l)
	}
	found := h.do("GET", "/v1/registry/packages?q=forecast", "", nil, 200)["items"].([]any)
	if len(found) != 1 {
		t.Fatalf("search: %v", found)
	}
}

func TestReleases(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := newHarness(t, func(c *Config) { c.ReleaseKey = base64.StdEncoding.EncodeToString(pub) })
	root := h.signup("root@example.com")
	user := h.signup("u@example.com")
	rel := ReleasePayload{Component: "daemon", Channel: "stable", Platform: "linux-amd64", Version: "0.1.0", URL: "https://example.com/d", SHA256: strings.Repeat("b", 64)}
	h.do("POST", "/v1/releases", user, signed(t, priv, rel), 403)
	h.do("POST", "/v1/releases", root, signed(t, priv, rel), 201)
	rel.Version = "0.2.0"
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	h.do("POST", "/v1/releases", root, signed(t, wrong, rel), 400)
	h.do("POST", "/v1/releases", root, signed(t, priv, rel), 201)

	got := h.do("GET", "/v1/updates/daemon/stable/linux-amd64?current=0.1.0", "", nil, 200)
	if got["version"] != "0.2.0" {
		t.Fatalf("latest: %v", got)
	}
	raw, _ := base64.StdEncoding.DecodeString(got["payload"].(string))
	sig, _ := base64.StdEncoding.DecodeString(got["signature"].(string))
	if !ed25519.Verify(pub, raw, sig) {
		t.Fatal("served release must verify against the release key")
	}
	h.do("GET", "/v1/updates/daemon/stable/linux-amd64?current=0.2.0", "", nil, 204)
	h.do("GET", "/v1/updates/daemon/beta/linux-amd64", "", nil, 404)
}

func TestSemver(t *testing.T) {
	cases := [][2]string{{"1.0.0", "1.0.1"}, {"1.9.0", "1.10.0"}, {"1.0.0-beta", "1.0.0"}, {"v0.1.0", "0.2.0"}}
	for _, c := range cases {
		if !semverLess(c[0], c[1]) || semverLess(c[1], c[0]) {
			t.Errorf("%s < %s", c[0], c[1])
		}
	}
}

func TestRoutesMatchOpenAPI(t *testing.T) {
	spec, err := os.ReadFile("../../api/openapi/hub.yaml")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	pathRe := regexp.MustCompile(`^  (/\S*):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|delete|patch):\s*$`)
	var cur string
	for _, line := range strings.Split(string(spec), "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if m := methodRe.FindStringSubmatch(line); m != nil && cur != "" {
			documented[strings.ToUpper(m[1])+" "+cur] = true
		}
		if !strings.HasPrefix(line, "  ") && strings.TrimSpace(line) != "" {
			cur = ""
		}
	}
	served := map[string]bool{}
	for _, r := range (&Server{}).routes() {
		method, path, _ := strings.Cut(r.pattern, " ")
		if path == "/healthz" {
			continue
		}
		path = strings.TrimPrefix(path, "/v1")
		served[method+" "+path] = true
		if !documented[method+" "+path] {
			t.Errorf("route %s %s is not in api/openapi/hub.yaml", method, path)
		}
	}
	for d := range documented {
		if !served[d] {
			t.Errorf("documented %s is not served", d)
		}
	}
}
