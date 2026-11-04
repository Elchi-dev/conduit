package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/hub"
)

type hubMail struct {
	mu   sync.Mutex
	sent []string
}

func (m *hubMail) Name() string { return "test" }
func (m *hubMail) Send(_ context.Context, to, subject, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to+"\n"+subject+"\n"+text)
	return nil
}

var hubTokenRe = regexp.MustCompile(`\?token=([0-9a-z]+)`)

// testHub is a real hub, for the daemon's side of the marketplace.
type testHub struct {
	t    *testing.T
	url  string
	mail *hubMail
}

func newTestHub(t *testing.T) *testHub {
	t.Helper()
	cfg := hub.Config{DatabaseURL: filepath.Join(t.TempDir(), "hub.db"), PublicURL: "https://hub.test", Name: "Test hub", OpenRegistration: true, AdminEmail: "root@example.com"}
	s, err := hub.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	m := &hubMail{}
	s.SetMailer(m)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return &testHub{t: t, url: ts.URL, mail: m}
}

func (h *testHub) call(method, path, tok string, body any, want int) map[string]any {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.url+path, rd)
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
		h.t.Fatalf("hub %s %s: %d, want %d: %s", method, path, res.StatusCode, want, raw)
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (h *testHub) signup(email string) string {
	h.call("POST", "/v1/accounts", "", map[string]string{"email": email, "password": "correct horse battery"}, 202)
	h.mail.mu.Lock()
	var tok string
	for _, m := range h.mail.sent {
		if strings.HasPrefix(m, email+"\n") {
			if mm := hubTokenRe.FindStringSubmatch(m); mm != nil {
				tok = mm[1]
			}
		}
	}
	h.mail.mu.Unlock()
	h.call("POST", "/v1/accounts/verify", "", map[string]string{"token": tok}, 200)
	return h.call("POST", "/v1/sessions", "", map[string]string{"email": email, "password": "correct horse battery"}, 200)["token"].(string)
}

func (h *testHub) pkg(name string) map[string]any {
	return h.call("GET", "/v1/registry/packages/"+url.PathEscape(name), "", nil, 200)["package"].(map[string]any)
}

// waitFor polls until ok or fails after a few seconds.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for " + what)
}

func TestMarketplaceThroughHub(t *testing.T) {
	wasm := buildEcho(t, "acme-echo")
	h := newTestHub(t)
	root := h.signup("root@example.com")
	alice := h.signup("alice@example.com")
	bob := h.signup("bob@example.com")

	// The download is served over https.
	files := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(wasm) }))
	defer files.Close()
	old := regHTTP
	regHTTP = files.Client()
	defer func() { regHTTP = old }()

	// Alice publishes acme/echo with a listing and an icon.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.call("POST", "/v1/registry/authors", alice, map[string]string{"handle": "acme", "publicKey": base64.StdEncoding.EncodeToString(pub)}, 201)
	sum := sha256.Sum256(wasm)
	payload, _ := json.Marshal(map[string]any{"name": "acme/echo", "version": "1.0.0", "description": "Echoes",
		"manifest":  map[string]any{"permissions": map[string]any{"network": []string{"api.example.com"}}},
		"artifacts": []map[string]string{{"platform": "wasm", "url": files.URL + "/echo.wasm", "sha256": hex.EncodeToString(sum[:])}}})
	esc := url.PathEscape("acme/echo")
	h.call("POST", "/v1/registry/packages/"+esc+"/versions", alice, map[string]string{"payload": base64.StdEncoding.EncodeToString(payload),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))}, 201)
	h.call("PUT", "/v1/registry/packages/"+esc+"/listing", alice, map[string]any{"readme": "# Echo\n\nSays it back.", "categories": []string{"dev"}, "license": "MIT"}, 200)
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 24)...)
	icon := h.call("PUT", "/v1/registry/packages/"+esc+"/icon", alice, map[string]string{"data": base64.StdEncoding.EncodeToString(png)}, 200)["icon"].(string)

	// Bob's daemon is paired with his account.
	app, c, _, _ := setup(t)
	code := h.call("POST", "/v1/pairing-codes", bob, nil, 201)["code"].(string)
	if _, err := app.Remote.LinkHub(context.Background(), h.url, code); err != nil {
		t.Fatal(err)
	}

	// Browse: categories, sorting, the listing and the icon pass through.
	var cats []map[string]any
	if st := c.do("GET", "/api/v1/registry/categories", nil, &cats); st != 200 || len(cats) < 10 {
		t.Fatalf("categories %d %v", st, cats)
	}
	var found []map[string]any
	if st := c.do("GET", "/api/v1/registry?category=dev&sort=rating", nil, &found); st != 200 || len(found) != 1 || found[0]["name"] != "acme/echo" {
		t.Fatalf("search %d %v", st, found)
	}
	var info map[string]any
	if st := c.do("GET", "/api/v1/registry/package?name=acme/echo", nil, &info); st != 200 {
		t.Fatalf("package %d %v", st, info)
	}
	l := info["listing"].(map[string]any)
	if l["readme"] != "# Echo\n\nSays it back." || l["license"] != "MIT" || l["icon"] != icon {
		t.Fatalf("listing %v", l)
	}
	req, _ := http.NewRequest("GET", c.base+"/api/v1/registry/media/"+icon, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("media %v %v", err, res)
	}
	res.Body.Close()
	if st := c.do("GET", "/api/v1/registry/media/not-an-id", nil, nil); st != 404 {
		t.Fatalf("bad media id %d", st)
	}

	// Installing counts an anonymous install.
	if st := c.do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": info["fingerprint"].(string)}, nil); st != 200 {
		t.Fatalf("install %d", st)
	}
	waitFor(t, "the install ping", func() bool { p := h.pkg("acme/echo"); return p["downloads"] == 1.0 && p["installs"] == 1.0 })

	// Rate and review as Bob's account, through the daemon.
	if st := c.do("PUT", "/api/v1/registry/reviews", map[string]any{"name": "acme/echo", "rating": 4, "body": "Does what it says"}, nil); st != 201 {
		t.Fatalf("rate %d", st)
	}
	var revs map[string]any
	c.do("GET", "/api/v1/registry/reviews?name=acme/echo", nil, &revs)
	if revs["count"] != 1.0 || revs["canReview"] != true || revs["mine"].(map[string]any)["rating"] != 4.0 {
		t.Fatalf("reviews %v", revs)
	}
	if st := c.do("PUT", "/api/v1/registry/reviews", map[string]any{"name": "acme/echo", "rating": 9}, nil); st != 400 {
		t.Fatalf("bad rating passes the hub's error on: %d", st)
	}

	// API keys can't rate or report: they aren't people.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ops", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	kc := client{t: t, base: c.base, token: k.Secret}
	if st := kc.do("POST", "/api/v1/registry/reports", map[string]string{"name": "acme/echo", "reason": "spam"}, nil); st != 403 {
		t.Fatalf("key reports: %d", st)
	}
	// Removing a rating follows the same rules as rating: people only, a
	// valid name, and it's audited.
	if st := kc.do("DELETE", "/api/v1/registry/reviews?name=acme/echo", nil, nil); st != 403 {
		t.Fatalf("key unrates: %d", st)
	}
	if st := c.do("DELETE", "/api/v1/registry/reviews?name=../../v1/admin", nil, nil); st != 400 {
		t.Fatalf("unrate with a bad name: %d", st)
	}
	if st := c.do("DELETE", "/api/v1/registry/reviews?name=acme/echo", nil, nil); st != 204 {
		t.Fatalf("unrate %d", st)
	}
	var audit []core.Entry
	c.do("GET", "/api/v1/audit?limit=5", nil, &audit)
	if len(audit) == 0 || audit[0].Action != "module_unrated" || !strings.Contains(string(audit[0].Input), "acme/echo") {
		t.Fatalf("unrate not audited: %+v", audit)
	}
	if st := c.do("PUT", "/api/v1/registry/reviews", map[string]any{"name": "acme/echo", "rating": 4, "body": "Does what it says"}, nil); st != 201 {
		t.Fatalf("rate again %d", st)
	}

	// Report it; the operator yanks the version as malware.
	if st := c.do("POST", "/api/v1/registry/reports", map[string]string{"name": "acme/echo", "version": "1.0.0", "reason": "malware", "details": "Phones home"}, nil); st != 201 {
		t.Fatalf("report %d", st)
	}
	if st := c.do("POST", "/api/v1/registry/reports", map[string]string{"name": "acme/echo", "reason": "spam"}, nil); st != 409 {
		t.Fatalf("second open report %d", st)
	}
	events, stop := app.Engine.Bus.Subscribe("registry.", 8)
	defer stop()
	rep := h.call("GET", "/v1/admin/reports", root, nil, 200)["items"].([]any)[0].(map[string]any)
	h.call("POST", "/v1/admin/reports/"+rep["id"].(string)+"/resolve", root, map[string]string{"action": "yank", "note": "Sends tokens away"}, 200)

	// The installed list warns, with the reason, and an event goes out once.
	var inst []InstalledModule
	c.do("GET", "/api/v1/registry/installed?check=1", nil, &inst)
	if len(inst) != 1 || inst[0].Advisory == nil || inst[0].Advisory.Status != "yanked" || inst[0].Advisory.Reason != "malware" || inst[0].Advisory.By != "operator" {
		t.Fatalf("installed %+v", inst)
	}
	select {
	case ev := <-events:
		if ev.Type != "registry.advisory" || !strings.Contains(string(ev.Data), "malware") {
			t.Fatalf("event %v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no registry.advisory event")
	}
	_ = app.Server.checkAdvisories(context.Background())
	select {
	case ev := <-events:
		t.Fatalf("the same advisory raised twice: %v", ev)
	case <-time.After(200 * time.Millisecond):
	}
	// The stored answer is shown without asking again.
	inst = nil
	c.do("GET", "/api/v1/registry/installed", nil, &inst)
	if inst[0].Advisory == nil {
		t.Fatal("advisory not kept")
	}

	// Delisted packages aren't offered.
	h.call("POST", "/v1/admin/registry/packages/"+esc+"/delist", root, map[string]string{"reason": "malware"}, 204)
	var e map[string]string
	if st := c.do("GET", "/api/v1/registry/package?name=acme/echo", nil, &e); st != 400 || !strings.Contains(e["error"], "removed from the marketplace") {
		t.Fatalf("delisted package %d %v", st, e)
	}

	// Removing it counts an uninstall and clears the warning.
	if st := c.do("DELETE", "/api/v1/registry/installed?name=acme/echo", nil, nil); st != 204 {
		t.Fatalf("remove %d", st)
	}
	waitFor(t, "the uninstall ping", func() bool { return h.pkg("acme/echo")["installs"] == 0.0 })
	if _, ok := app.Server.storedAdvisories(context.Background()).Modules["acme/echo"]; ok {
		t.Fatal("advisory kept after removal")
	}
}

func TestRatingNeedsPairing(t *testing.T) {
	_, c, _, _ := setup(t)
	// Without a link to a hub there's nothing to rate on.
	if st := c.do("PUT", "/api/v1/registry/reviews", map[string]any{"name": "acme/echo", "rating": 4}, nil); st != 409 {
		t.Fatalf("rate without a hub: %d", st)
	}
}
