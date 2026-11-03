package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildEcho(t *testing.T, id string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "echo.wasm")
	cmd := exec.Command("go", "build", "-ldflags", "-X main.moduleID="+id, "-o", out, "./testdata/echo")
	cmd.Dir = "../sandbox"
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("can't build the test module: %v %s", err, b)
	}
	b, _ := os.ReadFile(out)
	return b
}

type fakeRegistry struct {
	srv     *httptest.Server
	key     ed25519.PrivateKey
	wasm    []byte
	version string
	sum     string
}

func (f *fakeRegistry) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/acme-echo.wasm":
		w.Write(f.wasm)
	case "/v1/registry/packages/acme/echo":
		payload, _ := json.Marshal(map[string]any{"name": "acme/echo", "version": f.version, "description": "Echo",
			"manifest":  map[string]any{"permissions": map[string]any{"network": []string{"api.example.com"}}},
			"artifacts": []map[string]string{{"platform": "wasm", "url": f.srv.URL + "/acme-echo.wasm", "sha256": f.sum}}})
		sig := ed25519.Sign(f.key, payload)
		pub := f.key.Public().(ed25519.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"package":   map[string]any{"name": "acme/echo", "owner": "acme", "latest": f.version},
			"authorKey": base64.StdEncoding.EncodeToString(pub),
			"versions": []map[string]any{{"version": f.version, "payload": base64.StdEncoding.EncodeToString(payload),
				"signature": base64.StdEncoding.EncodeToString(sig)}},
		})
	default:
		w.WriteHeader(404)
	}
}

func TestRegistryInstall(t *testing.T) {
	good := buildEcho(t, "acme-echo")
	app, c, _, _ := setup(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeRegistry{key: key, wasm: good, version: "1.0.0"}
	s := sha256.Sum256(good)
	f.sum = hex.EncodeToString(s[:])
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handler))
	defer f.srv.Close()
	old := regHTTP
	regHTTP = f.srv.Client()
	defer func() { regHTTP = old }()
	_, _ = app.Store.DB.Exec(`INSERT INTO settings(key, value) VALUES ('registry.url', ?)`, f.srv.URL)

	var info map[string]any
	if code := c.do("GET", "/api/v1/registry/package?name=acme/echo", nil, &info); code != 200 || info["installable"] != true {
		t.Fatalf("package: %d %v", code, info)
	}
	fp := info["fingerprint"].(string)
	if code := c.do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": "not-it"}, nil); code != 409 {
		t.Fatalf("install with another fingerprint: %d", code)
	}
	var im InstalledModule
	if code := c.do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": fp}, &im); code != 200 || im.ModuleID != "acme-echo" {
		t.Fatalf("install: %d %+v", code, im)
	}
	if _, ok := app.Engine.Module("acme-echo"); !ok {
		t.Fatal("module not running")
	}

	// A changed download is refused.
	f.sum = hex.EncodeToString(make([]byte, 32))
	if code := c.do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": fp}, nil); code != 502 {
		t.Fatalf("bad checksum: %d", code)
	}
	f.sum = hex.EncodeToString(s[:])

	// The registry swapping the author key is refused for an installed package.
	_, f.key, _ = ed25519.GenerateKey(rand.Reader)
	if code := c.do("GET", "/api/v1/registry/package?name=acme/echo", nil, nil); code != 400 {
		t.Fatalf("swapped key: %d", code)
	}
	f.key = key

	// Modules must use their author's id space.
	f.wasm = buildEcho(t, "vaultish")
	s2 := sha256.Sum256(f.wasm)
	f.sum = hex.EncodeToString(s2[:])
	if code := c.do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": fp}, nil); code != 400 {
		t.Fatalf("foreign module id: %d", code)
	}

	// API keys can't install.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ops", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	if code := (client{t: t, base: c.base, token: k.Secret}).do("POST", "/api/v1/registry/install", map[string]string{"name": "acme/echo", "fingerprint": fp}, nil); code != 403 {
		t.Fatalf("key installs: %d", code)
	}

	// Removing stops it and deletes the files.
	if code := c.do("DELETE", "/api/v1/registry/installed?name=acme/echo", nil, nil); code != 204 {
		t.Fatalf("remove: %d", code)
	}
	if _, ok := app.Engine.Module("acme-echo"); ok {
		t.Fatal("still running")
	}
	_ = context.Background()
}
