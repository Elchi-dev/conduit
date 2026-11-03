package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func buildEcho(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "echo.wasm")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/echo")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	b, _ := os.ReadFile(out)
	return b
}

func TestSandboxedModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a wasm module")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.URL.Path)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	m, err := Start(ctx, buildEcho(t), Permissions{Network: []string{u.Hostname()}}, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{AllowPrivate: true, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if m.Manifest().ID != "echo" {
		t.Fatalf("manifest %+v", m.Manifest())
	}
	host := fakehost.New(map[string]string{"secret://token": "abcdef"})
	if err := m.Configure(ctx, host, "e", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	call := func(action string, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "e", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	if r := call("echo", `{"x":1}`); string(r.Output) != `{"x":1}` {
		t.Fatalf("echo %s", r.Output)
	}
	// A host callback from inside a handler.
	if r := call("secret", `{}`); string(r.Output) != "6" {
		t.Fatalf("secret %s", r.Output)
	}
	// Granted host.
	if r := call("fetch", `{"url":"`+srv.URL+`/hi"}`); !strings.Contains(string(r.Output), "hello from /hi") {
		t.Fatalf("fetch %s", r.Output)
	}
	// Not granted, and not https.
	for _, bad := range []string{"https://example.com/", "http://" + u.Host + "/"} {
		if _, err := m.Invoke(ctx, sdk.Call{Instance: "e", Action: "fetch", Input: json.RawMessage(`{"url":"` + bad + `"}`)}); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
	// No file system.
	if r := call("file", `{}`); string(r.Output) != `{"error":true}` {
		t.Fatalf("file access: %s", r.Output)
	}
	if h := m.Health(ctx, "e"); h.Message != "sandboxed" {
		t.Fatalf("health %+v", h)
	}
}

func TestAllowed(t *testing.T) {
	p := Permissions{Network: []string{"api.github.com", "*.example.com"}}
	for host, want := range map[string]bool{"api.github.com": true, "a.example.com": true, "example.com": false, "evil.com": false, "api.github.com.evil.com": false} {
		if got := p.Allowed(&url.URL{Host: host}); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

func TestReserved(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.100.100.100", "198.18.0.1",
		"64:ff9b::a00:1", "::1", "fe80::1", "fd00::1", "224.0.0.1", "0.0.0.0", "::ffff:127.0.0.1"} {
		if !reserved(net.ParseIP(s)) {
			t.Errorf("%s should be refused", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if reserved(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}
