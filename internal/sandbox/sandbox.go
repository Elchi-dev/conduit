// Package sandbox runs untrusted modules as WebAssembly (signature feature
// 12). A sandboxed module is a WASI (wasip1) program that speaks the normal
// external-module protocol over stdin and stdout, so the engine treats it
// like any other module. It gets no file system, no environment variables,
// no clock skew tricks and no sockets: its only way out is the host's
// `conduit.http_request` function, which allows only the hosts the module
// was granted, over HTTPS, with size and time limits. Secrets still go
// through the normal host callback, so a module only sees the vault
// references in its own instance settings.
//
// The runtime is wazero (pure Go, no cgo), so the daemon stays one static
// binary.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/elchi-dev/conduit/internal/core"
)

// Permissions are what a sandboxed module may do beyond computing.
type Permissions struct {
	// Network lists hosts it may reach over HTTPS: "api.example.com" or
	// "*.example.com". Empty means no network at all.
	Network []string `json:"network"`
	// MemoryMB caps linear memory (default 64, at most 512).
	MemoryMB int `json:"memoryMB"`
}

// Spec is the module.json next to a .wasm file.
type Spec struct {
	Permissions Permissions `json:"permissions"`
}

// Module is a running sandboxed module.
type Module struct {
	*core.External
	cancel context.CancelFunc
	done   chan struct{}
	stdin  io.Closer
}

// Stop ends the module.
func (m *Module) Stop() error {
	_ = m.stdin.Close()
	m.cancel()
	select {
	case <-m.done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

// Allowed reports whether a URL's host is granted.
func (p Permissions) Allowed(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	for _, h := range p.Network {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

const (
	maxResponse = 4 << 20
	maxRequest  = 1 << 20
)

// netHost implements conduit.http_request for one module.
type netHost struct {
	perms   Permissions
	client  *http.Client
	mu      sync.Mutex
	pending []byte
}

func (n *netHost) do(ctx context.Context, raw []byte) []byte {
	fail := func(msg string) []byte { b, _ := json.Marshal(map[string]string{"error": msg}); return b }
	var req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    []byte            `json:"body"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return fail("invalid request")
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fail("only https:// URLs are allowed")
	}
	if !n.perms.Allowed(u) {
		return fail("this module isn't allowed to reach " + u.Hostname())
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	hr, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(req.Body))
	if err != nil {
		return fail(err.Error())
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	res, err := n.client.Do(hr)
	if err != nil {
		return fail("request failed: " + err.Error())
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return fail(err.Error())
	}
	if len(body) > maxResponse {
		return fail("the response is larger than 4 MiB")
	}
	hd := map[string]string{}
	for _, k := range []string{"Content-Type", "Retry-After", "Link", "Etag"} {
		if v := res.Header.Get(k); v != "" {
			hd[k] = v
		}
	}
	b, _ := json.Marshal(map[string]any{"status": res.StatusCode, "headers": hd, "body": body})
	return b
}

// noPrivate refuses connections to loopback, private and link-local
// addresses, so a granted hostname can't be pointed at the local network.
func noPrivate(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.IP.IsLoopback() || ip.IP.IsPrivate() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsUnspecified() {
			return nil, fmt.Errorf("%s resolves to a local address", host)
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// Options tune Start (tests allow local servers).
type Options struct {
	AllowPrivate bool
	HTTP         *http.Client
}

// Start compiles and runs a sandboxed module and completes the protocol
// handshake.
func Start(ctx context.Context, wasm []byte, perms Permissions, log *slog.Logger, opt Options) (*Module, error) {
	mem := perms.MemoryMB
	if mem <= 0 {
		mem = 64
	}
	if mem > 512 {
		mem = 512
	}
	rctx, cancel := context.WithCancel(context.Background())
	rt := wazero.NewRuntimeWithConfig(rctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(uint32(mem*16)). // 64 KiB pages
		WithCloseOnContextDone(true))
	wasi_snapshot_preview1.MustInstantiate(rctx, rt)

	client := opt.HTTP
	if client == nil {
		tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second}
		if !opt.AllowPrivate {
			tr.DialContext = noPrivate
			tr.Proxy = nil
		}
		client = &http.Client{Timeout: 20 * time.Second, Transport: tr}
	}
	nh := &netHost{perms: perms, client: client}
	_, err := rt.NewHostModuleBuilder("conduit").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, size uint32) uint32 {
		if size > maxRequest {
			return 0
		}
		raw, ok := m.Memory().Read(ptr, size)
		if !ok {
			return 0
		}
		res := nh.do(ctx, append([]byte(nil), raw...))
		nh.mu.Lock()
		nh.pending = res
		nh.mu.Unlock()
		return uint32(len(res))
	}).Export("http_request").
		NewFunctionBuilder().WithFunc(func(_ context.Context, m api.Module, ptr uint32) {
		nh.mu.Lock()
		res := nh.pending
		nh.pending = nil
		nh.mu.Unlock()
		m.Memory().Write(ptr, res)
	}).Export("http_response").
		Instantiate(rctx)
	if err != nil {
		cancel()
		return nil, err
	}
	compiled, err := rt.CompileModule(rctx, wasm)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("not a usable WebAssembly module: %w", err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, err
	}
	outR, outW := io.Pipe()
	stderr := &logWriter{log: log}
	cfg := wazero.NewModuleConfig().
		WithStdin(inR).WithStdout(outW).WithStderr(stderr).
		WithArgs("module").
		WithEnv("CONDUIT_MODULE_PROTOCOL", "1").
		WithSysWalltime().WithSysNanotime().WithSysNanosleep().
		WithRandSource(cryptoRand{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer outW.Close()
		if _, err := rt.InstantiateModule(rctx, compiled, cfg); err != nil && rctx.Err() == nil {
			log.Warn("sandboxed module stopped", "err", err)
		}
		_ = rt.Close(context.Background())
	}()
	x, err := core.ConnectExternal(ctx, outR, inW)
	if err != nil {
		inW.Close()
		cancel()
		return nil, err
	}
	return &Module{External: x, cancel: cancel, done: done, stdin: inW}, nil
}

type logWriter struct{ log *slog.Logger }

func (l *logWriter) Write(p []byte) (int, error) {
	if s := strings.TrimSpace(string(p)); s != "" {
		l.log.Info("sandboxed module", "stderr", s)
	}
	return len(p), nil
}

// LoadDir starts every *.wasm in dir (with its <name>.json permissions, if
// any) and registers it with the engine.
func LoadDir(ctx context.Context, e *core.Engine, dir string, log *slog.Logger) []*Module {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.wasm"))
	var out []*Module
	for _, p := range paths {
		wasm, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var spec Spec
		if b, err := os.ReadFile(strings.TrimSuffix(p, ".wasm") + ".json"); err == nil {
			if err := json.Unmarshal(b, &spec); err != nil {
				log.Warn("sandboxed module: bad permissions file", "path", p, "err", err)
				continue
			}
		}
		m, err := Start(ctx, wasm, spec.Permissions, log, Options{})
		if err != nil {
			log.Warn("sandboxed module failed to start", "path", p, "err", err)
			continue
		}
		if err := e.Register(m); err != nil {
			log.Warn("sandboxed module rejected", "path", p, "err", err)
			_ = m.Stop()
			continue
		}
		log.Info("sandboxed module loaded", "id", m.Manifest().ID, "network", strings.Join(spec.Permissions.Network, ","))
		out = append(out, m)
	}
	return out
}

type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return randRead(p) }
