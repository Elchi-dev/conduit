package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/daemon"
)

type harness struct {
	t      *testing.T
	base   string
	cfg    string
	envs   map[string]string
	stdin  string
	stdout bytes.Buffer
	stderr bytes.Buffer
	ctx    context.Context
}

func newHarness(t *testing.T, base string) *harness {
	return &harness{t: t, base: base, cfg: filepath.Join(t.TempDir(), "conduit", "config.json"), envs: map[string]string{}, ctx: context.Background()}
}

func (h *harness) run(argv ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	t := h.t
	t.Setenv("CONDUIT_CONFIG", h.cfg)
	e := &env{ctx: h.ctx, stdin: strings.NewReader(h.stdin), stdout: &h.stdout, stderr: &h.stderr,
		getenv: func(k string) string {
			if v, ok := h.envs[k]; ok {
				return v
			}
			return ""
		}}
	return run(e, argv)
}

// fake is a small stand-in for the daemon API.
type fake struct {
	mu      sync.Mutex
	inputs  []map[string]any
	streams int
	keySeen string
	srv     *httptest.Server
	release chan struct{}
}

func newFake(t *testing.T) *fake {
	f := &fake{release: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.keySeen = r.Header.Get("Authorization")
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer cdt_live_good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"sign in or present an API key"}`)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/me":
			io.WriteString(w, `{"user":{"name":"Alex","email":"alex@example.com","role":"owner"},"actor":{"id":"key_1","kind":"key","name":"ci"},"scopes":["actions:*:invoke"]}`)
		case "GET /api/v1/instances":
			io.WriteString(w, `[{"id":"lamp_1","module":"lamp","name":"Desk lamp","enabled":true}]`)
		case "GET /api/v1/modules/lamp":
			io.WriteString(w, `{"id":"lamp","name":"Lamp","version":"1","description":"","actions":[{"name":"toggle","title":"Toggle","description":"","risk":"write","reversible":true}]}`)
		case "POST /api/v1/instances/lamp_1/actions/toggle":
			var body struct {
				Input  map[string]any `json:"input"`
				DryRun bool           `json:"dryRun"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.inputs = append(f.inputs, body.Input)
			f.mu.Unlock()
			if body.Input["ask"] == true {
				w.WriteHeader(202)
				io.WriteString(w, `{"result":{},"decision":{"effect":"ask"},"audit":{},"approval":{"id":"apr_9","expiresAt":"2030-01-01T00:00:00Z"}}`)
				return
			}
			if body.Input["deny"] == true {
				w.WriteHeader(403)
				io.WriteString(w, `{"error":"forbidden: agents may not do this"}`)
				return
			}
			out, _ := json.Marshal(map[string]any{"result": map[string]any{"output": body.Input, "undo": map[string]any{"description": "toggle back"}}, "audit": map[string]any{"seq": 7, "status": "ok"}})
			w.Write(out)
		case "POST /api/v1/approvals/apr_9/approve":
			w.WriteHeader(403)
			io.WriteString(w, `{"error":"only a signed-in person can do this, not an agent or API key"}`)
		case "GET /api/v1/events":
			f.mu.Lock()
			f.streams++
			n := f.streams
			f.mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": connected\n\n")
			fmt.Fprintf(w, "event: action.ok\ndata: {\"type\":\"action.ok\",\"module\":\"lamp\",\"at\":\"2026-11-03T22:00:0%dZ\",\"data\":{\"n\":%d}}\n\n", n, n)
			w.(http.Flusher).Flush()
			if n == 1 {
				return // drop the connection: the client reconnects
			}
			select {
			case <-f.release:
			case <-r.Context().Done():
			}
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"no such endpoint"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestLoginSavesPrivately(t *testing.T) {
	f := newFake(t)
	h := newHarness(t, f.srv.URL)
	h.stdin = f.srv.URL + "\ncdt_live_bad\n"
	if code := h.run("login"); code != exitError {
		t.Fatalf("bad key: code %d %s", code, h.stderr.String())
	}
	if _, err := os.Stat(h.cfg); err == nil {
		t.Fatal("a rejected key was saved")
	}
	h.stdin = f.srv.URL + "\ncdt_live_good\n"
	if code := h.run("login"); code != 0 {
		t.Fatalf("login: %d %s", code, h.stderr.String())
	}
	st, err := os.Stat(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", st.Mode().Perm())
	}
	if code := h.run("whoami"); code != 0 || !strings.Contains(h.stdout.String(), "alex@example.com") {
		t.Fatalf("whoami: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	// A second profile, then logout of the first.
	h.stdin = ""
	if code := h.run("login", "--profile", "work", "--url", f.srv.URL, "--key", "cdt_live_good"); code != 0 {
		t.Fatal("second profile")
	}
	if code := h.run("logout"); code != 0 {
		t.Fatal("logout")
	}
	if code := h.run("whoami"); code != exitError || !strings.Contains(h.stderr.String(), "no API key") {
		t.Fatalf("after logout: %d %s", code, h.stderr.String())
	}
	if code := h.run("whoami", "--profile", "work"); code != 0 {
		t.Fatalf("other profile survives: %d", code)
	}
	// Errors never print the key.
	h.envs["CONDUIT_API_KEY"] = "cdt_live_secretvalue"
	h.envs["CONDUIT_URL"] = f.srv.URL
	h.run("whoami")
	if strings.Contains(h.stderr.String()+h.stdout.String(), "secretvalue") {
		t.Fatal("key printed")
	}
}

func TestRun(t *testing.T) {
	f := newFake(t)
	h := newHarness(t, f.srv.URL)
	h.envs["CONDUIT_URL"] = f.srv.URL
	h.envs["CONDUIT_API_KEY"] = "cdt_live_good"

	code := h.run("run", "lamp", "toggle", "n=3", "ratio=0.5", "on=true", "off=false", "zip=0123", "name=desk", "tags:=[\"a\",\"b\"]", "obj={\"x\":1}", "nested.level=2", "quoted=\"42\"")
	if code != 0 {
		t.Fatalf("run: %d %s", code, h.stderr.String())
	}
	f.mu.Lock()
	got := f.inputs[len(f.inputs)-1]
	f.mu.Unlock()
	want := map[string]any{"n": 3.0, "ratio": 0.5, "on": true, "off": false, "zip": "0123", "name": "desk", "tags": []any{"a", "b"},
		"obj": map[string]any{"x": 1.0}, "nested": map[string]any{"level": 2.0}, "quoted": "42"}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Fatalf("input\n got %s\nwant %s", gb, wb)
	}
	if !strings.Contains(h.stderr.String(), "conduit undo 7") {
		t.Fatalf("no undo hint: %s", h.stderr.String())
	}

	// --json prints the whole outcome.
	if code := h.run("run", "lamp_1", "toggle", "a=1", "--json"); code != 0 {
		t.Fatal(code)
	}
	var out map[string]any
	if err := json.Unmarshal(h.stdout.Bytes(), &out); err != nil || out["audit"] == nil {
		t.Fatalf("json: %v %s", err, h.stdout.String())
	}

	// --input - reads JSON from stdin.
	h.stdin = `{"from":"stdin"}`
	if code := h.run("run", "lamp", "toggle", "--input", "-"); code != 0 {
		t.Fatal(code)
	}
	f.mu.Lock()
	if f.inputs[len(f.inputs)-1]["from"] != "stdin" {
		t.Fatalf("stdin input %v", f.inputs[len(f.inputs)-1])
	}
	f.mu.Unlock()

	// Waiting for approval exits 3; denied by policy exits 4.
	if code := h.run("run", "lamp", "toggle", "ask=true"); code != exitPending || !strings.Contains(h.stdout.String(), "apr_9") {
		t.Fatalf("pending: %d %s", code, h.stdout.String())
	}
	if code := h.run("run", "lamp", "toggle", "deny=true"); code != exitDenied {
		t.Fatalf("denied: %d", code)
	}
	if code := h.run("approve", "apr_9"); code != exitDenied || !strings.Contains(h.stderr.String(), "signed-in person") {
		t.Fatalf("approve with a key: %d %s", code, h.stderr.String())
	}

	// Usage errors exit 2.
	if code := h.run("run", "lamp"); code != exitUsage {
		t.Fatalf("usage: %d", code)
	}
	if code := h.run("run", "lamp", "toggle", "notapair"); code != exitUsage {
		t.Fatalf("bad pair: %d", code)
	}
	if code := h.run("nope"); code != exitUsage {
		t.Fatalf("unknown command: %d", code)
	}
	if code := h.run("instances", "--bogus"); code != exitUsage {
		t.Fatalf("unknown flag: %d", code)
	}

	// Tables and JSON listings.
	if code := h.run("actions", "lamp"); code != 0 || !strings.Contains(h.stdout.String(), "toggle") || !strings.Contains(h.stdout.String(), "undo") {
		t.Fatalf("actions: %s", h.stdout.String())
	}
	if code := h.run("instances", "--json"); code != 0 {
		t.Fatal(code)
	}
	var list []instance
	if err := json.Unmarshal(h.stdout.Bytes(), &list); err != nil || list[0].ID != "lamp_1" {
		t.Fatalf("instances json: %v %s", err, h.stdout.String())
	}
}

func TestEventsReconnect(t *testing.T) {
	f := newFake(t)
	h := newHarness(t, f.srv.URL)
	h.envs["CONDUIT_URL"] = f.srv.URL
	h.envs["CONDUIT_API_KEY"] = "cdt_live_good"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.ctx = ctx
	done := make(chan int)
	var buf safeBuf
	go func() {
		e := &env{ctx: ctx, stdin: strings.NewReader(""), stdout: &buf, stderr: io.Discard, json: true, getenv: func(k string) string { return h.envs[k] }}
		done <- run(e, []string{"events", "--type", "action."})
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && strings.Count(buf.String(), "\n") < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	close(f.release)
	<-done
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 || !strings.Contains(lines[0], `"n":1`) || !strings.Contains(lines[1], `"n":2`) {
		t.Fatalf("events across a reconnect: %q", buf.String())
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestReadSSE(t *testing.T) {
	var got []sseEvent
	err := readSSE(strings.NewReader(": hi\n\nevent: a\ndata: one\ndata: two\n\ndata: x\n\n"), func(e sseEvent) { got = append(got, e) })
	if err != nil || len(got) != 2 || got[0].Type != "a" || got[0].Data != "one\ntwo" || got[1].Data != "x" {
		t.Fatalf("%+v %v", got, err)
	}
}

// Against a real daemon: an API key signs in, lists modules, and can't
// decide approvals.
func TestAgainstDaemon(t *testing.T) {
	ctx := context.Background()
	app, err := daemon.Open(ctx, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	srv := httptest.NewServer(app.Server.Handler())
	defer srv.Close()

	post := func(path, tok string, body any, out any) int {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		_ = json.NewDecoder(res.Body).Decode(out)
		return res.StatusCode
	}
	var sess struct {
		Token string `json:"token"`
	}
	post("/api/v1/setup", "", map[string]string{"token": app.Server.SetupToken, "name": "Owner", "email": "owner@example.com", "password": "correct horse"}, &sess)
	var key struct {
		Secret string `json:"secret"`
	}
	if code := post("/api/v1/keys", sess.Token, map[string]any{"name": "cli", "kind": "live", "scopes": []string{"modules:*:read", "audit:*:read", "approvals:*:read", "events:*:read"}}, &key); code != 201 {
		t.Fatalf("key: %d", code)
	}

	h := newHarness(t, srv.URL)
	if code := h.run("login", "--url", srv.URL, "--key", key.Secret); code != 0 {
		t.Fatalf("login: %d %s", code, h.stderr.String())
	}
	// daemon.Open doesn't register the built-in modules (Run does), so the
	// list is empty here; this checks the call and the table.
	if code := h.run("modules"); code != 0 || !strings.Contains(h.stdout.String(), "CATEGORY") {
		t.Fatalf("modules: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("audit", "--limit", "5", "--json"); code != 0 {
		t.Fatalf("audit: %d %s", code, h.stderr.String())
	}
	if code := h.run("approvals", "--pending"); code != 0 {
		t.Fatalf("approvals: %d %s", code, h.stderr.String())
	}
	if code := h.run("approve", "apr_nope"); code == 0 {
		t.Fatal("a key decided an approval")
	}
	if code := h.run("whoami", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"kind": "key"`) {
		t.Fatalf("whoami: %d %s", code, h.stdout.String())
	}
}
