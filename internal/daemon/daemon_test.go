package daemon

import (
	"bufio"
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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/backup"
	"github.com/elchi-dev/conduit/internal/core"
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type lamp struct {
	mu sync.Mutex
	on bool
}

func (l *lamp) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "lamp", Name: "Lamp", Version: "1.0.0", Actions: []sdk.ActionSpec{
		{Name: "status", Risk: sdk.RiskRead},
		{Name: "toggle", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
	}}
}
func (l *lamp) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (l *lamp) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (l *lamp) Close(string) error                                                 { return nil }
func (l *lamp) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.Action == "status" {
		b, _ := json.Marshal(l.on)
		return sdk.Result{Output: b}, nil
	}
	if c.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "toggle"}}, nil
	}
	l.on = !l.on
	return sdk.Result{Undo: &sdk.Undo{Action: "toggle", Description: "toggle back"}}, nil
}

type client struct {
	t     *testing.T
	base  string
	token string
}

func (c client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func setup(t *testing.T) (*App, client, *lamp, string) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := Open(ctx, t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	l := &lamp{}
	_ = app.Engine.Register(l)
	srv := httptest.NewServer(app.Server.Handler())
	t.Cleanup(srv.Close)
	c := client{t: t, base: srv.URL}

	var st map[string]bool
	c.do("GET", "/api/v1/setup", nil, &st)
	if !st["needsSetup"] {
		t.Fatal("fresh daemon should need setup")
	}
	if code := c.do("POST", "/api/v1/setup", map[string]string{"token": "wrong", "email": "a@b.co", "password": "correct horse"}, nil); code != 403 {
		t.Fatalf("setup with wrong token = %d", code)
	}
	var sess sessionResp
	if code := c.do("POST", "/api/v1/setup", map[string]string{"token": app.Server.SetupToken, "name": "Owner", "email": "owner@example.com", "password": "correct horse"}, &sess); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	if code := c.do("POST", "/api/v1/setup", map[string]string{"token": app.Server.SetupToken, "email": "x@example.com", "password": "correct horse"}, nil); code != 409 {
		t.Fatalf("second setup = %d, want 409", code)
	}
	c.token = sess.Token
	var in core.Instance
	if code := c.do("POST", "/api/v1/instances", map[string]any{"module": "lamp", "name": "Desk lamp"}, &in); code != 201 {
		t.Fatalf("create instance = %d", code)
	}
	return app, c, l, in.ID
}

func TestHealthzAndVersion(t *testing.T) {
	_, c, _, _ := setup(t)
	if code := c.do("GET", "/healthz", nil, nil); code != 200 {
		t.Fatalf("healthz = %d", code)
	}
	var v map[string]string
	c.do("GET", "/api/v1/version", nil, &v)
	if v["version"] == "" {
		t.Fatal("no version")
	}
}

func TestUnauthenticated(t *testing.T) {
	_, c, _, _ := setup(t)
	c.token = ""
	if code := c.do("GET", "/api/v1/modules", nil, nil); code != 401 {
		t.Fatalf("modules without auth = %d", code)
	}
	c.token = "cdt_live_nope_nope"
	if code := c.do("GET", "/api/v1/modules", nil, nil); code != 401 {
		t.Fatalf("modules with bogus key = %d", code)
	}
}

func TestLoginAndInvokeAsUser(t *testing.T) {
	_, c, l, id := setup(t)
	var sess sessionResp
	c2 := client{t: t, base: c.base}
	if code := c2.do("POST", "/api/v1/auth/login", map[string]string{"email": "owner@example.com", "password": "wrong password"}, nil); code != 401 {
		t.Fatalf("bad login = %d", code)
	}
	if code := c2.do("POST", "/api/v1/auth/login", map[string]string{"email": "OWNER@example.com", "password": "correct horse"}, &sess); code != 200 {
		t.Fatalf("login = %d", code)
	}
	c2.token = sess.Token
	var out core.Outcome
	if code := c2.do("POST", "/api/v1/instances/"+id+"/actions/toggle", map[string]any{}, &out); code != 200 {
		t.Fatalf("toggle = %d", code)
	}
	if !l.on || out.Audit.Undo == nil {
		t.Fatalf("lamp not on or no undo: %+v", out.Audit)
	}
	if code := c2.do("POST", "/api/v1/audit/"+itoa(out.Audit.Seq)+"/undo", nil, nil); code != 200 {
		t.Fatalf("undo = %d", code)
	}
	if l.on {
		t.Fatal("undo did not toggle back")
	}
	var v core.VerifyResult
	c2.do("GET", "/api/v1/audit/verify", nil, &v)
	if !v.OK {
		t.Fatalf("audit chain broken: %+v", v)
	}
	if code := c2.do("POST", "/api/v1/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code := c2.do("GET", "/api/v1/me", nil, nil); code != 401 {
		t.Fatalf("me after logout = %d", code)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

type keyResp struct {
	Key struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
	} `json:"key"`
	Secret string `json:"secret"`
}

func TestAgentKeyApprovalFlow(t *testing.T) {
	_, c, l, id := setup(t)
	// Agent keys may not hold scopes that let them approve themselves.
	if code := c.do("POST", "/api/v1/keys", map[string]any{"name": "bad", "kind": "agent", "scopes": []string{"admin:*:*"}}, nil); code != 400 {
		t.Fatalf("agent admin key = %d, want 400", code)
	}
	var k keyResp
	if code := c.do("POST", "/api/v1/keys", map[string]any{"name": "desktop agent", "kind": "agent", "scopes": []string{"actions:*:invoke", "modules:*:read", "approvals:*:read"}}, &k); code != 201 {
		t.Fatalf("create key = %d", code)
	}
	if !strings.HasPrefix(k.Secret, "cdt_agent_") || !strings.HasPrefix(k.Secret, k.Key.Prefix+"_") {
		t.Fatalf("bad key format %q / %q", k.Secret, k.Key.Prefix)
	}
	agent := client{t: t, base: c.base, token: k.Secret}

	// Reads pass; writes wait for approval (default preset ask-writes).
	if code := agent.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil); code != 200 {
		t.Fatalf("agent read = %d", code)
	}
	var pending core.Outcome
	if code := agent.do("POST", "/api/v1/instances/"+id+"/actions/toggle", map[string]any{}, &pending); code != 202 || pending.Approval == nil {
		t.Fatalf("agent write = %d, approval %v", code, pending.Approval)
	}
	if pending.Approval.Plan == nil {
		t.Fatal("approval should include the dry-run plan")
	}
	// The agent cannot approve, even though it can see approvals.
	if code := agent.do("POST", "/api/v1/approvals/"+pending.Approval.ID+"/approve", nil, nil); code != 403 {
		t.Fatalf("agent self-approve = %d", code)
	}
	if code := c.do("POST", "/api/v1/approvals/"+pending.Approval.ID+"/approve", nil, nil); code != 200 {
		t.Fatalf("owner approve = %d", code)
	}
	// A call that didn't wait runs once approved, and the approval says
	// where its result is.
	var done core.Approval
	for i := 0; i < 200 && done.ResultSeq == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		c.do("GET", "/api/v1/approvals/"+pending.Approval.ID, nil, &done)
	}
	l.mu.Lock()
	on := l.on
	l.mu.Unlock()
	if done.ResultSeq == nil || !on {
		t.Fatalf("approved call didn't run: on=%v approval=%+v", on, done)
	}
	// With an allow rule the agent's writes run directly.
	if code := c.do("POST", "/api/v1/policy/rules", map[string]any{"subject": "agent:" + k.Key.ID, "module": "lamp", "effect": "allow"}, nil); code != 200 {
		t.Fatalf("put rule = %d", code)
	}
	if code := agent.do("POST", "/api/v1/instances/"+id+"/actions/toggle", map[string]any{}, nil); code != 200 {
		t.Fatalf("agent write with rule = %d", code)
	}
	l.mu.Lock()
	on = l.on
	l.mu.Unlock()
	if on {
		t.Fatal("lamp should be off again")
	}
	// Agents cannot change policy.
	if code := agent.do("PUT", "/api/v1/policy/preset", map[string]string{"preset": "full-autonomy"}, nil); code != 403 {
		t.Fatalf("agent change preset = %d", code)
	}
	var usage []map[string]any
	c.do("GET", "/api/v1/keys/"+k.Key.ID+"/usage", nil, &usage)
	if len(usage) < 3 {
		t.Fatalf("usage not recorded: %d", len(usage))
	}
}

func TestPanicRevokesAgentKeys(t *testing.T) {
	_, c, _, id := setup(t)
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "agent", "kind": "agent", "scopes": []string{"actions:*:invoke"}}, &k)
	var live keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "script", "kind": "live", "scopes": []string{"actions:*:invoke"}}, &live)

	var pr panicResp
	if code := c.do("POST", "/api/v1/panic", nil, &pr); code != 200 || pr.RevokedAgentKeys != 1 {
		t.Fatalf("panic = %d %+v", code, pr)
	}
	agent := client{t: t, base: c.base, token: k.Secret}
	if code := agent.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil); code != 401 {
		t.Fatalf("agent after panic = %d, want 401", code)
	}
	script := client{t: t, base: c.base, token: live.Secret}
	if code := script.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil); code != 403 {
		t.Fatalf("live key during panic = %d, want 403 (frozen)", code)
	}
	if code := script.do("DELETE", "/api/v1/panic", nil, nil); code != 403 {
		t.Fatalf("key lifting panic = %d", code)
	}
	if code := c.do("DELETE", "/api/v1/panic", nil, nil); code != 200 {
		t.Fatalf("owner unpanic = %d", code)
	}
	if code := script.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil); code != 200 {
		t.Fatalf("live key after unpanic = %d", code)
	}
}

func TestKeyRotationAndScopes(t *testing.T) {
	_, c, _, id := setup(t)
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ro", "kind": "test", "scopes": []string{"modules:*:read"}, "ipAllow": []string{"127.0.0.1"}}, &k)
	ro := client{t: t, base: c.base, token: k.Secret}
	if code := ro.do("GET", "/api/v1/instances", nil, nil); code != 200 {
		t.Fatalf("scoped read = %d", code)
	}
	if code := ro.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil); code != 403 {
		t.Fatalf("missing invoke scope = %d", code)
	}
	var rotated keyResp
	if code := c.do("POST", "/api/v1/keys/"+k.Key.ID+"/rotate", map[string]int{"graceSeconds": 1}, &rotated); code != 201 {
		t.Fatalf("rotate = %d", code)
	}
	if code := ro.do("GET", "/api/v1/instances", nil, nil); code != 200 {
		t.Fatalf("old key inside grace = %d", code)
	}
	time.Sleep(1100 * time.Millisecond)
	if code := ro.do("GET", "/api/v1/instances", nil, nil); code != 401 {
		t.Fatalf("old key after grace = %d", code)
	}
	nw := client{t: t, base: c.base, token: rotated.Secret}
	if code := nw.do("GET", "/api/v1/instances", nil, nil); code != 200 {
		t.Fatalf("new key = %d", code)
	}
	if code := c.do("DELETE", "/api/v1/keys/"+rotated.Key.ID, nil, nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	if code := nw.do("GET", "/api/v1/instances", nil, nil); code != 401 {
		t.Fatalf("revoked key = %d", code)
	}
}

func TestIPAllowList(t *testing.T) {
	_, c, _, _ := setup(t)
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "far", "scopes": []string{"modules:*:read"}, "ipAllow": []string{"10.0.0.0/8"}}, &k)
	far := client{t: t, base: c.base, token: k.Secret}
	if code := far.do("GET", "/api/v1/modules", nil, nil); code != 401 {
		t.Fatalf("request from outside allow-list = %d", code)
	}
}

func TestEventsStream(t *testing.T) {
	_, c, _, id := setup(t)
	req, _ := http.NewRequest("GET", c.base+"/api/v1/events?prefix=action.", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	br := bufio.NewReader(res.Body)
	if line, _ := br.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("first line %q", line)
	}
	go c.do("POST", "/api/v1/instances/"+id+"/actions/status", nil, nil)
	done := make(chan string, 1)
	go func() {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "event: ") {
				done <- strings.TrimSpace(line[7:])
				return
			}
		}
	}()
	select {
	case ev := <-done:
		if ev != "action.ok" {
			t.Fatalf("event %q", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
}

// TestRoutesMatchOpenAPI keeps the spec the source of truth: every route the
// daemon serves must be documented, and every documented path must exist.
func TestRoutesMatchOpenAPI(t *testing.T) {
	spec, err := os.ReadFile("../../api/openapi/daemon.yaml")
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
	srv := &Server{}
	all := srv.routes()
	for _, extra := range [][]route{srv.automationRoutes(), srv.assistantRoutes(), srv.remoteRoutes(), srv.updateRoutes(), srv.ambientRoutes(), srv.webhookRoutes(), srv.syncRoutes(), srv.phoneRoutes(), srv.twoFactorRoutes(), srv.passkeyRoutes(), srv.oidcRoutes(), srv.backupRoutes(), srv.tileRoutes(), srv.discoverRoutes(), srv.registryRoutes(), srv.vaultFolderRoutes(), srv.gamesRoutes(), srv.networkRoutes()} {
		all = append(all, extra...)
	}
	for _, r := range all {
		method, path, _ := strings.Cut(r.pattern, " ")
		if path == "/healthz" || path == "/mcp" || strings.HasPrefix(path, "/hooks/") || path == "/sync/exchange" {
			continue // outside the /api/v1 base; documented in docs/api/webhooks.md
		}
		path = strings.TrimPrefix(path, "/api/v1")
		served[method+" "+path] = true
		if !documented[method+" "+path] {
			t.Errorf("route %s %s is not in api/openapi/daemon.yaml", method, path)
		}
	}
	for d := range documented {
		if !served[d] {
			t.Errorf("documented %s is not served", d)
		}
	}
}

func TestVaultSecretsNeverLogged(t *testing.T) {
	app, c, _, _ := setup(t)
	if err := registerBuiltins(app); err != nil {
		t.Fatal(err)
	}
	if err := ensureSingletons(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if code := c.do("POST", "/api/v1/vault/setup", map[string]string{"passphrase": "a long vault passphrase"}, nil); code != 200 {
		t.Fatalf("vault setup = %d", code)
	}
	const secret = "hunter2-hunter2-hunter2"
	if code := c.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/set", map[string]any{"input": map[string]string{"name": "mail/work", "value": secret}}, nil); code != 200 {
		t.Fatalf("set = %d", code)
	}
	var out core.Outcome
	if code := c.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/reveal", map[string]any{"input": map[string]string{"name": "mail/work"}}, &out); code != 200 {
		t.Fatalf("reveal = %d", code)
	}
	if !strings.Contains(string(out.Result.Output), secret) {
		t.Fatal("caller should receive the value")
	}
	var entries []core.Entry
	c.do("GET", "/api/v1/audit?limit=50", nil, &entries)
	for _, e := range entries {
		if strings.Contains(string(e.Input)+string(e.Output), secret) {
			t.Fatalf("secret leaked into audit entry %d (%s)", e.Seq, e.Action)
		}
	}
	if !strings.Contains(string(entries[0].Input), "mail/work") {
		t.Fatalf("audit should still name the secret: %s", entries[0].Input)
	}
	// Agents need approval to reveal (destructive), and panic locks the vault.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "a", "kind": "agent", "scopes": []string{"actions:*:invoke"}}, &k)
	agent := client{t: t, base: c.base, token: k.Secret}
	if code := agent.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/reveal", map[string]any{"input": map[string]string{"name": "mail/work"}}, nil); code != 202 {
		t.Fatalf("agent reveal = %d, want 202", code)
	}
	c.do("POST", "/api/v1/panic", nil, nil)
	var st map[string]bool
	c.do("GET", "/api/v1/vault", nil, &st)
	if st["unlocked"] {
		t.Fatal("panic should lock the vault")
	}
}

func TestApprovalForwardedToChannel(t *testing.T) {
	app, c, _, id := setup(t)
	if err := registerBuiltins(app); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer hook.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go forwardAlerts(ctx, app)
	time.Sleep(50 * time.Millisecond)

	if code := c.do("POST", "/api/v1/instances", map[string]any{"module": "notify", "name": "Phone", "config": map[string]any{"channel": "webhook", "url": hook.URL, "approvals": true, "appUrl": "http://pc:7600"}}, nil); code != 201 {
		t.Fatalf("create channel = %d", code)
	}
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "a", "kind": "agent", "scopes": []string{"actions:*:invoke"}}, &k)
	agent := client{t: t, base: c.base, token: k.Secret}
	agent.do("POST", "/api/v1/instances/"+id+"/actions/toggle", map[string]any{}, nil)
	select {
	case body := <-got:
		if !strings.Contains(body, "Approval needed") || !strings.Contains(body, "http://pc:7600/approvals") {
			t.Fatalf("unexpected notification: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval was not forwarded")
	}
}

func mcpCall(t *testing.T, base, key, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", base+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

func TestMCPServer(t *testing.T) {
	_, c, l, id := setup(t)
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "desk", "kind": "agent", "scopes": []string{"actions:*:invoke", "modules:*:read", "audit:*:read"}}, &k)

	init := mcpCall(t, c.base, k.Secret, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if init["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %v", init)
	}
	list := mcpCall(t, c.base, k.Secret, "tools/list", nil)
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]map[string]any{}
	for _, x := range tools {
		tl := x.(map[string]any)
		names[tl["name"].(string)] = tl
	}
	status := id + "__status"
	toggle := id + "__toggle"
	for _, want := range []string{"conduit_overview", "conduit_preview", "conduit_what_changed", status, toggle} {
		if names[want] == nil {
			t.Fatalf("tool %s missing; have %v", want, len(names))
		}
	}
	if names["conduit_undo"] != nil {
		t.Fatal("undo tool offered without the audit:*:undo scope")
	}
	if !names[status]["annotations"].(map[string]any)["readOnlyHint"].(bool) {
		t.Fatal("read tool not marked read-only")
	}

	res := mcpCall(t, c.base, k.Secret, "tools/call", map[string]any{"name": status})
	if res["result"].(map[string]any)["isError"].(bool) {
		t.Fatalf("read call failed: %v", res)
	}
	prev := mcpCall(t, c.base, k.Secret, "tools/call", map[string]any{"name": "conduit_preview", "arguments": map[string]any{"tool": toggle}})
	if txt := fmt.Sprint(prev["result"]); !strings.Contains(txt, "Preview") || l.on {
		t.Fatalf("preview: %v", txt)
	}
	res = mcpCall(t, c.base, k.Secret, "tools/call", map[string]any{"name": toggle, "arguments": map[string]any{}})
	r := res["result"].(map[string]any)
	approval := r["structuredContent"].(map[string]any)["approvalId"].(string)
	if l.on || approval == "" {
		t.Fatal("write went through without approval")
	}
	c.do("POST", "/api/v1/approvals/"+approval+"/approve", nil, nil)
	st := mcpCall(t, c.base, k.Secret, "tools/call", map[string]any{"name": "conduit_approval_status", "arguments": map[string]any{"id": approval}})
	if !strings.Contains(fmt.Sprint(st["result"]), "Approved") {
		t.Fatalf("approval status: %v", st)
	}
	wc := mcpCall(t, c.base, k.Secret, "tools/call", map[string]any{"name": "conduit_what_changed", "arguments": map[string]any{"minutes": 10}})
	if !strings.Contains(fmt.Sprint(wc["result"]), "readsOmitted") {
		t.Fatalf("what changed: %v", wc)
	}
	// Without a key: rejected.
	if out := mcpCall(t, c.base, "", "tools/list", nil); out["result"] != nil {
		t.Fatal("unauthenticated MCP allowed")
	}
}

func TestHostAndOriginChecks(t *testing.T) {
	_, c, _, _ := setup(t)
	raw := func(method, path, host string, hdr map[string]string, cookie bool) int {
		req, _ := http.NewRequest(method, c.base+path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if host != "" {
			req.Host = host
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if cookie {
			req.AddCookie(&http.Cookie{Name: SessionCookie, Value: c.token})
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	// DNS rebinding: an attacker's name pointed at the daemon.
	if code := raw("GET", "/api/v1/me", "evil.example:7600", nil, false); code != http.StatusMisdirectedRequest {
		t.Fatalf("rebound host = %d", code)
	}
	for _, h := range []string{"localhost:7600", "127.0.0.1:7600", "[::1]:7600", "desk.local", "192.168.1.5"} {
		if code := raw("GET", "/api/v1/me", h, nil, false); code != 200 {
			t.Fatalf("host %s = %d", h, code)
		}
	}
	// CSRF: a cookie-authenticated mutation from another site, even with no body.
	if code := raw("POST", "/api/v1/auth/logout", "", map[string]string{"Sec-Fetch-Site": "cross-site"}, true); code != http.StatusForbidden {
		t.Fatalf("cross-site cookie POST = %d", code)
	}
	if code := raw("POST", "/api/v1/auth/logout", "", map[string]string{"Origin": "https://evil.example"}, true); code != http.StatusForbidden {
		t.Fatalf("foreign Origin cookie POST = %d", code)
	}
	// The same request with a bearer token is fine (browsers don't attach it).
	if code := raw("GET", "/api/v1/me", "", map[string]string{"Sec-Fetch-Site": "cross-site"}, false); code != 200 {
		t.Fatalf("bearer = %d", code)
	}
	if code := raw("POST", "/api/v1/auth/logout", "", map[string]string{"Sec-Fetch-Site": "same-origin"}, true); code >= 300 {
		t.Fatalf("same-origin cookie POST = %d", code)
	}
}

func TestPeopleManagement(t *testing.T) {
	_, c, _, _ := setup(t)
	var admin auth.User
	if code := c.do("POST", "/api/v1/users", map[string]string{"name": "Sam", "email": "sam@example.com", "password": "sam's long password", "role": "admin"}, &admin); code != 201 {
		t.Fatalf("create admin = %d", code)
	}
	var member auth.User
	c.do("POST", "/api/v1/users", map[string]string{"email": "kim@example.com", "password": "kim's long password", "role": "member"}, &member)

	// API keys can't manage accounts, even with admin scope.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ops", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	key := client{t: t, base: c.base, token: k.Secret}
	if code := key.do("POST", "/api/v1/users", map[string]string{"email": "evil@example.com", "password": "evil long password", "role": "admin"}, nil); code != 403 {
		t.Fatalf("key creates account = %d", code)
	}
	if code := key.do("PATCH", "/api/v1/users/"+member.ID, map[string]string{"role": "admin"}, nil); code != 403 {
		t.Fatalf("key changes role = %d", code)
	}

	// An admin manages members but not admins, and nobody changes themselves.
	var sess sessionResp
	c.do("POST", "/api/v1/auth/login", map[string]string{"email": "sam@example.com", "password": "sam's long password"}, &sess)
	sam := client{t: t, base: c.base, token: sess.Token}
	if code := sam.do("PATCH", "/api/v1/users/"+member.ID, map[string]string{"role": "viewer"}, nil); code != 200 {
		t.Fatalf("admin demotes member = %d", code)
	}
	if code := sam.do("PATCH", "/api/v1/users/"+member.ID, map[string]string{"role": "admin"}, nil); code != 403 {
		t.Fatalf("admin promotes to admin = %d", code)
	}
	if code := sam.do("PATCH", "/api/v1/users/"+admin.ID, map[string]any{"disabled": true}, nil); code != 400 {
		t.Fatalf("admin switches self off = %d", code)
	}

	// Switching an account off ends its sessions.
	var ks sessionResp
	c.do("POST", "/api/v1/auth/login", map[string]string{"email": "kim@example.com", "password": "kim's long password"}, &ks)
	kim := client{t: t, base: c.base, token: ks.Token}
	if code := sam.do("PATCH", "/api/v1/users/"+member.ID, map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable = %d", code)
	}
	if code := kim.do("GET", "/api/v1/me", nil, nil); code != 401 {
		t.Fatalf("disabled account still signed in = %d", code)
	}
	if code := sam.do("POST", "/api/v1/users/"+member.ID+"/password", map[string]string{"password": "a fresh long password"}, nil); code != 204 {
		t.Fatalf("reset = %d", code)
	}
}

func TestBackupAndTilesAPI(t *testing.T) {
	_, c, _, id := setup(t)
	// Tiles: read actions only.
	if code := c.do("PUT", "/api/v1/me/tiles", []map[string]any{{"instance": id, "action": "toggle", "label": "x", "refresh": 60}}, nil); code != 400 {
		t.Fatalf("write action pinned: %d", code)
	}
	var tiles []Tile
	if code := c.do("PUT", "/api/v1/me/tiles", []map[string]any{{"instance": id, "action": "status", "label": "Lamp", "refresh": 1}}, &tiles); code != 200 || len(tiles) != 1 || tiles[0].Refresh != 60 || tiles[0].ID == "" {
		t.Fatalf("pin: %d %+v", code, tiles)
	}
	c.do("GET", "/api/v1/me/tiles", nil, &tiles)
	if len(tiles) != 1 {
		t.Fatal("tiles not saved")
	}

	// Backups: people only, a passphrase is required, and the file restores.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ops", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	key := client{t: t, base: c.base, token: k.Secret}
	if code := key.do("POST", "/api/v1/backup", map[string]string{"passphrase": "a long backup passphrase"}, nil); code != 403 {
		t.Fatalf("key took a backup: %d", code)
	}
	if code := c.do("POST", "/api/v1/backup", map[string]string{"passphrase": "short"}, nil); code != 400 {
		t.Fatalf("short passphrase: %d", code)
	}
	b, _ := json.Marshal(map[string]string{"passphrase": "a long backup passphrase"})
	req, _ := http.NewRequest("POST", c.base+"/api/v1/backup", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("backup: %v %v", err, res)
	}
	file, _ := io.ReadAll(res.Body)
	res.Body.Close()
	out := filepath.Join(t.TempDir(), "restored")
	if _, err := backup.Restore(bytes.NewReader(file), out, "a long backup passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, backup.DBName)); err != nil {
		t.Fatal("restored backup has no database")
	}
}

func TestVaultFolders(t *testing.T) {
	app, c, _, _ := setup(t)
	ctx := context.Background()
	if err := app.Vault.Setup(ctx, "a long vault passphrase"); err != nil {
		t.Fatal(err)
	}
	app.Engine.Guard = app.Server.vaultGuard
	_ = app.Engine.Register(&vaultmod.Module{V: app.Vault})
	if _, err := app.Engine.SaveInstance(ctx, core.Instance{ID: vaultmod.InstanceID, Module: "vault", Name: "Vault", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	reveal := func(cl client, name string) int {
		return cl.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/reveal", map[string]any{"input": map[string]string{"name": name}}, nil)
	}
	set := func(cl client, name string) int {
		return cl.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/set", map[string]any{"input": map[string]string{"name": name, "value": "v"}}, nil)
	}
	if code := set(c, "finance/bank"); code != 200 {
		t.Fatalf("owner set: %d", code)
	}
	c.do("POST", "/api/v1/users", map[string]string{"email": "kim@example.com", "password": "kims long password", "role": "admin"}, nil)
	var ks sessionResp
	c.do("POST", "/api/v1/auth/login", map[string]string{"email": "kim@example.com", "password": "kims long password"}, &ks)
	kim := client{t: t, base: c.base, token: ks.Token}
	if code := reveal(kim, "finance/bank"); code != 200 {
		t.Fatalf("before restricting: %d", code)
	}
	// Only the owner restricts folders.
	if code := kim.do("PUT", "/api/v1/vault/folders", []map[string]any{{"prefix": "finance"}}, nil); code != 403 {
		t.Fatalf("admin restricts: %d", code)
	}
	var fs []VaultFolder
	if code := c.do("PUT", "/api/v1/vault/folders", []map[string]any{{"prefix": "finance", "roles": []string{}}}, &fs); code != 200 || fs[0].Prefix != "finance/" || fs[0].Roles[0] != "owner" {
		t.Fatalf("restrict: %d %+v", code, fs)
	}
	if code := reveal(kim, "finance/bank"); code != 403 {
		t.Fatalf("admin reveals restricted: %d", code)
	}
	if code := set(kim, "finance/new"); code != 403 {
		t.Fatalf("admin writes into restricted: %d", code)
	}
	if code := set(kim, "other/ok"); code != 200 {
		t.Fatalf("unrestricted: %d", code)
	}
	// Using a restricted secret in module settings is refused too.
	if code := kim.do("POST", "/api/v1/instances", map[string]any{"module": "lamp", "name": "x", "config": map[string]string{"token": "secret://finance/bank"}}, nil); code != 403 {
		t.Fatalf("restricted secret in settings: %d", code)
	}
	// Kim's key gets no more than Kim.
	var k keyResp
	kim.do("POST", "/api/v1/keys", map[string]any{"name": "k", "kind": "live", "scopes": []string{"actions:*:invoke"}}, &k)
	if code := reveal(client{t: t, base: c.base, token: k.Secret}, "finance/bank"); code != 403 {
		t.Fatalf("key reveals restricted: %d", code)
	}
	// The owner still can.
	if code := reveal(c, "finance/bank"); code != 200 {
		t.Fatalf("owner reveals: %d", code)
	}
	// A JSON-escaped reference is the same reference.
	esc := []byte(`{"module":"lamp","name":"y","config":{"token":"secret:\/\/finance\/bank"}}`)
	if code := kim.do("POST", "/api/v1/instances", json.RawMessage(esc), nil); code != 403 {
		t.Fatalf("escaped restricted secret in settings: %d", code)
	}
	// An import can't pick a restricted folder through its keys.
	imp := func(prefix, text string) int {
		return kim.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/import_env", map[string]any{"input": map[string]string{"prefix": prefix, "text": text}}, nil)
	}
	if code := imp("", "FINANCE/BANK=attacker"); code != 200 {
		t.Fatalf("import without prefix: %d", code)
	}
	if code := imp("finance", "BANK=attacker"); code != 403 {
		t.Fatalf("import into restricted: %d", code)
	}
	var got json.RawMessage
	c.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/reveal", map[string]any{"input": map[string]string{"name": "finance/bank"}}, &got)
	if strings.Contains(string(got), "attacker") {
		t.Fatal("import overwrote a restricted secret")
	}
	// Scanning would test guesses against restricted values.
	if code := kim.do("POST", "/api/v1/instances/"+vaultmod.InstanceID+"/actions/scan_text", map[string]any{"input": map[string]string{"text": "v"}}, nil); code != 403 {
		t.Fatalf("admin scans: %d", code)
	}
	// Only the owner may sync the vault while folders are restricted.
	if code := kim.do("POST", "/api/v1/sync/group", map[string]any{"collections": []string{"vault"}}, nil); code != 403 {
		t.Fatalf("admin syncs the vault: %d", code)
	}
	// Tiles are chosen by people, not keys.
	if code := (client{t: t, base: c.base, token: k.Secret}).do("PUT", "/api/v1/me/tiles", []any{}, nil); code != 403 {
		t.Fatalf("key sets tiles: %d", code)
	}
}
