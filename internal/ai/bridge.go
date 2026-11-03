package ai

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// MCPServer is an outside MCP server mounted as a Conduit module.
type MCPServer struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Transport string            `json:"transport"` // stdio | http
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"` // values may be secret:// references
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"` // values may be secret:// references
	// TrustReadOnly takes the server's readOnlyHint at its word, so tools it
	// marks read-only are treated as reads. Off by default: the hint is the
	// server's own claim, and a malicious or buggy server could label a
	// writing tool read-only to skip approvals.
	TrustReadOnly bool `json:"trustReadOnly,omitempty"`
	// RiskOverrides sets a tool's risk explicitly ("read", "write", "destructive").
	RiskOverrides map[string]string `json:"riskOverrides,omitempty"`
}

// rpc is a minimal MCP client over one transport.
type rpc interface {
	call(ctx context.Context, method string, params any, out any) error
	close()
}

// Bridge mounts outside MCP servers.
type Bridge struct {
	DB      *sql.DB
	Engine  *core.Engine
	Secrets core.SecretResolver

	mu      sync.Mutex
	mounted map[string]*bridgeModule
}

var slug = regexp.MustCompile(`[^a-z0-9]+`)

// ModuleID is the module (and instance) id of a mounted server.
func (s MCPServer) ModuleID() string {
	return "mcp-" + strings.Trim(slug.ReplaceAllString(strings.ToLower(s.ID), "-"), "-")
}

// List returns stored servers.
func (b *Bridge) List(ctx context.Context) ([]MCPServer, error) {
	rows, err := b.DB.QueryContext(ctx, `SELECT spec FROM mcp_servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MCPServer{}
	for rows.Next() {
		var sp string
		if err := rows.Scan(&sp); err != nil {
			return nil, err
		}
		var s MCPServer
		_ = json.Unmarshal([]byte(sp), &s)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Save stores a server and (re)mounts it.
func (b *Bridge) Save(ctx context.Context, s MCPServer) (MCPServer, error) {
	if strings.TrimSpace(s.Name) == "" {
		return s, errors.New("give the server a name")
	}
	switch s.Transport {
	case "stdio":
		if s.Command == "" {
			return s, errors.New("a command is required, e.g. npx")
		}
	case "http":
		if !strings.HasPrefix(s.URL, "https://") && !strings.HasPrefix(s.URL, "http://127.0.0.1") && !strings.HasPrefix(s.URL, "http://localhost") {
			return s, errors.New("use an https:// URL (plain http only on this computer)")
		}
	default:
		return s, errors.New(`transport must be "stdio" or "http"`)
	}
	for _, m := range []map[string]string{s.Env, s.Headers} {
		for k, v := range m {
			if looksSecret(k) && v != "" && !strings.HasPrefix(v, "secret://") {
				return s, fmt.Errorf("%s looks like a credential; store it in the vault and use its secret:// reference", k)
			}
		}
	}
	if s.ID == "" {
		s.ID = strings.Trim(slug.ReplaceAllString(strings.ToLower(s.Name), "-"), "-")
		if s.ID == "" {
			s.ID = core.NewID("mcp")
		}
	}
	sp, _ := json.Marshal(s)
	if _, err := b.DB.ExecContext(ctx, `INSERT INTO mcp_servers (id, name, spec) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET name = excluded.name, spec = excluded.spec`, s.ID, s.Name, string(sp)); err != nil {
		return s, err
	}
	return s, b.Mount(ctx, s)
}

func looksSecret(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"token", "key", "secret", "password", "authorization"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// Delete unmounts and removes a server.
func (b *Bridge) Delete(ctx context.Context, id string) error {
	list, _ := b.List(ctx)
	for _, s := range list {
		if s.ID == id {
			b.unmount(ctx, s.ModuleID())
		}
	}
	_, err := b.DB.ExecContext(ctx, `DELETE FROM mcp_servers WHERE id = ?`, id)
	return err
}

// MountAll mounts every stored server; failures are logged, not fatal.
func (b *Bridge) MountAll(ctx context.Context) {
	list, err := b.List(ctx)
	if err != nil {
		return
	}
	for _, s := range list {
		if err := b.Mount(ctx, s); err != nil {
			b.Engine.Log.Warn("MCP server not mounted", "server", s.Name, "err", err)
		}
	}
}

func (b *Bridge) unmount(ctx context.Context, modID string) {
	b.mu.Lock()
	m := b.mounted[modID]
	delete(b.mounted, modID)
	b.mu.Unlock()
	if m != nil {
		_ = b.Engine.DeleteInstance(ctx, modID)
		b.Engine.Unregister(modID)
		m.conn.close()
	}
}

func (b *Bridge) resolve(ctx context.Context, in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range in {
		if strings.HasPrefix(v, "secret://") {
			val, err := b.Secrets.Resolve(ctx, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			v = val
		}
		out[k] = v
	}
	return out, nil
}

// Mount connects to a server, reads its tools and registers it as a module.
func (b *Bridge) Mount(ctx context.Context, s MCPServer) error {
	b.unmount(ctx, s.ModuleID())
	var conn rpc
	switch s.Transport {
	case "stdio":
		env, err := b.resolve(ctx, s.Env)
		if err != nil {
			return err
		}
		c, err := startStdio(s.Command, s.Args, env)
		if err != nil {
			return err
		}
		conn = c
	case "http":
		hdr, err := b.resolve(ctx, s.Headers)
		if err != nil {
			return err
		}
		conn = &httpRPC{url: s.URL, headers: hdr, client: &http.Client{Timeout: 2 * time.Minute}}
	}
	ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var init struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := conn.call(ictx, "initialize", map[string]any{"protocolVersion": mcpVersions[0], "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "conduit", "version": "0.1.0"}}, &init); err != nil {
		conn.close()
		return fmt.Errorf("initialize: %w", err)
	}
	_ = conn.call(ictx, "notifications/initialized", nil, nil)
	var tl struct {
		Tools []struct {
			Name        string          `json:"name"`
			Title       string          `json:"title"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
			Annotations *Annotations    `json:"annotations"`
		} `json:"tools"`
	}
	if err := conn.call(ictx, "tools/list", map[string]any{}, &tl); err != nil {
		conn.close()
		return fmt.Errorf("tools/list: %w", err)
	}
	man := sdk.Manifest{ID: s.ModuleID(), Name: s.Name, Version: init.ServerInfo.Version, Category: "MCP servers",
		Description: fmt.Sprintf("Tools from the MCP server %q (%s).", s.Name, init.ServerInfo.Name)}
	for _, t := range tl.Tools {
		risk := sdk.RiskWrite
		if t.Annotations != nil {
			if t.Annotations.ReadOnlyHint && s.TrustReadOnly && !t.Annotations.DestructiveHint {
				risk = sdk.RiskRead
			}
			if t.Annotations.DestructiveHint {
				risk = sdk.RiskDestructive
			}
		}
		if o, ok := s.RiskOverrides[t.Name]; ok {
			risk = sdk.Risk(o)
		}
		title := t.Title
		if title == "" {
			title = t.Name
		}
		man.Actions = append(man.Actions, sdk.ActionSpec{Name: t.Name, Title: title, Description: t.Description, Risk: risk, Input: t.InputSchema})
	}
	mod := &bridgeModule{man: man, conn: conn}
	if err := b.Engine.Register(mod); err != nil {
		conn.close()
		return err
	}
	b.mu.Lock()
	if b.mounted == nil {
		b.mounted = map[string]*bridgeModule{}
	}
	b.mounted[man.ID] = mod
	b.mu.Unlock()
	_, err := b.Engine.SaveInstance(ctx, core.Instance{ID: man.ID, Module: man.ID, Name: s.Name, Enabled: true})
	return err
}

// bridgeModule adapts an MCP server to sdk.Module.
type bridgeModule struct {
	man  sdk.Manifest
	conn rpc
}

func (m *bridgeModule) Manifest() sdk.Manifest { return m.man }
func (m *bridgeModule) Configure(context.Context, sdk.Host, string, json.RawMessage) error {
	return nil
}
func (m *bridgeModule) Close(string) error { return nil }
func (m *bridgeModule) Health(ctx context.Context, _ string) sdk.Health {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := m.conn.call(hctx, "ping", map[string]any{}, nil); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d tools", len(m.man.Actions))}
}

func (m *bridgeModule) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	}
	args := c.Input
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	if err := m.conn.call(ctx, "tools/call", map[string]any{"name": c.Action, "arguments": args}, &res); err != nil {
		return sdk.Result{}, err
	}
	var texts []string
	for _, ct := range res.Content {
		if ct.Type == "text" {
			texts = append(texts, ct.Text)
		}
	}
	text := strings.Join(texts, "\n")
	if res.IsError {
		return sdk.Result{}, errors.New(text)
	}
	if len(res.StructuredContent) > 0 && string(res.StructuredContent) != "null" {
		return sdk.Result{Output: res.StructuredContent}, nil
	}
	var v any
	if json.Unmarshal([]byte(text), &v) == nil {
		return sdk.JSON(v)
	}
	return sdk.JSON(text)
}

// --- transports ------------------------------------------------------------

type stdioRPC struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	mu  sync.Mutex
	id  atomic.Int64
	wmu sync.Mutex

	pending map[int64]chan json.RawMessage
	errs    map[int64]chan error
}

func startStdio(command string, args []string, env map[string]string) (*stdioRPC, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start %s: %w", command, err)
	}
	s := &stdioRPC{cmd: cmd, in: in, pending: map[int64]chan json.RawMessage{}, errs: map[int64]chan error{}}
	go s.read(out)
	return s, nil
}

func (s *stdioRPC) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 32<<20)
	for sc.Scan() {
		var m struct {
			ID     *int64          `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcErr         `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.ID == nil {
			continue
		}
		s.mu.Lock()
		rc, ec := s.pending[*m.ID], s.errs[*m.ID]
		delete(s.pending, *m.ID)
		delete(s.errs, *m.ID)
		s.mu.Unlock()
		if m.Error != nil && ec != nil {
			ec <- errors.New(m.Error.Message)
		} else if rc != nil {
			rc <- m.Result
		}
	}
	s.mu.Lock()
	for id, ec := range s.errs {
		ec <- errors.New("the MCP server exited")
		delete(s.errs, id)
		delete(s.pending, id)
	}
	s.mu.Unlock()
}

func (s *stdioRPC) call(ctx context.Context, method string, params any, out any) error {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	notify := strings.HasPrefix(method, "notifications/")
	var id int64
	rc, ec := make(chan json.RawMessage, 1), make(chan error, 1)
	if !notify {
		id = s.id.Add(1)
		msg["id"] = id
		s.mu.Lock()
		s.pending[id], s.errs[id] = rc, ec
		s.mu.Unlock()
	}
	b, _ := json.Marshal(msg)
	s.wmu.Lock()
	_, err := s.in.Write(append(b, '\n'))
	s.wmu.Unlock()
	if err != nil || notify {
		return err
	}
	select {
	case r := <-rc:
		if out != nil && len(r) > 0 {
			return json.Unmarshal(r, out)
		}
		return nil
	case err := <-ec:
		return err
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		delete(s.errs, id)
		s.mu.Unlock()
		return ctx.Err()
	}
}

func (s *stdioRPC) close() {
	_ = s.in.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
}

type httpRPC struct {
	url     string
	headers map[string]string
	client  *http.Client
	id      atomic.Int64
	session atomic.Value
}

func (h *httpRPC) call(ctx context.Context, method string, params any, out any) error {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	notify := strings.HasPrefix(method, "notifications/")
	if !notify {
		msg["id"] = h.id.Add(1)
	}
	b, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid, ok := h.session.Load().(string); ok && sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	res, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" {
		h.session.Store(sid)
	}
	if notify {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", res.Status, truncate(strings.TrimSpace(string(body)), 300))
	}
	// Servers may answer with a single SSE event instead of plain JSON.
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(body), "\n") {
			if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data:"); ok {
				body = []byte(strings.TrimSpace(d))
			}
		}
	}
	var m struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcErr         `json:"error"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("unexpected answer: %s", truncate(string(body), 200))
	}
	if m.Error != nil {
		return errors.New(m.Error.Message)
	}
	if out != nil && len(m.Result) > 0 {
		return json.Unmarshal(m.Result, out)
	}
	return nil
}

func (h *httpRPC) close() {}
