package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// External is a module that runs out of process and speaks the external-module
// protocol (JSON-RPC 2.0 over stdio). It implements sdk.Module, so the engine
// treats it exactly like a built-in module.
type External struct {
	conn     *sdk.RPCConn
	manifest sdk.Manifest
	cmd      *exec.Cmd

	mu    sync.Mutex
	hosts map[string]sdk.Host // per instance, for callbacks
}

// ConnectExternal performs the handshake over an existing stream pair. It is
// used directly in tests and by StartExternal for real processes.
func ConnectExternal(ctx context.Context, r io.Reader, w io.Writer) (*External, error) {
	x := &External{hosts: map[string]sdk.Host{}}
	x.conn = sdk.NewRPCConn(r, w, x.handle)
	var init sdk.InitializeResult
	ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := x.conn.Call(ictx, "initialize", map[string]string{"protocolVersion": sdk.ProtocolVersion}, &init); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if init.ProtocolVersion != sdk.ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %q", init.ProtocolVersion)
	}
	if init.Manifest.ID == "" {
		return nil, errors.New("external module returned an empty manifest id")
	}
	x.manifest = init.Manifest
	return x, nil
}

// StartExternal launches an external module executable. Its stderr is
// forwarded to the daemon log.
func StartExternal(ctx context.Context, path string, args []string, stderr io.Writer) (*External, error) {
	cmd := exec.Command(path, args...)
	cmd.Dir = filepath.Dir(path)
	cmd.Env = append(os.Environ(), "CONDUIT_MODULE_PROTOCOL="+sdk.ProtocolVersion)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	x, err := ConnectExternal(ctx, stdout, stdin)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	x.cmd = cmd
	return x, nil
}

func (x *External) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	// Callbacks are attributed to the first configured instance's host when
	// the module does not say which instance it means; events carry their
	// own instance field.
	x.mu.Lock()
	var h sdk.Host
	for _, v := range x.hosts {
		h = v
		break
	}
	x.mu.Unlock()
	if h == nil {
		return nil, errors.New("module has no configured instance")
	}
	switch method {
	case "host.secret":
		var p sdk.SecretParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return h.Secret(ctx, p.Ref)
	case "host.publish":
		var ev sdk.Event
		if err := json.Unmarshal(params, &ev); err == nil {
			h.Publish(ctx, ev)
		}
		return nil, nil
	case "host.log":
		var p sdk.LogParams
		if err := json.Unmarshal(params, &p); err == nil {
			h.Log(p.Level, p.Msg, p.KV...)
		}
		return nil, nil
	}
	return nil, &sdk.RPCError{Code: -32601, Message: "method not found: " + method}
}

// Manifest implements sdk.Module.
func (x *External) Manifest() sdk.Manifest { return x.manifest }

// Configure implements sdk.Module.
func (x *External) Configure(ctx context.Context, h sdk.Host, instance string, config json.RawMessage) error {
	x.mu.Lock()
	x.hosts[instance] = h
	x.mu.Unlock()
	return x.conn.Call(ctx, "configure", sdk.ConfigureParams{Instance: instance, Config: config}, nil)
}

// Invoke implements sdk.Module.
func (x *External) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	var r sdk.Result
	err := x.conn.Call(ctx, "invoke", call, &r)
	return r, err
}

// Health implements sdk.Module.
func (x *External) Health(ctx context.Context, instance string) sdk.Health {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var h sdk.Health
	if err := x.conn.Call(hctx, "health", sdk.InstanceParams{Instance: instance}, &h); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return h
}

// Close implements sdk.Module.
func (x *External) Close(instance string) error {
	x.mu.Lock()
	delete(x.hosts, instance)
	x.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return x.conn.Call(ctx, "close", sdk.InstanceParams{Instance: instance}, nil)
}

// Stop terminates the module process.
func (x *External) Stop() error {
	if x.cmd == nil || x.cmd.Process == nil {
		return nil
	}
	_ = x.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- x.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		_ = x.cmd.Process.Kill()
		return <-done
	}
}

// LoadExternalDir starts every executable in dir as an external module and
// registers it. Failures are logged and skipped.
func (e *Engine) LoadExternalDir(ctx context.Context, dir string) []*External {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []*External
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		info, err := ent.Info()
		if err != nil || info.Mode()&0o111 == 0 {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		x, err := StartExternal(ctx, path, nil, os.Stderr)
		if err != nil {
			e.Log.Warn("external module failed to start", "path", path, "err", err)
			continue
		}
		if err := e.Register(x); err != nil {
			e.Log.Warn("external module rejected", "path", path, "err", err)
			_ = x.Stop()
			continue
		}
		out = append(out, x)
	}
	return out
}
