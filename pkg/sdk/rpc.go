package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// This file implements the external-module protocol: JSON-RPC 2.0, one JSON
// object per line, in both directions over a pair of streams (stdin/stdout of
// the module process). See docs/protocol/external-modules.md.
//
// Daemon → module methods: initialize, configure, invoke, health, close.
// Module → daemon methods: host.secret (request), host.publish and host.log
// (notifications).

// ProtocolVersion is the external-module protocol version.
const ProtocolVersion = "1"

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// RPCHandler answers incoming requests and notifications.
type RPCHandler func(ctx context.Context, method string, params json.RawMessage) (any, error)

// RPCConn is a symmetric JSON-RPC connection over line-delimited streams.
type RPCConn struct {
	w       io.Writer
	wmu     sync.Mutex
	handler RPCHandler

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan rpcMessage
	closed  chan struct{}
	err     error
}

// NewRPCConn starts reading from r. Incoming requests are passed to handler.
func NewRPCConn(r io.Reader, w io.Writer, handler RPCHandler) *RPCConn {
	c := &RPCConn{w: w, handler: handler, pending: map[int64]chan rpcMessage{}, closed: make(chan struct{})}
	go c.read(r)
	return c
}

// Done is closed when the connection's reader stops.
func (c *RPCConn) Done() <-chan struct{} { return c.closed }

func (c *RPCConn) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var m rpcMessage
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue // ignore non-protocol lines
		}
		if m.Method != "" {
			go c.serve(m)
			continue
		}
		if m.ID == nil {
			continue
		}
		c.mu.Lock()
		ch := c.pending[*m.ID]
		delete(c.pending, *m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
	c.mu.Lock()
	c.err = sc.Err()
	if c.err == nil {
		c.err = io.EOF
	}
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	close(c.closed)
}

func (c *RPCConn) serve(m rpcMessage) {
	var res any
	var err error
	if c.handler == nil {
		err = &RPCError{Code: -32601, Message: "method not found: " + m.Method}
	} else {
		res, err = c.handler(context.Background(), m.Method, m.Params)
	}
	if m.ID == nil { // notification
		return
	}
	reply := rpcMessage{JSONRPC: "2.0", ID: m.ID}
	if err != nil {
		var re *RPCError
		if !errors.As(err, &re) {
			re = &RPCError{Code: -32000, Message: err.Error()}
		}
		reply.Error = re
	} else {
		reply.Result, _ = json.Marshal(res)
	}
	_ = c.send(reply)
}

func (c *RPCConn) send(m rpcMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.w.Write(append(b, '\n'))
	return err
}

// Call sends a request and decodes the result into out (which may be nil).
func (c *RPCConn) Call(ctx context.Context, method string, params, out any) error {
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return fmt.Errorf("connection closed: %w", err)
	}
	c.nextID++
	id := c.nextID
	ch := make(chan rpcMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.send(rpcMessage{JSONRPC: "2.0", ID: &id, Method: method, Params: p}); err != nil {
		return err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return errors.New("connection closed")
		}
		if m.Error != nil {
			return m.Error
		}
		if out != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// Notify sends a notification (no reply).
func (c *RPCConn) Notify(method string, params any) error {
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return c.send(rpcMessage{JSONRPC: "2.0", Method: method, Params: p})
}

// Wire types shared by both sides.

// InitializeResult is the module's answer to "initialize".
type InitializeResult struct {
	ProtocolVersion string   `json:"protocolVersion"`
	Manifest        Manifest `json:"manifest"`
}

// ConfigureParams are the params of "configure".
type ConfigureParams struct {
	Instance string          `json:"instance"`
	Config   json.RawMessage `json:"config"`
}

// InstanceParams name one instance ("health", "close").
type InstanceParams struct {
	Instance string `json:"instance"`
}

// SecretParams are the params of "host.secret".
type SecretParams struct {
	Ref string `json:"ref"`
}

// LogParams are the params of "host.log".
type LogParams struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	KV    []any  `json:"kv,omitempty"`
}

// Serve runs m as an external module over r/w (normally os.Stdin and
// os.Stdout) until the daemon closes the stream. Module authors writing in Go
// call this from main.
func Serve(m Module, r io.Reader, w io.Writer) error {
	h := &rpcHost{}
	conn := NewRPCConn(r, w, func(ctx context.Context, method string, params json.RawMessage) (any, error) {
		switch method {
		case "initialize":
			return InitializeResult{ProtocolVersion: ProtocolVersion, Manifest: m.Manifest()}, nil
		case "configure":
			var p ConfigureParams
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			return struct{}{}, m.Configure(ctx, h, p.Instance, p.Config)
		case "invoke":
			var call Call
			if err := json.Unmarshal(params, &call); err != nil {
				return nil, err
			}
			return m.Invoke(ctx, call)
		case "health":
			var p InstanceParams
			_ = json.Unmarshal(params, &p)
			return m.Health(ctx, p.Instance), nil
		case "close":
			var p InstanceParams
			_ = json.Unmarshal(params, &p)
			return struct{}{}, m.Close(p.Instance)
		}
		return nil, &RPCError{Code: -32601, Message: "method not found: " + method}
	})
	h.conn.Store(conn)
	<-conn.Done()
	return nil
}

// rpcHost implements Host for a module running out of process.
// The connection is published atomically because requests can arrive (and
// call back into the host) before Serve finishes wiring it up.
type rpcHost struct{ conn atomic.Pointer[RPCConn] }

func (h *rpcHost) c() *RPCConn {
	for {
		if c := h.conn.Load(); c != nil {
			return c
		}
		runtime.Gosched()
	}
}

func (h *rpcHost) Secret(ctx context.Context, ref string) (string, error) {
	var v string
	err := h.c().Call(ctx, "host.secret", SecretParams{Ref: ref}, &v)
	return v, err
}

func (h *rpcHost) Publish(_ context.Context, e Event) { _ = h.c().Notify("host.publish", e) }

func (h *rpcHost) Log(level, msg string, kv ...any) {
	_ = h.c().Notify("host.log", LogParams{Level: level, Msg: msg, KV: kv})
}
