package remote

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/elchi-dev/conduit/pkg/relay"
)

// Streaming over the relay: the event stream (SSE) is answered with a
// series of frames as events happen, until the client cancels or leaves.

const maxStreamsPerConn = 4

// conn tracks one relayed connection's open streams.
type conn struct {
	mu      sync.Mutex
	cancels map[uint64]context.CancelFunc
}

func newConn() *conn { return &conn{cancels: map[uint64]context.CancelFunc{}} }

// closeAll ends every stream (the connection went away).
func (c *conn) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, cancel := range c.cancels {
		cancel()
		delete(c.cancels, id)
	}
}

// dispatch answers one request, streaming when the path calls for it.
func (s *Service) dispatch(ctx context.Context, c *conn, client string, r relay.Request, send func(relay.Response)) {
	if r.Method == relay.MethodCancel {
		c.mu.Lock()
		if cancel := c.cancels[r.ID]; cancel != nil {
			cancel()
			delete(c.cancels, r.ID)
		}
		c.mu.Unlock()
		return
	}
	if !strings.HasPrefix(r.Path, "/api/v1/events") || strings.ToUpper(r.Method) != http.MethodGet {
		send(s.execute(ctx, client, r))
		return
	}
	c.mu.Lock()
	if len(c.cancels) >= maxStreamsPerConn {
		c.mu.Unlock()
		send(relay.Response{ID: r.ID, Status: http.StatusTooManyRequests, Body: []byte(`{"error":"too many open streams"}`)})
		return
	}
	sctx, cancel := context.WithCancel(ctx)
	c.cancels[r.ID] = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.cancels, r.ID)
		c.mu.Unlock()
		cancel()
	}()

	req := httptest.NewRequestWithContext(sctx, http.MethodGet, r.Path, nil)
	req.RemoteAddr = "relay"
	for _, h := range passHeaders {
		if v, ok := r.Headers[h]; ok {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("X-Conduit-Relay-Client", client)
	w := &streamWriter{id: r.ID, send: send, header: http.Header{}, status: http.StatusOK}
	if s.Handler == nil {
		send(relay.Response{ID: r.ID, Status: http.StatusServiceUnavailable})
		return
	}
	s.Handler.ServeHTTP(w, req)
	w.Flush()
	send(relay.Response{ID: r.ID, Status: w.status}) // end of stream
}

// streamWriter turns each flush of an HTTP handler into one frame.
type streamWriter struct {
	id     uint64
	send   func(relay.Response)
	header http.Header
	status int
	mu     sync.Mutex
	buf    bytes.Buffer
	sent   bool
}

func (w *streamWriter) Header() http.Header { return w.header }
func (w *streamWriter) WriteHeader(code int) {
	w.mu.Lock()
	w.status = code
	w.mu.Unlock()
}
func (w *streamWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(b)
}
func (w *streamWriter) Flush() {
	w.mu.Lock()
	if w.buf.Len() == 0 && w.sent {
		w.mu.Unlock()
		return
	}
	res := relay.Response{ID: w.id, Status: w.status, Body: append([]byte(nil), w.buf.Bytes()...), Stream: true}
	if !w.sent {
		res.Headers = map[string]string{"Content-Type": w.header.Get("Content-Type")}
	}
	w.sent = true
	w.buf.Reset()
	w.mu.Unlock()
	w.send(res)
}
