package hub

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// The relay pipes opaque frames between a daemon and its clients. Everything
// it carries is end-to-end encrypted (pkg/relay): the hub sees stream ids,
// frame sizes and timing, never content.
//
// Daemon socket (GET /v1/relay/daemon, device token of kind "daemon"):
//   - binary message: 4-byte big-endian stream id, then one ciphertext frame
//   - text message:   {"type":"open"|"close","stream":n} control events
//
// Client socket (GET /v1/relay/connect/{daemon}): each binary message is one
// frame; the hub adds and strips the stream id.

const maxFrame = 4 << 20

type relayHub struct {
	mu      sync.Mutex
	daemons map[string]*daemonConn
}

type daemonConn struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	next    uint32
	clients map[uint32]*websocket.Conn
}

func newRelayHub() *relayHub { return &relayHub{daemons: map[string]*daemonConn{}} }

// Online reports whether a daemon is connected.
func (h *relayHub) online(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.daemons[id] != nil
}

func (d *daemonConn) write(ctx context.Context, typ websocket.MessageType, b []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return d.ws.Write(ctx, typ, b)
}

func (d *daemonConn) control(ctx context.Context, typ string, stream uint32) {
	b, _ := json.Marshal(map[string]any{"type": typ, "stream": stream})
	_ = d.write(ctx, websocket.MessageText, b)
}

func (s *Server) relayDaemon(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	c, err := s.authenticate(r.Context(), tok)
	if err != nil || c.DeviceID == "" {
		writeErr(w, http.StatusUnauthorized, "the relay needs a paired daemon's device token")
		return
	}
	var kind string
	_ = s.db.Row(r.Context(), `SELECT kind FROM devices WHERE id = ?`, c.DeviceID).Scan(&kind)
	if kind != "daemon" {
		writeErr(w, http.StatusForbidden, "only daemons can offer a relay endpoint")
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(maxFrame + 4)
	d := &daemonConn{ws: ws, clients: map[uint32]*websocket.Conn{}}

	s.relay.mu.Lock()
	if old := s.relay.daemons[c.DeviceID]; old != nil {
		old.ws.Close(websocket.StatusPolicyViolation, "replaced by a newer connection")
	}
	s.relay.daemons[c.DeviceID] = d
	s.relay.mu.Unlock()
	s.log.Info("relay: daemon online", "device", c.DeviceID)

	defer func() {
		s.relay.mu.Lock()
		if s.relay.daemons[c.DeviceID] == d {
			delete(s.relay.daemons, c.DeviceID)
		}
		s.relay.mu.Unlock()
		d.mu.Lock()
		for _, cl := range d.clients {
			cl.Close(websocket.StatusGoingAway, "daemon went offline")
		}
		d.mu.Unlock()
		ws.CloseNow()
		s.log.Info("relay: daemon offline", "device", c.DeviceID)
	}()

	ctx := r.Context()
	go keepAlive(ctx, ws)
	for {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if len(b) < 4 {
				continue
			}
			id := binary.BigEndian.Uint32(b[:4])
			d.mu.Lock()
			cl := d.clients[id]
			d.mu.Unlock()
			if cl != nil {
				wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				_ = cl.Write(wctx, websocket.MessageBinary, b[4:])
				cancel()
			}
		case websocket.MessageText:
			var m struct {
				Type   string `json:"type"`
				Stream uint32 `json:"stream"`
			}
			if json.Unmarshal(b, &m) == nil && m.Type == "close" {
				d.mu.Lock()
				if cl := d.clients[m.Stream]; cl != nil {
					cl.Close(websocket.StatusNormalClosure, "closed by daemon")
					delete(d.clients, m.Stream)
				}
				d.mu.Unlock()
			}
		}
	}
}

// relayClient connects a client to a daemon. The hub doesn't authenticate
// clients: the daemon does, end to end, with an enrolled client key or a
// one-time pairing secret. Connections are rate-limited per address.
func (s *Server) relayClient(w http.ResponseWriter, r *http.Request) {
	s.limited("relay-connect", 120, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("daemon")
		s.relay.mu.Lock()
		d := s.relay.daemons[id]
		s.relay.mu.Unlock()
		if d == nil {
			writeErr(w, http.StatusNotFound, "that daemon isn't connected to this hub right now")
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		ws.SetReadLimit(maxFrame)
		d.mu.Lock()
		if len(d.clients) >= 64 {
			d.mu.Unlock()
			ws.Close(websocket.StatusTryAgainLater, "too many clients on this daemon")
			return
		}
		d.next++
		stream := d.next
		d.clients[stream] = ws
		d.mu.Unlock()

		ctx := r.Context()
		d.control(ctx, "open", stream)
		defer func() {
			d.mu.Lock()
			delete(d.clients, stream)
			d.mu.Unlock()
			d.control(context.Background(), "close", stream)
			ws.CloseNow()
		}()
		go keepAlive(ctx, ws)
		head := make([]byte, 4)
		binary.BigEndian.PutUint32(head, stream)
		for {
			typ, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if typ != websocket.MessageBinary {
				continue
			}
			if err := d.write(ctx, websocket.MessageBinary, append(append([]byte{}, head...), b...)); err != nil {
				return
			}
		}
	})(w, r)
}

func keepAlive(ctx context.Context, ws *websocket.Conn) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := ws.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
