package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// Welcome is the daemon's first encrypted frame on a stream.
type Welcome struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Client string `json:"client,omitempty"` // the id the daemon knows this client by
	Daemon string `json:"daemon,omitempty"` // the daemon's display name
}

// Client is a Go relay client: it reaches a daemon through a hub and sends
// API requests over the encrypted tunnel. The web app and Android app use
// the TypeScript implementation of the same protocol.
type Client struct {
	ws      *websocket.Conn
	sess    *Session
	Welcome Welcome

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan Response
	streams map[uint64]chan Response
	readErr error
	done    chan struct{}
}

// HubWS turns a hub URL into its WebSocket base.
func HubWS(hub string) string {
	hub = strings.TrimRight(hub, "/")
	switch {
	case strings.HasPrefix(hub, "https://"):
		return "wss://" + hub[len("https://"):]
	case strings.HasPrefix(hub, "http://"):
		return "ws://" + hub[len("http://"):]
	}
	return hub
}

// Dial connects to daemonID through hub. daemonPub is the key pinned from the
// pairing QR code; pairingSecret is only needed the first time.
func Dial(ctx context.Context, hub, daemonID, daemonPub string, me KeyPair, pairingSecret, name string) (*Client, error) {
	return DialURL(ctx, HubWS(hub)+"/v1/relay/connect/"+daemonID, daemonPub, me, pairingSecret, name)
}

// DialURL connects to a relay endpoint directly: a hub's connect URL, or a
// daemon's own ws://host:port/relay on the local network.
func DialURL(ctx context.Context, wsURL, daemonPub string, me KeyPair, pairingSecret, name string) (*Client, error) {
	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("reach the daemon: %w", err)
	}
	ws.SetReadLimit(8 << 20)
	hello, sess, err := ClientHandshake(me, daemonPub, pairingSecret, name)
	if err != nil {
		ws.CloseNow()
		return nil, err
	}
	b, _ := json.Marshal(hello)
	if err := ws.Write(ctx, websocket.MessageBinary, b); err != nil {
		ws.CloseNow()
		return nil, err
	}
	_, frame, err := ws.Read(ctx)
	if err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("the daemon didn't answer: %w", err)
	}
	var w Welcome
	if err := sess.OpenJSON(frame, &w); err != nil {
		ws.CloseNow()
		return nil, errors.New("the daemon's answer didn't decrypt: its key doesn't match the one you paired with")
	}
	if !w.OK {
		ws.CloseNow()
		return nil, errors.New("the daemon refused the connection: " + w.Error)
	}
	c := &Client{ws: ws, sess: sess, Welcome: w, pending: map[uint64]chan Response{}, streams: map[uint64]chan Response{}, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *Client) readLoop() {
	defer close(c.done)
	for {
		_, frame, err := c.ws.Read(context.Background())
		if err == nil {
			var res Response
			if err = c.sess.OpenJSON(frame, &res); err == nil {
				c.mu.Lock()
				if sc := c.streams[res.ID]; sc != nil {
					if !res.Stream {
						delete(c.streams, res.ID)
						close(sc)
					} else {
						select {
						case sc <- res:
						default: // a slow reader drops frames rather than stalling the connection
						}
					}
					c.mu.Unlock()
					continue
				}
				ch := c.pending[res.ID]
				delete(c.pending, res.ID)
				c.mu.Unlock()
				if ch != nil {
					ch <- res
				}
				continue
			}
		}
		c.mu.Lock()
		c.readErr = err
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		for id, ch := range c.streams {
			close(ch)
			delete(c.streams, id)
		}
		c.mu.Unlock()
		return
	}
}

// Do sends one request and waits for its response.
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	ch := make(chan Response, 1)
	c.mu.Lock()
	if c.readErr != nil {
		err := c.readErr
		c.mu.Unlock()
		return Response{}, err
	}
	c.nextID++
	req.ID = c.nextID
	c.pending[req.ID] = ch
	// Sealing and writing happen under the lock so frames leave in nonce order.
	frame, err := c.sess.SealJSON(req)
	if err == nil {
		err = c.ws.Write(ctx, websocket.MessageBinary, frame)
	}
	if err != nil {
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return Response{}, err
	}
	c.mu.Unlock()
	select {
	case res, ok := <-ch:
		if !ok {
			return Response{}, errors.New("the relay connection closed")
		}
		return res, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return Response{}, ctx.Err()
	}
}

// Stream opens a streamed request (the event stream). Frames arrive on the
// channel until the daemon ends the stream, cancel is called or the
// connection closes.
func (c *Client) Stream(ctx context.Context, req Request) (<-chan Response, func(), error) {
	ch := make(chan Response, 64)
	c.mu.Lock()
	if c.readErr != nil {
		err := c.readErr
		c.mu.Unlock()
		return nil, nil, err
	}
	c.nextID++
	req.ID = c.nextID
	c.streams[req.ID] = ch
	frame, err := c.sess.SealJSON(req)
	if err == nil {
		err = c.ws.Write(ctx, websocket.MessageBinary, frame)
	}
	if err != nil {
		delete(c.streams, req.ID)
		c.mu.Unlock()
		return nil, nil, err
	}
	c.mu.Unlock()
	id := req.ID
	cancel := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if f, err := c.sess.SealJSON(Request{ID: id, Method: MethodCancel}); err == nil {
			_ = c.ws.Write(context.Background(), websocket.MessageBinary, f)
		}
	}
	return ch, cancel, nil
}

// Close ends the session.
func (c *Client) Close() error {
	err := c.ws.Close(websocket.StatusNormalClosure, "")
	<-c.done
	return err
}
