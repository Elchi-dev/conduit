// Package remote makes a daemon reachable from elsewhere through a hub,
// without opening a port. The daemon links to a hub once (with a pairing
// code from the hub account), keeps a WebSocket to the hub's relay, and
// serves end-to-end encrypted API requests from clients that paired with it
// by scanning its QR code. The hub only forwards ciphertext.
//
// Requests arriving through the tunnel run against the same HTTP handler as
// local ones, so they still need a session or API key, and every action
// still passes the permission policy.
package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/pkg/relay"
)

const keySetting = "remote.relay_key"

// Link is the daemon's registration with a hub.
type Link struct {
	Hub      string    `json:"hub"`
	DeviceID string    `json:"deviceId"`
	Account  string    `json:"account"`
	LinkedAt time.Time `json:"linkedAt"`
	token    string
}

// Client is a phone or browser allowed to use the relay.
type Client struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"createdAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
}

// Status is what the settings page shows.
type Status struct {
	Linked      bool     `json:"linked"`
	Link        *Link    `json:"link,omitempty"`
	Connected   bool     `json:"connected"`
	LastError   string   `json:"lastError,omitempty"`
	PublicKey   string   `json:"publicKey"`
	Fingerprint string   `json:"fingerprint"`
	Clients     []Client `json:"clients"`
	Streams     int      `json:"streams"`
}

// Pairing is what the daemon's QR code carries.
type Pairing struct {
	V         int       `json:"v"`
	Hub       string    `json:"hub"`
	Daemon    string    `json:"daemon"`
	Key       string    `json:"key"`
	Secret    string    `json:"secret"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
	// URI is the same data as a conduit://pair link, for QR codes.
	URI string `json:"uri"`
}

// Service runs the link and the tunnel.
type Service struct {
	DB      *sql.DB
	Log     *slog.Logger
	Name    string       // shown to clients
	Handler http.Handler // the daemon API; set before Start
	HTTP    *http.Client

	key relay.KeyPair

	mu        sync.Mutex
	link      *Link
	connected bool
	lastErr   string
	cancel    context.CancelFunc
	runCtx    context.Context
	pairings  map[string]time.Time // sha256(secret) -> expiry
	streams   int
}

// New loads (or creates) the daemon's relay key and its hub link.
func New(ctx context.Context, db *sql.DB, log *slog.Logger, name string) (*Service, error) {
	s := &Service{DB: db, Log: log, Name: name, HTTP: &http.Client{Timeout: 20 * time.Second}, pairings: map[string]time.Time{}}
	var enc string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, keySetting).Scan(&enc)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		kp, err := relay.NewKeyPair()
		if err != nil {
			return nil, err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?)`, keySetting, relay.Enc(kp.Private.Bytes())); err != nil {
			return nil, err
		}
		s.key = kp
	case err != nil:
		return nil, err
	default:
		b, err := relay.Dec(enc)
		if err != nil {
			return nil, fmt.Errorf("relay key: %w", err)
		}
		if s.key, err = relay.KeyPairFromBytes(b); err != nil {
			return nil, err
		}
	}
	var l Link
	var at string
	err = db.QueryRowContext(ctx, `SELECT hub, device_id, token, account, linked_at FROM remote_link WHERE id = 1`).Scan(&l.Hub, &l.DeviceID, &l.token, &l.Account, &at)
	if err == nil {
		l.LinkedAt, _ = time.Parse(time.RFC3339Nano, at)
		s.link = &l
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return s, nil
}

// PublicKey is the daemon's relay public key.
func (s *Service) PublicKey() string { return s.key.Public() }

// Start keeps the tunnel up while linked, until ctx ends.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.runCtx = ctx
	s.mu.Unlock()
	s.restart()
}

func (s *Service) restart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.link == nil || s.runCtx == nil {
		return
	}
	ctx, cancel := context.WithCancel(s.runCtx)
	s.cancel = cancel
	go s.loop(ctx, *s.link)
}

// Status reports the link, the connection and the paired clients.
func (s *Service) Status(ctx context.Context) Status {
	s.mu.Lock()
	st := Status{Linked: s.link != nil, Connected: s.connected, LastError: s.lastErr, PublicKey: s.key.Public(), Fingerprint: relay.Fingerprint(s.key.Public()), Streams: s.streams}
	if s.link != nil {
		l := *s.link
		st.Link = &l
	}
	s.mu.Unlock()
	st.Clients, _ = s.Clients(ctx)
	return st
}

// LinkHub pairs this daemon with a hub account using a code from that
// account, then connects.
func (s *Service) LinkHub(ctx context.Context, hub, code string) (Link, error) {
	hub = strings.TrimRight(strings.TrimSpace(hub), "/")
	u, err := url.Parse(hub)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Link{}, errors.New("enter the hub's address, like https://hub.example.com")
	}
	body, _ := json.Marshal(map[string]string{"code": code, "name": s.Name, "kind": "daemon", "publicKey": s.key.Public()})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, hub+"/v1/devices/pair", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := s.HTTP.Do(req)
	if err != nil {
		return Link{}, fmt.Errorf("couldn't reach the hub: %w", err)
	}
	defer res.Body.Close()
	var out struct {
		Error  string `json:"error"`
		Token  string `json:"token"`
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		Account struct {
			Email string `json:"email"`
		} `json:"account"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out)
	if res.StatusCode != http.StatusCreated {
		if out.Error == "" {
			out.Error = res.Status
		}
		return Link{}, errors.New("the hub refused: " + out.Error)
	}
	l := Link{Hub: hub, DeviceID: out.Device.ID, Account: out.Account.Email, LinkedAt: time.Now().UTC(), token: out.Token}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO remote_link (id, hub, device_id, token, account, linked_at) VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET hub = excluded.hub, device_id = excluded.device_id, token = excluded.token, account = excluded.account, linked_at = excluded.linked_at`,
		l.Hub, l.DeviceID, l.token, l.Account, l.LinkedAt.Format(time.RFC3339Nano)); err != nil {
		return Link{}, err
	}
	s.mu.Lock()
	s.link = &l
	s.lastErr = ""
	s.mu.Unlock()
	s.restart()
	return l, nil
}

// Unlink removes the device from the hub (best effort) and forgets the link.
func (s *Service) Unlink(ctx context.Context) error {
	s.mu.Lock()
	l := s.link
	s.link = nil
	s.connected = false
	s.mu.Unlock()
	s.restart()
	if l == nil {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, l.Hub+"/v1/devices/"+url.PathEscape(l.DeviceID), nil)
	req.Header.Set("Authorization", "Bearer "+l.token)
	if res, err := s.HTTP.Do(req); err == nil {
		res.Body.Close()
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM remote_link WHERE id = 1`)
	return err
}

// NewPairing makes a one-time secret (valid 10 minutes) for a client to
// enroll, and the QR payload that carries it with the daemon's key.
func (s *Service) NewPairing() (Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.link == nil {
		return Pairing{}, errors.New("link this daemon to a hub first")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return Pairing{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	for k, exp := range s.pairings {
		if now.After(exp) {
			delete(s.pairings, k)
		}
	}
	p := Pairing{V: 1, Hub: s.link.Hub, Daemon: s.link.DeviceID, Key: s.key.Public(), Secret: secret, Name: s.Name, ExpiresAt: now.Add(10 * time.Minute).UTC()}
	s.pairings[sum(secret)] = p.ExpiresAt
	j, _ := json.Marshal(map[string]any{"v": p.V, "hub": p.Hub, "daemon": p.Daemon, "key": p.Key, "secret": p.Secret, "name": p.Name})
	p.URI = "conduit://pair?d=" + base64.RawURLEncoding.EncodeToString(j)
	return p, nil
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// usePairing consumes a pairing secret.
func (s *Service) usePairing(secret string) bool {
	if secret == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sum(secret)
	for k, exp := range s.pairings {
		if subtle.ConstantTimeCompare([]byte(k), []byte(h)) == 1 {
			delete(s.pairings, k)
			return time.Now().Before(exp)
		}
	}
	return false
}

// Clients lists enrolled clients.
func (s *Service) Clients(ctx context.Context) ([]Client, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, public_key, created_at, last_seen_at FROM relay_clients WHERE revoked = 0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		var pub, cr, ls string
		if rows.Scan(&c.ID, &c.Name, &pub, &cr, &ls) == nil {
			c.Fingerprint = relay.Fingerprint(pub)
			c.CreatedAt, _ = time.Parse(time.RFC3339Nano, cr)
			c.LastSeenAt, _ = time.Parse(time.RFC3339Nano, ls)
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// RevokeClient stops a client from opening new sessions.
func (s *Service) RevokeClient(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE relay_clients SET revoked = 1 WHERE id = ? AND revoked = 0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such client")
	}
	return nil
}

// admit decides whether a client hello may open a session.
func (s *Service) admit(ctx context.Context, h relay.Hello, in relay.Intro) (string, error) {
	var id string
	var revoked int
	err := s.DB.QueryRowContext(ctx, `SELECT id, revoked FROM relay_clients WHERE public_key = ?`, h.Static).Scan(&id, &revoked)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err == nil {
		if revoked == 1 {
			return "", errors.New("this device was removed; pair it again")
		}
		_, _ = s.DB.ExecContext(ctx, `UPDATE relay_clients SET last_seen_at = ? WHERE id = ?`, now, id)
		return id, nil
	}
	if !s.usePairing(in.PairingSecret) {
		return "", errors.New("unknown device; scan a fresh pairing code")
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	id = "rc_" + hex.EncodeToString(b)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Remote device"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO relay_clients (id, name, public_key, created_at, last_seen_at) VALUES (?,?,?,?,?)
		ON CONFLICT(public_key) DO UPDATE SET revoked = 0, name = excluded.name, last_seen_at = excluded.last_seen_at`, id, name, h.Static, now, now); err != nil {
		return "", err
	}
	_ = s.DB.QueryRowContext(ctx, `SELECT id FROM relay_clients WHERE public_key = ?`, h.Static).Scan(&id)
	s.Log.Info("relay: new client paired", "client", id, "name", name)
	return id, nil
}

// --- tunnel ------------------------------------------------------------------

func (s *Service) setConn(ok bool, err error) {
	s.mu.Lock()
	s.connected = ok
	if err != nil {
		s.lastErr = err.Error()
	} else if ok {
		s.lastErr = ""
	}
	s.mu.Unlock()
}

func (s *Service) loop(ctx context.Context, l Link) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := s.serve(ctx, l)
		s.setConn(false, err)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		s.Log.Warn("relay: disconnected from hub; retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

type stream struct {
	mu     sync.Mutex // orders seal+write
	sess   *relay.Session
	client string
}

type tunnel struct {
	s       *Service
	ws      *websocket.Conn
	writeMu sync.Mutex
	streams map[uint32]*stream
}

func (t *tunnel) send(ctx context.Context, id uint32, frame []byte) error {
	b := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(b, id)
	copy(b[4:], frame)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return t.ws.Write(wctx, websocket.MessageBinary, b)
}

func (t *tunnel) closeStream(ctx context.Context, id uint32) {
	delete(t.streams, id)
	b, _ := json.Marshal(map[string]any{"type": "close", "stream": id})
	t.writeMu.Lock()
	_ = t.ws.Write(ctx, websocket.MessageText, b)
	t.writeMu.Unlock()
}

func (s *Service) serve(ctx context.Context, l Link) error {
	ws, _, err := websocket.Dial(ctx, relay.HubWS(l.Hub)+"/v1/relay/daemon", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + l.token}},
	})
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(8<<20 + 4)
	s.setConn(true, nil)
	s.Log.Info("relay: connected to hub", "hub", l.Hub)
	t := &tunnel{s: s, ws: ws, streams: map[uint32]*stream{}}
	defer func() {
		s.mu.Lock()
		s.streams = 0
		s.mu.Unlock()
	}()
	for {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ == websocket.MessageText {
			var m struct {
				Type   string `json:"type"`
				Stream uint32 `json:"stream"`
			}
			if json.Unmarshal(b, &m) == nil && m.Type == "close" {
				delete(t.streams, m.Stream)
			}
			s.mu.Lock()
			s.streams = len(t.streams)
			s.mu.Unlock()
			continue
		}
		if len(b) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(b[:4])
		frame := b[4:]
		st := t.streams[id]
		if st == nil {
			t.handshake(ctx, id, frame)
			s.mu.Lock()
			s.streams = len(t.streams)
			s.mu.Unlock()
			continue
		}
		// Frames are opened in arrival order (nonces count up); requests then
		// run concurrently and responses are sealed in the order they finish.
		var req relay.Request
		if err := st.sess.OpenJSON(frame, &req); err != nil {
			s.Log.Warn("relay: dropping stream after a bad frame", "client", st.client, "err", err)
			t.closeStream(ctx, id)
			continue
		}
		go func() {
			res := s.execute(ctx, st.client, req)
			st.mu.Lock()
			defer st.mu.Unlock()
			out, err := st.sess.SealJSON(res)
			if err == nil {
				_ = t.send(ctx, id, out)
			}
		}()
	}
}

func (t *tunnel) handshake(ctx context.Context, id uint32, frame []byte) {
	var h relay.Hello
	if err := json.Unmarshal(frame, &h); err != nil {
		t.closeStream(ctx, id)
		return
	}
	// A failed proof means the client pinned another key or forged its
	// static key; it can't read anything we'd send, so just close.
	sess, intro, err := relay.DaemonHandshake(t.s.key, h)
	if err != nil {
		t.closeStream(ctx, id)
		return
	}
	client, err := t.s.admit(ctx, h, intro)
	w := relay.Welcome{OK: err == nil, Client: client, Daemon: t.s.Name}
	if err != nil {
		w.Error = err.Error()
	}
	out, _ := sess.SealJSON(w)
	_ = t.send(ctx, id, out)
	if err != nil {
		t.closeStream(ctx, id)
		return
	}
	t.streams[id] = &stream{sess: sess, client: client}
}

// Headers a relayed request may carry; anything else is dropped.
var passHeaders = []string{"Authorization", "Content-Type", "Accept", "Idempotency-Key"}

const maxBody = 8 << 20

// execute runs one relayed API request against the daemon's handler.
func (s *Service) execute(ctx context.Context, client string, r relay.Request) relay.Response {
	res := relay.Response{ID: r.ID}
	if !strings.HasPrefix(r.Path, "/api/") || strings.Contains(r.Path, "..") {
		res.Status = http.StatusNotFound
		res.Body = []byte(`{"error":"only the API is reachable through the relay"}`)
		return res
	}
	// Server-sent events never end, so they can't be answered as one frame.
	if strings.HasPrefix(r.Path, "/api/v1/events") {
		res.Status = http.StatusNotImplemented
		res.Body = []byte(`{"error":"live events aren't carried over the relay yet; poll instead"}`)
		return res
	}
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodGet
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req := httptest.NewRequestWithContext(rctx, method, r.Path, bytes.NewReader(r.Body))
	req.RemoteAddr = "relay"
	for _, h := range passHeaders {
		if v, ok := r.Headers[h]; ok {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("X-Conduit-Relay-Client", client)
	rec := httptest.NewRecorder()
	if s.Handler == nil {
		res.Status = http.StatusServiceUnavailable
		return res
	}
	s.Handler.ServeHTTP(rec, req)
	res.Status = rec.Code
	res.Headers = map[string]string{}
	for _, h := range []string{"Content-Type", "Retry-After"} {
		if v := rec.Header().Get(h); v != "" {
			res.Headers[h] = v
		}
	}
	body := rec.Body.Bytes()
	if len(body) > maxBody {
		res.Status = http.StatusInsufficientStorage
		body = []byte(`{"error":"the response is too large for the relay"}`)
	}
	res.Body = body
	return res
}
