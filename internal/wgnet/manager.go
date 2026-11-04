package wgnet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned for an unknown network.
var ErrNotFound = errors.New("no such network")

// Resolver resolves secret:// references (the vault).
type Resolver func(ctx context.Context, ref string) (string, error)

// Manager keeps the daemon's networks in the database and runs their
// tunnels. A tunnel starts the first time an instance dials through it
// (the vault may still be locked when the daemon starts), and restarts
// when its settings change.
type Manager struct {
	db      *sql.DB
	secrets Resolver
	log     *slog.Logger

	mu      sync.Mutex
	tunnels map[string]*Tunnel
	errs    map[string]string
	// starting serialises tunnel start-up per network.
	starting map[string]*sync.Mutex
}

// NewManager returns a manager over the daemon database (table networks).
func NewManager(db *sql.DB, secrets Resolver, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{db: db, secrets: secrets, log: log, tunnels: map[string]*Tunnel{}, errs: map[string]string{}, starting: map[string]*sync.Mutex{}}
}

// List returns every network, by name.
func (m *Manager) List(ctx context.Context) ([]Config, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT config FROM networks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Config{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var c Config
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, rows.Err()
}

// Get returns one network.
func (m *Manager) Get(ctx context.Context, id string) (Config, error) {
	var raw string
	err := m.db.QueryRowContext(ctx, `SELECT config FROM networks WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, ErrNotFound
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	err = json.Unmarshal([]byte(raw), &c)
	return c, err
}

// Save creates or replaces a network (c.ID must be set) and restarts its
// tunnel on next use.
func (m *Manager) Save(ctx context.Context, c Config) (Config, error) {
	if c.ID == "" {
		return c, errors.New("network id is required")
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return c, err
	}
	now := time.Now().UTC()
	if old, err := m.Get(ctx, c.ID); err == nil {
		c.CreatedAt = old.CreatedAt
	} else {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	b, _ := json.Marshal(c)
	if _, err := m.db.ExecContext(ctx, `INSERT INTO networks (id, name, config, created_at, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, config = excluded.config, updated_at = excluded.updated_at`,
		c.ID, c.Name, string(b), c.CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return c, err
	}
	m.stop(c.ID)
	return c, nil
}

// Delete removes a network and takes its tunnel down.
func (m *Manager) Delete(ctx context.Context, id string) error {
	res, err := m.db.ExecContext(ctx, `DELETE FROM networks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	m.stop(id)
	return nil
}

func (m *Manager) stop(id string) {
	m.mu.Lock()
	t := m.tunnels[id]
	delete(m.tunnels, id)
	delete(m.errs, id)
	m.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// Restart takes a network's tunnel down and brings it up again.
func (m *Manager) Restart(ctx context.Context, id string) error {
	m.stop(id)
	_, err := m.tunnel(ctx, id)
	return err
}

// Close takes every tunnel down.
func (m *Manager) Close() {
	m.mu.Lock()
	ts := m.tunnels
	m.tunnels = map[string]*Tunnel{}
	m.mu.Unlock()
	for _, t := range ts {
		t.Close()
	}
}

// tunnel returns the running tunnel of a network, starting it if needed.
func (m *Manager) tunnel(ctx context.Context, id string) (*Tunnel, error) {
	m.mu.Lock()
	if t := m.tunnels[id]; t != nil {
		m.mu.Unlock()
		return t, nil
	}
	lk := m.starting[id]
	if lk == nil {
		lk = &sync.Mutex{}
		m.starting[id] = lk
	}
	m.mu.Unlock()
	lk.Lock()
	defer lk.Unlock()
	m.mu.Lock()
	if t := m.tunnels[id]; t != nil {
		m.mu.Unlock()
		return t, nil
	}
	m.mu.Unlock()

	t, err := m.start(ctx, id)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.errs[id] = err.Error()
		return nil, fmt.Errorf("network %s: %w", id, err)
	}
	delete(m.errs, id)
	m.tunnels[id] = t
	return t, nil
}

func (m *Manager) start(ctx context.Context, id string) (*Tunnel, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if m.secrets == nil {
		return nil, errors.New("the vault is not available")
	}
	var keys Keys
	if keys.Private, err = m.secrets(ctx, c.PrivateKey); err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	for i, p := range c.Peers {
		psk := ""
		if p.PresharedKey != "" {
			if psk, err = m.secrets(ctx, p.PresharedKey); err != nil {
				return nil, fmt.Errorf("peer %d preshared key: %w", i+1, err)
			}
		}
		keys.Preshared = append(keys.Preshared, psk)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	t, err := Start(sctx, c, keys, m.log)
	if err != nil {
		return nil, err
	}
	m.log.Info("network up", "network", id, "name", c.Name, "peers", len(c.Peers))
	return t, nil
}

// Dial connects through network id: destinations inside its AllowedIPs go
// through the tunnel, others directly when direct allows them (nil: all).
func (m *Manager) Dial(ctx context.Context, id, network, addr string, direct func(netip.Addr) bool) (net.Conn, error) {
	t, err := m.tunnel(ctx, id)
	if err != nil {
		return nil, err
	}
	return t.Dial(ctx, network, addr, direct)
}

// Routes reports whether ip is inside network id's AllowedIPs.
func (m *Manager) Routes(ctx context.Context, id string, ip netip.Addr) bool {
	c, err := m.Get(ctx, id)
	if err != nil {
		return false
	}
	for _, p := range c.Routes() {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// Status is a network's state.
type Status struct {
	ID      string       `json:"id"`
	Running bool         `json:"running"`
	Error   string       `json:"error,omitempty"`
	Since   *time.Time   `json:"since,omitempty"`
	Peers   []PeerStatus `json:"peers"`
}

// Status reports whether a network's tunnel is up and how its peers are.
// With connect, a stopped tunnel is started first.
func (m *Manager) Status(ctx context.Context, id string, connect bool) (Status, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return Status{}, err
	}
	st := Status{ID: id, Peers: []PeerStatus{}}
	if connect {
		_, _ = m.tunnel(ctx, id)
	}
	m.mu.Lock()
	t := m.tunnels[id]
	st.Error = m.errs[id]
	m.mu.Unlock()
	if t == nil {
		for _, p := range c.Peers {
			st.Peers = append(st.Peers, PeerStatus{PublicKey: p.PublicKey, Name: p.Name, Endpoint: p.Endpoint, HandshakeAgeSeconds: -1})
		}
		return st, nil
	}
	st.Running = true
	since := t.start.UTC()
	st.Since = &since
	ps, err := t.Status()
	if err != nil {
		st.Error = err.Error()
	}
	if ps != nil {
		st.Peers = ps
	}
	return st, nil
}
