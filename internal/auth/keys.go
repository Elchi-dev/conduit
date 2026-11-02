package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// KeyKind is the type of API key; it is visible in the key's prefix.
type KeyKind string

const (
	// KeyLive is for production programs.
	KeyLive KeyKind = "live"
	// KeyTest is for development; same powers, easy to spot and revoke in bulk.
	KeyTest KeyKind = "test"
	// KeyAgent is for AI agents. Calls made with it are attributed to an agent,
	// so the agent policy applies, and panic mode revokes these keys.
	KeyAgent KeyKind = "agent"
)

// Key is an API key's metadata. The secret is never stored or returned again
// after creation.
type Key struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Kind         KeyKind    `json:"kind"`
	Prefix       string     `json:"prefix"` // e.g. cdt_live_5kq2m8x4c1v7, safe to display
	OwnerID      string     `json:"ownerId"`
	Scopes       []string   `json:"scopes"`
	IPAllow      []string   `json:"ipAllow"`
	RatePerMin   int        `json:"ratePerMin"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	RevokeReason string     `json:"revokeReason,omitempty"`
	RotatedTo    string     `json:"rotatedTo,omitempty"`
	GraceUntil   *time.Time `json:"graceUntil,omitempty"`
}

// Active reports whether the key can be used at t.
func (k Key) Active(t time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && t.After(*k.ExpiresAt) {
		return false
	}
	if k.GraceUntil != nil && t.After(*k.GraceUntil) {
		return false
	}
	return true
}

// NewKey is the input to CreateKey.
type NewKey struct {
	Name       string     `json:"name"`
	Kind       KeyKind    `json:"kind"`
	Scopes     []string   `json:"scopes"`
	IPAllow    []string   `json:"ipAllow"`
	RatePerMin int        `json:"ratePerMin"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// KeyPrefix starts every API key.
const KeyPrefix = "cdt_"

// CreateKey creates a key and returns it with its full secret value, which
// must be shown to the person exactly once.
func (s *Service) CreateKey(ctx context.Context, ownerID string, in NewKey) (Key, string, error) {
	switch in.Kind {
	case KeyLive, KeyTest, KeyAgent:
	case "":
		in.Kind = KeyLive
	default:
		return Key{}, "", fmt.Errorf("invalid key kind %q", in.Kind)
	}
	if strings.TrimSpace(in.Name) == "" {
		return Key{}, "", errors.New("a key needs a name")
	}
	if len(in.Scopes) == 0 {
		return Key{}, "", errors.New("a key needs at least one scope")
	}
	for _, sc := range in.Scopes {
		if err := ValidateScope(sc); err != nil {
			return Key{}, "", err
		}
	}
	// An agent must never be able to approve its own requests or manage keys
	// and policy, whatever scopes someone asks for.
	if in.Kind == KeyAgent {
		for _, forbidden := range []string{"approvals:*:decide", "policy:*:manage", "keys:*:manage"} {
			if Allows(in.Scopes, forbidden) {
				return Key{}, "", fmt.Errorf("agent keys cannot have a scope that grants %s", forbidden)
			}
		}
	}
	for _, c := range in.IPAllow {
		if _, err := parseAllow(c); err != nil {
			return Key{}, "", fmt.Errorf("invalid IP allow entry %q", c)
		}
	}
	if in.RatePerMin <= 0 {
		in.RatePerMin = 120
	}
	if in.IPAllow == nil {
		in.IPAllow = []string{}
	}
	id := randomToken(8)[:12]
	secret := randomToken(20)
	full := fmt.Sprintf("%s%s_%s_%s", KeyPrefix, in.Kind, id, secret)
	k := Key{ID: "key_" + id, Name: strings.TrimSpace(in.Name), Kind: in.Kind, Prefix: fmt.Sprintf("%s%s_%s", KeyPrefix, in.Kind, id),
		OwnerID: ownerID, Scopes: in.Scopes, IPAllow: in.IPAllow, RatePerMin: in.RatePerMin, CreatedAt: s.now().UTC(), ExpiresAt: in.ExpiresAt}
	scopes, _ := json.Marshal(k.Scopes)
	ips, _ := json.Marshal(k.IPAllow)
	var exp any
	if k.ExpiresAt != nil {
		exp = ts(*k.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (id, name, kind, prefix, secret_hash, owner_id, scopes, ip_allow, rate_per_min, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		k.ID, k.Name, k.Kind, k.Prefix, sha(secret), k.OwnerID, string(scopes), string(ips), k.RatePerMin, ts(k.CreatedAt), exp)
	return k, full, err
}

const keyCols = `id, name, kind, prefix, owner_id, scopes, ip_allow, rate_per_min, created_at, expires_at, last_used_at, revoked_at, revoke_reason, rotated_to, grace_until`

func scanKey(sc interface{ Scan(...any) error }) (Key, error) {
	var k Key
	var scopes, ips, created string
	var exp, used, rev, rot, grace sql.NullString
	if err := sc.Scan(&k.ID, &k.Name, &k.Kind, &k.Prefix, &k.OwnerID, &scopes, &ips, &k.RatePerMin, &created, &exp, &used, &rev, &k.RevokeReason, &rot, &grace); err != nil {
		return k, err
	}
	_ = json.Unmarshal([]byte(scopes), &k.Scopes)
	_ = json.Unmarshal([]byte(ips), &k.IPAllow)
	k.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	k.ExpiresAt, k.LastUsedAt, k.RevokedAt, k.GraceUntil = parseTS(exp), parseTS(used), parseTS(rev), parseTS(grace)
	k.RotatedTo = rot.String
	return k, nil
}

// GetKey returns one key's metadata.
func (s *Service) GetKey(ctx context.Context, id string) (Key, error) {
	return scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id = ?`, id))
}

// ListKeys returns keys owned by ownerID ("" for all), newest first.
func (s *Service) ListKeys(ctx context.Context, ownerID string) ([]Key, error) {
	q := `SELECT ` + keyCols + ` FROM api_keys`
	var args []any
	if ownerID != "" {
		q += ` WHERE owner_id = ?`
		args = append(args, ownerID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// KeyError explains why a presented key was rejected.
type KeyError struct{ Reason string }

func (e *KeyError) Error() string { return "api key rejected: " + e.Reason }

// LookupKey validates a presented key: format, secret, revocation, expiry,
// rotation grace, IP allow-list and rate limit.
func (s *Service) LookupKey(ctx context.Context, full, remoteIP string) (Key, error) {
	rest, ok := strings.CutPrefix(full, KeyPrefix)
	if !ok {
		return Key{}, &KeyError{"malformed key"}
	}
	parts := strings.Split(rest, "_")
	if len(parts) != 3 {
		return Key{}, &KeyError{"malformed key"}
	}
	k, err := scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id = ? AND secret_hash = ?`, "key_"+parts[1], sha(parts[2])))
	if err != nil {
		return Key{}, &KeyError{"unknown key"}
	}
	if string(k.Kind) != parts[0] {
		return Key{}, &KeyError{"unknown key"}
	}
	now := s.now()
	if !k.Active(now) {
		return Key{}, &KeyError{"key revoked or expired"}
	}
	if len(k.IPAllow) > 0 && !ipAllowed(k.IPAllow, remoteIP) {
		return Key{}, &KeyError{"request IP not in the key's allow-list"}
	}
	if !s.limiter.allow(k.ID, k.RatePerMin, now) {
		return Key{}, &KeyError{"rate limit exceeded"}
	}
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, ts(now), k.ID)
	}
	return k, nil
}

// RotateKey issues a replacement with the same settings. The old key keeps
// working until the grace period ends, so deployments can switch over.
func (s *Service) RotateKey(ctx context.Context, id string, grace time.Duration) (Key, string, error) {
	old, err := s.GetKey(ctx, id)
	if err != nil {
		return Key{}, "", err
	}
	if !old.Active(s.now()) {
		return Key{}, "", errors.New("only active keys can be rotated")
	}
	nk, full, err := s.CreateKey(ctx, old.OwnerID, NewKey{Name: old.Name, Kind: old.Kind, Scopes: old.Scopes, IPAllow: old.IPAllow, RatePerMin: old.RatePerMin, ExpiresAt: old.ExpiresAt})
	if err != nil {
		return Key{}, "", err
	}
	until := s.now().Add(grace).UTC()
	_, err = s.db.ExecContext(ctx, `UPDATE api_keys SET rotated_to = ?, grace_until = ? WHERE id = ?`, nk.ID, ts(until), id)
	return nk, full, err
}

// RevokeKey disables a key immediately.
func (s *Service) RevokeKey(ctx context.Context, id, reason string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`, ts(s.now()), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("key not found or already revoked")
	}
	return nil
}

// RevokeKind revokes every active key of a kind (panic mode revokes agent keys).
func (s *Service) RevokeKind(ctx context.Context, kind KeyKind, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ?, revoke_reason = ? WHERE kind = ? AND revoked_at IS NULL`, ts(s.now()), reason, kind)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Usage is one logged request made with a key.
type Usage struct {
	At     time.Time `json:"at"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	IP     string    `json:"ip"`
}

// RecordUsage logs a request made with a key.
func (s *Service) RecordUsage(ctx context.Context, keyID string, u Usage) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO api_key_usage (key_id, at, method, path, status, ip) VALUES (?,?,?,?,?,?)`, keyID, ts(u.At), u.Method, u.Path, u.Status, u.IP)
}

// KeyUsage returns a key's most recent requests.
func (s *Service) KeyUsage(ctx context.Context, keyID string, limit int) ([]Usage, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT at, method, path, status, ip FROM api_key_usage WHERE key_id = ? ORDER BY at DESC LIMIT ?`, keyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		var at string
		if err := rows.Scan(&at, &u.Method, &u.Path, &u.Status, &u.IP); err != nil {
			return nil, err
		}
		u.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, u)
	}
	return out, rows.Err()
}

// PruneUsage deletes usage older than 30 days.
func (s *Service) PruneUsage(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_key_usage WHERE at < ?`, ts(s.now().Add(-30*24*time.Hour)))
	return err
}

func parseAllow(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "/") {
		return netip.ParsePrefix(entry)
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func ipAllowed(list []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, e := range list {
		if p, err := parseAllow(e); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// limiter is a per-key token bucket refilled continuously.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}} }

func (l *limiter) allow(key string, perMin int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	capacity := float64(perMin)
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * capacity
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
