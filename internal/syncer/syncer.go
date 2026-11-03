// Package syncer keeps chosen data the same across a person's daemons: the
// vault, the agent rules and, if asked, automations.
//
// Group. Daemons that sync share a 256-bit group key. One daemon creates it
// and shows a join code (the key itself, so it is shown once and treated
// like a password); the others join with that code. The key never leaves the
// daemons: what travels is a document per collection encrypted with
// XChaCha20-Poly1305 under the key, so a hub or a network in between sees only
// ciphertext and its size.
//
// Merge. Each collection is a map of items with an update time and a deleted
// flag. Every round a daemon compares its data with what it last agreed on to
// find its own changes (new, changed and deleted items get the current
// time), merges with the other side item by item (the later change wins; on
// a tie, the larger content hash, so every daemon picks the same winner), and
// applies what it lost locally. Deletions are kept as tombstones for 90 days
// so they win over stale copies.
//
// Transports. Through the hub the daemon is linked to (one encrypted blob per
// collection, written with the hub's version check, so concurrent writers
// merge and retry), and directly with peers on the local network
// (POST /sync/exchange: send your encrypted document, get the merged one
// back). Either is enough; both may run.
package syncer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Item is one entry of a collection.
type Item struct {
	Updated time.Time       `json:"u"`
	Deleted bool            `json:"d,omitempty"`
	Data    json.RawMessage `json:"x,omitempty"`
}

// Collection is something that syncs: it lists its items as id → JSON and
// applies items that changed elsewhere.
type Collection interface {
	Name() string
	// Export returns the current local items. ok=false means the collection
	// can't take part right now (a locked vault) and the round skips it.
	Export(ctx context.Context) (items map[string]json.RawMessage, ok bool, err error)
	// Apply writes an item that changed elsewhere; data nil means delete.
	Apply(ctx context.Context, id string, data json.RawMessage) error
}

// Doc is a collection's synced state.
type Doc struct {
	V          int             `json:"v"`
	Collection string          `json:"c"`
	Items      map[string]Item `json:"items"`
	// Made is when the document was sealed. The peer endpoint refuses
	// documents older than MaxDocAge, so a recorded request can't be
	// replayed later.
	Made time.Time `json:"made,omitempty"`
}

// ErrRefused answers a peer request that isn't from this daemon's group.
var ErrRefused = errors.New("refused")

// MaxDocAge is how old a document sent to the peer endpoint may be. Peers
// make a fresh one for every exchange, so an older one is a replay.
const MaxDocAge = 15 * time.Minute

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// Merge combines two documents of the same collection.
func Merge(a, b Doc) Doc {
	out := Doc{V: 1, Collection: a.Collection, Items: map[string]Item{}}
	if out.Collection == "" {
		out.Collection = b.Collection
	}
	for id, it := range a.Items {
		out.Items[id] = it
	}
	for id, it := range b.Items {
		cur, ok := out.Items[id]
		if !ok || wins(it, cur) {
			out.Items[id] = it
		}
	}
	return out
}

func wins(x, y Item) bool {
	if !x.Updated.Equal(y.Updated) {
		return x.Updated.After(y.Updated)
	}
	if x.Deleted != y.Deleted {
		return x.Deleted // a deletion at the same moment wins
	}
	return hashOf(x.Data) > hashOf(y.Data)
}

// --- encryption -----------------------------------------------------------

// Seal compresses and encrypts a document under the group key. The
// collection name is bound as associated data.
func Seal(key []byte, d Doc) (string, error) {
	d.Made = time.Now().UTC()
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, z.Bytes(), []byte("conduit-sync-v1 "+d.Collection))
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a document of the named collection.
func Open(key []byte, collection, sealed string) (Doc, error) {
	var d Doc
	b, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return d, errors.New("not a sync document")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return d, err
	}
	if len(b) < aead.NonceSize() {
		return d, errors.New("not a sync document")
	}
	z, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], []byte("conduit-sync-v1 "+collection))
	if err != nil {
		return d, errors.New("the sync document didn't decrypt: it's from another sync group, or was changed")
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		return d, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	if d.Collection != collection {
		return d, errors.New("sync document for a different collection")
	}
	if d.Items == nil {
		d.Items = map[string]Item{}
	}
	return d, nil
}

// --- service ---------------------------------------------------------------

// Transport moves a collection's sealed document somewhere and back.
type Transport interface {
	Name() string
	// Exchange gives the remote side our sealed document and returns what to
	// merge in (sealed), or "" when the remote side has nothing yet.
	Exchange(ctx context.Context, key []byte, mine Doc, merge func(Doc) Doc) (Doc, error)
}

// Status is what the settings page shows.
type Status struct {
	Enabled     bool             `json:"enabled"`
	GroupID     string           `json:"groupId,omitempty"`
	Collections []string         `json:"collections"`
	Peers       []string         `json:"peers"`
	ViaHub      bool             `json:"viaHub"`
	LastRun     *time.Time       `json:"lastRun,omitempty"`
	Results     []CollectionRun  `json:"results"`
	Available   []CollectionInfo `json:"available"`
}

// CollectionInfo describes a collection that can be synced.
type CollectionInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CollectionRun is the outcome of the last round for one collection.
type CollectionRun struct {
	Collection string `json:"collection"`
	Transport  string `json:"transport"`
	OK         bool   `json:"ok"`
	Skipped    string `json:"skipped,omitempty"`
	Error      string `json:"error,omitempty"`
	Sent       int    `json:"sent"`     // local changes sent
	Received   int    `json:"received"` // changes applied here
}

// Service runs sync rounds.
type Service struct {
	DB          *sql.DB
	Collections map[string]Collection
	Info        []CollectionInfo
	// Hub returns the hub transport, or nil when this daemon isn't linked.
	Hub func() Transport
	// Peer makes a transport for a peer daemon's base URL.
	Peer func(base string) Transport

	mu      sync.Mutex // one round at a time
	stateMu sync.Mutex
	lastRun *time.Time
	results []CollectionRun
	now     func() time.Time
}

const (
	setKey         = "sync.key"
	setCollections = "sync.collections"
	setPeers       = "sync.peers"
	// setJoining is set from joining a group until each collection has
	// agreed once; until then local data defers to the group's.
	setJoining = "sync.joining"
)

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

func (s *Service) setting(ctx context.Context, k string) string {
	var v string
	_ = s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, k).Scan(&v)
	return v
}

func (s *Service) put(ctx context.Context, k, v string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v)
	return err
}

// Key returns the group key, or nil when sync isn't set up.
func (s *Service) Key(ctx context.Context) []byte {
	k, err := base64.RawURLEncoding.DecodeString(s.setting(ctx, setKey))
	if err != nil || len(k) != 32 {
		return nil
	}
	return k
}

// GroupID is a short public name for the group (not secret).
func GroupID(key []byte) string {
	h := sha256.Sum256(append([]byte("conduit-sync-group "), key...))
	return hex.EncodeToString(h[:6])
}

// JoinPrefix starts every join code.
const JoinPrefix = "conduit-sync-"

// Create makes a new group key and returns its join code.
func (s *Service) Create(ctx context.Context, collections []string) (string, error) {
	if s.Key(ctx) != nil {
		return "", errors.New("this daemon already syncs; leave the group first")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	if err := s.put(ctx, setKey, base64.RawURLEncoding.EncodeToString(k)); err != nil {
		return "", err
	}
	if err := s.SetCollections(ctx, collections); err != nil {
		return "", err
	}
	return JoinPrefix + base64.RawURLEncoding.EncodeToString(k), nil
}

// JoinCode shows the current group's code again (for adding another daemon).
func (s *Service) JoinCode(ctx context.Context) (string, error) {
	k := s.Key(ctx)
	if k == nil {
		return "", errors.New("sync isn't set up")
	}
	return JoinPrefix + base64.RawURLEncoding.EncodeToString(k), nil
}

// Join enters a group with a code from another daemon.
func (s *Service) Join(ctx context.Context, code string, collections []string) error {
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(code), JoinPrefix))
	if err != nil || len(k) != 32 || !strings.HasPrefix(strings.TrimSpace(code), JoinPrefix) {
		return errors.New("that isn't a sync join code; it starts with " + JoinPrefix)
	}
	if err := s.put(ctx, setKey, base64.RawURLEncoding.EncodeToString(k)); err != nil {
		return err
	}
	// A new member starts with no common history, so nothing local counts as
	// deleted on the first round, and its existing data defers to the group's.
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sync_state`)
	if err := s.put(ctx, setJoining, "1"); err != nil {
		return err
	}
	return s.SetCollections(ctx, collections)
}

// Leave forgets the group key and the merge history. Local data stays.
func (s *Service) Leave(ctx context.Context) error {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sync_state`)
	_, err := s.DB.ExecContext(ctx, `DELETE FROM settings WHERE key IN (?, ?, ?, ?)`, setKey, setCollections, setPeers, setJoining)
	return err
}

// SetCollections chooses what syncs.
func (s *Service) SetCollections(ctx context.Context, names []string) error {
	for _, n := range names {
		if _, ok := s.Collections[n]; !ok {
			return fmt.Errorf("no collection %q", n)
		}
	}
	if names == nil {
		names = []string{}
	}
	b, _ := json.Marshal(names)
	return s.put(ctx, setCollections, string(b))
}

func (s *Service) collections(ctx context.Context) []string {
	var out []string
	_ = json.Unmarshal([]byte(s.setting(ctx, setCollections)), &out)
	return out
}

// SetPeers sets the other daemons on the network to sync with directly.
func (s *Service) SetPeers(ctx context.Context, peers []string) error {
	clean := []string{}
	for _, p := range peers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
			return fmt.Errorf("%q: a peer is the other daemon's address, like http://192.168.1.20:7600", p)
		}
		clean = append(clean, p)
	}
	b, _ := json.Marshal(clean)
	return s.put(ctx, setPeers, string(b))
}

func (s *Service) peers(ctx context.Context) []string {
	out := []string{}
	_ = json.Unmarshal([]byte(s.setting(ctx, setPeers)), &out)
	return out
}

// Status reports the configuration and the last round.
func (s *Service) Status(ctx context.Context) Status {
	k := s.Key(ctx)
	st := Status{Enabled: k != nil, Collections: s.collections(ctx), Peers: s.peers(ctx), Available: s.Info, Results: []CollectionRun{}}
	if st.Collections == nil {
		st.Collections = []string{}
	}
	if k != nil {
		st.GroupID = GroupID(k)
		st.ViaHub = s.Hub != nil && s.Hub() != nil
	}
	s.stateMu.Lock()
	st.LastRun = s.lastRun
	st.Results = append(st.Results, s.results...)
	s.stateMu.Unlock()
	return st
}

// --- local state ---------------------------------------------------------------

// known is the last agreed document (what every side had after the last
// successful round), stored per collection.
func (s *Service) known(ctx context.Context, c string) Doc {
	d := Doc{V: 1, Collection: c, Items: map[string]Item{}}
	var raw string
	if s.DB.QueryRowContext(ctx, `SELECT doc FROM sync_state WHERE collection = ?`, c).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &d)
		if d.Items == nil {
			d.Items = map[string]Item{}
		}
	}
	return d
}

func (s *Service) saveKnown(ctx context.Context, d Doc) error {
	b, _ := json.Marshal(d)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sync_state(collection, doc) VALUES (?, ?) ON CONFLICT(collection) DO UPDATE SET doc = excluded.doc`, d.Collection, string(b))
	return err
}

// local turns the current data into a document, stamping what changed since
// the last agreed state with now.
func local(known Doc, current map[string]json.RawMessage, now time.Time) (Doc, int) {
	d := Doc{V: 1, Collection: known.Collection, Items: map[string]Item{}}
	changed := 0
	for id, data := range current {
		k, ok := known.Items[id]
		if ok && !k.Deleted && bytes.Equal(canon(k.Data), canon(data)) {
			d.Items[id] = k
			continue
		}
		d.Items[id] = Item{Updated: now, Data: data}
		changed++
	}
	for id, k := range known.Items {
		if _, ok := current[id]; ok {
			continue
		}
		if k.Deleted {
			// Deletions are remembered for good (they are small): forgetting
			// one would let an old copy of the item come back.
			d.Items[id] = k
			continue
		}
		d.Items[id] = Item{Updated: now, Deleted: true}
		changed++
	}
	return d, changed
}

func canon(b []byte) []byte {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return b
	}
	out, _ := json.Marshal(v)
	return out
}

// stamp is the time given to local changes. A daemon that joined a group
// stamps its data with the zero time until it has agreed with the group once
// per collection, so what the group already has wins over the newcomer's
// defaults; items only the newcomer has still join. The daemon that created
// the group stamps with the current time from the start.
func (s *Service) stamp(ctx context.Context, known Doc) time.Time {
	if len(known.Items) == 0 && s.setting(ctx, setJoining) == "1" {
		return time.Unix(0, 0).UTC()
	}
	return s.clock()
}

// Run does one round for every chosen collection over every transport.
func (s *Service) Run(ctx context.Context) []CollectionRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.Key(ctx)
	if key == nil {
		return nil
	}
	var ts []Transport
	if s.Hub != nil {
		if h := s.Hub(); h != nil {
			ts = append(ts, h)
		}
	}
	if s.Peer != nil {
		for _, p := range s.peers(ctx) {
			ts = append(ts, s.Peer(p))
		}
	}
	var results []CollectionRun
	for _, name := range s.collections(ctx) {
		c := s.Collections[name]
		if c == nil {
			continue
		}
		if len(ts) == 0 {
			results = append(results, CollectionRun{Collection: name, Skipped: "no hub link and no peers"})
			continue
		}
		for _, t := range ts {
			results = append(results, s.round(ctx, key, c, t))
		}
	}
	if s.setting(ctx, setJoining) == "1" {
		agreed := 0
		names := s.collections(ctx)
		for _, n := range names {
			if len(s.known(ctx, n).Items) > 0 {
				agreed++
			}
		}
		if agreed == len(names) {
			_, _ = s.DB.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, setJoining)
		}
	}
	now := s.clock()
	s.stateMu.Lock()
	s.lastRun = &now
	s.results = results
	s.stateMu.Unlock()
	return results
}

func (s *Service) round(ctx context.Context, key []byte, c Collection, t Transport) CollectionRun {
	r := CollectionRun{Collection: c.Name(), Transport: t.Name()}
	cur, ok, err := c.Export(ctx)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if !ok {
		r.Skipped = "not available right now (is the vault locked?)"
		return r
	}
	known := s.known(ctx, c.Name())
	mine, sent := local(known, cur, s.stamp(ctx, known))
	r.Sent = sent
	merged, err := t.Exchange(ctx, key, mine, func(theirs Doc) Doc { return Merge(mine, theirs) })
	if err != nil {
		r.Error = err.Error()
		return r
	}
	n, err := s.apply(ctx, c, mine, merged)
	r.Received = n
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if err := s.saveKnown(ctx, merged); err != nil {
		r.Error = err.Error()
		return r
	}
	r.OK = true
	return r
}

// apply writes the items where the merged document differs from ours.
func (s *Service) apply(ctx context.Context, c Collection, mine, merged Doc) (int, error) {
	ids := make([]string, 0, len(merged.Items))
	for id := range merged.Items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n := 0
	for _, id := range ids {
		m := merged.Items[id]
		x, had := mine.Items[id]
		if had && x.Updated.Equal(m.Updated) && x.Deleted == m.Deleted && bytes.Equal(canon(x.Data), canon(m.Data)) {
			continue
		}
		if m.Deleted {
			if !had || x.Deleted {
				continue // never had it
			}
			if err := c.Apply(ctx, id, nil); err != nil {
				return n, fmt.Errorf("%s: %w", id, err)
			}
		} else if err := c.Apply(ctx, id, m.Data); err != nil {
			return n, fmt.Errorf("%s: %w", id, err)
		}
		n++
	}
	return n, nil
}

// Exchange answers a peer: merge its document with ours, apply, and return
// the merged document sealed. Used by POST /sync/exchange.
func (s *Service) Exchange(ctx context.Context, collection, sealed string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.Key(ctx)
	if key == nil {
		return "", ErrRefused
	}
	// Nothing about this daemon is told to a caller whose document doesn't
	// decrypt under the group key.
	theirs, err := Open(key, collection, sealed)
	if err != nil {
		return "", ErrRefused
	}
	chosen := false
	for _, n := range s.collections(ctx) {
		chosen = chosen || n == collection
	}
	c := s.Collections[collection]
	if c == nil || !chosen {
		return "", fmt.Errorf("this daemon doesn't sync %q", collection)
	}
	if age := s.clock().Sub(theirs.Made); age > MaxDocAge || age < -MaxDocAge {
		return "", errors.New("the sync document is too old (or the clocks are far apart)")
	}
	cur, ok, err := c.Export(ctx)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("this side can't sync it right now (is the vault locked?)")
	}
	known := s.known(ctx, collection)
	mine, _ := local(known, cur, s.stamp(ctx, known))
	merged := Merge(mine, theirs)
	if _, err := s.apply(ctx, c, mine, merged); err != nil {
		return "", err
	}
	if err := s.saveKnown(ctx, merged); err != nil {
		return "", err
	}
	return Seal(key, merged)
}
