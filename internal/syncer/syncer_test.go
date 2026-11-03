package syncer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

// mapCollection is an in-memory collection.
type mapCollection struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *mapCollection) Name() string { return "things" }
func (c *mapCollection) Export(context.Context) (map[string]json.RawMessage, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]json.RawMessage{}
	for k, v := range c.m {
		out[k], _ = json.Marshal(v)
	}
	return out, true, nil
}
func (c *mapCollection) Apply(_ context.Context, id string, data json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if data == nil {
		delete(c.m, id)
		return nil
	}
	var v string
	_ = json.Unmarshal(data, &v)
	c.m[id] = v
	return nil
}
func (c *mapCollection) get() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{}
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

type node struct {
	svc  *Service
	data *mapCollection
	srv  *httptest.Server
	t    *time.Time
}

func newNode(t *testing.T, start map[string]string) *node {
	ctx := context.Background()
	st, err := core.OpenStore(ctx, t.TempDir()+"/n.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	n := &node{data: &mapCollection{m: start}}
	clock := time.Now().UTC()
	n.t = &clock
	n.svc = &Service{DB: st.DB, Collections: map[string]Collection{"things": n.data},
		Peer: func(base string) Transport { return &PeerTransport{Base: base} }, now: func() time.Time { return *n.t }}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Collection, Doc string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		out, err := n.svc.Exchange(r.Context(), req.Collection, req.Doc)
		if err != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"doc": out})
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *node) tick(d time.Duration) { *n.t = n.t.Add(d) }

func TestPeerSync(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, map[string]string{"x": "1", "shared": "from a", "preset": "ask-destructive"})
	b := newNode(t, map[string]string{"y": "2", "shared": "from b", "preset": "ask-writes"})

	code, err := a.svc.Create(ctx, []string{"things"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.svc.Join(ctx, "nope", nil); err == nil {
		t.Fatal("bad code accepted")
	}
	if err := b.svc.Join(ctx, code, []string{"things"}); err != nil {
		t.Fatal(err)
	}
	_ = b.svc.SetPeers(ctx, []string{a.srv.URL})

	// First round: union of both, conflicts resolved the same way on both.
	res := b.svc.Run(ctx)
	if len(res) != 1 || !res[0].OK {
		t.Fatalf("%+v", res)
	}
	ga, gb := a.data.get(), b.data.get()
	if ga["x"] != "1" || ga["y"] != "2" || gb["x"] != "1" || gb["y"] != "2" || ga["shared"] != gb["shared"] || gb["preset"] != "ask-destructive" {
		t.Fatalf("a=%v b=%v", ga, gb)
	}

	// A change on A reaches B; a later change on B wins over an earlier one on A.
	a.tick(time.Minute)
	b.tick(time.Minute)
	a.data.m["x"] = "changed on a"
	b.tick(time.Second)
	b.data.m["y"] = "changed on b"
	delete(a.data.m, "shared")
	b.svc.Run(ctx)
	ga, gb = a.data.get(), b.data.get()
	if gb["x"] != "changed on a" || ga["y"] != "changed on b" {
		t.Fatalf("a=%v b=%v", ga, gb)
	}
	if _, ok := gb["shared"]; ok {
		t.Fatal("deletion didn't reach b")
	}
	// The deletion sticks: a stale copy doesn't bring it back.
	b.svc.Run(ctx)
	if _, ok := a.data.get()["shared"]; ok {
		t.Fatal("deleted item came back")
	}

	// Another group can't read or write.
	c := newNode(t, map[string]string{"z": "3"})
	_, _ = c.svc.Create(ctx, []string{"things"})
	_ = c.svc.SetPeers(ctx, []string{a.srv.URL})
	if r := c.svc.Run(ctx); len(r) != 1 || r[0].OK {
		t.Fatalf("other group synced: %+v", r)
	}
	if _, ok := a.data.get()["z"]; ok {
		t.Fatal("other group's data applied")
	}
}

func TestMergeDeterministic(t *testing.T) {
	t0 := time.Unix(100, 0)
	a := Doc{Collection: "c", Items: map[string]Item{"k": {Updated: t0, Data: json.RawMessage(`"a"`)}}}
	b := Doc{Collection: "c", Items: map[string]Item{"k": {Updated: t0, Data: json.RawMessage(`"b"`)}}}
	if string(Merge(a, b).Items["k"].Data) != string(Merge(b, a).Items["k"].Data) {
		t.Fatal("tie broken differently depending on order")
	}
	del := Doc{Collection: "c", Items: map[string]Item{"k": {Updated: t0, Deleted: true}}}
	if !Merge(a, del).Items["k"].Deleted || !Merge(del, a).Items["k"].Deleted {
		t.Fatal("a deletion at the same moment should win")
	}
}

func TestSealBindsCollection(t *testing.T) {
	key := make([]byte, 32)
	s, _ := Seal(key, Doc{Collection: "vault", Items: map[string]Item{}})
	if _, err := Open(key, "policy", s); err == nil {
		t.Fatal("document opened as another collection")
	}
	other := make([]byte, 32)
	other[0] = 1
	if _, err := Open(other, "vault", s); err == nil {
		t.Fatal("document opened with another key")
	}
}

// A recorded request replayed later is refused, and an old copy can't bring
// back something that was deleted, however long ago.
func TestReplayAndResurrection(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, map[string]string{"rule": "allow everything"})
	b := newNode(t, map[string]string{})
	code, _ := a.svc.Create(ctx, []string{"things"})
	_ = b.svc.Join(ctx, code, []string{"things"})
	_ = b.svc.SetPeers(ctx, []string{a.srv.URL})
	b.svc.Run(ctx)
	if b.data.get()["rule"] != "allow everything" {
		t.Fatal("setup")
	}
	// Record B's document while it still has the rule.
	key := b.svc.Key(ctx)
	old, _ := Seal(key, b.svc.known(ctx, "things"))

	// A deletes the rule; it reaches B.
	a.tick(time.Minute)
	b.tick(time.Minute)
	delete(a.data.m, "rule")
	b.svc.Run(ctx)
	if _, ok := b.data.get()["rule"]; ok {
		t.Fatal("deletion didn't sync")
	}

	// Long after, the recorded document is replayed at A.
	a.tick(200 * 24 * time.Hour)
	if _, err := a.svc.Exchange(ctx, "things", old); err == nil {
		t.Fatal("a replayed document was accepted")
	}
	// Even a fresh document with the stale item can't bring it back.
	stale := b.svc.known(ctx, "things")
	stale.Items["rule"] = Item{Updated: stale.Items["rule"].Updated.Add(-time.Hour), Data: json.RawMessage(`"allow everything"`)}
	sealed, _ := Seal(key, stale)
	a.t = func() *time.Time { n := time.Now().UTC(); return &n }()
	if _, err := a.svc.Exchange(ctx, "things", sealed); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.data.get()["rule"]; ok {
		t.Fatal("deleted item came back")
	}
}
