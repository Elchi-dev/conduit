package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type events struct {
	mu   sync.Mutex
	seen []string
}

func (e *events) Secret(context.Context, string) (string, error) { return "", nil }
func (e *events) Publish(_ context.Context, ev sdk.Event) {
	e.mu.Lock()
	e.seen = append(e.seen, ev.Type)
	e.mu.Unlock()
}
func (e *events) Log(string, string, ...any) {}

func TestChecksAndTransitions(t *testing.T) {
	var mu sync.Mutex
	healthy := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !healthy {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte("<h1>Add to cart</h1>"))
	}))
	defer srv.Close()

	m := New()
	ev := &events{}
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{Checks: []Check{{Name: "Shop", URL: srv.URL, Contains: "Add to cart"}}, IntervalSeconds: 3600})
	if err := m.Configure(ctx, ev, "w", cfg); err != nil {
		t.Fatal(err)
	}
	defer m.Close("w")
	r, _ := m.Invoke(ctx, sdk.Call{Instance: "w", Action: "check_now"})
	var res []Result
	_ = json.Unmarshal(r.Output, &res)
	if len(res) != 1 || !res[0].Up {
		t.Fatalf("first check: %s", r.Output)
	}
	mu.Lock()
	healthy = false
	mu.Unlock()
	_, _ = m.Invoke(ctx, sdk.Call{Instance: "w", Action: "check_now"})
	if h := m.Health(ctx, "w"); h.Status != "down" || h.Message != "Down: Shop" {
		t.Fatalf("health = %+v", h)
	}
	mu.Lock()
	healthy = true
	mu.Unlock()
	_, _ = m.Invoke(ctx, sdk.Call{Instance: "w", Action: "check_now"})
	ev.mu.Lock()
	defer ev.mu.Unlock()
	found := map[string]bool{}
	for _, s := range ev.seen {
		found[s] = true
	}
	if !found["web.down"] || !found["web.up"] {
		t.Fatalf("events = %v", ev.seen)
	}
	if err := m.Configure(ctx, ev, "bad", json.RawMessage(`{"checks":[{"url":"ftp://x"}]}`)); err == nil {
		t.Fatal("ftp accepted")
	}
}
