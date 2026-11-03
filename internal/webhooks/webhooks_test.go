package webhooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestSignVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"type":"action.ok"}`)
	h := Sign("whsec_x", now, body)
	if err := Verify("whsec_x", h, body, now.Add(time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if Verify("whsec_y", h, body, now, 5*time.Minute) == nil {
		t.Fatal("wrong secret accepted")
	}
	if Verify("whsec_x", h, []byte(`{}`), now, 5*time.Minute) == nil {
		t.Fatal("changed body accepted")
	}
	if Verify("whsec_x", h, body, now.Add(time.Hour), 5*time.Minute) == nil {
		t.Fatal("old signature accepted")
	}
}

func TestDelivery(t *testing.T) {
	old := Retries
	Retries = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { Retries = old }()

	var mu sync.Mutex
	var got []map[string]any
	calls := 0
	var sec string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			w.WriteHeader(503) // first try fails, the retry succeeds
			return
		}
		if err := Verify(sec, r.Header.Get("X-Conduit-Signature"), b, time.Now(), 5*time.Minute); err != nil {
			w.WriteHeader(401)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
	}))
	defer srv.Close()

	ctx := context.Background()
	st, err := core.OpenStore(ctx, t.TempDir()+"/d.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bus := core.NewBus()
	s := New(st.DB, bus, nil)
	if _, err := s.Create(ctx, "x", "ftp://nope", nil); err == nil {
		t.Fatal("bad URL accepted")
	}
	w, err := s.Create(ctx, "CI", srv.URL, []string{"action."})
	if err != nil {
		t.Fatal(err)
	}
	sec = w.Secret
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.Run(rctx)
	time.Sleep(20 * time.Millisecond)
	bus.Publish(sdk.Event{Type: "approval.requested", Module: "core"}) // filtered out
	bus.Publish(sdk.Event{Type: "action.ok", Module: "docker", Data: json.RawMessage(`{"seq":4}`)})

	for i := 0; i < 200; i++ {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0]["type"] != "action.ok" || got[0]["module"] != "docker" {
		t.Fatalf("got %v (calls %d)", got, calls)
	}
	// The record of the second attempt is written just after the receiver
	// answers.
	var ds []Delivery
	for i := 0; i < 100; i++ {
		ds, _ = s.Deliveries(ctx, w.ID, 10)
		if len(ds) == 1 && ds[0].OK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ds) != 1 || !ds[0].OK || ds[0].Attempts != 2 {
		t.Fatalf("deliveries %+v", ds)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 || list[0].Secret != "" {
		t.Fatal("list must not include secrets")
	}
}

func TestSwitchesOffAfterFailures(t *testing.T) {
	old := Retries
	Retries = nil
	defer func() { Retries = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	ctx := context.Background()
	st, _ := core.OpenStore(ctx, t.TempDir()+"/d.db")
	defer st.Close()
	s := New(st.DB, core.NewBus(), nil)
	w, _ := s.Create(ctx, "", srv.URL, nil)
	tg := target{id: w.ID, url: srv.URL, secret: w.Secret}
	for i := 0; i < DisableAfter; i++ {
		s.deliver(ctx, tg, core.Envelope{Event: sdk.Event{Type: "x"}})
	}
	got, _ := s.Get(ctx, w.ID)
	if got.Enabled {
		t.Fatalf("still enabled after %d failures", got.Failures)
	}
}
