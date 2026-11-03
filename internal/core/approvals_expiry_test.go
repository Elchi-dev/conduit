package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStaleApprovalsExpire(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	q := NewApprovals(store, NewBus(), time.Millisecond)
	a, err := q.Request(ctx, Approval{Actor: Actor{ID: "a", Kind: ActorAgent}, Module: "m", Instance: "i", Action: "x", Risk: "write"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if list, _ := q.List(ctx, "pending"); len(list) != 0 {
		t.Fatalf("stale approval still pending: %v", list)
	}
	if err := q.Decide(ctx, a.ID, true, "u"); err == nil {
		t.Fatal("an expired approval must not be approvable")
	}
	got, _ := q.Get(ctx, a.ID)
	if got.Status != "expired" {
		t.Fatalf("status %s", got.Status)
	}
}
