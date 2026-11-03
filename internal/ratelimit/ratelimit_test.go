package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	w := New(3, time.Minute, 2)
	w.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !w.Add("a") {
			t.Fatal("under the limit")
		}
	}
	if w.Allow("a") || w.Add("a") {
		t.Fatal("over the limit")
	}
	if d := w.RetryAfter("a"); d != time.Minute {
		t.Fatalf("retry after %v", d)
	}
	if !w.Add("b") {
		t.Fatal("second key")
	}
	if w.Add("c") {
		t.Fatal("table full: new keys are refused")
	}
	now = now.Add(time.Minute)
	if !w.Add("c") || !w.Allow("a") {
		t.Fatal("expired entries are swept")
	}
	w.Reset("a")
	if !w.Allow("a") {
		t.Fatal("reset")
	}
}

func TestBounded(t *testing.T) {
	w := New(1, time.Hour, 100)
	for i := 0; i < 10000; i++ {
		w.Add(strconv.Itoa(i))
	}
	if len(w.hits) > 100 {
		t.Fatalf("%d keys", len(w.hits))
	}
}
