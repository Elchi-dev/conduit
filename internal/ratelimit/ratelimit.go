// Package ratelimit counts events per key in a sliding window. It is used
// for failed sign-ins (per address and per account) and webhook calls.
//
// The number of keys is capped so a flood of distinct keys can't grow memory
// without bound: when the table is full, expired keys are swept, and if it
// is still full, new keys are refused until room frees up. Refusing is the
// safe side for every current use.
package ratelimit

import (
	"sync"
	"time"
)

// Window allows Limit events per key in any Per-long window.
type Window struct {
	Limit   int
	Per     time.Duration
	MaxKeys int

	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

// New returns a window limiter.
func New(limit int, per time.Duration, maxKeys int) *Window {
	return &Window{Limit: limit, Per: per, MaxKeys: maxKeys, hits: map[string][]time.Time{}, now: time.Now}
}

func (w *Window) recent(key string, now time.Time) []time.Time {
	old := w.hits[key]
	keep := old[:0]
	for _, t := range old {
		if now.Sub(t) < w.Per {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(w.hits, key)
		return nil
	}
	w.hits[key] = keep
	return keep
}

func (w *Window) sweep(now time.Time) {
	for k := range w.hits {
		w.recent(k, now)
	}
}

// Allow reports whether key is under its limit, without recording anything.
func (w *Window) Allow(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if len(w.recent(key, now)) >= w.Limit {
		return false
	}
	if _, ok := w.hits[key]; !ok && len(w.hits) >= w.MaxKeys {
		w.sweep(now)
		return len(w.hits) < w.MaxKeys
	}
	return true
}

// Add records one event for key. It reports false (and records nothing)
// when key is over its limit or the table is full.
func (w *Window) Add(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	r := w.recent(key, now)
	if len(r) >= w.Limit {
		return false
	}
	if r == nil && len(w.hits) >= w.MaxKeys {
		w.sweep(now)
		if len(w.hits) >= w.MaxKeys {
			return false
		}
	}
	w.hits[key] = append(r, now)
	return true
}

// Take is Allow then Add in one step: it records the event if allowed.
func (w *Window) Take(key string) bool { return w.Add(key) }

// Reset forgets key (after a successful sign-in, say).
func (w *Window) Reset(key string) {
	w.mu.Lock()
	delete(w.hits, key)
	w.mu.Unlock()
}

// RetryAfter is how long until key has room again (0 when it has now).
func (w *Window) RetryAfter(key string) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	r := w.recent(key, now)
	if len(r) < w.Limit {
		return 0
	}
	return w.Per - now.Sub(r[0])
}
