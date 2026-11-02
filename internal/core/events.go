package core

import (
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Envelope is an event as delivered to subscribers, with bus metadata.
type Envelope struct {
	sdk.Event
	At time.Time `json:"at"`
}

// Bus is an in-process publish/subscribe event bus. Subscribers that fall
// behind lose events rather than blocking publishers; the UI resyncs from the
// API on reconnect, and the audit log is the durable record.
type Bus struct {
	mu   sync.RWMutex
	subs map[int]*subscription
	next int
}

type subscription struct {
	prefix string
	ch     chan Envelope
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{subs: map[int]*subscription{}} }

// Subscribe receives events whose type starts with prefix ("" for all).
// Call the returned function to unsubscribe.
func (b *Bus) Subscribe(prefix string, buffer int) (<-chan Envelope, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	b.mu.Lock()
	id := b.next
	b.next++
	s := &subscription{prefix: prefix, ch: make(chan Envelope, buffer)}
	b.subs[id] = s
	b.mu.Unlock()
	return s.ch, func() {
		b.mu.Lock()
		if s, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(s.ch)
		}
		b.mu.Unlock()
	}
}

// Publish delivers e to every matching subscriber without blocking.
func (b *Bus) Publish(e sdk.Event) {
	env := Envelope{Event: e, At: time.Now().UTC()}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if !strings.HasPrefix(e.Type, s.prefix) {
			continue
		}
		select {
		case s.ch <- env:
		default: // slow subscriber: drop
		}
	}
}
