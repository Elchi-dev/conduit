// Package fakehost is an sdk.Host for module tests.
package fakehost

import (
	"context"
	"fmt"
	"sync"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Host resolves secrets from a map and records events.
type Host struct {
	Secrets map[string]string
	mu      sync.Mutex
	events  []sdk.Event
}

// New returns a host with the given secrets ("secret://name" → value).
func New(secrets map[string]string) *Host { return &Host{Secrets: secrets} }

// Secret implements sdk.Host.
func (h *Host) Secret(_ context.Context, ref string) (string, error) {
	if v, ok := h.Secrets[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret %s", ref)
}

// Publish implements sdk.Host.
func (h *Host) Publish(_ context.Context, e sdk.Event) {
	h.mu.Lock()
	h.events = append(h.events, e)
	h.mu.Unlock()
}

// Log implements sdk.Host.
func (h *Host) Log(string, string, ...any) {}

// Events returns the events published so far.
func (h *Host) Events() []sdk.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sdk.Event(nil), h.events...)
}
