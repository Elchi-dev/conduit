// Package inst holds a module's configured instances.
package inst

import (
	"errors"
	"sync"
)

// Set maps instance ids to their state.
type Set[T any] struct {
	mu sync.Mutex
	m  map[string]*T
}

// Put stores an instance, replacing any previous state.
func (s *Set[T]) Put(id string, v *T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*T{}
	}
	s.m[id] = v
}

// Get returns an instance or an error naming what's missing.
func (s *Set[T]) Get(id string) (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := s.m[id]; v != nil {
		return v, nil
	}
	return nil, errors.New("this instance isn't set up")
}

// Delete forgets an instance and returns what was stored.
func (s *Set[T]) Delete(id string) *T {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[id]
	delete(s.m, id)
	return v
}
