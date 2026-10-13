package solver

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Memory is an in-memory solver for tests. It serves the HTTP-01 key authorizations it holds (it is an
// http.Handler for HTTPPathPrefix + token) and records every call. Hooks run after the built-in work
// (for example to copy a DNS-01 value into a fake DNS table) and PresentErr makes Present fail.
type Memory struct {
	// AfterPresent and AfterCleanUp run after the built-in work; their error is returned.
	AfterPresent func(context.Context, Challenge) error
	AfterCleanUp func(context.Context, Challenge) error
	// PresentErr, when set, is returned by Present before anything is published.
	PresentErr error

	types []string

	mu        sync.Mutex
	tokens    map[string]string
	presented []Challenge
	cleaned   []Challenge
}

// NewMemory makes a solver for the given types (default: DNS-01 then HTTP-01).
func NewMemory(types ...string) *Memory {
	if len(types) == 0 {
		types = []string{DNS01, HTTP01}
	}
	return &Memory{types: slices.Clone(types), tokens: map[string]string{}}
}

// Types implements Solver.
func (m *Memory) Types() []string { return slices.Clone(m.types) }

// Present implements Solver.
func (m *Memory) Present(ctx context.Context, ch Challenge) error {
	m.mu.Lock()
	m.presented = append(m.presented, ch)
	if m.PresentErr != nil {
		m.mu.Unlock()
		return m.PresentErr
	}
	if ch.Type == HTTP01 {
		m.tokens[ch.Token] = ch.KeyAuth
	}
	m.mu.Unlock()
	if m.AfterPresent != nil {
		return m.AfterPresent(ctx, ch)
	}
	return nil
}

// CleanUp implements Solver.
func (m *Memory) CleanUp(ctx context.Context, ch Challenge) error {
	m.mu.Lock()
	m.cleaned = append(m.cleaned, ch)
	delete(m.tokens, ch.Token)
	m.mu.Unlock()
	if m.AfterCleanUp != nil {
		return m.AfterCleanUp(ctx, ch)
	}
	return nil
}

// Presented and CleanedUp are copies of the calls so far.
func (m *Memory) Presented() []Challenge {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.presented)
}

// CleanedUp is a copy of the CleanUp calls so far.
func (m *Memory) CleanedUp() []Challenge {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.cleaned)
}

// Live is the number of HTTP-01 tokens currently served.
func (m *Memory) Live() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tokens)
}

// ServeHTTP serves GET HTTPPathPrefix + token with the key authorization, 404 otherwise.
func (m *Memory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, HTTPPathPrefix)
	m.mu.Lock()
	body, found := m.tokens[token]
	m.mu.Unlock()
	if r.Method != http.MethodGet || !ok || !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(body))
}
