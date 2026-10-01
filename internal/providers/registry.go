package providers

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds the providers of this build. It is filled in cmd/alice (no init magic) and
// frozen before the first request (spec §6.4).
type Registry struct {
	mu        sync.RWMutex
	providers map[Kind]Provider
	frozen    bool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{providers: map[Kind]Provider{}} }

// Register adds p. It panics on a nil provider, an empty kind or display name, no capabilities,
// an invalid schema, a duplicate kind or a frozen registry: a broken provider never starts.
func (r *Registry) Register(p Provider) {
	if p == nil {
		panic("providers: nil provider")
	}
	k := p.Kind()
	switch {
	case k == "":
		panic("providers: provider without a kind")
	case p.DisplayNameKey() == "":
		panic(fmt.Sprintf("providers: %s has no display name key", k))
	case len(p.Capabilities()) == 0:
		panic(fmt.Sprintf("providers: %s advertises no capabilities", k))
	}
	if err := checkFields(p.ConfigSchema().Fields); err != nil {
		panic(fmt.Sprintf("providers: %s config schema: %v", k, err))
	}
	if err := checkFields(p.CredentialSchema().Fields); err != nil {
		panic(fmt.Sprintf("providers: %s credential schema: %v", k, err))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		panic(fmt.Sprintf("providers: registry is frozen; cannot register %s", k))
	}
	if _, dup := r.providers[k]; dup {
		panic(fmt.Sprintf("providers: kind %s is registered twice", k))
	}
	r.providers[k] = p
}

// Freeze makes the registry immutable.
func (r *Registry) Freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
}

// Get returns the provider of kind k.
func (r *Registry) Get(k Kind) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[k]
	return p, ok
}

// List describes every provider, sorted by kind.
func (r *Registry) List() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, Descriptor{
			Kind: p.Kind(), DisplayNameKey: p.DisplayNameKey(), Capabilities: p.Capabilities().Sorted(),
			ConfigSchema: p.ConfigSchema(), CredentialSchema: p.CredentialSchema(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}
