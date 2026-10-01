// Package fake is an in-memory provider for inventory and job tests. Behaviour is scripted with
// Configure; every call is recorded. Open follows the pinning rules of the real linuxssh dialer.
package fake

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// Call is one recorded method call.
type Call struct {
	Method string // "Open", "TestConnection", "Discover", "ListAuthorizedKeys", "AddAuthorizedKey", "RemoveAuthorizedKey", "Close"
	Target uuid.UUID
	Change providers.AuthKeyChange // Add/Remove only
}

// Config is the scripted behaviour.
type Config struct {
	OpenErr          error
	SkipHostKeyCheck bool              // Open does not consult env.HostKeys
	PresentedKey     providers.HostKey // the key "the server" presents; "" fingerprint = do not check
	Report           providers.ConnectionReport
	TestErr          error
	Discovery        providers.DiscoveryResult
	DiscoverErr      error
	Keys             []providers.DiscoveredSSHKey
	ListErr          error
	AddResult        providers.AuthKeyResult
	AddErr           error
	RemoveResult     providers.AuthKeyResult
	RemoveErr        error
}

// Provider is the scriptable provider.
type Provider struct {
	kind  providers.Kind
	caps  providers.CapabilitySet
	mu    sync.Mutex
	cfg   Config
	calls []Call
}

// New returns a fake of kind with caps (test_connection, discover_ssh_keys and authorized_keys
// when none are given).
func New(kind providers.Kind, caps ...providers.Capability) *Provider {
	if len(caps) == 0 {
		caps = []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys}
	}
	return &Provider{kind: kind, caps: providers.NewCapabilitySet(caps...)}
}

// Configure changes the scripted behaviour under the lock.
func (p *Provider) Configure(fn func(c *Config)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(&p.cfg)
}

// Calls returns a copy of the recorded calls.
func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Call(nil), p.calls...)
}

// Count returns how many calls of method were recorded.
func (p *Provider) Count(method string) int {
	n := 0
	for _, c := range p.Calls() {
		if c.Method == method {
			n++
		}
	}
	return n
}

func (p *Provider) record(c Call) Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, c)
	return p.cfg
}

// Kind implements providers.Provider.
func (p *Provider) Kind() providers.Kind { return p.kind }

// DisplayNameKey implements providers.Provider.
func (p *Provider) DisplayNameKey() string { return "provider.fake.name" }

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps }

// ConfigSchema implements providers.Provider.
func (p *Provider) ConfigSchema() providers.ConfigSchema {
	return providers.ConfigSchema{Fields: []providers.Field{
		{Name: "host", Type: providers.FieldHost, Required: true, LabelKey: "provider.fake.fields.host.label"},
		{Name: "port", Type: providers.FieldInt, Min: 1, Max: 65535, Default: 22, LabelKey: "provider.fake.fields.port.label"},
		{Name: "username", Type: providers.FieldString, Default: "alice-svc", LabelKey: "provider.fake.fields.username.label"},
	}}
}

// CredentialSchema implements providers.Provider.
func (p *Provider) CredentialSchema() providers.CredentialSchema { return providers.CredentialSchema{} }

// ValidateConfig implements providers.Provider: only host is required.
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	if h, _ := cfg["host"].(string); h == "" {
		return []validate.FieldError{{Field: "host", Code: validate.Required}}
	}
	return nil
}

// Open implements providers.Provider with the pinning rules of the real dialer.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	cfg := p.record(Call{Method: "Open", Target: t.ID})
	if cfg.OpenErr != nil {
		return nil, cfg.OpenErr
	}
	presented := cfg.PresentedKey
	if !cfg.SkipHostKeyCheck && env.HostKeys != nil && presented.Fingerprint != "" {
		pinned, err := env.HostKeys.Pinned(ctx, t.ID)
		switch {
		case errors.Is(err, providers.ErrNoPinnedKey):
			if err := env.HostKeys.Observed(ctx, t.ID, presented, false); err != nil {
				return nil, err
			}
			return nil, providers.NewError("target.host_key_unconfirmed", false, nil, map[string]string{"fingerprint": presented.Fingerprint})
		case err != nil:
			return nil, err
		case pinned.Fingerprint != presented.Fingerprint:
			if err := env.HostKeys.Observed(ctx, t.ID, presented, true); err != nil {
				return nil, err
			}
			return nil, providers.NewError("target.host_key_changed", false, nil,
				map[string]string{"old_fingerprint": pinned.Fingerprint, "new_fingerprint": presented.Fingerprint})
		}
	}
	if cred != nil {
		_, release, err := cred.SSHSigner(ctx)
		if err != nil {
			return nil, err
		}
		release()
	}
	return &session{p: p, target: t.ID}, nil
}

type session struct {
	p      *Provider
	target uuid.UUID
}

func (s *session) Close() error {
	s.p.record(Call{Method: "Close", Target: s.target})
	return nil
}

func (s *session) TestConnection(context.Context) (providers.ConnectionReport, error) {
	cfg := s.p.record(Call{Method: "TestConnection", Target: s.target})
	if !s.p.caps.Has(providers.CapTestConnection) {
		return providers.ConnectionReport{}, providers.ErrUnsupported
	}
	rep := cfg.Report
	if rep.HostKey.Fingerprint == "" {
		rep.HostKey = cfg.PresentedKey
	}
	return rep, cfg.TestErr
}

func (s *session) Discover(context.Context, providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	cfg := s.p.record(Call{Method: "Discover", Target: s.target})
	if !s.p.caps.Has(providers.CapDiscoverSSHKeys) {
		return providers.DiscoveryResult{}, providers.ErrUnsupported
	}
	return cfg.Discovery, cfg.DiscoverErr
}

func (s *session) ListAuthorizedKeys(context.Context) ([]providers.DiscoveredSSHKey, error) {
	cfg := s.p.record(Call{Method: "ListAuthorizedKeys", Target: s.target})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return nil, providers.ErrUnsupported
	}
	return cfg.Keys, cfg.ListErr
}

func (s *session) AddAuthorizedKey(_ context.Context, req providers.AuthKeyChange, _ providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "AddAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	return cfg.AddResult, cfg.AddErr
}

func (s *session) RemoveAuthorizedKey(_ context.Context, req providers.AuthKeyChange, _ providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "RemoveAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	return cfg.RemoveResult, cfg.RemoveErr
}

var (
	_ providers.Provider = (*Provider)(nil)
	_ providers.Session  = (*session)(nil)
)
