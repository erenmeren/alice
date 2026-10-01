// Package providertest holds the conformance checks every provider runs (spec §6.5 item 5).
// It uses only testing.TB, so it never pulls test libraries into a build that imports it.
package providertest

import (
	"context"
	"errors"
	"testing"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// CheckProvider verifies the static contract: kind, display name, capabilities, schemas that a
// registry accepts, and that ValidateConfig reports every required field of an empty config.
func CheckProvider(t testing.TB, p providers.Provider) {
	t.Helper()
	if p.Kind() == "" {
		t.Errorf("provider has no kind")
	}
	if p.DisplayNameKey() == "" {
		t.Errorf("%s: no display name key", p.Kind())
	}
	if len(p.Capabilities()) == 0 {
		t.Errorf("%s: no capabilities", p.Kind())
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: a registry refuses it: %v", p.Kind(), r)
			}
		}()
		providers.NewRegistry().Register(p)
	}()
	reported := map[string]bool{}
	for _, fe := range p.ValidateConfig(providers.TargetConfig{}) {
		if fe.Code == validate.Required {
			reported[fe.Field] = true
		}
	}
	for _, f := range p.ConfigSchema().Fields {
		if f.Required && f.Default == nil && !reported[f.Name] {
			t.Errorf("%s: an empty config does not report the required field %q", p.Kind(), f.Name)
		}
	}
}

// CheckUnsupported verifies that every operation of a capability the provider does not
// advertise answers ErrUnsupported (spec §6.1), so the job layer can rely on Capabilities().
func CheckUnsupported(t testing.TB, s providers.Session, caps providers.CapabilitySet) {
	t.Helper()
	ctx := context.Background()
	expect := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, providers.ErrUnsupported) {
			t.Errorf("%s without its capability: got %v, want ErrUnsupported", name, err)
		}
	}
	if !caps.Has(providers.CapTestConnection) {
		_, err := s.TestConnection(ctx)
		expect("TestConnection", err)
	}
	if !caps.Has(providers.CapDiscoverSSHKeys) {
		_, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
		expect("Discover", err)
	}
	if !caps.Has(providers.CapAuthorizedKeys) {
		_, err := s.ListAuthorizedKeys(ctx)
		expect("ListAuthorizedKeys", err)
		_, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
		expect("AddAuthorizedKey", err)
		_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
		expect("RemoveAuthorizedKey", err)
	}
}
