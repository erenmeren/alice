package providers_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// stub is the smallest valid provider; tests break one property at a time.
type stub struct {
	kind   providers.Kind
	name   string
	caps   providers.CapabilitySet
	config providers.ConfigSchema
	creds  providers.CredentialSchema
}

func validStub(kind providers.Kind) *stub {
	return &stub{
		kind: kind, name: "provider.stub.name",
		caps: providers.NewCapabilitySet(providers.CapTestConnection),
		config: providers.ConfigSchema{Fields: []providers.Field{
			{Name: "host", Type: providers.FieldHost, Required: true, LabelKey: "provider.stub.fields.host.label"},
			{Name: "port", Type: providers.FieldInt, Min: 1, Max: 65535, Default: 22, LabelKey: "provider.stub.fields.port.label"},
			{Name: "mode", Type: providers.FieldEnum, Values: []string{"a", "b"}, LabelKey: "provider.stub.fields.mode.label", Pattern: `^[ab]$`},
		}},
	}
}

func (s *stub) Kind() providers.Kind                         { return s.kind }
func (s *stub) DisplayNameKey() string                       { return s.name }
func (s *stub) Capabilities() providers.CapabilitySet        { return s.caps }
func (s *stub) ConfigSchema() providers.ConfigSchema         { return s.config }
func (s *stub) CredentialSchema() providers.CredentialSchema { return s.creds }
func (s *stub) ValidateConfig(providers.TargetConfig) []validate.FieldError {
	return nil
}
func (s *stub) Open(context.Context, providers.TargetRef, providers.CredentialSource, providers.Env) (providers.Session, error) {
	return providers.UnsupportedSession{}, nil
}

func TestRegistryRegistersFreezesAndLists(t *testing.T) {
	r := providers.NewRegistry()
	r.Register(validStub(providers.KindNginx))
	r.Register(validStub(providers.KindLinuxSSH))
	r.Freeze()

	p, ok := r.Get(providers.KindLinuxSSH)
	require.True(t, ok)
	assert.Equal(t, providers.KindLinuxSSH, p.Kind())
	_, ok = r.Get(providers.KindAzureKV)
	assert.False(t, ok)

	list := r.List()
	require.Len(t, list, 2)
	assert.Equal(t, providers.KindLinuxSSH, list[0].Kind, "sorted by kind")
	assert.Equal(t, providers.KindNginx, list[1].Kind)
	assert.Equal(t, []providers.Capability{providers.CapTestConnection}, list[0].Capabilities)
	assert.Equal(t, "provider.stub.name", list[0].DisplayNameKey)
	assert.Len(t, list[0].ConfigSchema.Fields, 3)

	assert.PanicsWithValue(t, "providers: registry is frozen; cannot register azurekv", func() {
		r.Register(validStub(providers.KindAzureKV))
	})
}

func TestRegistryRefusesBrokenProviders(t *testing.T) {
	cases := map[string]func(s *stub){
		"empty kind":         func(s *stub) { s.kind = "" },
		"no display name":    func(s *stub) { s.name = "" },
		"no capabilities":    func(s *stub) { s.caps = providers.NewCapabilitySet() },
		"bad field name":     func(s *stub) { s.config.Fields[0].Name = "Host" },
		"field name digit":   func(s *stub) { s.config.Fields[0].Name = "1host" },
		"duplicate field":    func(s *stub) { s.config.Fields[1].Name = "host" },
		"bad field type":     func(s *stub) { s.config.Fields[0].Type = "url" },
		"empty label key":    func(s *stub) { s.config.Fields[0].LabelKey = "" },
		"bad pattern":        func(s *stub) { s.config.Fields[2].Pattern = `^[a` },
		"enum without value": func(s *stub) { s.config.Fields[2].Values = nil },
		"min above max":      func(s *stub) { s.config.Fields[1].Min = 70000 },
		"bad credential field": func(s *stub) {
			s.creds = providers.CredentialSchema{Fields: []providers.Field{{Name: "secret", Type: "blob", LabelKey: "x"}}}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			s := validStub(providers.KindLinuxSSH)
			breakIt(s)
			assert.Panics(t, func() { providers.NewRegistry().Register(s) })
		})
	}
	t.Run("duplicate kind", func(t *testing.T) {
		r := providers.NewRegistry()
		r.Register(validStub(providers.KindLinuxSSH))
		assert.PanicsWithValue(t, "providers: kind linuxssh is registered twice", func() {
			r.Register(validStub(providers.KindLinuxSSH))
		})
	})
	t.Run("nil provider", func(t *testing.T) {
		assert.Panics(t, func() { providers.NewRegistry().Register(nil) })
	})
}

func TestKindForTargetType(t *testing.T) {
	for typ, want := range map[string]providers.Kind{
		"linux": providers.KindLinuxSSH, "nginx": providers.KindNginx, "azure_key_vault": providers.KindAzureKV,
	} {
		got, ok := providers.KindForTargetType(typ)
		assert.True(t, ok, typ)
		assert.Equal(t, want, got, typ)
	}
	for _, typ := range []string{"", "Linux", "linuxssh", "windows"} {
		_, ok := providers.KindForTargetType(typ)
		assert.False(t, ok, typ)
	}
}

func TestCapabilitySet(t *testing.T) {
	c := providers.NewCapabilitySet(providers.CapAuthorizedKeys, providers.CapTestConnection, providers.CapAuthorizedKeys)
	assert.True(t, c.Has(providers.CapTestConnection))
	assert.False(t, c.Has(providers.CapDeployCertificate))
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapTestConnection}, c.Sorted())
	assert.Empty(t, providers.NewCapabilitySet().Sorted())
	var nilSet providers.CapabilitySet
	assert.False(t, nilSet.Has(providers.CapTestConnection))
}

// Spec §6.3 item 5: no secret in errors. The message is the stable code only, whatever the cause says.
func TestErrorNeverShowsItsCause(t *testing.T) {
	cause := errors.New("ssh: handshake failed: password=CANARY-hunter2")
	err := providers.NewError("ssh.auth_failed", false, cause, map[string]string{"host": "web-01"})
	assert.Equal(t, "providers: ssh.auth_failed", err.Error())
	for _, s := range []string{fmt.Sprint(err), fmt.Sprintf("%v %+v %s %q", err, err, err, err), fmt.Errorf("job: %w", err).Error()} {
		assert.NotContains(t, s, "CANARY", s)
	}
	assert.ErrorIs(t, err, cause, "the cause stays reachable for errors.Is")
	var pe *providers.Error
	require.True(t, errors.As(fmt.Errorf("wrapped: %w", err), &pe))
	assert.Equal(t, "ssh.auth_failed", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, map[string]string{"host": "web-01"}, pe.Params)

	retry := providers.NewError("ssh.unreachable", true, nil, nil)
	assert.True(t, retry.Retryable)
	assert.NotNil(t, retry.Params, "params are never nil")
	assert.NoError(t, retry.Unwrap())
}

func TestUnsupportedSession(t *testing.T) {
	ctx := context.Background()
	s := providers.UnsupportedSession{}
	assert.NoError(t, s.Close())
	_, err := s.TestConnection(ctx)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.ListAuthorizedKeys(ctx)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}
