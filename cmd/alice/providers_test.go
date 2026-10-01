package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/providertest"
)

func newTestPool() *linuxssh.Pool {
	return linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}}, linuxssh.MaxConnections,
		linuxssh.MaxConnectionsPerTarget, linuxssh.IdleTimeout)
}

// The shipped provider set is visible in one place (spec §6.4): exactly linuxssh in Phase 3,
// with the capabilities the SSH key inventory needs, and the registry is frozen afterwards.
func TestRegisterProvidersShipsExactlyLinuxSSH(t *testing.T) {
	pool := newTestPool()
	t.Cleanup(pool.Close)
	reg := providers.NewRegistry()
	registerProviders(reg, pool)

	list := reg.List()
	require.Len(t, list, 1)
	assert.Equal(t, providers.KindLinuxSSH, list[0].Kind)
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverSSHKeys, providers.CapTestConnection},
		list[0].Capabilities)
	_, ok := reg.Get(providers.KindNginx)
	assert.False(t, ok, "nginx arrives in Phase 4")

	p, ok := reg.Get(providers.KindLinuxSSH)
	require.True(t, ok)
	providertest.CheckProvider(t, p)
	_, isGuide := p.(providers.SetupGuide)
	assert.True(t, isGuide, "the setup snippets come from the linuxssh provider")

	assert.Panics(t, func() { reg.Register(linuxssh.New(linuxssh.Options{Pool: pool})) }, "the registry is frozen")
}
