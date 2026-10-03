package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/providertest"
	"alice/internal/version"
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
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))

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

// Only a development build ("dev", what go build and go test produce) may offer a setup script
// that cannot verify alice-helper; any versioned build without the helper checksums offers none
// (R37 item 2).
func TestOnlyADevelopmentBuildSkipsTheHelperCheck(t *testing.T) {
	line := "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform"
	var logs strings.Builder
	script := func() string {
		logs.Reset()
		pool := newTestPool()
		t.Cleanup(pool.Close)
		reg := providers.NewRegistry()
		registerProviders(reg, pool, slog.New(slog.NewTextHandler(&logs, nil)))
		p, ok := reg.Get(providers.KindLinuxSSH)
		require.True(t, ok)
		return p.(providers.SetupGuide).SetupSnippets(line)["linux"].Script
	}
	require.Equal(t, "dev", version.Version)
	require.False(t, linuxssh.HelperChecksumsKnown(), "go test links no helper checksums")
	assert.Contains(t, script(), "cannot verify alice-helper")
	assert.Empty(t, logs.String(), "a development build starts without a warning")

	version.Version = "1.0.0"
	t.Cleanup(func() { version.Version = "dev" })
	assert.Empty(t, script(), "a release build without the checksums has no setup script")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "this build has no alice-helper checksums")
}
