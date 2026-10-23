package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
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

// The shipped provider set is visible in one place (spec §6.4): linuxssh with the capabilities
// the SSH key inventory needs, from Phase 4 nginx with the certificate capabilities on top, and
// from Phase 5 azurekv (Key Vault); the registry is frozen afterwards. List sorts by kind, so the
// rows are looked up by kind, never by position.
func TestRegisterProvidersShipsEveryProvider(t *testing.T) {
	pool := newTestPool()
	t.Cleanup(pool.Close)
	reg := providers.NewRegistry()
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))

	list := reg.List()
	require.Len(t, list, 6)
	byKind := map[providers.Kind]providers.Descriptor{}
	for _, d := range list {
		byKind[d.Kind] = d
	}
	require.Len(t, byKind, 6)
	assert.ElementsMatch(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverSSHKeys, providers.CapKeyLogin, providers.CapTestConnection},
		byKind[providers.KindLinuxSSH].Capabilities)
	assert.ElementsMatch(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment, providers.CapKeyLogin, providers.CapHTTP01}, byKind[providers.KindNginx].Capabilities)
	assert.ElementsMatch(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapKeyLogin}, byKind[providers.KindApache].Capabilities, "discovery only")
	assert.ElementsMatch(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapKeyLogin}, byKind[providers.KindHAProxy].Capabilities, "discovery only")
	assert.ElementsMatch(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDiscoverKVKeys,
		providers.CapDiscoverKVSecrets, providers.CapReadCertificateSecret, providers.CapImportCertificate}, byKind[providers.KindAzureKV].Capabilities)
	assert.ElementsMatch(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDeployCertificate,
		providers.CapVerifyDeployment, providers.CapCleanupCertificates}, byKind[providers.KindWindows].Capabilities,
		"R61 W2: a Windows server is deployed to and verified; R62 W3: what Alice imported is cleaned up")

	p, ok := reg.Get(providers.KindLinuxSSH)
	require.True(t, ok)
	providertest.CheckProvider(t, p)
	_, isGuide := p.(providers.SetupGuide)
	assert.True(t, isGuide, "the setup snippets come from the linuxssh provider")
	n, ok := reg.Get(providers.KindNginx)
	require.True(t, ok)
	providertest.CheckProvider(t, n)
	_, isCache := n.(providers.ConnectionCache)
	assert.True(t, isCache, "deleting an Nginx server closes its connections")
	ap, ok := reg.Get(providers.KindApache)
	require.True(t, ok)
	providertest.CheckProvider(t, ap)
	_, isCache = ap.(providers.ConnectionCache)
	assert.True(t, isCache, "deleting an Apache server closes its connections")
	hp, ok := reg.Get(providers.KindHAProxy)
	require.True(t, ok)
	providertest.CheckProvider(t, hp)
	_, isCache = hp.(providers.ConnectionCache)
	assert.True(t, isCache, "deleting an HAProxy server closes its connections")
	a, ok := reg.Get(providers.KindAzureKV)
	require.True(t, ok)
	_, isCache = a.(providers.ConnectionCache)
	assert.True(t, isCache, "deleting a vault releases its limiter")
	w, ok := reg.Get(providers.KindWindows)
	require.True(t, ok)
	providertest.CheckProvider(t, w)
	_, isCache = w.(providers.ConnectionCache)
	assert.True(t, isCache, "deleting a Windows server forgets it in the shared pool")

	assert.Panics(t, func() { reg.Register(linuxssh.New(linuxssh.Options{Pool: pool})) }, "the registry is frozen")
}

// Both providers share one connection pool: forgetting a deleted target through the nginx provider
// reaches the pool the linuxssh provider dials with, so neither reconnects to it.
func TestNginxAndLinuxSSHShareOnePool(t *testing.T) {
	pool := newTestPool()
	t.Cleanup(pool.Close)
	reg := providers.NewRegistry()
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))
	ssh, _ := reg.Get(providers.KindLinuxSSH)
	ngx, _ := reg.Get(providers.KindNginx)

	gone, kept := uuid.New(), uuid.New()
	ngx.(providers.ConnectionCache).ForgetTarget(gone)
	// Port 1 on the loopback refuses at once: a target that is not forgotten is dialled.
	cfg := providers.TargetConfig{"host": "127.0.0.1", "port": 1, "username": "alice-svc"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := ssh.Open(ctx, providers.TargetRef{ID: gone, Kind: providers.KindLinuxSSH, Config: cfg}, nil, providers.Env{})
	assert.Equal(t, "linuxssh: the target was deleted", causeOf(t, err), "the linuxssh pool refuses the target the nginx provider forgot")
	_, err = ssh.Open(ctx, providers.TargetRef{ID: kept, Kind: providers.KindLinuxSSH, Config: cfg}, nil, providers.Env{})
	assert.NotEqual(t, "linuxssh: the target was deleted", causeOf(t, err), "another target is dialled")

	pool.Close()
	_, err = ngx.Open(ctx, providers.TargetRef{ID: kept, Kind: providers.KindNginx, Config: cfg}, nil, providers.Env{})
	assert.Equal(t, "linuxssh: connection pool closed", causeOf(t, err), "the nginx provider dials through the same (now closed) pool")
}

// causeOf is the cause of a provider error (its message names only the code).
func causeOf(t *testing.T, err error) string {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	if pe.Cause == nil {
		return ""
	}
	return pe.Cause.Error()
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
	assert.Contains(t, logs.String(), "this build has no alice-helper.exe checksums")
}

// Every web-server type of the one list maps to a kind this build registers (Phase A carry).
func TestEveryWebServerTypeHasARegisteredKind(t *testing.T) {
	pool := newTestPool()
	t.Cleanup(pool.Close)
	reg := providers.NewRegistry()
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))
	for _, typ := range inventory.WebServerTypes() {
		kind, ok := providers.KindForTargetType(typ)
		require.True(t, ok, typ)
		_, ok = reg.Get(kind)
		assert.True(t, ok, "%s is not registered", typ)
	}
}
