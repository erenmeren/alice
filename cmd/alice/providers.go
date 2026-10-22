package main

import (
	"log/slog"

	"alice/internal/providers"
	"alice/internal/providers/apache"
	"alice/internal/providers/azurekv"
	"alice/internal/providers/haproxy"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/nginx"
	"alice/internal/providers/windows"
	"alice/internal/version"
)

// registerProviders registers every provider this build ships and freezes the registry
// (spec §6.4: explicit registration in one file, no init() magic). It is the only place that
// imports a provider implementation. nginx (Phase 4), apache and haproxy (both discovery only) are built on linuxssh: one connection pool, one
// host-key check, one helper; azurekv (Phase 5, Key Vault) has no pool: its sessions are built per
// job, and the clock and logger arrive in the Env of each Open. windows (R60 W1: connection test and
// discovery) shares the pool and its host-key check, with its own helper (alice-helper.exe) that
// sshd forces on every session. checkWiring (wiring.go) refuses to start a build that lacks one of them.
// Only a development build (version "dev") may show a setup script that cannot verify
// alice-helper or alice-helper.exe; make build and the image build always embed both helpers' checksums.
// A versioned build without them (a hand-made go build) starts, but logs a warning per helper:
// its Servers page cannot show the setup commands (ALC-SSH-0011).
func registerProviders(reg *providers.Registry, sshPool *linuxssh.Pool, log *slog.Logger) {
	dev := version.Version == "dev"
	if !dev && !linuxssh.HelperChecksumsKnown() {
		log.Warn("this build has no alice-helper checksums, so it cannot show the commands that prepare a server; "+
			"build it with make build or the image build", "version", version.Version)
	}
	if !dev && !windows.HelperChecksumsKnown() {
		log.Warn("this build has no alice-helper.exe checksums, so it cannot show the commands that prepare a Windows server; "+
			"build it with make build or the image build", "version", version.Version)
	}
	ssh := linuxssh.New(linuxssh.Options{Pool: sshPool, AllowUnverifiedHelper: dev})
	reg.Register(ssh)
	// The defaults: Alice's own TLS probe, 5 verification attempts 2 s apart.
	reg.Register(nginx.New(nginx.Options{SSH: ssh}))
	// apache (discovery only) shares the same linuxssh provider: one pool, one host-key check, one helper.
	reg.Register(apache.New(apache.Options{SSH: ssh}))
	// haproxy (discovery only) shares it too.
	reg.Register(haproxy.New(haproxy.Options{SSH: ssh}))
	// azureRoots (testapi_*.go) is the trust of Azure's TLS certificates: the system roots in a
	// release build, only the fake Azure service's CA in the e2e build (R40 row 35).
	reg.Register(azurekv.New(azurekv.Options{RootCAs: azureRoots}))
	// windows: one fresh connection of the shared pool per helper call (design §8).
	reg.Register(windows.New(windows.Options{Pool: sshPool, AllowUnverifiedHelper: dev}))
	reg.Freeze()
}
