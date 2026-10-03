package main

import (
	"log/slog"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/version"
)

// registerProviders registers every provider this build ships and freezes the registry
// (spec §6.4: explicit registration in one file, no init() magic). It is the only place that
// imports a provider implementation; nginx (Phase 4) and azurekv (Phase 5) are added here.
// Only a development build (version "dev") may show a setup script that cannot verify
// alice-helper; make build and the image build always embed the helper checksums.
// A versioned build without the checksums (a hand-made go build) starts, but logs a warning:
// its Servers page cannot show the setup commands (ALC-SSH-0011).
func registerProviders(reg *providers.Registry, sshPool *linuxssh.Pool, log *slog.Logger) {
	dev := version.Version == "dev"
	if !dev && !linuxssh.HelperChecksumsKnown() {
		log.Warn("this build has no alice-helper checksums, so it cannot show the commands that prepare a server; "+
			"build it with make build or the image build", "version", version.Version)
	}
	reg.Register(linuxssh.New(linuxssh.Options{Pool: sshPool, AllowUnverifiedHelper: dev}))
	reg.Freeze()
}
