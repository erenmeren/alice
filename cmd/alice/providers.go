package main

import (
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
)

// registerProviders registers every provider this build ships and freezes the registry
// (spec §6.4: explicit registration in one file, no init() magic). It is the only place that
// imports a provider implementation; nginx (Phase 4) and azurekv (Phase 5) are added here.
func registerProviders(reg *providers.Registry, sshPool *linuxssh.Pool) {
	reg.Register(linuxssh.New(linuxssh.Options{Pool: sshPool}))
	reg.Freeze()
}
