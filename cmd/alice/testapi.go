package main

import (
	"log/slog"

	"alice/internal/setup"
)

// testDeps is what the e2e-only test endpoints need. Release builds ignore it.
type testDeps struct {
	OwnerURL    string // migration (owner) role: truncating tables needs it; never logged or returned
	Setup       *setup.Service
	Log         *slog.Logger
	ResetLimits func()
}
