package main

import (
	"log/slog"
	"net/http"

	"alice/internal/setup"
	"alice/internal/version"
)

// testDeps is what the e2e-only test endpoints need. Release builds ignore it.
type testDeps struct {
	OwnerURL    string // migration (owner) role: truncating tables needs it; never logged or returned
	Setup       *setup.Service
	Log         *slog.Logger
	ResetLimits func()
}

// buildVersion is the version this binary reports; e2e builds carry versionSuffix "+e2e".
func buildVersion() version.Info {
	v := version.Get()
	v.Version += versionSuffix
	return v
}

// warnIfTestBuild logs a warning when the test-only /test endpoints are mounted.
func warnIfTestBuild(log *slog.Logger, testHandler http.Handler) {
	if testHandler != nil {
		log.Warn("e2e build: test-only /test endpoints are enabled; never use for real data")
	}
}
