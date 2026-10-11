package main

import (
	"context"
	"log/slog"
	"net/http"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/tlscert"
	"alice/internal/setup"
	"alice/internal/version"
)

// testDeps is what the e2e-only test endpoints need. Release builds ignore it.
type testDeps struct {
	OwnerURL    string // migration (owner) role: truncating tables needs it; never logged or returned
	Setup       *setup.Service
	License     *license.Service
	Scheduler   *jobs.Scheduler
	Sender      *notify.Sender
	StateDir    string
	BackupDir   string         // /test/reset removes the backup files (Phase 8)
	TLS         *tlscert.Store // /test/reset serves a temporary HTTPS certificate again (Phase 8)
	KeysDir     string
	TLSHosts    []string
	Log         *slog.Logger
	ResetLimits func()
	Inventory   *inventory.Service // the reset creates a new platform key
	Runner      jobRunner          // POST /test/jobs/drain
}

// jobRunner runs one due job (*jobs.Runner).
type jobRunner interface {
	RunOnce(ctx context.Context) (bool, error)
}

// testLicenseSuffix marks a build that trusts the test license key but is not the e2e
// build (the e2e build is marked "+e2e" and always trusts it).
const testLicenseSuffix = "+testlicense"

// buildVersion is the version this binary reports; e2e builds carry versionSuffix "+e2e",
// other builds that trust the test license key "+testlicense".
func buildVersion() version.Info {
	v := version.Get()
	v.Version += versionSuffix
	if license.TestKeyTrusted && versionSuffix == "" {
		v.Version += testLicenseSuffix
	}
	return v
}

// warnIfTestBuild logs a warning when the test-only /test endpoints are mounted or the test
// license signing key is trusted.
func warnIfTestBuild(log *slog.Logger, testHandler http.Handler) {
	if testHandler != nil {
		log.Warn("e2e build: test-only /test endpoints are enabled; never use for real data")
	}
	if license.TestKeyTrusted {
		log.Warn("test build: test license key trusted — never use for real data")
	}
}
