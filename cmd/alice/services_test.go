//go:build !e2e

package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/auth"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
	"alice/internal/version"
	"alice/locales"
)

// The build time set at link time is the floor of the license clock; a development build
// has none.
// A build without one (a plain docker compose build, B6) starts with a warning, because the
// time record then has no floor after its loss (L-53).
func TestBuildTime(t *testing.T) {
	saved := version.BuildTime
	t.Cleanup(func() { version.BuildTime = saved })
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))

	version.BuildTime = "unknown"
	assert.True(t, buildTime(log).IsZero())
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "this build has no build time")

	logs.Reset()
	version.BuildTime = "2026-09-30T12:00:00Z"
	assert.Equal(t, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), buildTime(log))
	assert.Empty(t, logs.String())
}

// The release build sweeps for interrupted deployments every minute (R38 item 8).
func TestReleaseSweepsEveryMinute(t *testing.T) {
	assert.Equal(t, time.Minute, sweepEvery)
}

// The release build schedules due vault polls and plans automatic deployments every minute (R40 row 29).
func TestReleaseSchedulesKeyVaultWorkEveryMinute(t *testing.T) {
	assert.Equal(t, time.Minute, kvScheduleEvery)
	assert.Equal(t, time.Minute, kvAutoDeployEvery)
}

// The release build ends crashed ACME orders and queues leftover challenge cleanups every minute.
func TestReleaseSweepsACMEOrdersEveryMinute(t *testing.T) {
	assert.Equal(t, time.Minute, acmeSweepEvery)
}

// The release build plans due rotations and sweeps the live runs every minute (contract C1: the sweep
// advances runs and checks the 15-minute re-check bound, so a coarser tick would delay a removal past
// its re-check), and destroys retired private keys hourly (that task also reconciles ended deploys:
// the S3 wait is minutes, so an hourly pass is timely).
func TestReleaseSchedulesRotationWork(t *testing.T) {
	assert.Equal(t, time.Minute, rotationPlanEvery)
	assert.Equal(t, time.Minute, rotationSweepEvery)
	assert.Equal(t, time.Hour, destroyRetiredEvery)
}

// The release build scans for expiring certificates and Key Vault objects every 15 minutes (contract C1, alerts.ScanEvery).
func TestReleaseScansAlertsEvery15Minutes(t *testing.T) {
	assert.Equal(t, alerts.ScanEvery, alertsScanEvery)
	assert.Equal(t, 15*time.Minute, alertsScanEvery)
}

// The release build's mail settings connect through netaddr (no dialer override: SettingsConfig.Dial is nil, so every
// SMTP connection passes the SEC-065 address rule) and have no fallback mailer: without mail settings an e-mail is
// recorded as skipped (L-18), never delivered to a test mailbox.
func TestReleaseMailSettingsHaveNoDialerOverrideOrFallback(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://alice@127.0.0.1:1/alice?connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	keyring := &secrets.Keyring{}
	svc := wiringServices(t)
	svc.keyring = keyring
	clk := clock.NewOffset(clock.Real{})
	log := slog.New(slog.DiscardHandler)
	cfg := notifySettingsConfig(pool, svc, catalog, clk, log)
	assert.Nil(t, cfg.Dial, "the release build dials SMTP through netaddr.DialContext")
	assert.Nil(t, cfg.Fallback, "the release build has no test mailbox")
	assert.Same(t, pool, cfg.Pool)
	assert.Same(t, keyring, cfg.Keyring, "the SMTP password is sealed with serve's keyring")
	assert.Same(t, svc.auditLog, cfg.Audit)
	assert.Same(t, clk, cfg.Clock)
	assert.Same(t, catalog, cfg.Catalog)
	assert.Same(t, log, cfg.Log)

	// The identity providers' discovery, key set and token requests pass the same rule.
	svc.pool = pool
	svc.auth = &auth.Service{}
	oc := oidcConfig(svc, clk, log)
	assert.Nil(t, oc.Dial, "the release build dials identity providers through netaddr.DialContext")
	assert.Same(t, pool, oc.Pool)
	assert.Same(t, keyring, oc.Keyring, "client secrets are sealed with serve's keyring")
	assert.Same(t, svc.auth, oc.Auth)
	assert.Same(t, svc.auditLog, oc.Audit)
	assert.Same(t, clk, oc.Clock)
	assert.Same(t, log, oc.Log)
}
