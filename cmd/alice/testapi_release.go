//go:build !e2e

package main

import (
	"crypto/x509"
	"net/http"
	"time"

	"alice/internal/alerts"
	"alice/internal/notify"
	"alice/internal/platform/clock"
)

// versionSuffix marks the build variant in the reported version (none for release builds).
const versionSuffix = ""

// newClock returns the wall clock. Only the e2e build can shift time.
func newClock() serverClock { return clock.Real{} }

// testMailer is nil: a release build sends e-mail only through the mail settings (imported once from ALICE_SMTP_*);
// without them an e-mail is recorded as skipped (L-18).
var testMailer notify.Mailer

// startJobWorkers is true: serve runs the job workers (runner.Run).
const startJobWorkers = true

// sweepEvery is the interval of the deployment recovery sweep (spec R38 item 8).
const sweepEvery = time.Minute

// kvScheduleEvery and kvAutoDeployEvery are the intervals of the Key Vault poll scheduler and the
// automatic deployment planner (R40 row 29).
const (
	kvScheduleEvery   = time.Minute
	kvAutoDeployEvery = time.Minute
)

// rotationPlanEvery, rotationSweepEvery and destroyRetiredEvery are the intervals of the SSH key
// rotation tasks (contract C1: rotation.plan and rotation.sweep every minute, sshkey.destroy_retired
// every hour). The sweep's minute keeps a removal well inside the 15-minute bound of its re-check
// (sshkeys.ReverifyFreshness) and the S3 wait (helper budget + 30 s) short; the hourly task reconciles
// ended deploys whose wait is minutes.
const (
	rotationPlanEvery   = time.Minute
	rotationSweepEvery  = time.Minute
	destroyRetiredEvery = time.Hour
)

// alertsScanEvery is the interval of the expiry scan (contract C1: alerts.scan every 15 minutes).
const alertsScanEvery = alerts.ScanEvery

// azureRoots is the trust of Azure's TLS certificates: nil means the system roots. Only the e2e build
// trusts anything else (testapi_e2e.go), and a release build reads no file for it.
func azureRoots() (*x509.CertPool, error) { return nil, nil }

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }

// backupScheduleEvery is the interval of the daily backup check (contract C1: backup.schedule every 5 minutes).
const backupScheduleEvery = 5 * time.Minute
