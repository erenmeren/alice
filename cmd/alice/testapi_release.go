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

// acmeSweepEvery is the interval of the ACME sweep (abandoned orders, leftover challenge records).
const acmeSweepEvery = time.Minute

// acmeScheduleEvery is the interval of the ACME renewal planner (acme.schedule; design row 6).
const acmeScheduleEvery = time.Minute

// acmeAutoDeployEvery is the interval of the ACME automatic deployment planner (acme.auto_deploy; design row 7).
const acmeAutoDeployEvery = time.Minute

// incidentAdvanceEvery is the interval of the key-compromise incident task (incident.advance).
const incidentAdvanceEvery = 30 * time.Second

// revocationCheckEvery is the interval of the revocation check (revocation.check, R64 Ruling 17).
const revocationCheckEvery = 15 * time.Minute

// driftScheduleEvery and driftRepairEvery are the intervals of the certificate drift tasks (R52): the observation
// schedule (each bound location is observed every inventory.DriftObserveInterval; the schedule only finds the due ones)
// and the repair planner.
const (
	driftScheduleEvery = 5 * time.Minute
	driftRepairEvery   = time.Minute
)

// canaryAdvanceEvery is the interval of the canary deployment's decisions (R65, design §18).
const canaryAdvanceEvery = 10 * time.Second

// windowsCleanupScheduleEvery is the interval of the Windows certificate cleanup schedule (R62 W3 Ruling 13): each
// Windows server is cleaned up once a day; the hourly schedule only finds the due ones.
const windowsCleanupScheduleEvery = time.Hour

// netdiscoScheduleEvery and netdiscoRetentionEvery are the intervals of the network discovery schedule (a scope's
// window is minute-exact) and its retention.
const (
	netdiscoScheduleEvery  = time.Minute
	netdiscoRetentionEvery = time.Hour
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

// acmeRoots is the trust of the fake ACME CA in the e2e build; here there is none: nil means no extra roots,
// so a release build knows no fake CA and no place to read one from.
func acmeRoots() (*x509.CertPool, error) { return nil, nil }

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }

// backupScheduleEvery is the interval of the daily backup check (contract C1: backup.schedule every 5 minutes).
const backupScheduleEvery = 5 * time.Minute
