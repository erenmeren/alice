//go:build !e2e

package main

import (
	"crypto/x509"
	"net/http"
	"time"

	"alice/internal/notify"
	"alice/internal/platform/clock"
)

// versionSuffix marks the build variant in the reported version (none for release builds).
const versionSuffix = ""

// newClock returns the wall clock. Only the e2e build can shift time.
func newClock() serverClock { return clock.Real{} }

// testMailer is nil: release builds send email only through ALICE_SMTP_*.
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

// azureRoots is the trust of Azure's TLS certificates: nil means the system roots. Only the e2e build
// trusts anything else (testapi_e2e.go), and a release build reads no file for it.
func azureRoots() (*x509.CertPool, error) { return nil, nil }

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }
