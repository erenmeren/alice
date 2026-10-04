//go:build !e2e

package main

import (
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

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }
