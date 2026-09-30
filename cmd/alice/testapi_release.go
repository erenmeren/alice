//go:build !e2e

package main

import (
	"net/http"

	"alice/internal/notify"
	"alice/internal/platform/clock"
)

// versionSuffix marks the build variant in the reported version (none for release builds).
const versionSuffix = ""

// newClock returns the wall clock. Only the e2e build can shift time.
func newClock() serverClock { return clock.Real{} }

// testMailer is nil: release builds send email only through ALICE_SMTP_*.
var testMailer notify.Mailer

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }
