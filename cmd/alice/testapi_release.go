//go:build !e2e

package main

import (
	"net/http"

	"alice/internal/platform/clock"
)

// newClock returns the wall clock. Only the e2e build can shift time.
func newClock() clock.Clock { return clock.Real{} }

// testHandler returns nil: release builds have no /test endpoints.
func testHandler(testDeps) http.Handler { return nil }
