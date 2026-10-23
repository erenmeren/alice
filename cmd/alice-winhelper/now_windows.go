//go:build windows && !alicetest

package main

import "time"

// Now is the helper's clock (W3 Ruling 8: the import inventory's unbound_since and a certificate's
// age are judged by it): the machine's own. The test build's variant (now_alicetest_windows.go, -tags
// alicetest) adds an offset its environment names, so a runner can judge the age path without waiting
// seven days; that file is never in the shipped binary (internal/archtest
// TestReleaseBinariesLinkNoTestPackages).
func (h host) Now() time.Time { return h.now() }

// testClockOffset reports that this build carries no clock offset.
const testClockOffset = false
