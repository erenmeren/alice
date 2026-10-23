//go:build windows && alicetest

package main

// The clock offset of the fidelity tests (W3 Ruling 22), built with -tags alicetest only and never
// into the shipped helper (internal/archtest TestReleaseBinariesLinkNoTestPackages and
// TestTestOnlyFilesRequireTheirTag): while ALICE_WIN_TEST_CLOCK_OFFSET holds a Go duration ("192h"),
// the helper's clock runs that far ahead of the machine's, so TestFidelityCleanup judges the age of a
// certificate replaced moments ago. Only Now moves: the store reads and the lock keep the machine's
// time.

import (
	"os"
	"time"
)

// clockOffsetEnv names the offset the test build's helper clock runs ahead by.
const clockOffsetEnv = "ALICE_WIN_TEST_CLOCK_OFFSET"

// testClockOffset reports that this build carries the clock offset (the tests that need it fail
// without it).
const testClockOffset = true

// Now is the machine's time plus ALICE_WIN_TEST_CLOCK_OFFSET, read at every call (a value that is not
// a duration is no offset: the tests check that the offset took effect).
func (h host) Now() time.Time {
	d, err := time.ParseDuration(os.Getenv(clockOffsetEnv))
	if err != nil {
		d = 0
	}
	return h.now().Add(d)
}
