//go:build windows && alicetest

package main

// The kill hook of the fidelity tests (W2 Task 9), built with -tags alicetest only and never into the
// shipped helper (internal/archtest TestReleaseBinariesLinkNoTestPackages and
// TestTestOnlyFilesRequireTheirTag): while ALICE_WIN_TEST_KILL_AT names a crash point, a call reaching
// it stops there as a killed process would (winhelper answers nothing, Outcome.Killed), leaving the
// machine as it had written it.

import (
	"errors"
	"os"
)

// killAtEnv names the crash point the test build's helper dies at.
const killAtEnv = "ALICE_WIN_TEST_KILL_AT"

// testKillHook reports that this build carries the hook (the tests that need it fail without it).
const testKillHook = true

var errTestKilled = errors.New("alice-winhelper: killed at a crash point by " + killAtEnv)

// Point kills the call at the point ALICE_WIN_TEST_KILL_AT names.
func (host) Point(name string) error {
	if v := os.Getenv(killAtEnv); v != "" && v == name {
		return errTestKilled
	}
	return nil
}
