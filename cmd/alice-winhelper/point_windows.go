//go:build windows && !alicetest

package main

// Point is a crash point of the platform-neutral transaction (winhelper.WriteHost); the real helper
// never stops at one. The test build's variant (point_alicetest_windows.go, -tags alicetest) stops
// where its environment variable says; that file is never in the shipped binary
// (internal/archtest TestReleaseBinariesLinkNoTestPackages).
func (host) Point(string) error { return nil }

// testKillHook reports that this build carries no kill hook.
const testKillHook = false
