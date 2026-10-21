//go:build integration

package dnsapi

// This file is the only way a harness outside a provider's own package points every DNS provider client at an
// in-process fake. It exists in builds with the integration tag only (never in a release or e2e binary: the e2e
// stack needs no mapping, Docker's DNS answers the providers' host names with the fake services).
//
// The mapping changes where a connection goes and nothing else: requests are still addressed to the provider's
// fixed hosts, the host allow-list, the TLS server name and every other guard stay as they are, and a client built
// while a mapping is set refuses to start without explicit roots (the fake's CA, given as the provider's BaseRoots).

// MapAddressesForTest makes every client built from now on map its connections through f; restore removes the
// mapping. Tests that use it must not run in parallel with tests that expect the real hosts.
func MapAddressesForTest(f func(hostport string) string) (restore func()) {
	testMapAddr.Store(&f)
	return func() { testMapAddr.Store(nil) }
}
