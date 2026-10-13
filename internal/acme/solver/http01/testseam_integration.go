//go:build integration

package http01

import "net"

// SetTestTarget makes the solver's own check of the token URL dial port on the addresses resolver answers, for the
// integration tests of the packages that drive the real solver (the acme jobs). Only the integration build tag
// compiles it, and that tag never builds alice: a shipped binary has no way to point the check elsewhere. Every dial
// still goes through netaddr.
func SetTestTarget(s *Solver, port int, resolver *net.Resolver) { s.port, s.resolver = port, resolver }
