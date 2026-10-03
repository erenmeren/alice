package inventory

import (
	"context"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/secrets"
)

// AuditLicenseDenial exposes auditLicenseDenial to the integration tests.
func (s *Service) AuditLicenseDenial(ctx context.Context, a Actor, name string, cause error) {
	s.auditLicenseDenial(ctx, a, name, cause)
}

// ServersTextBound exposes the size bound of boundServers to the integration tests, which compare
// it with PostgreSQL's rendering.
func ServersTextBound(servers []providers.CertServer) int {
	total := 2
	for i, s := range servers {
		total += serverTextSize(s)
		if i > 0 {
			total += 2
		}
	}
	return total
}

// LoadKey exposes loadKey to the integration tests (the round trip of a sealed key and the leak
// test's markers of generated keys).
func (s *Service) LoadKey(ctx context.Context, id uuid.UUID) (secrets.Plaintext, error) {
	return s.loadKey(ctx, s.pool, id)
}

// HoldPFXSlots takes n PFX decode slots without waiting; ok is false (and nothing is held) when
// they are not all free. release gives them back.
func HoldPFXSlots(n int) (release func(), ok bool) {
	var held []func()
	release = func() {
		for _, r := range held {
			r()
		}
	}
	for range n {
		r, ok := acquirePFXSlot()
		if !ok {
			release()
			return func() {}, false
		}
		held = append(held, r)
	}
	return release, true
}

// ValidSNI exposes validSNI to the test that compares it with helperproto.ValidSNI.
func ValidSNI(s string) bool { return validSNI(s) }
