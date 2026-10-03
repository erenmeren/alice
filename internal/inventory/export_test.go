package inventory

import (
	"context"

	"alice/internal/providers"
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
