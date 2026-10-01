package inventory

import "context"

// AuditLicenseDenial exposes auditLicenseDenial to the integration tests.
func (s *Service) AuditLicenseDenial(ctx context.Context, a Actor, name string, cause error) {
	s.auditLicenseDenial(ctx, a, name, cause)
}
