package discoverysvc

import (
	"context"
	"fmt"
	"time"

	"alice/internal/discovery"
)

// ListCertificates lists discovered leaf certificates (discovery.ListCertificates, soonest expiry first); f.Limit is the
// page size (1..discovery.MaxPage-1, else 50) and more reports whether a page follows. f.Now is the service's clock
// when the filter has a time condition and no reference time.
func (s *Service) ListCertificates(ctx context.Context, f discovery.CertificateFilter) (list []discovery.CertificateRow, more bool, err error) {
	n := pageSize(f.Limit)
	f.Limit = n + 1
	if f.Now.IsZero() {
		f.Now = s.now()
	}
	list, err = discovery.ListCertificates(ctx, s.pool, f)
	if err != nil {
		return nil, false, err
	}
	if more = len(list) > n; more {
		list = list[:n]
	}
	return list, more, nil
}

// MaxDetailEndpoints is how many endpoints a certificate's detail lists (more says there are more).
const MaxDetailEndpoints = 200

// Certificate is one discovered leaf with the endpoints presenting it (or that last presented it), at most
// MaxDetailEndpoints; ErrNotFound for a fingerprint that is no discovered leaf.
func (s *Service) Certificate(ctx context.Context, fingerprint string) (c discovery.CertificateRow, eps []discovery.EndpointRow, more bool, err error) {
	list, err := discovery.ListCertificates(ctx, s.pool, discovery.CertificateFilter{Fingerprint: fingerprint, Limit: 1})
	if err != nil {
		return discovery.CertificateRow{}, nil, false, err
	}
	if len(list) == 0 {
		return discovery.CertificateRow{}, nil, false, ErrNotFound
	}
	eps, err = discovery.ListEndpoints(ctx, s.pool, discovery.EndpointFilter{Fingerprint: fingerprint, Limit: MaxDetailEndpoints + 1})
	if err != nil {
		return discovery.CertificateRow{}, nil, false, err
	}
	if more = len(eps) > MaxDetailEndpoints; more {
		eps = eps[:MaxDetailEndpoints]
	}
	return list[0], eps, more, nil
}

// ListEndpoints lists discovered endpoints (discovery.ListEndpoints: inside a scope in the order of its unique key);
// more reports whether a page follows.
func (s *Service) ListEndpoints(ctx context.Context, f discovery.EndpointFilter) (list []discovery.EndpointRow, more bool, err error) {
	n := pageSize(f.Limit)
	f.Limit = n + 1
	list, err = discovery.ListEndpoints(ctx, s.pool, f)
	if err != nil {
		return nil, false, err
	}
	if more = len(list) > n; more {
		list = list[:n]
	}
	return list, more, nil
}

// Summary is the Overview's discovery metric (decision D2): unmanaged leaf certificates that an endpoint which is not
// gone presents or last presented, how many of them expire within 30 days (not expired yet), the live scopes and when
// a scan last finished (nil: never).
type Summary struct {
	UnmanagedTotal       int
	UnmanagedExpiring30d int
	Scopes               int
	LastScanAt           *time.Time
}

// Summary reads the metric with index-backed counts (the leaf expiry index, the endpoint fingerprint index and the
// inventory's unique fingerprint).
func (s *Service) Summary(ctx context.Context) (Summary, error) {
	now := s.now()
	var out Summary
	err := s.pool.QueryRow(ctx, `WITH u AS (
    SELECT d.not_after FROM discovery_certificates d
    WHERE d.is_leaf AND NOT EXISTS (SELECT 1 FROM certificates c WHERE c.fingerprint_sha256 = d.fingerprint_sha256)
      AND EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256 AND e.state <> 'gone'))
SELECT (SELECT count(*) FROM u)::int, (SELECT count(*) FROM u WHERE not_after >= $1 AND not_after <= $2)::int,
    (SELECT count(*) FROM discovery_scopes WHERE deleted_at IS NULL)::int, (SELECT max(finished_at) FROM discovery_scans)`,
		now, now.AddDate(0, 0, 30)).Scan(&out.UnmanagedTotal, &out.UnmanagedExpiring30d, &out.Scopes, &out.LastScanAt)
	if err != nil {
		return Summary{}, fmt.Errorf("discoverysvc: read the summary: %w", err)
	}
	out.LastScanAt = utcPtr(out.LastScanAt)
	return out, nil
}
