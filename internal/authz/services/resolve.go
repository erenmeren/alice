package services

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrResourceNotFound: the resource a resolver was asked about does not exist (or is deleted).
var ErrResourceNotFound = errors.New("services: resource not found")

// Resolution is where a resource belongs (design §4.5): the owning service (writes need rights there) and the services
// it is visible from (reads need rights on one of them; the owning service is always one). Certificates and SSH keys
// are de-duplicated installation-wide, so one row can be on servers of several services.
type Resolution struct {
	Owning  uuid.UUID
	Visible []uuid.UUID
}

// resolvers is one indexed query per resource kind: the owning service, then every service the row is visible from.
var resolvers = map[string]string{
	KindTarget: `SELECT service_id, ARRAY[service_id] FROM targets WHERE id = $1 AND deleted_at IS NULL`,
	// A certificate: owning, the servers holding a live location of it, the vault of a Key Vault version that is it, and
	// the ACME certificate whose current or an earlier certificate it is.
	KindCertificate: `SELECT c.service_id, ARRAY(
    SELECT c.service_id
    UNION SELECT t.service_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id
        WHERE l.certificate_id = c.id AND l.missing_since IS NULL AND t.deleted_at IS NULL
    UNION SELECT v.service_id FROM kv_certificate_versions kv JOIN kv_certificates kc ON kc.id = kv.kv_certificate_id
        JOIN targets v ON v.id = kc.target_id WHERE kv.certificate_id = c.id AND v.deleted_at IS NULL
    UNION SELECT ac.service_id FROM acme_certificates ac WHERE ac.current_certificate_id = c.id
    UNION SELECT ac.service_id FROM acme_orders o JOIN acme_certificates ac ON ac.id = o.acme_certificate_id WHERE o.certificate_id = c.id)
FROM certificates c WHERE c.id = $1`,
	KindCSR: `SELECT service_id, ARRAY[service_id] FROM csr_requests WHERE id = $1`,
	KindSSHKey: `SELECT k.service_id, ARRAY(
    SELECT k.service_id
    UNION SELECT t.service_id FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id
        WHERE l.ssh_key_id = k.id AND l.missing_since IS NULL AND t.deleted_at IS NULL)
FROM ssh_keys k WHERE k.id = $1`,
	KindACMECertificate: `SELECT ac.service_id, ARRAY(
    SELECT ac.service_id
    UNION SELECT t.service_id FROM acme_bindings ab JOIN certificate_locations l ON l.id = ab.location_id
        JOIN targets t ON t.id = l.target_id WHERE ab.acme_certificate_id = ac.id AND t.deleted_at IS NULL)
FROM acme_certificates ac WHERE ac.id = $1 AND ac.deleted_at IS NULL`,
	KindDiscoveryScope: `SELECT service_id, ARRAY[service_id] FROM discovery_scopes WHERE id = $1 AND deleted_at IS NULL`,
}

// Resolve answers where a resource of kind belongs. ErrResourceNotFound; an unknown kind is an error.
func (s *Store) Resolve(ctx context.Context, kind string, id uuid.UUID) (Resolution, error) {
	q, ok := resolvers[kind]
	if !ok {
		return Resolution{}, fmt.Errorf("services: no resolver for %q", kind)
	}
	var r Resolution
	err := s.pool.QueryRow(ctx, q, id).Scan(&r.Owning, &r.Visible)
	if errors.Is(err, pgx.ErrNoRows) {
		return Resolution{}, ErrResourceNotFound
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("services: resolve the %s: %w", kind, err)
	}
	slices.SortFunc(r.Visible, func(a, b uuid.UUID) int { return compareIDs(a, b) })
	return r, nil
}

func compareIDs(a, b uuid.UUID) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
