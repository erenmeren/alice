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
//
// A resource without an owning service has uuid.Nil as Owning: a discovered certificate (read-only, visible through
// the scopes that saw it) and platform work (a job of no service, visible to global grants only, so Visible is empty).
type Resolution struct {
	Owning  uuid.UUID
	Visible []uuid.UUID
}

// The resource kinds the routes resolve beyond the ones that can be moved (design §4.5, §11): each is derived from
// a parent (a location from its server, a scan from its scope, ...) or carries its services itself (a job, an
// incident).
const (
	KindLocation         = "location"           // a certificate location: its server's service
	KindSSHKeyLocation   = "ssh_key_location"   // an SSH key location: its server's service
	KindDiscoveryScan    = "discovery_scan"     // a scan: its scope's service
	KindDiscoveredCert   = "discovery_cert"     // a discovered certificate (by fingerprint): the scopes that saw it
	KindDeployment       = "deployment"         // a deployment: its server's service; visible from the certificate's too
	KindKVBinding        = "kv_binding"         // a Key Vault binding: the vault's service; visible from its websites' too
	KindIncident         = "incident"           // a key-compromise incident: its certificate's service; visible from service_ids
	KindJob              = "job"                // a job: jobs.service_id (none: platform work)
	KindRotationPolicy   = "rotation_policy"    // a rotation policy: its key's service; visible from the approved ones too
	KindRotationRun      = "rotation_run"       // a rotation run: its policy's
	KindService          = "service"            // a service itself
	KindServiceTrust     = "service_trust"      // a trust: its target service; visible from (and removable by) either side
	KindACMEBindingPlace = "acme_binding_place" // the server of an ACME binding's location (by location id)
	// KindIncidentReach is a certificate as a key-compromise incident would reach it: its service and every service of
	// a server holding a certificate with its key (what certificate_incidents.service_ids records at the start).
	KindIncidentReach = "incident_reach"
	// KindRotationReach is a rotation policy as switching it on or running it reaches: its key's service and every
	// service of a server holding a live location of the key (what approved_service_ids records, design §5.7).
	KindRotationReach = "rotation_reach"
	// KindKVCertificate is a certificate in a Key Vault: its vault's service (the source of a new Key Vault binding).
	KindKVCertificate = "kv_certificate"
)

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

	KindLocation: `SELECT t.service_id, ARRAY[t.service_id] FROM certificate_locations l JOIN targets t ON t.id = l.target_id
WHERE l.id = $1 AND t.deleted_at IS NULL`,
	KindACMEBindingPlace: `SELECT t.service_id, ARRAY[t.service_id] FROM certificate_locations l JOIN targets t ON t.id = l.target_id
WHERE l.id = $1`,
	KindSSHKeyLocation: `SELECT t.service_id, ARRAY[t.service_id] FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id
WHERE l.id = $1 AND t.deleted_at IS NULL`,
	KindDiscoveryScan: `SELECT ds.service_id, ARRAY[ds.service_id] FROM discovery_scans sc JOIN discovery_scopes ds ON ds.id = sc.scope_id
WHERE sc.id = $1`,
	// A discovered certificate: every scope with an endpoint presenting it, as the leaf or in the chain (design §4.5).
	KindDiscoveredCert: `SELECT NULL::uuid, ARRAY(
    SELECT DISTINCT ds.service_id FROM discovery_endpoints e JOIN discovery_scopes ds ON ds.id = e.scope_id
    WHERE e.fingerprint_sha256 = dc.fingerprint_sha256 OR dc.fingerprint_sha256 = ANY (e.chain_fingerprints))
FROM discovery_certificates dc WHERE dc.fingerprint_sha256 = $1`,
	KindDeployment: `SELECT t.service_id, ARRAY(SELECT t.service_id UNION SELECT c.service_id)
FROM deployments d JOIN targets t ON t.id = d.target_id JOIN certificates c ON c.id = d.certificate_id WHERE d.id = $1`,
	KindKVBinding: `SELECT v.service_id, ARRAY(
    SELECT v.service_id
    UNION SELECT t.service_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id
        WHERE l.binding_id = b.id AND t.deleted_at IS NULL)
FROM bindings b JOIN targets v ON v.id = b.kv_target_id WHERE b.id = $1`,
	KindIncident: `SELECT c.service_id, ARRAY(SELECT c.service_id UNION SELECT unnest(i.service_ids))
FROM certificate_incidents i JOIN certificates c ON c.id = i.certificate_id WHERE i.id = $1`,
	KindJob: `SELECT j.service_id, CASE WHEN j.service_id IS NULL THEN '{}'::uuid[] ELSE ARRAY[j.service_id] END FROM jobs j WHERE j.id = $1`,
	KindRotationPolicy: `SELECT k.service_id, ARRAY(SELECT k.service_id UNION SELECT unnest(p.approved_service_ids))
FROM rotation_policies p JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE p.id = $1 AND p.deleted_at IS NULL`,
	KindRotationRun: `SELECT k.service_id, ARRAY(SELECT k.service_id UNION SELECT unnest(p.approved_service_ids))
FROM rotations r JOIN rotation_policies p ON p.id = r.policy_id JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE r.id = $1`,
	KindIncidentReach: `SELECT c.service_id, ARRAY(
    SELECT c.service_id
    UNION SELECT t.service_id FROM certificate_locations l JOIN certificates k ON k.id = l.certificate_id JOIN targets t ON t.id = l.target_id
        WHERE k.public_key_sha256 = c.public_key_sha256 AND l.missing_since IS NULL AND t.deleted_at IS NULL)
FROM certificates c WHERE c.id = $1`,
	KindRotationReach: `SELECT k.service_id, ARRAY(
    SELECT k.service_id
    UNION SELECT t.service_id FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id
        WHERE l.ssh_key_id = k.id AND l.missing_since IS NULL AND t.deleted_at IS NULL)
FROM rotation_policies p JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE p.id = $1 AND p.deleted_at IS NULL`,
	KindKVCertificate: `SELECT v.service_id, ARRAY[v.service_id] FROM kv_certificates kc JOIN targets v ON v.id = kc.target_id
WHERE kc.id = $1 AND v.deleted_at IS NULL`,
	KindService:      `SELECT id, ARRAY[id] FROM services WHERE id = $1`,
	KindServiceTrust: `SELECT target_service_id, ARRAY[source_service_id, target_service_id] FROM service_trusts WHERE id = $1`,
}

// ResolveKinds lists every kind Resolve knows (the API's route table and its scoped IDOR test name them).
func ResolveKinds() []string {
	out := make([]string, 0, len(resolvers))
	for k := range resolvers {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Resolve answers where a resource of kind belongs. id is the resource's id (a uuid.UUID), or the fingerprint (a
// string) of a discovered certificate. ErrResourceNotFound; an unknown kind is an error.
func (s *Store) Resolve(ctx context.Context, kind string, id any) (Resolution, error) {
	q, ok := resolvers[kind]
	if !ok {
		return Resolution{}, fmt.Errorf("services: no resolver for %q", kind)
	}
	var r Resolution
	var owning *uuid.UUID
	err := s.pool.QueryRow(ctx, q, id).Scan(&owning, &r.Visible)
	if errors.Is(err, pgx.ErrNoRows) {
		return Resolution{}, ErrResourceNotFound
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("services: resolve the %s: %w", kind, err)
	}
	if owning != nil {
		r.Owning = *owning
	}
	r.Visible = slices.DeleteFunc(r.Visible, func(id uuid.UUID) bool { return id == uuid.Nil })
	slices.SortFunc(r.Visible, func(a, b uuid.UUID) int { return compareIDs(a, b) })
	r.Visible = slices.Compact(r.Visible)
	return r, nil
}

// TargetServices is the service of each of the servers and Key Vaults named (deleted ones included: a detail answer
// may name a location on a deleted server), by id; an unknown id is absent. The detail answers use it to leave out the
// related rows of servers outside the caller's reach (design §5.8, hidden_count).
func (s *Store) TargetServices(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := map[uuid.UUID]uuid.UUID{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, "SELECT id, service_id FROM targets WHERE id = ANY($1)", ids)
	if err != nil {
		return nil, fmt.Errorf("services: read the servers' services: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, service uuid.UUID
		if err := rows.Scan(&id, &service); err != nil {
			return nil, fmt.Errorf("services: read the servers' services: %w", err)
		}
		out[id] = service
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("services: read the servers' services: %w", err)
	}
	return out, nil
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
