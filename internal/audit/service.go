package audit

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// serviceOf is how the owning service of an audit row's object is read (R49 Phase 2, design §5.8: "every audit row
// about a resource carries details.service_id, the owning service at that time", so a scoped audit view can follow
// without a migration of the chain). One indexed query per object type, in the transaction of the row: the service the
// object belongs to as the change commits. Object types without a service (people, settings, the license, ...) are
// absent.
var serviceOf = map[string]string{
	"target":                 `SELECT service_id FROM targets WHERE id = $1`,
	"certificate":            `SELECT service_id FROM certificates WHERE id = $1`,
	"csr":                    `SELECT service_id FROM csr_requests WHERE id = $1`,
	"ssh_key":                `SELECT service_id FROM ssh_keys WHERE id = $1`,
	"acme_certificate":       `SELECT service_id FROM acme_certificates WHERE id = $1`,
	"discovery_scope":        `SELECT service_id FROM discovery_scopes WHERE id = $1`,
	"discovery_scan":         `SELECT ds.service_id FROM discovery_scans sc JOIN discovery_scopes ds ON ds.id = sc.scope_id WHERE sc.id = $1`,
	"certificate_location":   `SELECT t.service_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id WHERE l.id = $1`,
	"ssh_key_location":       `SELECT t.service_id FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id WHERE l.id = $1`,
	"host_key":               `SELECT t.service_id FROM host_keys h JOIN targets t ON t.id = h.target_id WHERE h.id = $1`,
	"deployment":             `SELECT t.service_id FROM deployments d JOIN targets t ON t.id = d.target_id WHERE d.id = $1`,
	"binding":                `SELECT v.service_id FROM bindings b JOIN targets v ON v.id = b.kv_target_id WHERE b.id = $1`,
	"kv_certificate":         `SELECT v.service_id FROM kv_certificates kc JOIN targets v ON v.id = kc.target_id WHERE kc.id = $1`,
	"kv_certificate_version": `SELECT v.service_id FROM kv_certificate_versions kv JOIN kv_certificates kc ON kc.id = kv.kv_certificate_id JOIN targets v ON v.id = kc.target_id WHERE kv.id = $1`,
	"kv_import":              `SELECT v.service_id FROM kv_imports i JOIN targets v ON v.id = i.target_id WHERE i.id = $1`,
	"rotation_policy":        `SELECT k.service_id FROM rotation_policies p JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE p.id = $1`,
	"rotation":               `SELECT k.service_id FROM rotations r JOIN rotation_policies p ON p.id = r.policy_id JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE r.id = $1`,
	"certificate_incident":   `SELECT c.service_id FROM certificate_incidents i JOIN certificates c ON c.id = i.certificate_id WHERE i.id = $1`,
	"job":                    `SELECT service_id FROM jobs WHERE id = $1`,
	"deployment_rollout":     `SELECT service_id FROM deployment_rollouts WHERE id = $1`, // the source service (R65)
}

// withServiceID adds details.service_id to an event about a resource that has an owning service, unless the event
// names one itself. An object that is gone (a refusal about an unknown id) or has none (platform work) adds nothing.
// The details map is copied, never changed in place.
func withServiceID(ctx context.Context, tx pgx.Tx, e Event) (map[string]string, error) {
	q, ok := serviceOf[e.ObjectType]
	if !ok {
		return e.Details, nil
	}
	if _, named := e.Details["service_id"]; named {
		return e.Details, nil
	}
	id, err := uuid.Parse(e.ObjectID)
	if err != nil || id == uuid.Nil {
		return e.Details, nil //nolint:nilerr // an object id that is not a row id names no resource
	}
	var service *uuid.UUID
	err = tx.QueryRow(ctx, q, id).Scan(&service)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return e.Details, nil
	case err != nil:
		return nil, fmt.Errorf("audit: read the object's service: %w", err)
	case service == nil:
		return e.Details, nil
	}
	out := make(map[string]string, len(e.Details)+1)
	maps.Copy(out, e.Details)
	out["service_id"] = service.String()
	return out, nil
}
