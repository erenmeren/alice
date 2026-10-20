package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/providers"
)

// The rollback guard (R48, docs/superpowers/rulings/certificate-revocation.md "Rollback guard"): no rollback puts a
// revoked or compromised certificate, or a compromised key, back on a server. A rollback restores the files a
// deployment replaced, so what it may put back is the certificate the location's file held when the deployment started:
// StartDeployment records its leaf fingerprint and public key hash (deployments.rollback_leaf_sha256 and
// rollback_spki_sha256, 00023), and RollbackGuard reads them against the marks of 00021 every time it is asked (at the
// start, before the provider's own rollback, before every rollback of a recovery), so a certificate marked compromised
// while the deployment runs is still refused. A refused rollback restores nothing: the files stay as the failed
// deployment left them and the deployment ends rollback_failed with deployment.rollback_forbidden (the website may stay
// broken until another certificate is deployed: security first).
//
// The guard also carries the forbidden material itself, for the helper's own check of the backup it would restore
// (defence in depth: Alice's knowledge of the file may be wrong, and an unknown operation's backup is unknown to it):
// every compromised key and every unexpired revoked certificate, newest first, the deployment's own backup first, each
// list at most providers.MaxForbidden.

// Rollback target verdicts of the deployment.started audit row (detail "rollback").
const (
	rollbackAllowed   = "allowed"
	rollbackForbidden = "forbidden"
	rollbackUnknown   = "unknown" // the file's certificate was not known: only the helper's own check applies
)

// RollbackGuard is the rollback guard of a deployment as it stands now: the recorded backup's certificate once the
// deployment started, the location's current certificate before (see the comment at the top of this file). Required is
// set when the backup is forbidden (or unknown while anything is forbidden) or the location is one an open
// key-compromise incident replaces: such a deployment never runs on a helper that cannot check the guard itself.
func (s *Service) RollbackGuard(ctx context.Context, deploymentID uuid.UUID) (providers.RollbackGuard, error) {
	var (
		leaf, spki string
		location   uuid.UUID
		recorded   bool
	)
	err := s.pool.QueryRow(ctx, `SELECT d.location_id, d.operation_id IS NOT NULL,
    CASE WHEN d.operation_id IS NOT NULL THEN d.rollback_leaf_sha256 ELSE coalesce(c.fingerprint_sha256, '') END,
    CASE WHEN d.operation_id IS NOT NULL THEN d.rollback_spki_sha256 ELSE coalesce(c.public_key_sha256, '') END
FROM deployments d
JOIN certificate_locations l ON l.id = d.location_id
LEFT JOIN certificates c ON c.id = l.certificate_id
WHERE d.id = $1`, deploymentID).Scan(&location, &recorded, &leaf, &spki)
	if errors.Is(err, pgx.ErrNoRows) {
		return providers.RollbackGuard{}, ErrNotFound
	}
	if err != nil {
		return providers.RollbackGuard{}, fmt.Errorf("inventory: read the deployment's rollback target: %w", err)
	}
	return rollbackGuard(ctx, s.pool, location, leaf, spki, s.clock.Now().UTC())
}

// rollbackGuard builds the guard of a backup holding the certificate leaf (public key spki; either may be "") at a
// location.
func rollbackGuard(ctx context.Context, q db.Querier, location uuid.UUID, leaf, spki string, now time.Time) (providers.RollbackGuard, error) {
	var g providers.RollbackGuard
	var leafForbidden, keyForbidden, incident bool
	err := q.QueryRow(ctx, `SELECT
    EXISTS (SELECT 1 FROM certificates WHERE $1 <> '' AND fingerprint_sha256 = $1 AND (revoked_at IS NOT NULL OR compromised_at IS NOT NULL)),
    EXISTS (SELECT 1 FROM certificates WHERE $2 <> '' AND public_key_sha256 = $2 AND compromised_at IS NOT NULL),
    EXISTS (SELECT 1 FROM certificate_incident_locations il JOIN certificate_incidents i ON i.id = il.incident_id
            WHERE il.location_id = $3 AND i.finished_at IS NULL AND il.status IN ('pending', 'deploying'))`, leaf, spki, location).
		Scan(&leafForbidden, &keyForbidden, &incident)
	if err != nil {
		return g, fmt.Errorf("inventory: check the rollback target: %w", err)
	}
	g.TargetForbidden = leafForbidden || keyForbidden
	g.TargetUnknown = leaf == "" && spki == ""
	if keyForbidden {
		g.ForbiddenSPKI = append(g.ForbiddenSPKI, spki)
	}
	if leafForbidden {
		g.ForbiddenLeaf = append(g.ForbiddenLeaf, leaf)
	}
	// Every compromised key (keys do not expire), newest compromise first.
	rows, err := q.Query(ctx, `SELECT public_key_sha256 FROM certificates WHERE compromised_at IS NOT NULL AND public_key_sha256 <> $1
GROUP BY public_key_sha256 ORDER BY max(compromised_at) DESC, public_key_sha256 LIMIT $2`, spki, providers.MaxForbidden)
	if err != nil {
		return g, fmt.Errorf("inventory: read the compromised keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return g, fmt.Errorf("inventory: read the compromised keys: %w", err)
	}
	// Revoked certificates that are still valid (an expired one is refused by every client anyway, ruling 3); a
	// compromised certificate is covered by its key.
	rows, err = q.Query(ctx, `SELECT fingerprint_sha256 FROM certificates WHERE revoked_at IS NOT NULL AND compromised_at IS NULL
    AND not_after > $1 AND fingerprint_sha256 <> $2
ORDER BY revoked_at DESC, fingerprint_sha256 LIMIT $3`, now, leaf, providers.MaxForbidden)
	if err != nil {
		return g, fmt.Errorf("inventory: read the revoked certificates: %w", err)
	}
	leaves, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return g, fmt.Errorf("inventory: read the revoked certificates: %w", err)
	}
	g.ForbiddenSPKI = capped(g.ForbiddenSPKI, keys)
	g.ForbiddenLeaf = capped(g.ForbiddenLeaf, leaves)
	g.Required = g.RefusesUnchecked() || incident
	return g, nil
}

// capped appends more to first (the backup's own entry, when forbidden) up to providers.MaxForbidden entries.
func capped(first, more []string) []string {
	out := append([]string{}, first...)
	for _, h := range more {
		if len(out) == providers.MaxForbidden {
			break
		}
		out = append(out, h)
	}
	return out
}

// rollbackVerdict is the audit detail of a guard: allowed, forbidden, or unknown (the file's certificate was not known).
func rollbackVerdict(g providers.RollbackGuard, leaf string) string {
	switch {
	case g.TargetForbidden:
		return rollbackForbidden
	case g.TargetUnknown || leaf == "":
		return rollbackUnknown
	}
	return rollbackAllowed
}
