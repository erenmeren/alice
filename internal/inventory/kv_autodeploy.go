package inventory

// Automatic deployment of renewed Key Vault certificates (spec §11.6; R40 rows 20, 21): the transactional
// half. planAutoDeploy (kv_autodeploy_plan.go) decides; this file reads the snapshot of one binding
// under its locks, applies the plan in the same transaction and writes the marks that make every notice
// and every stop happen once.
//
// Locks, in the order of bindings.go: the vault (FOR NO KEY UPDATE), the binding (FOR UPDATE), the
// Nginx servers (id order), the websites (id order). Both of the first two are taken with SKIP LOCKED: a
// binding someone is changing, or a vault a poll's batch is storing, is simply planned at the next run.
// No lock is assumed to outlive its transaction (D24): the candidates are chosen without a lock, and
// each binding is read, decided and written in one transaction of its own, so the planner is idempotent
// and can run from several polls at once; a deployment is created by the same insertDeployment as a
// manual request, after the same location checks, and deployments_one_active is the backstop.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/rbac"
)

// PlanKVAutoDeploy runs the planner once over the bindings that may have work and returns how many
// deployments it created (at most autoDeployBatch, 50, in all; AutoDeployWave per binding). It does
// nothing while the licence gate refuses changes (kv.auto_deploy is a ClassChange job; the gate is read
// again inside each binding's transaction). A binding whose planning failed is skipped for this run;
// the others are still planned and the errors are returned together. The deployments are the Phase 4
// kind (trigger kv_renewal, job kind system, audit deployment.requested); notices and stops are
// described at planAutoDeploy. Audit rows: kv.auto_deploy.stopped.
func (s *Service) PlanKVAutoDeploy(ctx context.Context) (int, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return 0, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT b.id FROM bindings b
JOIN targets t ON t.id = b.kv_target_id AND t.deleted_at IS NULL AND t.status IN ('ok', 'degraded')
JOIN kv_certificates kc ON kc.id = b.kv_certificate_id AND kc.missing_since IS NULL
JOIN kv_certificate_versions v ON v.kv_certificate_id = kc.id AND v.version = kc.current_version
WHERE b.deleted_at IS NULL AND (
    ((v.held OR NOT b.auto_deploy) AND v.notified_at IS NULL AND coalesce(v.kv_created_at, v.detected_at) > b.created_at)
 OR (b.auto_deploy AND NOT v.held AND v.version <> b.stopped_version AND EXISTS (
        SELECT 1 FROM certificate_locations l WHERE l.binding_id = b.id AND l.certificate_id IS DISTINCT FROM v.certificate_id
          AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.kv_version_id = v.id AND d.location_id = l.id AND d.status IN ('succeeded', 'unchanged')))))
ORDER BY b.id LIMIT $1`, autoDeployBindings)
	if err != nil {
		return 0, fmt.Errorf("inventory: find the bindings to plan: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("inventory: find the bindings to plan: %w", err)
	}
	var (
		created int
		errs    []error
	)
	for _, id := range ids {
		if created >= autoDeployBatch {
			break
		}
		n, err := s.planBinding(ctx, id, autoDeployBatch-created)
		created += n
		if err != nil {
			if errors.Is(err, ErrClaimLost) || ctx.Err() != nil {
				return created, err
			}
			errs = append(errs, err)
		}
	}
	return created, errors.Join(errs...)
}

// planBinding plans one binding in one transaction (see the file comment). It returns the number of
// deployments created.
func (s *Service) planBinding(ctx context.Context, id uuid.UUID, remaining int) (int, error) {
	created := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		created = 0
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var vaultID uuid.UUID
		err := tx.QueryRow(ctx, "SELECT kv_target_id FROM bindings WHERE id = $1 AND deleted_at IS NULL", id).Scan(&vaultID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inventory: find the binding's vault: %w", err)
		}
		var (
			vaultName, vaultURL, vaultStatus string
		)
		err = tx.QueryRow(ctx, `SELECT name::text, coalesce(config->>'vault_url', ''), status FROM targets
WHERE id = $1 AND type = 'azure_key_vault' AND deleted_at IS NULL FOR NO KEY UPDATE SKIP LOCKED`, vaultID).Scan(&vaultName, &vaultURL, &vaultStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // deleted, or busy: the next run
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the vault: %w", err)
		}
		var (
			sn                planSnapshot
			certID            uuid.UUID
			certName, current string
			since             *time.Time
			missing           bool
		)
		err = tx.QueryRow(ctx, `SELECT b.kv_certificate_id, kc.name, kc.current_version, kc.missing_since IS NOT NULL, b.auto_deploy, b.auto_since,
    b.stopped_version, b.created_at
FROM bindings b JOIN kv_certificates kc ON kc.id = b.kv_certificate_id
WHERE b.id = $1 AND b.deleted_at IS NULL FOR UPDATE OF b SKIP LOCKED`, id).Scan(&certID, &certName, &current, &missing, &sn.autoDeploy, &since,
			&sn.stoppedVersion, &sn.bindingCreated)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the binding: %w", err)
		}
		// The gate is read again here: the licence may have locked since the run began.
		if s.license.Allow(license.ClassChange) != nil {
			return nil
		}
		now := s.clock.Now().UTC()
		sn.now, sn.gateOpen, sn.certificateMissing, sn.autoSince = now, true, missing, utcPtr(since)
		sn.vaultOK = vaultStatus == StatusOK || vaultStatus == StatusDegraded
		sn.bindingCreated = sn.bindingCreated.UTC()
		sn.remaining = remaining
		if err := s.readPlanSnapshot(ctx, tx, id, certID, current, &sn); err != nil {
			return err
		}
		p := planAutoDeploy(sn)
		var cur *planVersion
		for i := range sn.versions {
			if sn.versions[i].current {
				cur = &sn.versions[i]
			}
		}

		// Websites first: a vanished server aborts before anything is written, and the next run sees it gone.
		if len(p.deploy) > 0 && p.budget > 0 && cur != nil && cur.leaf != nil {
			leaf, err := readDeployCertificate(ctx, tx, *cur.leaf)
			if err != nil {
				return err
			}
			targets, locs, err := s.lockDeployTargets(ctx, tx, p.deploy)
			if errors.Is(err, ErrNotFound) {
				s.log.Debug("automatic deployment skipped: a website or its server is gone", "binding_id", id)
				return nil
			}
			if err != nil {
				return err
			}
			dv := deployVersion{id: cur.id, certificate: certID, certificateRow: cur.leaf, version: cur.version, enabled: cur.enabled,
				exportable: cur.exportable, held: cur.held, heldReason: cur.heldReason}
			// The same judgement of the version as a person's request gets (an Operator's: held is refused).
			if _, err := versionRefusal(dv, kvCertInfo{id: certID, missing: missing}, leaf, Actor{Role: rbac.Operator}, now); err != nil {
				return nil
			}
			a := Actor{Audit: jobsActor}
			src := deploySource{Trigger: triggerKVRenewal, BindingID: &id, KVVersionID: &cur.id, Version: cur.version}
			for _, locID := range p.deploy {
				if created >= p.budget {
					break
				}
				l := locs[locID]
				if _, err := s.checkDeployLocation(ctx, tx, leaf, l, targets[l.target]); err != nil {
					continue // no person asked: no audit row, the website is simply not ready
				}
				if _, err := s.insertDeployment(ctx, tx, a, leaf, l, src, now); err != nil {
					if errors.Is(err, ErrDeploymentInProgress) {
						continue
					}
					return err
				}
				created++
			}
		}

		for _, n := range p.notices {
			col := "notified_at"
			if n.skipped {
				col = "skipped_notified_at"
			}
			var marked bool
			// The mark and the mail are one decision: the mark is set only if nobody set it before.
			if col == "notified_at" {
				err = tx.QueryRow(ctx, "UPDATE kv_certificate_versions SET notified_at = $2 WHERE id = $1 AND notified_at IS NULL RETURNING true", n.version, now).Scan(&marked)
			} else {
				err = tx.QueryRow(ctx, "UPDATE kv_certificate_versions SET skipped_notified_at = $2 WHERE id = $1 AND skipped_notified_at IS NULL RETURNING true", n.version, now).Scan(&marked)
			}
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("inventory: mark the notice: %w", err)
			}
			if s.notifier != nil {
				if err := s.notifier.NotifyAdmins(ctx, tx, n.template, map[string]string{"target_name": vaultName, "certificate_name": certName}); err != nil {
					return fmt.Errorf("inventory: queue the notice: %w", err)
				}
			}
		}

		if p.stop != nil {
			tag, err := tx.Exec(ctx, "UPDATE bindings SET stopped_version = $2, version = version + 1 WHERE id = $1 AND stopped_version <> $2", id, p.stop.name)
			if err != nil {
				return fmt.Errorf("inventory: stop the wave: %w", err)
			}
			if tag.RowsAffected() == 1 {
				if s.notifier != nil {
					if err := s.notifier.NotifyAdmins(ctx, tx, TemplateKVAutoDeployStopped, map[string]string{"target_name": vaultName,
						"certificate_name": certName, "count": strconv.Itoa(p.stop.failed)}); err != nil {
						return fmt.Errorf("inventory: queue the stop notice: %w", err)
					}
				}
				if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.auto_deploy.stopped", ObjectType: "binding",
					ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"binding_id": id.String(), "kv_certificate_id": certID.String(),
						"certificate_name": certName, "version": p.stop.name, "failed_count": strconv.Itoa(p.stop.failed), "vault_url": vaultURL}}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return created, err
}

// readPlanSnapshot fills the version, website and deployment parts of the snapshot (under the locks).
func (s *Service) readPlanSnapshot(ctx context.Context, tx pgx.Tx, binding, cert uuid.UUID, current string, sn *planSnapshot) error {
	horizon := sn.bindingCreated
	if sn.autoSince != nil {
		horizon = *sn.autoSince
	}
	rows, err := tx.Query(ctx, `SELECT v.id, v.version, v.version = $2, v.certificate_id, c.not_before, c.not_after, v.enabled, v.exportable, v.key_type,
    v.not_before, v.expires, v.kv_created_at, v.detected_at, v.held, v.held_reason, v.notified_at, v.skipped_notified_at
FROM kv_certificate_versions v LEFT JOIN certificates c ON c.id = v.certificate_id
WHERE v.kv_certificate_id = $1 AND (v.version = $2 OR v.detected_at > $3) ORDER BY v.detected_at DESC, v.id LIMIT 100`, cert, current, horizon)
	if err != nil {
		return fmt.Errorf("inventory: read the versions: %w", err)
	}
	defer rows.Close()
	var versionIDs []uuid.UUID
	for rows.Next() {
		var v planVersion
		if err := rows.Scan(&v.id, &v.version, &v.current, &v.leaf, &v.leafNotBefore, &v.leafNotAfter, &v.enabled, &v.exportable, &v.keyType,
			&v.notBefore, &v.expires, &v.kvCreatedAt, &v.detectedAt, &v.held, &v.heldReason, &v.notifiedAt, &v.skippedAt); err != nil {
			return fmt.Errorf("inventory: read a version: %w", err)
		}
		v.leafNotBefore, v.leafNotAfter, v.notBefore, v.expires = utcPtr(v.leafNotBefore), utcPtr(v.leafNotAfter), utcPtr(v.notBefore), utcPtr(v.expires)
		v.kvCreatedAt, v.detectedAt = utcPtr(v.kvCreatedAt), v.detectedAt.UTC()
		v.notifiedAt, v.skippedAt = utcPtr(v.notifiedAt), utcPtr(v.skippedAt)
		sn.versions = append(sn.versions, v)
		versionIDs = append(versionIDs, v.id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: read the versions: %w", err)
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT l.id, l.certificate_id, c.not_after FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
LEFT JOIN certificates c ON c.id = l.certificate_id
WHERE l.binding_id = $1 ORDER BY l.id`, binding)
	if err != nil {
		return fmt.Errorf("inventory: read the websites: %w", err)
	}
	var locIDs []uuid.UUID
	for rows.Next() {
		var l planLocation
		if err := rows.Scan(&l.id, &l.served, &l.servedNotAfter); err != nil {
			rows.Close()
			return fmt.Errorf("inventory: read a website: %w", err)
		}
		l.servedNotAfter = utcPtr(l.servedNotAfter)
		sn.locations = append(sn.locations, l)
		locIDs = append(locIDs, l.id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: read the websites: %w", err)
	}

	rows, err = tx.Query(ctx, `SELECT d.location_id, d.kv_version_id, d.trigger = 'kv_renewal', d.state = 'done', d.status, d.error_code, d.created_at, d.finished_at
FROM deployments d
WHERE (d.binding_id = $1 AND (d.kv_version_id = ANY($2) OR d.state <> 'done')) OR (d.state <> 'done' AND d.location_id = ANY($3))
ORDER BY d.created_at, d.id`, binding, versionIDs, locIDs)
	if err != nil {
		return fmt.Errorf("inventory: read the deployments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d planDeployment
		if err := rows.Scan(&d.location, &d.version, &d.automatic, &d.done, &d.status, &d.errorCode, &d.createdAt, &d.finishedAt); err != nil {
			return fmt.Errorf("inventory: read a deployment: %w", err)
		}
		d.createdAt, d.finishedAt = d.createdAt.UTC(), utcPtr(d.finishedAt)
		sn.deployments = append(sn.deployments, d)
	}
	return rows.Err()
}
