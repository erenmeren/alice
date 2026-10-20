package inventory

// Automatic repair of drifted locations (R52 item 4, mode auto): the periodic drift.repair (PlanDriftRepairs,
// continuity work: automatic upkeep of a certificate that is already managed, as certificate.deploy_auto is, R44)
// deploys the desired certificate again to a location whose drift episode is open, through the same insertDeployment as
// every other deployment (trigger drift_repair, the system actor, a certificate.deploy_auto job) after the same
// certificate and location checks as the automatic deployment planners (prepareACMEDeployment, the Key Vault planner's
// versionRefusal), so the deployment engine's guards apply unchanged: the rollback guard (R48), the trust of the served
// chain (R51), the refusal of a revoked or compromised certificate (00021), the compare-and-swap of the file. The job
// judges the repair again before it sends (driftRepairPrecheck).
//
// Two tools managing one file would fight: a repair is made only after an observation newer than the previous repair's
// end, and automatic repair backs off to observe when DriftMaxRepairs repairs of the location within DriftRepairWindow
// all succeeded and the drift came back (BackoffFlapping: "another tool keeps changing this file") or all failed
// (BackoffRepairFailing), with one notice each.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/rbac"
)

// DriftRepairRun counts what one run of the repair planner did.
type DriftRepairRun struct {
	Created, BackedOff int
}

// driftRepairHook runs before a location's repair is planned (tests: the world changes).
var driftRepairHook func(location uuid.UUID)

// PlanDriftRepairs runs the repair planner once over the drifted locations in mode auto (at most driftRepairBatch, the
// oldest drift first). It does nothing while the licence gate refuses continuity work (read again in each location's
// transaction). A location whose planning failed is skipped for this run; the errors are returned together.
func (s *Service) PlanDriftRepairs(ctx context.Context) (DriftRepairRun, error) {
	var run DriftRepairRun
	if s.license.Allow(license.ClassContinuity) != nil {
		return run, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT o.location_id FROM location_observations o
JOIN certificate_locations l ON l.id = o.location_id AND l.missing_since IS NULL
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
WHERE o.drift_since IS NOT NULL AND o.backed_off_at IS NULL AND (o.drift_mode IS NULL OR o.drift_mode = 'auto')
  AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.location_id = o.location_id AND d.state <> 'done')
ORDER BY o.drift_since, o.location_id LIMIT $1`, driftRepairBatch)
	if err != nil {
		return run, fmt.Errorf("inventory: find the drifted locations: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return run, fmt.Errorf("inventory: find the drifted locations: %w", err)
	}
	var errs []error
	for _, id := range ids {
		if driftRepairHook != nil {
			driftRepairHook(id)
		}
		if err := s.planDriftRepair(ctx, id, &run); err != nil {
			if errors.Is(err, ErrClaimLost) || ctx.Err() != nil {
				return run, errors.Join(append(errs, err)...)
			}
			errs = append(errs, err)
		}
	}
	return run, errors.Join(errs...)
}

// driftRepairRecord is one earlier repair of a location.
type driftRepairRecord struct {
	status     string
	finishedAt *time.Time
}

// errDriftRepairSkip rolls a location's transaction back without an error (the next run looks again).
var errDriftRepairSkip = errors.New("inventory: the location is repaired at a later run")

// planDriftRepair decides one location in one transaction, under its observation row's lock (SKIP LOCKED: a location
// someone is changing is planned at the next run): the health again (still drifted, still auto, no back-off), no open
// key-compromise incident on it, an observation newer than the last repair's end and a scan of the file newer than the
// last deployment (the repair's compare-and-swap needs the file's current hash), then the back-off rule, then the
// deployment.
func (s *Service) planDriftRepair(ctx context.Context, id uuid.UUID, run *DriftRepairRun) error {
	var created, backedOff int
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		created, backedOff = 0, 0
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var locked uuid.UUID
		err := tx.QueryRow(ctx, "SELECT location_id FROM location_observations WHERE location_id = $1 FOR UPDATE SKIP LOCKED", id).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return errDriftRepairSkip
		}
		if err != nil {
			return fmt.Errorf("inventory: lock the location's observations: %w", err)
		}
		if s.license.Allow(license.ClassContinuity) != nil {
			return errDriftRepairSkip
		}
		m, err := s.locationObservations(ctx, tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		o, ok := m[id]
		if !ok || o.Health != HealthDrifted || o.Mode != DriftModeAuto || o.BackedOffAt != nil || o.DriftSince == nil || o.Desired == nil ||
			o.Desired.CertificateID == nil || o.SourceID == nil {
			return errDriftRepairSkip
		}
		var incident bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificate_incident_locations il JOIN certificate_incidents i ON i.id = il.incident_id
WHERE il.location_id = $1 AND i.finished_at IS NULL)`, id).Scan(&incident); err != nil {
			return fmt.Errorf("inventory: read the location's incidents: %w", err)
		}
		if incident {
			return errDriftRepairSkip // the incident decides what the location gets
		}
		now := s.clock.Now().UTC()
		rows, err := tx.Query(ctx, `SELECT status, finished_at FROM deployments WHERE location_id = $1 AND trigger = $2 AND created_at > $3
ORDER BY created_at DESC, id DESC`, id, TriggerDriftRepair, now.Add(-DriftRepairWindow))
		if err != nil {
			return fmt.Errorf("inventory: read the location's repairs: %w", err)
		}
		repairs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (driftRepairRecord, error) {
			var d driftRepairRecord
			err := r.Scan(&d.status, &d.finishedAt)
			return d, err
		})
		if err != nil {
			return fmt.Errorf("inventory: read the location's repairs: %w", err)
		}
		latest := o.TLSAttemptAt
		if o.File != nil && newer(&o.File.At, latest) {
			latest = &o.File.At
		}
		if len(repairs) > 0 && (repairs[0].finishedAt == nil || !newer(latest, repairs[0].finishedAt)) {
			return errDriftRepairSkip // nothing was observed since the last repair ended
		}
		var lastDeployed *time.Time
		if o.LastDeployment != nil {
			lastDeployed = o.LastDeployment.At
		}
		if o.File == nil || !newer(&o.File.At, lastDeployed) {
			return errDriftRepairSkip // the file was not scanned since the last deployment: its hash is not known
		}
		var good, bad int
		for _, r := range repairs {
			switch r.status {
			case DeployStatusSucceeded, DeployStatusUnchanged:
				good++
			case DeployStatusFailed, DeployStatusRolledBack, DeployStatusRollbackFailed:
				bad++
			}
		}
		switch {
		case good >= DriftMaxRepairs:
			backedOff = 1
			return s.driftBackoff(ctx, tx, o, BackoffFlapping, TemplateDriftFlapping, good, now)
		case bad >= DriftMaxRepairs:
			backedOff = 1
			return s.driftBackoff(ctx, tx, o, BackoffRepairFailing, TemplateDriftRepairFailing, bad, now)
		}
		n, err := s.insertDriftRepair(ctx, tx, o, now)
		created = n
		return err
	})
	if errors.Is(err, errDriftRepairSkip) {
		return nil
	}
	if err == nil {
		run.Created += created
		run.BackedOff += backedOff
	}
	return err
}

// insertDriftRepair queues the repair of o (see the file comment) and reports whether it did: a desired certificate
// that cannot be deployed unattended (no private key, a key type Alice cannot deploy, expired, not yet valid, revoked
// or compromised, an incomplete chain; for a Key Vault version: held, disabled, missing, not exportable) or a location
// that is not ready (checkDeployLocation) is left for the next run, without an audit row: no person asked.
func (s *Service) insertDriftRepair(ctx context.Context, tx pgx.Tx, o LocationObservation, now time.Time) (int, error) {
	c, err := readDeployCertificate(ctx, tx, *o.Desired.CertificateID)
	if err != nil {
		return 0, err
	}
	if c.algorithm != "rsa" && c.algorithm != "ecdsa" || !now.Before(c.notAfter) || now.Before(c.notBefore) || c.revoked || c.compromised {
		return 0, nil
	}
	src := deploySource{Trigger: TriggerDriftRepair}
	switch o.Source {
	case DriftSourceACME:
		if c.keyID == nil || !c.chainComplete {
			return 0, nil // an incomplete chain needs an Administrator's confirmation, which a repair never gives
		}
	case DriftSourceKeyVault:
		binding := *o.SourceID
		v := deployVersion{}
		err := tx.QueryRow(ctx, `SELECT v.id, v.kv_certificate_id, v.certificate_id, v.version, v.enabled, v.exportable, v.held, v.held_reason,
    v.chain_incomplete
FROM bindings kb JOIN kv_certificates kc ON kc.id = kb.kv_certificate_id
JOIN kv_certificate_versions v ON v.kv_certificate_id = kc.id AND v.version = kc.current_version
WHERE kb.id = $1 AND kb.deleted_at IS NULL FOR SHARE OF v`, binding).Scan(&v.id, &v.certificate, &v.certificateRow, &v.version, &v.enabled,
			&v.exportable, &v.held, &v.heldReason, &v.chainIncomplete)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		if err != nil {
			return 0, fmt.Errorf("inventory: read the binding's current version: %w", err)
		}
		kc, err := kvCertificateOf(ctx, tx, v.certificate)
		if err != nil {
			return 0, err
		}
		// The same judgement of the version as the Key Vault planner's (an Operator's: a held version is refused).
		if _, err := versionRefusal(v, kc, c, Actor{Role: rbac.Operator}, now); err != nil || v.chainIncomplete {
			return 0, nil
		}
		src.BindingID, src.KVVersionID, src.Version = &binding, &v.id, v.version
	default:
		return 0, nil
	}
	targets, locs, err := s.lockDeployTargets(ctx, tx, []uuid.UUID{o.LocationID})
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	l := locs[o.LocationID]
	if _, err := s.checkDeployLocation(ctx, tx, c, l, targets[l.target]); err != nil {
		return 0, nil
	}
	r, err := s.insertDeployment(ctx, tx, Actor{Audit: jobsActor}, c, l, src, now)
	if errors.Is(err, ErrDeploymentInProgress) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "location.drift_repair_requested", ObjectType: "certificate_location",
		ObjectID: o.LocationID.String(), Result: audit.Success, Details: map[string]string{"location_id": o.LocationID.String(),
			"deployment_id": r.ID.String(), "certificate_id": c.id.String(), "cert_path": o.certPath,
			"drift_since": o.DriftSince.UTC().Format(time.RFC3339)}}); err != nil {
		return 0, err
	}
	return 1, nil
}

// driftBackoff switches automatic repair of o off (mode observe, the reason and the time; audit location.drift_backoff)
// and sends template once (the ledger names the back-off's time).
func (s *Service) driftBackoff(ctx context.Context, tx pgx.Tx, o LocationObservation, reason, template string, count int, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE location_observations SET drift_mode = 'observe', backoff_reason = $2, backed_off_at = $3, updated_at = $3
WHERE location_id = $1`, o.LocationID, reason, now); err != nil {
		return fmt.Errorf("inventory: back off the automatic repair: %w", err)
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "location.drift_backoff", ObjectType: "certificate_location",
		ObjectID: o.LocationID.String(), Result: audit.Success, Details: map[string]string{"location_id": o.LocationID.String(),
			"target_id": o.TargetID.String(), "cert_path": o.certPath, "reason": reason, "repairs": fmt.Sprint(count),
			"window_hours": fmt.Sprint(int(DriftRepairWindow.Hours()))}}); err != nil {
		return err
	}
	return s.driftNotice(ctx, tx, driftBackoffKind, template, o, now, o.DriftFingerprint)
}
