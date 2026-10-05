package sshkeys

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/sshkeys/keymat"
	"alice/internal/sshkeys/plan"
)

// systemActor is the actor of the module's periodic work.
var systemActor = inventory.Actor{Audit: audit.SystemActor("jobs")}

// PlanDue (task rotation.plan) creates the previewed run of every enabled policy whose notice is
// due (plan.NoticeDue) and that has no open run; the run starts at plan.PlannedFor, never before
// the full notice period. A plan with nothing to change creates nothing (it is tried again at the
// next tick, without an email); a key the planner refuses switches its policy off. In lock nothing
// is planned (L-88: no email; the policy previews again after the renewal). It returns the number of
// runs created; one policy's failure does not stop the others.
func (s *Service) PlanDue(ctx context.Context) (int, error) {
	if s.license.Allow(license.ClassChange) != nil {
		return 0, nil
	}
	now := s.clock.Now().UTC()
	rows, err := s.pool.Query(ctx, `SELECT p.id FROM rotation_policies p
WHERE p.enabled AND p.deleted_at IS NULL AND p.next_run_at IS NOT NULL
  AND p.next_run_at - make_interval(hours => p.notify_before_hours) <= $1
  AND NOT EXISTS (SELECT 1 FROM rotations r WHERE r.policy_id = p.id AND r.status NOT IN `+finishedStatuses+`)
ORDER BY p.next_run_at, p.id`, now)
	if err != nil {
		return 0, fmt.Errorf("sshkeys: list due policies: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("sshkeys: list due policies: %w", err)
	}
	n := 0
	var errs []error
	for _, id := range ids {
		created, err := s.planOne(ctx, id)
		if err != nil {
			s.log.Error("could not plan a rotation", "policy_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			errs = append(errs, err)
			continue
		}
		if created {
			n++
		}
	}
	return n, errors.Join(errs...)
}

// planOne plans one due policy under its row lock.
func (s *Service) planOne(ctx context.Context, id uuid.UUID) (bool, error) {
	created := false
	err := s.inPolicyTx(ctx, id, func(tx pgx.Tx, pol policyRow, run *runRow) error {
		now := s.clock.Now().UTC()
		if run != nil || !pol.Enabled || pol.NextRunAt == nil || !plan.Due(now, plan.NoticeDue(*pol.NextRunAt, pol.NotifyBeforeHours)) {
			return nil
		}
		plannedFor := plan.PlannedFor(now, *pol.NextRunAt, pol.NotifyBeforeHours)
		in, key, err := s.loadPlanInput(ctx, tx, pol, plannedFor, true)
		if err != nil {
			return err
		}
		p, err := plan.Build(in)
		switch {
		case errors.Is(err, plan.ErrNothingToRotate):
			s.log.Info("rotation not planned: no location can change", "policy_id", id.String())
			return nil
		case err != nil:
			// The key can no longer be rotated (Alice's own key, retired, …): the policy cannot run.
			if _, err := tx.Exec(ctx, `UPDATE rotation_policies SET enabled = false, next_run_at = NULL, version = version + 1, updated_at = $2
WHERE id = $1`, id, now); err != nil {
				return policyWriteError(err)
			}
			return s.switchedOff(ctx, tx, systemActor.Audit, id, nil, plannerDisableReason(err))
		}
		if _, err := s.insertRun(ctx, tx, pol, key, p, p.Digest(), TriggerScheduled, plannedFor, systemActor); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created && err == nil, err
}

// RunNow starts a rotation at once (an Administrator with step-up; the route checks it). digest
// must be the digest of the preview the Administrator saw: when the plan built now differs, nothing
// is created or started (ErrPlanChanged; the plan is never silently re-planned). Without an open run
// a run is created (trigger manual) and started; a previewed run (dry_run_notified) is started when
// its stored digest and the plan now both equal digest (its notice delivery is not waited for: an
// Administrator is present, S1); any other open run is ErrRotationInProgress.
func (s *Service) RunNow(ctx context.Context, a inventory.Actor, policyID uuid.UUID, digest string) (Rotation, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Rotation{}, err
	}
	var runID uuid.UUID
	err := s.inPolicyTx(ctx, policyID, func(tx pgx.Tx, pol policyRow, run *runRow) error {
		now := s.clock.Now().UTC()
		if run != nil {
			if run.status != StatusDryRunNotified {
				return ErrRotationInProgress
			}
			if run.digest != digest {
				return ErrPlanChanged
			}
		}
		in, key, err := s.loadPlanInput(ctx, tx, pol, now, true)
		if err != nil {
			return err
		}
		p, err := plan.Build(in)
		if err != nil {
			return planError(err)
		}
		if p.Digest() != digest {
			return ErrPlanChanged
		}
		if run != nil {
			runID = run.id
			return nil
		}
		runID, err = s.insertRun(ctx, tx, pol, key, p, digest, TriggerManual, now, a)
		return err
	})
	if err != nil {
		return Rotation{}, err
	}
	if err := s.start(ctx, runID, a); err != nil {
		return Rotation{}, err
	}
	return s.Rotation(ctx, runID)
}

// start moves a previewed run to adding_new (C8 "dry_run_notified → adding_new"; Task 9's Advance
// calls it for a scheduled run). The new key is generated outside the transaction in a generation
// slot (ErrGenerateBusy: the run stays as it is). In one transaction (run, then policy, then targets
// and locations locked): the run must still be previewed; the plan is built again and must have the
// run's digest, otherwise the run is cancelled (rotation.plan_changed) and ErrPlanChanged returned;
// then the new key is stored (rotated_from = the old key, the old key's label, a comment of today),
// set on the run with the status, the policy's next run counted from now, and one rotation.location
// job (phase add) queued per planned location.
func (s *Service) start(ctx context.Context, runID uuid.UUID, a inventory.Actor) error {
	run, err := readRunRow(ctx, s.pool, runID)
	if err != nil {
		return err
	}
	if run.status != StatusDryRunNotified {
		return nil
	}
	m, err := s.generate(ctx, keymat.KeyType(run.newKeyType))
	if err != nil {
		return err
	}
	defer m.PKCS8.Zero()
	changed := false
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, runID)
		if err != nil || run.status != StatusDryRunNotified {
			return err
		}
		pol, err := scanPolicy(tx.QueryRow(ctx, policySelect+" WHERE p.id = $1 FOR UPDATE OF p", run.policyID))
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		in, oldKey, err := s.loadPlanInput(ctx, tx, pol, now, true)
		if err != nil {
			return err
		}
		p, err := plan.Build(in)
		if err != nil || p.Digest() != run.digest || pol.deleted {
			changed = true
			return s.cancelRun(ctx, tx, a.Audit, run, ReasonPlanChanged)
		}
		nk, err := s.storeGeneratedTx(ctx, tx, a.Audit, a.UserID, m, oldKey.label, &oldKey.id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rotations SET new_ssh_key_id = $2, status = $3, started_at = $4, updated_at = $4, version = version + 1
WHERE id = $1`, runID, nk.ID, StatusAddingNew, now); err != nil {
			return fmt.Errorf("sshkeys: start the rotation: %w", err)
		}
		if pol.Enabled {
			if _, err := tx.Exec(ctx, "UPDATE rotation_policies SET next_run_at = $2 WHERE id = $1", pol.ID,
				plan.NextRun(now, pol.IntervalDays)); err != nil {
				return policyWriteError(err)
			}
		}
		if err := s.recordRunStatus(ctx, tx, a.Audit, runID, StatusDryRunNotified, StatusAddingNew, "", now); err != nil {
			return err
		}
		return s.queueLocationJobs(ctx, tx, a, runID, LocPlanned, "add")
	})
	if err == nil && changed {
		return ErrPlanChanged
	}
	return err
}

// queueLocationJobs queues one rotation.location job of the phase for every location of the run in
// the state (C1 payload and dedupe).
func (s *Service) queueLocationJobs(ctx context.Context, tx pgx.Tx, a inventory.Actor, runID uuid.UUID, state, phase string) error {
	rows, err := tx.Query(ctx, "SELECT id, target_id FROM rotation_locations WHERE rotation_id = $1 AND state = $2 ORDER BY n", runID, state)
	if err != nil {
		return fmt.Errorf("sshkeys: read the run's locations: %w", err)
	}
	type loc struct{ id, target uuid.UUID }
	locs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (loc, error) {
		var l loc
		err := r.Scan(&l.id, &l.target)
		return l, err
	})
	if err != nil {
		return fmt.Errorf("sshkeys: read the run's locations: %w", err)
	}
	for _, l := range locs {
		if _, err := s.jobs.EnqueueTx(ctx, tx, inventory.JobRequest{Type: JobRotationLocation, TargetID: l.target, Kind: jobKind(a),
			CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: JobRotationLocation + ":" + l.id.String() + ":" + phase,
			Payload: map[string]string{"rotation_id": runID.String(), "location_id": l.id.String(), "phase": phase}}); err != nil {
			return err
		}
	}
	return nil
}

// noticeDelivered reports whether the run's rotation.preview reached at least one Administrator
// (outbox status sent; skipped_no_smtp, pending and failed are not delivered: S1).
func (s *Service) noticeDelivered(ctx context.Context, q db.Querier, runID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notifications_outbox WHERE template_key = $1 AND params->>'rotation_id' = $2
AND status = 'sent')`, TemplatePreview, runID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("sshkeys: read the run's notice: %w", err)
	}
	return ok, nil
}
