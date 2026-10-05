package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// Lock order of every transaction that touches a run (deadlock-free with inventory and with each
// other): the rotations row first, then its policy row, then its location rows in n order. A
// transaction that starts from a policy (policy edits) reads the open run's id without a lock, locks
// that run, then the policy, and starts over when another run became open meanwhile (lockPolicyRun).

// runRow is what a transition needs of a run.
type runRow struct {
	id, policyID, oldKeyID          uuid.UUID
	newKeyID                        *uuid.UUID
	status, trigger                 string
	digest, newKeyType              string
	plannedFor                      time.Time
	pausedLicense, awaitingDecision bool
	removalAllowed                  bool
	pausedAt, decisionDueAt         *time.Time
	verifiedAt, overlapUntil        *time.Time
	reminderSentAt, renotifiedAt    *time.Time
	overlapMinutes                  int
	resultCode                      string
	oldFingerprint, oldLabel        string
	newFingerprint                  string
}

const runSelect = `SELECT r.id, r.policy_id, r.old_ssh_key_id, r.new_ssh_key_id, r.status, r.trigger, r.plan_digest, r.new_key_type,
    r.planned_for, r.paused_license, r.awaiting_decision, r.removal_allowed, r.paused_at, r.decision_due_at, r.verified_at,
    r.overlap_until, r.reminder_sent_at, r.renotified_at, r.overlap_minutes, r.result_code, ok.fingerprint_sha256, ok.label,
    coalesce(nk.fingerprint_sha256, '')
FROM rotations r JOIN ssh_keys ok ON ok.id = r.old_ssh_key_id LEFT JOIN ssh_keys nk ON nk.id = r.new_ssh_key_id WHERE r.id = $1`

// lockRun locks a run row (FOR UPDATE OF the run only); ErrNotFound.
func lockRun(ctx context.Context, tx pgx.Tx, id uuid.UUID) (runRow, error) {
	return scanRun(tx.QueryRow(ctx, runSelect+" FOR UPDATE OF r", id))
}

// readRunRow reads a run row without a lock; ErrNotFound.
func readRunRow(ctx context.Context, q db.Querier, id uuid.UUID) (runRow, error) {
	return scanRun(q.QueryRow(ctx, runSelect, id))
}

func scanRun(row pgx.Row) (runRow, error) {
	var r runRow
	err := row.Scan(&r.id, &r.policyID, &r.oldKeyID, &r.newKeyID, &r.status, &r.trigger, &r.digest, &r.newKeyType, &r.plannedFor,
		&r.pausedLicense, &r.awaitingDecision, &r.removalAllowed, &r.pausedAt, &r.decisionDueAt, &r.verifiedAt, &r.overlapUntil,
		&r.reminderSentAt, &r.renotifiedAt, &r.overlapMinutes, &r.resultCode, &r.oldFingerprint, &r.oldLabel, &r.newFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return runRow{}, ErrNotFound
	}
	if err != nil {
		return runRow{}, fmt.Errorf("sshkeys: read the rotation: %w", err)
	}
	r.plannedFor = r.plannedFor.UTC()
	r.pausedAt, r.decisionDueAt, r.verifiedAt = utcPtr(r.pausedAt), utcPtr(r.decisionDueAt), utcPtr(r.verifiedAt)
	r.overlapUntil, r.reminderSentAt, r.renotifiedAt = utcPtr(r.overlapUntil), utcPtr(r.reminderSentAt), utcPtr(r.renotifiedAt)
	return r, nil
}

// finished reports whether the run's status is terminal.
func (r runRow) finished() bool { return slices.Contains(finishedList, r.status) }

// appendStep records one step of a run (rotation_steps, append-only). The caller holds the run's
// row lock, which serializes the step numbers.
func appendStep(ctx context.Context, tx pgx.Tx, runID uuid.UUID, locationID *uuid.UUID, name, status string, params map[string]string,
	now time.Time) error {
	if params == nil {
		params = map[string]string{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO rotation_steps (id, rotation_id, n, location_id, name, status, at, params)
VALUES ($1, $2, (SELECT coalesce(max(n), 0) + 1 FROM rotation_steps WHERE rotation_id = $2), $3, $4, $5, $6, $7)`,
		uuid.Must(uuid.NewV7()), runID, locationID, name, status, now, params)
	if err != nil {
		return fmt.Errorf("sshkeys: record a rotation step: %w", err)
	}
	return nil
}

// recordRunStatus appends the audit row and the step of a run's status change (C8: one of each).
func (s *Service) recordRunStatus(ctx context.Context, tx pgx.Tx, actor audit.Actor, runID uuid.UUID, from, to, reason string,
	now time.Time) error {
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "rotation.status_changed", ObjectType: "rotation",
		ObjectID: runID.String(), Result: audit.Success, Details: map[string]string{"rotation_id": runID.String(), "from": from, "to": to,
			"reason": reason}}); err != nil {
		return err
	}
	return appendStep(ctx, tx, runID, nil, to, "ok", map[string]string{"from": from, "reason": reason}, now)
}

// locRef is what the audit row of a location change names.
type locRef struct {
	id, targetID     uuid.UUID
	osUser, filePath string
}

// recordLocationState appends the audit row and the step of a location's state change.
func (s *Service) recordLocationState(ctx context.Context, tx pgx.Tx, actor audit.Actor, runID uuid.UUID, l locRef, from, to, reason string,
	now time.Time) error {
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "rotation.location_changed", ObjectType: "rotation",
		ObjectID: runID.String(), Result: audit.Success, Details: map[string]string{"rotation_id": runID.String(),
			"location_id": l.id.String(), "target_id": l.targetID.String(), "os_user": l.osUser, "file_path": l.filePath, "from": from,
			"to": to, "reason": reason}}); err != nil {
		return err
	}
	return appendStep(ctx, tx, runID, &l.id, to, "ok", map[string]string{"from": from, "reason": reason}, now)
}

// cancelRun ends a dry_run_notified run as cancelled (C8): its planned locations become cancelled
// first (the location guard refuses changes to a finished run's rows), then the run. The caller
// holds the run's row lock.
func (s *Service) cancelRun(ctx context.Context, tx pgx.Tx, actor audit.Actor, run runRow, reason string) error {
	now := s.clock.Now().UTC()
	rows, err := tx.Query(ctx, `SELECT id, target_id, os_user, file_path FROM rotation_locations WHERE rotation_id = $1 AND state = $2
ORDER BY n FOR UPDATE`, run.id, LocPlanned)
	if err != nil {
		return fmt.Errorf("sshkeys: read the run's planned locations: %w", err)
	}
	locs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (locRef, error) {
		var l locRef
		err := r.Scan(&l.id, &l.targetID, &l.osUser, &l.filePath)
		return l, err
	})
	if err != nil {
		return fmt.Errorf("sshkeys: read the run's planned locations: %w", err)
	}
	for _, l := range locs {
		if _, err := tx.Exec(ctx, "UPDATE rotation_locations SET state = $2, updated_at = $3 WHERE id = $1 AND state = $4",
			l.id, LocCancelled, now, LocPlanned); err != nil {
			return fmt.Errorf("sshkeys: cancel a location: %w", err)
		}
		if err := s.recordLocationState(ctx, tx, actor, run.id, l, LocPlanned, LocCancelled, reason, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE rotations SET status = $2, result_code = $3, finished_at = $4, updated_at = $4, version = version + 1
WHERE id = $1`, run.id, StatusCancelled, reason, now); err != nil {
		return fmt.Errorf("sshkeys: cancel the run: %w", err)
	}
	return s.recordRunStatus(ctx, tx, actor, run.id, run.status, StatusCancelled, reason, now)
}
