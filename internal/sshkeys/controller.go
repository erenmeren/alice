package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/sshkeys/plan"
)

// Advance moves a run by at most one status transition of C8 (the sweep, the next location job or
// the next action makes the next one), so every intermediate state is observable. It runs in one
// transaction under the run's row lock (after the job's claim check); its emails are outbox rows of
// that transaction. G (the license allows changes) is asked for every forward step that leads to a
// change on servers; an undo never asks it (L-86).
//
// A previewed run (dry_run_notified): in lock it is cancelled (rotation.cancelled_license, L-88);
// before planned_for nothing happens; a scheduled run starts only once its rotation.preview was
// delivered to an Administrator by planned_for, and is cancelled at planned_for otherwise (S1); a
// plan that changed cancels it (rotation.plan_changed); a busy generator leaves it for the next sweep.
func (s *Service) Advance(ctx context.Context, id uuid.UUID) error {
	run, err := readRunRow(ctx, s.pool, id)
	if err != nil {
		return err
	}
	if run.status == StatusDryRunNotified {
		return s.advancePreviewed(ctx, run)
	}
	if run.finished() {
		return nil
	}
	return s.storeTx(ctx, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, id)
		if err != nil || run.finished() || run.status == StatusDryRunNotified {
			return err
		}
		locs, err := runLocations(ctx, tx, id)
		if err != nil {
			return err
		}
		c := &advance{s: s, tx: tx, run: run, locs: locs, now: s.clock.Now().UTC(), actor: jobActor(ctx), gate: s.gateOK()}
		if run.pausedLicense && c.gate && run.renotifiedAt == nil {
			// S6, L-84: the first call after the renewal tells the Administrators before Continue is
			// possible; nothing else moves in the same call.
			return c.renotify(ctx)
		}
		switch run.status {
		case StatusAddingNew:
			return c.adding(ctx)
		case StatusVerifyingNew:
			return c.verifying(ctx)
		case StatusOverlap:
			return c.overlap(ctx)
		case StatusRemovingOld:
			return c.removing(ctx)
		case StatusRollingBack:
			return c.rollingBack(ctx)
		}
		return nil
	})
}

func (s *Service) advancePreviewed(ctx context.Context, run runRow) error {
	if !s.gateOK() {
		return s.cancelPreviewed(ctx, run.id, ReasonCancelledLicense)
	}
	now := s.clock.Now().UTC()
	if now.Before(run.plannedFor) {
		return nil
	}
	if run.trigger == TriggerScheduled {
		delivered, err := s.noticeDelivered(ctx, s.pool, run.id)
		if err != nil {
			return err
		}
		if !delivered {
			// No notice reached anyone by the planned start: it can never give the full notice
			// period now (review M1). The run counts as this interval's run (review M4).
			return s.cancelPreviewed(ctx, run.id, ReasonNoticeUndelivered)
		}
	}
	err := s.start(ctx, run.id, systemActor, true)
	if errors.Is(err, ErrPlanChanged) || errors.Is(err, ErrGenerateBusy) || errors.Is(err, errNoticePending) {
		return nil
	}
	return err
}

// cancelPreviewed cancels a run that is still previewed, under its row lock (system actor).
func (s *Service) cancelPreviewed(ctx context.Context, id uuid.UUID, reason string) error {
	return s.cancelIfPreviewed(ctx, id, systemActor.Audit, reason)
}

// cancelIfPreviewed cancels a run that is still previewed, under its row lock. A run cancelled for an
// undelivered notice counts as its interval's run: an enabled policy's next run moves one interval on
// (review M4: at most one cancelled run per interval, no create-and-cancel loop).
func (s *Service) cancelIfPreviewed(ctx context.Context, id uuid.UUID, actor audit.Actor, reason string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, id)
		if err != nil || run.status != StatusDryRunNotified {
			return err
		}
		if err := s.cancelRun(ctx, tx, actor, run, reason); err != nil {
			return err
		}
		if reason != ReasonNoticeUndelivered {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE rotation_policies SET next_run_at = next_run_at + make_interval(days => interval_days)
WHERE id = $1 AND enabled AND deleted_at IS NULL AND next_run_at IS NOT NULL`, run.policyID)
		if err != nil {
			return policyWriteError(err)
		}
		return nil
	})
}

// runLocations reads the run's locations in n order (the caller holds the run's row lock, which every
// writer of them takes first).
func runLocations(ctx context.Context, tx pgx.Tx, runID uuid.UUID) ([]locRow, error) {
	rows, err := tx.Query(ctx, locSelect+" WHERE rotation_id = $1 ORDER BY n", runID)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: read the run's locations: %w", err)
	}
	defer rows.Close()
	var out []locRow
	for rows.Next() {
		l, err := scanLoc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// advance is one Advance call on a locked run.
type advance struct {
	s     *Service
	tx    pgx.Tx
	run   runRow
	locs  []locRow
	now   time.Time
	actor audit.Actor
	gate  bool
}

func (c *advance) count(states ...string) int {
	n := 0
	for _, l := range c.locs {
		if slices.Contains(states, l.state) {
			n++
		}
	}
	return n
}

// setStatus moves the run (one compare-and-set update; sets: extra assignments from $5 on, constants
// of this file) and records the change.
func (c *advance) setStatus(ctx context.Context, to, reason, sets string, args ...any) error {
	return c.s.setRunStatus(ctx, c.tx, c.actor, c.run, to, reason, c.now, sets, args...)
}

func (s *Service) setRunStatus(ctx context.Context, tx pgx.Tx, actor audit.Actor, run runRow, to, reason string, now time.Time,
	sets string, args ...any) error {
	if slices.Contains(finishedList, to) {
		sets += ", finished_at = $3"
	}
	tag, err := tx.Exec(ctx, "UPDATE rotations SET status = $2, updated_at = $3, version = version + 1"+sets+" WHERE id = $1 AND status = $4",
		append([]any{run.id, to, now, run.status}, args...)...)
	if err != nil {
		return fmt.Errorf("sshkeys: update the rotation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotWaiting
	}
	return s.recordRunStatus(ctx, tx, actor, run.id, run.status, to, reason, now)
}

// mail queues an email to every Administrator in the transaction (nothing without a notifier).
func (s *Service) mail(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.NotifyAdmins(ctx, tx, template, params)
}

// pause sets the run's license pause (L-83, L-85, S6) and mails rotation.paused_license once, when
// the pause begins; renotified_at is cleared so the renewal is announced again.
func (c *advance) pause(ctx context.Context) error {
	if c.run.pausedLicense {
		return nil
	}
	if _, err := c.tx.Exec(ctx, `UPDATE rotations SET paused_license = true, paused_at = $2, renotified_at = NULL, updated_at = $2,
    version = version + 1 WHERE id = $1`, c.run.id, c.now); err != nil {
		return fmt.Errorf("sshkeys: pause the rotation: %w", err)
	}
	if _, err := c.s.audit.Append(ctx, c.tx, audit.Event{Actor: c.actor, Action: "rotation.paused", ObjectType: "rotation",
		ObjectID: c.run.id.String(), Result: audit.Success, Details: map[string]string{"rotation_id": c.run.id.String(),
			"reason": ReasonPausedLicense}}); err != nil {
		return err
	}
	if err := appendStep(ctx, c.tx, c.run.id, nil, "paused", "ok", map[string]string{"reason": ReasonPausedLicense}, c.now); err != nil {
		return err
	}
	return c.s.mail(ctx, c.tx, TemplatePausedLicense, map[string]string{"key_label": c.run.oldLabel})
}

// renotify sends rotation.preview_after_license once after a renewal (S6, L-84) and records it.
func (c *advance) renotify(ctx context.Context) error {
	return c.s.renotify(ctx, c.tx, c.run, c.now)
}

func (s *Service) renotify(ctx context.Context, tx pgx.Tx, run runRow, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE rotations SET renotified_at = $2, updated_at = $2 WHERE id = $1", run.id, now); err != nil {
		return fmt.Errorf("sshkeys: record the renewal notice: %w", err)
	}
	var changes int
	if err := tx.QueryRow(ctx, "SELECT coalesce((plan->>'Changes')::int, 0) FROM rotations WHERE id = $1", run.id).Scan(&changes); err != nil {
		return fmt.Errorf("sshkeys: read the rotation's plan: %w", err)
	}
	return s.mail(ctx, tx, TemplatePreviewAfterLicense, map[string]string{"key_label": run.oldLabel, "fingerprint": run.oldFingerprint,
		"change_count": strconv.Itoa(changes)})
}

// failure is the first add or verify failure of the run (by n): its result code.
func (c *advance) failure() (string, bool) {
	for _, l := range c.locs {
		switch l.state {
		case LocAddFailed:
			return ReasonAddFailed, true
		case LocVerifyFailed:
			return ReasonVerifyFailed, true
		}
	}
	return "", false
}

func (c *advance) adding(ctx context.Context) error {
	if reason, failed := c.failure(); failed {
		return c.s.rollBack(ctx, c.tx, c.actor, c.run, c.locs, reason, c.now)
	}
	if c.run.pausedLicense {
		return nil
	}
	if !c.gate && c.count(LocPlanned) > 0 {
		return c.pause(ctx) // L-85: no new add; the ones in flight finish
	}
	if c.count(LocPlanned, LocAdding, LocAdded) > 0 {
		return nil
	}
	if n := c.count(LocUnverifiable); n > 0 {
		due := plan.DecisionDue(c.now)
		if err := c.setStatus(ctx, StatusVerifyingNew, "", ", awaiting_decision = true, decision_due_at = $5", due); err != nil {
			return err
		}
		return c.s.mail(ctx, c.tx, TemplateDecisionNeeded, map[string]string{"key_label": c.run.oldLabel, "count": strconv.Itoa(n),
			"decision_due": mailTime(due)})
	}
	return c.s.toOverlap(ctx, c.tx, c.actor, c.run, c.now)
}

// toOverlap starts the overlap (C8): the new key works everywhere Alice could check it.
func (s *Service) toOverlap(ctx context.Context, tx pgx.Tx, actor audit.Actor, run runRow, now time.Time) error {
	until := plan.OverlapUntil(now, run.overlapMinutes)
	if err := s.setRunStatus(ctx, tx, actor, run, StatusOverlap, "", now,
		", verified_at = $3, overlap_until = $5, awaiting_decision = false, decision_due_at = NULL", until); err != nil {
		return err
	}
	return s.mail(ctx, tx, TemplateOverlapStarted, map[string]string{"key_label": run.oldLabel, "new_fingerprint": run.newFingerprint,
		"overlap_until": mailTime(until)})
}

func (c *advance) verifying(ctx context.Context) error {
	if c.run.pausedLicense {
		return nil // S6: no deadline runs while paused
	}
	if !c.gate {
		return c.pause(ctx)
	}
	if c.count(LocUnverifiable) == 0 {
		return c.s.toOverlap(ctx, c.tx, c.actor, c.run, c.now)
	}
	if c.run.decisionDueAt != nil && plan.Due(c.now, *c.run.decisionDueAt) {
		return c.s.rollBack(ctx, c.tx, c.actor, c.run, c.locs, ReasonDecisionTimeout, c.now)
	}
	return nil
}

func (c *advance) overlap(ctx context.Context) error {
	if c.run.pausedLicense || c.run.overlapUntil == nil {
		return nil
	}
	until := *c.run.overlapUntil
	if !plan.Due(c.now, until) {
		if at, ok := plan.ReminderDue(until, c.run.overlapMinutes); ok && plan.Due(c.now, at) && c.run.reminderSentAt == nil {
			if _, err := c.tx.Exec(ctx, "UPDATE rotations SET reminder_sent_at = $2, updated_at = $2 WHERE id = $1", c.run.id, c.now); err != nil {
				return fmt.Errorf("sshkeys: record the reminder: %w", err)
			}
			return c.s.mail(ctx, c.tx, TemplateOverlapEnding, map[string]string{"key_label": c.run.oldLabel, "overlap_until": mailTime(until)})
		}
		return nil
	}
	if !c.gate {
		return c.pause(ctx) // L-83: nothing is removed in lock
	}
	// G18: a verified location in a (target, file) where another location of the run is not verified
	// (skipped or kept) keeps the old key: it ends kept_old and counts where the old key stays.
	var remove []locRow
	for _, l := range c.filter(LocVerified) {
		if c.fileBlocked(l) {
			if err := c.s.setLocation(ctx, c.tx, c.actor, l, LocKeptOld, "rotation.old_kept", c.now, ""); err != nil {
				return err
			}
			continue
		}
		remove = append(remove, l)
	}
	if err := c.setStatus(ctx, StatusRemovingOld, "", ", removal_allowed = true"); err != nil {
		return err
	}
	return c.s.queueJobs(ctx, c.tx, systemActor, c.run.id, remove, "remove")
}

// fileBlocked: another location of the run in l's (target, file) is not verified (G18).
func (c *advance) fileBlocked(l locRow) bool {
	for _, o := range c.locs {
		if o.id != l.id && o.targetID == l.targetID && o.filePath == l.filePath && o.state != LocVerified {
			return true
		}
	}
	return false
}

func (c *advance) filter(states ...string) []locRow {
	var out []locRow
	for _, l := range c.locs {
		if slices.Contains(states, l.state) {
			out = append(out, l)
		}
	}
	return out
}

// retryableRemoval: a failed removal the sweep still retries (G3) before the run needs attention.
func retryableRemoval(l locRow) bool {
	return l.state == LocRemoveFailed && l.retries < MaxLocationJobs
}

func (c *advance) removing(ctx context.Context) error {
	pending := c.count(LocVerified, LocRemoving)
	retry := 0
	for _, l := range c.locs {
		if retryableRemoval(l) {
			retry++
		}
	}
	if c.run.pausedLicense {
		return nil
	}
	if pending+retry > 0 {
		if !c.gate && c.count(LocVerified, LocRemoveFailed) > 0 {
			return c.pause(ctx) // removals in flight finish; no new one
		}
		return nil
	}
	kept := c.count(LocSkipped, LocKeptOld, LocRemoveFailed)
	if c.count(LocRemoveFailed) > 0 {
		if err := c.setStatus(ctx, StatusNeedsAttention, ReasonRemoveIncomplete, ", result_code = $5, kept_count = $6",
			ReasonRemoveIncomplete, kept); err != nil {
			return err
		}
		return c.s.mail(ctx, c.tx, TemplateNeedsAttention, map[string]string{"key_label": c.run.oldLabel, "code": ReasonRemoveIncomplete})
	}
	if err := c.setStatus(ctx, StatusCompleted, "", ", kept_count = $5", kept); err != nil {
		return err
	}
	if err := c.s.completed(ctx, c.tx, c.actor, c.run, c.now); err != nil {
		return err
	}
	if kept > 0 {
		return c.s.mail(ctx, c.tx, TemplateCompletedPartial, map[string]string{"key_label": c.run.oldLabel,
			"new_fingerprint": c.run.newFingerprint, "kept_count": strconv.Itoa(kept)})
	}
	return c.s.mail(ctx, c.tx, TemplateCompleted, map[string]string{"key_label": c.run.oldLabel, "new_fingerprint": c.run.newFingerprint})
}

// completed moves the policy to the new key and retires the old key when no location of it is live
// any more (the rule DestroyRetiredKeys reactivates by, S5). The run is already completed.
func (s *Service) completed(ctx context.Context, tx pgx.Tx, actor audit.Actor, run runRow, now time.Time) error {
	if run.newKeyID == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, "UPDATE rotation_policies SET ssh_key_id = $2 WHERE id = $1 AND deleted_at IS NULL", run.policyID,
		*run.newKeyID); err != nil {
		return policyWriteError(err)
	}
	var live int
	if err := tx.QueryRow(ctx, "SELECT ("+liveLocations+") FROM ssh_keys k WHERE k.id = $1 FOR UPDATE OF k", run.oldKeyID).Scan(&live); err != nil {
		return fmt.Errorf("sshkeys: count the old key's locations: %w", err)
	}
	if live > 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1 AND retired_at IS NULL", run.oldKeyID, now); err != nil {
		return fmt.Errorf("sshkeys: retire the old key: %w", err)
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.retired", ObjectType: "ssh_key", ObjectID: run.oldKeyID.String(),
		Result: audit.Success, Details: map[string]string{"ssh_key_id": run.oldKeyID.String(), "fingerprint": run.oldFingerprint,
			"rotation_id": run.id.String()}})
	return err
}

// undoPending: the location's add was sent and its undo has not ended.
func undoPending(l locRow) bool {
	return l.addSentAt != nil && slices.Contains(undoable, l.state)
}

// rollBack ends a started run's forward path (C8): planned locations become cancelled, the run
// rolling_back with the result, the license pause and the decision cleared, and one undo job queued
// for every location whose add was sent.
func (s *Service) rollBack(ctx context.Context, tx pgx.Tx, actor audit.Actor, run runRow, locs []locRow, reason string, now time.Time) error {
	for _, l := range locs {
		if l.state == LocPlanned {
			if err := s.setLocation(ctx, tx, actor, l, LocCancelled, reason, now, ""); err != nil {
				return err
			}
		}
	}
	if err := s.setRunStatus(ctx, tx, actor, run, StatusRollingBack, reason, now, `, result_code = $5, paused_license = false,
    paused_at = NULL, awaiting_decision = false, decision_due_at = NULL`, reason); err != nil {
		return err
	}
	var undo []locRow
	for _, l := range locs {
		if undoPending(l) {
			undo = append(undo, l)
		}
	}
	return s.queueJobs(ctx, tx, systemActor, run.id, undo, "undo")
}

func (c *advance) rollingBack(ctx context.Context) error {
	for _, l := range c.locs {
		if undoPending(l) {
			return nil
		}
	}
	if c.count(LocUndoFailed) > 0 {
		if err := c.setStatus(ctx, StatusNeedsAttention, ReasonUndoFailed, ", result_code = $5", ReasonUndoFailed); err != nil {
			return err
		}
		return c.s.mail(ctx, c.tx, TemplateNeedsAttention, map[string]string{"key_label": c.run.oldLabel, "code": ReasonUndoFailed})
	}
	if err := c.setStatus(ctx, StatusAborted, c.run.resultCode, ""); err != nil {
		return err
	}
	return c.s.mail(ctx, c.tx, TemplateAborted, map[string]string{"key_label": c.run.oldLabel, "code": c.run.resultCode})
}

// queueJobs queues one rotation.location job of the phase per location (C1 payload and dedupe; a live
// job of the same location and phase is that job).
func (s *Service) queueJobs(ctx context.Context, tx pgx.Tx, a inventory.Actor, runID uuid.UUID, locs []locRow, phase string) error {
	for _, l := range locs {
		if err := s.queueJob(ctx, tx, a, runID, l.id, l.targetID, phase); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) queueJob(ctx context.Context, tx pgx.Tx, a inventory.Actor, runID, locID, targetID uuid.UUID, phase string) error {
	_, err := s.jobs.EnqueueTx(ctx, tx, inventory.JobRequest{Type: JobRotationLocation, TargetID: targetID, Kind: jobKind(a),
		CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: locationDedupe(locID, phase),
		Payload: map[string]string{"rotation_id": runID.String(), "location_id": locID.String(), "phase": phase}})
	return err
}

func locationDedupe(locID uuid.UUID, phase string) string {
	return JobRotationLocation + ":" + locID.String() + ":" + phase
}
