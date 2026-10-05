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
)

// SweepSummary counts what one sweep did.
type SweepSummary struct{ Advanced, Paused, Requeued, Failed int }

// Sweep (task rotation.sweep) advances every live run once, then re-queues (dedupe) the location
// job of every location that waits for one (C8's last paragraph), at most MaxLocationJobs times per
// location and phase; a location that reached the bound without progress ends with
// rotation.retries_exhausted and its run advances again. It never starts remote work itself: in
// lock, paused runs get no add or remove job (undo jobs are queued in every state, L-86).
func (s *Service) Sweep(ctx context.Context) (SweepSummary, error) {
	var sum SweepSummary
	rows, err := s.pool.Query(ctx, "SELECT id FROM rotations WHERE status NOT IN "+finishedStatuses+" ORDER BY planned_for, created_at, id")
	if err != nil {
		return sum, fmt.Errorf("sshkeys: list live rotations: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return sum, fmt.Errorf("sshkeys: list live rotations: %w", err)
	}
	var errs []error
	for _, id := range ids {
		before, err := readRunRow(ctx, s.pool, id)
		if err != nil {
			errs = append(errs, err)
			sum.Failed++
			continue
		}
		if err := s.Advance(ctx, id); err != nil {
			s.log.Error("could not advance a rotation", "rotation_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			errs = append(errs, err)
			sum.Failed++
			continue
		}
		after, err := readRunRow(ctx, s.pool, id)
		if err != nil {
			errs = append(errs, err)
			sum.Failed++
			continue
		}
		if after.status != before.status {
			sum.Advanced++
		}
		if after.pausedLicense && !before.pausedLicense {
			sum.Paused++
		}
		queued, ended, err := s.requeue(ctx, id)
		sum.Requeued += queued
		if err != nil {
			errs = append(errs, err)
			sum.Failed++
			continue
		}
		if ended {
			if err := s.Advance(ctx, id); err != nil {
				errs = append(errs, err)
				sum.Failed++
			}
		}
	}
	return sum, errors.Join(errs...)
}

// phaseOf is the location job phase a location waits for in the run's status, "" when none.
func (s *Service) phaseOf(run runRow, l locRow) string {
	switch {
	case run.status == StatusAddingNew && !run.pausedLicense && slices.Contains([]string{LocPlanned, LocAdding, LocAdded}, l.state):
		return "add"
	case run.status == StatusRemovingOld && !run.pausedLicense && (l.state == LocVerified || l.state == LocRemoving || retryableRemoval(l)):
		return "remove"
	case run.status == StatusRollingBack && undoPending(l):
		return "undo"
	}
	return ""
}

// requeue queues the jobs of one run's waiting locations, under the run's lock; ended reports
// whether a location was ended by the bound.
func (s *Service) requeue(ctx context.Context, id uuid.UUID) (queued int, ended bool, err error) {
	err = s.storeTx(ctx, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, id)
		if err != nil || run.finished() || run.status == StatusDryRunNotified {
			return err
		}
		locs, err := runLocations(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		actor := jobActor(ctx)
		for _, l := range locs {
			phase := s.phaseOf(run, l)
			if phase == "" {
				continue
			}
			if phase == "undo" && s.undoMustWait(l, now) {
				continue // S3: the undo waits; the wait does not count toward the bound
			}
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jobs WHERE dedupe_key = $1 AND status IN ('queued', 'running',
    'blocked_license'))`, locationDedupe(l.id, phase)).Scan(&live); err != nil {
				return fmt.Errorf("sshkeys: read the location's job: %w", err)
			}
			if live {
				continue
			}
			if l.state == LocRemoveFailed {
				// A failed removal never changes in place (it moves only into removing): its retries are
				// counted as steps (G3); retryableRemoval bounds them.
				if err := s.queueJob(ctx, tx, systemActor, id, l.id, l.targetID, phase); err != nil {
					return err
				}
				if err := appendStep(ctx, tx, id, &l.id, "remove_retry", "started", nil, now); err != nil {
					return err
				}
				queued++
				continue
			}
			if l.jobCount >= MaxLocationJobs && (phase != "undo" || l.state != LocAdding) { // G17: an adding row gets a real undo
				if err := s.exhaust(ctx, tx, actor, l, phase, now); err != nil {
					return err
				}
				ended = true
				continue
			}
			if err := s.queueJob(ctx, tx, systemActor, id, l.id, l.targetID, phase); err != nil {
				return err
			}
			if err := s.setLocation(ctx, tx, actor, l, l.state, "", now, ", job_count = job_count + 1"); err != nil {
				return err
			}
			queued++
		}
		return nil
	})
	return queued, ended, err
}

// exhaust ends a location whose jobs reached MaxLocationJobs without progress (rotation.retries_exhausted).
func (s *Service) exhaust(ctx context.Context, tx pgx.Tx, actor audit.Actor, l locRow, phase string, now time.Time) error {
	var to string
	switch {
	case phase == "add" && l.state == LocAdded:
		to = LocAddFailed // G1
	case phase == "add":
		to = LocAddFailed
	case phase == "remove":
		to = LocRemoveFailed
	default:
		to = LocUndoFailed // G2: nothing more is sent
	}
	return s.setLocation(ctx, tx, actor, l, to, ReasonRetriesExhausted, now, ", error_code = $5", ReasonRetriesExhausted)
}
