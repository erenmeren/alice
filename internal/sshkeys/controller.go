package sshkeys

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/license"
	"alice/internal/platform/db"
)

// Advance moves a run by at most one status transition of C8. Task 8 implements the rows of a
// previewed run (dry_run_notified); Task 9 adds the others. In lock the previewed run is cancelled
// (rotation.cancelled_license, L-88). Before planned_for nothing happens. A scheduled run starts only
// once its rotation.preview was delivered to an Administrator; undelivered NoticeGrace after
// planned_for it is cancelled (rotation.notice_undelivered, S1) and PlanDue previews again. A plan
// that changed cancels the run (rotation.plan_changed); a busy generator leaves it for the next sweep.
func (s *Service) Advance(ctx context.Context, id uuid.UUID) error {
	run, err := readRunRow(ctx, s.pool, id)
	if err != nil {
		return err
	}
	if run.status != StatusDryRunNotified {
		return nil
	}
	if s.license.Allow(license.ClassChange) != nil {
		return s.cancelPreviewed(ctx, id, ReasonCancelledLicense)
	}
	now := s.clock.Now().UTC()
	if now.Before(run.plannedFor) {
		return nil
	}
	if run.trigger == TriggerScheduled {
		delivered, err := s.noticeDelivered(ctx, s.pool, id)
		if err != nil {
			return err
		}
		if !delivered {
			if !now.Before(run.plannedFor.Add(NoticeGrace)) {
				return s.cancelPreviewed(ctx, id, ReasonNoticeUndelivered)
			}
			return nil
		}
	}
	err = s.start(ctx, id, systemActor)
	if errors.Is(err, ErrPlanChanged) || errors.Is(err, ErrGenerateBusy) {
		return nil
	}
	return err
}

// cancelPreviewed cancels a run that is still previewed, under its row lock.
func (s *Service) cancelPreviewed(ctx context.Context, id uuid.UUID, reason string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, id)
		if err != nil || run.status != StatusDryRunNotified {
			return err
		}
		return s.cancelRun(ctx, tx, systemActor.Audit, run, reason)
	})
}
