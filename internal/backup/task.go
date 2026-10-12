package backup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alice/internal/audit"
	"alice/internal/platform/settings"
)

// schedulerActor is the actor of scheduled backups (C14).
var schedulerActor = audit.SystemActor("scheduler")

// The gap before a failed scheduled backup is tried again: retryFirst after the first failure, doubling up to
// retryMax (review-fixes L-3), so a persistent failure is not audited every 5 minutes.
const (
	retryFirst = 5 * time.Minute
	retryMax   = time.Hour
)

// retryGap is the wait after n consecutive failures.
func retryGap(n int) time.Duration {
	gap := retryFirst
	for i := 1; i < n && gap < retryMax; i++ {
		gap *= 2
	}
	return min(gap, retryMax)
}

// RunScheduled is the backup.schedule task (every 5 minutes): it makes the automatic backup when the latest scheduled
// instant has none (so a missed run happens at the next check, §20.2). Before the recovery passphrase exists there is
// nothing to back up to, and it does nothing. A backup another caller is making counts as no run: the next check tries
// again. Every tick also raises the 48-hour alarm when it is due. A failure was recorded by Create (state, audit,
// e-mails) and is returned for the task log.
//
// After a failure (review-fixes L-3): a backup key or sender key that does not work is recorded once per episode and
// only checked (no backup.failed row) on later ticks until it works; any other failure is tried again after
// retryGap. A scheduled backup whose file was made but whose success could not be recorded is recorded first, and no
// other backup is made until that succeeds.
func (s *Service) RunScheduled(ctx context.Context) error {
	if err := s.checkAlarm(ctx); err != nil {
		s.c.Log.Error("could not check the backup alarm", "error_type", fmt.Sprintf("%T", err))
	}
	var raw any
	configured, err := settings.Get(ctx, s.c.Pool, keyBackupKey, &raw)
	if err != nil || !configured {
		return err
	}
	if err := s.recordPending(ctx); err != nil {
		return err
	}
	sch, err := s.Schedule(ctx)
	if err != nil {
		return err
	}
	st, err := s.State(ctx)
	if err != nil {
		return err
	}
	loc, err := loadZone(sch.Zone)
	if err != nil {
		loc = s.c.Zone
	}
	if !Due(s.c.Clock.Now(), loc, sch.Time, st.LastAutoSuccessAt) {
		return nil
	}
	if st.Failing() {
		if st.LastErrorCode == codeNotConfigured {
			if _, _, err := s.keys(ctx); err != nil {
				var f *failure
				if errors.As(err, &f) && f.code == codeNotConfigured {
					return nil // still not configured: recorded once for this episode
				}
				return err
			}
		} else if s.c.Clock.Now().Before(st.LastFailureAt.Add(retryGap(st.ConsecutiveFailures))) {
			return nil
		}
	}
	_, err = s.Create(ctx, CreateInput{Kind: KindAuto, Actor: schedulerActor})
	if errors.Is(err, ErrRunning) {
		return nil
	}
	return err
}

// recordPending records the success of a scheduled backup whose state write failed. While it cannot, it returns the
// error and the scheduler makes no other backup.
func (s *Service) recordPending(ctx context.Context) error {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pending == nil {
		return nil
	}
	if err := s.recordSuccess(ctx, s.pending.in, s.pending.info); err != nil {
		return err
	}
	s.pending = nil
	return nil
}
