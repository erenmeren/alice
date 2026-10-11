package backup

import (
	"context"
	"errors"
	"fmt"

	"alice/internal/audit"
	"alice/internal/platform/settings"
)

// schedulerActor is the actor of scheduled backups (C14).
var schedulerActor = audit.SystemActor("scheduler")

// RunScheduled is the backup.schedule task (every 5 minutes): it makes the automatic backup when the latest scheduled
// instant has none (so a missed run happens at the next check, §20.2). Before the recovery passphrase exists there is
// nothing to back up to, and it does nothing. A backup another caller is making counts as no run: the next check tries
// again. Every tick also raises the 48-hour alarm when it is due. A failure was recorded by Create (state, audit,
// e-mails) and is returned for the task log.
func (s *Service) RunScheduled(ctx context.Context) error {
	if err := s.checkAlarm(ctx); err != nil {
		s.c.Log.Error("could not check the backup alarm", "error_type", fmt.Sprintf("%T", err))
	}
	var raw any
	configured, err := settings.Get(ctx, s.c.Pool, keyBackupKey, &raw)
	if err != nil || !configured {
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
	_, err = s.Create(ctx, CreateInput{Kind: KindAuto, Actor: schedulerActor})
	if errors.Is(err, ErrRunning) {
		return nil
	}
	return err
}
