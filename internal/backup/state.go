package backup

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// AlarmAfter is how long Alice may go without a successful backup before it raises the alarm (R7, F-88).
const AlarmAfter = 48 * time.Hour

// State is the setting backup.state: the outcome of the latest backups.
type State struct {
	LastSuccessAt       time.Time `json:"last_success_at"`
	LastSuccessName     string    `json:"last_success_name"`
	LastAutoSuccessAt   time.Time `json:"last_auto_success_at"`
	LastFailureAt       time.Time `json:"last_failure_at"`
	LastErrorCode       string    `json:"last_error_code"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	FailureNotified     bool      `json:"failure_notified"`
	AlarmNotified       bool      `json:"alarm_notified"`
	// SetupCompletedAt is not stored: State fills it from setup.completed_at, so Alarm can count from it when there
	// was never a success. Zero while the setup wizard is open.
	SetupCompletedAt time.Time `json:"-"`
}

// Alarm reports whether there has been no successful backup for AlarmAfter: counted from the last success, or from
// the setup completion when there was never one; never while setup is open.
func (st State) Alarm(now time.Time) bool {
	if st.SetupCompletedAt.IsZero() {
		return false
	}
	since := st.LastSuccessAt
	if since.IsZero() {
		since = st.SetupCompletedAt
	}
	return now.Sub(since) >= AlarmAfter
}

// Failing reports whether the latest backup attempt failed.
func (st State) Failing() bool { return st.ConsecutiveFailures > 0 }

const keyState = "backup.state"

// stateLock serializes the read-modify-write of backup.state.
const stateLock = "alice.backup.state"

// State returns backup.state with SetupCompletedAt filled in.
func (s *Service) State(ctx context.Context) (State, error) {
	return readState(ctx, s.c.Pool)
}

func readState(ctx context.Context, q db.Querier) (State, error) {
	var st State
	if _, err := settings.Get(ctx, q, keyState, &st); err != nil {
		return State{}, err
	}
	var completed string
	found, err := settings.Get(ctx, q, keyCompletedAt, &completed)
	if err != nil {
		return State{}, err
	}
	if found {
		if t, err := time.Parse(time.RFC3339, completed); err == nil {
			st.SetupCompletedAt = t.UTC()
		}
	}
	return st, nil
}

// updateState runs fn on backup.state inside one locked transaction and stores the result.
func (s *Service) updateState(ctx context.Context, fn func(tx pgx.Tx, st *State) error) error {
	return db.InTx(ctx, s.c.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", stateLock); err != nil {
			return fmt.Errorf("backup: lock the state: %w", err)
		}
		st, err := readState(ctx, tx)
		if err != nil {
			return err
		}
		if err := fn(tx, &st); err != nil {
			return err
		}
		return settings.Set(ctx, tx, keyState, st, s.c.Clock.Now())
	})
}

// recordSuccess audits backup.created and resets the failure episode.
func (s *Service) recordSuccess(ctx context.Context, in CreateInput, info Info) error {
	return s.updateState(ctx, func(tx pgx.Tx, st *State) error {
		st.LastSuccessAt, st.LastSuccessName = info.CreatedAt, info.Name
		if in.Kind == KindAuto {
			st.LastAutoSuccessAt = info.CreatedAt
		}
		st.LastErrorCode, st.ConsecutiveFailures, st.FailureNotified, st.AlarmNotified = "", 0, false, false
		_, err := s.c.Audit.Append(ctx, tx, audit.Event{Actor: in.Actor, Action: "backup.created", ObjectType: "backup",
			ObjectID: info.Name, Result: audit.Success,
			Details: map[string]string{"name": info.Name, "kind": string(info.Kind), "size": strconv.FormatInt(info.Size, 10), "reason": in.Reason}})
		return err
	})
}

// emailTime is the time format of the e-mails.
const emailTime = "2006-01-02 15:04 UTC"

// dashboardURL is the link of the e-mails: the public URL's root.
func dashboardURL(ctx context.Context, tx pgx.Tx) (string, error) {
	g, err := settings.GetGeneral(ctx, tx)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(g.PublicURL, "/") + "/", nil
}

// recordFailure audits backup.failed and records the failure; in the same transaction it queues the failure e-mail
// once per episode (scheduled backups only) and the 48-hour alarm once (F-70, F-88, R43 row 11).
func (s *Service) recordFailure(ctx context.Context, in CreateInput, code string) error {
	now := s.c.Clock.Now().UTC()
	return s.updateState(ctx, func(tx pgx.Tx, st *State) error {
		st.LastFailureAt, st.LastErrorCode = now, code
		st.ConsecutiveFailures++
		if _, err := s.c.Audit.Append(ctx, tx, audit.Event{Actor: in.Actor, Action: "backup.failed", ObjectType: "backup",
			Result: audit.Failure, Details: map[string]string{"kind": string(in.Kind), "error_code": code}}); err != nil {
			return err
		}
		if in.Kind == KindAuto && !st.FailureNotified {
			dashboard, err := dashboardURL(ctx, tx)
			if err != nil {
				return err
			}
			if err := s.c.Notifier.NotifyAdmins(ctx, tx, TemplateFailed,
				map[string]string{"time": now.Format(emailTime), "error_code": code, "dashboard_url": dashboard}); err != nil {
				return err
			}
			st.FailureNotified = true
		}
		return s.queueAlarm(ctx, tx, st, now)
	})
}

// checkAlarm queues the 48-hour alarm when it is due and was not sent yet. The scheduler runs it on every tick, so the
// alarm does not depend on a failure being recorded (a hung backup holding the lock records none; review minor 5).
func (s *Service) checkAlarm(ctx context.Context) error {
	now := s.c.Clock.Now().UTC()
	st, err := s.State(ctx)
	if err != nil {
		return err
	}
	if !st.Alarm(now) || st.AlarmNotified {
		return nil // the common case: no write
	}
	return s.updateState(ctx, func(tx pgx.Tx, st *State) error { return s.queueAlarm(ctx, tx, st, now) })
}

// queueAlarm queues the alarm e-mail once per episode: backup.alarm with the last success, or backup.alarm_never when
// there was none.
func (s *Service) queueAlarm(ctx context.Context, tx pgx.Tx, st *State, now time.Time) error {
	if !st.Alarm(now) || st.AlarmNotified {
		return nil
	}
	dashboard, err := dashboardURL(ctx, tx)
	if err != nil {
		return err
	}
	tpl, params := TemplateAlarmNever, map[string]string{"dashboard_url": dashboard}
	if !st.LastSuccessAt.IsZero() {
		tpl, params["last_success"] = TemplateAlarm, st.LastSuccessAt.UTC().Format(emailTime)
	}
	if err := s.c.Notifier.NotifyAdmins(ctx, tx, tpl, params); err != nil {
		return err
	}
	st.AlarmNotified = true
	return nil
}
