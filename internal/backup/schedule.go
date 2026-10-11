package backup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

// The schedule's defaults and bounds (C1, R43 rows 10 and 12).
const (
	DefaultTime      = "02:30"
	DefaultRetention = 14
	MinRetention     = 7
	MaxRetention     = 60
)

// errTimeOfDay is returned for a time that is not HH:MM.
var errTimeOfDay = errors.New("backup: the time of day is not HH:MM")

// ParseTimeOfDay reads "HH:MM" (00:00 to 23:59, two digits each).
func ParseTimeOfDay(s string) (hour, minute int, err error) {
	if len(s) != 5 || s[2] != ':' || !digits(s[:2]) || !digits(s[3:]) {
		return 0, 0, errTimeOfDay
	}
	hour, _ = strconv.Atoi(s[:2])
	minute, _ = strconv.Atoi(s[3:])
	if hour > 23 || minute > 59 {
		return 0, 0, errTimeOfDay
	}
	return hour, minute, nil
}

func digits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// LastScheduled returns, in UTC, the latest instant at or before now whose wall clock in loc is hhmm. On a day where
// hhmm does not exist (spring daylight saving) or exists twice (autumn), it is the instant time.Date gives, once per
// day. An unreadable hhmm counts as midnight, so a damaged setting never stops the backups.
func LastScheduled(now time.Time, loc *time.Location, hhmm string) time.Time {
	h, m, err := ParseTimeOfDay(hhmm)
	if err != nil {
		h, m = 0, 0
	}
	local := now.In(loc)
	at := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, loc)
	if at.After(now) {
		at = time.Date(local.Year(), local.Month(), local.Day()-1, h, m, 0, 0, loc)
	}
	return at.UTC()
}

// Due reports whether the latest scheduled instant has no successful automatic backup: never backed up, or the last
// automatic success is older than that instant. A missed run therefore happens at the next check (§20.2).
func Due(now time.Time, loc *time.Location, hhmm string, lastAutoSuccess time.Time) bool {
	return lastAutoSuccess.IsZero() || lastAutoSuccess.Before(LastScheduled(now, loc, hhmm))
}

// Schedule is the setting backup.schedule (C1): the daily time (HH:MM), the IANA zone it is read in, the number of
// automatic backups kept, and the optimistic version (0 = never saved).
type Schedule struct {
	Time      string `json:"time"`
	Zone      string `json:"zone"`
	Retention int    `json:"retention"`
	Version   int    `json:"version"`
}

const keySchedule = "backup.schedule"

// Schedule returns the schedule, with the defaults (02:30 in ALICE_TZ, 14 backups) when it was never saved.
func (s *Service) Schedule(ctx context.Context) (Schedule, error) {
	return s.readSchedule(ctx, s.c.Pool)
}

func (s *Service) readSchedule(ctx context.Context, q db.Querier) (Schedule, error) {
	sch := Schedule{Time: DefaultTime, Zone: s.c.Zone.String(), Retention: DefaultRetention}
	if _, err := settings.Get(ctx, q, keySchedule, &sch); err != nil {
		return Schedule{}, err
	}
	return sch, nil
}

// SaveSchedule validates and stores the schedule when version is the stored one (else ErrVersion), bumps the version
// and audits backup.settings_changed (time, zone, retention).
func (s *Service) SaveSchedule(ctx context.Context, a audit.Actor, version int, in Schedule) (Schedule, error) {
	var v validate.Errors
	if _, _, err := ParseTimeOfDay(in.Time); err != nil {
		v.Add("time", validate.Pattern, nil)
	}
	if in.Zone == "" {
		v.Add("zone", validate.Required, nil)
	} else if _, err := loadZone(in.Zone); err != nil {
		v.Add("zone", validate.Pattern, nil)
	}
	if in.Retention < MinRetention || in.Retention > MaxRetention {
		v.Add("retention", validate.OutOfRange, map[string]string{"min": strconv.Itoa(MinRetention), "max": strconv.Itoa(MaxRetention)})
	}
	if err := v.Err(); err != nil {
		return Schedule{}, err
	}
	var out Schedule
	err := db.InTx(ctx, s.c.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", keySchedule); err != nil {
			return fmt.Errorf("backup: lock the schedule: %w", err)
		}
		cur, err := s.readSchedule(ctx, tx)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrVersion
		}
		out = Schedule{Time: in.Time, Zone: in.Zone, Retention: in.Retention, Version: version + 1}
		if err := settings.Set(ctx, tx, keySchedule, out, s.c.Clock.Now()); err != nil {
			return err
		}
		_, err = s.c.Audit.Append(ctx, tx, audit.Event{Actor: a, Action: "backup.settings_changed", ObjectType: "setting",
			ObjectID: keySchedule, Result: audit.Success,
			Details: map[string]string{"time": out.Time, "zone": out.Zone, "retention": strconv.Itoa(out.Retention)}})
		return err
	})
	if err != nil {
		return Schedule{}, err
	}
	return out, nil
}

// loadZone loads an IANA zone; "Local" depends on the host and is refused, like ALICE_TZ refuses it.
func loadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" {
		return nil, errors.New("backup: not an IANA time zone")
	}
	return time.LoadLocation(name)
}
