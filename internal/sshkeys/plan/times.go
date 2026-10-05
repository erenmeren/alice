package plan

import "time"

const (
	day            = 24 * time.Hour
	decisionWindow = 14 * day
	freshness      = 15 * time.Minute
)

// FirstRun is when a policy switched on at enabledAt first runs (R41 row 12).
func FirstRun(enabledAt time.Time, intervalDays int) time.Time {
	return enabledAt.UTC().Add(time.Duration(intervalDays) * day)
}

// NextRun is the run after one that started at startedAt.
func NextRun(startedAt time.Time, intervalDays int) time.Time {
	return startedAt.UTC().Add(time.Duration(intervalDays) * day)
}

// NoticeDue is when the preview of a run due at nextRun is sent.
func NoticeDue(nextRun time.Time, notifyBeforeHours int) time.Time {
	return nextRun.UTC().Add(-time.Duration(notifyBeforeHours) * time.Hour)
}

// PlannedFor is the start of a run previewed now: never earlier than the full notice period.
func PlannedFor(now, nextRun time.Time, notifyBeforeHours int) time.Time {
	earliest := now.UTC().Add(time.Duration(notifyBeforeHours) * time.Hour)
	if nextRun.Before(earliest) {
		return earliest
	}
	return nextRun.UTC()
}

// OverlapUntil is the end of the overlap of a run verified at verifiedAt.
func OverlapUntil(verifiedAt time.Time, overlapMinutes int) time.Time {
	return verifiedAt.UTC().Add(time.Duration(overlapMinutes) * time.Minute)
}

// Due reports whether a timer at "at" has fired at now (inclusive).
func Due(now, at time.Time) bool { return !now.Before(at) }

// ReminderDue is the "one day before the end" reminder of an overlap longer than 48 hours.
func ReminderDue(overlapUntil time.Time, overlapMinutes int) (time.Time, bool) {
	if overlapMinutes <= 48*60 {
		return time.Time{}, false
	}
	return overlapUntil.UTC().Add(-day), true
}

// DecisionDue is the end of the window for an Administrator's decision on unverifiable locations.
func DecisionDue(waitingSince time.Time) time.Time { return waitingSince.UTC().Add(decisionWindow) }

// Fresh reports whether a re-verification at reverifiedAt may justify a removal sent at now.
func Fresh(now, reverifiedAt time.Time) bool {
	return !reverifiedAt.After(now) && now.Sub(reverifiedAt) <= freshness
}
