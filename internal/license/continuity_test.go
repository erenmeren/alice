package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// Owner decision 2026-10-20: a licensed lock keeps the automatic upkeep of what is already managed for
// ContinuityPeriod (the continuity window); the evaluation has none.
func TestContinuityWindowOfALicensedLock(t *testing.T) {
	locksAt := expiry.Add(license.GracePeriod)
	ends := locksAt.Add(license.ContinuityPeriod)
	require.Equal(t, 45*day, license.ContinuityPeriod)

	active := license.Evaluate(expiry.Add(-day), installedAt, baseline())
	assert.Equal(t, ends, active.ContinuityEndsAt, "known before the lock: the date is shown ahead")
	assert.Zero(t, active.ContinuityDaysLeft, "days are counted only in lock")
	assert.False(t, active.InContinuity())

	grace := license.Evaluate(expiry.Add(3*day), installedAt, baseline())
	assert.Equal(t, ends, grace.ContinuityEndsAt)
	assert.False(t, grace.InContinuity())

	first := license.Evaluate(locksAt, installedAt, baseline())
	require.Equal(t, license.PhaseLocked, first.Phase)
	assert.True(t, first.InContinuity())
	assert.Equal(t, 45, first.ContinuityDaysLeft)

	mid := license.Evaluate(locksAt.Add(44*day+time.Hour), installedAt, baseline())
	assert.True(t, mid.InContinuity())
	assert.Equal(t, 1, mid.ContinuityDaysLeft, "rounded up")

	over := license.Evaluate(ends, installedAt, baseline())
	assert.Equal(t, license.PhaseLocked, over.Phase)
	assert.False(t, over.InContinuity(), "the window ends at ContinuityEndsAt")
	assert.Zero(t, over.ContinuityDaysLeft)
	assert.Equal(t, ends, over.ContinuityEndsAt)
}

func TestEvaluationHasNoContinuity(t *testing.T) {
	during := license.Evaluate(installedAt.Add(day), installedAt, nil)
	assert.True(t, during.ContinuityEndsAt.IsZero())
	ended := license.Evaluate(installedAt.Add(31*day), installedAt, nil)
	require.Equal(t, license.PhaseEvaluationExpired, ended.Phase)
	assert.True(t, ended.ContinuityEndsAt.IsZero())
	assert.False(t, ended.InContinuity())
	assert.Zero(t, ended.ContinuityDaysLeft)
}

// The gate: ClassContinuity runs wherever ClassChange runs, and in a licensed lock until ContinuityEndsAt.
func TestGateContinuity(t *testing.T) {
	locksAt := expiry.Add(license.GracePeriod)
	ends := locksAt.Add(license.ContinuityPeriod)
	active := snapshotAt(expiry.Add(-100*day), baseline())
	inWindow := snapshotAt(locksAt.Add(10*day), baseline())
	lastHour := snapshotAt(ends.Add(-time.Hour), baseline())
	after := snapshotAt(ends, baseline())
	evalEnded := snapshotAt(installedAt.Add(31*day), nil)
	evalSoon := snapshotAt(installedAt.Add(30*day-time.Hour), nil)
	graceSoon := snapshotAt(locksAt.Add(-time.Hour), baseline())
	notReady := active
	notReady.Ready = false

	type row struct {
		name      string
		snap      license.Snapshot
		since     time.Duration
		want      error
		confirmed bool
	}
	for _, r := range []row{
		{"active", active, 0, nil, false},
		{"not started", notReady, 0, license.ErrUnverified, false},
		{"active, stale", active, license.MaxEvaluationAge + time.Second, license.ErrUnverified, false},
		{"grace, LocksAt passed by uptime: still before the window's end", graceSoon, 2 * time.Hour, nil, false},
		{"locked, in the window", inWindow, 0, nil, false},
		{"locked, in the window, stale", inWindow, 4 * time.Hour, license.ErrUnverified, false},
		{"locked, 59 minutes before the end", lastHour, 59 * time.Minute, nil, false},
		{"locked, the end reached by uptime", lastHour, time.Hour, license.ErrLockDue, false},
		{"locked, the window evaluated as ended", after, 0, license.ErrLocked, true},
		{"evaluation ended: no window", evalEnded, 0, license.ErrLocked, true},
		{"evaluation, its end reached by uptime: no window", evalSoon, time.Hour, license.ErrLockDue, false},
	} {
		got := license.AllowIn(r.snap, license.ClassContinuity, r.since)
		if r.want == nil {
			assert.NoError(t, got, r.name)
			continue
		}
		assert.ErrorIs(t, got, r.want, r.name)
		assert.Equal(t, r.confirmed, license.ConfirmedLock(got), r.name)
	}
	// Change and read-only work stay refused in the window.
	assert.ErrorIs(t, license.AllowIn(inWindow, license.ClassChange, 0), license.ErrLocked)
	assert.True(t, license.ConfirmedLock(license.AllowIn(inWindow, license.ClassReadOnly, 0)))
}

func TestContinuityClassName(t *testing.T) {
	assert.Equal(t, "continuity", license.ClassContinuity.String())
	assert.True(t, license.ClassContinuity.Valid())
}

// The banners say what the window means: renewals go on until a date, then they stop.
func TestContinuityBanners(t *testing.T) {
	locksAt := expiry.Add(license.GracePeriod)
	in := snapshotAt(locksAt.Add(5*day), baseline())
	assert.Equal(t, []string{"locked_continuity/danger"}, kinds(in.Banners(false)))
	assert.Equal(t, map[string]string{"valid_until": "2027-10-01T00:00:00Z", "continuity_ends_at": "2027-11-22T00:00:00Z",
		"days_left": "40"}, in.Banners(false)[0].Params)
	after := snapshotAt(locksAt.Add(license.ContinuityPeriod), baseline())
	assert.Equal(t, []string{"locked/danger"}, kinds(after.Banners(false)))
	assert.Equal(t, map[string]string{"valid_until": "2027-10-01T00:00:00Z", "continuity_ended_at": "2027-11-22T00:00:00Z"},
		after.Banners(false)[0].Params)
	assert.Equal(t, []string{"evaluation_ended/danger"}, kinds(snapshotAt(installedAt.Add(31*day), nil).Banners(false)),
		"the evaluation has no window")
}

// The notices: one when the lock begins (naming the window's end), one when the window ends.
func TestContinuityNotices(t *testing.T) {
	locksAt := expiry.Add(license.GracePeriod)
	key, tpl, params, ok := license.DueNotice(snapshotAt(locksAt.Add(time.Hour), baseline()))
	require.True(t, ok)
	assert.Equal(t, "locked", key)
	assert.Equal(t, license.TemplateLocked, tpl)
	assert.Equal(t, "2027-11-22 00:00 UTC", params["continuity_ends_at"])
	assert.Equal(t, "45", params["continuity_days_left"])

	key, tpl, params, ok = license.DueNotice(snapshotAt(locksAt.Add(license.ContinuityPeriod), baseline()))
	require.True(t, ok)
	assert.Equal(t, "continuity_ended", key)
	assert.Equal(t, license.TemplateContinuityEnded, tpl)
	assert.Equal(t, "2027-11-22 00:00 UTC", params["continuity_ends_at"])
	assert.Contains(t, license.Templates(), license.TemplateContinuityEnded)

	key, _, _, ok = license.DueNotice(snapshotAt(installedAt.Add(31*day), nil))
	require.True(t, ok)
	assert.Equal(t, "evaluation_ended", key, "the evaluation's end has no window and no window notice")
}
