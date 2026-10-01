//go:build integration

package license_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// L-10..L-13: one email per threshold, none in between, none before 60 days.
func TestNoticesAreSentOncePerThreshold(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)

	e.tickAt(until.Add(-61*day - 12*time.Hour))
	assert.Empty(t, e.notices.templates(), "L-10")
	for _, d := range []int{60, 30, 14, 7, 1} {
		at := until.Add(-time.Duration(d) * day)
		e.tickAt(at)
		for h := 1; h <= 3; h++ {
			e.tickAt(at.Add(time.Duration(h) * time.Hour)) // L-12: hourly ticks send nothing new
		}
	}
	assert.Equal(t, repeat(license.TemplateExpiryWarning, 5), e.notices.templates())
	assert.Equal(t, 5, e.auditCount("license.warning.sent"))
	assert.Equal(t, 5, e.countWhere("license_history", "event = 'notice' AND license_id = 'LIC-A' AND notice LIKE 'expiry:%'"))
	e.notices.mu.Lock()
	params := e.notices.calls[1]
	e.notices.mu.Unlock()
	assert.Equal(t, "30", params["days_left"])
	assert.Equal(t, "Test Company", params["customer"])
	assert.Equal(t, e.installation(), params["installation_id"])
	assert.Equal(t, until.UTC().Format("2006-01-02 15:04 UTC"), params["ends_at"])
}

// Review Focus 5 and L-16: after downtime only the current threshold is sent.
func TestCatchUpSendsOnlyTheCurrentThreshold(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-31 * day))
	e.clk.Set(until.Add(-29 * day)) // Alice was down for two days
	e.restart()
	assert.Equal(t, 2, len(e.notices.templates()))
	assert.Equal(t, 1, e.countWhere("license_history", "notice = 'expiry:60'"))
	assert.Equal(t, 1, e.countWhere("license_history", "notice = 'expiry:30'"))
	assert.Zero(t, e.countWhere("license_history", "notice IN ('expiry:14', 'expiry:7', 'expiry:1')"))

	e.restart() // L-14: a restart repeats nothing
	e.tickAt(until.Add(-29*day + time.Hour))
	assert.Equal(t, 2, len(e.notices.templates()))
}

// L-17, L-31: a renewal restarts the warnings from its own valid_until.
func TestRenewalRestartsWarnings(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-20 * day))
	require.Len(t, e.notices.templates(), 1)
	_, err = e.upload(e.payload("LIC-B", until.Add(-20*day), until.Add(345*day), 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-14 * day))
	assert.Len(t, e.notices.templates(), 1, "no 14-day warning of the replaced license")
	e.tickAt(until.Add(3 * day))
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
}

// L-20..L-24: grace is announced daily, the lock once, each transition audited once.
func TestTickGraceAndLock(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-1 * day)) // the 1-day warning (the only one: catch-up sends the current threshold)
	e.tickAt(until)
	assert.Equal(t, "grace", e.state())
	for n := 2; n <= 7; n++ {
		e.tickAt(until.Add(time.Duration(n-1) * day))
		e.tickAt(until.Add(time.Duration(n-1)*day + 12*time.Hour))
	}
	require.NoError(t, e.svc.Allow(license.ClassChange), "grace: everything works (L-22)")
	e.tickAt(until.Add(168 * time.Hour))
	assert.Equal(t, "locked", e.state())
	e.restart()
	e.tickAt(until.Add(169 * time.Hour))

	want := append([]string{license.TemplateExpiryWarning}, repeat(license.TemplateGrace, 7)...)
	assert.Equal(t, append(want, license.TemplateLocked), e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.expired"), "L-20: once")
	assert.Equal(t, 1, e.auditCount("license.locked"), "L-24")
	assert.Equal(t, 2, e.countWhere("license_history", "event = 'state_change'"))
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.NoError(t, e.svc.Allow(license.ClassAlways))
}

// L-07 and L-03: evaluation warnings at 7, 3 and 1 days, then the end (no grace).
func TestEvaluationNotices(t *testing.T) {
	e := newEnv(t)
	for _, d := range []time.Duration{23 * day, 27 * day, 29 * day, 30 * day} {
		e.tickAt(installedAt.Add(d))
	}
	assert.Equal(t, append(repeat(license.TemplateEvaluationWarning, 3), license.TemplateEvaluationEnded), e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.evaluation_ended"))
	assert.Equal(t, "evaluation_expired", e.state())
	assert.Equal(t, 4, e.countWhere("license_history", "event = 'notice' AND license_id = 'evaluation'"))
}

// L-18: without email the banner and the record still appear; nobody sees an error.
func TestWithoutEmailTheBannerStillShows(t *testing.T) {
	e := newEnv(t)
	e.noMail = true
	e.restart()
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-30 * day))
	assert.Empty(t, e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.warning.sent"))
	assert.Contains(t, kinds(e.svc.Snapshot().Banners(true)), "expiry_warning/warning")
}

// Review Focus 1, L-51: a clock set back never extends the license and is audited once a day.
func TestRollbackIsWarnedOncePerDay(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(15*day), 10))
	require.NoError(t, err)
	e.tickAt(now.Add(10 * day))

	e.clk.JumpWall(-20 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap := e.svc.Snapshot()
	assert.True(t, snap.Reading.Behind)
	assert.True(t, snap.Reading.Effective.Equal(now.Add(10*day)), "the high-water mark is used")
	assert.Equal(t, 5, snap.Eval.DaysLeft, "not extended")
	assert.Contains(t, kinds(snap.Banners(true)), "clock_behind/caution")
	assert.Equal(t, 1, e.auditCount("clock.rollback_detected"))

	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, 1, e.auditCount("clock.rollback_detected"), "once per day")
	assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(now.Add(10*day+time.Hour)), "time keeps moving with uptime")
	e.clk.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, 2, e.auditCount("clock.rollback_detected"))
}

// R36 item 9 (L-52): a clock less than 65 minutes behind is not a finding.
func TestSmallRollbackIsNotAudited(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(time.Hour))
	e.clk.JumpWall(-60 * time.Minute)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.False(t, e.svc.Snapshot().Reading.Behind)
	assert.Zero(t, e.auditCount("clock.rollback_detected"))
	assert.Zero(t, e.countWhere("license_history", "notice LIKE 'clock_behind:%'"))
}

// Review Focus 1, L-58: restarts with the clock set back never move time backwards.
func TestRestartsNeverMoveEffectiveTimeBackwards(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(10 * day))
	last := e.svc.Snapshot().Reading.Effective
	for i := range 10 {
		e.clk.JumpWall(-24 * time.Hour)
		e.restart()
		eff := e.svc.Snapshot().Reading.Effective
		assert.False(t, eff.Before(last), "restart %d", i)
		last = eff
	}
	assert.False(t, last.Before(installedAt.Add(10*day)))
}

// L-59, L-60: a forward jump warns first, survives a restart, and counts after 24 h of uptime.
func TestForwardJumpIsHeldThenAccepted(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))

	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap := e.svc.Snapshot()
	require.NotNil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseActive, snap.Eval.Phase, "warn first, no immediate lock")
	assert.Contains(t, kinds(snap.Banners(true)), "clock_jump/caution")
	assert.Equal(t, 1, e.auditCount("clock.forward_jump"))
	assert.Contains(t, e.notices.templates(), license.TemplateClockJump)
	assert.Equal(t, 1, e.countWhere("license", "clock_jump IS NOT NULL"))

	e.restart()
	assert.NotNil(t, e.svc.Snapshot().Reading.Jump, "the hold survives a restart")
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)

	e.clk.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap = e.svc.Snapshot()
	assert.Nil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseLocked, snap.Eval.Phase, "L-60: the new time is accepted")
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	assert.Zero(t, e.countWhere("license", "clock_jump IS NOT NULL"))
}

// A held jump ends when the clock is set right again; that is audited once and the hold is removed.
func TestForwardJumpClearedWhenTheClockIsCorrected(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(time.Hour))
	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	require.NotNil(t, e.svc.Snapshot().Reading.Jump)

	e.clk.JumpWall(-200 * day)
	for range 2 {
		e.clk.Advance(time.Hour)
		require.NoError(t, e.svc.Tick(e.ctx))
	}
	assert.Nil(t, e.svc.Snapshot().Reading.Jump)
	assert.Equal(t, 1, e.auditCount("clock.forward_jump"))
	assert.Equal(t, 1, e.auditCount("clock.jump_cleared"))
	assert.Zero(t, e.auditCount("clock.jump_accepted"))
	assert.Zero(t, e.countWhere("license", "clock_jump IS NOT NULL"))
	assert.Equal(t, 2, e.countWhere("license_history", "event = 'clock_anomaly'"))
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
}

// L-61: a correction license ends the hold at once; the HWM stays at the new time.
func TestCorrectionLicenseAcceptsTheJump(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	jumped := e.clk.Now()

	fix := e.payload("LIC-FIX", jumped.Add(-time.Hour), jumped.Add(365*day), 10)
	fix.Replaces = "LIC-A"
	_, err = e.upload(fix)
	require.NoError(t, err)
	snap := e.svc.Snapshot()
	assert.Nil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseActive, snap.Eval.Phase)
	assert.Equal(t, "LIC-FIX", snap.Eval.Key())
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	raw, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(t, err)
	rec, err := license.NewHWMCodec(e.keyring).Decode(raw)
	require.NoError(t, err)
	assert.False(t, rec.At.Before(jumped.Truncate(time.Second)), "no rollback of the HWM")
}

// L-49: a damaged stored file is audited once, however often it is evaluated.
func TestTamperedFileIsAuditedOnce(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file =
		convert_to(replace(convert_from(raw_file, 'UTF8'), 'Test Company', 'Evil Company'), 'UTF8')`)
	require.NoError(t, err)
	for range 3 {
		e.clk.Advance(time.Hour)
		require.NoError(t, e.svc.Tick(e.ctx))
	}
	assert.Equal(t, 1, e.auditCount("license.tampered"))
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
	assert.True(t, e.svc.Snapshot().Tampered)
	d := e.auditDetails("license.tampered")
	assert.Equal(t, "invalid_signature", d["reason"])
	assert.NotContains(t, d, "raw_file", "no file content in the audit log")
	for _, v := range d {
		assert.NotContains(t, v, "Company")
	}
}

// Task 8 review: an upload that committed is reported as accepted even when the evaluation
// that follows it fails; that evaluation's effects (here the due warning) roll back and are
// made by the next successful one, still exactly once.
func TestUploadSucceedsWhenOnlyTheFollowUpTickFails(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	e.notices.fail = errors.New("outbox unavailable")
	res, err := e.upload(e.payload("LIC-A", now, now.Add(10*day), 10)) // 14-day warning due at once
	require.NoError(t, err)
	assert.Equal(t, license.PhaseActive, res.Phase)
	assert.Equal(t, 1, e.countWhere("license_files", "true"))
	assert.Equal(t, 1, e.auditCount("license.activated"))
	assert.Zero(t, e.auditCount("license.warning.sent"), "the failed evaluation left nothing behind")

	e.notices.fail = nil
	for range 2 {
		e.clk.Advance(time.Hour)
		require.NoError(t, e.svc.Tick(e.ctx))
	}
	assert.Equal(t, []string{license.TemplateExpiryWarning}, e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.warning.sent"))
}

// Task 8 review: the guard is published only after the evaluation commits, so a forward jump
// seen by a failed evaluation is detected, stored and audited by the next one.
func TestFailedTickDoesNotLoseAClockJump(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(time.Hour))
	e.clk.JumpWall(200 * day)
	e.notices.fail = errors.New("outbox unavailable")
	require.Error(t, e.svc.Tick(e.ctx))
	assert.Nil(t, e.svc.Snapshot().Reading.Jump, "nothing published")
	assert.Zero(t, e.countWhere("license", "clock_jump IS NOT NULL"))

	e.notices.fail = nil
	require.NoError(t, e.svc.Tick(e.ctx))
	require.NotNil(t, e.svc.Snapshot().Reading.Jump)
	assert.Equal(t, 1, e.auditCount("clock.forward_jump"))
	assert.Equal(t, 1, e.countWhere("license", "clock_jump IS NOT NULL"))
	assert.Equal(t, []string{license.TemplateClockJump}, e.notices.templates())
}

func TestTemplatesListsEveryEmail(t *testing.T) {
	assert.ElementsMatch(t, []string{"license.expiry_warning", "license.evaluation_warning", "license.evaluation_ended",
		"license.grace", "license.locked", "license.clock_jump"}, license.Templates())
}

// B2: the evaluation that follows a committed upload does not depend on the request, so a
// browser that disconnects right after the commit does not leave the gate on the old state
// until the next hourly evaluation.
func TestFollowUpTickOutlivesTheRequest(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(31 * day))
	require.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase)

	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	license.SetUploadCommittedHook(e.svc, cancel) // the client goes away right after the commit
	now := e.clk.Now()
	res, err := e.svc.Install(ctx, licensetest.Sign(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10)), uploader, uuid.Nil)
	require.NoError(t, err)
	assert.Equal(t, license.PhaseActive, res.Phase)
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase, "the follow-up evaluation ran")
	require.NoError(t, e.svc.Allow(license.ClassChange))
}
