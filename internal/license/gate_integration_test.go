//go:build integration

package license_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// leaderLockKey is jobs.leaderLockKey (unexported): the session advisory lock of the scheduling leader.
const leaderLockKey int64 = 7160927315633811303

// holdLicenseRow opens a transaction of the application role that holds the license row lock,
// as a customer's database session can (AUD-02). It is rolled back at the end of the test.
func (e *env) holdLicenseRow() func() {
	e.t.Helper()
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(e.t, err)
	_, err = tx.Exec(e.ctx, "SELECT 1 FROM license WHERE id = 1 FOR UPDATE")
	require.NoError(e.t, err)
	released := false
	release := func() {
		if !released {
			released = true
			require.NoError(e.t, tx.Rollback(e.ctx))
		}
	}
	e.t.Cleanup(release)
	return release
}

// AUD-02 (the audit's first PoC, inverted): a session holding the license row stops every
// evaluation; the gate still locks at LocksAt, by the monotonic time since the last evaluation.
func TestGateLocksAtLocksAtWhileTheRowIsHeld(t *testing.T) {
	e := newEnv(t)
	license.SetRowLockTimeout(e.svc, 200*time.Millisecond)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	locksAt := now.Add(24*time.Hour + license.GracePeriod)
	e.tickAt(locksAt.Add(-time.Hour)) // grace, evaluated
	auditsBefore := e.countWhere("audit_log", "true")

	e.holdLicenseRow()
	e.clk.Set(locksAt.Add(time.Minute))
	start := time.Now()
	require.Error(t, e.svc.Tick(e.ctx), "the evaluation gives up instead of waiting for ever")
	assert.Less(t, time.Since(start), 10*time.Second, "bounded by the row lock timeout")
	assert.Equal(t, license.PhaseGrace, e.svc.Snapshot().Eval.Phase, "the snapshot is stale")
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked, "but the gate locked at LocksAt")
	assert.NotErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrUnverified, "61 minutes is not stale yet")
	assert.ErrorIs(t, e.svc.Allow(license.ClassReadOnly), license.ErrLocked)
	assert.NoError(t, e.svc.Allow(license.ClassAlways), "recovery and rollback still run")
	assert.False(t, e.svc.Snapshot().Unverified)
	assert.Equal(t, auditsBefore, e.countWhere("audit_log", "true"), "the failed evaluation wrote nothing")

	// 29 days after LocksAt (the PoC's moment), still without one evaluation: refused, now as unverified.
	e.clk.Set(locksAt.Add(29 * day))
	require.Error(t, e.svc.Tick(e.ctx))
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrUnverified)
}

// AUD-02: no successful evaluation for MaxEvaluationAge closes the gate (fail closed); the next
// successful one opens it again, without a restart.
func TestGateFailsClosedWhenEvaluationsStop(t *testing.T) {
	e := newEnv(t)
	license.SetRowLockTimeout(e.svc, 200*time.Millisecond)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(365*24*time.Hour), 10))
	require.NoError(t, err)
	release := e.holdLicenseRow()

	e.clk.Advance(license.MaxEvaluationAge - time.Minute)
	require.Error(t, e.svc.Tick(e.ctx))
	assert.NoError(t, e.svc.Allow(license.ClassChange), "not stale yet")
	e.clk.Advance(2 * time.Minute)
	require.Error(t, e.svc.Tick(e.ctx))
	err = e.svc.Allow(license.ClassChange)
	assert.ErrorIs(t, err, license.ErrUnverified)
	assert.ErrorIs(t, err, license.ErrLocked, "every lock-mode path treats it as lock")
	assert.ErrorIs(t, e.svc.Allow(license.ClassReadOnly), license.ErrUnverified)
	assert.NoError(t, e.svc.Allow(license.ClassAlways))
	snap := e.svc.Snapshot()
	assert.True(t, snap.Unverified)
	assert.Equal(t, license.PhaseActive, snap.Eval.Phase, "the last evaluated state is kept for display")
	assert.Contains(t, kinds(snap.Banners(false)), "unverified/danger")
	_, err = e.upload(e.payload("LIC-B", now, now.Add(400*24*time.Hour), 10))
	require.Error(t, err, "an upload waits for the row lock as long as an evaluation, then fails")

	release()
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.NoError(t, e.svc.Allow(license.ClassChange))
	assert.False(t, e.svc.Snapshot().Unverified)
}

// Setting the wall clock back between evaluations neither stretches the 3 hours nor delays LocksAt:
// the gate measures uptime, which a wall-clock change does not move.
func TestGateIgnoresTheWallClockBetweenEvaluations(t *testing.T) {
	e := newEnv(t)
	license.SetRowLockTimeout(e.svc, 200*time.Millisecond)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	locksAt := now.Add(24*time.Hour + license.GracePeriod)
	e.tickAt(locksAt.Add(-30 * time.Minute))
	e.holdLicenseRow()

	e.clk.JumpWall(-48 * time.Hour) // the clock is set back two days
	e.clk.Advance(31 * time.Minute)
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked, "LocksAt is reached by uptime regardless")
	e.clk.Advance(license.MaxEvaluationAge)
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrUnverified)
}

// A service that has not completed Start answers "not verified": closed for changes, open for
// sign-in and uploads (ClassAlways).
func TestGateBeforeTheFirstEvaluation(t *testing.T) {
	e := newEnv(t)
	svc := e.newService()
	err := svc.Allow(license.ClassChange)
	assert.ErrorIs(t, err, license.ErrUnverified)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.NoError(t, svc.Allow(license.ClassAlways))
	assert.False(t, svc.Snapshot().Ready)
	assert.False(t, svc.Snapshot().Unverified, "nothing to show before the first evaluation (the status endpoint answers 503)")
	require.NoError(t, svc.Start(e.ctx))
	assert.NoError(t, svc.Allow(license.ClassChange))
}

// A start whose first evaluation cannot take the license row gives up after the row lock timeout.
func TestStartGivesUpWhenTheRowIsHeld(t *testing.T) {
	e := newEnv(t)
	e.holdLicenseRow()
	svc := license.New(license.Config{
		Pool: e.db.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk, Keys: licensetest.KeySet(),
		StateDir: e.stateDir, RowLockTimeout: 200 * time.Millisecond, Log: slog.New(slog.DiscardHandler),
	})
	start := time.Now()
	require.Error(t, svc.Start(e.ctx))
	assert.Less(t, time.Since(start), 10*time.Second)
	assert.ErrorIs(t, svc.Allow(license.ClassChange), license.ErrUnverified)
}

// AUD-02 (the audit's second PoC, inverted): a foreign session holding the scheduling lock no
// longer stops license.evaluate.
func TestForeignLeaderLockDoesNotStopEvaluation(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	conn, err := e.db.App.Acquire(e.ctx)
	require.NoError(t, err)
	_, err = conn.Exec(e.ctx, "SELECT pg_advisory_lock($1)", leaderLockKey)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", leaderLockKey)
		conn.Release()
	}()
	log := slog.New(slog.DiscardHandler)
	leader := jobs.NewLeader(e.db.App, log)
	sched := jobs.NewScheduler(e.clk, e.svc, log, jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Hour, Run: e.svc.Tick}).WithLeader(leader)
	ctx, stop := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() { sched.Run(ctx); close(done) }()
	defer func() { stop(); <-done; leader.Close() }()

	e.clk.Advance(40 * day)
	require.Eventually(t, func() bool {
		e.clk.Advance(time.Hour)
		return e.svc.Snapshot().Eval.Phase == license.PhaseLocked
	}, 10*time.Second, 100*time.Millisecond, "the evaluation ran although another session holds the leader lock")
	assert.False(t, leader.IsLeader(e.ctx))
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.NotErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrUnverified)
}

// Every process evaluates (AUD-02), so two evaluators see every transition. The license row lock
// serializes them and each transition, notice, email and clock event is recorded once.
func TestTwoEvaluatorsRecordEachTransitionOnce(t *testing.T) {
	e := newEnv(t)
	other := e.newService()
	require.NoError(t, other.Start(e.ctx))
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	both := func() {
		t.Helper()
		require.NoError(t, e.svc.Tick(e.ctx))
		require.NoError(t, other.Tick(e.ctx))
	}

	e.clk.Advance(25 * time.Hour) // grace
	both()
	both()
	assert.Equal(t, 1, e.auditCount("license.expired"))
	assert.Equal(t, 1, e.countWhere("license_history", "event = 'state_change' AND to_state = 'grace'"))
	assert.Equal(t, 1, countOf(e.notices.templates(), license.TemplateGrace), "one grace email")

	e.clk.JumpWall(10 * day) // a forward jump of the system clock past LocksAt: held (R26)
	both()
	both()
	assert.Equal(t, 1, e.auditCount("clock.forward_jump"))
	assert.Equal(t, 1, e.countWhere("license_history", "event = 'clock_anomaly' AND details->>'problem' = 'forward_jump'"))
	assert.Equal(t, 1, countOf(e.notices.templates(), license.TemplateClockJump), "one clock email")
	assert.Equal(t, license.PhaseGrace, e.svc.Snapshot().Eval.Phase)
	assert.Equal(t, license.PhaseGrace, other.Snapshot().Eval.Phase, "both hold the jump")

	e.clk.Advance(license.JumpSettle) // the jump is accepted after 24 h of uptime: the license locks
	both()
	both()
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	assert.Equal(t, 1, e.auditCount("license.locked"))
	assert.Equal(t, 1, countOf(e.notices.templates(), license.TemplateLocked))
	assert.Equal(t, license.PhaseLocked, other.Snapshot().Eval.Phase)
	assert.ErrorIs(t, other.Allow(license.ClassChange), license.ErrLocked)
}

// Two evaluations started at once wait for each other on the row lock (no deadlock) and both succeed.
func TestConcurrentEvaluationsBothSucceed(t *testing.T) {
	e := newEnv(t)
	other := e.newService()
	require.NoError(t, other.Start(e.ctx))
	e.clk.Advance(30 * day) // the evaluation ends
	errs := make(chan error, 8)
	for range 4 {
		go func() { errs <- e.svc.Tick(e.ctx) }()
		go func() { errs <- other.Tick(e.ctx) }()
	}
	for range 8 {
		require.NoError(t, <-errs)
	}
	assert.Equal(t, 1, e.auditCount("license.evaluation_ended"))
	assert.Equal(t, 1, countOf(e.notices.templates(), license.TemplateEvaluationEnded))
}

func countOf(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}
