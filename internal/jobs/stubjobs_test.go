package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// Stub job types for L-29 and L-81..L-88 (spec §26.4): the real jobs arrive in Phases 3, 4
// and 6, where the cases are re-run.
var (
	testVerify   = Register("test.verify", license.ClassAlways)
	testPoll     = Register("test.kvpoll", license.ClassReadOnly)
	testRotation = Register("test.rotation", license.ClassReadOnly)
)

// stubStore records everything a stub job could destroy or send.
type stubStore struct {
	mu       sync.Mutex
	rows     int
	deleted  int
	commands []string
	events   []string
}

func (s *stubStore) event(e string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *stubStore) snapshot() (rows, deleted int, commands, events []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows, s.deleted, append([]string(nil), s.commands...), append([]string(nil), s.events...)
}

// L-29: in lock the integrity verification runs and deletes nothing, revokes nothing and
// runs no remote command; scheduled external-read work stays paused.
func TestLockDeletesNothing(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	store := &stubStore{rows: 5}
	gate := &fakeGate{locked: true}
	var polled atomic.Int32
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testVerify, Every: time.Hour, Run: func(context.Context) error { store.event("verified"); return nil }},
		Task{Type: testPoll, Every: time.Minute, Run: func(context.Context) error { polled.Add(1); return nil }},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	require.NoError(t, s.RunNow(ctx, "test.verify"))
	assert.ErrorIs(t, s.RunNow(ctx, "test.kvpoll"), license.ErrLocked)
	rows, deleted, commands, events := store.snapshot()
	assert.Equal(t, 5, rows)
	assert.Zero(t, deleted)
	assert.Empty(t, commands, "no remote command while locked")
	assert.Equal(t, []string{"verified"}, events)
	assert.Zero(t, polled.Load())
}

// L-81 (scheduler part): work that is due at lock time is not started and stays unstarted
// after the renewal until something starts it again; the scheduler never queues a missed
// run. External-change work cannot be scheduled at all (R29: confirmation needs the queue).
func TestDueWorkIsNotStartedInLockAndNotReplayedAfterRenewal(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{locked: true}
	var runs atomic.Int32
	s := NewScheduler(clk, gate, quiet, Task{Type: testPoll, Every: time.Minute, Run: func(context.Context) error { runs.Add(1); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	for range 5 {
		clk.Advance(time.Minute)
		time.Sleep(10 * time.Millisecond)
	}
	assert.Zero(t, runs.Load(), "paused: nothing started")
	gate.set(false)
	time.Sleep(30 * time.Millisecond)
	assert.Zero(t, runs.Load(), "missed ticks are not replayed on renewal")
	assert.Panics(t, func() {
		NewScheduler(clk, gate, quiet, Task{Type: testDeploy, Every: time.Minute, Run: func(context.Context) error { return nil }})
	})
}

// L-82, L-85: an in-flight run is never cancelled by the lock; its own rollback or
// verification steps run to completion, and the next run is refused.
func TestInFlightRunFinishesItsStepsAndRollbackDespiteLock(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{}
	store := &stubStore{}
	started, release := make(chan struct{}), make(chan struct{})
	var ctxErr atomic.Value
	s := NewScheduler(clk, gate, quiet, Task{Type: testRotation, Every: time.Hour, Run: func(ctx context.Context) error {
		store.event("add-new-key")
		close(started)
		<-release
		ctxErr.Store(ctx.Err() == nil)
		store.event("verify")
		store.event("rollback-own-addition")
		return nil
	}})
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(context.Background(), "test.rotation") }()
	<-started
	gate.set(true)
	close(release)
	require.NoError(t, <-errc)
	assert.Equal(t, true, ctxErr.Load(), "lock does not cancel the running task's context")
	_, _, _, events := store.snapshot()
	assert.Equal(t, []string{"add-new-key", "verify", "rollback-own-addition"}, events)
	assert.ErrorIs(t, s.RunNow(context.Background(), "test.rotation"), license.ErrLocked, "the removal step of a later run is paused")
}

// L-83, L-88: while locked, a due recurring task (overlap timer, dry-run notice) does
// nothing; always-class work keeps running on the same clock.
func TestLockedTicksPauseWorkWhileAlwaysClassContinues(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{locked: true}
	store := &stubStore{}
	ran := make(chan struct{}, 50)
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testRotation, Every: time.Hour, Run: func(context.Context) error { store.event("overlap-removal-or-notice"); return nil }},
		Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { ran <- struct{}{}; return nil }},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	advanceUntil(t, clk, time.Hour, ran) // an hour passes: the rotation task is due, the mail task runs
	time.Sleep(30 * time.Millisecond)
	_, _, _, events := store.snapshot()
	assert.Empty(t, events, "nothing removed or sent by paused work")
	cancel()
	<-done
}

// L-87: a read-only request in flight at lock finishes and stores its result; the lock
// starts no follow-up run from it.
func TestInFlightPollFinishesAndTriggersNothingInLock(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{}
	store := &stubStore{}
	started, release := make(chan struct{}), make(chan struct{})
	s := NewScheduler(clk, gate, quiet, Task{Type: testPoll, Every: time.Hour, Run: func(context.Context) error {
		close(started)
		<-release
		store.event("result-stored")
		return nil
	}})
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(context.Background(), "test.kvpoll") }()
	<-started
	gate.set(true)
	close(release)
	require.NoError(t, <-errc)
	assert.ErrorIs(t, s.RunNow(context.Background(), "test.kvpoll"), license.ErrLocked, "no follow-up (auto-deploy) run is started")
	_, _, _, events := store.snapshot()
	assert.Equal(t, []string{"result-stored"}, events)
}

// Every run asks the gate: a class the gate does not know fails closed and the task does
// not run.
func TestGateRefusalOtherThanLockAlsoStopsTheRun(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	var ran atomic.Bool
	s := NewScheduler(clk, refuseAll{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { ran.Store(true); return nil }})
	assert.Error(t, s.RunNow(context.Background(), "notify.send"))
	assert.False(t, ran.Load())
}

type refuseAll struct{}

func (refuseAll) Allow(license.Class) error { return license.ErrUnclassified }
