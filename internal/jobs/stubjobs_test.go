package jobs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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

// countingGate wraps fakeGate and reports every Allow call, so a test can wait until ticks
// were really evaluated before it asserts that nothing ran.
type countingGate struct {
	fakeGate
	mu    sync.Mutex
	calls map[license.Class]int
}

func (g *countingGate) Allow(c license.Class) error {
	err := g.fakeGate.Allow(c)
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[license.Class]int{}
	}
	g.calls[c]++
	g.mu.Unlock()
	return err
}

func (g *countingGate) count(c license.Class) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[c]
}

// tickUntilAllows moves the fake clock by every until the gate has been asked n times for
// class c (the loops may not have created their tickers on the first moves).
func tickUntilAllows(t *testing.T, clk *clock.Fake, every time.Duration, g *countingGate, c license.Class, n int) {
	t.Helper()
	for range 500 {
		if g.count(c) >= n {
			return
		}
		clk.Advance(every)
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the gate was asked %d times for %v, want %d", g.count(c), c, n)
}

// sideEffects is stub work with real effects: a read-only job that deletes a row and runs a
// remote command when it is allowed to run.
func (s *stubStore) sideEffects(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows--
	s.deleted++
	s.commands = append(s.commands, "nginx -t")
	return nil
}

// L-29: in lock the integrity verification runs; scheduled and manual runs of work with
// side effects are refused, so nothing is deleted and no remote command is executed.
func TestLockDeletesNothing(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	store := &stubStore{rows: 5}
	gate := &countingGate{fakeGate: fakeGate{locked: true}}
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testVerify, Every: time.Minute, Run: func(context.Context) error { store.event("verified"); return nil }},
		Task{Type: testPoll, Every: time.Minute, Run: store.sideEffects},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	tickUntilAllows(t, clk, time.Minute, gate, license.ClassReadOnly, 3)
	assert.ErrorIs(t, s.RunNow(ctx, "test.kvpoll"), license.ErrLocked)
	require.NoError(t, s.RunNow(ctx, "test.verify"))
	cancel()
	<-done
	rows, deleted, commands, events := store.snapshot()
	assert.Equal(t, 5, rows)
	assert.Zero(t, deleted)
	assert.Empty(t, commands, "no remote command while locked")
	assert.NotEmpty(t, events, "verification still runs in lock")

	// Control: the same stub does act when the gate allows it.
	gate.set(false)
	require.NoError(t, s.RunNow(context.Background(), "test.kvpoll"))
	_, deleted, commands, _ = store.snapshot()
	assert.Equal(t, 1, deleted)
	assert.Len(t, commands, 1)
}

// L-81 (scheduler part): work that is due at lock time is not started. After the renewal
// the scheduler starts it again only by its normal schedule; external-change work cannot be
// scheduled at all (R29: confirmation needs the queue).
func TestDueWorkIsNotStartedInLockAndResumesOnNextTickAfterRenewal(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &countingGate{fakeGate: fakeGate{locked: true}}
	var runs atomic.Int32
	s := NewScheduler(clk, gate, quiet, Task{Type: testPoll, Every: time.Minute, Run: func(context.Context) error { runs.Add(1); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	tickUntilAllows(t, clk, time.Minute, gate, license.ClassReadOnly, 5)
	assert.Zero(t, runs.Load(), "five ticks evaluated by the gate, none ran")
	gate.set(false)
	n := gate.count(license.ClassReadOnly)
	tickUntilAllows(t, clk, time.Minute, gate, license.ClassReadOnly, n+2)
	require.Eventually(t, func() bool { return runs.Load() > 0 }, 2*time.Second, 5*time.Millisecond)
	cancel()
	<-done
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
	gate := &countingGate{fakeGate: fakeGate{locked: true}}
	store := &stubStore{rows: 1}
	var mails atomic.Int32
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testRotation, Every: time.Minute, Run: func(ctx context.Context) error {
			store.event("overlap-removal-or-notice")
			return store.sideEffects(ctx)
		}},
		Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { mails.Add(1); return nil }},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	tickUntilAllows(t, clk, time.Minute, gate, license.ClassReadOnly, 4)
	require.Eventually(t, func() bool { return mails.Load() >= 1 }, 2*time.Second, 5*time.Millisecond, "always-class work runs in lock")
	cancel()
	<-done
	rows, deleted, commands, events := store.snapshot()
	assert.Equal(t, 1, rows)
	assert.Zero(t, deleted)
	assert.Empty(t, commands)
	assert.Empty(t, events, "nothing removed or sent by paused work")
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

// A running task makes RunNow wait; cancelling its context ends the wait with ctx.Err().
func TestRunNowOnABusyTaskHonoursContext(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	started, release := make(chan struct{}), make(chan struct{})
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error {
		close(started)
		<-release
		return nil
	}})
	first := make(chan error, 1)
	go func() { first <- s.RunNow(context.Background(), "notify.send") }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() { second <- s.RunNow(ctx, "notify.send") }()
	cancel()
	select {
	case err := <-second:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("RunNow did not return after its context was cancelled")
	}
	close(release)
	require.NoError(t, <-first)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A panic or an error on the scheduled path is contained: later ticks still run and the log
// holds neither the panic value nor the error text (they may carry data from the task).
func TestScheduledPanicsAndErrorsAreContainedAndNotLogged(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	var buf lockedBuffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var panicRuns, errRuns atomic.Int32
	s := NewScheduler(clk, &fakeGate{}, log,
		Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error {
			if panicRuns.Add(1) == 1 {
				panic("PANIC-VALUE-CANARY")
			}
			return nil
		}},
		Task{Type: LicenseEvaluate, Every: time.Minute, Run: func(context.Context) error {
			errRuns.Add(1)
			return errors.New("ERROR-TEXT-CANARY")
		}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	for range 500 {
		if panicRuns.Load() >= 2 && errRuns.Load() >= 2 {
			break
		}
		clk.Advance(time.Minute)
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	assert.GreaterOrEqual(t, panicRuns.Load(), int32(2), "a tick after the panic still runs")
	assert.GreaterOrEqual(t, errRuns.Load(), int32(2))
	out := buf.String()
	assert.Contains(t, out, "panicked")
	assert.NotContains(t, out, "PANIC-VALUE-CANARY")
	assert.NotContains(t, out, "ERROR-TEXT-CANARY")
}

// A tick that races with cancellation starts no run.
func TestCancelledContextStartsNoRun(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	var runs atomic.Int32
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { runs.Add(1); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	task := s.tasks["notify.send"]
	ticks := make(chan time.Time, 1)
	ticks <- clk.Now()
	s.loopWith(ctx, task, ticks)
	assert.Zero(t, runs.Load())
}
