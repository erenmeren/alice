package jobs

import (
	"context"
	"errors"
	"io"
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

// Stub job types for L-27, L-30 and L-80 until the real jobs exist (spec §26.4).
var (
	testDiscover = Register("test.discover", license.ClassReadOnly)
	testDeploy   = Register("test.deploy", license.ClassChange)
)

type fakeGate struct {
	mu     sync.Mutex
	locked bool
	refuse error // the refusal of gated work while locked; nil = license.ErrLocked
}

func (g *fakeGate) Allow(c license.Class) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !c.Valid():
		return license.ErrUnclassified
	case c != license.ClassAlways && g.locked && g.refuse != nil:
		return g.refuse
	case c != license.ClassAlways && g.locked:
		return license.ErrLocked
	}
	return nil
}

func (g *fakeGate) set(locked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.locked, g.refuse = locked, nil
}

// setUnverified makes the gate refuse gated work as license.ErrUnverified (AUD-02), or opens it.
func (g *fakeGate) setUnverified(on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.locked, g.refuse = on, nil
	if on {
		g.refuse = license.ErrUnverified
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// X-01: a job type without a license class cannot exist.
func TestEveryJobTypeHasALicenseClass(t *testing.T) {
	types := Types()
	require.NotEmpty(t, types)
	names := map[string]license.Class{}
	for _, jt := range types {
		assert.True(t, jt.Class.Valid(), jt.Name)
		names[jt.Name] = jt.Class
	}
	assert.Equal(t, license.ClassAlways, names["license.evaluate"], "the evaluation itself runs in lock (§8.6)")
	assert.Equal(t, license.ClassAlways, names["notify.send"], "expiry emails continue in lock")
	assert.Panics(t, func() { Register("test.unclassified", license.ClassUnset) })
	assert.Panics(t, func() { Register("test.bogus", license.Class(42)) })
	assert.Panics(t, func() { Register("license.evaluate", license.ClassAlways) }, "names are unique")
}

func TestNewSchedulerRefusesBadTasks(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	run := func(context.Context) error { return nil }
	for name, task := range map[string]Task{
		"unregistered":    {Type: Type{Name: "nope", Class: license.ClassAlways}, Every: time.Minute, Run: run},
		"class differs":   {Type: Type{Name: "license.evaluate", Class: license.ClassReadOnly}, Every: time.Minute, Run: run},
		"external change": {Type: testDeploy, Every: time.Minute, Run: run},
		"no interval":     {Type: LicenseEvaluate, Run: run},
		"no function":     {Type: LicenseEvaluate, Every: time.Minute},
	} {
		assert.Panics(t, func() { NewScheduler(clk, &fakeGate{}, quiet, task) }, name)
	}
	assert.Panics(t, func() {
		NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: run}, Task{Type: NotifySend, Every: time.Hour, Run: run})
	}, "duplicate task")
}

// Schedules lets the composition root check that every periodic job type is scheduled.
func TestSchedulesReportsTheScheduledTasks(t *testing.T) {
	run := func(context.Context) error { return nil }
	s := NewScheduler(nil, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: run})
	assert.True(t, s.Schedules(NotifySend))
	assert.False(t, s.Schedules(LicenseEvaluate))
	assert.False(t, s.Schedules(Type{Name: NotifySend.Name, Class: license.ClassChange}), "a type differing in class is not the scheduled one")
}

// advanceUntil moves the fake clock by every until ran reports a run (the loop goroutine
// may not have created its ticker yet on the first move).
func advanceUntil(t *testing.T, clk *clock.Fake, every time.Duration, ran <-chan struct{}) {
	t.Helper()
	for range 100 {
		clk.Advance(every)
		select {
		case <-ran:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("the task did not run")
}

func TestTasksRunOnTheirInterval(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	ran := make(chan struct{}, 10)
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error {
		ran <- struct{}{}
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	advanceUntil(t, clk, time.Hour, ran)
	advanceUntil(t, clk, time.Hour, ran)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// L-27, L-30 (stub jobs): read-only recurring work is paused while locked and resumes by
// itself after a renewal; the evaluation and email jobs run in lock.
func TestLockPausesReadOnlyWorkAndRenewalResumesIt(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{locked: true}
	var discovered, evaluated atomic.Int32
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testDiscover, Every: 15 * time.Minute, Run: func(context.Context) error { discovered.Add(1); return nil }},
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { evaluated.Add(1); return nil }},
	)
	ctx := context.Background()
	assert.ErrorIs(t, s.RunNow(ctx, "test.discover"), license.ErrLocked)
	assert.Zero(t, discovered.Load(), "no external call while locked")
	require.NoError(t, s.RunNow(ctx, "license.evaluate"))
	assert.Equal(t, int32(1), evaluated.Load())

	gate.set(false) // a renewal was uploaded
	require.NoError(t, s.RunNow(ctx, "test.discover"))
	assert.Equal(t, int32(1), discovered.Load())
}

// L-80 (stub): lock is checked before a run starts, never in the middle; running work
// completes on its own.
func TestRunningTaskCompletesWhenLockStarts(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{}
	started, release := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	s := NewScheduler(clk, gate, quiet, Task{Type: testDiscover, Every: time.Hour, Run: func(context.Context) error {
		close(started)
		<-release
		finished.Store(true)
		return nil
	}})
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(context.Background(), "test.discover") }()
	<-started
	gate.set(true)
	close(release)
	require.NoError(t, <-errc)
	assert.True(t, finished.Load())
	assert.ErrorIs(t, s.RunNow(context.Background(), "test.discover"), license.ErrLocked, "the next run is paused")
}

// A task never runs twice at once: a tick that finds it running is skipped.
func TestATaskNeverOverlapsItself(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	var running, maxRunning, runs atomic.Int32
	release := make(chan struct{})
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error {
		n := running.Add(1)
		for {
			m := maxRunning.Load()
			if n <= m || maxRunning.CompareAndSwap(m, n) {
				break
			}
		}
		runs.Add(1)
		<-release
		running.Add(-1)
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(ctx, "notify.send") }()
	require.Eventually(t, func() bool { return running.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	for range 20 {
		clk.Advance(time.Minute)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	require.NoError(t, <-errc)
	assert.Equal(t, int32(1), maxRunning.Load())
}

func TestFailuresAndPanicsAreContained(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	boom := errors.New("boom")
	s := NewScheduler(clk, &fakeGate{}, quiet,
		Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { return boom }},
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { panic("bad") }},
	)
	assert.ErrorIs(t, s.RunNow(context.Background(), "notify.send"), boom)
	assert.Error(t, s.RunNow(context.Background(), "license.evaluate"))
	assert.Error(t, s.RunNow(context.Background(), "no.such.task"))
}

// AUD-02: license.evaluate runs in every process, also in one that is not the scheduling leader;
// every other task still runs only in the leader. A closed Leader never touches the database and
// is never the leader.
func TestTheEvaluationRunsWithoutTheLeaderLock(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	leader := NewLeader(nil, quiet)
	leader.Close()
	ran, other := make(chan struct{}, 10), make(chan struct{}, 10)
	s := NewScheduler(clk, &fakeGate{}, quiet,
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { ran <- struct{}{}; return nil }},
		Task{Type: NotifySend, Every: time.Hour, Run: func(context.Context) error { other <- struct{}{}; return nil }},
	).WithLeader(leader)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	advanceUntil(t, clk, time.Hour, ran)
	advanceUntil(t, clk, time.Hour, ran)
	cancel()
	<-done
	assert.Empty(t, other, "the other tasks run only in the leader")
}

// AUD-02, S1: while the license cannot be verified, read-only periodic work is paused and resumes
// by itself after the next successful evaluation; the evaluation itself keeps running.
func TestUnverifiedPausesReadOnlyTasksUntilAnEvaluationSucceeds(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{}
	gate.setUnverified(true)
	var discovered atomic.Int32
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testDiscover, Every: time.Minute, Run: func(context.Context) error { discovered.Add(1); return nil }},
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { gate.setUnverified(false); return nil }},
	)
	ctx := context.Background()
	err := s.RunNow(ctx, "test.discover")
	assert.ErrorIs(t, err, license.ErrUnverified)
	assert.Zero(t, discovered.Load())
	require.NoError(t, s.RunNow(ctx, "license.evaluate"), "the evaluation is never paused")
	require.NoError(t, s.RunNow(ctx, "test.discover"))
	assert.Equal(t, int32(1), discovered.Load())
}

// AUD-02 (I2): a failed run of a task with Retry is run again after 1, then 2 minutes (doubling up
// to its interval), not an hour later; after a success it waits for its interval again.
func TestFailedRunsAreRetriedWithBackoff(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	clk := clock.NewFake(start)
	var mu sync.Mutex
	var at []time.Duration
	ran := make(chan struct{}, 10)
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: LicenseEvaluate, Every: time.Hour, Retry: time.Minute,
		Run: func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			at = append(at, clk.Now().Sub(start))
			ran <- struct{}{}
			if len(at) <= 2 {
				return errors.New("the database is down")
			}
			return nil
		}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	runs := func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), at...)
	}
	advanceUntil(t, clk, time.Hour, ran) // the hourly run fails
	for i := 0; i < 600 && len(runs()) < 3; i++ {
		clk.Advance(5 * time.Second)
		time.Sleep(2 * time.Millisecond)
	}
	got := runs()
	require.Len(t, got, 3, "two retries within minutes")
	assert.InDelta(t, time.Minute, got[1]-got[0], float64(30*time.Second), "first retry after a minute")
	assert.InDelta(t, 2*time.Minute, got[2]-got[1], float64(30*time.Second), "second retry after two minutes")
	for range 100 { // 50 minutes: the success ended the retries
		clk.Advance(30 * time.Second)
		time.Sleep(time.Millisecond)
	}
	assert.Len(t, runs(), 3)
}
