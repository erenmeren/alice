package acmejobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
)

type stubPlanner struct {
	calls atomic.Int32
	run   inventory.ACMERenewRun
	err   error
}

func (p *stubPlanner) PlanACMERenewals(context.Context) (inventory.ACMERenewRun, error) {
	p.calls.Add(1)
	return p.run, p.err
}

func TestScheduleTask(t *testing.T) {
	assert.Panics(t, func() { ScheduleTask(nil, time.Minute, nil) })
	p := &stubPlanner{}
	task := ScheduleTask(p, time.Minute, nil)
	assert.Equal(t, jobs.ACMESchedule, task.Type)
	assert.Equal(t, time.Minute, task.Every)
	assert.Equal(t, license.ClassContinuity, task.Type.Class, "the scheduler pauses it in lock once the continuity window has ended")
	require.NoError(t, task.Run(context.Background()))

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	p.run = inventory.ACMERenewRun{Started: 2, Stopped: 1, ARIChecked: 3}
	require.NoError(t, ScheduleTask(p, time.Minute, log).Run(context.Background()))
	assert.Contains(t, logs.String(), "planned ACME renewals")
	assert.Contains(t, logs.String(), "started=2")

	logs.Reset()
	p.err = errors.Join(fmt.Errorf("secret value 'x'"), &inventory.ACMEError{Reason: "acme.ca_rate_limited"}, fmt.Errorf("again"))
	err := ScheduleTask(p, time.Minute, log).Run(context.Background())
	assert.ErrorIs(t, err, errPlanFailed)
	assert.Contains(t, logs.String(), "error_type=*errors.errorString,*inventory.ACMEError")
	assert.NotContains(t, logs.String(), "secret value", "error texts are never logged")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.err = context.Canceled
	assert.ErrorIs(t, ScheduleTask(p, time.Minute, log).Run(ctx), context.Canceled)
}

func TestTypesOfIsBounded(t *testing.T) {
	type e1 struct{ error }
	type e2 struct{ error }
	type e3 struct{ error }
	type e4 struct{ error }
	type e5 struct{ error }
	type e6 struct{ error }
	err := errors.Join(e1{}, e2{}, e3{}, e4{}, e5{}, e6{}, e1{})
	assert.Equal(t, "acmejobs.e1,acmejobs.e2,acmejobs.e3,acmejobs.e4,acmejobs.e5", typesOf(err))
}

// lockSwitch is a licence gate with a switch.
type lockSwitch struct {
	mu     sync.Mutex
	locked bool
}

func (g *lockSwitch) Allow(c license.Class) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.locked && c != license.ClassAlways {
		return license.ErrLocked
	}
	return nil
}

// The scheduler pauses acme.schedule in lock after the continuity window (ClassContinuity): the planner is not even called.
func TestScheduleTaskIsPausedInLock(t *testing.T) {
	p := &stubPlanner{}
	gate := &lockSwitch{locked: true}
	s := jobs.NewScheduler(clock.NewFake(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)), gate, slog.New(slog.DiscardHandler),
		ScheduleTask(p, time.Minute, nil))
	assert.ErrorIs(t, s.RunNow(context.Background(), "acme.schedule"), license.ErrLocked)
	assert.Zero(t, p.calls.Load())
	gate.mu.Lock()
	gate.locked = false
	gate.mu.Unlock()
	require.NoError(t, s.RunNow(context.Background(), "acme.schedule"))
	assert.Equal(t, int32(1), p.calls.Load())
}

// acme.schedule runs only in the scheduling leader: a process that is not the leader never plans (license.evaluate,
// which runs everywhere, shows that its scheduler did tick).
func TestScheduleTaskRunsOnlyInTheLeader(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))
	notLeader := jobs.NewLeader(nil, slog.New(slog.DiscardHandler))
	notLeader.Close() // a closed Leader is never the leader
	p := &stubPlanner{}
	evaluated := make(chan struct{}, 10)
	s := jobs.NewScheduler(clk, &lockSwitch{}, slog.New(slog.DiscardHandler),
		jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Minute, Run: func(context.Context) error { evaluated <- struct{}{}; return nil }},
		ScheduleTask(p, time.Minute, nil),
	).WithLeader(notLeader)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	for range 3 {
		deadline := time.After(10 * time.Second)
	wait:
		for {
			clk.Advance(time.Minute)
			select {
			case <-evaluated:
				break wait
			case <-deadline:
				t.Fatal("the scheduler did not tick")
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	cancel()
	<-done
	assert.Zero(t, p.calls.Load(), "not the leader: never planned")

	// The same scheduler in the leader (no leader lock configured: a single process) plans on its interval.
	leader := jobs.NewScheduler(clk, &lockSwitch{}, slog.New(slog.DiscardHandler), ScheduleTask(p, time.Minute, nil))
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		leader.Run(ctx)
		close(done)
	}()
	deadline := time.After(10 * time.Second)
	for p.calls.Load() == 0 {
		clk.Advance(time.Minute)
		select {
		case <-deadline:
			t.Fatal("the leader did not plan")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
