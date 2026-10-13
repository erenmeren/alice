package acmejobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
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

type stubDeployPlanner struct {
	calls atomic.Int32
	run   inventory.ACMEDeployRun
	err   error
}

func (p *stubDeployPlanner) PlanACMEAutoDeploy(context.Context) (inventory.ACMEDeployRun, error) {
	p.calls.Add(1)
	return p.run, p.err
}

func TestAutoDeployTask(t *testing.T) {
	assert.Panics(t, func() { AutoDeployTask(nil, time.Minute, nil) })
	p := &stubDeployPlanner{}
	task := AutoDeployTask(p, time.Minute, nil)
	assert.Equal(t, jobs.ACMEAutoDeploy, task.Type)
	assert.Equal(t, time.Minute, task.Every)
	assert.Equal(t, license.ClassReadOnly, task.Type.Class, "the scheduler pauses it in lock")
	require.NoError(t, task.Run(context.Background()))

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	p.run = inventory.ACMEDeployRun{Created: 4, Held: 1, Stopped: 1}
	require.NoError(t, AutoDeployTask(p, time.Minute, log).Run(context.Background()))
	assert.Contains(t, logs.String(), "planned automatic deployments of ACME certificates")
	assert.Contains(t, logs.String(), "created=4")

	logs.Reset()
	p.err = errors.Join(fmt.Errorf("secret value 'x'"), fmt.Errorf("again"))
	err := AutoDeployTask(p, time.Minute, log).Run(context.Background())
	assert.ErrorIs(t, err, errDeployPlanFailed)
	assert.Contains(t, logs.String(), "error_type=*errors.errorString")
	assert.NotContains(t, logs.String(), "secret value", "error texts are never logged")

	p.err = fmt.Errorf("wrapped: %w", inventory.ErrClaimLost)
	assert.ErrorIs(t, AutoDeployTask(p, time.Minute, log).Run(context.Background()), inventory.ErrClaimLost)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.err = context.Canceled
	assert.ErrorIs(t, AutoDeployTask(p, time.Minute, log).Run(ctx), context.Canceled)
}

// The scheduler pauses acme.auto_deploy in lock (ReadOnly class): the planner is not even called.
func TestAutoDeployTaskIsPausedInLock(t *testing.T) {
	p := &stubDeployPlanner{}
	gate := &lockSwitch{locked: true}
	s := jobs.NewScheduler(clock.NewFake(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)), gate, slog.New(slog.DiscardHandler),
		AutoDeployTask(p, time.Minute, nil))
	assert.ErrorIs(t, s.RunNow(context.Background(), "acme.auto_deploy"), license.ErrLocked)
	assert.Zero(t, p.calls.Load())
	gate.mu.Lock()
	gate.locked = false
	gate.mu.Unlock()
	require.NoError(t, s.RunNow(context.Background(), "acme.auto_deploy"))
	assert.Equal(t, int32(1), p.calls.Load())
}

// acme.auto_deploy runs only in the scheduling leader.
func TestAutoDeployTaskRunsOnlyInTheLeader(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))
	notLeader := jobs.NewLeader(nil, slog.New(slog.DiscardHandler))
	notLeader.Close()
	p := &stubDeployPlanner{}
	evaluated := make(chan struct{}, 10)
	s := jobs.NewScheduler(clk, &lockSwitch{}, slog.New(slog.DiscardHandler),
		jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Minute, Run: func(context.Context) error { evaluated <- struct{}{}; return nil }},
		AutoDeployTask(p, time.Minute, nil),
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
}
