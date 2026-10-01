//go:build integration

package jobs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

var testLeaderTask = Register("test.leader", license.ClassAlways)

func TestLeaderLockIsExclusiveAndSurvivesALostConnection(t *testing.T) {
	e := newQEnv(t)
	l1, l2 := NewLeader(e.d.App, quiet), NewLeader(e.d.App, quiet)
	t.Cleanup(l1.Close)
	t.Cleanup(l2.Close)
	require.True(t, l1.IsLeader(e.ctx))
	assert.False(t, l2.IsLeader(e.ctx))
	assert.True(t, l1.IsLeader(e.ctx), "leadership is kept across checks")

	// The leader's database session dies (network cut, PostgreSQL restart): the lock is gone.
	l1.mu.Lock()
	pid := l1.conn.Conn().PgConn().PID()
	l1.mu.Unlock()
	_, err := e.d.Owner.Exec(e.ctx, `SELECT pg_terminate_backend($1)`, pid)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return l2.IsLeader(e.ctx) }, 5*time.Second, 20*time.Millisecond)
	assert.False(t, l1.IsLeader(e.ctx), "the old leader notices it lost the lock")

	l2.Close()
	assert.False(t, l2.IsLeader(e.ctx), "a closed leader never leads again")
	assert.True(t, l1.IsLeader(e.ctx), "closing releases the lock at once")
}

// A leader whose context ends while it asks for the lock does not keep a pooled connection
// that might hold it.
func TestLeaderWithCancelledContextLeadsNot(t *testing.T) {
	e := newQEnv(t)
	l := NewLeader(e.d.App, quiet)
	t.Cleanup(l.Close)
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	assert.False(t, l.IsLeader(ctx))
	other := NewLeader(e.d.App, quiet)
	t.Cleanup(other.Close)
	assert.True(t, other.IsLeader(e.ctx), "the lock is free")
}

// P2-06: two processes during an update both run the periodic scheduler; only the one holding
// the advisory lock runs the tasks.
func TestOnlyOneSchedulerLeads(t *testing.T) {
	e := newQEnv(t)
	clk := clock.NewFake(queueStart)
	l1, l2 := NewLeader(e.d.App, quiet), NewLeader(e.d.App, quiet)
	t.Cleanup(l1.Close)
	t.Cleanup(l2.Close)
	var runs1, runs2 atomic.Int32
	s1 := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: testLeaderTask, Every: time.Minute,
		Run: func(context.Context) error { runs1.Add(1); return nil }}).WithLeader(l1)
	s2 := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: testLeaderTask, Every: time.Minute,
		Run: func(context.Context) error { runs2.Add(1); return nil }}).WithLeader(l2)
	require.True(t, l1.IsLeader(e.ctx), "process 1 started first")
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	go s1.Run(ctx)
	go s2.Run(ctx)
	require.Eventually(t, func() bool { clk.Advance(time.Minute); return runs1.Load() >= 3 }, 10*time.Second, 5*time.Millisecond)
	assert.Zero(t, runs2.Load(), "the second process never runs scheduled work while the first leads")

	l1.Close() // process 1 stops
	require.Eventually(t, func() bool { clk.Advance(time.Minute); return runs2.Load() >= 1 }, 10*time.Second, 5*time.Millisecond)
	assert.NoError(t, s2.RunNow(e.ctx, testLeaderTask.Name), "RunNow is an explicit request and runs regardless")
}
