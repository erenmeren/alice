//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
)

// deadEmails returns the params of the queued job.dead emails, by job id.
func (e *qenv) deadEmails(t *testing.T) map[string]map[string]string {
	t.Helper()
	rows, err := e.d.Owner.Query(e.ctx, `SELECT params FROM notifications_outbox WHERE template_key = $1`, TemplateJobDead)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var p map[string]string
		require.NoError(t, json.Unmarshal(raw, &p))
		out[p["job_id"]] = p
	}
	require.NoError(t, rows.Err())
	return out
}

// §8.4: a job that is out of attempts raises an alert. Until the Phase 7 alert engine that is
// one email to the Administrators per dead job, queued in the transaction that kills the job.
func TestDeadJobsAlertTheAdministratorsOncePerJob(t *testing.T) {
	e := newQEnv(t)
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE users SET email = 'admin@example.com' WHERE id = $1`, admin.ID)
	require.NoError(t, err)
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Notifier = notify.AdminNotifier{Clock: e.clk} })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		return nil, Retry("ssh.timeout", nil, nil)
	})

	// Exhausted retries.
	retried := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 2})
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.Empty(t, e.deadEmails(t), "a job with attempts left raises nothing")
	e.fake.Advance(30 * time.Second)
	_, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.Equal(t, "dead", e.row(t, retried).status)

	// A dead worker's lease expiring on the last attempt.
	reaped := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 1})
	_, err = e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'gone/1', attempts = 1, locked_until = $2 WHERE id = $1`,
		reaped, e.clk.Now().Add(-time.Second))
	require.NoError(t, err)
	n, err := r.Reap(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, "dead", e.row(t, reaped).status)

	got := e.deadEmails(t)
	require.Len(t, got, 2)
	assert.Equal(t, map[string]string{"job_id": retried.String(), "type": testQueueJob.Name, "reason": "ssh.timeout", "attempts": "2"},
		got[retried.String()])
	assert.Equal(t, map[string]string{"job_id": reaped.String(), "type": testQueueJob.Name, "reason": "job.lease_expired", "attempts": "1"},
		got[reaped.String()])
	assert.Equal(t, 2, e.audits(t, "job.dead"))

	// Nothing more happens to dead jobs: no second email.
	e.fake.Advance(time.Hour)
	_, err = r.Reap(e.ctx)
	require.NoError(t, err)
	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran)
	assert.Len(t, e.deadEmails(t), 2)
}
