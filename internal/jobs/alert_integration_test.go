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
	return e.emails(t, TemplateJobDead, "job_id")
}

// emails returns the params of the queued emails of template, by the param by.
func (e *qenv) emails(t *testing.T, template, by string) map[string]map[string]string {
	t.Helper()
	rows, err := e.d.Owner.Query(e.ctx, `SELECT params FROM notifications_outbox WHERE template_key = $1`, template)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var p map[string]string
		require.NoError(t, json.Unmarshal(raw, &p))
		out[p[by]] = p
	}
	require.NoError(t, rows.Err())
	return out
}

// §8.4: a job that is out of attempts raises an alert. Until the Phase 7 alert engine that is
// one email to the Administrators per dead job, queued in the transaction that kills the job.
func TestDeadJobsAlertTheAdministratorsOncePerJob(t *testing.T) {
	e := newQEnv(t)
	e.adminWithEmail(t)
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Notifier = notify.AdminNotifier{Clock: e.clk} })
	r.Handle(testQueueJob, func(context.Context, Job, StepRecorder) (map[string]any, error) {
		return nil, Retry("ssh.timeout", nil, nil)
	})

	// Exhausted retries.
	retried := e.enqueue(t, Spec{Type: testQueueJob, MaxAttempts: 2})
	_, err := r.RunOnce(e.ctx)
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

// adminWithEmail gives the test Administrator an address, so admin emails are queued.
func (e *qenv) adminWithEmail(t *testing.T) {
	t.Helper()
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE users SET email = 'admin@example.com' WHERE id = $1`, admin.ID)
	require.NoError(t, err)
}

// J-1: a job whose stored data fails its integrity check is never run, and the Administrators
// are told once, in the transaction that stops the job.
func TestTamperedJobsAlertTheAdministratorsOnce(t *testing.T) {
	e := newQEnv(t)
	e.adminWithEmail(t)
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Notifier = notify.AdminNotifier{Clock: e.clk} })
	r.Handle(testQueueJob, succeed)
	id := e.enqueue(t, Spec{Type: testQueueJob})
	_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET payload_mac = $2 WHERE id = $1`, id, make([]byte, 32))
	require.NoError(t, err)

	ran, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	require.Equal(t, "dead", e.row(t, id).status)
	got := e.emails(t, TemplateJobTampered, "job_id")
	require.Len(t, got, 1)
	assert.Equal(t, map[string]string{"job_id": id.String(), "type": testQueueJob.Name}, got[id.String()])
	assert.Empty(t, e.deadEmails(t), "a tampered job is announced as tampered, not as exhausted")

	e.fake.Advance(time.Hour)
	_, err = r.Reap(e.ctx)
	require.NoError(t, err)
	ran, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	assert.False(t, ran)
	assert.Len(t, e.emails(t, TemplateJobTampered, "job_id"), 1, "a second pass adds none")
}

// I-2: a job type whose exhaustion does not alert (a deployment recovery: its deployment's own
// escalation is the alert) is not mailed when it dies on the reaper's path (a crashed worker) or on
// the release path (a lost lease on its last attempt) either; the dead status and the job.dead
// audit row stay. Other types keep the email on both paths.
func TestDeadJobsOfQuietTypesAreAuditedNotMailed(t *testing.T) {
	for _, tc := range []struct {
		typ    Type
		mailed bool
	}{{CertificateDeployRecover, false}, {testQueueJob, true}} {
		t.Run(tc.typ.Name, func(t *testing.T) {
			e := newQEnv(t)
			e.adminWithEmail(t)
			r := e.runner(t, "w1", func(c *RunnerConfig) { c.Notifier = notify.AdminNotifier{Clock: e.clk} })
			r.Handle(tc.typ, succeed)

			// The reaper: the worker died on the job's last attempt.
			reaped := e.enqueue(t, Spec{Type: tc.typ, TargetID: insertTarget(t, e.d), MaxAttempts: 1})
			_, err := e.d.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'running', locked_by = 'gone/1', attempts = 1, locked_until = $2 WHERE id = $1`,
				reaped, e.clk.Now().Add(-time.Second))
			require.NoError(t, err)
			_, err = r.Reap(e.ctx)
			require.NoError(t, err)
			require.Equal(t, "dead", e.row(t, reaped).status)

			// The release: this worker gives a job back on its last attempt (lease lost to failing
			// heartbeats while the row is still its own).
			released := e.enqueue(t, Spec{Type: tc.typ, TargetID: insertTarget(t, e.d), MaxAttempts: 1})
			c, err := r.claim(e.ctx)
			require.NoError(t, err)
			require.NotNil(t, c)
			require.Equal(t, released, c.id)
			r.release(e.ctx, c, false)
			require.Equal(t, "dead", e.row(t, released).status)

			assert.Equal(t, 2, e.audits(t, "job.dead"), "both deaths are audited")
			if tc.mailed {
				assert.Len(t, e.deadEmails(t), 2)
			} else {
				assert.Empty(t, e.deadEmails(t), "the deployment's escalation is the alert")
			}
		})
	}
}
