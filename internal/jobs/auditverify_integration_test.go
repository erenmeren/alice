//go:build integration

package jobs

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/notify"
	"alice/internal/platform/db"
)

// tamperAudit changes an audit row as the table owner with the append-only triggers disabled.
func (e *qenv) tamperAudit(t *testing.T, sql string) {
	t.Helper()
	require.NoError(t, db.InTx(e.ctx, e.d.Owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(e.ctx, "ALTER TABLE audit_log DISABLE TRIGGER USER"); err != nil {
			return err
		}
		if _, err := tx.Exec(e.ctx, sql); err != nil {
			return err
		}
		_, err := tx.Exec(e.ctx, "ALTER TABLE audit_log ENABLE TRIGGER USER")
		return err
	}))
}

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func (e *qenv) auditVerifyTask() Task {
	return AuditVerifyTask(AuditVerifyConfig{Pool: e.d.App, Verifier: audit.NewService(e.audit, e.d.App),
		Notifier: notify.AdminNotifier{Clock: e.clk}, Clock: e.clk})
}

func TestAuditVerifyTaskTicksHourlyAndVerifiesOncePerDay(t *testing.T) {
	e := newQEnv(t)
	task := e.auditVerifyTask()
	assert.Equal(t, AuditVerify, task.Type)
	assert.Equal(t, time.Hour, task.Every, "hourly ticks: a restart or a new leader never skips a day")

	require.NoError(t, task.Run(e.ctx))
	assert.Equal(t, 1, e.audits(t, "audit.verified"))
	for range 22 {
		e.fake.Advance(time.Hour)
		require.NoError(t, task.Run(e.ctx))
	}
	assert.Equal(t, 1, e.audits(t, "audit.verified"), "ticks within 23 hours of the last verification do nothing")

	// The process restarts (or another process becomes the leader) 22 hours after the last
	// verification: its fresh scheduler still verifies within the day.
	restarted := e.auditVerifyTask()
	e.fake.Advance(30 * time.Minute)
	require.NoError(t, restarted.Run(e.ctx))
	assert.Equal(t, 1, e.audits(t, "audit.verified"))
	e.fake.Advance(30 * time.Minute) // 23 hours
	require.NoError(t, restarted.Run(e.ctx))
	assert.Equal(t, 2, e.audits(t, "audit.verified"))
	e.fake.Advance(time.Hour)
	require.NoError(t, restarted.Run(e.ctx))
	assert.Equal(t, 2, e.audits(t, "audit.verified"))
}

// A broken audit chain is an error of the task (logged at Error by the scheduler) and one email
// to the Administrators per break; the next check of the same break sends no second email.
func TestAuditVerifyTaskAlertsOncePerBreak(t *testing.T) {
	e := newQEnv(t)
	e.adminWithEmail(t)
	task := e.auditVerifyTask()
	require.NoError(t, task.Run(e.ctx)) // seq 1: audit.verified
	e.fake.Advance(23 * time.Hour)
	require.NoError(t, task.Run(e.ctx)) // seq 2
	assert.Empty(t, e.emails(t, TemplateAuditBroken, "first_bad_seq"))

	e.tamperAudit(t, `UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 2`)
	e.fake.Advance(23 * time.Hour)
	err := task.Run(e.ctx)
	require.ErrorIs(t, err, ErrAuditChainBroken)
	got := e.emails(t, TemplateAuditBroken, "first_bad_seq")
	require.Len(t, got, 1)
	assert.Equal(t, map[string]string{"first_bad_seq": "2", "problem": audit.ProblemHashMismatch}, got["2"])

	e.fake.Advance(time.Hour) // a broken chain is checked again on the next tick
	require.ErrorIs(t, task.Run(e.ctx), ErrAuditChainBroken)
	require.ErrorIs(t, e.auditVerifyTask().Run(e.ctx), ErrAuditChainBroken, "also after a restart")
	assert.Len(t, e.emails(t, TemplateAuditBroken, "first_bad_seq"), 1, "the same break is announced once")

	// A break further back is a new break.
	e.tamperAudit(t, `UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 1`)
	e.fake.Advance(time.Hour)
	require.ErrorIs(t, task.Run(e.ctx), ErrAuditChainBroken)
	assert.Len(t, e.emails(t, TemplateAuditBroken, "first_bad_seq"), 2)
}

// The scheduler logs the broken chain at Error level.
func TestScheduledAuditVerifyLogsABrokenChainAsAnError(t *testing.T) {
	e := newQEnv(t)
	task := e.auditVerifyTask()
	require.NoError(t, task.Run(e.ctx))
	e.tamperAudit(t, `UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 1`)
	e.fake.Advance(23 * time.Hour)
	logs := &syncBuffer{}
	s := NewScheduler(e.clk, &fakeGate{}, slogTo(logs), task)
	assert.ErrorIs(t, s.RunNow(context.Background(), AuditVerify.Name), ErrAuditChainBroken)
	assert.Contains(t, logs.String(), "level=ERROR")
	assert.Contains(t, logs.String(), "scheduled task failed")
}
