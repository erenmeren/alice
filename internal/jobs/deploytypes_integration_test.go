//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// R38 #8 / L-82: in lock, a queued deployment is held for an Administrator's confirmation and a
// recovery still runs; recovery requests for one deployment do not pile up.
func TestDeploymentJobsInLock(t *testing.T) {
	e := newQEnv(t)
	target1, target2 := insertTarget(t, e.d), insertTarget(t, e.d)
	dep := uuid.New()
	enqueue := func(typ string, target uuid.UUID, dedupe string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		require.NoError(t, db.InTx(e.ctx, e.d.App, func(tx pgx.Tx) error {
			var err error
			id, err = e.q.EnqueueTx(e.ctx, tx, inventory.JobRequest{Type: typ, TargetID: target, Kind: "system",
				Payload: map[string]string{"deployment_id": dep.String()}, DedupeKey: dedupe})
			return err
		}))
		return id
	}
	deploy := enqueue(inventory.JobCertificateDeploy, target1, "certificate.deploy:"+dep.String())
	recover1 := enqueue(inventory.JobDeployRecover, target2, "certificate.deploy_recover:"+dep.String())
	assert.Equal(t, recover1, enqueue(inventory.JobDeployRecover, target2, "certificate.deploy_recover:"+dep.String()), "no pile-up")
	assert.Equal(t, 3, e.count(t, "SELECT max_attempts FROM jobs WHERE id = $1", deploy))
	assert.Equal(t, 1, e.count(t, "SELECT max_attempts FROM jobs WHERE id = $1", recover1))

	e.gate.set(true)
	var ran []string
	r := e.runner(t, "w1")
	r.Handle(CertificateDeploy, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		ran = append(ran, j.Type.Name)
		return nil, nil
	})
	r.Handle(CertificateDeployRecover, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
		ran = append(ran, j.Type.Name)
		return nil, nil
	})
	for {
		ok, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		if !ok {
			break
		}
	}
	assert.Equal(t, []string{inventory.JobDeployRecover}, ran)
	assert.Equal(t, "blocked_license", e.row(t, deploy).status)
	assert.Equal(t, "succeeded", e.row(t, recover1).status)
}

// Important 5: a recovery that cannot reach the server ends its job as a plain failure, never
// dead: no job.dead email per 15-minute cycle (the deployment sweep queues the next one and sends
// the deployment's single needs-attention email). Other job types keep the dead-job alert.
func TestRecoveryJobsNeverDieWithAnAlert(t *testing.T) {
	e := newQEnv(t)
	sent := 0
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Notifier = countingNotifier{&sent} })
	unreachable := func(context.Context, Job, StepRecorder) (map[string]any, error) {
		return nil, FromProvider(providers.NewError("ssh.unreachable", true, nil, nil))
	}
	r.Handle(CertificateDeployRecover, unreachable)
	r.Handle(CertificateDeploy, unreachable)
	recoverJob := e.enqueue(t, Spec{Type: CertificateDeployRecover, TargetID: insertTarget(t, e.d)})
	deployJob := e.enqueue(t, Spec{Type: CertificateDeploy, TargetID: insertTarget(t, e.d), MaxAttempts: 1})
	for range 2 {
		ok, err := r.RunOnce(e.ctx)
		require.NoError(t, err)
		require.True(t, ok)
	}
	got := e.row(t, recoverJob)
	assert.Equal(t, "failed", got.status)
	assert.Equal(t, "ssh.unreachable", got.lastError)
	assert.Equal(t, "dead", e.row(t, deployJob).status, "other types keep the alert")
	assert.Equal(t, 1, sent, "only the deploy job's job.dead email")
	assert.Equal(t, 1, e.audits(t, "job.dead"))
}

type countingNotifier struct{ n *int }

func (c countingNotifier) NotifyAdmins(context.Context, pgx.Tx, string, map[string]string) error {
	*c.n++
	return nil
}
