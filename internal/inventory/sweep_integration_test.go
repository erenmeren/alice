//go:build integration

package inventory_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

func TestSweepDeployments(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	// Every deployment is requested before any recovers (a recovery refuses new ones on its server).
	a := f.request(f.admin, f.cert.ID, f.loc1)
	b := f.request(f.admin, f.cert.ID, f.loc2)
	c := f.request(f.admin, f.cert.ID, f.loc5)
	dd := f.request(f.admin, f.cert.ID, f.loc3onTarget2)
	e := f.request(f.admin, f.cert.ID, f.loc4)
	f.start(a)
	f.start(b)
	f.start(c)
	require.NoError(t, f.h.svc.MarkRecovering(ctx, b, f.h.clock.Now().Add(time.Hour), false))
	f.jobStatus(f.jobOf(a), "dead", "ssh.unreachable")
	f.jobStatus(f.jobOf(c), "running", "")
	f.jobStatus(f.jobOf(dd), "dead", "ssh.unreachable")
	f.jobStatus(f.jobOf(e), "blocked_license", "")
	emailsBefore := len(f.emails())

	n, err := f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	da := f.get(a)
	assert.Equal(t, inventory.DeployStateRecovering, da.State)
	assert.Equal(t, inventory.DeployStatusRunning, da.Status)
	require.NotNil(t, da.RecoverAfter)
	assert.Equal(t, f.h.clock.Now().Add(15*time.Minute), *da.RecoverAfter)
	assert.Equal(t, 1, da.RecoveryAttempts)
	assert.Equal(t, []string{"queued"}, f.recoverJobs(a))
	dD := f.get(dd)
	assert.Equal(t, inventory.DeployStateDone, dD.State)
	assert.Equal(t, inventory.DeployStatusFailed, dD.Status)
	assert.Equal(t, "ssh.unreachable", dD.ErrorCode)
	for _, id := range []uuid.UUID{b, c} {
		assert.NotEqual(t, inventory.DeployStateDone, f.get(id).State)
		assert.Empty(t, f.recoverJobs(id))
	}
	assert.Equal(t, inventory.DeployStateQueued, f.get(e).State, "held for an Administrator's confirmation, not failed")
	assert.Equal(t, 1, f.h.audits("deployment.recovery_started"))
	emails := f.emails()[emailsBefore:]
	require.Len(t, emails, 1)
	assert.Equal(t, "deployment.failed", emails[0].Template)

	n, err = f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "idempotent: A's recovery is queued and its recover_after is ahead")
	f.h.clock.Advance(16 * time.Minute)
	n, err = f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a live recovery is never doubled")
	assert.Equal(t, []string{"queued"}, f.recoverJobs(a))
}

// Every way a deployment can be left behind ends in recovery or a terminal state.
func TestSweepFailurePoints(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	sweep := func() int {
		t.Helper()
		n, err := f.h.svc.SweepDeployments(ctx)
		require.NoError(t, err)
		return n
	}
	// 1. The handler crashed in precheck (nothing sent) and its job is dead: failed, nothing changed.
	pre := f.request(f.admin, f.cert.ID, f.loc1)
	_, err := f.h.svc.BeginDeployment(ctx, pre)
	require.NoError(t, err)
	f.jobStatus(f.jobOf(pre), "dead", "job.lease_expired")
	// 2. The job row was pruned (job_id → NULL) while the deployment was queued.
	pruned := f.request(f.admin, f.cert.ID, f.loc2)
	_, err = f.h.db.Owner.Exec(ctx, "DELETE FROM jobs WHERE id = $1", f.jobOf(pruned))
	require.NoError(t, err)
	assert.Nil(t, f.get(pruned).JobID)
	// 3. The job ended without finishing the deployment (a handler bug): failed.
	lost := f.request(f.admin, f.cert.ID, f.loc5)
	f.jobStatus(f.jobOf(lost), "succeeded", "")
	// 4. A job's error code that does not fit the column is not copied.
	odd := f.request(f.admin, f.cert.ID, f.loc3onTarget2)
	f.jobStatus(f.jobOf(odd), "failed", "weird code with spaces/and \"quotes\"")
	// 5. The license held the job and an Administrator discarded it.
	locked := f.request(f.admin, f.cert.ID, f.loc4)
	f.jobStatus(f.jobOf(locked), "cancelled", "license.locked")
	emailsBefore := len(f.emails())
	assert.Equal(t, 5, sweep())
	for id, code := range map[uuid.UUID]string{pre: "job.lease_expired", pruned: "deployment.interrupted", lost: "deployment.interrupted",
		odd: "deployment.interrupted", locked: "license.locked"} {
		d := f.get(id)
		assert.Equal(t, inventory.DeployStatusFailed, d.Status, code)
		assert.Equal(t, code, d.ErrorCode)
	}
	assert.Len(t, f.emails(), emailsBefore+4, "a deployment the license stopped sends no failure email")

	// 6. A send happened (deploying) and the deploy job's row was pruned: recovery.
	sent := f.deploying(f.loc1)
	_, err = f.h.db.Owner.Exec(ctx, "DELETE FROM jobs WHERE id = $1", f.jobOf(sent))
	require.NoError(t, err)
	// 7. A send happened and the deploy job waits for a retry (restart, lease expired) or is held by
	// the license: recovery runs anyway (R38 #8); only a running deploy job defers it.
	queuedAgain := f.deploying(f.loc2)
	held := f.deploying(f.loc5)
	f.jobStatus(f.jobOf(held), "blocked_license", "")
	assert.Equal(t, 3, sweep())
	for _, id := range []uuid.UUID{sent, queuedAgain, held} {
		assert.Equal(t, []string{"queued"}, f.recoverJobs(id))
		assert.Equal(t, inventory.DeployStateRecovering, f.get(id).State)
	}
}

// A recovery that keeps failing is retried every 15 minutes; after an hour one email says that
// the deployment needs attention; after a day Alice stops and asks for manual action. The location
// is never held without a scheduled recovery or a person told.
func TestSweepRetriesAreBoundedAndEmailOnce(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	id := f.deploying(f.loc1)
	f.jobStatus(f.jobOf(id), "dead", "ssh.unreachable")
	for i := 1; i <= inventory.MaxRecoveryAttempts; i++ {
		n, err := f.h.svc.SweepDeployments(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n, "attempt %d", i)
		d := f.get(id)
		require.Equal(t, i, d.RecoveryAttempts)
		want := inventory.DeployStatusRunning
		if i > inventory.RecoveryAttentionAfter {
			want = inventory.DeployStatusNeedsAttention
		}
		require.Equal(t, want, d.Status, "attempt %d", i)
		_, err = f.h.db.Owner.Exec(ctx, "UPDATE jobs SET status = 'failed', last_error_code = 'ssh.unreachable', finished_at = $2 WHERE dedupe_key = $1 AND status = 'queued'",
			"certificate.deploy_recover:"+id.String(), f.h.clock.Now())
		require.NoError(t, err)
		f.h.clock.Advance(14 * time.Minute)
		n, err = f.h.svc.SweepDeployments(ctx)
		require.NoError(t, err)
		require.Zero(t, n, "15-minute spacing")
		f.h.clock.Advance(time.Minute)
	}
	assert.Equal(t, 1, f.h.audits("deployment.needs_attention"))
	n, err := f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusRollbackFailed, d.Status, "the outcome is unknown: the files may be either")
	assert.Equal(t, "deployment.recovery_exhausted", d.ErrorCode)
	var templates []string
	for _, e := range f.emails() {
		templates = append(templates, e.Template)
	}
	assert.Equal(t, []string{"deployment.needs_attention", "deployment.outcome_unknown"}, templates, "Alice never reached the server: unknown, not a failed restore")
	assert.Len(t, f.recoverJobs(id), inventory.MaxRecoveryAttempts)
	loc, err := f.h.svc.GetLocation(ctx, f.loc1)
	require.NoError(t, err)
	assert.Nil(t, loc.ActiveDeploymentID)
}

// A deleted server's unfinished deployments end: nothing can reach the server any more.
func TestSweepEndsDeploymentsOfDeletedTargets(t *testing.T) {
	f := newDeployFixture(t)
	queued := f.request(f.admin, f.cert.ID, f.loc2)
	sent := f.deploying(f.loc3onTarget2)
	f.jobStatus(f.jobOf(sent), "dead", "system.not_found")
	running := f.deploying(f.loc4)
	f.jobStatus(f.jobOf(running), "running", "")
	require.NoError(t, f.h.svc.DeleteTarget(f.h.ctx, f.admin, f.target2))
	n, err := f.h.svc.SweepDeployments(f.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "a running job finishes or fails first")
	assert.Equal(t, inventory.DeployStatusFailed, f.get(queued).Status)
	assert.Equal(t, "deployment.target_deleted", f.get(queued).ErrorCode)
	assert.Equal(t, inventory.DeployStatusRollbackFailed, f.get(sent).Status)
	assert.Equal(t, "deployment.target_deleted", f.get(sent).ErrorCode)
	assert.Equal(t, inventory.DeployStateDeploying, f.get(running).State)
}

// Two sweeps at once (two Alice processes, a lost leader lock) handle each deployment once.
func TestConcurrentSweepsHandleEachDeploymentOnce(t *testing.T) {
	f := newDeployFixture(t)
	ids := []uuid.UUID{f.deploying(f.loc1), f.deploying(f.loc5), f.deploying(f.loc2), f.deploying(f.loc3onTarget2), f.deploying(f.loc4)}
	for _, id := range ids {
		f.jobStatus(f.jobOf(id), "dead", "ssh.unreachable")
	}
	var wg sync.WaitGroup
	counts := make([]int, 4)
	for i := range counts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := f.h.svc.SweepDeployments(f.h.ctx)
			assert.NoError(t, err)
			counts[i] = n
		}()
	}
	wg.Wait()
	total := 0
	for _, n := range counts {
		total += n
	}
	assert.Equal(t, len(ids), total)
	for _, id := range ids {
		assert.Equal(t, []string{"queued"}, f.recoverJobs(id))
		assert.Equal(t, 1, f.get(id).RecoveryAttempts)
	}
	assert.Equal(t, len(ids), f.h.audits("deployment.recovery_started"))
}

// RecordOutcome writes what an outcome means: terminal shapes finish the deployment, uncertain
// ones keep it in recovery with the earlier verification failure.
func TestRecordOutcome(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	id := f.deploying(f.loc1)
	lost := errors.New("connection lost")
	unc := inventory.DeployOutcomeRecord(providers.DeployOutcome{Result: providers.DeployUncertain, Reason: "deployment.verify_failed",
		Params: map[string]string{"port": "8443", "failed_step": "verify"}}, lost, false)
	retry := f.h.clock.Now().Add(10 * time.Second)
	require.NoError(t, f.h.svc.RecordOutcome(ctx, id, unc, retry))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, "uncertain", d.Result)
	assert.Equal(t, "deployment.verify_failed", d.VerifyFailedReason)
	require.NotNil(t, d.VerifyFailedPort)
	assert.Equal(t, 8443, *d.VerifyFailedPort)
	assert.Equal(t, retry, *d.RecoverAfter)
	assert.Empty(t, f.recoverJobs(id), "D22: the first recovery waits for recover_after; the sweep queues it")
	n, err := f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	f.h.clock.Advance(11 * time.Second)
	n, err = f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []string{"queued"}, f.recoverJobs(id))

	rb := inventory.RollbackOutcomeRecord(providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"},
		nil, d.VerifyFailedReason)
	require.NoError(t, f.h.svc.RecordOutcome(ctx, id, rb, time.Time{}))
	d = f.get(id)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
	assert.Equal(t, "deployment.verify_failed", d.VerifyFailedReason, "kept")
	assert.Equal(t, 1, f.h.audits("deployment.rolled_back"))
}

// Requirement: the key unsealed for a deployment appears in no returned value's printed form, no
// error, audit row, email, job payload, log line or database row of the whole deployment flow.
func TestDeploymentFlowLeaksNoKey(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	s := &leakScan{t: t, h: f.h, markers: secretMarkers(t, f.nw.Key)}
	got, err := f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1, f.loc2}})
	require.NoError(t, err)
	s.add(got)
	for i, r := range got {
		d, err := f.h.svc.BeginDeployment(ctx, r.ID)
		require.NoError(t, err)
		m, err := f.h.svc.DeploymentMaterial(ctx, r.ID, true)
		require.NoError(t, err)
		require.Contains(t, string(m.PrivateKeyPEM.Bytes()), "PRIVATE KEY")
		v := m.SendValues(pki.Fingerprint(f.old.Cert), 2)
		req := m.DeployRequest(v)
		s.add(d, m, req, v, m.PrecheckRequest())
		require.NoError(t, f.h.svc.StartDeployment(ctx, r.ID, v))
		require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, r.ID, "write_key", providers.StepOK, map[string]string{"mode": "0600",
			"key": string(m.PrivateKeyPEM.Bytes())}))
		_, err = f.h.svc.DeploymentMaterial(ctx, r.ID, true)
		s.add(err)
		m.PrivateKeyPEM.Zero()
		if i == 0 {
			require.NoError(t, f.h.svc.FinishDeployment(ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
				ErrorCode: "deployment.rollback_failed", FailedStep: "restore"}))
			continue
		}
		require.NoError(t, f.h.svc.MarkRecovering(ctx, r.ID, f.h.clock.Now(), true))
		_, err = f.h.svc.SweepDeployments(ctx)
		require.NoError(t, err)
	}
	page, err := f.h.svc.ListDeployments(ctx, inventory.DeploymentFilter{})
	require.NoError(t, err)
	s.add(page)
	for _, d := range page.Items {
		full, err := f.h.svc.Deployment(ctx, d.ID)
		require.NoError(t, err)
		rm, err := f.h.svc.DeploymentMaterial(ctx, d.ID, false)
		require.NoError(t, err)
		s.add(full, rm, rm.RollbackRequest(), rm.VerifyRequest())
	}
	require.NotEmpty(t, f.emails())
	s.check()
}

// Important 4: each deployment is swept in its own transaction; one that fails is logged with its
// id and retried next time, and does not stop the others.
func TestSweepOneFailingDeploymentDoesNotStopTheOthers(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	ids := []uuid.UUID{f.deploying(f.loc1), f.deploying(f.loc5), f.deploying(f.loc2)}
	for _, id := range ids {
		f.jobStatus(f.jobOf(id), "dead", "ssh.unreachable")
	}
	f.h.jobs.mu.Lock()
	f.h.jobs.fail = errors.New("queue down")
	f.h.jobs.mu.Unlock()
	n, err := f.h.svc.SweepDeployments(ctx)
	assert.Error(t, err, "the failure is reported")
	assert.Equal(t, 2, n)
	assert.Empty(t, f.recoverJobs(ids[0]), "the oldest one failed")
	assert.Equal(t, inventory.DeployStateDeploying, f.get(ids[0]).State, "and was rolled back alone")
	for _, id := range ids[1:] {
		assert.Equal(t, []string{"queued"}, f.recoverJobs(id))
	}
	assert.Contains(t, f.h.logs.String(), ids[0].String())
	n, err = f.h.svc.SweepDeployments(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "retried on the next run")
	assert.Equal(t, []string{"queued"}, f.recoverJobs(ids[0]))
}
