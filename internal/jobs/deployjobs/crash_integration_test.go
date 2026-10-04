//go:build integration

package deployjobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// F-66 / D24: Alice is killed at every point the engine can observe. The kill is simulated in
// process (runDying: the handler's goroutine ends at the point, its job keeps its lease, nothing
// after the point runs); Alice then starts again (the lease expires, Recover re-queues the job),
// and the real sweep and handlers run until the deployment ends. Each row asserts the final record,
// the files on the emulated server (a complete old or new pair, never mixed) and that the website
// serves what the record claims. The helper's own steps reach Alice only after nginx-deploy
// returned (D24), so "during the send" is observed as "after the send, before the outcome is
// recorded" (the helper finished on its own) and, inside the provider call, at the steps it
// reports: the verification and the inline rollback.
func TestDeploymentSurvivesAKillAtEveryPoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		point  string
		setup  func(s *server)
		status string
		reason string
		want   func(e *env) pki.Leaf
		sends  int
	}{
		// D23: nothing was recorded as started; the re-queued job deploys normally.
		{name: "after the pre-check, before the start record", point: "before:StartDeployment",
			status: inventory.DeployStatusSucceeded, want: newLeaf, sends: 1},
		// Recorded as started, nothing sent: no journal; final once the operation is fenced (AUD-05).
		{name: "after the start record, before the send", point: "after:StartDeployment",
			status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, sends: 0},
		// The helper finished on its own; the answer was never recorded: the journal and a fresh
		// verification decide.
		{name: "after the send, before the outcome is recorded", point: "session:after:DeployCertificate",
			status: inventory.DeployStatusSucceeded, want: newLeaf, sends: 1},
		// The provider verified, failed and rolled back inline before the kill: the files are back.
		// The verification's reason was recorded with its step before the restore (M-3), so the
		// recovery names it.
		{name: "after the send, the reload did nothing", point: "session:after:DeployCertificate",
			setup:  func(s *server) { s.emu.NoopReload(true) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf, sends: 1},
		// Killed while the new certificate is being verified (journal committed).
		{name: "during the verification", point: "step:verify:started",
			status: inventory.DeployStatusSucceeded, want: newLeaf, sends: 1},
		{name: "during the verification, the reload did nothing", point: "step:verify:started",
			setup:  func(s *server) { s.emu.NoopReload(true) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf, sends: 1},
		// The verification failed; killed before the inline restore was sent (journal committed).
		{name: "after a failed verification, before the inline rollback", point: "step:verify:failed",
			setup:  func(s *server) { s.emu.NoopReload(true) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf, sends: 1},
		// Killed during the inline rollback: the files are back (journal restored), the old
		// certificate not checked yet.
		{name: "during the inline rollback", point: "step:verify_old:started",
			setup:  func(s *server) { s.emu.NoopReload(true) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf, sends: 1},
		// Killed while the outcome of a completed rollback was being recorded.
		{name: "before recording a rolled back outcome", point: "before:RecordOutcome",
			setup:  func(s *server) { s.emu.FailReload(1) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.reload_failed", want: oldLeaf, sends: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			if tc.setup != nil {
				tc.setup(s)
			}
			id := e.request(s.locs[wwwCert])[0]
			k := newKiller(tc.point)
			e.runDying(k)
			require.Equal(t, tc.point, k.firedAt(), "the process was killed at the point")
			require.NotEqual(t, inventory.DeployStateDone, e.deployment(id).State, "the kill left the deployment unfinished")

			e.restart()
			assert.Equal(t, 1, e.audits("job.recovered"), "the killed job was taken back")
			if tc.point == "after:StartDeployment" {
				// AUD-05: right after the restart there is no journal; the recovery fences the
				// operation, after which "nothing was written" is final without waiting for any budget.
				e.drain()
				d := e.deployment(id)
				assert.Equal(t, inventory.DeployStateDone, d.State, "fenced: final at once")
				assert.Equal(t, 1, s.emu.FenceCount())
				assert.Equal(t, helperproto.PhaseFenced, s.emu.NginxPhase(d.OperationID.String()))
			}
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertPair(s, wwwCert, wwwKey, wwwName, tc.want(e))
			assert.Equal(t, tc.sends, s.emu.DeployCount(), "the certificate is sent at most once")
		})
	}
}

func newLeaf(e *env) pki.Leaf { return e.nw }
func oldLeaf(e *env) pki.Leaf { return e.old }

// A handler that panics after the send (the runner recovers it as a retryable failure): the job
// runs again, finds the deployment deploying and recovers from the journal instead of sending.
func TestPanicAfterTheSendIsRecovered(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	k := newKiller("session:after:DeployCertificate")
	k.panics = true
	e.runDying(k)
	require.Equal(t, "session:after:DeployCertificate", k.firedAt())
	v := e.jobOf(id)
	assert.Equal(t, jobs.StatusQueued, v.Status, "a panic is a retryable failure")
	assert.Equal(t, inventory.DeployStateDeploying, e.deployment(id).State)
	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, 1, s.emu.DeployCount())
}

// Killed during the recovery itself (a recovery job: its rollback reached the server, its outcome
// was never recorded): the next recovery reads the journal again and ends the deployment.
func TestDeploymentSurvivesAKillDuringRecovery(t *testing.T) {
	for _, tc := range []struct{ point, reason string }{
		// The first recovery's rollback reached the server before the kill; its verification failure
		// was recorded as a step first (M-3), so the second recovery (journal restored) names it.
		{"session:after:RollbackDeployment", "deployment.verify_failed"},
		{"before:RecordOutcome", "deployment.verify_failed"},
		// Killed before anything was decided: the second recovery verifies again.
		{"step:verify:started", "deployment.verify_failed"},
	} {
		point := tc.point
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			id := e.request(s.locs[wwwCert])[0]
			s.emu.NoopReload(true)
			s.emu.HangupAfter(helperproto.StepReload)
			e.drain() // uncertain: the answer was lost
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
			e.clock.Advance(inventory.FirstRecoveryDelay + time.Second)
			_, err := e.inv.SweepDeployments(e.ctx)
			require.NoError(t, err)
			k := newKiller(point)
			e.runDying(k) // the recovery job
			require.Equal(t, point, k.firedAt())
			require.NotEqual(t, inventory.DeployStateDone, e.deployment(id).State)

			e.restart()
			d := e.settle(id)
			assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
			assert.Equal(t, 1, s.emu.DeployCount())
			assert.GreaterOrEqual(t, e.audits("deployment.recovery_started"), 2, "a second recovery finished it")
			assert.Equal(t, 1, e.audits("job.dead"), "the killed recovery job is dead and audited")
			assert.Zero(t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'job.dead'"),
				"I-2: the deployment's own escalation is the alert, not a job.dead email")
		})
	}
}

// leaseThief is a session whose call makes the job lose its lease: another process takes the job
// over (as the reaper would), the runner's next heartbeat finds it gone and cancels the handler's
// context; the call then returns what it got.
type leaseThief struct {
	providers.Session
	e      *env
	method string
	done   chan struct{}
}

func (s leaseThief) steal(ctx context.Context) {
	// What the reaper does to a job whose lease expired: back to the queue.
	_, err := s.e.db.Owner.Exec(s.e.ctx, `UPDATE jobs SET status = 'queued', locked_by = NULL, locked_until = NULL, run_at = $1
WHERE status = 'running'`, s.e.clock.Now())
	require.NoError(s.e.t, err)
	s.e.clock.Advance(15 * time.Second) // the next heartbeat
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		s.e.t.Error("the runner did not cancel the handler after the lease was lost")
	}
	close(s.done)
}

func (s leaseThief) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if s.method == "VerifyDeployment" {
		s.steal(ctx)
		return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
	}
	return s.Session.VerifyDeployment(ctx, req)
}

func (s leaseThief) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	out, err := s.Session.DeployCertificate(ctx, req, log)
	if s.method == "DeployCertificate" {
		s.steal(ctx)
	}
	return out, err
}

// Lease loss with the real heartbeat: the runner cancels the handler. Lost during the pre-check,
// nothing is recorded and the job (taken back) deploys normally; lost after the send completed, the
// stale run records nothing (its writes are fenced to its claim, I-1): the job's next run reads the
// journal, verifies and records the outcome. Never sent twice.
func TestLeaseLostDuringTheDeployment(t *testing.T) {
	for _, tc := range []struct {
		method string
		state  string // right after the cancelled run
	}{
		{"VerifyDeployment", inventory.DeployStatePrecheck},
		{"DeployCertificate", inventory.DeployStateDeploying},
	} {
		t.Run(tc.method, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			id := e.request(s.locs[wwwCert])[0]
			done := make(chan struct{})
			e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
				return leaseThief{Session: sess, e: e, method: tc.method, done: done}
			})
			ran, err := e.runner.RunOnce(e.ctx)
			require.NoError(t, err)
			require.True(t, ran)
			<-done
			e.setWrap(nil)
			assert.Equal(t, tc.state, e.deployment(id).State)

			e.restart() // the thief's lease expires; the job is taken back and runs again
			d := e.settle(id)
			assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
			e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
			assert.Equal(t, 1, s.emu.DeployCount())
		})
	}
}

// verifyFails is a session of the second run whose verification of the new certificate fails (the
// website answered with something else at that moment); the old certificate's check is real.
type verifyFails struct {
	providers.Session
	newLeaf string
}

func (s verifyFails) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if req.Fingerprint == s.newLeaf {
		return providers.VerifyResult{Mode: "remote", Reason: "deployment.verify_other", Params: map[string]string{"port": "443"}}, nil
	}
	return s.Session.VerifyDeployment(ctx, req)
}

// I-1 (a): run A sent and verified, then stalled past its lease before recording; run B (the job
// taken back) recovered: its verification failed and it rolled back. When A resumes, its success
// is refused: the record says what the server holds.
func TestStaleRunCannotRecordAfterAnotherRunRolledBack(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	a := newStaller("session:after:DeployCertificate")
	doneA := e.startDying(a)
	waitFor(t, a.reach)
	require.Equal(t, pki.Fingerprint(e.nw.Cert), s.emu.Served(443, wwwName), "A's send and verification completed")

	e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return verifyFails{Session: sess, newLeaf: pki.Fingerprint(e.nw.Cert)}
	})
	e.restart() // A's lease expired: the job is taken back and B runs it
	e.drain()
	e.setWrap(nil)
	require.Equal(t, inventory.DeployStatusRolledBack, e.deployment(id).Status, "B rolled back")

	a.resume()
	waitFor(t, doneA)
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status, "A's stale success was not recorded")
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
	assert.Zero(t, e.audits("deployment.succeeded"))
	assert.NotEqual(t, pki.Fingerprint(e.nw.Cert), e.location(s, wwwCert).DeployedFingerprint)
	assert.Contains(t, e.logs.String(), "a stale run did not record its outcome")
}

// I-1 mirror: run A's verification failed and it stalled past its lease before its inline
// rollback; run B recovered and recorded success. When A resumes, the step it records before the
// restore is refused, its provider call is cancelled and the restore is never sent.
func TestStaleRunDoesNotRestoreAfterAnotherRunSucceeded(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	a := newStaller("before-step:verify:failed")
	// Something else answers while A verifies (A's verification fails), and is gone afterwards.
	a.on = map[string]func(){"step:verify:started": func() { s.emu.ServeOther(443, sha([]byte("balancer"))) }}
	doneA := e.startDying(a)
	waitFor(t, a.reach)
	s.emu.ServeOther(443, "")

	e.restart()
	e.drain()
	require.Equal(t, inventory.DeployStatusSucceeded, e.deployment(id).Status, "B verified and recorded success")
	reloads := s.emu.Reloads()

	a.resume()
	waitFor(t, doneA)
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, reloads, s.emu.Reloads(), "A's inline restore was never sent")
	assert.NotContains(t, strings.Join(s.srv.Commands(), "\n"), helperproto.SubNginxRestore)
}

// I-1 (b): run A recorded the start and stalled past its lease before the send; the job's next run
// and a recovery ended the deployment failed (no journal, after the helper's budget). When A
// resumes, its fenced check refuses the send: the record stays true.
func TestStaleRunCannotSendAfterTheDeploymentEnded(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	a := newStaller("after:StartDeployment")
	doneA := e.startDying(a)
	waitFor(t, a.reach)

	e.restart()
	d := e.settle(id)
	require.Equal(t, inventory.DeployStatusFailed, d.Status)

	a.resume()
	waitFor(t, doneA)
	assert.Zero(t, s.emu.DeployCount(), "the stale run did not send")
	assert.Equal(t, inventory.DeployStatusFailed, e.deployment(id).Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
}

func waitFor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Minute):
		t.Fatal("timed out")
	}
}

// M-5: the sweep alone hands a deployment whose deploy job died after the send to a recovery job
// (no restart pass re-queues the deploy job here): the recovery reads the journal and ends it.
func TestSweepHandsADeadJobsDeploymentToRecovery(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	k := newKiller("session:after:DeployCertificate")
	e.runDying(k)
	job := *e.deployment(id).JobID
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE jobs SET status = 'dead', locked_by = NULL, locked_until = NULL, finished_at = $2 WHERE id = $1`,
		job, e.clock.Now())
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM target_locks WHERE job_id = $1", job)
	require.NoError(t, err)
	require.Equal(t, inventory.DeployStateDeploying, e.deployment(id).State)

	n, err := e.inv.SweepDeployments(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM jobs WHERE type = 'certificate.deploy_recover' AND status = 'queued'"))
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
	assert.Equal(t, 1, e.count("SELECT attempts FROM jobs WHERE id = $1", job), "the dead deploy job did not run again")
}

// M-5: the helper itself is killed inside its transaction (no answer: uncertain); the recovery
// reads the journal it left and puts the old pair back.
func TestHelperKilledInsideItsTransaction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(s *server)
		phase string // the journal the helper left
	}{
		{"killed while writing", func(s *server) { s.emu.KillAt(helperproto.StepWriteCert) }, helperproto.PhaseWriting},
		{"killed while writing, exit 137", func(s *server) { s.emu.KillAtWithExit137(helperproto.StepWriteCert) }, helperproto.PhaseWriting},
		{"killed while restoring", func(s *server) {
			s.emu.FailReload(1)
			s.emu.KillAt(helperproto.StepRollbackReload)
		}, helperproto.PhaseRestoring},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			id := e.request(s.locs[wwwCert])[0]
			tc.setup(s)
			e.drain()
			require.Equal(t, tc.phase, s.emu.NginxPhase(id.String()))
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "a killed helper is an uncertain outcome")
			d := e.settle(id)
			assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
			e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
			assert.Equal(t, 1, s.emu.DeployCount())
		})
	}
}

// M-5: Alice restarts while the helper still holds its lock (status active): recovery waits, then
// finishes from the journal the helper leaves (committed: verified; restored: rolled back).
func TestRecoveryWaitsForAnActiveHelper(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(s *server)
		status string
		want   func(e *env) pki.Leaf
	}{
		{"then committed", func(s *server) { s.emu.HangupAfter(helperproto.StepReload) }, inventory.DeployStatusSucceeded, newLeaf},
		{"then restored", func(s *server) {
			s.emu.FailReload(1)
			s.emu.HangupAfter(helperproto.StepRollbackReload)
		}, inventory.DeployStatusRolledBack, oldLeaf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			s := e.addServer("web-01", wwwSite())
			id := e.request(s.locs[wwwCert])[0]
			tc.setup(s)
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
			s.emu.HoldLock(true)
			for range 3 {
				e.clock.Advance(inventory.RecoveryRetryInterval + time.Minute)
				_, err := e.inv.SweepDeployments(e.ctx)
				require.NoError(t, err)
				e.drain()
				d := e.deployment(id)
				require.Equal(t, inventory.DeployStateRecovering, d.State, "nothing is decided while the helper is active")
				assert.Equal(t, "nginx.busy", d.ErrorCode)
			}
			s.emu.HoldLock(false)
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status)
			e.assertPair(s, wwwCert, wwwKey, wwwName, tc.want(e))
		})
	}
}
