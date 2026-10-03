//go:build integration

package deployjobs

import (
	"context"
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
		// Recorded as started, nothing sent: no journal; final only after the helper's budget (S6).
		{name: "after the start record, before the send", point: "after:StartDeployment",
			status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, sends: 0},
		// The helper finished on its own; the answer was never recorded: the journal and a fresh
		// verification decide.
		{name: "after the send, before the outcome is recorded", point: "session:after:DeployCertificate",
			status: inventory.DeployStatusSucceeded, want: newLeaf, sends: 1},
		// The provider verified, failed and rolled back inline before the kill: the files are back;
		// the verification's reason lived only in the killed process, so the record says
		// interrupted (true, and never "nothing was written").
		{name: "after the send, the reload did nothing", point: "session:after:DeployCertificate",
			setup:  func(s *server) { s.emu.NoopReload(true) },
			status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf, sends: 1},
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
			status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf, sends: 1},
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
				// S6: right after the restart the start record is younger than the helper's budget:
				// "no journal" is not final yet.
				e.drain()
				d := e.deployment(id)
				assert.Equal(t, inventory.DeployStateRecovering, d.State, "no journal within the budget is not final")
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
		// The first recovery's rollback reached the server; its verification reason was never
		// recorded, so the second recovery (journal restored) can only say interrupted.
		{"session:after:RollbackDeployment", "deployment.interrupted"},
		{"before:RecordOutcome", "deployment.interrupted"},
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
	_, err := s.e.db.Owner.Exec(s.e.ctx, "UPDATE jobs SET locked_by = 'another-process/x' WHERE status = 'running'")
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
// nothing is recorded and the job (reaped) deploys normally; lost after the send completed, the
// outcome is still recorded (a detached write) and never sent again.
func TestLeaseLostDuringTheDeployment(t *testing.T) {
	for _, tc := range []struct {
		method string
		state  string // right after the cancelled run
	}{
		{"VerifyDeployment", inventory.DeployStatePrecheck},
		{"DeployCertificate", inventory.DeployStateDone},
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
