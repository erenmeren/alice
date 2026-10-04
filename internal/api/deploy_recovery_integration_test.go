//go:build integration

package api

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// Interruption journeys (F-08, F-66): the helper dies, the connection drops, Alice dies or the
// server cannot be reached. The real runner, the sweep (a scheduled task of the real process) and
// the recovery jobs finish the deployment; in every case the final record, the files on the server
// and the certificate the website serves agree.

// TestHelperKilledAndConnectionLost: the uncertain outcomes of the helper's side.
func TestHelperKilledAndConnectionLost(t *testing.T) {
	type row struct {
		name   string
		setup  func(n *nj)
		status string
		code   string
		want   string // "old" or "new"
	}
	for _, tc := range []row{
		{"the helper is killed by a signal while writing", func(n *nj) { n.f.emu.KillAt(helperproto.StepWriteCert) }, "rolled_back", "ALC-DEP-0010", "old"},
		{"the helper is killed, exit status 137", func(n *nj) { n.f.emu.KillAtWithExit137(helperproto.StepWriteCert) }, "rolled_back", "ALC-DEP-0010", "old"},
		{"the helper is killed while restoring", func(n *nj) {
			n.f.emu.FailReload(1)
			n.f.emu.KillAt(helperproto.StepRollbackReload)
		}, "rolled_back", "ALC-DEP-0006", "old"},
		{"the connection drops after the reload", func(n *nj) { n.f.emu.HangupAfter(helperproto.StepReload) }, "succeeded", "", "new"},
		{"the connection drops and the reload did nothing", func(n *nj) {
			n.f.emu.NoopReload(true)
			n.f.emu.HangupAfter(helperproto.StepReload)
		}, "rolled_back", "ALC-DEP-0003", "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNJ(t, wwwSite())
			leaf := n.issue()
			certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
			tc.setup(n)
			start := n.clock.Now()
			ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]
			n.runJobs()

			// The answer was lost: what the API shows is a deployment being recovered, not a failure.
			d := n.deployment(n.op, ref.ID)
			require.Equal(t, "recovering", d.State)
			assert.Equal(t, "running", d.Status)
			assert.Equal(t, "uncertain", d.Result)
			require.NotNil(t, d.RecoverAfter)
			assert.Equal(t, start.Add(inventory.FirstRecoveryDelay), *d.RecoverAfter)
			assert.Empty(t, n.deploymentEmails(), "no email while the outcome is being recovered")

			d = n.settle(n.op, ref.ID)
			assert.Equal(t, tc.status, d.Status)
			assert.Equal(t, tc.code, d.errorCode())
			assert.Equal(t, 1, n.f.emu.DeployCount(), "never sent twice")
			if tc.want == "new" {
				n.f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
				assert.Equal(t, pki.Fingerprint(leaf.Cert), n.location(n.admin, n.targetID, wwwCert)["deployed_fingerprint"])
				assert.Empty(t, n.deploymentEmails())
			} else {
				n.f.requirePair(t, wwwCert, wwwKey, wwwName, n.f.old)
				assert.Equal(t, "", n.location(n.admin, n.targetID, wwwCert)["deployed_fingerprint"])
				assert.Equal(t, map[string]int{"deployment.failed": 1}, n.deploymentEmails())
			}
			assert.Equal(t, 1, n.auditCount("deployment.recovery_started"))
			assert.Zero(t, n.emails("job.dead"), "the deployment's own email is the alert")
		})
	}
}

// killAfterSend is a session of a process that dies the moment the helper's answer has arrived:
// the deployment is sent, nothing was recorded. The goroutine ends at once (runtime.Goexit: nothing
// after the call runs and no outcome reaches the runner), so the job keeps its lease, as after a
// SIGKILL; its deferred calls only close the session and zero the key.
type killAfterSend struct {
	providers.Session
	fired *atomic.Bool
}

func (k killAfterSend) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	out, err := k.Session.DeployCertificate(ctx, req, log)
	if k.fired.CompareAndSwap(false, true) {
		runtime.Goexit()
	}
	return out, err
}

// Alice is killed between the send and the record. After the restart (the lease of the killed job
// expires and the startup pass takes the job back) the deployment is finished from the helper's
// journal; the certificate is never sent twice.
func TestAliceRestartsBetweenSendAndRecord(t *testing.T) {
	n := newNJ(t, wwwSite())
	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
	ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]

	var fired atomic.Bool
	n.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return killAfterSend{Session: sess, fired: &fired}
	})
	dying := n.newRunner("dying", 24*time.Hour)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = dying.RunOnce(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("the dying process did not end")
	}
	n.setWrap(nil)
	require.True(t, fired.Load(), "the process was killed after the send")
	require.Equal(t, 1, n.f.emu.DeployCount())

	d := n.deployment(n.op, ref.ID)
	assert.Equal(t, "deploying", d.State, "the record knows the send was started, not how it ended")
	assert.Equal(t, "running", n.job(n.op, ref.JobID)["status"], "the dead process's job still holds its lease")

	n.clock.Advance(46 * time.Second) // the lease runs out
	n.signIn(n.op, n.opAcct)
	recovered, err := n.runner.Recover(context.Background()) // what the new process does at startup
	require.NoError(t, err)
	assert.Equal(t, 1, recovered)
	assert.Equal(t, 1, n.auditCount("job.recovered"))

	d = n.settle(n.op, ref.ID)
	assert.Equal(t, "succeeded", d.Status)
	n.f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
	assert.Equal(t, 1, n.f.emu.DeployCount(), "the certificate is sent at most once")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), n.location(n.admin, n.targetID, wwwCert)["deployed_fingerprint"])
	assert.Empty(t, n.deploymentEmails())
}

// The server cannot be reached while a deployment is being recovered: the deployment says it is
// being recovered, the Administrators get one email when Alice has tried for an hour, and when the
// server is back the recovery finishes the deployment from the journal.
func TestUnreachableServerDuringRecovery(t *testing.T) {
	n := newNJ(t, wwwSite())
	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Renewed"))
	n.f.emu.NoopReload(true) // the website will not serve the new certificate: recovery must roll back
	n.f.emu.HangupAfter(helperproto.StepReload)
	ref := n.deploy(n.op, certID, n.locs[wwwCert])[0]
	n.runJobs()
	require.Equal(t, "recovering", n.deployment(n.op, ref.ID).State)

	n.setDown(true)
	attention := 0
	for round := 1; round <= 8; round++ {
		// Half of the interval, a request (the Operator's session ends after 15 idle minutes), the rest.
		n.clock.Advance((inventory.RecoveryRetryInterval + time.Minute) / 2)
		n.deployment(n.op, ref.ID)
		n.clock.Advance((inventory.RecoveryRetryInterval + time.Minute) / 2)
		_, err := n.inv.SweepDeployments(context.Background())
		require.NoError(t, err)
		n.runJobs()
		d := n.deployment(n.op, ref.ID)
		require.Equal(t, "recovering", d.State, "nothing is decided while the server cannot be reached (round %d)", round)
		if d.Status == "needs_attention" && attention == 0 {
			attention = round
		}
		// The latest recovery attempt failed because the server cannot be reached; the deployment itself
		// keeps saying what is known of the send (its state is recovering).
		var recoverJob string
		require.NoError(t, n.db.Owner.QueryRow(context.Background(),
			"SELECT id::text FROM jobs WHERE type = 'certificate.deploy_recover' ORDER BY created_at DESC, id DESC LIMIT 1").Scan(&recoverJob))
		assert.Equal(t, "ALC-SSH-0001", jobErrorCode(n.job(n.op, recoverJob)), "round %d", round)
	}
	require.NotZero(t, attention, "the deployment asks for attention")
	assert.Equal(t, inventory.RecoveryAttentionAfter+1, attention)
	assert.Equal(t, map[string]int{"deployment.needs_attention": 1}, n.deploymentEmails(), "one email, however long it takes")
	assert.Equal(t, 1, n.f.emu.DeployCount())

	n.setDown(false)
	d := n.settle(n.op, ref.ID)
	assert.Equal(t, "rolled_back", d.Status)
	assert.Equal(t, "ALC-DEP-0003", d.errorCode())
	n.f.requirePair(t, wwwCert, wwwKey, wwwName, n.f.old)
	assert.Equal(t, map[string]int{"deployment.needs_attention": 1, "deployment.failed": 1}, n.deploymentEmails())
	assert.Equal(t, 1, n.f.emu.DeployCount())
	assert.Equal(t, "", n.location(n.op, n.targetID, wwwCert)["deployed_fingerprint"])
}
