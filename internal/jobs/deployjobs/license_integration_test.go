//go:build integration

package deployjobs

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// lockingSession puts the license in lock while its deployment is in flight.
type lockingSession struct {
	providers.Session
	gate *lockGate
}

func (s lockingSession) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	s.gate.locked.Store(true) // the license expires past its grace while nginx-deploy runs
	return s.Session.DeployCertificate(ctx, req, log)
}

// L-80: a deployment already running when the license locks finishes (the gate is checked when a
// job is claimed, never in the middle of a change); a deployment queued meanwhile is held
// (blocked_license) after the runner's lock sweep, and its record shows it (L-81 part).
func TestL80InFlightDeployFinishesAcrossLock(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite(), apiSite())
	ids := e.request(s.locs[wwwCert], s.locs[apiCert])
	e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return lockingSession{Session: sess, gate: e.gate}
	})
	ran, err := e.runner.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ran)
	require.True(t, e.gate.locked.Load())
	e.setWrap(nil)
	first, second := ids[0], ids[1]
	if e.deployment(first).State != inventory.DeployStateDone {
		first, second = second, first
	}
	assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(first).Status, "the in-flight deployment finished in lock")

	e.clock.Advance(2 * time.Second) // the runner sweeps queued changes in lock at most once per poll
	e.drain()
	d := e.deployment(second)
	assert.Equal(t, inventory.DeployStateQueued, d.State)
	assert.Equal(t, string(jobs.StatusBlocked), d.JobStatus, "the deployment says it is held for an Administrator")
	assert.Equal(t, 1, s.emu.DeployCount(), "nothing else was sent in lock")
	_, err = e.inv.SweepDeployments(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateQueued, e.deployment(second).State, "the sweep leaves a held deployment alone")
}

// L-81: a deployment queued before the lock is held; a renewal alone does not start it; an
// Administrator's confirmation does, and it succeeds.
func TestL81QueuedDeployIsBlockedThenConfirmed(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	e.gate.locked.Store(true)
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStateQueued, d.State)
	assert.Equal(t, string(jobs.StatusBlocked), d.JobStatus)
	assert.Equal(t, 1, e.audits("job.blocked_license"))

	e.gate.locked.Store(false) // renewed
	e.drain()
	assert.Equal(t, string(jobs.StatusBlocked), e.deployment(id).JobStatus, "a renewal alone starts nothing")
	assert.Zero(t, s.emu.DeployCount())

	require.NoError(t, e.queue.Confirm(e.ctx, e.admin.Audit, e.admin.UserID, *d.JobID))
	e.drain()
	d = e.deployment(id)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, string(jobs.StatusSucceeded), d.JobStatus)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.nw)
}

// L-82: a lock during a deployment never strands a server: the recovery (ClassAlways) runs in lock,
// verifies, rolls back and ends the deployment; no certificate.deploy job runs in lock.
func TestL82RollbackRunsDespiteLock(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.NoopReload(true)
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
	e.gate.locked.Store(true)
	deployRuns := e.count("SELECT count(*) FROM job_attempts a JOIN jobs j ON j.id = a.job_id WHERE j.type = 'certificate.deploy'")

	d := e.settle(id)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
	assert.Equal(t, 1, e.audits("deployment.failed"))
	assert.Equal(t, 1, e.audits("deployment.rolled_back"))
	assert.Equal(t, deployRuns, e.count("SELECT count(*) FROM job_attempts a JOIN jobs j ON j.id = a.job_id WHERE j.type = 'certificate.deploy'"),
		"no certificate.deploy job ran in lock")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM jobs WHERE type = 'certificate.deploy_recover' AND status = 'succeeded'"))
}

// Requirement 7: no trace of the private key anywhere Alice keeps or shows data, over a deployment,
// an uncertain one and its recovery: job rows (payload, result, error), deployment records, steps,
// audit, outbox, and every log line.
func TestDeployAndRecoveryLeakNoKey(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite(), apiSite())
	ids := e.request(s.locs[wwwCert])
	e.drain()
	require.Equal(t, inventory.DeployStatusSucceeded, e.deployment(ids[0]).Status)
	s.emu.NoopReload(true)
	s.emu.HangupAfter(helperproto.StepReload)
	ids = append(ids, e.request(s.locs[apiCert])...)
	e.drain()
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(ids[1]).State)
	d := e.settle(ids[1])
	require.Equal(t, inventory.DeployStatusRolledBack, d.Status)

	var dump strings.Builder
	for _, table := range []string{"jobs", "job_attempts", "deployments", "deployment_steps", "audit_log", "notifications_outbox", "targets",
		"certificate_locations"} {
		rows, err := e.db.Owner.Query(e.ctx, "SELECT t::text FROM "+table+" t")
		require.NoError(t, err)
		for rows.Next() {
			var line string
			require.NoError(t, rows.Scan(&line))
			dump.WriteString(line + "\n")
		}
		require.NoError(t, rows.Err())
		rows.Close()
	}
	dump.WriteString(e.logs.String())
	for _, j := range []inventory.Deployment{e.deployment(ids[0]), e.deployment(ids[1])} {
		v := e.jobOf(j.ID)
		dump.WriteString(strings.Join([]string{v.LastErrorCode}, " "))
	}
	text := dump.String()
	require.Contains(t, text, "certificate.deploy_recover", "the dump holds the jobs")
	for i, needle := range keyMarkers(t, e.nw.KeyPEM) {
		// A boolean, so that a failing run does not print what it found.
		assert.False(t, strings.Contains(text, needle), "key marker %d leaked into a record or a log", i)
	}
}

// keyMarkers renders a PEM private key the ways it could leak: the PEM marker, a slice of the base64
// body, the DER as hex and as base64.
func keyMarkers(t *testing.T, keyPEM []byte) []string {
	t.Helper()
	b, _ := pem.Decode(keyPEM)
	require.NotNil(t, b)
	body := base64.StdEncoding.EncodeToString(b.Bytes)
	return []string{"PRIVATE " + "KEY", body[10:50], hex.EncodeToString(b.Bytes)[20:80], base64.RawStdEncoding.EncodeToString(b.Bytes[7:40])}
}
