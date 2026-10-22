//go:build integration

package deployjobs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// R48 through the whole stack (the engine, inventory on PostgreSQL, the nginx provider and the emulated helper): with
// the old key marked compromised, no failing new install ever puts the old key back on the server.

// compromiseOld marks the certificate the server held before (found by the discovery) compromised.
func (e *env) compromiseOld() {
	e.t.Helper()
	tag, err := e.db.Owner.Exec(e.ctx, "UPDATE certificates SET compromised_at = $2 WHERE fingerprint_sha256 = $1", pki.Fingerprint(e.old.Cert),
		e.clock.Now())
	require.NoError(e.t, err)
	require.EqualValues(e.t, 1, tag.RowsAffected())
}

// assertOldKeyGone checks that the server's key file is not the compromised key.
func (e *env) assertOldKeyGone(s *server) {
	e.t.Helper()
	assert.NotEqual(e.t, string(e.old.KeyPEM), string(s.emu.NginxFile(wwwKey)), "the compromised key is never put back")
	assert.Equal(e.t, string(e.nw.KeyPEM), string(s.emu.NginxFile(wwwKey)))
}

func (e *env) assertForbidden(d inventory.Deployment) {
	e.t.Helper()
	assert.Equal(e.t, inventory.DeployStatusRollbackFailed, d.Status)
	assert.Equal(e.t, providers.ReasonRollbackForbidden, d.ErrorCode)
	assert.Equal(e.t, providers.PhaseRestoreForbidden, d.Phase)
	assert.Equal(e.t, providers.StepNameRestore, d.FailedStep)
	// A Windows deployment's notice is queued in its Windows text (_windows, notify-windows 2db347aa).
	assert.Equal(e.t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key IN ('deployment.rollback_forbidden', 'deployment.rollback_forbidden_windows')"))
	assert.Zero(e.t, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key IN ('deployment.rollback_failed', 'deployment.rollback_failed_windows')"),
		"never the e-mail that says to restore the backup")
}

// The controller path: the commit's answer is lost and the website does not serve the new certificate; the old key is
// marked compromised only after the deployment started, so the recovery's own read of the guard is what refuses.
func TestRecoveryNeverReinstallsACompromisedKey(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	s.emu.NoopReload(true)
	s.emu.HangupAfter(helperproto.StepReload)
	e.drain()
	require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
	require.Equal(t, helperproto.PhaseCommitted, s.emu.NginxPhase(id.String()))
	e.compromiseOld()
	d := e.settle(id)
	e.assertForbidden(d)
	assert.Equal(t, "deployment.verify_failed", d.VerifyFailedReason, "why it was rolled back")
	assert.Equal(t, helperproto.PhaseRestoreForbidden, s.emu.NginxPhase(id.String()))
	e.assertOldKeyGone(s)
	assert.Equal(t, 1, s.emu.DeployCount(), "never sent twice")
}

// The helper path: the old key was compromised before the deployment; the helper dies while writing (the new key is
// in place, the certificate is still the old one), and the recovery's restore is refused by the helper itself: the
// mixed pair stays (the website may be broken: security first) and the old key never comes back.
func TestInterruptedWriteWithACompromisedKeyIsNotRestored(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	e.compromiseOld()
	id := e.request(s.locs[wwwCert])[0]
	s.emu.KillAt(helperproto.StepWriteCert)
	e.drain()
	require.Equal(t, helperproto.PhaseWriting, s.emu.NginxPhase(id.String()))
	d := e.settle(id)
	e.assertForbidden(d)
	assert.NotEqual(t, string(e.old.KeyPEM), string(s.emu.NginxFile(wwwKey)), "the compromised key is never put back")
	started := e.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.started' AND details->>'rollback' = 'forbidden'")
	assert.Equal(t, 1, started, "the plan-time verdict is audited")
}

// The helper's own rollback in the deploy job: a failed reload, the old key compromised before the deployment.
func TestFailedReloadWithACompromisedKeyIsNotRestored(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	e.compromiseOld()
	id := e.request(s.locs[wwwCert])[0]
	s.emu.FailReload(1)
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStateDone, d.State)
	e.assertForbidden(d)
	assert.Equal(t, providers.StepNameReload, d.CauseStep)
	e.assertOldKeyGone(s)
}

// A helper older than protocol 10 is never used for a deployment whose backup is forbidden: refused before the send.
func TestOlderHelperIsNotUsedOverACompromisedKey(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	s.emu.SetProtocol(9)
	e.compromiseOld()
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, linuxssh.ReasonRollbackGuardOutdated, d.ErrorCode)
	assert.Equal(t, map[string]string{"helper_protocol": "9", "required_protocol": "10"}, d.ErrorParams)
	assert.Zero(t, s.emu.DeployCount(), "nothing was sent")
	e.assertPair(s, wwwCert, wwwKey, wwwName, e.old)
}
