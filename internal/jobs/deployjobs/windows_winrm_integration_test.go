//go:build integration

package deployjobs

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs/winjobs"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// R71 Task 6: the engine over WinRS. The same queue, runner, deployment engine and inventory as the SSH tests; the
// Windows provider reaches wintest's WinRM listener (NTLMv2, the pinned SPKI) with the password inventory seals, and the
// helper's own code runs on the modelled host. Nothing in the engine knows the transport.

// TestWindowsWinRMDeployAndRollback: a binding deployment commits and verifies; with StaleTLS it rolls back.
func TestWindowsWinRMDeployAndRollback(t *testing.T) {
	e := newEnv(t)
	s := e.addWinRMServer("iis-01", nil)
	e.connectWinRM(s)
	d := e.settle(e.request(s.loc)[0])
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, winSteps, stepList(d.Steps))
	assert.GreaterOrEqual(t, d.Level, providers.LevelServed)
	e.assertWinServes(s.winServer, e.nw)
	assert.Equal(t, winproto.PhaseCommitted, s.phase(t, d.ID))
	assert.Empty(t, s.srv.Commands(), "nothing went over SSH")

	s.model.StaleTLS(true)
	c3 := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(c3.FullchainPEM), PrivateKeyPEM: string(c3.KeyPEM)})
	require.NoError(t, err)
	e.evaluate()
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	d = e.settle(got[0].ID)
	require.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
	assert.Equal(t, winproto.PhaseRestored, s.phase(t, d.ID))
	e.assertWinServes(s.winServer, e.nw)
}

// TestWindowsWinRMCrashTable (Review Focus 3): the helper killed at each W2 journal point over WinRS; the server
// reboots and the engine's recovery (iis-status, iis-fence over WinRS) ends the deployment as over SSH.
func TestWindowsWinRMCrashTable(t *testing.T) {
	for point, tc := range winKillRows {
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addWinRMServer("iis-01", nil)
			e.connectWinRM(s)
			s.model.StaleTLS(tc.stale)
			s.model.KillAt(point)
			id := e.request(s.loc)[0]
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "a killed helper is an uncertain outcome")
			require.Equal(t, 1, s.sentWinRM(winproto.SubIISDeploy))
			s.model.StaleTLS(false)
			s.model.Reboot()
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertWinServes(s.winServer, tc.want(e))
			assert.Equal(t, 1, s.sentWinRM(winproto.SubIISDeploy), "the certificate is sent at most once")
			switch {
			case tc.fenced:
				assert.Equal(t, winproto.PhaseFenced, s.phase(t, id))
				assert.Equal(t, tc.phase, d.Phase)
			case tc.status == inventory.DeployStatusRolledBack:
				assert.Equal(t, winproto.PhaseRestored, s.phase(t, id))
			default:
				assert.Equal(t, winproto.PhaseCommitted, s.phase(t, id))
			}
		})
	}
}

// sentWinRM is the number of shells created for sub: the WinRM log keeps each Create's SSH_ORIGINAL_COMMAND line.
func (s *winrmServer) sentWinRM(sub string) int {
	n := 0
	for _, r := range s.model.WinRMLog() {
		if first, _, _ := strings.Cut(r.Line, " "); r.Action == "Create" && first == sub {
			n++
		}
	}
	return n
}

// TestWindowsWinRMDiscoveryAndCleanup: over WinRM discovery lists the bindings, the CCS files and the RDP listener of
// the demo host (the WinRM record unsupported), and the W3 cleanup runs.
func TestWindowsWinRMDiscoveryAndCleanup(t *testing.T) {
	e := newEnv(t)
	winjobs.Register(e.runner, winjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
	m, err := wintest.Demo(e.clock.Now())
	require.NoError(t, err)
	s := e.addWinRMServer("iis-demo", m)
	e.connectWinRM(s)
	list, err := e.inv.ListLocations(e.ctx, s.target, false)
	require.NoError(t, err)
	kinds := map[string]bool{}
	for _, l := range list.Items {
		kinds[string(l.Kind)] = true
		if l.CertPath == "http.sys/ipport/0.0.0.0:5986" {
			assert.False(t, l.Supported, "the WinRM listener's own binding (Ruling 11)")
			assert.Equal(t, "win_foreign_app", l.UnsupportedReason)
		}
	}
	for _, k := range []providers.LocationKind{providers.LocationWinSSLBinding, providers.LocationWinRDP} {
		assert.True(t, kinds[string(k)], "%s listed: %v", k, kinds)
	}
	status, res := e.cleanupNow(s.winServer)
	assert.Equal(t, "succeeded", status, "%v", res)
}

// TestWindowsWinRMIdentityChangeBlocks: a listener presenting a new key blocks the target, and no deployment is sent.
func TestWindowsWinRMIdentityChangeBlocks(t *testing.T) {
	e := newEnv(t)
	s := e.addWinRMServer("iis-01", nil)
	e.connectWinRM(s)
	before := len(s.model.WinRMLog())
	l := e.ca.Issue(pki.Opts{CommonName: "iis-01", SANs: []string{"iis-01"}}, e.clock.Now())
	b, ok := s.model.Binding(winrmLocator)
	require.True(t, ok)
	b.CertSHA1 = s.model.AddCertificate("My", l.CertPEM, l.KeyPEM, wintest.CertOptions{})
	require.NoError(t, s.model.Host().UpdateBinding(context.Background(), b))

	d := e.settle(e.request(s.loc)[0])
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "target.host_key_changed", d.ErrorCode)
	assert.Len(t, s.model.WinRMLog(), before, "no request reached the listener")
	assert.Empty(t, s.model.Imported(), "nothing was deployed")
	e.assertWinServes(s.winServer, e.old)
	got, err := e.inv.GetTarget(e.ctx, s.target)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusHostKeyChanged, got.Status)
}

// TestWindowsWinRMAuthRefused: the account's password changed on the server: the deployment fails
// windows.winrm_auth_refused (ALC-WIN-0024) with nothing sent; the new password set in Alice makes the next one work.
func TestWindowsWinRMAuthRefused(t *testing.T) {
	e := newEnv(t)
	s := e.addWinRMServer("iis-01", nil)
	e.connectWinRM(s)
	pw := "W7-new-" + rand.Text()
	s.model.SetWinRMAccount("alice", pw)

	d := e.settle(e.request(s.loc)[0])
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "windows.winrm_auth_refused", d.ErrorCode)
	assert.Equal(t, "winrm", d.ErrorParams["transport"], "the e-mail's and the web's variant")
	assert.Empty(t, s.model.Imported(), "nothing was sent")
	assert.Empty(t, s.phase(t, d.ID), "no journal")

	e.setWinRMPassword(s, pw)
	d = e.settle(e.request(s.loc)[0])
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	e.assertWinServes(s.winServer, e.nw)
}

// TestWindowsWinRMPasswordMissing: a WinRM target without a password is never dialled: its connection test fails
// windows.winrm_password_missing (ALC-WIN-0025), and so does a deployment once its password is gone.
func TestWindowsWinRMPasswordMissing(t *testing.T) {
	e := newEnv(t)
	s := e.addWinRMServer("iis-01", nil)
	e.drain()
	got, err := e.inv.GetTarget(e.ctx, s.target)
	require.NoError(t, err)
	assert.Equal(t, "windows.winrm_password_missing", got.LastErrorCode)
	assert.Zero(t, s.ws.Connections(), "nothing was dialled")
	keys, err := e.inv.ListHostKeys(e.ctx, s.target)
	require.NoError(t, err)
	assert.Empty(t, keys, "no identity sighting before the password")

	e.connectWinRM(s)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM credentials WHERE target_id = $1 AND purpose = 'win_winrm'", s.target)
	require.NoError(t, err)
	conns := s.ws.Connections()
	d := e.settle(e.request(s.loc)[0])
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "windows.winrm_password_missing", d.ErrorCode)
	assert.Equal(t, conns, s.ws.Connections(), "nothing was dialled")
	e.assertWinServes(s.winServer, e.old)
}
