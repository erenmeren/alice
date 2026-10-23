//go:build integration

package deployjobs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// winKillRow is one row of the kill matrix.
type winKillRow struct {
	stale  bool   // the website does not take the change, so the verification fails and the inline restore runs
	status string // the final record
	reason string
	want   func(e *env) pki.Leaf
	fenced bool   // nothing was written: the recovery fenced the operation
	phase  string // a fenced row: the phase recorded (the status read before the fence)
}

// winKillRows are the rows of the helper's crash points (Task 3), by point; the matrix runs them in the order a run passes them.
var winKillRows = map[string]winKillRow{
	"deploy.locked":             {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhaseNone},
	"deploy.prepared":           {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"deploy.import_chain":       {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"deploy.import_certificate": {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"deploy.writing":            {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"deploy.bound":              {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"deploy.read_back":          {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"deploy.committed":          {status: inventory.DeployStatusSucceeded, want: newLeaf},
	"restore.restoring":         {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.bound":             {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.restored":          {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
}

// Design §13 W2 item 4 and Review Focus 4: the helper is killed at every crash point (it answers nothing), the server
// reboots (the lock, schannel's cache and the stale listeners are gone; records, stores and journals stay), and
// Alice's recovery ends the deployment. The binding then names exactly the previous or the new certificate, the
// website serves what the record claims, and the record agrees with the model; a kill before prepared is fenced and
// the operation, sent again, never runs.
func TestWindowsDeploymentSurvivesAKillAtEveryPoint(t *testing.T) {
	// The matrix is complete: a deployment rolled back after its verification passes exactly these points.
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	s.model.StaleTLS(true)
	e.request(s.loc)
	e.drain()
	points := s.model.Points()
	require.Len(t, points, len(winKillRows), "%v", points)
	for _, p := range points {
		require.Contains(t, winKillRows, p, "a crash point without a row")
	}

	for _, point := range points {
		tc := winKillRows[point]
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addWinServer("iis-01")
			s.model.StaleTLS(tc.stale)
			s.model.KillAt(point)
			deployedBefore := e.winLocation(s).DeployedFingerprint
			id := e.request(s.loc)[0]
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "a killed helper is an uncertain outcome")
			require.Equal(t, 1, s.sent(winproto.SubIISDeploy))

			s.model.StaleTLS(false)
			s.model.Reboot()
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertWinServes(s, tc.want(e))
			if tc.status == inventory.DeployStatusSucceeded {
				assert.Equal(t, pki.Fingerprint(e.nw.Cert), e.winLocation(s).DeployedFingerprint)
				assert.Equal(t, winproto.PhaseCommitted, s.phase(t, id))
			} else {
				assert.Equal(t, deployedBefore, e.winLocation(s).DeployedFingerprint, "the record still names what was deployed before")
			}
			if tc.status == inventory.DeployStatusRolledBack {
				assert.Equal(t, winproto.PhaseRestored, s.phase(t, id), "the helper's journal agrees with the record")
			}
			assert.Equal(t, 1, s.sent(winproto.SubIISDeploy), "the certificate is sent at most once")
			if !tc.fenced {
				return
			}
			assert.Equal(t, winproto.PhaseFenced, s.phase(t, id))
			assert.Equal(t, tc.phase, d.Phase)
			// The operation sent again (a late or replayed send) never runs: the helper answers FENCED and changes nothing.
			in, err := json.Marshal(winproto.DeployInput{Locator: s.locator, ExpectSHA256: pki.Fingerprint(e.old.Cert), ChainPEM: string(e.nw.FullchainPEM),
				KeyPEM: string(e.nw.KeyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
			require.NoError(t, err)
			r := s.model.Handler()(winproto.SubIISDeploy+" --op "+id.String(), in)
			var refusal winproto.ErrorResponse
			require.NoError(t, json.Unmarshal(r.Stdout, &refusal), "%s", r.Stdout)
			assert.Equal(t, winproto.CodeFenced, refusal.Code)
			assert.Equal(t, winproto.PhaseFenced, s.phase(t, id))
			e.assertWinServes(s, e.old)
		})
	}
}

// M-5 on Windows: Alice recovers while another helper process holds helper.lock (status Active): the recovery records
// the engine's nginx.busy and decides nothing, then finishes from the journal once the lock is released.
func TestWindowsRecoveryWaitsForAnActiveHelper(t *testing.T) {
	for _, tc := range []struct {
		point  string
		status string
		want   func(e *env) pki.Leaf
	}{
		{"deploy.committed", inventory.DeployStatusSucceeded, newLeaf},
		{"deploy.bound", inventory.DeployStatusRolledBack, oldLeaf},
	} {
		t.Run(tc.point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addWinServer("iis-01")
			s.model.KillAt(tc.point)
			id := e.request(s.loc)[0]
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
			release := s.model.HoldLock()
			for range 3 {
				e.clock.Advance(inventory.RecoveryRetryInterval + time.Minute)
				_, err := e.inv.SweepDeployments(e.ctx)
				require.NoError(t, err)
				e.drain()
				d := e.deployment(id)
				require.Equal(t, inventory.DeployStateRecovering, d.State, "nothing is decided while the helper is active")
				assert.Equal(t, "nginx.busy", d.ErrorCode, "the engine's reason")
			}
			release()
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
			e.assertWinServes(s, tc.want(e))
		})
	}
}
