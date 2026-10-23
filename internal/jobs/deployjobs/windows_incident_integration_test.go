//go:build integration

package deployjobs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs/winjobs"
	"alice/internal/testutil/pki"
)

// newWinCleanupEnv is the world of the Windows incident and cleanup tests: the stack with the windows.cleanup handler on
// the runner and one emulated Windows server whose binding serves e.old (imported by someone else, not Alice), the
// helper's clock set to Alice's.
func newWinCleanupEnv(t *testing.T) (*env, *winServer) {
	t.Helper()
	e := newEnv(t)
	winjobs.Register(e.runner, winjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
	s := e.addWinServer("iis-01")
	s.model.SetNow(e.clock.Now())
	e.evaluate()
	return e, s
}

// windowsIncident runs a key-compromise incident of the compromised certificate, which the server's binding holds,
// through the incident engine and the real deployment engine: the binding is a pending place, the replacement is
// chosen, the place's deployment runs over SSH and is verified (between runs after its job, before the place is judged),
// the place is verified, and the server's cleanup that the incident queued runs. It returns the incident as it ended.
func (e *env) windowsIncident(s *winServer, compromised, replacement inventory.Certificate, between func()) inventory.Incident {
	e.t.Helper()
	i, err := e.inv.StartIncident(e.ctx, e.admin, compromised.ID, inventory.IncidentInput{})
	require.NoError(e.t, err)
	require.Len(e.t, i.Locations, 1)
	assert.Equal(e.t, inventory.IncidentLocationPending, i.Locations[0].Status, "the binding is a place Alice replaces")
	_, err = e.inv.ChooseIncidentReplacement(e.ctx, e.admin, i.ID, replacement.ID)
	require.NoError(e.t, err)
	_, err = e.inv.AdvanceIncidents(e.ctx)
	require.NoError(e.t, err)
	e.drain()
	if between != nil {
		between()
	}
	_, err = e.inv.AdvanceIncidents(e.ctx)
	require.NoError(e.t, err)

	i, err = e.inv.GetIncident(e.ctx, i.ID)
	require.NoError(e.t, err)
	require.Len(e.t, i.Locations, 1)
	l := i.Locations[0]
	require.Equal(e.t, inventory.IncidentLocationVerified, l.Status, "%s", l.ErrorCode)
	require.NotNil(e.t, l.DeploymentID)
	assert.Equal(e.t, inventory.DeployStatusSucceeded, e.deployment(*l.DeploymentID).Status)
	e.drain() // the cleanup job
	assert.Equal(e.t, 1, e.count(`SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1 AND payload->>'incident_id' = $2
    AND status = 'succeeded'`, s.target, i.ID.String()), "the server's cleanup ran with the incident")
	return i
}

// R62 W3 Ruling 9 (§15 Q7): a key-compromise incident replaces the certificate of an IIS binding through the real
// deployment engine on the emulated Windows server, as it does a file: the binding is a pending place, its deployment is
// requested, runs over SSH and is verified, the place is verified, and the server's certificate cleanup runs at once
// with the incident. The compromised certificate was not imported by Alice, so the helper keeps it: with every place of
// the server settled the job reports it once; when it is gone from the store meanwhile, nothing is reported.
func TestWindowsIncidentReachesVerified(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gone    bool
		notices int
	}{
		{"still in the store", false, 1},
		{"gone from the store", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s := newWinCleanupEnv(t)
			oldCert, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(e.old.FullchainPEM),
				PrivateKeyPEM: string(e.old.KeyPEM)})
			require.NoError(t, err)
			require.Equal(t, pki.Fingerprint(e.old.Cert), oldCert.Fingerprint)
			nw := e.upload()

			i := e.windowsIncident(s, oldCert, nw, func() {
				if tc.gone {
					s.model.RemoveCertificate("My", s.oldSHA1)
				}
			})
			e.assertWinServes(s, e.nw)
			assert.Equal(t, tc.notices, e.count(`SELECT count(*) FROM notifications_outbox WHERE template_key = $1 AND params->>'thumbprint' = $2
    AND params->>'incident_id' = $3`, inventory.TemplateWindowsCompromisedInStore, s.oldSHA1, i.ID.String()))
		})
	}
}
