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
			e := newEnv(t)
			winjobs.Register(e.runner, winjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
			s := e.addWinServer("iis-01")
			e.evaluate()
			oldCert, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(e.old.FullchainPEM),
				PrivateKeyPEM: string(e.old.KeyPEM)})
			require.NoError(t, err)
			require.Equal(t, pki.Fingerprint(e.old.Cert), oldCert.Fingerprint)
			nw := e.upload()

			i, err := e.inv.StartIncident(e.ctx, e.admin, oldCert.ID, inventory.IncidentInput{})
			require.NoError(t, err)
			require.Len(t, i.Locations, 1)
			assert.Equal(t, inventory.IncidentLocationPending, i.Locations[0].Status, "the binding is a place Alice replaces")
			_, err = e.inv.ChooseIncidentReplacement(e.ctx, e.admin, i.ID, nw.ID)
			require.NoError(t, err)
			_, err = e.inv.AdvanceIncidents(e.ctx)
			require.NoError(t, err)
			e.drain()
			if tc.gone {
				s.model.RemoveCertificate("My", s.oldSHA1)
			}
			_, err = e.inv.AdvanceIncidents(e.ctx)
			require.NoError(t, err)

			i, err = e.inv.GetIncident(e.ctx, i.ID)
			require.NoError(t, err)
			require.Len(t, i.Locations, 1)
			l := i.Locations[0]
			require.Equal(t, inventory.IncidentLocationVerified, l.Status, "%s", l.ErrorCode)
			require.NotNil(t, l.DeploymentID)
			assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(*l.DeploymentID).Status)
			e.assertWinServes(s, e.nw)
			e.drain() // the cleanup job
			assert.Equal(t, 1, e.count(`SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1 AND payload->>'incident_id' = $2
    AND status = 'succeeded'`, s.target, i.ID.String()), "the server's cleanup ran with the incident")
			assert.Equal(t, tc.notices, e.count(`SELECT count(*) FROM notifications_outbox WHERE template_key = $1 AND params->>'thumbprint' = $2`,
				inventory.TemplateWindowsCompromisedInStore, s.oldSHA1))
		})
	}
}
