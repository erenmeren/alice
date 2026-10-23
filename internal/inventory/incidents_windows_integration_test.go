//go:build integration

package inventory_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/testutil/pki"
)

// R62 W3 Ruling 9 (§15 Q7): when an incident's place on a Windows server is verified (or unverified: the compromised
// certificate is out of the binding either way), the incident engine queues a windows.cleanup of that server at once,
// naming the incident, so the compromised certificate leaves the machine store without waiting for the daily run. Once
// per server and incident; a Linux server's places queue nothing.
func TestIncidentQueuesWindowsCleanup(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	h.installLicense("LIC-INCIDENT-WINDOWS", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	var old uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM certificates WHERE fingerprint_sha256 = $1", pki.Fingerprint(f.old.Cert)).Scan(&old))

	i, err := h.svc.StartIncident(h.ctx, f.admin, old, inventory.IncidentInput{})
	require.NoError(t, err)
	// The incident's place selection (insertIncidentLocations) reads a deployable place by a Unix path, so it skips an
	// http.sys binding as incident.not_deployable today (reported to the controller); the two IIS bindings are made
	// pending here as the owner, so the engine requests, follows and settles them as it does a file.
	assert.Equal(t, "skipped:"+inventory.IncidentCodeNotDeployable, locationStatus(i)[f.bound])
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE certificate_incident_locations SET status = 'pending', error_code = '' WHERE incident_id = $1
    AND location_id = ANY ($2)`, i.ID, []uuid.UUID{f.bound, f.spare})
	require.NoError(t, err)
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	deps := map[uuid.UUID]uuid.UUID{}
	for _, l := range i.Locations {
		if l.DeploymentID != nil {
			deps[l.LocationID] = *l.DeploymentID
		}
	}
	require.Contains(t, deps, f.bound)
	require.Contains(t, deps, f.spare)
	require.Contains(t, deps, f.file)
	cleanups := func() []inventory.JobRequest {
		var out []inventory.JobRequest
		for _, r := range h.jobs.requests() {
			if r.Type == inventory.JobWindowsCleanup {
				out = append(out, r)
			}
		}
		return out
	}
	require.Empty(t, cleanups(), "nothing before a place is settled")

	end := func(loc uuid.UUID, verified string) {
		_, err := h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'done', status = 'succeeded', verified = $2, finished_at = $3 WHERE id = $1`,
			deps[loc], verified, h.clock.Now())
		require.NoError(t, err)
	}
	end(f.file, "remote")
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	assert.Empty(t, cleanups(), "a Linux server's place queues nothing")

	end(f.bound, "remote")
	end(f.spare, "skipped")
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentLocationVerified, incidentLocation(t, i, f.bound).Status)
	assert.Equal(t, inventory.IncidentLocationUnverified, incidentLocation(t, i, f.spare).Status)
	got := cleanups()
	require.Len(t, got, 2, "each settled place asks; the dedupe key makes it one job")
	for _, r := range got {
		assert.Equal(t, f.win, r.TargetID)
		assert.Equal(t, map[string]string{"incident_id": i.ID.String()}, r.Payload)
		assert.Equal(t, "system", r.Kind)
		assert.Equal(t, "windows.cleanup:"+f.win.String()+":incident:"+i.ID.String(), r.DedupeKey)
	}
	assert.Equal(t, 1, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1 AND payload->>'incident_id' = $2",
		f.win, i.ID.String()))
	assert.Zero(t, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1", f.web))
}
