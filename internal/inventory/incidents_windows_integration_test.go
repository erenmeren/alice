//go:build integration

package inventory_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
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

	// The impact view and the incident's places use a deployment request's rule: the IIS bindings are deployable places,
	// a binding with a key problem and the WinRM binding are not.
	impact, err := h.svc.CertificateImpact(h.ctx, old)
	require.NoError(t, err)
	deployable := map[uuid.UUID]bool{}
	for _, l := range impact.Locations {
		deployable[l.LocationID] = l.Deployable
	}
	assert.Equal(t, map[uuid.UUID]bool{f.bound: true, f.spare: true, f.file: true, f.foreign: false, f.keyProb: false}, deployable,
		"the CCS binding names no certificate, so it is no place of it")

	i, err := h.svc.StartIncident(h.ctx, f.admin, old, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, map[uuid.UUID]string{f.bound: "pending", f.spare: "pending", f.file: "pending",
		f.foreign: "skipped:" + inventory.IncidentCodeNotDeployable, f.keyProb: "skipped:" + inventory.IncidentCodeNotDeployable,
	}, locationStatus(i), "the IIS bindings are places Alice replaces")
	cleanups := func() map[string]inventory.JobRequest { // by dedupe key
		out := map[string]inventory.JobRequest{}
		for _, r := range h.jobs.requests() {
			if r.Type == inventory.JobWindowsCleanup {
				out[r.DedupeKey] = r
			}
		}
		return out
	}
	key := func(loc uuid.UUID) string {
		return "windows.cleanup:" + f.win.String() + ":incident:" + i.ID.String() + ":" + loc.String()
	}
	assert.ElementsMatch(t, []string{key(f.foreign), key(f.keyProb)}, keysOf(cleanups()), "a place skipped at the start has settled")

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
	require.Len(t, cleanups(), 2, "nothing more before a requested place is settled")

	end := func(loc uuid.UUID, status, verified string) {
		_, err := h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'done', status = $2, verified = $3, finished_at = $4 WHERE id = $1`,
			deps[loc], status, verified, h.clock.Now())
		require.NoError(t, err)
	}
	advance := func() {
		_, err := h.svc.AdvanceIncidents(h.ctx)
		require.NoError(t, err)
	}
	end(f.file, inventory.DeployStatusSucceeded, "remote")
	advance()
	assert.Len(t, cleanups(), 2, "a Linux server's place queues nothing")

	// The job of a place that settles while another place of the server is still deploying: the compromised certificate
	// may still be bound there, so its report waits (no false alarm).
	plan := providers.CleanupPlan{Watched: []providers.CleanupWatched{{Store: "My", SHA1: thumbprint(f.old), SHA256: derSHA(f.old),
		State: providers.WatchKept, Reason: "bound"}}}
	end(f.bound, inventory.DeployStatusSucceeded, "remote")
	advance()
	require.Contains(t, cleanups(), key(f.bound))
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &i.ID, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Zero(t, h.emails(inventory.TemplateWindowsCompromisedInStore), "spare (8443) is still deploying: no report")

	// The last place settles (failed: the certificate stays bound there): its own job is queued, and it reports once.
	end(f.spare, inventory.DeployStatusFailed, "")
	advance()
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentLocationVerified, incidentLocation(t, i, f.bound).Status)
	assert.Equal(t, inventory.IncidentLocationFailed, incidentLocation(t, i, f.spare).Status)
	got := cleanups()
	assert.ElementsMatch(t, []string{key(f.foreign), key(f.keyProb), key(f.bound), key(f.spare)}, keysOf(got),
		"one job per settled place, so a job running for an earlier place never absorbs the last one")
	for _, r := range got {
		assert.Equal(t, f.win, r.TargetID)
		assert.Equal(t, map[string]string{"incident_id": i.ID.String()}, r.Payload)
		assert.Equal(t, "system", r.Kind)
	}
	assert.Equal(t, 4, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1 AND payload->>'incident_id' = $2",
		f.win, i.ID.String()))
	assert.Zero(t, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup' AND target_id = $1", f.web))
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &i.ID, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	n := h.emails(inventory.TemplateWindowsCompromisedInStore)
	assert.Positive(t, n, "every place settled and the certificate is still in the store: reported")
	require.NoError(t, h.svc.RecordCleanup(h.ctx, f.win, &i.ID, plan, inventory.CleanupDecision{}, providers.CleanupApplyResult{}))
	assert.Equal(t, n, h.emails(inventory.TemplateWindowsCompromisedInStore), "once")
}

func keysOf(m map[string]inventory.JobRequest) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Ruling 9 as the schedule (Ruling 13): a server without the cleanup capability gets no incident cleanup either.
func TestIncidentCleanupNeedsTheCapability(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	h.installLicense("LIC-INCIDENT-WINDOWS-CAP", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	var old uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM certificates WHERE fingerprint_sha256 = $1", pki.Fingerprint(f.old.Cert)).Scan(&old))
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = array_remove(capabilities, 'cleanup_certificates') WHERE id = $1", f.win)
	require.NoError(t, err)

	i, err := h.svc.StartIncident(h.ctx, f.admin, old, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	dep := incidentLocation(t, i, f.bound).DeploymentID
	require.NotNil(t, dep)
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'done', status = 'succeeded', verified = 'remote', finished_at = $2 WHERE id = $1`,
		*dep, h.clock.Now())
	require.NoError(t, err)
	_, err = h.svc.AdvanceIncidents(h.ctx)
	require.NoError(t, err)
	i, err = h.svc.GetIncident(h.ctx, i.ID)
	require.NoError(t, err)
	require.Equal(t, inventory.IncidentLocationVerified, incidentLocation(t, i, f.bound).Status)
	assert.Zero(t, h.count("SELECT count(*) FROM jobs WHERE type = 'windows.cleanup'"), "no capability, no cleanup job")
}
