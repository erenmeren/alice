//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// R48: the rollback guard of a deployment names the certificate the replaced file held (the location's at plan time,
// the recorded one once the deployment started) and is read again every time: a compromise marked after the start
// still applies, and a later discovery of the location changes nothing.
func TestRollbackGuardOfADeployment(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	id := f.request(f.admin, f.cert.ID, f.loc1)
	oldLeaf, oldKey := pki.Fingerprint(f.old.Cert), f.discovered.PublicKeySHA256

	g, err := h.svc.RollbackGuard(h.ctx, id)
	require.NoError(t, err)
	assert.True(t, g.Empty(), "nothing is forbidden yet")
	assert.False(t, g.Required || g.TargetUnknown)
	m, err := h.svc.DeploymentMaterial(h.ctx, id, false)
	require.NoError(t, err)
	assert.Equal(t, oldLeaf, m.RollbackLeafSHA256, "before the start: the location's current certificate")
	assert.Equal(t, oldKey, m.RollbackSPKISHA256)

	f.start(id)
	d := f.get(id)
	assert.Equal(t, oldLeaf, d.RollbackLeafSHA256, "recorded with the send values")
	assert.Equal(t, oldKey, d.RollbackSPKISHA256)
	started := h.auditDetails("deployment.started")
	require.Len(t, started, 1)
	assert.Equal(t, "allowed", started[0]["rollback"], "the plan-time verdict is audited")

	// The old key is marked compromised while the deployment runs, and a discovery meanwhile finds the new certificate
	// in the file: the guard still names the recorded backup.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificates SET compromised_at = now() WHERE id = $1", f.discovered.ID)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET certificate_id = $2 WHERE id = $1", f.loc1, f.cert.ID)
	require.NoError(t, err)
	g, err = h.svc.RollbackGuard(h.ctx, id)
	require.NoError(t, err)
	assert.True(t, g.TargetForbidden)
	assert.False(t, g.TargetUnknown)
	assert.True(t, g.Required)
	assert.Equal(t, []string{oldKey}, g.ForbiddenSPKI)
	assert.Equal(t, []string{oldLeaf}, g.ForbiddenLeaf, "the backup's own leaf too; other compromised certificates are covered by their key")
	m, err = h.svc.DeploymentMaterial(h.ctx, id, false)
	require.NoError(t, err)
	assert.Equal(t, g, m.Guard, "the recovery's material carries the guard as read now")
	assert.Equal(t, g, m.RollbackRequest(m.Guard).Guard)

	_, err = h.svc.RollbackGuard(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// The lists: every compromised key and every unexpired revoked certificate, the backup's own entry first, at most
// providers.MaxForbidden each; an expired revoked certificate is not listed (no client accepts it anyway).
func TestRollbackGuardLists(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	id := f.request(f.admin, f.cert.ID, f.loc1)
	// The revoked RSA certificate is valid; make the uploaded incomplete one revoked and expired.
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'superseded' WHERE id = $1", f.rsaCert.ID)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE certificates SET revoked_at = now(), revocation_reason = 'superseded', not_before = $2::timestamptz - interval '1 day',
    not_after = $2 WHERE id = $1`, f.incomplete.ID, h.clock.Now().Add(-time.Minute))
	require.NoError(t, err)
	g, err := h.svc.RollbackGuard(h.ctx, id)
	require.NoError(t, err)
	assert.False(t, g.TargetForbidden, "the location holds neither")
	assert.False(t, g.Required)
	assert.Equal(t, []string{f.rsaCert.Fingerprint}, g.ForbiddenLeaf)
	assert.Empty(t, g.ForbiddenSPKI)

	// The location's own certificate revoked (not compromised): its leaf comes first; its key is not forbidden.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificates SET revoked_at = now() + interval '1 second', revocation_reason = 'superseded' WHERE id = $1",
		f.discovered.ID)
	require.NoError(t, err)
	g, err = h.svc.RollbackGuard(h.ctx, id)
	require.NoError(t, err)
	assert.True(t, g.TargetForbidden)
	assert.True(t, g.Required)
	assert.Equal(t, []string{pki.Fingerprint(f.old.Cert), f.rsaCert.Fingerprint}, g.ForbiddenLeaf)
	assert.Empty(t, g.ForbiddenSPKI)
}

// A location an open incident replaces requires a helper that checks the guard, even when its backup is allowed; a
// location whose certificate Alice does not know has an unknown target.
func TestRollbackGuardRequiredForAnIncidentLocation(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	h.installLicense("LIC-GUARD", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	w := &acmeDeployWorld{deployFixture: f}
	w.advance()
	deps := w.deps(f.cert.ID)
	require.NotEmpty(t, deps)
	g, err := h.svc.RollbackGuard(h.ctx, deps[0].ID)
	require.NoError(t, err)
	assert.True(t, g.Required)
	assert.True(t, g.TargetForbidden, "the incident marked the file's certificate compromised")

	// The file's certificate unknown: the target is unknown, and with anything forbidden a helper must check it.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET certificate_id = NULL WHERE id = $1", f.unsupported)
	require.NoError(t, err)
	id := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'queued', 'pending', $5, '/etc/nginx/ssl/var.crt',
'/etc/nginx/ssl/var.key', $6)`, id, f.cert.ID, f.unsupported, f.target2, f.cert.Fingerprint, h.clock.Now())
	require.NoError(t, err)
	g, err = h.svc.RollbackGuard(h.ctx, id)
	require.NoError(t, err)
	assert.True(t, g.TargetUnknown)
	assert.False(t, g.TargetForbidden)
	assert.True(t, g.Required, "unknown while a key is compromised")
	assert.Equal(t, []string{old.PublicKeySHA256}, g.ForbiddenSPKI)
}

// A rollback the guard refused ends the deployment rollback_failed with deployment.rollback_forbidden, phase
// restore_forbidden: audited, and the e-mail is its own (never the rollback-failed one that names the backup to
// restore by hand).
func TestRollbackForbiddenIsRecordedWithItsOwnEmail(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	id := f.deploying(f.loc1)
	rec := inventory.RollbackOutcomeRecord(providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreForbidden,
		FailedStep: providers.StepNameRestore, CauseStep: providers.StepNameReload, Error: providers.DeployErrForbidden,
		Reason: providers.ReasonRollbackForbidden}, nil, "deployment.reload_failed")
	require.True(t, rec.Terminal)
	require.False(t, rec.RetryRollback, "a forbidden restore is never sent again")
	require.NoError(t, h.svc.RecordOutcome(h.ctx, id, rec, h.clock.Now().Add(time.Minute)))
	d := f.get(id)
	assert.Equal(t, inventory.DeployStatusRollbackFailed, d.Status)
	assert.Equal(t, providers.ReasonRollbackForbidden, d.ErrorCode)
	assert.Equal(t, providers.PhaseRestoreForbidden, d.Phase)
	assert.Equal(t, providers.StepNameRestore, d.FailedStep)
	assert.Equal(t, providers.DeployErrForbidden, d.HelperError)
	mails := f.emails()
	require.Len(t, mails, 1)
	assert.Equal(t, inventory.TemplateDeploymentRollbackForbidden, mails[0].Template)
	assert.NotContains(t, mails[0].Params, "backup_dir", "restoring the backup by hand would put the key back")
	details := h.auditDetails("deployment.rollback_failed")
	require.Len(t, details, 1)
	assert.Equal(t, providers.ReasonRollbackForbidden, details[0]["reason"])
	assert.Equal(t, providers.StepNameRestore, details[0]["failed_step"])
}

// The incident shows it: a location whose replacement ended rollback_forbidden fails with that code and the incident
// needs attention; a location whose server cannot be reached (the deployment's outcome is uncertain, in recovery) is
// never counted as replaced: it stays deploying, and nothing is revoked or completed while it does.
func TestIncidentShowsAForbiddenRollbackAndNeverCountsAnUnreachableServer(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	h.installLicense("LIC-GUARD-I", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	w := &acmeDeployWorld{deployFixture: f}
	w.advance()
	byLoc := map[uuid.UUID]uuid.UUID{}
	for _, d := range w.deps(f.cert.ID) {
		byLoc[d.Location] = d.ID
	}
	require.Contains(t, byLoc, f.loc1)
	require.Contains(t, byLoc, f.loc2)

	// loc1: the replacement failed and the guard refused to put the compromised pair back.
	f.start(byLoc[f.loc1])
	require.NoError(t, h.svc.RecordOutcome(h.ctx, byLoc[f.loc1], inventory.OutcomeRecord{Terminal: true, Finish: inventory.DeploymentFinish{
		Status: inventory.DeployStatusRollbackFailed, Result: string(providers.DeployRollbackFailed), Phase: providers.PhaseRestoreForbidden,
		FailedStep: providers.StepNameRestore, ErrorCode: providers.ReasonRollbackForbidden, Params: map[string]string{}}}, h.clock.Now()))
	// loc2: sent, then the server could not be reached: uncertain, in recovery.
	f.start(byLoc[f.loc2])
	require.NoError(t, h.svc.RecordOutcome(h.ctx, byLoc[f.loc2], inventory.OutcomeRecord{Finish: inventory.DeploymentFinish{
		Result: string(providers.DeployUncertain), ErrorCode: "ssh.unreachable", Params: map[string]string{}}}, h.clock.Now().Add(time.Minute)))
	// Every other location succeeded.
	for loc, d := range byLoc {
		if loc != f.loc1 && loc != f.loc2 {
			w.finish(d, inventory.DeployStatusSucceeded, "")
		}
	}
	for range 3 {
		w.advance()
	}
	i = w.incident(i.ID)
	st := locationStatus(i)
	assert.Equal(t, "failed:"+providers.ReasonRollbackForbidden, st[f.loc1])
	assert.Equal(t, inventory.IncidentLocationDeploying, st[f.loc2], "an unreachable server is never counted as replaced")
	for _, l := range i.Locations {
		assert.Equal(t, l.LocationID == f.loc2, l.OutcomeUncertain, "only the place in recovery is uncertain")
		if l.LocationID == f.loc2 {
			assert.Equal(t, "ssh.unreachable", l.UncertainCode)
		}
	}
	assert.Equal(t, inventory.IncidentDeploying, i.State, "waits for the uncertain location")
	assert.Nil(t, i.FinishedAt)

	// The recovery gives up (outcome unknown): failed, never verified; the incident needs a person.
	require.NoError(t, h.svc.FinishDeployment(h.ctx, byLoc[f.loc2], inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		ErrorCode: "deployment.outcome_unknown"}))
	w.advance()
	i = w.incident(i.ID)
	st = locationStatus(i)
	assert.Equal(t, "failed:deployment.outcome_unknown", st[f.loc2])
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentCodeDeploymentsFailed, i.AttentionCode)
}
