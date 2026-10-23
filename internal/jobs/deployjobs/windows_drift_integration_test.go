//go:build integration

package deployjobs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// R62 W3 (Rulings 14-16): drift of an IIS binding through the real job engine against the emulated Windows server. The
// drift engine is R52's, unchanged: drift.schedule queues drift.observe (the scan of the binding and the TLS probe),
// drift.repair deploys through the deployment engine and the Windows provider. Mirror of drift_integration_test.go.

// ACCEPTANCE item 1. Alice deployed C2 to the binding; another tool binds C1 again. The binding and the website both
// show C1: the location is drifted with cause binding_repointed and the Administrators get the Windows text once; mode
// observe deploys nothing.
func TestWindowsDriftObservedIsReported(t *testing.T) {
	w := newWinDriftWorld(t)
	w.setMode(inventory.DriftModeObserve)
	o := w.observe()
	require.Equal(t, inventory.HealthInSync, o.Health, "C2 is bound and served")
	require.NotNil(t, o.TLS)
	assert.Equal(t, w.c2, o.TLS.Fingerprint)
	require.NotNil(t, o.File)
	assert.Equal(t, w.c2, o.File.Fingerprint)
	assert.Empty(t, o.Cause)

	w.repoint(w.win.oldSHA1)
	deployments := w.count("SELECT count(*) FROM deployments")
	o = w.observe()
	c1 := pki.Fingerprint(w.old.Cert)
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, inventory.DriftCauseRepointed, o.Cause)
	assert.False(t, o.AutoCertRebind)
	require.NotNil(t, o.TLS)
	assert.Equal(t, c1, o.TLS.Fingerprint, "the website serves C1")
	require.NotNil(t, o.File)
	assert.Equal(t, c1, o.File.Fingerprint, "the binding names C1")
	require.NotNil(t, o.LastDeployment)
	assert.Equal(t, w.c2, o.LastDeployment.Fingerprint, "what Alice last deployed is kept apart")
	require.NotNil(t, o.DriftSince)
	assert.Equal(t, "tls", o.DriftSource)
	assert.Equal(t, c1, o.DriftFingerprint)

	assert.Empty(t, w.repairNow(), "observe never repairs")
	assert.Equal(t, deployments, w.count("SELECT count(*) FROM deployments"))
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftDetectedWindows))
	assert.Zero(t, w.mails(inventory.TemplateDriftDetected), "a binding is never told in a file's words")
	var path string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT params->>'cert_path' FROM notifications_outbox WHERE template_key = $1",
		inventory.TemplateDriftDetectedWindows).Scan(&path))
	assert.Equal(t, winText, path)

	o = w.observe()
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftDetectedWindows), "one notice per drift")
	assert.Equal(t, w.win.oldSHA1, w.win.bound())
}

// In mode auto drift.repair deploys C2 again through the engine and the Windows provider (trigger drift_repair, a
// certificate.deploy_auto job): the binding names C2 again, the next observation is in sync and the Windows text of the
// repair goes out.
func TestWindowsDriftAutoIsRepaired(t *testing.T) {
	w := newWinDriftWorld(t)
	o := w.observe()
	require.Equal(t, inventory.DriftModeAuto, o.Mode, "automatic deployment is on: the default repairs")
	w.repoint(w.win.oldSHA1)
	o = w.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Zero(t, w.mails(inventory.TemplateDriftDetectedWindows), "auto repairs before it tells")

	deploys := w.win.sent(winproto.SubIISDeploy)
	assert.Equal(t, []string{inventory.DeployStatusSucceeded}, w.repairNow())
	var trigger, job string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT d.trigger, j.type FROM deployments d JOIN jobs j ON j.id = d.job_id
WHERE d.trigger = 'drift_repair'`).Scan(&trigger, &job))
	assert.Equal(t, inventory.TriggerDriftRepair, trigger)
	assert.Equal(t, inventory.JobCertificateDeployAuto, job)
	assert.Equal(t, deploys+1, w.win.sent(winproto.SubIISDeploy), "through the Windows provider")
	assert.Equal(t, w.c2SHA1, w.win.bound(), "the binding names C2 again")
	assert.Equal(t, w.c2, w.win.served())

	o = w.observe()
	assert.Equal(t, inventory.HealthInSync, o.Health)
	assert.Nil(t, o.DriftSince, "the drift ended")
	assert.Empty(t, o.Cause)
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftRepairedWindows))
	assert.Zero(t, w.mails(inventory.TemplateDriftRepaired))
	assert.Empty(t, w.repairNow(), "nothing more to repair")
}

// Another tool binds C1 again after each repair: after DriftMaxRepairs repairs that all came back, automatic repair
// backs off to observe with the Windows text, once.
func TestWindowsDriftFlappingBacksOff(t *testing.T) {
	w := newWinDriftWorld(t)
	for i := range inventory.DriftMaxRepairs {
		w.repoint(w.win.oldSHA1)
		require.Equal(t, inventory.HealthDrifted, w.observe().Health, "round %d", i)
		require.Equal(t, []string{inventory.DeployStatusSucceeded}, w.repairNow(), "round %d", i)
		require.Equal(t, w.c2SHA1, w.win.bound(), "round %d", i)
	}
	w.repoint(w.win.oldSHA1)
	require.Equal(t, inventory.HealthDrifted, w.observe().Health)
	assert.Empty(t, w.repairNow(), "backed off: no fourth repair")
	o := w.observation()
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	assert.Equal(t, inventory.BackoffFlapping, o.BackoffReason)
	assert.NotNil(t, o.BackedOffAt)
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftFlappingWindows))
	assert.Zero(t, w.mails(inventory.TemplateDriftFlapping))
	assert.Equal(t, w.win.oldSHA1, w.win.bound(), "the other tool's certificate stays")
	w.observe()
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftFlappingWindows), "once")
}

// Review Focus 4. Someone removes the bound certificate (and its key) from the store: the binding is drifted with cause
// cert_removed, and no repair deployment is made however often drift.repair runs (a deployment cannot fix a store
// outside Alice), so nothing is counted and nothing backs off; in mode auto the Administrators are told after
// DriftAutoNoticeAfter, once, in the text of the cause.
func TestWindowsDriftCertRemovedIsReportedNotRepaired(t *testing.T) {
	w := newWinDriftWorld(t)
	require.Equal(t, inventory.HealthInSync, w.observe().Health)
	w.win.model.RemoveCertificate("My", w.c2SHA1)
	o := w.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, inventory.DriftCauseCertRemoved, o.Cause)
	assert.Equal(t, inventory.DriftModeAuto, o.Mode)

	deployments, deploys := w.count("SELECT count(*) FROM deployments"), w.win.sent(winproto.SubIISDeploy)
	for i := range inventory.DriftMaxRepairs + 1 {
		assert.Empty(t, w.repairNow(), "run %d: never repaired", i)
		o = w.observe()
		assert.Equal(t, inventory.HealthDrifted, o.Health, "run %d", i)
		assert.Equal(t, inventory.DriftCauseCertRemoved, o.Cause, "run %d", i)
	}
	assert.Equal(t, deployments, w.count("SELECT count(*) FROM deployments"), "no repair deployment")
	assert.Zero(t, w.count("SELECT count(*) FROM deployments WHERE trigger = 'drift_repair'"))
	assert.Equal(t, deploys, w.win.sent(winproto.SubIISDeploy), "nothing sent to the server")
	assert.Equal(t, inventory.DriftModeAuto, o.Mode, "no back-off")
	assert.Empty(t, o.BackoffReason)
	assert.Nil(t, o.BackedOffAt)
	require.NotNil(t, o.DriftSince)
	assert.False(t, w.clock.Now().Before(o.DriftSince.Add(inventory.DriftAutoNoticeAfter)), "the auto-mode notice is due")
	assert.Equal(t, 1, w.mails(inventory.TemplateDriftDetectedWindowsCertRemoved), "told once, in the text of its cause")
	assert.Zero(t, w.mails(inventory.TemplateDriftDetectedWindows))
	assert.Zero(t, w.mails(inventory.TemplateDriftFlappingWindows))
	assert.Zero(t, w.mails(inventory.TemplateDriftRepairFailingWindows))
	assert.Zero(t, w.audits("location.drift_backoff"))
}

// Design §6.2 item 4: a server whose IIS AutoCertRebind task is on (the scan's warning win_autocertrebind) gets the
// AutoCertRebind sentence with its drift e-mail (param windows_note).
func TestWindowsDriftAutoCertRebind(t *testing.T) {
	w := newWinDriftWorld(t)
	w.setMode(inventory.DriftModeObserve)
	w.win.model.SetIIS(winproto.IISFacts{Installed: true, Version: "10.0", AutoCertRebind: true})
	w.repoint(w.win.oldSHA1)
	o := w.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.True(t, o.AutoCertRebind)
	var note string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT coalesce(params->>'windows_note', '') FROM notifications_outbox WHERE template_key = $1",
		inventory.TemplateDriftDetectedWindows).Scan(&note))
	assert.Equal(t, "autocertrebind", note)
}
