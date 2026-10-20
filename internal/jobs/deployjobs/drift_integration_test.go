//go:build integration

package deployjobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/driftjobs"
	"alice/internal/testutil/pki"
)

// driftWorld is the ACME world (an emulated Nginx host, the real queue, runner, nginx provider and deployment engine, a
// fake CA) with the drift work on the same runner: the drift.observe handler and the drift.schedule and drift.repair
// tasks. The ACME certificate is issued and deployed by the planner and the engine (C2); the certificate the server
// served before Alice (e.old, C1) is what another tool puts back.
type driftWorld struct {
	*acmeWorld
	schedule, repair jobs.Task
	acme             inventory.ACMECertificate
	c2               string
}

func newDriftWorld(t *testing.T) *driftWorld {
	t.Helper()
	w := newACMEWorld(t)
	driftjobs.Register(w.runner, driftjobs.Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: w.log()})
	d := &driftWorld{acmeWorld: w, schedule: driftjobs.ScheduleTask(w.inv, time.Minute, w.log()),
		repair: driftjobs.RepairTask(w.inv, time.Minute, w.log())}
	d.acme, d.c2 = w.issueFirst()
	return d
}

// putBack is another tool: it writes the old pair over Alice's and reloads Nginx.
func (d *driftWorld) putBack() {
	d.t.Helper()
	d.s.emu.SetNginxFile(wwwCert, d.old.FullchainPEM)
	d.s.emu.SetNginxFile(wwwKey, d.old.KeyPEM)
	require.NoError(d.t, d.s.emu.ReloadNginx())
}

// observe moves the clock past the observation interval and runs drift.schedule and the observation job it queued.
func (d *driftWorld) observe() inventory.LocationObservation {
	d.t.Helper()
	d.clock.Advance(inventory.DriftObserveInterval + time.Hour)
	d.evaluate()
	require.NoError(d.t, d.schedule.Run(d.ctx))
	d.drain()
	return d.observation()
}

func (d *driftWorld) observation() inventory.LocationObservation {
	d.t.Helper()
	o, err := d.inv.LocationObservation(d.ctx, d.loc)
	require.NoError(d.t, err)
	return o
}

// repairNow runs drift.repair and the jobs it queued, and returns the deployments it created.
func (d *driftWorld) repairNow() []string {
	d.t.Helper()
	before := d.count("SELECT count(*) FROM deployments WHERE trigger = 'drift_repair'")
	d.evaluate()
	require.NoError(d.t, d.repair.Run(d.ctx))
	d.drain()
	rows, err := d.db.Owner.Query(d.ctx, "SELECT status FROM deployments WHERE trigger = 'drift_repair' ORDER BY created_at OFFSET $1", before)
	require.NoError(d.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(d.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(d.t, rows.Err())
	return out
}

func (d *driftWorld) setMode(mode string) {
	d.t.Helper()
	_, err := d.inv.SetDriftMode(d.ctx, d.admin, d.loc, mode, true)
	require.NoError(d.t, err)
}

func (d *driftWorld) mails(template string) int {
	return d.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", template)
}

// ACCEPTANCE (R52). Alice deployed C2; another tool puts C1 back on the server. The reconcile finds the location
// drifted from both the file and the website, although the last deployment succeeded: with mode observe nothing is
// deployed and the Administrators get one notice.
func TestDriftObservedIsReportedAndNotRepaired(t *testing.T) {
	d := newDriftWorld(t)
	d.setMode(inventory.DriftModeObserve)
	o := d.observe()
	require.Equal(t, inventory.HealthInSync, o.Health, "C2 is served")
	require.NotNil(t, o.TLS)
	assert.Equal(t, d.c2, o.TLS.Fingerprint)
	assert.Equal(t, inventory.DriftProbeAlice, o.TLS.Probe)
	require.NotNil(t, o.File)
	assert.Equal(t, d.c2, o.File.Fingerprint)

	d.putBack()
	deployments := d.count("SELECT count(*) FROM deployments")
	o = d.observe()
	c1 := pki.Fingerprint(d.old.Cert)
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, c1, o.TLS.Fingerprint, "the website serves the old certificate")
	assert.Equal(t, c1, o.File.Fingerprint, "the file holds it")
	require.NotNil(t, o.LastDeployment)
	assert.Equal(t, d.c2, o.LastDeployment.Fingerprint, "what Alice last deployed is kept apart")
	require.NotNil(t, o.DriftSince)
	assert.Equal(t, "tls", o.DriftSource)
	assert.Equal(t, c1, o.DriftFingerprint)
	assert.Equal(t, inventory.ACMEBindingDrifted, d.bindingState(d.acme.ID).State, "a past success no longer makes the binding current")

	assert.Empty(t, d.repairNow(), "observe never repairs")
	assert.Equal(t, deployments, d.count("SELECT count(*) FROM deployments"))
	assert.Equal(t, 1, d.mails(inventory.TemplateDriftDetected))
	assert.Equal(t, 1, d.count("SELECT count(*) FROM alerts WHERE kind = 'location_drift' AND object_id = $1", d.loc))
	assert.Equal(t, 1, d.audits("location.drift_detected"))

	o = d.observe()
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, 1, d.mails(inventory.TemplateDriftDetected), "one notice per drift")
	assert.Equal(t, c1, leafServed(d))
}

// ACCEPTANCE (R52). In mode auto the repair planner deploys C2 again through the deployment engine (a
// certificate.deploy_auto job, trigger drift_repair, the engine's checks and steps); after the next observation the
// location is in sync and the Administrators learn that it was repaired.
func TestDriftAutoIsRepairedByTheEngine(t *testing.T) {
	d := newDriftWorld(t)
	o := d.observe()
	require.Equal(t, inventory.DriftModeAuto, o.Mode, "automatic deployment is on: the default repairs")
	require.Empty(t, o.ModeSetting)
	d.putBack()
	o = d.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Zero(t, d.mails(inventory.TemplateDriftDetected), "auto repairs before it tells")

	assert.Equal(t, []string{inventory.DeployStatusSucceeded}, d.repairNow())
	var trigger, job string
	require.NoError(t, d.db.Owner.QueryRow(d.ctx, `SELECT d.trigger, j.type FROM deployments d JOIN jobs j ON j.id = d.job_id
WHERE d.trigger = 'drift_repair'`).Scan(&trigger, &job))
	assert.Equal(t, inventory.JobCertificateDeployAuto, job, "continuity work, as an automatic deployment")
	assert.Equal(t, d.c2, leafServed(d), "C2 is back")

	o = d.observe()
	assert.Equal(t, inventory.HealthInSync, o.Health)
	assert.Nil(t, o.DriftSince, "the drift ended")
	assert.Equal(t, d.c2, o.TLS.Fingerprint)
	assert.Equal(t, 1, d.mails(inventory.TemplateDriftRepaired))
	assert.Equal(t, 1, d.audits("location.drift_resolved"))
	assert.Empty(t, d.repairNow(), "nothing more to repair")
}

// ACCEPTANCE (R52). Another tool keeps putting C1 back: after DriftMaxRepairs repairs within DriftRepairWindow that all
// came back, automatic repair backs off to observe with one notice.
func TestDriftAutoBacksOffWhenAnotherToolKeepsChangingTheFile(t *testing.T) {
	d := newDriftWorld(t)
	for i := range inventory.DriftMaxRepairs {
		d.putBack()
		o := d.observe()
		require.Equal(t, inventory.HealthDrifted, o.Health, "round %d", i)
		require.Equal(t, []string{inventory.DeployStatusSucceeded}, d.repairNow(), "round %d", i)
	}
	d.putBack()
	o := d.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Empty(t, d.repairNow(), "backed off: no fourth repair")
	o = d.observation()
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	assert.Equal(t, inventory.BackoffFlapping, o.BackoffReason)
	assert.NotNil(t, o.BackedOffAt)
	assert.Equal(t, 1, d.mails(inventory.TemplateDriftFlapping))
	assert.Equal(t, 1, d.audits("location.drift_backoff"))
	assert.Equal(t, pki.Fingerprint(d.old.Cert), leafServed(d), "the other tool's certificate stays")

	// An Administrator switches it on again: the back-off is cleared and the next drift is repaired.
	d.setMode(inventory.DriftModeAuto)
	o = d.observation()
	assert.Empty(t, o.BackoffReason)
	assert.Equal(t, inventory.DriftModeAuto, o.Mode)
}

// A queued repair is judged again when its job runs: a person who chose observe meanwhile stops it before anything is
// sent (deployment.drift_repair_off), and the server keeps what it has.
func TestDriftRepairIsJudgedAgainBeforeItSends(t *testing.T) {
	d := newDriftWorld(t)
	d.putBack()
	require.Equal(t, inventory.HealthDrifted, d.observe().Health)
	d.evaluate()
	require.NoError(t, d.repair.Run(d.ctx))
	d.setMode(inventory.DriftModeObserve)
	writes := d.s.emu.DeployCount()
	d.drain()
	var status, code string
	require.NoError(t, d.db.Owner.QueryRow(d.ctx, "SELECT status, error_code FROM deployments WHERE trigger = 'drift_repair'").Scan(&status, &code))
	assert.Equal(t, inventory.DeployStatusFailed, status)
	assert.Equal(t, inventory.ReasonDriftRepairOff, code)
	assert.Equal(t, writes, d.s.emu.DeployCount(), "nothing was sent")
	assert.Equal(t, pki.Fingerprint(d.old.Cert), leafServed(d))
}

// Switching automatic repair on is an Administrator's act with a fresh step-up, like switching automatic deployment on.
func TestDriftModeAutoNeedsAnAdministrator(t *testing.T) {
	d := newDriftWorld(t)
	d.setMode(inventory.DriftModeObserve)
	_, err := d.inv.SetDriftMode(d.ctx, d.operator, d.loc, inventory.DriftModeAuto, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired)
	_, err = d.inv.SetDriftMode(d.ctx, d.admin, d.loc, inventory.DriftModeAuto, false)
	assert.ErrorIs(t, err, inventory.ErrAutoDeployNeedsStepUp)
	_, err = d.inv.SetDriftMode(d.ctx, d.operator, d.loc, inventory.DriftModeApprove, false)
	assert.NoError(t, err, "observe and approve change nothing on a server")
}

// Mode approve: the drift is told with the repair prepared, and a person's one action repairs it (Deploy now of the
// current certificate to that location: a person's deployment, with its checks).
func TestDriftApproveIsRepairedByOneAction(t *testing.T) {
	d := newDriftWorld(t)
	d.setMode(inventory.DriftModeApprove)
	d.putBack()
	o := d.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	assert.Equal(t, 1, d.mails(inventory.TemplateDriftRepairReady))
	assert.Empty(t, d.repairNow(), "approve waits for a person")
	got, err := d.inv.RepairDrift(d.ctx, d.operator, d.loc, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	d.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, d.deployment(got[0].ID).Status)
	assert.Equal(t, "manual", d.deployment(got[0].ID).Trigger)
	assert.Equal(t, d.c2, leafServed(d))
	_, err = d.inv.RepairDrift(d.ctx, d.operator, d.loc, false)
	assert.ErrorIs(t, err, inventory.ErrDriftNotDrifted, "in sync after the deployment")
}

// leafServed is the leaf the emulated website serves for www.
func leafServed(d *driftWorld) string {
	state, _ := d.served()
	return state
}
