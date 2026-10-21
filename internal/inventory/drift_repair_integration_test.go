//go:build integration

package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// planRepairs runs the repair planner once (the licence checked first, as the running process does every minute).
func (f *driftFixture) planRepairs() inventory.DriftRepairRun {
	f.h.t.Helper()
	require.NoError(f.h.t, f.h.lic.Tick(f.h.ctx))
	run, err := f.h.svc.PlanDriftRepairs(f.h.ctx)
	require.NoError(f.h.t, err)
	return run
}

// repairs are the deployments of loc1 with trigger drift_repair, oldest first.
func (f *driftFixture) repairs() []acmeDep {
	f.h.t.Helper()
	var out []acmeDep
	for _, d := range f.deps(f.cur) {
		if d.Trigger == inventory.TriggerDriftRepair {
			out = append(out, d)
		}
	}
	return out
}

// driftAgain is another tool putting the old certificate back, seen by a probe and by a scan of the file.
func (f *driftFixture) driftAgain() {
	f.h.t.Helper()
	f.h.clock.Advance(time.Hour)
	f.scanFile(f.old)
	require.Equal(f.h.t, 1, f.record(f.served(f.oldFP)))
}

// R52 item 4, mode auto: the planner repairs only after a scan of the file newer than the last deployment, through a
// certificate.deploy_auto deployment with trigger drift_repair and its audit row, once at a time; the job judges the
// queued repair again (off when a person chose another mode, superseded when the desired certificate changed); the
// drift is mailed when no repair ended it within DriftAutoNoticeAfter; after DriftMaxRepairs repairs that all came back
// it backs off to observe with one notice; the next probe in sync ends the episode with the "repaired" notice.
func TestDriftAutoRepairAndFlapping(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	h.clock.Advance(time.Hour)
	require.Equal(t, 1, f.record(f.served(f.oldFP)))
	assert.Zero(t, h.emails(inventory.TemplateDriftDetected), "auto repairs before it tells")
	assert.Equal(t, inventory.DriftRepairRun{}, f.planRepairs(), "the file was not scanned since the deployment")

	f.scanFile(f.old)
	before := len(h.jobs.requests())
	assert.Equal(t, inventory.DriftRepairRun{Created: 1}, f.planRepairs())
	reps := f.repairs()
	require.Len(t, reps, 1)
	assert.Equal(t, f.loc1, reps[0].Location)
	reqs := h.jobs.requests()[before:]
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobCertificateDeployAuto, reqs[0].Type)
	requested := h.auditDetails("location.drift_repair_requested")
	require.Len(t, requested, 1)
	assert.Equal(t, reps[0].ID.String(), requested[0]["deployment_id"])
	assert.Equal(t, f.cur.String(), requested[0]["certificate_id"])
	assert.Equal(t, inventory.DriftRepairRun{}, f.planRepairs(), "one repair at a time")

	// The job judges the queued repair again.
	_, err := h.svc.DeploymentMaterial(h.ctx, reps[0].ID, true)
	require.NoError(t, err)
	f.setMode(inventory.DriftModeObserve)
	_, err = h.svc.DeploymentMaterial(h.ctx, reps[0].ID, true)
	assert.ErrorIs(t, err, inventory.ErrDriftRepairOff)
	f.setMode(inventory.DriftModeAuto)
	f.finish(reps[0].ID, inventory.DeployStatusSucceeded, "")
	assert.Equal(t, inventory.DriftRepairRun{}, f.planRepairs(), "repaired: nothing observed since")

	// Two more repairs that come back; the drift is now older than an hour: mailed once.
	for i := 1; i < inventory.DriftMaxRepairs; i++ {
		f.driftAgain()
		require.Equal(t, inventory.DriftRepairRun{Created: 1}, f.planRepairs(), "repair %d", i+1)
		reps = f.repairs()
		f.finish(reps[len(reps)-1].ID, inventory.DeployStatusSucceeded, "")
	}
	assert.Equal(t, 1, h.emails(inventory.TemplateDriftDetected), "no repair ended it within the hour")
	f.driftAgain()
	assert.Equal(t, inventory.DriftRepairRun{BackedOff: 1}, f.planRepairs())
	o := f.observation()
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	assert.Equal(t, inventory.BackoffFlapping, o.BackoffReason)
	require.NotNil(t, o.BackedOffAt)
	backoff := h.auditDetails("location.drift_backoff")
	require.Len(t, backoff, 1)
	assert.Equal(t, "3", backoff[0]["repairs"])
	assert.Equal(t, "24", backoff[0]["window_hours"])
	assert.Equal(t, 1, h.emails(inventory.TemplateDriftFlapping))
	assert.Equal(t, inventory.DriftRepairRun{}, f.planRepairs(), "backed off")
	assert.Len(t, f.repairs(), inventory.DriftMaxRepairs)

	// The desired certificate comes back: the episode ends, repaired automatically.
	h.clock.Advance(time.Minute)
	assert.Zero(t, f.record(f.served(f.curFP)))
	assert.Equal(t, inventory.HealthInSync, f.observation().Health)
	resolved := h.auditDetails("location.drift_resolved")
	require.Len(t, resolved, 1)
	assert.Equal(t, "true", resolved[0]["repaired_automatically"])
	assert.Equal(t, 1, h.emails(inventory.TemplateDriftRepaired))

	// Switched on again by an Administrator: the back-off is cleared.
	o = f.setMode(inventory.DriftModeAuto)
	assert.Empty(t, o.BackoffReason)
	assert.Nil(t, o.BackedOffAt)
}

// Repairs that fail: after DriftMaxRepairs failures in the window automatic repair backs off with its own notice.
func TestDriftAutoRepairBacksOffWhenRepairsFail(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	f.driftAgain()
	for i := range inventory.DriftMaxRepairs {
		require.Equal(t, inventory.DriftRepairRun{Created: 1}, f.planRepairs(), "repair %d", i+1)
		reps := f.repairs()
		f.finish(reps[len(reps)-1].ID, inventory.DeployStatusFailed, "deployment.reload_failed")
		assert.Equal(t, inventory.DriftRepairRun{}, f.planRepairs(), "repair %d: nothing observed since it ended", i+1)
		h.clock.Advance(time.Hour)
		require.Equal(t, 1, f.record(f.served(f.oldFP)), "a failed repair leaves the drift")
		if i == 1 {
			h.clock.Advance(time.Minute)
			f.scanFile(f.old) // the scan of the file is the newest observation now
		}
	}
	assert.Equal(t, inventory.DriftRepairRun{BackedOff: 1}, f.planRepairs())
	o := f.observation()
	assert.Equal(t, inventory.BackoffRepairFailing, o.BackoffReason)
	assert.Equal(t, inventory.DriftModeObserve, o.Mode)
	assert.Equal(t, 1, h.emails(inventory.TemplateDriftRepairFailing))
	assert.Zero(t, h.emails(inventory.TemplateDriftFlapping))
}

// A queued repair whose desired certificate changed (a renewal) is superseded when its job runs; an open
// key-compromise incident on the location, or a licence that refuses continuity work, keeps the planner away.
func TestDriftRepairSupersededAndHeldBack(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	f.driftAgain()
	require.Equal(t, inventory.DriftRepairRun{Created: 1}, f.planRepairs())
	queued := f.repairs()[0].ID
	h.clock.Advance(time.Minute)
	f.issue(f.acme)
	_, err := h.svc.DeploymentMaterial(h.ctx, queued, true)
	assert.ErrorIs(t, err, inventory.ErrDriftRepairSuperseded)

	// An open incident on the location: the incident decides what it gets.
	g := newDriftFixture(t, true)
	g.driftAgain()
	incident := uuid.Must(uuid.NewV7())
	_, err = g.h.db.Owner.Exec(g.h.ctx, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, started_by, created_at, updated_at)
VALUES ($1, $2, repeat('ab', 32), 'awaiting_replacement', 'not_possible', $3, $4, $4)`, incident, g.cur, g.admin.UserID, g.h.clock.Now())
	require.NoError(t, err)
	_, err = g.h.db.Owner.Exec(g.h.ctx, "INSERT INTO certificate_incident_locations (incident_id, location_id, status, updated_at) VALUES ($1, $2, 'pending', $3)",
		incident, g.loc1, g.h.clock.Now())
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftRepairRun{}, g.planRepairs())
	assert.Empty(t, g.repairs())
}

// succeed ends a deployment succeeded (as the engine would, verified remotely).
func succeed(h *harness, id uuid.UUID) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, `UPDATE deployments SET state = 'done', status = 'succeeded', result = 'committed', phase = 'committed',
verified = 'remote', finished_at = $2 WHERE id = $1`, id, h.clock.Now())
	require.NoError(h.t, err)
}

// A Key Vault binding's location (R52): the desired certificate is the binding's current version; a person's repair
// goes through the Key Vault request path of that version, and the planner's repair in mode auto carries the binding
// and the version.
func TestDriftOfAKeyVaultBinding(t *testing.T) {
	b := newBindFixture(t)
	h := b.h
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	reqs, err := h.svc.RequestKVDeployment(h.ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
		LocationIDs: []uuid.UUID{b.loc1}})
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	succeed(h, reqs[0].ID)
	h.clock.Advance(time.Minute)

	o, err := h.svc.LocationObservation(h.ctx, b.loc1)
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftSourceKeyVault, o.Source)
	require.NotNil(t, o.SourceID)
	assert.Equal(t, bind.ID, *o.SourceID)
	require.NotNil(t, o.Desired)
	assert.Equal(t, pki.Fingerprint(b.webLeaf.Cert), o.Desired.Fingerprint)
	assert.Equal(t, inventory.DriftModeObserve, o.Mode, "automatic deployment off")

	oldFP := pki.Fingerprint(b.old.Cert)
	served := func() inventory.DriftResult {
		return inventory.DriftResult{LocationID: b.loc1, At: h.clock.Now(), Reached: true, Served: oldFP, Probe: inventory.DriftProbeHelper}
	}
	n, err := h.svc.RecordDriftObservations(h.ctx, b.target1, []inventory.DriftResult{served()})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	got, err := h.svc.RepairDrift(h.ctx, b.admin, b.loc1, true)
	require.NoError(t, err)
	require.Len(t, got, 1)
	d := b.get(got[0].ID)
	require.NotNil(t, d.BindingID)
	assert.Equal(t, bind.ID, *d.BindingID)
	assert.Equal(t, ver(1), d.KVVersion)
	assert.Equal(t, "manual", d.Trigger)
	succeed(h, got[0].ID)

	// Mode auto: the planner repairs through the vault.
	require.NoError(t, h.lic.Tick(h.ctx))
	o, err = h.svc.SetDriftMode(h.ctx, b.admin, b.loc1, inventory.DriftModeAuto, true)
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftModeAuto, o.Mode)
	assert.Equal(t, inventory.DriftModeObserve, o.DefaultMode)
	h.clock.Advance(time.Hour)
	_, err = h.svc.Reconcile(h.ctx, b.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), b.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), b.old)}})
	require.NoError(t, err)
	n, err = h.svc.RecordDriftObservations(h.ctx, b.target1, []inventory.DriftResult{served()})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.NoError(t, h.lic.Tick(h.ctx))
	run, err := h.svc.PlanDriftRepairs(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftRepairRun{Created: 1}, run)
	var repair uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM deployments WHERE trigger = $1", inventory.TriggerDriftRepair).Scan(&repair))
	d = b.get(repair)
	require.NotNil(t, d.BindingID)
	assert.Equal(t, bind.ID, *d.BindingID)
	assert.Equal(t, ver(1), d.KVVersion)

	// The binding's current version held (a version seen during a licence lock): a repair never deploys it.
	succeed(h, repair)
	h.clock.Advance(time.Hour)
	n, err = h.svc.RecordDriftObservations(h.ctx, b.target1, []inventory.DriftResult{served()})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
	require.NoError(t, h.lic.Tick(h.ctx))
	run, err = h.svc.PlanDriftRepairs(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.DriftRepairRun{}, run)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM deployments WHERE trigger = $1", inventory.TriggerDriftRepair))
}

// The planner judges each location again in its own transaction and leaves it for a later run, writing nothing, when:
// the licence gate refuses continuity work (before the run, or by the time the location's transaction starts),
// someone holds the location's observation row, the mode changed meanwhile, the desired certificate cannot be deployed
// unattended (not valid yet, an incomplete chain that needs a person's confirmation) or the server is not ready. A context
// that ends stops the run with its error.
func TestDriftPlannerLeavesALocationForLater(t *testing.T) {
	f := newDriftFixture(t, true)
	h := f.h
	f.driftAgain()
	plan := func(ctx context.Context) (inventory.DriftRepairRun, error) { return h.svc.PlanDriftRepairs(ctx) }
	none := func(what string) {
		t.Helper()
		run, err := plan(h.ctx)
		require.NoError(t, err, what)
		assert.Equal(t, inventory.DriftRepairRun{}, run, what)
		assert.Empty(t, f.repairs(), what)
	}

	h.clock.Advance(4 * time.Hour) // no evaluation of the licence for longer than its gate allows
	none("the licence is not verified")
	require.NoError(t, h.lic.Tick(h.ctx))

	restore := inventory.SetDriftRepairHook(func(uuid.UUID) { h.clock.Advance(4 * time.Hour) })
	none("the licence is not verified by the location's transaction")
	restore()
	require.NoError(t, h.lic.Tick(h.ctx))

	tx, err := h.db.Owner.Begin(h.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, "SELECT 1 FROM location_observations WHERE location_id = $1 FOR UPDATE", f.loc1)
	require.NoError(t, err)
	none("someone holds the row")
	require.NoError(t, tx.Rollback(h.ctx))

	restore = inventory.SetDriftRepairHook(func(uuid.UUID) {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE location_observations SET drift_mode = 'observe' WHERE location_id = $1", f.loc1)
		require.NoError(t, err)
	})
	none("a person chose observe meanwhile")
	restore()
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE location_observations SET drift_mode = NULL WHERE location_id = $1", f.loc1)
	require.NoError(t, err)

	for _, tc := range []struct{ what, set, reset string }{
		{"the desired certificate is not valid yet", "UPDATE certificates SET not_before = not_before + interval '100 years' WHERE id = $1",
			"UPDATE certificates SET not_before = not_before - interval '100 years' WHERE id = $1"},
		{"its chain needs a confirmation", "UPDATE certificates SET chain_complete = false WHERE id = $1", "UPDATE certificates SET chain_complete = true WHERE id = $1"},
	} {
		_, err := h.db.Owner.Exec(h.ctx, tc.set, f.cur)
		require.NoError(t, err, tc.what)
		none(tc.what)
		_, err = h.db.Owner.Exec(h.ctx, tc.reset, f.cur)
		require.NoError(t, err, tc.what)
	}
	f.setTargetStatus(f.target1, "disabled")
	none("the server is not ready")
	f.setTargetStatus(f.target1, "ok")

	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	restore = inventory.SetDriftRepairHook(func(uuid.UUID) { cancel() })
	_, err = plan(ctx)
	restore()
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, f.repairs())

	assert.Equal(t, inventory.DriftRepairRun{Created: 1}, f.planRepairs(), "nothing else held it back")
}

// A drift the scan of the file found (another certificate written by someone outside Alice) while the website was not
// probed: the episode names the file as what found it and the certificate in it.
func TestDriftFoundInTheFile(t *testing.T) {
	f := newDriftFixture(t, false)
	h := f.h
	var chain string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT pem_chain FROM certificates WHERE id = $1", f.cur).Scan(&chain))
	f.scanFile(pki.Leaf{FullchainPEM: []byte(chain)})
	assert.Equal(t, inventory.HealthInSync, f.observation().Health, "the file holds the desired certificate")
	h.clock.Advance(time.Hour)
	intruder := f.ca.Issue(pki.Opts{CommonName: "intruder.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	f.scanFile(intruder)
	o := f.observation()
	require.NotNil(t, o.File)
	require.NotNil(t, o.File.ChangedOutsideAt, "a certificate Alice did not put there")
	assert.Equal(t, inventory.HealthDrifted, o.Health)

	h.clock.Advance(time.Minute)
	assert.Equal(t, 1, f.record(inventory.DriftResult{LocationID: f.loc1, At: h.clock.Now(), Skipped: true}))
	o = f.observation()
	assert.Equal(t, "file", o.DriftSource)
	assert.Equal(t, pki.Fingerprint(intruder.Cert), o.DriftFingerprint)
	mails := f.outboxParams(inventory.TemplateDriftDetected)
	require.NotEmpty(t, mails)
	assert.Equal(t, "intruder.example.test", mails[0]["observed_name"])
}
