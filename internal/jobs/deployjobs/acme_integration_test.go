//go:build integration

package deployjobs

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/acmejobs"
	"alice/internal/license/licensetest"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
)

// acmeWorld is the Phase 4 world (an emulated Nginx host serving the old certificate, the real queue, runner, nginx
// provider and deployment engine) plus the ACME side: a fake CA, a provider whose bundle completes its chains, an
// account, a DNS hook, the acme.issue / acme.cleanup handlers on the same runner, and the two ACME planners. Certificates
// are issued through the real acme.issue job and deployed through the real deployment engine: nothing here talks to the
// server except the engine.
type acmeWorld struct {
	*env
	fake     *fakeacme.Server
	operator inventory.Actor
	provider inventory.ACMEProvider
	hook     inventory.ACMEHook
	schedule jobs.Task // acme.schedule
	deploy   jobs.Task // acme.auto_deploy
	s        *server
	loc      uuid.UUID
}

func newACMEWorld(t *testing.T) *acmeWorld {
	t.Helper()
	e := newEnv(t)
	w := &acmeWorld{env: e}
	p := licensetest.Payload(e.lic.Snapshot().InstallationID, e.clock.Now(), e.clock.Now().Add(3650*24*time.Hour), 10)
	p.LicenseID = "LIC-ACME-DEPLOY"
	_, err := e.lic.Install(e.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	w.fake, err = fakeacme.New(fakeacme.Options{Now: e.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, w.fake.Start())
	t.Cleanup(w.fake.Close)
	require.NoError(t, w.fake.SetLeafLifetime(6*24*time.Hour)) // renewed two days before its end
	acmejobs.Register(e.runner, acmejobs.Deps{Inventory: e.inv, Registry: e.reg, Gate: e.gate, Clock: e.clock, Log: e.log()})
	w.schedule = acmejobs.ScheduleTask(e.inv, time.Minute, e.log())
	w.deploy = acmejobs.AutoDeployTask(e.inv, time.Minute, e.log())

	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'otto', 'otto@example.com', 'Otto Yılmaz', 'x', 'operator', $2, $2)`, id, e.clock.Now())
	require.NoError(t, err)
	w.operator = inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: "otto"}, UserID: id, Role: rbac.Operator}
	w.provider, err = e.inv.CreateACMEProvider(e.ctx, e.admin, inventory.ACMEProviderInput{Name: "Fake CA", DirectoryURL: w.fake.DirectoryURL(),
		CABundlePEM: string(w.fake.CAPEM()) + string(w.fake.IssuerRootPEM()), AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	_, err = e.inv.RegisterACMEAccount(e.ctx, e.admin, w.provider.ID, "ops@example.test", false)
	require.NoError(t, err)
	none := 0
	w.hook, err = e.inv.CreateACMEHook(e.ctx, e.admin, inventory.ACMEHookInput{Name: "fake dns", URL: w.fake.Credentials().HookURL,
		CABundlePEM: string(w.fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(w.fake.Credentials().HookSecret)),
		AllowedSuffixes: []string{"example.test"}, PropagationWaitSeconds: &none, PollTimeoutSeconds: 5})
	require.NoError(t, err)
	w.s = e.addServer("web-01", wwwSite())
	w.loc = w.s.locs[wwwCert]
	return w
}

// define creates the ACME certificate for www.example.test with automatic deployment on.
func (w *acmeWorld) define() inventory.ACMECertificate {
	w.t.Helper()
	hook := w.hook.ID
	c, err := w.inv.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: []string{wwwName},
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook, AutoDeploy: true})
	require.NoError(w.t, err)
	return c
}

func (w *acmeWorld) acmeCert(id uuid.UUID) inventory.ACMECertificate {
	w.t.Helper()
	c, err := w.inv.GetACMECertificate(w.ctx, id)
	require.NoError(w.t, err)
	return c
}

// current is the ACME certificate's current certificate and its leaf fingerprint.
func (w *acmeWorld) current(id uuid.UUID) (uuid.UUID, string) {
	w.t.Helper()
	c := w.acmeCert(id)
	require.NotNil(w.t, c.CurrentCertificateID)
	var fp string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT fingerprint_sha256 FROM certificates WHERE id = $1", *c.CurrentCertificateID).Scan(&fp))
	return *c.CurrentCertificateID, fp
}

// setClock moves the clock (the fake CA shares it) and evaluates the licence, as a running server does.
func (w *acmeWorld) setClock(at time.Time) {
	w.t.Helper()
	w.clock.Set(at)
	w.evaluate()
}

// planDeploy runs acme.auto_deploy once and returns the new deployments of cert (oldest first).
func (w *acmeWorld) planDeploy(cert uuid.UUID) []uuid.UUID {
	w.t.Helper()
	before := w.depsOf(cert)
	w.evaluate()
	require.NoError(w.t, w.deploy.Run(w.ctx))
	return append([]uuid.UUID(nil), w.depsOf(cert)[len(before):]...)
}

func (w *acmeWorld) depsOf(cert uuid.UUID) []uuid.UUID {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, "SELECT id FROM deployments WHERE certificate_id = $1 ORDER BY created_at, id", cert)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(w.t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// auditOrder is the actions of the deployment's audit rows in the order they were written.
func (w *acmeWorld) auditOrder(deployment uuid.UUID) []string {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, "SELECT action FROM audit_log WHERE object_id = $1 ORDER BY seq", deployment.String())
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		require.NoError(w.t, rows.Scan(&a))
		out = append(out, a)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// served is the leaf the website serves, by the server's state and by Alice's own TLS probe.
func (w *acmeWorld) served() (state, probe string) {
	w.t.Helper()
	probe, _, ok := w.s.emu.ProbeServed("", 443, wwwName, "ecdsa")
	require.True(w.t, ok)
	return w.s.emu.Served(443, wwwName), probe
}

func (w *acmeWorld) bindingState(acme uuid.UUID) inventory.ACMEBinding {
	w.t.Helper()
	list, err := w.inv.ListACMEBindings(w.ctx, acme)
	require.NoError(w.t, err)
	require.Len(w.t, list, 1)
	return list[0]
}

// issueFirst defines the certificate, orders it through the acme.issue job, binds the location and deploys it through
// the planner and the engine: the website serves it.
func (w *acmeWorld) issueFirst() (inventory.ACMECertificate, string) {
	w.t.Helper()
	c := w.define()
	_, err := w.inv.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(w.t, err)
	w.drain()
	cert1, fp1 := w.current(c.ID)
	_, err = w.inv.AddACMEBinding(w.ctx, w.operator, c.ID, w.loc, true)
	require.NoError(w.t, err)
	ids := w.planDeploy(cert1)
	require.Len(w.t, ids, 1)
	w.drain()
	d := w.deployment(ids[0])
	require.Equal(w.t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	return w.acmeCert(c.ID), fp1
}

// renew moves the clock to the renewal time and lets acme.schedule and the acme.issue job renew the certificate.
func (w *acmeWorld) renew(c inventory.ACMECertificate) (uuid.UUID, string) {
	w.t.Helper()
	old, _ := w.current(c.ID)
	var na time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT not_after FROM certificates WHERE id = $1", old).Scan(&na))
	w.setClock(na.Add(-2 * 24 * time.Hour))
	require.NoError(w.t, w.schedule.Run(w.ctx))
	w.drain()
	cur, fp := w.current(c.ID)
	require.NotEqual(w.t, old, cur, "renewed")
	return cur, fp
}

// The renewal of an ACME certificate is deployed by acme.auto_deploy through the engine: the deployment records, steps
// and deployment.* audit rows are the engine's, as for a person's request.
func TestACMERenewalIsDeployedByTheEngine(t *testing.T) {
	w := newACMEWorld(t)
	c, fp1 := w.issueFirst()
	state, probe := w.served()
	assert.Equal(t, fp1, state)
	assert.Equal(t, fp1, probe)
	assert.Equal(t, fp1, w.location(w.s, wwwCert).DeployedFingerprint)

	cert2, fp2 := w.renew(c)
	ids := w.planDeploy(cert2)
	require.Len(t, ids, 1)
	assert.Empty(t, w.planDeploy(cert2), "nothing twice")
	w.drain()
	d := w.deployment(ids[0])
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, inventory.TriggerACMERenewal, d.Trigger)
	assert.Nil(t, d.RequestedBy, "the planner's, not a person's")
	assert.Equal(t, fp1, d.PreviousFingerprint)
	assert.Equal(t, fp2, d.NewFingerprint)
	assert.Equal(t, []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok",
		"reload:ok", "verify:started", "verify:ok"}, stepList(d.Steps))
	assert.Equal(t, []string{"deployment.requested", "deployment.precheck_started", "deployment.started", "deployment.succeeded"}, w.auditOrder(ids[0]))
	assert.Equal(t, 1, w.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.requested' AND object_id = $1 AND actor_name = 'jobs'",
		ids[0].String()))
	state, probe = w.served()
	assert.Equal(t, fp2, state)
	assert.Equal(t, fp2, probe)
	assert.Equal(t, fp2, w.location(w.s, wwwCert).DeployedFingerprint)
	assert.Equal(t, inventory.ACMEBindingCurrent, w.bindingState(c.ID).State)
	assert.Empty(t, w.planDeploy(cert2), "deployed: nothing more")
}

// ROLLBACK PROOF (plan Task 12, Review Focus 5). The renewal's deployment fails after the files were written (nginx -t
// fails, the reload fails, or the verification still sees the old leaf because the reload did nothing): the engine
// records deployment.failed then deployment.rolled_back, the location's deployed fingerprint stays the previous
// certificate's, the website (and Alice's TLS probe) still serves the previous leaf, the ACME certificate stays issued
// (active, the renewed certificate current), the binding is marked attention, the Administrators get the engine's
// failure e-mail, and the planner does not retry within the hour.
func TestACMERenewalDeployFailureRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(w *acmeWorld)
		code   string
		step   string
	}{
		{"nginx -t fails after the write", func(w *acmeWorld) { w.s.emu.FailConfigTest(1) }, "deployment.config_test_failed", "config_test"},
		{"the reload fails", func(w *acmeWorld) { w.s.emu.FailReload(1) }, "deployment.reload_failed", "reload"},
		{"the verification sees the old leaf", func(w *acmeWorld) { w.s.emu.NoopReload(true) }, "deployment.verify_failed", "verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newACMEWorld(t)
			c, fp1 := w.issueFirst()
			cert2, fp2 := w.renew(c)
			writes := w.s.emu.DeployCount()
			tc.inject(w)
			ids := w.planDeploy(cert2)
			require.Len(t, ids, 1)
			w.drain()
			w.s.emu.NoopReload(false)
			d := w.deployment(ids[0])
			assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
			assert.Equal(t, tc.code, d.ErrorCode)
			assert.Contains(t, []string{d.FailedStep, d.CauseStep}, tc.step, "the step that failed: %s/%s", d.FailedStep, d.CauseStep)
			assert.Equal(t, writes+1, w.s.emu.DeployCount(), "the new pair was written")
			actions := w.auditOrder(ids[0])
			failed, rolled := indexOf(actions, "deployment.failed"), indexOf(actions, "deployment.rolled_back")
			require.GreaterOrEqual(t, failed, 0, "%v", actions)
			require.Greater(t, rolled, failed, "deployment.failed then deployment.rolled_back: %v", actions)
			assert.NotContains(t, actions, "deployment.succeeded")

			// The previous certificate is still what Alice deployed and what is served.
			assert.Equal(t, fp1, w.location(w.s, wwwCert).DeployedFingerprint)
			state, probe := w.served()
			assert.Equal(t, fp1, state, "the website serves the previous leaf")
			assert.Equal(t, fp1, probe, "Alice's TLS probe sees the previous leaf")
			assert.NotEqual(t, fp2, state)
			assert.Equal(t, fp1, leafOf(t, w.s.emu.NginxFile(wwwCert)), "the files are the previous pair")

			// The ACME certificate itself is fine: issued, the renewal current, no failure counted against it.
			got := w.acmeCert(c.ID)
			assert.Equal(t, inventory.ACMEStateActive, got.State)
			require.NotNil(t, got.CurrentCertificateID)
			assert.Equal(t, cert2, *got.CurrentCertificateID)
			assert.Zero(t, got.Failures)
			assert.Equal(t, 1, w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"),
				"the Administrators are told by the engine")

			// The planner marks the binding and does not retry in a tight loop.
			assert.Empty(t, w.planDeploy(cert2))
			b := w.bindingState(c.ID)
			t.Logf("evidence: status=%s error=%s failed_step=%s cause_step=%s audit=%v deployed_fingerprint=%s served=%s probe=%s previous=%s renewal=%s "+
				"acme_state=%s binding=%s/%s", d.Status, d.ErrorCode, d.FailedStep, d.CauseStep, actions, w.location(w.s, wwwCert).DeployedFingerprint[:12],
				state[:12], probe[:12], fp1[:12], fp2[:12], got.State, b.State, b.AttentionCode)
			assert.Equal(t, inventory.ACMEBindingAttention, b.State)
			assert.Equal(t, tc.code, b.AttentionCode)
			for range 5 {
				w.setClock(w.clock.Now().Add(10 * time.Minute))
				assert.Empty(t, w.planDeploy(cert2), "within the hour")
			}
			w.setClock(w.clock.Now().Add(10 * time.Minute))
			assert.Len(t, w.planDeploy(cert2), 1, "after an hour, one retry")
		})
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// Three failed deployments of the renewal (each rolled back, an hour apart) stop its automatic deployment with one audit
// row and one e-mail; the old certificate is served throughout; a person's Deploy now after the cause is gone deploys
// the renewal and clears the attention mark.
func TestACMERenewalStopsAfterThreeRolledBackDeployments(t *testing.T) {
	w := newACMEWorld(t)
	c, fp1 := w.issueFirst()
	cert2, fp2 := w.renew(c)
	for i := range 3 {
		w.s.emu.FailConfigTest(1)
		ids := w.planDeploy(cert2)
		require.Len(t, ids, 1, "attempt %d", i+1)
		w.drain()
		assert.Equal(t, inventory.DeployStatusRolledBack, w.deployment(ids[0]).Status, "attempt %d", i+1)
		state, probe := w.served()
		assert.Equal(t, fp1, state, "attempt %d", i+1)
		assert.Equal(t, fp1, probe, "attempt %d", i+1)
		w.setClock(w.clock.Now().Add(time.Hour))
	}
	assert.Empty(t, w.planDeploy(cert2))
	stopped := w.auditDetailsOf("acme.auto_deploy.stopped")
	require.Len(t, stopped, 1)
	assert.Equal(t, "3", stopped[0]["failed_count"])
	assert.Equal(t, "deployment.config_test_failed", stopped[0]["error_code"])
	assert.Equal(t, 1, w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'acme.auto_deploy_stopped'"))
	w.setClock(w.clock.Now().Add(5 * time.Hour))
	assert.Empty(t, w.planDeploy(cert2), "stopped")
	assert.Len(t, w.depsOf(cert2), 3)
	assert.Equal(t, fp1, w.location(w.s, wwwCert).DeployedFingerprint)
	assert.Equal(t, inventory.ACMEStateActive, w.acmeCert(c.ID).State)

	got, err := w.inv.DeployACMENow(w.ctx, w.operator, c.ID, inventory.ACMEDeployInput{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	w.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, w.deployment(got[0].ID).Status)
	assert.Equal(t, "manual", w.deployment(got[0].ID).Trigger)
	state, probe := w.served()
	assert.Equal(t, fp2, state)
	assert.Equal(t, fp2, probe)
	assert.Empty(t, w.planDeploy(cert2))
	assert.Equal(t, inventory.ACMEBindingCurrent, w.bindingState(c.ID).State, "the attention mark is cleared")
}

func (w *acmeWorld) auditDetailsOf(action string) []map[string]string {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, "SELECT details FROM audit_log WHERE action = $1 ORDER BY seq", action)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var d map[string]string
		require.NoError(w.t, rows.Scan(&d))
		out = append(out, d)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// A lost answer after the reload of a renewal: the recovery (ClassAlways) finishes it from the journal, also in lock;
// the planner creates nothing in lock.
func TestACMERenewalDeployRecoveredInLock(t *testing.T) {
	w := newACMEWorld(t)
	c, fp1 := w.issueFirst()
	cert2, _ := w.renew(c)
	w.s.emu.NoopReload(true)
	w.s.emu.HangupAfter(helperproto.StepReload)
	ids := w.planDeploy(cert2)
	require.Len(t, ids, 1)
	w.drain()
	require.Equal(t, inventory.DeployStateRecovering, w.deployment(ids[0]).State)
	w.gate.locked.Store(true)
	assert.Empty(t, w.planDeploy(cert2), "nothing is planned in lock")
	d := w.settle(ids[0])
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status)
	state, probe := w.served()
	assert.Equal(t, fp1, state)
	assert.Equal(t, fp1, probe)
	assert.Equal(t, fp1, w.location(w.s, wwwCert).DeployedFingerprint)
}
