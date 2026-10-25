//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
)

// svcWith is the harness's inventory with another licence gate.
func (h *harness) svcWith(gate inventory.LicenseGate) *inventory.Service {
	return inventory.New(inventory.Config{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, License: gate,
		Registry: h.svc.Registry(), Jobs: h.jobs, Notifier: notify.ServiceNotifier{Clock: h.clock}})
}

// setPolicy stores doc as the service's next policy version (the owner writes what services.SetPolicy writes) and
// answers the version.
func (h *harness) setPolicy(service uuid.UUID, doc string) int {
	h.t.Helper()
	var v int
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, "UPDATE services SET policy_version = policy_version + 1 WHERE id = $1 RETURNING policy_version",
		service).Scan(&v))
	_, err := h.db.Owner.Exec(h.ctx, "INSERT INTO service_policies (service_id, version, body, created_at) VALUES ($1, $2, $3, now())", service, v, doc)
	require.NoError(h.t, err)
	return v
}

const canaryOn = `{"schema":1,"canary":{"enabled":true,"hold":"1h"}}`

func (f *deployFixture) deploymentCount() int {
	f.h.t.Helper()
	return f.h.count("SELECT count(*) FROM deployments")
}

// CAN-17: a person's request to three websites with the canary on becomes a rollout: wave 1 inserted, wave 2 kept.
func TestRequestCreatesARollout(t *testing.T) {
	f := newDeployFixture(t)
	version := f.h.setPolicy(f.h.defaultService(), canaryOn)
	locs := []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}

	// Every location is still checked: a server that is not ready refuses the whole request, wave 2 included.
	f.setTargetStatus(f.target2, inventory.StatusDisabled)
	_, _, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
	assert.ErrorIs(t, err, inventory.ErrTargetNotReady)
	assert.Zero(t, f.deploymentCount())
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployment_rollouts"))
	f.setTargetStatus(f.target2, inventory.StatusOK)

	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Len(t, got, 1, "wave 1 only")
	assert.Equal(t, inventory.RolloutWave1, r.State)
	assert.Equal(t, inventory.RolloutOriginManual, r.Origin)
	assert.Equal(t, version, r.PolicyVersion)
	assert.Equal(t, time.Hour, r.Settings.Hold)
	assert.Equal(t, 1, r.Settings.Count)
	require.Len(t, r.Wave1, 1)
	require.Len(t, r.Wave2, 2)
	assert.Equal(t, got[0].LocationID, r.Wave1[0])
	assert.ElementsMatch(t, locs, append(append([]uuid.UUID{}, r.Wave1...), r.Wave2...))
	require.NotNil(t, r.ServiceID)
	assert.Equal(t, f.h.defaultService(), *r.ServiceID)
	require.NotNil(t, r.RequestedBy)
	assert.Equal(t, f.admin.UserID, *r.RequestedBy)

	d := f.get(got[0].ID)
	require.NotNil(t, d.RolloutID)
	assert.Equal(t, r.ID, *d.RolloutID)
	assert.Equal(t, 1, d.Wave)
	assert.Equal(t, 1, f.deploymentCount())
	started := f.h.auditDetails("deployment.rollout_started")
	require.Len(t, started, 1)
	assert.Equal(t, r.ID.String(), started[0]["rollout_id"])
	assert.Equal(t, "manual", started[0]["origin"])
	assert.Equal(t, 1, f.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.rollout_started' AND details->>'service_id' = $1",
		f.h.defaultService().String()), "the source service")

	read, err := f.h.svc.Rollout(f.h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, r.Wave2, read.Wave2)
	assert.Equal(t, r.Settings, read.Settings)
	_, err = f.h.svc.Rollout(f.h.ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrRolloutNotFound)

	// The old signature answers the same deployments (the rollout is dropped).
	f2 := newDeployFixture(t)
	f2.h.setPolicy(f2.h.defaultService(), canaryOn)
	plain, err := f2.h.svc.RequestDeployment(f2.h.ctx, f2.admin, inventory.DeployRequestInput{CertificateID: f2.cert.ID, LocationIDs: []uuid.UUID{f2.loc1, f2.loc2}})
	require.NoError(t, err)
	assert.Len(t, plain, 1)
}

// CAN-18 (Review Focus 5): a current certificate on a destination that ends within hold + 24 h skips the canary.
func TestCanarySkippedWhenAWaveTwoCertificateExpiresSoon(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryOn)
	soon := f.h.clock.Now().Add(time.Hour + 20*time.Hour).UTC().Truncate(time.Second)
	_, err := f.h.db.Owner.Exec(f.h.ctx, "UPDATE certificates SET not_after = $2 WHERE id = $1", f.discovered.ID, soon)
	require.NoError(t, err)
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}})
	require.NoError(t, err)
	assert.Nil(t, r)
	assert.Len(t, got, 3, "all at once")
	skipped := f.h.auditDetails("deployment.canary_skipped")
	require.Len(t, skipped, 1)
	assert.Equal(t, "expiry", skipped[0]["reason"])
	assert.Equal(t, soon.Format(time.RFC3339), skipped[0]["not_after"])
	assert.Contains(t, []string{f.loc1.String(), f.loc2.String(), f.loc3onTarget2.String()}, skipped[0]["location_id"])
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployment_rollouts"))
}

// CAN-19 (design §13.1): deploying to all at once, allowed or forbidden by the policy.
func TestOverride(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryOn)
	locs := []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs,
		CanaryOverride: true})
	require.NoError(t, err)
	assert.Nil(t, r)
	assert.Len(t, got, 3)
	overridden := f.h.auditDetails("deployment.canary_overridden")
	require.Len(t, overridden, 1)
	assert.Equal(t, f.cert.ID.String(), overridden[0]["certificate_id"])
	assert.Equal(t, "2", overridden[0]["policy_version"])

	g := newDeployFixture(t)
	g.h.setPolicy(g.h.defaultService(), `{"schema":1,"canary":{"enabled":true,"override":"forbidden"}}`)
	_, _, err = g.h.svc.RequestDeploymentWithRollout(g.h.ctx, g.admin, inventory.DeployRequestInput{CertificateID: g.cert.ID,
		LocationIDs: []uuid.UUID{g.loc1, g.loc2}, CanaryOverride: true})
	assert.ErrorIs(t, err, inventory.ErrCanaryOverrideForbidden)
	assert.Zero(t, g.deploymentCount())
	denied := g.h.auditDetails("deployment.denied")
	require.Len(t, denied, 1)
	assert.Equal(t, "canary_override_forbidden", denied[0]["reason"])

	// Without a canary that would apply, the override is accepted and ignored.
	got, r, err = g.h.svc.RequestDeploymentWithRollout(g.h.ctx, g.admin, inventory.DeployRequestInput{CertificateID: g.cert.ID,
		LocationIDs: []uuid.UUID{g.loc1}, CanaryOverride: true})
	require.NoError(t, err)
	assert.Nil(t, r)
	assert.Len(t, got, 1)
}

// CAN-19: Key Vault and ACME Deploy now follow the policy of their source service (the vault's, the ACME certificate's),
// not the certificate row's.
func TestKVDeployNowAndACMEDeployNowCreateRollouts(t *testing.T) {
	b := newBindFixture(t)
	pay := b.h.newService("Payments")
	b.h.setPolicy(pay, canaryOn)
	b.h.trust(pay, b.h.defaultService())
	_, err := b.h.db.Owner.Exec(b.h.ctx, "UPDATE targets SET service_id = $2 WHERE id = $1", b.vault, pay)
	require.NoError(t, err)
	bind := b.create(b.admin, b.web, b.loc1, b.loc2)
	got, r, err := b.h.svc.RequestKVDeploymentWithRollout(b.h.ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID,
		VersionID: b.versionID(b.web, ver(1))})
	require.NoError(t, err)
	require.NotNil(t, r, "the vault's service asks for the canary")
	assert.Len(t, got, 1)
	assert.Equal(t, inventory.RolloutOriginManual, r.Origin)
	require.NotNil(t, r.BindingID)
	assert.Equal(t, bind.ID, *r.BindingID)
	require.NotNil(t, r.KVVersionID)
	require.NotNil(t, r.ServiceID)
	assert.Equal(t, pay, *r.ServiceID)

	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, false, w.loc1, w.loc2)
	shop := w.h.newService("Shop")
	w.h.setPolicy(shop, canaryOn)
	w.h.trust(shop, w.h.defaultService())
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_certificates SET service_id = $2 WHERE id = $1", c.ID, shop)
	require.NoError(t, err)
	reqs, ro, err := w.h.svc.DeployACMENowWithRollout(w.h.ctx, w.admin, c.ID, inventory.ACMEDeployInput{})
	require.NoError(t, err)
	require.NotNil(t, ro, "the ACME certificate's service asks for the canary")
	assert.Len(t, reqs, 1)
	require.NotNil(t, ro.ACMECertificateID)
	assert.Equal(t, c.ID, *ro.ACMECertificateID)
	assert.Equal(t, cur, ro.CertificateID)
	assert.Equal(t, inventory.RolloutOriginManual, ro.Origin)
}

// Decision 5: a key-compromise incident's replacement never waits for a canary.
func TestIncidentReplacementNeverCreatesARollout(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryOn)
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.IncidentDeployInput(f.cert.ID, f.loc1, f.loc2))
	require.NoError(t, err)
	assert.Nil(t, r)
	assert.Len(t, got, 2)
	assert.Zero(t, f.h.audits("deployment.canary_skipped"))
}

// The licence refusal comes before anything canary-related (a person's request is a change).
func TestCanaryRequestInLock(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryOn)
	lock := &lockableLicense{LicenseGate: f.h.lic}
	lock.locked.Store(true)
	svc := f.h.svcWith(lock)
	_, _, err := svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2}})
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployment_rollouts"))
}
