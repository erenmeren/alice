//go:build integration

package inventory_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// Service policy (R55, docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md §7.3, §12 Phase 5):
// each field lets an action inside the policy through and refuses one outside with its error before anything is
// stored, ordered or generated; automatic deployment holds while the policy forbids it and resumes when it allows it.

// setPolicy stores doc as the service's next policy version (what PUT /services/{id}/policy does).
func setPolicy(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service uuid.UUID, doc string) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO service_policies (service_id, version, body, created_at)
SELECT id, policy_version + 1, $2::jsonb, now() FROM services WHERE id = $1`, service, doc)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "UPDATE services SET policy_version = policy_version + 1 WHERE id = $1", service)
	require.NoError(t, err)
}

func TestPolicyACMECertificates(t *testing.T) {
	w := newCertWorld(t)
	other := w.registryWorld.provider("Other CA", false)
	w.register(other)
	pay := w.newService("Payments")
	setPolicy(t, w.ctx, w.db.Owner, pay, `{"schema":1,"domains":["*.pay.example.test"],"certificate_sources":["acme"],
"acme":{"providers":["`+w.provider.ID.String()+`"],"challenges":["dns01"],"key_types":["ecdsa_p256","ecdsa_p384"],"renew_before_days":14},
"deployment":{"auto_deploy":"forbidden"}}`)
	in := func(names ...string) inventory.ACMECertificateInput {
		i := w.dnsInput(names...)
		i.ServiceID = pay
		return i
	}

	// Inside the policy: stored, with the policy's renewal window as the default.
	c := w.create(in("api.pay.example.test", "*.pay.example.test"))
	assert.Equal(t, 14, c.RenewBeforeDays)
	assert.Equal(t, pay, c.ServiceID)
	given := in("www.pay.example.test")
	given.RenewBeforeDays = 40
	assert.Equal(t, 40, w.create(given).RenewBeforeDays, "a window given is kept: the policy sets a default, not a rule")

	refused := func(i inventory.ACMECertificateInput) error {
		_, err := w.svc.CreateACMECertificate(w.ctx, w.admin, i)
		return err
	}
	var de *authz.DomainError
	require.ErrorAs(t, refused(in("api.pay.example.test", "shop.example.test")), &de)
	assert.Equal(t, authz.DomainError{Name: "shop.example.test", Field: "names"}, *de)
	require.ErrorAs(t, refused(in("pay.example.test")), &de, "the wildcard entry does not admit its own suffix")

	kt := in("k.pay.example.test")
	kt.KeyType = "rsa_2048"
	var ae *authz.ACMEPolicyError
	require.ErrorAs(t, refused(kt), &ae)
	assert.Equal(t, "key_type", ae.Field)
	op := in("o.pay.example.test")
	op.ProviderID = other.ID
	require.ErrorAs(t, refused(op), &ae)
	assert.Equal(t, "provider_id", ae.Field)
	auto := in("auto.pay.example.test")
	auto.AutoDeploy = true
	assert.ErrorIs(t, refused(auto), authz.ErrAutoDeployForbidden)
	assert.Equal(t, 2, w.count("SELECT count(*) FROM acme_certificates WHERE service_id = $1", pay), "nothing stored")
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders"), "nothing ordered")

	// The Default service has no policy: the same names are fine there.
	assert.Equal(t, 30, w.create(w.dnsInput("shop.example.test")).RenewBeforeDays)

	// A change is judged in what it changes only.
	_, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{Names: &[]string{"shop.example.test"}})
	require.ErrorAs(t, err, &de)
	on := true
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{AutoDeploy: &on})
	assert.ErrorIs(t, err, authz.ErrAutoDeployForbidden)
	setPolicy(t, w.ctx, w.db.Owner, pay, `{"schema":1,"domains":["*.pay.example.test"],"acme":{"key_types":["rsa_3072"]}}`)
	days := 21
	got, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{RenewBeforeDays: &days})
	require.NoError(t, err, "a stricter policy is not applied to what exists")
	assert.Equal(t, 21, got.RenewBeforeDays)
	p384 := "ecdsa_p384"
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, c.ID, inventory.ACMECertificatePatch{KeyType: &p384})
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, "key_type", ae.Field)

	// Sources: a service that takes uploads only refuses a new ACME certificate.
	setPolicy(t, w.ctx, w.db.Owner, pay, `{"schema":1,"certificate_sources":["uploaded"]}`)
	var se *authz.SourceError
	require.ErrorAs(t, refused(in("z.pay.example.test")), &se)
	assert.Equal(t, authz.SourceACME, se.Source)
}

func (w *registryWorld) newService(name string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := w.db.Owner.Exec(w.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())", id, name)
	require.NoError(w.t, err)
	return id
}

func TestPolicyUploadsAndSigningRequests(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	pay := h.newService("Payments")
	setPolicy(t, h.ctx, h.db.Owner, pay, `{"schema":1,"domains":["*.pay.example.test","10.20.0.0/16"],"certificate_sources":["uploaded","csr"]}`)
	ca := pki.NewCA("Policy", pki.ECDSA256, start)

	upload := func(cn string, sans []string) error { // an IP address among the SANs is an IP SAN
		leaf := ca.Issue(pki.Opts{CommonName: cn, SANs: sans}, h.clock.Now())
		in := pemUpload(leaf)
		in.ServiceID = pay
		_, _, err := h.svc.UploadCertificate(h.ctx, admin, in)
		return err
	}
	require.NoError(t, upload("api.pay.example.test", []string{"api.pay.example.test", "a.b.pay.example.test", "10.20.3.4"}))
	var de *authz.DomainError
	require.ErrorAs(t, upload("web.pay.example.test", []string{"web.pay.example.test", "10.21.0.1"}), &de)
	assert.Equal(t, authz.DomainError{Name: "10.21.0.1", Field: "certificate_pem"}, *de)
	require.ErrorAs(t, upload("shop.example.test", []string{"shop.example.test"}), &de)
	assert.Equal(t, "shop.example.test", de.Name)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates WHERE service_id = $1", pay), "nothing uploaded")
	assert.Equal(t, 2, h.count(`SELECT count(*) FROM audit_log WHERE action = 'certificate.upload_rejected' AND details->>'reason' = 'policy'`))

	keys := h.count("SELECT count(*) FROM managed_private_keys")
	_, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "req.pay.example.test", SANs: []string{"shop.example.test"},
		KeyType: "ecdsa-p256", ServiceID: pay})
	require.ErrorAs(t, err, &de)
	assert.Equal(t, authz.DomainError{Name: "shop.example.test", Field: "sans"}, *de)
	_, err = h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "shop.example.test", KeyType: "ecdsa-p256", ServiceID: pay})
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "common_name", de.Field)
	assert.Equal(t, keys, h.count("SELECT count(*) FROM managed_private_keys"), "no key generated")
	csr, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "req.pay.example.test", KeyType: "ecdsa-p256", ServiceID: pay})
	require.NoError(t, err)
	assert.Equal(t, pay, csr.ServiceID)

	// Sources.
	setPolicy(t, h.ctx, h.db.Owner, pay, `{"schema":1,"certificate_sources":["acme"]}`)
	var se *authz.SourceError
	require.ErrorAs(t, upload("x.pay.example.test", []string{"x.pay.example.test"}), &se)
	assert.Equal(t, authz.SourceUploaded, se.Source)
	_, err = h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "x.pay.example.test", KeyType: "ecdsa-p256", ServiceID: pay})
	require.ErrorAs(t, err, &se)
	assert.Equal(t, authz.SourceCSR, se.Source)

	// An empty list is no constraint.
	setPolicy(t, h.ctx, h.db.Owner, pay, `{"schema":1}`)
	require.NoError(t, upload("anything.example.org", []string{"anything.example.org"}))
}

// incident.revoke_mode is the default of an incident started on the service's certificates.
func TestPolicyIncidentRevokeModeDefault(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	pay := h.newService("Payments")
	setPolicy(t, h.ctx, h.db.Owner, pay, `{"schema":1,"incident":{"revoke_mode":"now"}}`)
	ca := pki.NewCA("Incident", pki.ECDSA256, start)
	in := pemUpload(ca.Issue(pki.Opts{CommonName: "inc.example.test", SANs: []string{"inc.example.test"}}, h.clock.Now()))
	in.ServiceID = pay
	c, _, err := h.svc.UploadCertificate(h.ctx, admin, in)
	require.NoError(t, err)
	i, err := h.svc.StartIncident(h.ctx, admin, c.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevokeNow, i.RevokeMode)

	in = pemUpload(ca.Issue(pki.Opts{CommonName: "inc2.example.test", SANs: []string{"inc2.example.test"}}, h.clock.Now()))
	in.ServiceID = pay
	c, _, err = h.svc.UploadCertificate(h.ctx, admin, in)
	require.NoError(t, err)
	i, err = h.svc.StartIncident(h.ctx, admin, c.ID, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeAfterVerified})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevokeAfterVerified, i.RevokeMode, "a mode given is kept")
}

// auto_deploy forbidden: switching on is refused; the ACME planner holds the automatic bindings with the mark and
// resumes when the policy allows it.
func TestPolicyForbidsACMEAutomaticDeployment(t *testing.T) {
	w := newACMEDeployWorld(t)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1)
	def := w.h.defaultService()
	setPolicy(t, w.h.ctx, w.h.db.Owner, def, `{"schema":1,"deployment":{"auto_deploy":"forbidden"}}`)

	_, err := w.h.svc.AddACMEBinding(w.h.ctx, w.admin, c.ID, w.loc2, true)
	assert.ErrorIs(t, err, authz.ErrAutoDeployForbidden)
	b, err := w.h.svc.AddACMEBinding(w.h.ctx, w.admin, c.ID, w.loc2, false)
	require.NoError(t, err, "a binding without automatic deployment is fine")
	assert.False(t, b.AutoDeploy)

	run := w.plan()
	assert.Zero(t, run.Created)
	assert.Empty(t, w.deps(cur), "nothing deployed")
	assert.Equal(t, map[uuid.UUID]string{w.loc1: inventory.ReasonAutoDeployForbidden}, w.attention(w.get(c.ID)))
	assert.Equal(t, 1, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'acme.auto_deploy.forbidden'"))
	w.plan()
	assert.Equal(t, 1, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'acme.auto_deploy.forbidden'"), "the mark is recorded once")
	assert.True(t, w.get(c.ID).AutoDeploy, "the certificate's automatic deployment stays on")

	// Allowed again: the held binding resumes by itself at the next run.
	setPolicy(t, w.h.ctx, w.h.db.Owner, def, `{"schema":1,"deployment":{"auto_deploy":"allowed"}}`)
	run = w.plan()
	assert.Equal(t, 1, run.Created, "it resumes")
	assert.Equal(t, []uuid.UUID{w.loc1}, locationsOf(w.deps(cur)))
	assert.Empty(t, w.attention(w.get(c.ID)), "the mark is cleared")
}

// The Key Vault planner holds the binding's websites while the vault's service forbids automatic deployment; switching
// on is refused; allowing it again resumes the wave.
func TestPolicyForbidsKeyVaultAutomaticDeployment(t *testing.T) {
	f := newAutoFixture(t, true)
	h := f.h
	def := h.defaultService()
	setPolicy(t, h.ctx, h.db.Owner, def, `{"schema":1,"deployment":{"auto_deploy":"forbidden"}}`)
	f.renew(2, nil)
	assert.Zero(t, f.plan())
	marked := func() int {
		return h.count("SELECT count(*) FROM certificate_locations WHERE binding_attention_code = $1", inventory.ReasonAutoDeployForbidden)
	}
	assert.Equal(t, 3, marked())
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.auto_deploy.forbidden'"))
	assert.Zero(t, f.plan())
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.auto_deploy.forbidden'"), "recorded once")
	got, err := h.svc.Binding(h.ctx, f.bind.ID)
	require.NoError(t, err)
	assert.True(t, got.AutoDeploy, "the binding stays on")
	for _, l := range got.Locations {
		assert.Equal(t, inventory.ReasonAutoDeployForbidden, l.AttentionCode)
	}

	off := f.setAuto(false)
	assert.Zero(t, marked(), "switched off, nothing is held any more")
	_, err = h.svc.SetAutoDeploy(h.ctx, f.admin, f.bind.ID, off.Version, true)
	assert.ErrorIs(t, err, authz.ErrAutoDeployForbidden)
	assert.Equal(t, 1, h.count(`SELECT count(*) FROM audit_log WHERE action = 'binding.denied' AND details->>'reason' = 'auto_deploy_forbidden'`))

	setPolicy(t, h.ctx, h.db.Owner, def, `{"schema":1}`)
	f.setAuto(true)
	f.renew(3, nil)
	assert.Equal(t, 3, f.plan(), "it resumes")
	assert.Zero(t, marked(), "the marks are cleared")
}
