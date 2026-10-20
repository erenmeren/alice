//go:build integration

package inventory_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// Scoped access, Phase 1 (R49, docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md §4.4,
// §5.6): every create path names a service (the Default service when none is given), what Alice finds itself inherits
// the service of where it was found, and a key goes to a server or a vault of another service only with a trust.

func (h *harness) defaultService() uuid.UUID {
	h.t.Helper()
	var id uuid.UUID
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM services WHERE is_default").Scan(&id))
	return id
}

func (h *harness) newService(name string) uuid.UUID {
	h.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())", id, name)
	require.NoError(h.t, err)
	return id
}

// moveTo puts a row of table in a service (what the assignment does).
func (h *harness) moveTo(table string, id, service uuid.UUID) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE "+table+" SET service_id = $2 WHERE id = $1", id, service)
	require.NoError(h.t, err)
}

func (h *harness) trust(source, target uuid.UUID) {
	h.t.Helper()
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO service_trusts (id, source_service_id, target_service_id, created_at) VALUES ($1, $2, $3, now())`,
		uuid.Must(uuid.NewV7()), source, target)
	require.NoError(h.t, err)
}

func serviceFieldError(t *testing.T, err error) {
	t.Helper()
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	assert.Equal(t, "service_id", v[0].Field)
	assert.Equal(t, validate.Required, v[0].Code)
}

// Design §4.4: without service_id the Default service, with one that service, an unknown one 422 on service_id.
func TestCreatePathsNameAService(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	def, pay := h.defaultService(), h.newService("Payments")

	tg, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com"})
	require.NoError(t, err)
	assert.Equal(t, def, tg.ServiceID)
	tg2, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-02", Type: "linux", Host: "web-02.example.com", ServiceID: pay})
	require.NoError(t, err)
	assert.Equal(t, pay, tg2.ServiceID)
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-03", Type: "linux", Host: "web-03.example.com", ServiceID: uuid.New()})
	serviceFieldError(t, err)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM targets"), "nothing stored")

	ca := pki.NewCA("Svc", pki.ECDSA256, start)
	leaf := ca.Issue(pki.Opts{CommonName: "pay.example.test", SANs: []string{"pay.example.test"}}, h.clock.Now())
	in := pemUpload(leaf)
	in.ServiceID = uuid.New()
	_, _, err = h.svc.UploadCertificate(h.ctx, admin, in)
	serviceFieldError(t, err)
	in.ServiceID = pay
	c, _, err := h.svc.UploadCertificate(h.ctx, admin, in)
	require.NoError(t, err)
	assert.Equal(t, pay, c.ServiceID)
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, pay, got.ServiceID)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{ServiceIDs: []uuid.UUID{def}})
	require.NoError(t, err)
	assert.Empty(t, page.Items, "the list filter keeps the services named")
	page, err = h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{ServiceIDs: []uuid.UUID{pay}})
	require.NoError(t, err)
	assert.Len(t, page.Items, 1)
	page, err = h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{ServiceIDs: []uuid.UUID{}})
	require.NoError(t, err)
	assert.Empty(t, page.Items, "an empty set names no service")

	_, err = h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "req.example.test", KeyType: "ecdsa-p256", ServiceID: uuid.New()})
	serviceFieldError(t, err)
	csr, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "req.example.test", KeyType: "ecdsa-p256", ServiceID: pay})
	require.NoError(t, err)
	assert.Equal(t, pay, csr.ServiceID)
	csr2, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "req2.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	assert.Equal(t, def, csr2.ServiceID)
	assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE details ? 'service_id'"), "Phase 1 leaves the audit rows as they were")
}

// What a scan finds on a server goes to the server's service; a certificate Alice knows keeps its service.
func TestDiscoveredRowsTakeTheServersService(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	assert.Equal(t, h.defaultService(), f.discovered.ServiceID, "found on a server of the Default service")
	pay := h.newService("Payments")
	h.moveTo("targets", f.target2, pay)
	leaf := f.ca.Issue(pki.Opts{CommonName: "new.example.test", SANs: []string{"new.example.test"}}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, f.target2, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/new.crt", "/etc/nginx/ssl/new.key", "new.example.test"), leaf),
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old)}})
	require.NoError(t, err)
	assert.Equal(t, pay, f.certByFingerprint(t, pki.Fingerprint(leaf.Cert)).ServiceID, "first seen on a Payments server")
	assert.Equal(t, h.defaultService(), f.certByFingerprint(t, pki.Fingerprint(f.old.Cert)).ServiceID, "an existing row keeps its service")
}

// Design §5.6 (c): a person's deployment, a Key Vault binding and its Deploy now across services need a trust.
func TestDeploymentsAndBindingsAcrossServicesNeedATrust(t *testing.T) {
	b := newBindFixture(t)
	h := b.h
	def, pay := h.defaultService(), h.newService("Payments")
	h.moveTo("targets", b.target2, pay)

	_, err := h.svc.RequestDeployment(h.ctx, b.admin, inventory.DeployRequestInput{CertificateID: b.cert.ID, LocationIDs: []uuid.UUID{b.loc2}})
	var refused *inventory.LocationRefusalError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, b.loc2, refused.LocationID)
	assert.ErrorIs(t, err, inventory.ErrServiceUntrusted)
	var ue *authz.UntrustedError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, authz.UntrustedError{Source: def, Target: pay}, *ue)
	_, err = h.svc.RequestDeployment(h.ctx, b.admin, inventory.DeployRequestInput{CertificateID: b.cert.ID, LocationIDs: []uuid.UUID{b.loc1}})
	require.NoError(t, err, "a server of the certificate's own service needs no trust")

	_, err = h.svc.CreateBinding(h.ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc3}})
	assert.ErrorIs(t, err, inventory.ErrServiceUntrusted, "the vault (Default) and the website (Payments) differ")
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'binding.denied' AND details->>'reason' = $1",
		inventory.ReasonServiceUntrusted))
	h.trust(def, pay)
	bind := b.create(b.admin, b.web, b.loc3)
	assert.Len(t, bind.Locations, 1)
}

// Design §5.6: the Key Vault planner holds a website across services without a trust, marks it once with
// service.untrusted and mails once; a trust lets the next run deploy and clears the mark.
func TestKVAutoDeployAcrossServicesHoldsUntilATrust(t *testing.T) {
	f := newAutoFixture(t, true)
	h := f.h
	def, pay := h.defaultService(), h.newService("Payments")
	h.moveTo("targets", f.target2, pay) // loc2 and loc3 are on web-02
	f.renew(2, nil)
	require.Equal(t, 1, f.plan(), "only web-01's website, in the vault's service")
	assert.Equal(t, []uuid.UUID{f.loc1}, f.locationsOf(ver(2)))
	marked := func() int {
		return h.count("SELECT count(*) FROM certificate_locations WHERE binding_attention_code = $1", inventory.ReasonServiceUntrusted)
	}
	assert.Equal(t, 2, marked())
	assert.Equal(t, 1, f.mails()[inventory.TemplateKVAutoDeployUntrusted])
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.auto_deploy.untrusted'"))
	assert.Zero(t, f.plan())
	assert.Equal(t, 1, f.mails()[inventory.TemplateKVAutoDeployUntrusted], "the mark is the once-only flag")

	h.trust(def, pay)
	assert.Equal(t, 2, f.plan(), "with a trust the next run deploys to web-02")
	assert.Zero(t, marked(), "the marks are cleared")
}

// The deployment engine's first send (DeploymentMaterial) refuses a queued deployment whose trust was removed.
func TestFirstSendChecksTheTrustAgain(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	def, pay := h.defaultService(), h.newService("Payments")
	h.moveTo("targets", f.target2, pay)
	h.trust(def, pay)
	got, err := h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc2}})
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "DELETE FROM service_trusts")
	require.NoError(t, err)
	_, err = h.svc.DeploymentMaterial(h.ctx, got[0].ID, false)
	assert.ErrorIs(t, err, inventory.ErrServiceUntrusted)
	h.trust(def, pay)
	_, err = h.svc.DeploymentMaterial(h.ctx, got[0].ID, false)
	assert.NoError(t, err)
}
