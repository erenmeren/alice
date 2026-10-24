//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
	"alice/internal/testutil/seed"
)

// complete runs a running order of the world's fake CA to its end as the acme.issue job does.
func (w *acmeDeployWorld) complete(orderID uuid.UUID) uuid.UUID {
	w.h.t.Helper()
	ctx := w.h.ctx
	work, err := w.h.svc.ACMEOrderWork(ctx, orderID)
	require.NoError(w.h.t, err)
	client, err := w.h.svc.ACMEOrderClient(ctx, orderID)
	require.NoError(w.h.t, err)
	signer, err := w.h.svc.NewACMEOrderKey(ctx, orderID)
	require.NoError(w.h.t, err)
	csr, err := keygen.NewCSR(signer, work.Names)
	require.NoError(w.h.t, err)
	sol := solver.NewMemory(solver.DNS01)
	sol.AfterPresent = func(_ context.Context, ch solver.Challenge) error { w.fake.DNSSet(ch.DNSName, ch.DNSValue); return nil }
	chain, err := client.Order(ctx, work.Names, csr, sol)
	require.NoError(w.h.t, err)
	got, err := w.h.svc.FinishACMEOrder(ctx, orderID, chain)
	require.NoError(w.h.t, err)
	_, err = w.h.db.Owner.Exec(ctx, "UPDATE jobs SET status = 'succeeded', finished_at = $1 WHERE type = 'acme.issue' AND status = 'queued'",
		w.h.clock.Now())
	require.NoError(w.h.t, err)
	return got.CertificateID
}

func (w *acmeDeployWorld) certOf(id uuid.UUID) inventory.Certificate {
	w.h.t.Helper()
	c, err := w.h.svc.GetCertificate(w.h.ctx, id)
	require.NoError(w.h.t, err)
	return c
}

// serves puts the certificate in the location's file, as a scan would find it after Alice deployed it there.
func (w *acmeDeployWorld) serves(loc, cert uuid.UUID) {
	w.h.t.Helper()
	_, err := w.h.db.Owner.Exec(w.h.ctx, `UPDATE certificate_locations SET certificate_id = $2,
    deployed_fingerprint = (SELECT fingerprint_sha256 FROM certificates WHERE id = $2) WHERE id = $1`, loc, cert)
	require.NoError(w.h.t, err)
}

func (w *acmeDeployWorld) advance() int {
	w.h.t.Helper()
	n, err := w.h.svc.AdvanceIncidents(w.h.ctx)
	require.NoError(w.h.t, err)
	return n
}

func (w *acmeDeployWorld) incident(id uuid.UUID) inventory.Incident {
	w.h.t.Helper()
	i, err := w.h.svc.GetIncident(w.h.ctx, id)
	require.NoError(w.h.t, err)
	return i
}

func locationStatus(i inventory.Incident) map[uuid.UUID]string {
	out := map[uuid.UUID]string{}
	for _, l := range i.Locations {
		out[l.LocationID] = l.Status
		if l.ErrorCode != "" {
			out[l.LocationID] += ":" + l.ErrorCode
		}
	}
	return out
}

func revocationStatus(t *testing.T, fake *fakeacme.Server, c inventory.Certificate) fakeacme.CertStatus {
	t.Helper()
	st, ok := fake.CertificateStatus(c.Serial)
	require.True(t, ok, "the fake CA issued %s", c.Serial)
	return st
}

// An Administrator revokes a version of an ACME certificate at its CA: recorded on the version, audited, never deployed
// again, and the renewal planner orders a new one at once.
func TestACMERevokeAVersion(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")

	var verr validate.Errors
	_, err := w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "cACompromise"})
	require.ErrorAs(t, err, &verr)
	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{CertificateID: &w.cert.ID, Reason: "superseded"})
	require.ErrorIs(t, err, inventory.ErrNotACMEVersion)
	assert.Zero(t, w.fake.Counters()["revoke-cert"], "nothing was sent")

	got, err := w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "superseded"})
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	assert.Equal(t, "superseded", got.RevocationReason)
	assert.Equal(t, "ada Yılmaz", got.RevokedByName)
	assert.Equal(t, cur, got.ID)
	st := revocationStatus(t, w.fake, got)
	assert.Equal(t, "revoked", st.Status)
	assert.Equal(t, 4, st.Reason)
	assert.Equal(t, 1, w.h.audits("acme.certificate.revoked"))
	assert.NotContains(t, inventory.CertificateCapabilities(got), inventory.SourceCapRevoke)
	assert.NotContains(t, inventory.CertificateCapabilities(got), inventory.SourceCapDeploy)

	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "superseded"})
	require.ErrorIs(t, err, inventory.ErrCertificateRevoked)

	// Never deployed again: a person's request, Deploy now and the automatic planner refuse it.
	_, err = w.h.svc.RequestDeployment(w.h.ctx, w.admin, inventory.DeployRequestInput{CertificateID: cur, LocationIDs: []uuid.UUID{w.loc1}})
	require.ErrorIs(t, err, inventory.ErrCertificateRevoked)
	w.bind(w.get(c.ID), true, w.loc1)
	assert.Zero(t, w.plan().Created)

	// The renewal planner orders a replacement at once (a revoked current certificate is due), after the 15-minute spacing.
	w.h.clock.Advance(16 * time.Minute)
	run, err := w.h.svc.PlanACMERenewals(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, run.Started)
}

// A CA without revokeCert, and one that refuses: nothing is recorded, the failure is audited.
func TestACMERevokeFailures(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal, Times: 1}))
	_, err := w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "keyCompromise"})
	var ae *inventory.ACMEError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, acme.ReasonProviderUnreachable, ae.Reason)
	require.NoError(t, w.fake.Advertise("revokeCert", "off"))
	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "keyCompromise"})
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, acme.ReasonRevokeUnsupported, ae.Reason)
	assert.Nil(t, w.certOf(cur).RevokedAt)
	assert.Equal(t, 2, w.h.audits("acme.certificate.revoke_failed"))
	assert.Zero(t, w.h.audits("acme.certificate.revoked"))
}

// A deployment queued before its certificate was marked compromised is refused when it is about to send.
func TestQueuedDeploymentOfACompromisedCertificateIsRefused(t *testing.T) {
	f := newDeployFixture(t)
	f.h.installLicense("LIC-REVOKE", 5, 365)
	require.NoError(t, f.h.lic.Tick(f.h.ctx))
	got, err := f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	require.NoError(t, err)
	_, err = f.h.db.Owner.Exec(f.h.ctx, "UPDATE certificates SET compromised_at = now() WHERE id = $1", f.cert.ID)
	require.NoError(t, err)
	_, err = f.h.svc.DeploymentMaterial(f.h.ctx, got[0].ID, true)
	require.ErrorIs(t, err, inventory.ErrCertificateCompromised)
	_, err = f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc5}})
	require.ErrorIs(t, err, inventory.ErrCertificateCompromised)
	assert.Equal(t, 1, f.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND details->>'reason' = 'compromised'"))
}

// The impact of a certificate: its files on managed servers, another certificate with the same key, a Key Vault-less
// fixture, and the endpoints network discovery found presenting either.
func TestCertificateImpact(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	// Another certificate made with the old certificate's key, found in b.crt of web-01.
	same := f.ca.Issue(pki.Opts{CommonName: "other.example.test", SANs: []string{"other.example.test"}, Key: f.old.Key}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, f.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "other.example.test"), same)}})
	require.NoError(t, err)

	// Network discovery found the other certificate on 10.0.0.9:443.
	scope, err := seed.DiscoveryScope(h.ctx, h.db.App, "LAN", false)
	require.NoError(t, err)
	sameFP := pki.Fingerprint(same.Cert)
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, not_before, not_after, key_algorithm,
    pem, first_seen, last_seen, public_key_sha256) VALUES ($1, true, 'other.example.test', now(), now() + interval '30 days', 'ecdsa',
    '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', now(), now(), $2)`, sameFP, f.discovered.PublicKeySHA256)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, state, first_seen, last_seen,
    last_scanned_at) VALUES ($1, $2, '10.0.0.9', 443, $3, 'present', now(), now(), now())`, uuid.New(), scope, sameFP)
	require.NoError(t, err)

	imp, err := h.svc.CertificateImpact(h.ctx, f.discovered.ID)
	require.NoError(t, err)
	require.Len(t, imp.Certificates, 2)
	assert.Equal(t, f.discovered.ID, imp.Certificates[0].ID)
	assert.Equal(t, inventory.ImpactMatchCertificate, imp.Certificates[0].Match)
	assert.Equal(t, inventory.ImpactMatchKey, imp.Certificates[1].Match)
	matches := map[uuid.UUID]string{}
	for _, l := range imp.Locations {
		matches[l.LocationID] = l.Match
		assert.True(t, l.Deployable, l.CertPath)
	}
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "certificate", f.loc5: "key", f.loc2: "certificate", f.loc3onTarget2: "certificate",
		f.loc4: "certificate"}, matches)
	require.Len(t, imp.Endpoints, 1)
	assert.Equal(t, "10.0.0.9", imp.Endpoints[0].Address.String())
	assert.Equal(t, inventory.ImpactMatchKey, imp.Endpoints[0].Match)
	assert.Empty(t, imp.Vaults)
	assert.Nil(t, imp.OpenIncidentID)

	// An unrelated certificate affects nothing.
	imp, err = h.svc.CertificateImpact(h.ctx, f.cert.ID)
	require.NoError(t, err)
	assert.Empty(t, imp.Locations)
	assert.Empty(t, imp.Endpoints)
	_, err = h.svc.CertificateImpact(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// The whole ACME incident: compromised marks, a new order with a new key, the replacement deployed to every affected
// file, the old certificate revoked with keyCompromise only after the deployments are verified.
func TestACMEIncidentReplacesEverywhereThenRevokes(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	w.serves(w.loc2, cur)
	w.bind(w.get(c.ID), false, w.loc1)
	old := w.certOf(cur)

	_, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: "later"})
	var verr validate.Errors
	require.ErrorAs(t, err, &verr)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentOrdering, i.State)
	assert.Equal(t, inventory.IncidentRevocationPending, i.Revocation)
	require.NotNil(t, i.OrderID)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "pending", w.loc2: "pending"}, locationStatus(i))
	assert.NotNil(t, w.certOf(cur).CompromisedAt)
	_, err = w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.ErrorIs(t, err, inventory.ErrIncidentOpen)
	_, err = w.h.svc.RequestDeployment(w.h.ctx, w.admin, inventory.DeployRequestInput{CertificateID: cur, LocationIDs: []uuid.UUID{w.loc5}})
	require.ErrorIs(t, err, inventory.ErrCertificateCompromised)

	assert.Zero(t, w.advance(), "the order runs")
	replacement := w.complete(*i.OrderID)
	assert.NotEqual(t, old.PublicKeySHA256, w.certOf(replacement).PublicKeySHA256, "a new key")

	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentDeploying, i.State)
	require.NotNil(t, i.ReplacementCertificateID)
	assert.Equal(t, replacement, *i.ReplacementCertificateID)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "deploying", w.loc2: "deploying"}, locationStatus(i))
	assert.Equal(t, "valid", revocationStatus(t, w.fake, old).Status, "not revoked before the deployments are verified")

	w.finishAll(replacement, inventory.DeployStatusSucceeded, "")
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentCompleted, i.State)
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "verified", w.loc2: "verified"}, locationStatus(i))
	st := revocationStatus(t, w.fake, old)
	assert.Equal(t, "revoked", st.Status)
	assert.Equal(t, 1, st.Reason, "keyCompromise")
	assert.Equal(t, "keyCompromise", w.certOf(cur).RevocationReason)
	for _, a := range []string{"incident.started", "certificate.compromised", "incident.replacement_chosen", "incident.deployed",
		"incident.revoked", "incident.completed", "acme.certificate.revoked"} {
		assert.Equal(t, 1, w.h.audits(a), a)
	}
	assert.Zero(t, w.advance(), "a finished incident is not advanced")
	imp, err := w.h.svc.CertificateImpact(w.h.ctx, cur)
	require.NoError(t, err)
	assert.Nil(t, imp.OpenIncidentID)
}

// A failed deployment needs a person; "revoke now regardless" revokes anyway; a failed revocation the CA could not
// answer is tried again later; closing finishes the incident as it stands.
func TestACMEIncidentAttentionRevokeNowAndClose(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	replacement := w.complete(*i.OrderID)
	w.advance()
	w.finishAll(replacement, inventory.DeployStatusFailed, "deployment.reload_failed")
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentCodeDeploymentsFailed, i.AttentionCode)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "failed:deployment.reload_failed"}, locationStatus(i))
	_, err = w.h.svc.CloseIncident(w.h.ctx, w.admin, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)

	// Revoke now regardless, while the CA is down: tried again after a minute.
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal, Times: 1}))
	i, err = w.h.svc.RevokeIncidentNow(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevokeNow, i.RevokeMode)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, 1, i.RevokeAttempts)
	require.NotNil(t, i.NextAttemptAt)
	assert.Equal(t, inventory.IncidentRevocationPending, i.Revocation)
	w.advance()
	assert.Equal(t, 1, w.incident(i.ID).RevokeAttempts, "the wait is kept")
	w.h.clock.Advance(2 * time.Minute)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State, "the failed location still needs a person")
	assert.Equal(t, "revoked", revocationStatus(t, w.fake, w.certOf(cur)).Status)

	// Retry the failed location, then close.
	i, err = w.h.svc.RetryIncident(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentDeploying, i.State)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "pending"}, locationStatus(i))
	i, err = w.h.svc.CloseIncident(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentClosed, i.State)
	_, err = w.h.svc.RetryIncident(w.h.ctx, w.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState)
	_, err = w.h.svc.CloseIncident(w.h.ctx, w.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState)
	assert.Equal(t, 1, w.h.audits("incident.closed"))
}

// A failed order needs a person; a retry orders again.
func TestACMEIncidentOrderFailure(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
	require.NoError(t, err)
	require.NoError(t, w.h.svc.FailACMEOrder(w.h.ctx, *i.OrderID, acme.ReasonValidationFailedDNS, 0))
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE jobs SET status = 'failed', finished_at = now() WHERE type = 'acme.issue' AND status = 'queued'")
	require.NoError(t, err)
	w.advance()
	i = w.incident(i.ID)
	// Revoke now: the compromised certificate was revoked at once, whatever the order did.
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, acme.ReasonValidationFailedDNS, i.AttentionCode)

	i, err = w.h.svc.RetryIncident(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentOrdering, i.State)
	assert.Nil(t, i.OrderID)
	w.advance()
	i = w.incident(i.ID)
	require.NotNil(t, i.OrderID, "ordered again")
	assert.Equal(t, inventory.ACMEOrderRunning, i.OrderState)
}

// Another source: Alice cannot revoke it; the person chooses the replacement, which is deployed to every file that holds
// the compromised certificate (a file with another certificate made with the same key is skipped).
func TestIncidentOfAnUploadedCertificate(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	h.installLicense("LIC-INCIDENT", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	// The old certificate's key arrives in Alice (the discovered certificate becomes an uploaded one), and b.crt of
	// web-01 holds another certificate made with the same key.
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	same := f.ca.Issue(pki.Opts{CommonName: "other.example.test", SANs: []string{"other.example.test"}, Key: f.old.Key}, h.clock.Now())
	_, err = h.svc.Reconcile(h.ctx, f.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "other.example.test"), same)}})
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	require.True(t, old.HasPrivateKey)

	i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentAwaitingReplacement, i.State)
	assert.Equal(t, inventory.IncidentRevocationNotPossible, i.Revocation)
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "pending", f.loc5: "skipped:incident.other_certificate", f.loc2: "pending",
		f.loc3onTarget2: "pending", f.loc4: "pending"}, locationStatus(i))
	assert.Equal(t, 2, h.count("SELECT count(*) FROM certificates WHERE compromised_at IS NOT NULL"), "both certificates with the key")
	_, err = h.svc.RevokeIncidentNow(h.ctx, f.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentNotRevocable)
	assert.Zero(t, f.h.count("SELECT count(*) FROM deployments"))
	assert.Zero(t, func() int { w := &acmeDeployWorld{deployFixture: f}; return w.advance() }(), "waits for a person")

	for _, bad := range []uuid.UUID{old.ID, f.discovered.ID, uuid.New()} {
		_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, bad)
		require.ErrorIs(t, err, inventory.ErrIncidentReplacement, bad.String())
	}
	i, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentDeploying, i.State)
	w := &acmeDeployWorld{deployFixture: f}
	w.advance()
	i = w.incident(i.ID)
	// spare.crt on web-02 holds an RSA key type: the ECDSA replacement is refused there.
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "deploying", f.loc5: "skipped:incident.other_certificate", f.loc2: "deploying",
		f.loc3onTarget2: "deploying", f.loc4: "deploying"}, locationStatus(i))
	for _, d := range w.deps(f.cert.ID) {
		w.finish(d.ID, inventory.DeployStatusSucceeded, "")
	}
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentCompleted, i.State)
	assert.Equal(t, 1, h.audits("incident.completed"))
	assert.Zero(t, h.audits("incident.revoked"))
}

// The start is all or nothing and needs the licence gate open.
func TestIncidentRefusals(t *testing.T) {
	f := newDeployFixture(t)
	_, err := f.h.svc.StartIncident(f.h.ctx, f.admin, uuid.New(), inventory.IncidentInput{})
	require.Error(t, err) // the evaluation licence of a fresh harness may refuse first; either way nothing is written
	f.h.installLicense("LIC-INCIDENT-R", 5, 365)
	require.NoError(t, f.h.lic.Tick(f.h.ctx))
	_, err = f.h.svc.StartIncident(f.h.ctx, f.admin, uuid.New(), inventory.IncidentInput{})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Zero(t, f.h.count("SELECT count(*) FROM certificate_incidents"))
	assert.Zero(t, f.h.count("SELECT count(*) FROM certificates WHERE compromised_at IS NOT NULL"))
	list, err := f.h.svc.ListIncidents(f.h.ctx, inventory.IncidentFilter{OpenOnly: true})
	require.NoError(t, err)
	assert.Empty(t, list.Items)
	assert.Nil(t, list.Next)
	_, err = f.h.svc.ListIncidents(f.h.ctx, inventory.IncidentFilter{Limit: 1000})
	var verr validate.Errors
	require.True(t, errors.As(err, &verr))
}
