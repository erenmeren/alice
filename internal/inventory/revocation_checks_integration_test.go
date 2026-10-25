//go:build integration

package inventory_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/rbac"
	"alice/internal/revocation"
	"alice/internal/testutil/fakerevocation"
	"alice/internal/testutil/pki"
	"alice/internal/testutil/seed"
)

// The scheduled revocation check (D5, HB-14 to HB-16, R64 Rulings 14 to 20): the real checker against the fake
// responder of a test CA, its leaves naming the fake's addresses.

const (
	revOCSP = "http://ocsp.alice.test/ocsp"
	revCRL  = "http://crl.alice.test/crl"
)

// revFake is the fake authority of a harness built withRevocation.
type revFake struct {
	ca   *pki.CA
	fake *fakerevocation.Server
}

// withRevocation gives the inventory the real checker, every dial reaching the fake authority (rf, filled here).
func withRevocation(t *testing.T, rf *revFake) harnessOption {
	return func(c *inventory.Config) {
		rf.ca = pki.NewCA("Revocation", pki.ECDSA256, c.Clock.Now())
		rf.fake = fakerevocation.New(rf.ca, c.Clock)
		addr := rf.fake.Start(t)
		dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		c.Revocation = inventory.RevocationCheckerOf(revocation.NewWithDial(c.Clock, dial))
	}
}

func (rf *revFake) leaf(h *harness, cn string, ocspURLs, crlURLs []string) pki.Leaf {
	return rf.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}, OCSPServer: ocspURLs, CRLDistributionPoints: crlURLs}, h.clock.Now())
}

func (h *harness) runRevocation() inventory.RevocationRunReport {
	h.t.Helper()
	require.NoError(h.t, h.lic.Tick(h.ctx)) // the gate is evaluated as license.evaluate does in production
	rep, err := h.svc.RunRevocationChecks(h.ctx)
	require.NoError(h.t, err)
	return rep
}

type revRow struct {
	Status, Method, Reason, Code string
	Failures                     int
	Next                         time.Time
	Notified                     bool
}

func (h *harness) revocationRow(l pki.Leaf) (revRow, bool) {
	h.t.Helper()
	var r revRow
	err := h.db.Owner.QueryRow(h.ctx, `SELECT status, method, reason, error_code, failures, next_check_at, notified_at IS NOT NULL
FROM revocation_checks WHERE fingerprint_sha256 = $1`, pki.Fingerprint(l.Cert)).Scan(&r.Status, &r.Method, &r.Reason, &r.Code, &r.Failures, &r.Next, &r.Notified)
	if err != nil {
		return revRow{}, false
	}
	r.Next = r.Next.UTC()
	return r, true
}

func (h *harness) uploadLeaf(a inventory.Actor, l pki.Leaf) inventory.Certificate {
	h.t.Helper()
	c, _, err := h.svc.UploadCertificate(h.ctx, a, pemUpload(l))
	require.NoError(h.t, err)
	return c
}

// HB-15: the authority revoked an uploaded certificate: it is marked revoked for good (seen by OCSP), never deployed
// again, audited and e-mailed once; the next run asks nothing more about it.
func TestRevocationRunMarksAnAuthorityRevocation(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf))
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	l := rf.leaf(h, "www.example.test", []string{revOCSP}, []string{revCRL})
	c := h.uploadLeaf(admin, l)
	at := h.clock.Now().Add(-2 * time.Hour).Truncate(time.Second)
	rf.fake.Revoke(l.Cert.SerialNumber, 1, at)

	rep := h.runRevocation()
	assert.Equal(t, 1, rep.Checked)
	assert.Equal(t, 1, rep.Revoked)
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	assert.True(t, at.Equal(*got.RevokedAt))
	assert.Equal(t, "keyCompromise", got.RevocationReason)
	assert.True(t, got.RevokedByAuthority)
	require.NotNil(t, got.RevocationCheck)
	assert.Equal(t, "revoked", got.RevocationCheck.Status)
	assert.Equal(t, "ocsp", got.RevocationCheck.Method)
	var seen string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT revocation_seen FROM certificates WHERE id = $1", c.ID).Scan(&seen))
	assert.Equal(t, "ocsp", seen)

	_, err = h.svc.RequestDeployment(h.ctx, admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{uuid.New()}})
	require.ErrorIs(t, err, inventory.ErrCertificateRevoked)
	assert.Equal(t, 1, h.audits("certificate.revoked_by_authority"))
	details := h.auditDetails("certificate.revoked_by_authority")[0]
	assert.Equal(t, "ocsp", details["method"])
	assert.Equal(t, "keyCompromise", details["reason"])
	assert.Equal(t, pki.Fingerprint(l.Cert), details["fingerprint"])
	assert.Equal(t, []string{"ada@example.com"}, h.recipients(inventory.TemplateCertificateRevokedByAuthority))
	p := h.incidentMailParams(inventory.TemplateCertificateRevokedByAuthority)[0]
	assert.Equal(t, "OCSP", p["method"])
	assert.Equal(t, at.UTC().Format("2006-01-02 15:04")+" UTC", p["revoked_at"])

	before := rf.fake.Requests("/ocsp") + rf.fake.Requests("/crl")
	h.clock.Advance(48 * time.Hour)
	assert.Zero(t, h.runRevocation().Checked)
	assert.Equal(t, before, rf.fake.Requests("/ocsp")+rf.fake.Requests("/crl"), "a revoked certificate is never asked about again")
	assert.Equal(t, 1, h.emails(inventory.TemplateCertificateRevokedByAuthority))
}

// HB-15: the current certificate of an ACME certificate that the authority revoked is due for renewal at once. The fake
// ACME CA names no revocation address, so the version's stored chain is replaced by one the fake authority issued (the
// row is otherwise the ACME version's).
func TestRevocationRunRenewsARevokedACMECertificate(t *testing.T) {
	rf := &revFake{}
	w := newACMEDeployWorldLicensed(t, true, withRevocation(t, rf))
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	l := rf.leaf(w.h, "www.example.test", []string{revOCSP}, nil)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificates SET pem_chain = $2 WHERE id = $1", cur, string(l.FullchainPEM))
	require.NoError(t, err)
	rf.fake.Revoke(l.Cert.SerialNumber, 4, w.h.clock.Now().Add(-time.Hour))
	rep := w.h.runRevocation()
	assert.Positive(t, rep.Revoked)
	require.NotNil(t, w.certOf(cur).RevokedAt)

	w.h.clock.Advance(16 * time.Minute)
	run, err := w.h.svc.PlanACMERenewals(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, run.Started, "a revoked current certificate is due at once")
}

// HB-11, HB-14: a responder that is down, answers garbage, signs with another key, a stale CRL without the serial and
// an unknown certificate never mark anything; failures back off 1, 2, 4 hours and at most a day; no mail.
func TestRevocationRunNeverMarksOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		faults map[string]fakerevocation.Fault
		status string
	}{
		{"down", map[string]fakerevocation.Fault{"/ocsp": fakerevocation.FaultDown, "/crl": fakerevocation.FaultDown}, "unavailable"},
		{"garbage", map[string]fakerevocation.Fault{"/ocsp": fakerevocation.FaultGarbage, "/crl": fakerevocation.FaultGarbage}, "unavailable"},
		{"wrong signer", map[string]fakerevocation.Fault{"/ocsp": fakerevocation.FaultWrongSigner, "/crl": fakerevocation.FaultWrongSigner}, "unavailable"},
		{"stale, not listed", map[string]fakerevocation.Fault{"/ocsp": fakerevocation.FaultDown, "/crl": fakerevocation.FaultStale}, "unavailable"},
		{"unknown", map[string]fakerevocation.Fault{"/ocsp": fakerevocation.FaultUnknown, "/crl": fakerevocation.FaultDown}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rf := &revFake{}
			h := newHarness(t, withRevocation(t, rf))
			admin := h.user("ada", rbac.Admin, "ada@example.com")
			l := rf.leaf(h, "www.example.test", []string{revOCSP}, []string{revCRL})
			c := h.uploadLeaf(admin, l)
			for path, f := range tc.faults {
				rf.fake.SetFault(path, f)
			}
			h.runRevocation()
			r, ok := h.revocationRow(l)
			require.True(t, ok)
			assert.Equal(t, tc.status, r.Status)
			got, err := h.svc.GetCertificate(h.ctx, c.ID)
			require.NoError(t, err)
			assert.Nil(t, got.RevokedAt)
			assert.Zero(t, h.emails(inventory.TemplateCertificateRevokedByAuthority)+h.emails(inventory.TemplateCertificateOnHoldByAuthority))
			if tc.status == "unknown" {
				assert.Equal(t, h.clock.Now().Add(24*time.Hour), r.Next)
			}
		})
	}

	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf))
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	l := rf.leaf(h, "www.example.test", []string{revOCSP}, nil)
	h.uploadLeaf(admin, l)
	rf.fake.SetFault("/ocsp", fakerevocation.FaultDown)
	for n, want := range []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour} {
		h.runRevocation()
		r, _ := h.revocationRow(l)
		assert.Equal(t, n+1, r.Failures)
		assert.Equal(t, revocation.CodeUnreachable, r.Code)
		assert.Equal(t, h.clock.Now().Add(want), r.Next, "failure %d", n+1)
		h.clock.Set(r.Next)
	}
	rf.fake.SetFault("/ocsp", fakerevocation.FaultNone)
	h.runRevocation()
	r, _ := h.revocationRow(l)
	assert.Equal(t, revRow{Status: "good", Method: "ocsp", Next: h.clock.Now().Add(24 * time.Hour)}, r, "a good answer clears the failures")
}

// A suspension (certificateHold) is recorded and mailed once per hold, never marked; lifted, the certificate is good
// again; a second hold mails again.
func TestRevocationRunHoldIsNotFinal(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf))
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	l := rf.leaf(h, "www.example.test", []string{revOCSP}, nil)
	c := h.uploadLeaf(admin, l)
	rf.fake.Hold(l.Cert.SerialNumber, h.clock.Now().Add(-time.Hour))
	rep := h.runRevocation()
	assert.Equal(t, 1, rep.OnHold)
	r, _ := h.revocationRow(l)
	assert.Equal(t, "on_hold", r.Status)
	assert.Equal(t, "certificateHold", r.Reason)
	assert.True(t, r.Notified)
	assert.Equal(t, h.clock.Now().Add(6*time.Hour), r.Next)
	assert.Equal(t, 1, h.emails(inventory.TemplateCertificateOnHoldByAuthority))
	assert.Equal(t, 1, h.audits("certificate.revocation_on_hold"))
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Nil(t, got.RevokedAt, "a hold is not final")

	h.clock.Advance(6 * time.Hour)
	h.runRevocation()
	assert.Equal(t, 1, h.emails(inventory.TemplateCertificateOnHoldByAuthority), "the same hold is mailed once")

	rf.fake.Release(l.Cert.SerialNumber)
	h.clock.Advance(6 * time.Hour)
	h.runRevocation()
	r, _ = h.revocationRow(l)
	assert.Equal(t, "good", r.Status)
	assert.False(t, r.Notified, "lifted: the next hold is news")

	rf.fake.Hold(l.Cert.SerialNumber, h.clock.Now())
	h.clock.Advance(24 * time.Hour)
	h.runRevocation()
	assert.Equal(t, 2, h.emails(inventory.TemplateCertificateOnHoldByAuthority))
}

// A leaf network discovery found, with its issuer in the chain an endpoint presented, is checked too; revoked, the
// scope's service is mailed and no certificate row changes.
func TestRevocationRunChecksDiscoveredLeaves(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf), withTrustedRevocationRoot(rf))
	h.user("ada", rbac.Admin, "ada@example.com")
	payments := h.newService("Payments")
	h.owner(payments, "pia", "pia@example.com")
	l := rf.leaf(h, "lan.example.test", []string{revOCSP}, nil)
	scope, err := seed.DiscoveryScope(h.ctx, h.db.App, "LAN", false)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE discovery_scopes SET service_id = $2 WHERE id = $1", scope, payments)
	require.NoError(t, err)
	interFP := pki.Fingerprint(rf.ca.Intermediate)
	for _, row := range []struct {
		fp, pem string
		leaf    bool
	}{{pki.Fingerprint(l.Cert), string(l.CertPEM), true}, {interFP, string(rf.ca.IntermediatePEM), false}} {
		_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, not_before, not_after, key_algorithm,
    pem, first_seen, last_seen) VALUES ($1, $2, 'lan.example.test', $3, $4, 'ecdsa', $5, $3, $3)`, row.fp, row.leaf, h.clock.Now().Add(-time.Hour),
			h.clock.Now().Add(30*24*time.Hour), row.pem)
		require.NoError(t, err)
	}
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, chain_fingerprints, state, first_seen,
    last_seen, last_scanned_at) VALUES ($1, $2, '10.0.0.9', 443, $3, ARRAY[$4], 'present', now(), now(), now())`, uuid.New(), scope, pki.Fingerprint(l.Cert), interFP)
	require.NoError(t, err)
	rf.fake.Revoke(l.Cert.SerialNumber, 5, h.clock.Now().Add(-time.Hour))

	rep := h.runRevocation()
	assert.Equal(t, 1, rep.Revoked)
	r, ok := h.revocationRow(l)
	require.True(t, ok)
	assert.Equal(t, "revoked", r.Status)
	assert.Equal(t, "cessationOfOperation", r.Reason)
	assert.Equal(t, []string{"ada@example.com", "pia@example.com"}, h.recipients(inventory.TemplateCertificateRevokedByAuthorityDiscovered))
	assert.Contains(t, h.incidentMailParams(inventory.TemplateCertificateRevokedByAuthorityDiscovered)[0]["endpoints"], "10.0.0.9:443")
	assert.Zero(t, h.count("SELECT count(*) FROM certificates WHERE revoked_at IS NOT NULL"))
	assert.Zero(t, h.audits("certificate.revoked_by_authority"))
	h.clock.Advance(48 * time.Hour)
	h.runRevocation()
	assert.Equal(t, 2, h.emails(inventory.TemplateCertificateRevokedByAuthorityDiscovered), "one e-mail per recipient, once")
}

// HB-14: 300 due certificates on one OCSP host: one run selects at most 200 and asks at most 50; the rest stay due.
func TestRevocationRunBudget(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf))
	for n := range 300 {
		l := rf.leaf(h, "bulk.example.test", []string{revOCSP}, nil)
		sum := sha256.Sum256(l.Cert.Raw)
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at, subject_cn) VALUES ($1, $2, $3, $4, 'ecdsa', $5, $6, 'discovered', now(), now(), now(), $7)`,
			uuid.New(), hex.EncodeToString(sum[:]), l.Cert.NotBefore, l.Cert.NotAfter, strings.Repeat("ab", 32), string(l.FullchainPEM), "bulk-"+string(rune('a'+n%26)))
		require.NoError(t, err)
	}
	rep := h.runRevocation()
	assert.Equal(t, 50, rep.Checked)
	assert.Equal(t, 150, rep.Deferred)
	assert.Equal(t, 50, rf.fake.Requests("/ocsp"))
	assert.Equal(t, 50, h.count("SELECT count(*) FROM revocation_checks"))
	rep = h.runRevocation()
	assert.Equal(t, 50, rep.Checked, "the next run takes the next ones")
	assert.Equal(t, 100, h.count("SELECT count(*) FROM revocation_checks"))
}

// HB-16: switched off, the licence locked or no checker: no request is made.
func TestRevocationRunSkipsWhenOffLockedOrUnconfigured(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf))
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	h.uploadLeaf(admin, rf.leaf(h, "www.example.test", []string{revOCSP}, []string{revCRL}))
	set, err := h.svc.SaveRevocationSettings(h.ctx, admin.Audit, 0, false)
	require.NoError(t, err)
	assert.Zero(t, h.runRevocation())
	assert.Zero(t, rf.fake.Requests("/ocsp")+rf.fake.Requests("/crl"), "switched off")
	_, err = h.svc.SaveRevocationSettings(h.ctx, admin.Audit, set.Version, true)
	require.NoError(t, err)

	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	assert.Zero(t, h.runRevocation())
	assert.Zero(t, rf.fake.Requests("/ocsp")+rf.fake.Requests("/crl"), "locked")

	bare := newHarness(t)
	rep, err := bare.svc.RunRevocationChecks(bare.ctx)
	require.NoError(t, err)
	assert.Zero(t, rep, "no checker configured")
}

// The switch: a fresh database reads on; a save needs the version read, is audited and counts the version up.
func TestRevocationSettingsDefaults(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	set, err := h.svc.RevocationSettings(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.RevocationSettings{Enabled: true, Version: 0}, set)
	set, err = h.svc.SaveRevocationSettings(h.ctx, admin.Audit, 0, false)
	require.NoError(t, err)
	assert.Equal(t, inventory.RevocationSettings{Enabled: false, Version: 1}, set)
	assert.Equal(t, []map[string]string{{"enabled": "false"}}, h.auditDetails("settings.revocation_check_changed"))
	_, err = h.svc.SaveRevocationSettings(h.ctx, admin.Audit, 0, true)
	require.ErrorIs(t, err, inventory.ErrRevocationSettingsVersion)
	got, err := h.svc.RevocationSettings(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, set, got)
}

// Without a notifier (Config.Notifier nil: no e-mails) the incident engine and the revocation check still move and
// mark; nothing is queued and nothing panics (final review, R64).
func TestIncidentAndRevocationWorkWithoutANotifier(t *testing.T) {
	noMail := func(c *inventory.Config) { c.Notifier = nil }
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf), noMail)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	l := rf.leaf(h, "www.example.test", []string{revOCSP}, nil)
	c := h.uploadLeaf(admin, l)
	rf.fake.Revoke(l.Cert.SerialNumber, 1, h.clock.Now().Add(-time.Hour))
	assert.Equal(t, 1, h.runRevocation().Revoked)
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)

	f := newDeployFixture(t, noMail)
	f.h.installLicense("LIC-NO-MAIL", 5, 365)
	require.NoError(t, f.h.lic.Tick(f.h.ctx))
	w := &acmeDeployWorld{deployFixture: f}
	_, _, err = f.h.svc.UploadCertificate(f.h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))
	i, err := f.h.svc.StartIncident(f.h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = f.h.svc.ChooseIncidentReplacement(f.h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	w.advance()
	require.Positive(t, w.endRunning(i.ID, inventory.DeployStatusFailed))
	w.advance()
	assert.Equal(t, inventory.IncidentNeedsAttention, w.incident(i.ID).State)
	assert.Zero(t, f.h.count("SELECT count(*) FROM notifications_outbox"))
}

// withTrustedRevocationRoot makes the fake authority's root a trusted root (Config.Roots), as a public CA's root is in
// the system pool. Listed after withRevocation, which creates the authority.
func withTrustedRevocationRoot(rf *revFake) harnessOption {
	return func(c *inventory.Config) {
		pool := x509.NewCertPool()
		pool.AddCert(rf.ca.Root)
		c.Roots = pool
	}
}

// discoveredLeaf stores a leaf network discovery found on 10.0.0.<n>:443 with its issuer in the presented chain.
func (h *harness) discoveredLeaf(scope uuid.UUID, l pki.Leaf, issuer *x509.Certificate, issuerPEM []byte, cn string, n int) {
	h.t.Helper()
	for _, row := range []struct {
		fp, pem, cn string
		leaf        bool
	}{{pki.Fingerprint(l.Cert), string(l.CertPEM), cn, true}, {pki.Fingerprint(issuer), string(issuerPEM), "issuer", false}} {
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, not_before, not_after, key_algorithm,
    pem, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, 'ecdsa', $6, $4, $4) ON CONFLICT DO NOTHING`, row.fp, row.leaf, row.cn,
			h.clock.Now().Add(-time.Hour), h.clock.Now().Add(30*24*time.Hour), row.pem)
		require.NoError(h.t, err)
	}
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, chain_fingerprints, state, first_seen,
    last_seen, last_scanned_at) VALUES ($1, $2, $3::inet, 443, $4, ARRAY[$5], 'present', now(), now(), now())`, uuid.New(), scope,
		fmt.Sprintf("10.0.%d.%d", n/250, n%250+1), pki.Fingerprint(l.Cert), pki.Fingerprint(issuer))
	require.NoError(h.t, err)
}

// Final review I1, ruling 42: a discovered leaf whose presented chain does not reach a trusted root (and whose issuer
// is no inventory certificate) is not checked: no request goes to the address it names, and nothing is mailed.
func TestRevocationRunSkipsDiscoveredLeavesOfUntrustedIssuers(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf)) // the fake authority's root is not trusted
	h.user("ada", rbac.Admin, "ada@example.com")
	scope, err := seed.DiscoveryScope(h.ctx, h.db.App, "LAN", false)
	require.NoError(t, err)
	l := rf.leaf(h, "lan.example.test", []string{revOCSP}, []string{revCRL})
	h.discoveredLeaf(scope, l, rf.ca.Intermediate, rf.ca.IntermediatePEM, "lan.example.test", 1)
	rf.fake.Revoke(l.Cert.SerialNumber, 1, h.clock.Now().Add(-time.Hour))
	h.runRevocation()
	r, ok := h.revocationRow(l)
	require.True(t, ok)
	assert.Equal(t, "not_checkable", r.Status)
	assert.Equal(t, revocation.CodeUntrustedIssuer, r.Code)
	assert.Zero(t, rf.fake.Requests("/ocsp")+rf.fake.Requests("/crl"), "no request to an address an untrusted certificate names")
	assert.Zero(t, h.emails(inventory.TemplateCertificateRevokedByAuthorityDiscovered))

	// An issuer Alice holds in her inventory (not one discovery found) is trusted without a root.
	sum := sha256.Sum256(rf.ca.Intermediate.Raw)
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at, subject_cn, self_signed) VALUES ($1, $2, $3, $4, 'ecdsa', $5, $6, 'uploaded', now(), now(), now(),
'issuer', false)`, uuid.New(), hex.EncodeToString(sum[:]), rf.ca.Intermediate.NotBefore, h.clock.Now().Add(-time.Minute), strings.Repeat("cd", 32),
		string(rf.ca.IntermediatePEM))
	require.NoError(t, err)
	h.clock.Advance(8 * 24 * time.Hour)
	h.runRevocation()
	r, _ = h.revocationRow(l)
	assert.Equal(t, "revoked", r.Status, "the issuer is an uploaded inventory certificate")
}

// Final review I1: at most 20 discovered-revocation mails per run (the rest recorded and counted); the name in a mail
// is printable.
func TestRevocationRunCapsDiscoveredMails(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf), withTrustedRevocationRoot(rf))
	h.user("ada", rbac.Admin, "ada@example.com")
	scope, err := seed.DiscoveryScope(h.ctx, h.db.App, "LAN", false)
	require.NoError(t, err)
	for n := range 25 {
		l := rf.leaf(h, "lan.example.test", []string{revOCSP}, nil)
		h.discoveredLeaf(scope, l, rf.ca.Intermediate, rf.ca.IntermediatePEM, "evil\x1b[31m\u202e"+strings.Repeat("x", n), n)
		rf.fake.Revoke(l.Cert.SerialNumber, 1, h.clock.Now().Add(-time.Hour))
	}
	rep := h.runRevocation()
	assert.Equal(t, 25, rep.Revoked)
	assert.Equal(t, 5, rep.MailsSuppressed)
	assert.Equal(t, 20, h.emails(inventory.TemplateCertificateRevokedByAuthorityDiscovered))
	for _, p := range h.incidentMailParams(inventory.TemplateCertificateRevokedByAuthorityDiscovered) {
		assert.True(t, strings.HasPrefix(p["certificate_name"], "evil?[31m?"), p["certificate_name"])
	}
}

// Final review I2: two runs recording the same first result at once queue one mail set.
func TestRevocationRunRecordsOnceUnderConcurrency(t *testing.T) {
	rf := &revFake{}
	h := newHarness(t, withRevocation(t, rf), withTrustedRevocationRoot(rf))
	h.user("ada", rbac.Admin, "ada@example.com")
	scope, err := seed.DiscoveryScope(h.ctx, h.db.App, "LAN", false)
	require.NoError(t, err)
	l := rf.leaf(h, "lan.example.test", []string{revOCSP}, nil)
	h.discoveredLeaf(scope, l, rf.ca.Intermediate, rf.ca.IntermediatePEM, "lan.example.test", 1)
	rf.fake.Revoke(l.Cert.SerialNumber, 1, h.clock.Now().Add(-time.Hour))
	require.NoError(t, h.lic.Tick(h.ctx))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.svc.RunRevocationChecks(h.ctx)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, h.emails(inventory.TemplateCertificateRevokedByAuthorityDiscovered), "one Administrator, one e-mail")
}
