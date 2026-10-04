//go:build integration

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// keyDER is the PKCS#8 DER inside a "PRIVATE KEY" PEM.
func keyDER(t *testing.T, keyPEM []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(keyPEM)
	require.NotNil(t, b)
	return b.Bytes
}

func fieldsOf(err error) map[string]string {
	var verrs validate.Errors
	if !errors.As(err, &verrs) {
		return nil
	}
	out := map[string]string{}
	for _, f := range verrs {
		out[f.Field] = f.Code
	}
	return out
}

func rejectReasons(h *harness) []string {
	var reasons []string
	for _, d := range h.auditDetails("certificate.upload_rejected") {
		reasons = append(reasons, d["reason"])
	}
	return reasons
}

func pemUpload(l pki.Leaf) inventory.UploadInput {
	return inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM)}
}

func TestUploadStoresTheKeyEncrypted(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	c, warnings, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM),
		PrivateKeyPEM: string(l.KeyPEM), Label: "Web 2026"})
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, warnings, "the test root is not a system root")
	assert.Equal(t, "uploaded", c.Source)
	assert.True(t, c.HasPrivateKey)
	assert.Equal(t, "Web 2026", c.Label)
	assert.Equal(t, pki.Fingerprint(l.Cert), c.Fingerprint)
	assert.Equal(t, string(l.FullchainPEM), c.PEMChain)
	assert.Equal(t, []string{"www.example.test"}, c.SANs)
	var ct []byte
	var owner, alg string
	var bits int
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT ciphertext, owner_type, algorithm, bits FROM managed_private_keys").
		Scan(&ct, &owner, &alg, &bits))
	assert.NotContains(t, string(ct), "PRIVATE", "S-04: only ciphertext")
	assert.NotContains(t, string(ct), string(keyDER(t, l.KeyPEM)[30:60]))
	assert.Equal(t, "certificate", owner)
	assert.Equal(t, "ecdsa", alg)
	assert.Equal(t, 256, bits)
	assert.Equal(t, 1, h.count(`SELECT count(*) FROM certificates c
JOIN managed_private_keys k ON k.id = c.private_key_id AND k.public_key_sha256 = c.public_key_sha256`))
	d := h.auditDetails("certificate.uploaded")
	require.Len(t, d, 1)
	assert.Equal(t, pki.Fingerprint(l.Cert), d[0]["fingerprint"])
	assert.Equal(t, c.ID.String(), d[0]["certificate_id"])
	assert.Equal(t, "uploaded", d[0]["source"])
	assert.Equal(t, "pem", d[0]["format"])
	assert.Equal(t, "chain_incomplete", d[0]["warnings"], "the warnings are kept in the audit trail")
	var details string // every audit row's details, as text
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log").Scan(&details))
	assert.NotContains(t, details, string(l.KeyPEM[30:70]))

	// The sealed key opens to the uploaded key, and only for its own row: the AAD binds the id.
	var keyID uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT private_key_id FROM certificates").Scan(&keyID))
	pt, err := h.svc.LoadKey(h.ctx, keyID)
	require.NoError(t, err)
	assert.Equal(t, keyDER(t, l.KeyPEM), pt.Bytes())
	pt.Zero()
	copyID := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
wrapped_dek, key_version, created_at) SELECT $1, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek,
key_version, created_at FROM managed_private_keys WHERE id = $2`, copyID, keyID)
	require.NoError(t, err)
	_, err = h.svc.LoadKey(h.ctx, copyID)
	require.Error(t, err, "an envelope copied to another row does not open")
	_, err = h.svc.LoadKey(h.ctx, uuid.Must(uuid.NewV7()))
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestUploadKeyFormatsAndPFX(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.RSA2048, h.clock.Now())
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, h.clock.Now())
	ecLeaf := ca.Issue(pki.Opts{CommonName: "ec.example.test", KeyType: pki.ECDSA384}, h.clock.Now())
	pfxLeaf := ca.Issue(pki.Opts{CommonName: "pfx.example.test"}, h.clock.Now())

	// PKCS#1 and SEC 1 keys, with CRLF and surrounding blanks, are stored as PKCS#8.
	pkcs1 := "\n  " + strings.ReplaceAll(string(pki.KeyPEMPKCS1(rsaLeaf.Key.(*rsa.PrivateKey))), "\n", "\r\n") + "  \n"
	c, _, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(rsaLeaf.FullchainPEM), PrivateKeyPEM: pkcs1})
	require.NoError(t, err)
	assert.Equal(t, "rsa", c.KeyAlgorithm)
	assert.Equal(t, 2048, c.KeyBits)
	c, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(ecLeaf.FullchainPEM),
		PrivateKeyPEM: string(pki.KeyPEMSEC1(ecLeaf.Key.(*ecdsa.PrivateKey)))})
	require.NoError(t, err)
	assert.Equal(t, 384, c.KeyBits)
	var pt []byte
	for _, l := range []pki.Leaf{rsaLeaf, ecLeaf} {
		var id uuid.UUID
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT private_key_id FROM certificates WHERE fingerprint_sha256 = $1",
			pki.Fingerprint(l.Cert)).Scan(&id))
		k, err := h.svc.LoadKey(h.ctx, id)
		require.NoError(t, err)
		pt = append(pt[:0], k.Bytes()...)
		k.Zero()
		assert.Equal(t, keyDER(t, l.KeyPEM), pt, "stored as PKCS#8")
	}

	// A PFX with its chain, audited with its format.
	c, warnings, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{
		PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(pfxLeaf, ca, "s3cret-pfx")), PFXPassword: "s3cret-pfx", Label: "From PFX"})
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, warnings)
	assert.Equal(t, pki.Fingerprint(pfxLeaf.Cert), c.Fingerprint)
	assert.Equal(t, string(pfxLeaf.FullchainPEM), c.PEMChain)
	assert.True(t, c.HasPrivateKey)
	d := h.auditDetails("certificate.uploaded")
	require.Len(t, d, 3)
	assert.Equal(t, "pfx", d[2]["format"])
	assert.Equal(t, 3, h.count("SELECT count(*) FROM managed_private_keys"))
}

func TestUploadRefusalsAreAuditedAndStoreNothing(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	now := h.clock.Now()
	l, other := ca.Issue(pki.Opts{CommonName: "a"}, now), ca.Issue(pki.Opts{CommonName: "b"}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-time.Minute)}, now)
	weak := ca.Issue(pki.Opts{CommonName: "weak", KeyType: pki.RSA1024}, now)
	p521 := ca.Issue(pki.Opts{CommonName: "p521", KeyType: pki.ECDSA521}, now)
	for _, tc := range []struct {
		in     inventory.UploadInput
		err    error
		reason string
	}{
		{inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(other.KeyPEM)}, inventory.ErrKeyMismatch, "key_mismatch"},
		{inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(l, ca, "pw")), PFXPassword: "no"}, inventory.ErrPFXPassword, "pfx_password"},
		{inventory.UploadInput{PFXBase64: "!!!"}, inventory.ErrCertificateInvalid, "invalid"},
		{pemUpload(expired), inventory.ErrCertificateExpired, "expired"},
		{inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(pki.EncryptedKeyPEM(l))}, inventory.ErrKeyEncrypted, "key_encrypted"},
		{pemUpload(weak), inventory.ErrWeakCertificate, "weak"},
		{pemUpload(p521), inventory.ErrUnsupportedKey, "unsupported_key"},
		{inventory.UploadInput{CertificatePEM: strings.Repeat("x", 256<<10+1), PrivateKeyPEM: string(l.KeyPEM)}, inventory.ErrCertificateTooLarge, "too_large"},
		{inventory.UploadInput{PFXBase64: strings.Repeat("A", 400<<10)}, inventory.ErrCertificateTooLarge, "too_large"},
		{inventory.UploadInput{CertificatePEM: "not a certificate", PrivateKeyPEM: string(l.KeyPEM)}, inventory.ErrCertificateInvalid, "invalid"},
	} {
		_, _, err := h.svc.UploadCertificate(h.ctx, op, tc.in)
		assert.ErrorIs(t, err, tc.err, tc.reason)
		assert.Nil(t, fieldsOf(err))
	}
	assert.Equal(t, []string{"key_mismatch", "pfx_password", "invalid", "expired", "key_encrypted", "weak", "unsupported_key", "too_large",
		"too_large", "invalid"}, rejectReasons(h))

	// Field errors: a PEM upload's are not audited; every PFX attempt is (the carried mitigation).
	_, _, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{})
	assert.Equal(t, map[string]string{"certificate_pem": validate.Required, "private_key_pem": validate.Required,
		"pfx_base64": validate.Required}, fieldsOf(err), "neither PEM nor PFX")
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: "x", PFXBase64: "eA=="})
	assert.Equal(t, map[string]string{"pfx_base64": validate.Pattern}, fieldsOf(err), "both PEM and PFX")
	// D21: a key of blanks only is a missing key, not a server error.
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: " \r\n\t "})
	assert.Equal(t, map[string]string{"private_key_pem": validate.Required}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PrivateKeyPEM: string(l.KeyPEM)})
	assert.Equal(t, map[string]string{"certificate_pem": validate.Required}, fieldsOf(err))
	// A key pasted into the certificate field is never used from there: the person is told to put it
	// in the key field (the contract has no combined paste).
	combined := string(l.FullchainPEM) + string(l.KeyPEM)
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: combined, PrivateKeyPEM: string(l.KeyPEM)})
	assert.Equal(t, map[string]string{"certificate_pem": inventory.CodeKeyInCertificate}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: combined})
	assert.Equal(t, map[string]string{"certificate_pem": inventory.CodeKeyInCertificate, "private_key_pem": validate.Required}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM),
		Label: "tab\there"})
	assert.Equal(t, map[string]string{"label": validate.Pattern}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM),
		Label: strings.Repeat("ş", 101)})
	assert.Equal(t, map[string]string{"label": validate.TooLong}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(l.KeyPEM),
		Label: "\xff"})
	assert.Equal(t, map[string]string{"label": validate.Pattern}, fieldsOf(err))
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: "eA==", Label: "\x00"})
	assert.Equal(t, map[string]string{"label": validate.Pattern}, fieldsOf(err))

	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM managed_private_keys"))
	assert.Equal(t, []string{"key_mismatch", "pfx_password", "invalid", "expired", "key_encrypted", "weak", "unsupported_key", "too_large",
		"too_large", "invalid", "validation", "validation"}, rejectReasons(h))
	for _, d := range h.auditDetails("certificate.upload_rejected") {
		assert.Contains(t, []string{"pem", "pfx"}, d["format"])
	}
	assert.Equal(t, 12, h.count("SELECT count(*) FROM audit_log WHERE action = 'certificate.upload_rejected' AND result = 'failure' AND actor_id = $1",
		op.UserID))
}

// The key of a certificate found on a server can be added later; the same pair twice is refused
// and stores nothing more.
func TestUploadAttachesTheKeyOfADiscoveredCertificate(t *testing.T) {
	ca := pki.NewCA("Up", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	leafOnly := providers.DiscoveredCertificate{Location: cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"),
		PEMChain: l.CertPEM, FileSHA256: sha(l.CertPEM)}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{leafOnly}})
	require.NoError(t, err)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	discovered := page.Items[0]
	require.False(t, discovered.ChainComplete)
	firstSeen := discovered.FirstSeenAt

	h.clock.Advance(time.Hour)
	op := h.user("oya", rbac.Operator, "")
	in := pemUpload(l)
	in.Label = "Web"
	c, warnings, err := h.svc.UploadCertificate(h.ctx, op, in)
	require.NoError(t, err)
	assert.Equal(t, []string{}, warnings, "the chain is complete with the configured roots")
	assert.Equal(t, discovered.ID, c.ID, "the same certificate")
	assert.Equal(t, "discovered", c.Source, "the source is not rewritten")
	assert.True(t, c.HasPrivateKey)
	assert.Equal(t, "Web", c.Label, "an empty label takes the upload's")
	assert.True(t, c.ChainComplete, "a complete chain replaces an incomplete one")
	assert.Equal(t, string(l.FullchainPEM), c.PEMChain)
	assert.Equal(t, firstSeen, c.FirstSeenAt)
	assert.Equal(t, 1, c.LocationCount)
	require.Len(t, h.auditDetails("certificate.key_attached"), 1)
	assert.Equal(t, map[string]string{"certificate_id": c.ID.String(), "fingerprint": c.Fingerprint, "format": "pem", "algorithm": "ecdsa",
		"bits": "256", "warnings": ""}, h.auditDetails("certificate.key_attached")[0])
	assert.Equal(t, 0, h.audits("certificate.uploaded"))

	// Again: refused, nothing stored, nothing changed.
	in.Label = "Other"
	_, _, err = h.svc.UploadCertificate(h.ctx, op, in)
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM managed_private_keys"))
	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "Web", got.Label)
	assert.Equal(t, []string{"duplicate"}, rejectReasons(h))
	assert.Equal(t, c.Fingerprint, h.auditDetails("certificate.upload_rejected")[0]["fingerprint"])

	// A later scan keeps the key, the label, the source and the better chain.
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{leafOnly}})
	require.NoError(t, err)
	got, err = h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, got.HasPrivateKey)
	assert.Equal(t, "Web", got.Label)
	assert.Equal(t, "discovered", got.Source)
	assert.Equal(t, string(l.FullchainPEM), got.PEMChain)
}

// An upload whose chain is worse than the stored one never replaces it, and the warnings describe
// what Alice holds.
func TestUploadNeverDowngradesAChain(t *testing.T) {
	ca := pki.NewCA("Up", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), l)}})
	require.NoError(t, err)
	c, warnings, err := h.svc.UploadCertificate(h.ctx, admin, inventory.UploadInput{CertificatePEM: string(l.CertPEM), PrivateKeyPEM: string(l.KeyPEM)})
	require.NoError(t, err)
	assert.Equal(t, []string{}, warnings, "Alice holds the complete chain")
	assert.True(t, c.ChainComplete)
	assert.Equal(t, string(l.FullchainPEM), c.PEMChain)
}

// SANs and text are bounded as discovery bounds them: a SAN longer than a DNS name is dropped.
func TestUploadBoundsCertificateText(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".example.test"
	require.Greater(t, len(long), 253)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", long}}, h.clock.Now())
	c, _, err := h.svc.UploadCertificate(h.ctx, op, pemUpload(l))
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.test"}, c.SANs)
}

// Discovery and an upload of the same certificate at the same time: one row, the key attached,
// no deadlock and no error (uploads insert with ON CONFLICT, as discovery does).
func TestUploadRacesDiscovery(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	const rounds = 12
	for i := range rounds {
		l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, errs[0] = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK,
				Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), l)}})
		}()
		go func() {
			defer wg.Done()
			_, _, errs[1] = h.svc.UploadCertificate(h.ctx, admin, pemUpload(l))
		}()
		wg.Wait()
		require.NoError(t, errs[0], i)
		require.NoError(t, errs[1], i)
		assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates WHERE fingerprint_sha256 = $1 AND private_key_id IS NOT NULL",
			pki.Fingerprint(l.Cert)), i)
	}
	assert.Equal(t, rounds, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, rounds, h.count("SELECT count(*) FROM managed_private_keys"))
	assert.Equal(t, rounds, h.audits("certificate.uploaded")+h.audits("certificate.key_attached"))
}

// The upload's insert meets a scan's uncommitted insert of the same certificate: it waits, yields
// to it (ON CONFLICT DO NOTHING), reads the row again and attaches the key.
func TestUploadYieldsToAConcurrentInsert(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	p, err := certs.ParseChainPEM(l.FullchainPEM)
	require.NoError(t, err)
	tx, err := h.db.Owner.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	scanned := uuid.Must(uuid.NewV7())
	_, err = tx.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, key_bits, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at) VALUES ($1, $2, $3, $4, 'ecdsa', 256, $5, $6, 'discovered', $7, $7, $7)`,
		scanned, p.Fingerprint, p.NotBefore, p.NotAfter, p.PublicKeySHA256, p.PEMChain, h.clock.Now())
	require.NoError(t, err)
	type result struct {
		c   inventory.Certificate
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, _, err := h.svc.UploadCertificate(h.ctx, op, pemUpload(l))
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the upload did not wait for the scan's insert: %+v", r.err)
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(h.ctx))
	r := <-done
	require.NoError(t, r.err)
	assert.Equal(t, scanned, r.c.ID)
	assert.Equal(t, "discovered", r.c.Source)
	assert.True(t, r.c.HasPrivateKey)
	assert.Equal(t, 1, h.audits("certificate.key_attached"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM managed_private_keys"), "the key stored before the insert is the one attached")
}

// Two uploads of the same pair at the same time: one wins, the other is a duplicate; one key row.
func TestConcurrentUploadsOfOnePair(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = h.svc.UploadCertificate(h.ctx, op, pemUpload(l))
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, inventory.ErrCertificateDuplicate)
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM managed_private_keys"))
}

// The carried PFX mitigation: at most two PFX files are decoded at once; a third is refused at
// once with a retryable error and audited. PEM uploads do not wait for PFX decodes. Every path
// gives the slot back.
func TestPFXDecodesAreCapped(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "pfx.example.test"}, h.clock.Now())
	pfx := inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(l, ca, "pw")), PFXPassword: "pw"}

	// Failures of every kind give the slot back.
	for _, in := range []inventory.UploadInput{{PFXBase64: "!!!"}, {PFXBase64: pfx.PFXBase64, PFXPassword: "wrong"},
		{PFXBase64: base64.StdEncoding.EncodeToString([]byte("not a pfx"))}} {
		_, _, err := h.svc.UploadCertificate(h.ctx, op, in)
		require.Error(t, err)
	}
	release, ok := inventory.HoldPFXSlots(2)
	require.True(t, ok, "both slots are free after the failures")

	_, _, err := h.svc.UploadCertificate(h.ctx, op, pfx)
	require.ErrorIs(t, err, inventory.ErrPFXBusy)
	assert.Equal(t, "busy", rejectReasons(h)[len(rejectReasons(h))-1])
	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificates"))
	pemLeaf := ca.Issue(pki.Opts{CommonName: "pem.example.test"}, h.clock.Now())
	_, _, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(pemLeaf))
	require.NoError(t, err, "a PEM upload does not need a PFX slot")
	release()

	_, _, err = h.svc.UploadCertificate(h.ctx, op, pfx)
	require.NoError(t, err)
	release, ok = inventory.HoldPFXSlots(2)
	require.True(t, ok, "the slot is back after a success")
	release()
	assert.Equal(t, []string{"invalid", "pfx_password", "pfx_password", "busy"}, rejectReasons(h))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'certificate.uploaded' AND details->>'format' = 'pfx'"))
}

// Every PFX attempt is on record, even one the database failed (here: the request was cancelled
// before the transaction began); the record does not depend on the request's context.
func TestFailedPFXUploadIsAudited(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "pfx.example.test"}, h.clock.Now())
	ctx, cancel := context.WithCancel(h.ctx)
	cancel()
	_, _, err := h.svc.UploadCertificate(ctx, op, inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(l, ca, "pw")),
		PFXPassword: "pw"})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"internal"}, rejectReasons(h))
	assert.Equal(t, pki.Fingerprint(l.Cert), h.auditDetails("certificate.upload_rejected")[0]["fingerprint"])
	assert.Equal(t, 0, h.count("SELECT count(*) FROM managed_private_keys"))
	release, ok := inventory.HoldPFXSlots(2)
	require.True(t, ok)
	release()
}

// The PFX size bound is on the file, not its text: line breaks of a wrapped base64 do not count.
func TestPFXSizeBoundIgnoresLineBreaks(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	wrap := func(n int) string {
		text := base64.StdEncoding.EncodeToString(make([]byte, n))
		var b strings.Builder
		for len(text) > 64 {
			b.WriteString(text[:64] + "\r\n")
			text = text[64:]
		}
		b.WriteString(text)
		return b.String()
	}
	limit := 256 << 10
	require.Greater(t, len(wrap(limit)), base64.StdEncoding.EncodedLen(limit), "the wrapped text is longer than the bound's encoding")
	_, _, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: wrap(limit), PFXPassword: "pw"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, inventory.ErrCertificateTooLarge, "a file of exactly 256 KiB is read")
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: wrap(limit + 1), PFXPassword: "pw"})
	require.ErrorIs(t, err, inventory.ErrCertificateTooLarge)
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: "ZW Fz\neQ==", PFXPassword: "pw"})
	require.ErrorIs(t, err, inventory.ErrPFXPassword, "blanks inside the text are ignored")
}

// A panic while a file is decoded becomes an internal error: the attempt is audited, the PFX slot
// comes back, and neither the audit nor the log carries the panic's text.
func TestDecoderPanicIsAnAuditedInternalError(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	restore := inventory.SetValidateUpload(func(certs.Upload, time.Time, *x509.CertPool) (certs.Validated, error) {
		panic("decoder exploded on SECRET-INPUT")
	})
	defer restore()
	_, _, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{PFXBase64: "eA==", PFXPassword: "pw"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET-INPUT")
	for _, sentinel := range []error{inventory.ErrCertificateInvalid, inventory.ErrPFXPassword, inventory.ErrCertificateTooLarge} {
		assert.NotErrorIs(t, err, sentinel)
	}
	assert.Equal(t, []string{"internal"}, rejectReasons(h))
	release, ok := inventory.HoldPFXSlots(2)
	require.True(t, ok, "the slot is back")
	release()
	assert.Contains(t, h.logs.String(), "decoding an uploaded certificate failed")
	assert.NotContains(t, h.logs.String(), "SECRET-INPUT")
	var details string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log").Scan(&details))
	assert.NotContains(t, details, "SECRET-INPUT")
}

// AUD-17 (independent audit of 2026-10-04): an incomplete chain is completed by uploading the same
// certificate again with a complete chain (audited certificate.chain_completed, the key not stored
// again); every other repeated upload stays a duplicate.
func TestUploadCompletesTheIncompleteChainOfAHeldCertificate(t *testing.T) {
	ca := pki.NewCA("Pub", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	op := h.user("oya", rbac.Operator, "")
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	leafOnly := inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)}

	c, warnings, err := h.svc.UploadCertificate(h.ctx, op, leafOnly)
	require.NoError(t, err)
	require.Equal(t, []string{"chain_incomplete"}, warnings)
	_, _, err = h.svc.UploadCertificate(h.ctx, op, leafOnly)
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate, "an incomplete chain again is a duplicate")
	keys := h.count("SELECT count(*) FROM managed_private_keys")

	got, warnings, err := h.svc.UploadCertificate(h.ctx, op, pemUpload(leaf))
	require.NoError(t, err)
	assert.Equal(t, []string{inventory.WarnChainCompleted}, warnings)
	assert.Equal(t, c.ID, got.ID)
	assert.True(t, got.ChainComplete)
	assert.Equal(t, string(leaf.FullchainPEM), got.PEMChain)
	assert.Equal(t, keys, h.count("SELECT count(*) FROM managed_private_keys"), "the key is not stored again")
	assert.Equal(t, []map[string]string{{"certificate_id": c.ID.String(), "fingerprint": c.Fingerprint, "format": "pem"}},
		h.auditDetails("certificate.chain_completed"))

	_, _, err = h.svc.UploadCertificate(h.ctx, op, pemUpload(leaf))
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate, "a complete chain is never replaced")
	_, _, err = h.svc.UploadCertificate(h.ctx, op, leafOnly)
	require.ErrorIs(t, err, inventory.ErrCertificateDuplicate)
	assert.Len(t, h.auditDetails("certificate.chain_completed"), 1)
}
