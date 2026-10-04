//go:build integration

package inventory_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// B1-I1 (and the independent audit of 2026-10-04, AUD-17): a discovery on one server never
// rewrites the chain of a certificate a person uploaded (with its key): a scanned server's file
// that holds the same leaf with an unrelated certificate and the real intermediate leaves the stored
// chain, chain_complete and what a deployment to another server sends unchanged.
func TestDiscoveryNeverRewritesAnUploadedCertificatesChain(t *testing.T) {
	ca := pki.NewCA("Pub", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withNginxProvider(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	leaf := ca.Issue(www, h.clock.Now())

	c, warnings, err := h.svc.UploadCertificate(h.ctx, admin, inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	require.Contains(t, warnings, "chain_incomplete")
	require.Equal(t, string(leaf.CertPEM), c.PEMChain)

	// A less trusted server holds the public leaf with a certificate of its own choosing and the real
	// intermediate: the file would "complete" the chain.
	junk := pki.SelfSigned("attacker-chosen.example", pki.ECDSA256, h.clock.Now())
	file := append(append(append([]byte{}, leaf.CertPEM...), junk.CertPEM...), ca.IntermediatePEM...)
	hostile := nginxTarget(t, h, admin, "web-hostile")
	_, err = h.svc.Reconcile(h.ctx, hostile.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test"), PEMChain: file, FileSHA256: sha(file)}}})
	require.NoError(t, err)

	got, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, got.HasPrivateKey)
	assert.Equal(t, string(leaf.CertPEM), got.PEMChain, "the uploaded chain is what the uploader gave")
	assert.False(t, got.ChainComplete, "a server's file does not lift the incomplete-chain confirmation")
	assert.Equal(t, "uploaded", got.Source)
	assert.Equal(t, 1, got.LocationCount, "the location still points at the certificate")

	// What a deployment of it to another server sends: the uploaded chain, no foreign certificate.
	web := nginxTarget(t, h, admin, "web-02")
	current := ca.Issue(www, h.clock.Now())
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), current)}})
	require.NoError(t, err)
	reqd, err := h.svc.RequestDeployment(h.ctx, admin, inventory.DeployRequestInput{CertificateID: c.ID,
		LocationIDs: []uuid.UUID{byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"].ID}, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	m, err := h.svc.DeploymentMaterial(h.ctx, reqd[0].ID, false)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM), string(m.CertificatePEM))
	assert.NotContains(t, string(m.CertificatePEM), strings.TrimSpace(string(junk.CertPEM)))
}

// A certificate found only on servers is stored as the ordered path from the leaf the server
// serves: the file's other certificates and its order are not kept (B1-I1).
func TestDiscoveredCertificateStoresTheOrderedPathOnly(t *testing.T) {
	ca := pki.NewCA("Inv", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	junk := pki.SelfSigned("attacker-chosen.example", pki.ECDSA256, h.clock.Now())
	file := append(append(append(append([]byte{}, leaf.CertPEM...), ca.RootPEM...), junk.CertPEM...), ca.IntermediatePEM...)
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), PEMChain: file, FileSHA256: sha(file)}}})
	require.NoError(t, err)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	require.NotNil(t, l.Certificate)
	got, err := h.svc.GetCertificate(h.ctx, l.Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, string(leaf.CertPEM)+string(ca.IntermediatePEM)+string(ca.RootPEM), got.PEMChain)
	assert.True(t, got.ChainComplete)
	assert.Equal(t, sha(file), l.CertFileSHA256, "the location's compare-and-swap value is still the file's own hash")
}

// hugeRSACertificate is a certificate whose subject is its issuer and whose RSA key has a
// 753,664-bit modulus with the largest exponent (adapted from the independent audit of 2026-10-04,
// AUD-04): checking its self-signature used to cost about 22 s of CPU.
func hugeRSACertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	const modBytes = 92 << 10
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	name := pkix.Name{CommonName: "big.example.test"}
	n := make([]byte, modBytes)
	_, _ = rand.Read(n)
	n[0] |= 0x80
	n[len(n)-1] |= 1
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: name, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"big.example.test"}}, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: name},
		&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 1<<31 - 1}, signer)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	sig := make([]byte, modBytes)
	_, _ = rand.Read(sig)
	sig[0] = 0
	out, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: c.RawTBSCertificate}, outer.Alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: out})
}

// AUD-04(b): a certificate file with an oversized RSA key is refused at once (the location shows
// the file as not a certificate it can read), and certificate files are parsed before the scan's
// transaction: the target's row is not locked while they are.
func TestDiscoveryParsesFilesCheaplyAndOutsideTheTransaction(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	huge := hugeRSACertificate(t, h.clock.Now())
	calls := 0
	restore := inventory.SetPrepareHook(func() {
		calls++
		// Another connection can take the target's row lock: no transaction of the scan holds it.
		tx, err := h.db.Owner.Begin(h.ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(h.ctx) }()
		_, err = tx.Exec(h.ctx, "SELECT 1 FROM targets WHERE id = $1 FOR UPDATE NOWAIT", web.ID)
		require.NoError(t, err, "the scan parses certificate files under the target's row lock")
	})
	defer restore()
	started := time.Now()
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: cl("/etc/nginx/ssl/big.crt", "/etc/nginx/ssl/big.key", "big.example.test"), PEMChain: huge, FileSHA256: sha(huge)}}})
	require.NoError(t, err)
	assert.Less(t, time.Since(started), 3*time.Second)
	assert.Equal(t, 1, calls)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/big.crt"]
	assert.False(t, l.Supported)
	assert.Equal(t, providers.CertProblemNotACertificate, l.Problem)
	assert.Nil(t, l.Certificate)
	assert.Zero(t, h.count("SELECT count(*) FROM certificates"))
}
