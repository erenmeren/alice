package tlscert_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/platform/tlscert"
	"alice/internal/testutil/pki"
)

func issue(ca *pki.CA, o pki.Opts) pki.Leaf {
	if o.CommonName == "" {
		o.CommonName = "alice.example.com"
		o.SANs = []string{"alice.example.com"}
	}
	return ca.Issue(o, t0)
}

func chainDER(t *testing.T, c [][]byte) []*x509.Certificate {
	t.Helper()
	out := make([]*x509.Certificate, 0, len(c))
	for _, der := range c {
		x, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		out = append(out, x)
	}
	return out
}

func TestParseUploadPEM(t *testing.T) {
	ca := pki.NewCA("Upload", pki.ECDSA256, t0)
	ec := issue(ca, pki.Opts{})
	rsaLeaf := issue(ca, pki.Opts{KeyType: pki.RSA2048})
	cases := map[string]tlscert.Upload{
		"leaf then intermediate, PKCS #8":  {CertPEM: ec.FullchainPEM, KeyPEM: ec.KeyPEM},
		"intermediate first":               {CertPEM: append(append([]byte{}, ca.IntermediatePEM...), ec.CertPEM...), KeyPEM: ec.KeyPEM},
		"SEC 1 key":                        {CertPEM: ec.FullchainPEM, KeyPEM: pki.KeyPEMSEC1(ec.Key.(*ecdsa.PrivateKey))},
		"key inside the certificate field": {CertPEM: append(append([]byte{}, ec.KeyPEM...), ec.FullchainPEM...)},
	}
	for name, u := range cases {
		c, info, _, err := tlscert.ParseUpload(u, t0)
		require.NoError(t, err, name)
		chain := chainDER(t, c.Certificate)
		require.Len(t, chain, 2, name)
		assert.Equal(t, ec.Cert.Raw, chain[0].Raw, "%s: leaf first", name)
		assert.Equal(t, ca.Intermediate.Raw, chain[1].Raw, name)
		assert.Equal(t, pki.Fingerprint(ec.Cert), info.FingerprintSHA256, name)
		assert.Equal(t, []string{"alice.example.com"}, info.DNSNames, name)
		assert.Equal(t, "CN=alice.example.com", info.Subject, name)
		assert.Equal(t, ec.Cert.NotAfter, info.NotAfter, name)
		assert.Equal(t, ec.Cert.NotBefore, info.NotBefore, name)
		assert.False(t, info.Temporary, name)
		assert.NotNil(t, c.Leaf, name)
	}
	c, _, _, err := tlscert.ParseUpload(tlscert.Upload{CertPEM: rsaLeaf.FullchainPEM,
		KeyPEM: pki.KeyPEMPKCS1(rsaLeaf.Key.(*rsa.PrivateKey))}, t0)
	require.NoError(t, err, "PKCS #1 key")
	assert.Equal(t, rsaLeaf.Cert.Raw, c.Certificate[0])

	ipLeaf := ca.Issue(pki.Opts{CommonName: "x", SANs: []string{"192.0.2.10"}}, t0)
	_, info, _, err := tlscert.ParseUpload(tlscert.Upload{CertPEM: ipLeaf.FullchainPEM, KeyPEM: ipLeaf.KeyPEM}, t0)
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.10"}, info.IPs)

	// An unrelated extra certificate is dropped; a root is kept at the end.
	other := pki.NewCA("Other", pki.ECDSA256, t0)
	extra := bytes.Join([][]byte{other.RootPEM, ca.RootPEM, ec.CertPEM, ca.IntermediatePEM}, nil)
	c, _, _, err = tlscert.ParseUpload(tlscert.Upload{CertPEM: extra, KeyPEM: ec.KeyPEM}, t0)
	require.NoError(t, err)
	chain := chainDER(t, c.Certificate)
	require.Len(t, chain, 3)
	assert.Equal(t, ca.Root.Raw, chain[2].Raw)
}

func TestParseUploadPFX(t *testing.T) {
	ca := pki.NewCA("Upload", pki.ECDSA256, t0)
	l := issue(ca, pki.Opts{})
	c, info, _, err := tlscert.ParseUpload(tlscert.Upload{PFX: pki.PFX(l, ca, "alice-test"), PFXPassword: []byte("alice-test")}, t0)
	require.NoError(t, err)
	chain := chainDER(t, c.Certificate)
	require.Len(t, chain, 2)
	assert.Equal(t, l.Cert.Raw, chain[0].Raw)
	assert.Equal(t, pki.Fingerprint(l.Cert), info.FingerprintSHA256)

	noInter, err := pkcs12.Modern.Encode(l.Key, l.Cert, nil, "alice-test")
	require.NoError(t, err)
	c, _, warnings, err := tlscert.ParseUpload(tlscert.Upload{PFX: noInter, PFXPassword: []byte("alice-test")}, t0)
	require.NoError(t, err)
	assert.Len(t, c.Certificate, 1)
	assert.Contains(t, warnings, "chain_incomplete")
}

func TestParseUploadRefusals(t *testing.T) {
	ca := pki.NewCA("Upload", pki.ECDSA256, t0)
	good := issue(ca, pki.Opts{})
	other := issue(ca, pki.Opts{})
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	pem1 := func(l pki.Leaf) tlscert.Upload { return tlscert.Upload{CertPEM: l.FullchainPEM, KeyPEM: l.KeyPEM} }
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: pki.CSRFor("x", nil, good.Key).Raw})
	cases := []struct {
		name string
		u    tlscert.Upload
		want error
	}{
		{"key of another certificate", tlscert.Upload{CertPEM: good.FullchainPEM, KeyPEM: other.KeyPEM}, tlscert.ErrKeyMismatch},
		{"no key", tlscert.Upload{CertPEM: good.FullchainPEM}, tlscert.ErrKeyMismatch},
		{"expired", pem1(issue(ca, pki.Opts{NotBefore: t0.AddDate(0, 0, -90), NotAfter: t0.Add(-time.Hour)})), tlscert.ErrNotValidNow},
		{"not yet valid", pem1(issue(ca, pki.Opts{NotBefore: t0.Add(time.Hour), NotAfter: t0.AddDate(0, 0, 90)})), tlscert.ErrNotValidNow},
		{"less than one more day", pem1(issue(ca, pki.Opts{NotAfter: t0.Add(23 * time.Hour)})), tlscert.ErrNotValidNow},
		{"RSA 1024", pem1(issue(ca, pki.Opts{KeyType: pki.RSA1024})), tlscert.ErrWeakKey},
		{"P-224", pem1(issue(ca, pki.Opts{Key: p224})), tlscert.ErrWeakKey},
		{"P-521", pem1(issue(ca, pki.Opts{KeyType: pki.ECDSA521})), tlscert.ErrWeakKey},
		{"Ed25519", pem1(issue(ca, pki.Opts{KeyType: pki.Ed25519})), tlscert.ErrWeakKey},
		{"wrong PFX password", tlscert.Upload{PFX: pki.PFX(good, ca, "alice-test"), PFXPassword: []byte("wrong")}, tlscert.ErrPFXPassword},
		{"PFX garbage", tlscert.Upload{PFX: []byte("not a pfx")}, tlscert.ErrUnreadable},
		{"PFX without a key", tlscert.Upload{PFX: pki.CertificatesOnlyPFX("alice-test", good.Cert), PFXPassword: []byte("alice-test")}, tlscert.ErrUnreadable},
		{"garbage", tlscert.Upload{CertPEM: []byte("hello"), KeyPEM: []byte("world")}, tlscert.ErrUnreadable},
		{"empty", tlscert.Upload{}, tlscert.ErrUnreadable},
		{"a CSR", tlscert.Upload{CertPEM: csr, KeyPEM: good.KeyPEM}, tlscert.ErrUnreadable},
		{"both PEM and PFX", tlscert.Upload{CertPEM: good.FullchainPEM, KeyPEM: good.KeyPEM, PFX: pki.PFX(good, ca, "x"), PFXPassword: []byte("x")}, tlscert.ErrUnreadable},
		{"larger than 1 MiB", tlscert.Upload{CertPEM: append(bytes.Repeat([]byte("\n"), 1<<20), good.FullchainPEM...), KeyPEM: good.KeyPEM}, tlscert.ErrUnreadable},
		{"encrypted key", tlscert.Upload{CertPEM: good.FullchainPEM, KeyPEM: pki.EncryptedKeyPEM(good)}, tlscert.ErrUnreadable},
		{"two keys", tlscert.Upload{CertPEM: good.FullchainPEM, KeyPEM: append(append([]byte{}, good.KeyPEM...), other.KeyPEM...)}, tlscert.ErrUnreadable},
		{"broken certificate", tlscert.Upload{CertPEM: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), KeyPEM: good.KeyPEM}, tlscert.ErrUnreadable},
		{"key only", tlscert.Upload{KeyPEM: good.KeyPEM}, tlscert.ErrUnreadable},
		{"trailing text", tlscert.Upload{CertPEM: append(append([]byte{}, good.FullchainPEM...), "junk"...), KeyPEM: good.KeyPEM}, tlscert.ErrUnreadable},
	}
	for _, c := range cases {
		_, _, _, err := tlscert.ParseUpload(c.u, t0)
		assert.ErrorIs(t, err, c.want, c.name)
	}
	// A refusal never quotes the upload.
	_, _, _, err = tlscert.ParseUpload(tlscert.Upload{CertPEM: good.FullchainPEM, KeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n")}, t0)
	require.ErrorIs(t, err, tlscert.ErrUnreadable)
	assert.NotContains(t, err.Error(), "QUJD")
}

func TestWarnings(t *testing.T) {
	ca := pki.NewCA("Upload", pki.ECDSA256, t0)
	l := issue(ca, pki.Opts{})
	u := tlscert.Upload{CertPEM: l.FullchainPEM, KeyPEM: l.KeyPEM}

	restore := tlscert.SetSystemRootsForTest(ca.Root)
	defer restore()
	_, _, w, err := tlscert.ParseUpload(u, t0)
	require.NoError(t, err)
	assert.Empty(t, w, "trusted, named, long enough")

	u.Hosts = []string{"other.example.com", "10.0.0.1"}
	_, _, w, err = tlscert.ParseUpload(u, t0)
	require.NoError(t, err)
	assert.Equal(t, []string{"name_mismatch"}, w)
	u.Hosts = []string{"other.example.com", "alice.example.com"}
	_, _, w, err = tlscert.ParseUpload(u, t0)
	require.NoError(t, err)
	assert.Empty(t, w, "one matching name is enough")

	_, _, w, err = tlscert.ParseUpload(tlscert.Upload{CertPEM: l.CertPEM, KeyPEM: l.KeyPEM}, t0)
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, w, "the intermediate is missing")

	soon := issue(ca, pki.Opts{NotAfter: t0.AddDate(0, 0, 29)})
	_, _, w, err = tlscert.ParseUpload(tlscert.Upload{CertPEM: soon.FullchainPEM, KeyPEM: soon.KeyPEM}, t0)
	require.NoError(t, err)
	assert.Equal(t, []string{"expires_soon"}, w)

	restore()
	_, _, w, err = tlscert.ParseUpload(tlscert.Upload{CertPEM: soon.FullchainPEM, KeyPEM: soon.KeyPEM,
		Hosts: []string{"nope.example.com"}}, t0)
	require.NoError(t, err)
	assert.Equal(t, []string{"name_mismatch", "chain_incomplete", "expires_soon"}, w)
	assert.False(t, strings.Contains(strings.Join(w, ""), " "))
}
