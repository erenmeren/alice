package providers_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

var trustNow = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

// intermediateValid signs an intermediate of ca's root valid from notBefore to notAfter, and a leaf for name under it.
func intermediateValid(t *testing.T, ca *pki.CA, notBefore, notAfter time.Time, name string) (inter, leaf *x509.Certificate) {
	t.Helper()
	key := pki.NewKey(pki.ECDSA256)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "Odd Intermediate"}, NotBefore: notBefore,
		NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Root, key.Public(), ca.RootKey)
	require.NoError(t, err)
	inter, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	lkey := pki.NewKey(pki.ECDSA256)
	ltmpl := &x509.Certificate{SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: trustNow.Add(-time.Hour), NotAfter: trustNow.AddDate(0, 0, 30), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, ltmpl, inter, lkey.Public(), key)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	return inter, leaf
}

func ders(cs ...*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

func rootsOf(cs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

// R51: the served chain verifies with crypto/x509 against the trust store for the endpoint's name at the probe time, and
// a failure says precisely why.
func TestCheckServedChain(t *testing.T) {
	ca := pki.NewCA("Trust", pki.ECDSA256, trustNow)
	other := pki.NewCA("Other", pki.ECDSA256, trustNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "*.app.example.test"}}, trustNow)
	expected := []*x509.Certificate{leaf.Cert, ca.Intermediate}
	policy := providers.TrustPolicy{Roots: rootsOf(ca.Root), Expected: expected, Store: providers.TrustStoreSystem, Enforce: true}
	expiredInter, expiredLeaf := intermediateValid(t, ca, trustNow.AddDate(-2, 0, 0), trustNow.AddDate(0, 0, -1), "www.example.test")
	futureInter, futureLeaf := intermediateValid(t, ca, trustNow.AddDate(0, 0, 1), trustNow.AddDate(2, 0, 0), "www.example.test")

	for _, tc := range []struct {
		name   string
		served [][]byte
		policy providers.TrustPolicy
		sni    string
		status string
		code   string
	}{
		{"good chain", ders(leaf.Cert, ca.Intermediate), policy, "www.example.test", providers.TrustTrusted, ""},
		{"good chain with its root", ders(leaf.Cert, ca.Intermediate, ca.Root), policy, "www.example.test", providers.TrustTrusted, ""},
		{"a wildcard name", ders(leaf.Cert, ca.Intermediate), policy, "alice-check.app.example.test", providers.TrustTrusted, ""},
		{"no server name: the name is not checked", ders(leaf.Cert, ca.Intermediate), policy, "", providers.TrustTrusted, ""},
		{"wrong intermediate", ders(leaf.Cert, other.Intermediate), policy, "www.example.test", providers.TrustUntrusted, providers.TrustErrWrongIntermediate},
		{"missing intermediate", ders(leaf.Cert), policy, "www.example.test", providers.TrustUntrusted, providers.TrustErrIncompleteChain},
		{"wrong order", ders(leaf.Cert, ca.Root, ca.Intermediate), policy, "www.example.test", providers.TrustUntrusted, providers.TrustErrChainOrder},
		{"expired intermediate", ders(expiredLeaf, expiredInter),
			providers.TrustPolicy{Roots: rootsOf(ca.Root), Expected: []*x509.Certificate{expiredLeaf, expiredInter}, Enforce: true},
			"www.example.test", providers.TrustUntrusted, providers.TrustErrExpired},
		{"intermediate not valid yet", ders(futureLeaf, futureInter),
			providers.TrustPolicy{Roots: rootsOf(ca.Root), Expected: []*x509.Certificate{futureLeaf, futureInter}, Enforce: true},
			"www.example.test", providers.TrustUntrusted, providers.TrustErrNotYetValid},
		{"name mismatch", ders(leaf.Cert, ca.Intermediate), policy, "shop.example.test", providers.TrustUntrusted, providers.TrustErrNameMismatch},
		{"unknown root", ders(leaf.Cert, ca.Intermediate), providers.TrustPolicy{Roots: rootsOf(other.Root), Expected: expected},
			"www.example.test", providers.TrustUntrusted, providers.TrustErrUnknownAuthority},
		{"a self-signed root sent along is no anchor", ders(leaf.Cert, ca.Intermediate, ca.Root),
			providers.TrustPolicy{Roots: x509.NewCertPool(), Expected: expected}, "www.example.test", providers.TrustUntrusted, providers.TrustErrUnknownAuthority},
		{"unreadable certificate", [][]byte{[]byte("not DER")}, policy, "www.example.test", providers.TrustUntrusted, providers.TrustErrInvalidChain},
		{"nothing to check", nil, policy, "www.example.test", providers.TrustUnchecked, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, code := providers.CheckServedChain(tc.served, tc.policy, tc.sni, trustNow)
			assert.Equal(t, tc.status, status)
			assert.Equal(t, tc.code, code)
		})
	}

	expiredLeafOnly := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"},
		NotBefore: trustNow.AddDate(0, 0, -60), NotAfter: trustNow.AddDate(0, 0, -1)}, trustNow)
	status, code := providers.CheckServedChain(ders(expiredLeafOnly.Cert, ca.Intermediate), policy, "www.example.test", trustNow)
	assert.Equal(t, providers.TrustUntrusted, status)
	assert.Equal(t, providers.TrustErrExpired, code, "an expired leaf")
}

// The anchor is known (Enforce) only when the chain Alice deploys verifies against the store itself: a public or
// configured CA, or a self-signed root that came with the upload (added to the store as the anchor).
func TestTrustPolicyFor(t *testing.T) {
	ca := pki.NewCA("Trust", pki.ECDSA256, trustNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, trustNow)

	known := providers.TrustPolicyFor([]*x509.Certificate{leaf.Cert, ca.Intermediate}, rootsOf(ca.Root), providers.TrustStoreACME, trustNow)
	assert.True(t, known.Enforce, "the chain verifies against the store")
	assert.Equal(t, providers.TrustStoreACME, known.Store)

	unknown := providers.TrustPolicyFor([]*x509.Certificate{leaf.Cert, ca.Intermediate}, x509.NewCertPool(), providers.TrustStoreSystem, trustNow)
	assert.False(t, unknown.Enforce, "a private CA Alice has no root of: a warning only")
	status, code := providers.CheckServedChain(ders(leaf.Cert, ca.Intermediate), unknown, "www.example.test", trustNow)
	assert.Equal(t, providers.TrustUntrusted, status)
	assert.Equal(t, providers.TrustErrUnknownAuthority, code)

	uploaded := providers.TrustPolicyFor([]*x509.Certificate{leaf.Cert, ca.Intermediate, ca.Root}, x509.NewCertPool(), providers.TrustStoreSystem, trustNow)
	assert.True(t, uploaded.Enforce, "the root uploaded with the chain is the anchor")
	assert.Equal(t, providers.TrustStoreUploadedRoot, uploaded.Store)
	status, _ = providers.CheckServedChain(ders(leaf.Cert, ca.Intermediate), uploaded, "www.example.test", trustNow)
	assert.Equal(t, providers.TrustTrusted, status)

	self := pki.SelfSigned("self.example.test", pki.ECDSA256, trustNow)
	sp := providers.TrustPolicyFor([]*x509.Certificate{self.Cert}, x509.NewCertPool(), providers.TrustStoreSystem, trustNow)
	assert.True(t, sp.Enforce)
	status, _ = providers.CheckServedChain(ders(self.Cert), sp, "self.example.test", trustNow)
	assert.Equal(t, providers.TrustTrusted, status, "a self-signed certificate Alice deploys is its own anchor")

	assert.False(t, providers.TrustPolicyFor(nil, x509.NewCertPool(), providers.TrustStoreSystem, trustNow).Enforce)
}

// A name mismatch is a warning whatever the anchor; every other reason fails only with a known anchor.
func TestTrustPolicyEnforces(t *testing.T) {
	known, unknown := providers.TrustPolicy{Enforce: true}, providers.TrustPolicy{}
	for _, code := range providers.TrustErrors {
		assert.Equal(t, code != providers.TrustErrNameMismatch, known.Enforces(code), code)
		assert.False(t, unknown.Enforces(code), code)
	}
}

func TestVerificationLevel(t *testing.T) {
	for _, tc := range []struct {
		verified string
		trust    string
		want     int
	}{
		{"", "", providers.LevelNone},
		{"skipped", "", providers.LevelInstalled},
		{"remote", "", providers.LevelServed},
		{"local", providers.TrustUnchecked, providers.LevelServed},
		{"remote", providers.TrustUntrusted, providers.LevelServed},
		{"remote", providers.TrustTrusted, providers.LevelTrusted},
		{"local", providers.TrustTrusted, providers.LevelTrusted},
		{"skipped", providers.TrustTrusted, providers.LevelInstalled},
		{"", providers.TrustTrusted, providers.LevelNone},
	} {
		assert.Equal(t, tc.want, providers.VerificationLevel(tc.verified, tc.trust), "%q %q", tc.verified, tc.trust)
	}
}
