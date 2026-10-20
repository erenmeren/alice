package tlsprobe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/pki"
)

func requireParseCode(t *testing.T, der [][]byte, want Code) {
	t.Helper()
	c, err := ParsePresentedChain(der)
	code, ok := CodeOf(err)
	require.True(t, ok, "not a probe error: %v", err)
	assert.Equal(t, want, code)
	assert.Empty(t, c.Certificates)
}

func TestParseRefusesWhatItCannotRead(t *testing.T) {
	requireParseCode(t, nil, CodeMalformed)
	requireParseCode(t, [][]byte{}, CodeMalformed)
	requireParseCode(t, [][]byte{nil}, CodeMalformed)
	requireParseCode(t, [][]byte{[]byte("not DER")}, CodeMalformed)
	requireParseCode(t, make([][]byte, MaxCertificates+1), CodeChainTooLarge)
	requireParseCode(t, [][]byte{make([]byte, MaxCertificateSize+1)}, CodeChainTooLarge)

	f := sharedFleet(t)
	requireParseCode(t, f.Server(fakefleet.KindMalformed).Chain(), CodeMalformed) // a negative serial number
	good := f.Server(fakefleet.KindValid).Chain()
	requireParseCode(t, [][]byte{good[0], {0x30, 0x03, 0x02, 0x01}}, CodeMalformed) // one bad certificate spoils the chain

	ca := pki.NewCA("Times", pki.ECDSA256, testNow)
	yearZero := ca.IssueRawValidity(pki.Opts{CommonName: "y0.test"}, pki.GeneralizedTime("00000101000000Z"),
		pki.GeneralizedTime("20300101000000Z"), testNow)
	requireParseCode(t, [][]byte{yearZero.Cert.Raw}, CodeMalformed)
	reversed := ca.IssueRawValidity(pki.Opts{CommonName: "rev.test"}, pki.UTCTime("300101000000Z"), pki.UTCTime("250101000000Z"), testNow)
	requireParseCode(t, [][]byte{reversed.Cert.Raw}, CodeMalformed)
	requireParseCode(t, [][]byte{yearZero.Cert.Raw, good[0]}, CodeMalformed) // a bad leaf spoils the chain
}

// Ruling L2b: a non-leaf certificate Go parses but whose dates Alice cannot store is dropped from the
// chain (counted); the leaf and the other certificates are kept, in their order.
func TestBadDatesInANonLeafAreDropped(t *testing.T) {
	f := sharedFleet(t)
	good := f.Server(fakefleet.KindValid).Chain()
	ca := pki.NewCA("Times", pki.ECDSA256, testNow)
	yearZero := ca.IssueRawValidity(pki.Opts{CommonName: "y0.test"}, pki.GeneralizedTime("00000101000000Z"),
		pki.GeneralizedTime("20300101000000Z"), testNow)
	reversed := ca.IssueRawValidity(pki.Opts{CommonName: "rev.test"}, pki.UTCTime("300101000000Z"), pki.UTCTime("250101000000Z"), testNow)
	c, err := ParsePresentedChain([][]byte{good[0], yearZero.Cert.Raw, good[1], reversed.Cert.Raw})
	require.NoError(t, err)
	require.Len(t, c.Certificates, 2)
	assert.Equal(t, good[0], c.Certificates[0].Raw)
	assert.Equal(t, good[1], c.Certificates[1].Raw)
	assert.Equal(t, 2, c.DroppedCerts)
	// An unparseable non-leaf is still malformed (Go's own client refuses such a chain anyway).
	requireParseCode(t, [][]byte{good[0], {0x30, 0x03, 0x02, 0x01}}, CodeMalformed)
}

func TestLeafOfAnEmptyChain(t *testing.T) {
	_, ok := Chain{}.Leaf()
	assert.False(t, ok, "an empty chain has no leaf, and asking does not panic")
	c, err := ParsePresentedChain(sharedFleetChain(t))
	require.NoError(t, err)
	l, ok := c.Leaf()
	require.True(t, ok)
	assert.Equal(t, c.Certificates[0], l)
}

func sharedFleetChain(t *testing.T) [][]byte {
	t.Helper()
	return sharedFleet(t).Server(fakefleet.KindValid).Chain()
}

// The public key hash is internal/certs' (SHA-256 of the SubjectPublicKeyInfo): the same key gives the same hash on a
// managed certificate and on a discovered one.
func TestPublicKeyHash(t *testing.T) {
	der := sharedFleetChain(t)
	c, err := ParsePresentedChain(der)
	require.NoError(t, err)
	x, err := x509.ParseCertificate(der[0])
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(x.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)
	assert.Equal(t, hex.EncodeToString(sum[:]), leafOf(t, c).PublicKeySHA256)
}

// leafOf is the leaf of a chain that must have one.
func leafOf(t *testing.T, c Chain) Certificate {
	t.Helper()
	l, ok := c.Leaf()
	require.True(t, ok)
	return l
}

func TestParseBoundsWhatItKeeps(t *testing.T) {
	key := pki.NewKey(pki.Ed25519)
	var names []string
	for i := range MaxSANs + 10 {
		names = append(names, "n"+strings.Repeat("x", i%5)+".example.test")
	}
	long := strings.Repeat("a", 300) + ".example.test"
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(255), Subject: pkix.Name{CommonName: "bad\x00name" + strings.Repeat("é", 600)},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), DNSNames: append([]string{long}, names...),
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	c, err := ParsePresentedChain([][]byte{der})
	require.NoError(t, err)
	leaf := leafOf(t, c)
	assert.Equal(t, der, leaf.Raw)
	assert.Equal(t, "FF", leaf.Serial)
	assert.Equal(t, "ed25519", leaf.KeyAlgorithm)
	assert.Equal(t, 256, leaf.KeyBits)
	assert.Equal(t, "Ed25519", leaf.SignatureAlgorithm)
	assert.True(t, leaf.SelfSigned)
	assert.True(t, leaf.IsCA)
	assert.True(t, leaf.SANsTruncated)
	assert.Len(t, leaf.DNSNames, MaxSANs, "at most MaxSANs names are kept")
	assert.Empty(t, leaf.IPAddresses, "the IP address came after the cap")
	assert.Len(t, leaf.DNSNames[0], maxSANBytes, "a long name is cut")
	assert.LessOrEqual(t, len(leaf.SubjectCN), maxNameBytes)
	assert.True(t, utf8.ValidString(leaf.SubjectCN))
	assert.True(t, strings.HasPrefix(leaf.SubjectCN, "bad�name"), "NUL is replaced")
	assert.Equal(t, time.UTC, leaf.NotAfter.Location())

	tmpl.DNSNames, tmpl.IPAddresses = []string{"a.example.test"}, []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.7")}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	c, err = ParsePresentedChain([][]byte{der})
	require.NoError(t, err)
	assert.Equal(t, []string{"2001:db8::1", "192.0.2.7"}, leafOf(t, c).IPAddresses)
	assert.False(t, leafOf(t, c).SANsTruncated)
}

func TestCleanText(t *testing.T) {
	for _, tc := range []struct {
		in    string
		limit int
		want  string
	}{
		{"plain", 10, "plain"},
		{"a\x00b", 10, "a�b"},
		{"a\xffb", 10, "a�b"},
		{"ééé", 5, "éé"}, // 6 bytes, cut on a character boundary
		{"ééé", 4, "éé"},
		{"ééé", 3, "é"},
		{"�", 2, ""},
		{"abc", 0, ""},
	} {
		got := cleanText(tc.in, tc.limit)
		assert.Equal(t, tc.want, got, "%q %d", tc.in, tc.limit)
		assert.True(t, utf8.ValidString(got))
		assert.LessOrEqual(t, len(got), tc.limit)
	}
}

func TestSelfSignedAndKeyNames(t *testing.T) {
	name := []byte{0x30, 0x00}
	huge := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), maxSignatureCheckBits), E: 65537}
	assert.False(t, selfSigned(&x509.Certificate{RawIssuer: name, RawSubject: name, PublicKey: huge}),
		"an RSA key over 16384 bits is never used to check a signature")
	assert.False(t, selfSigned(&x509.Certificate{RawIssuer: name, RawSubject: []byte{0x30, 0x01}}))
	alg, bits := keyAlgorithm(nil)
	assert.Equal(t, "other", alg)
	assert.Zero(t, bits)
	alg, bits = keyAlgorithm(huge)
	assert.Equal(t, "rsa", alg)
	assert.Equal(t, maxSignatureCheckBits+1, bits)
}
