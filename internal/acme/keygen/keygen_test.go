package keygen_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/secrets"
)

func TestReasonIsTheClientsReason(t *testing.T) {
	assert.Equal(t, acme.ReasonKeyPolicyNotAllowed, keygen.ReasonKeyPolicyNotAllowed)
}

func TestParseKeyPolicy(t *testing.T) {
	for _, p := range keygen.Policies() {
		got, err := keygen.ParseKeyPolicy(string(p))
		require.NoError(t, err)
		assert.Equal(t, p, got)
	}
	assert.Equal(t, keygen.ECDSAP256, keygen.Default)
	assert.Equal(t, keygen.Default, keygen.Policies()[0])
	for _, bad := range []string{"", "ECDSA_P256", "ecdsa-p256", "rsa_1024", "rsa_8192", "ed25519", "ecdsa_p521", " rsa_2048"} {
		_, err := keygen.ParseKeyPolicy(bad)
		assert.ErrorIs(t, err, keygen.ErrKeyPolicy, bad)
	}
}

func TestAlgorithmMatchesManagedPrivateKeysCheck(t *testing.T) {
	want := map[keygen.KeyPolicy]struct {
		alg  string
		bits int
	}{
		keygen.ECDSAP256: {"ecdsa", 256}, keygen.ECDSAP384: {"ecdsa", 384},
		keygen.RSA2048: {"rsa", 2048}, keygen.RSA3072: {"rsa", 3072}, keygen.RSA4096: {"rsa", 4096},
	}
	require.Len(t, keygen.Policies(), len(want))
	for p, w := range want {
		alg, bits, err := p.Algorithm()
		require.NoError(t, err)
		assert.Equal(t, w.alg, alg, p)
		assert.Equal(t, w.bits, bits, p)
		// managed_private_keys: (algorithm = 'rsa' AND bits >= 2048) OR (algorithm = 'ecdsa' AND bits IN (256, 384))
		assert.True(t, (alg == "rsa" && bits >= 2048) || (alg == "ecdsa" && (bits == 256 || bits == 384)), p)
	}
	_, _, err := keygen.KeyPolicy("rsa_1024").Algorithm()
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)
}

func TestPolicyOf(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsa2560, err := rsa.GenerateKey(rand.Reader, 2560)
	require.NoError(t, err)
	for _, pub := range []any{&p224.PublicKey, &p521.PublicKey, edPub, &rsa2560.PublicKey, nil, "text"} {
		_, err := keygen.PolicyOf(pub)
		assert.ErrorIs(t, err, keygen.ErrKeyPolicy, "%T", pub)
	}
}

// generated caches one key per policy: RSA 4096 costs about a second.
var generated = map[keygen.KeyPolicy]*keygen.Key{}

func keyOf(t *testing.T, p keygen.KeyPolicy) *keygen.Key {
	t.Helper()
	if k, ok := generated[p]; ok {
		return k
	}
	k, err := keygen.Generate(p)
	require.NoError(t, err)
	generated[p] = k
	return k
}

func TestGenerateEveryPolicy(t *testing.T) {
	for _, p := range keygen.Policies() {
		t.Run(string(p), func(t *testing.T) {
			k := keyOf(t, p)
			assert.Equal(t, p, k.Policy)
			got, err := keygen.PolicyOf(k.Signer.Public())
			require.NoError(t, err)
			assert.Equal(t, p, got)
			// The DER is the PKCS#8 of the signer.
			parsed, err := x509.ParsePKCS8PrivateKey(k.DER.Bytes())
			require.NoError(t, err)
			assert.True(t, parsed.(interface{ Equal(crypto.PrivateKey) bool }).Equal(k.Signer))
			// The public key hash is the one certs.KeyInfoOf and managed_private_keys use.
			spki, err := x509.MarshalPKIXPublicKey(k.Signer.Public())
			require.NoError(t, err)
			sum := sha256.Sum256(spki)
			h, err := k.PublicKeySHA256()
			require.NoError(t, err)
			assert.Equal(t, hex.EncodeToString(sum[:]), h)
		})
	}
	_, err := keygen.Generate("rsa_1024")
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)
	_, err = keygen.Generate("")
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)
}

func TestTwoKeysDiffer(t *testing.T) {
	a, err := keygen.Generate(keygen.ECDSAP256)
	require.NoError(t, err)
	b, err := keygen.Generate(keygen.ECDSAP256)
	require.NoError(t, err)
	assert.NotEqual(t, a.DER.Bytes(), b.DER.Bytes())
}

func TestParsePKCS8(t *testing.T) {
	for _, p := range []keygen.KeyPolicy{keygen.ECDSAP256, keygen.ECDSAP384, keygen.RSA2048} {
		k := keyOf(t, p)
		der := secrets.NewPlaintext(bytes.Clone(k.DER.Bytes()))
		opened, err := keygen.ParsePKCS8(der)
		require.NoError(t, err)
		assert.Equal(t, p, opened.Policy)
		assert.True(t, opened.Signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Signer.Public()))
		// Not copied: zeroing the opened key's DER zeroes the caller's buffer.
		opened.Zero()
		assert.Equal(t, make([]byte, len(der.Bytes())), der.Bytes())
	}
	_, err := keygen.ParsePKCS8(secrets.NewPlaintext([]byte("not a key")))
	assert.ErrorIs(t, err, keygen.ErrKey)

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	require.NoError(t, err)
	_, err = keygen.ParsePKCS8(secrets.NewPlaintext(edDER))
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)

	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the refused size under test
	require.NoError(t, err)
	smallDER, err := x509.MarshalPKCS8PrivateKey(small)
	require.NoError(t, err)
	_, err = keygen.ParsePKCS8(secrets.NewPlaintext(smallDER))
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)
}

func TestZeroClearsTheDER(t *testing.T) {
	k, err := keygen.Generate(keygen.ECDSAP256)
	require.NoError(t, err)
	buf := k.DER.Bytes()
	require.NotEqual(t, make([]byte, len(buf)), buf)
	k.Zero()
	assert.Equal(t, make([]byte, len(buf)), buf, "the PKCS#8 bytes are overwritten in place")
	// The signer still works (it cannot be zeroed; A10).
	_, err = keygen.NewCSR(k.Signer, []string{"a.example.test"})
	require.NoError(t, err)
	var nilKey *keygen.Key
	nilKey.Zero() // no panic
}

func TestKeyRedacts(t *testing.T) {
	for _, p := range []keygen.KeyPolicy{keygen.ECDSAP256, keygen.RSA2048} {
		k := keyOf(t, p)
		var markers []string
		switch s := k.Signer.(type) {
		case *ecdsa.PrivateKey:
			d, err := s.Bytes()
			require.NoError(t, err)
			markers = append(markers, hex.EncodeToString(d), new(big.Int).SetBytes(d).String())
		case *rsa.PrivateKey:
			markers = append(markers, s.D.String(), s.D.Text(16), s.Primes[0].String())
		}
		markers = append(markers, hex.EncodeToString(k.DER.Bytes()), string(k.DER.Bytes()))
		var logged bytes.Buffer
		slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "key", k, "pointer", k)
		js, err := json.Marshal(struct{ K *keygen.Key }{k})
		require.NoError(t, err)
		out := strings.Join([]string{
			fmt.Sprintf("%v %+v %#v %s %q %x %X %d", k, k, k, k, k, k, k, k),
			fmt.Sprintf("%v %+v", *k, *k), // a copied struct: its fields are each redacted or a pointer
			k.String(), k.GoString(), logged.String(), string(js),
		}, "\n")
		for _, m := range markers {
			assert.NotContains(t, out, m, "the private key was printed")
		}
		assert.Contains(t, fmt.Sprintf("%v", k), "redacted")
		assert.Contains(t, logged.String(), "redacted")
	}
}

func TestNewCSRContents(t *testing.T) {
	cases := []struct {
		policy keygen.KeyPolicy
		alg    x509.SignatureAlgorithm
	}{
		{keygen.ECDSAP256, x509.ECDSAWithSHA256}, {keygen.ECDSAP384, x509.ECDSAWithSHA384},
		{keygen.RSA2048, x509.SHA256WithRSA}, {keygen.RSA3072, x509.SHA256WithRSA}, {keygen.RSA4096, x509.SHA256WithRSA},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			k := keyOf(t, c.policy)
			names := []string{"www.example.test", "example.test", "xn--bcher-kva.example.test"}
			der, err := keygen.NewCSR(k.Signer, names)
			require.NoError(t, err)
			csr, err := x509.ParseCertificateRequest(der)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())
			assert.Equal(t, c.alg, csr.SignatureAlgorithm)
			assert.Equal(t, names, csr.DNSNames)
			assert.Equal(t, "www.example.test", csr.Subject.CommonName)
			assert.Empty(t, csr.IPAddresses)
			assert.Empty(t, csr.EmailAddresses)
			assert.Empty(t, csr.URIs)
			assert.True(t, csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Signer.Public()))

			// Deterministic contents: a second request has the same names, subject, key and algorithm.
			again, err := keygen.NewCSR(k.Signer, names)
			require.NoError(t, err)
			csr2, err := x509.ParseCertificateRequest(again)
			require.NoError(t, err)
			assert.Equal(t, csr.RawSubject, csr2.RawSubject)
			assert.Equal(t, csr.RawSubjectPublicKeyInfo, csr2.RawSubjectPublicKeyInfo)
			assert.Equal(t, csr.DNSNames, csr2.DNSNames)
			assert.Equal(t, csr.SignatureAlgorithm, csr2.SignatureAlgorithm)
		})
	}
}

func TestNewCSRCommonName(t *testing.T) {
	k := keyOf(t, keygen.ECDSAP256)
	long := strings.Repeat("a", 60) + ".example.test" // 73 characters: too long for a common name
	for _, c := range []struct {
		names []string
		cn    string
	}{
		{[]string{"*.example.test", "example.test"}, "example.test"},
		{[]string{"*.example.test"}, ""},
		{[]string{"*.a.example.test", "*.b.example.test"}, ""},
		{[]string{long, "short.example.test"}, "short.example.test"},
		{[]string{long}, ""},
		{[]string{"one.example.test"}, "one.example.test"},
	} {
		der, err := keygen.NewCSR(k.Signer, c.names)
		require.NoError(t, err, c.names)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		assert.Equal(t, c.cn, csr.Subject.CommonName, c.names)
		assert.Equal(t, c.names, csr.DNSNames)
	}
}

func TestNewCSRRefuses(t *testing.T) {
	k := keyOf(t, keygen.ECDSAP256)
	for _, names := range [][]string{
		nil, {}, {""}, {"a.example.test", ""}, {"bücher.example.test"}, {"a b.example.test"}, {"a.example.test\n"},
		{"a.example.test", "A.example.test"}, {strings.Repeat("a", 254)}, {"tab\t.example.test"}, {"del\x7f.example.test"},
	} {
		_, err := keygen.NewCSR(k.Signer, names)
		assert.ErrorIs(t, err, keygen.ErrNames, "%q", names)
	}
	_, err := keygen.NewCSR(nil, []string{"a.example.test"})
	assert.ErrorIs(t, err, keygen.ErrKey)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = keygen.NewCSR(edPriv, []string{"a.example.test"})
	assert.ErrorIs(t, err, keygen.ErrKeyPolicy)
}
