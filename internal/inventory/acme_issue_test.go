package inventory

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/keygen"
	"alice/internal/certs"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	raw := make([]byte, secrets.KeySize)
	_, _ = rand.Read(raw)
	k, err := secrets.NewKeyring(1, raw)
	require.NoError(t, err)
	return k
}

var acmeNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func zeroed(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// The key's DER is zeroed once it is sealed, and once the opened key was used (A10: the buffers the code holds).
func TestPendingKeyIsZeroedAfterSealAndOpen(t *testing.T) {
	ring := testKeyring(t)
	order := uuid.New()
	key, err := keygen.Generate(keygen.ECDSAP256)
	require.NoError(t, err)
	generated := key.DER.Bytes()
	want := bytes.Clone(generated)
	env, err := sealPendingKey(ring, order, key)
	require.NoError(t, err)
	assert.True(t, zeroed(generated), "the generated DER is zeroed after sealing")

	var seen []byte
	err = openPendingKey(ring, order, env, func(k *keygen.Key) error {
		seen = k.DER.Bytes()
		assert.Equal(t, want, seen, "the sealed key opens to the generated one")
		assert.Equal(t, keygen.ECDSAP256, k.Policy)
		return nil
	})
	require.NoError(t, err)
	assert.True(t, zeroed(seen), "the opened DER is zeroed when the use returns")

	// Also when the use fails.
	boom := errors.New("boom")
	err = openPendingKey(ring, order, env, func(k *keygen.Key) error { seen = k.DER.Bytes(); return boom })
	require.ErrorIs(t, err, boom)
	assert.True(t, zeroed(seen))

	// The AAD binds the key to its order.
	err = openPendingKey(ring, uuid.New(), env, func(*keygen.Key) error { t.Fatal("opened under another order"); return nil })
	require.ErrorIs(t, err, errPendingKeySeal)
	// Another master key cannot open it.
	err = openPendingKey(testKeyring(t), order, env, func(*keygen.Key) error { return nil })
	require.ErrorIs(t, err, errPendingKeySeal)
}

func TestOpenPendingKeyRefusesAnotherKeyType(t *testing.T) {
	ring := testKeyring(t)
	order := uuid.New()
	// A sealed value that is not a PKCS#8 key of a policy.
	env, err := ring.Seal(pendingKeyLocation(order), []byte("not a key"))
	require.NoError(t, err)
	err = openPendingKey(ring, order, env, func(*keygen.Key) error { return nil })
	require.ErrorIs(t, err, errPendingKeySeal)
	assert.Equal(t, secrets.Location{Table: "acme_orders", RowID: order.String(), Column: "pending_key"}, pendingKeyLocation(order))
}

func TestRootsWithAddsTheBundleOnly(t *testing.T) {
	ca := pki.NewCA("Private Root", pki.ECDSA256, acmeNow)
	base := x509.NewCertPool()
	s := &Service{roots: base}
	assert.Same(t, base, s.rootsWith(""))
	assert.Same(t, base, s.rootsWith("  \n"))
	bundle := string(ca.RootPEM)
	inter := x509.NewCertPool()
	inter.AddCert(ca.Intermediate)
	pool := s.rootsWith(bundle + "\n-----BEGIN CERTIFICATE-----\nbm90\n-----END CERTIFICATE-----\n")
	assert.NotSame(t, base, pool)
	leaf := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, acmeNow)
	_, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: acmeNow})
	require.NoError(t, err, "the bundle's root is trusted")
	_, err = leaf.Cert.Verify(x509.VerifyOptions{Roots: base, Intermediates: inter, CurrentTime: acmeNow})
	require.Error(t, err, "the service's roots are unchanged")
}

func TestChainPEM(t *testing.T) {
	ca := pki.NewCA("Root", pki.ECDSA256, acmeNow)
	leaf := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, acmeNow)
	out, err := chainPEM([][]byte{leaf.Cert.Raw, ca.Intermediate.Raw})
	require.NoError(t, err)
	p, err := certs.ParseChainPEM(out)
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, p.Leaf.Raw)
	require.Len(t, p.Chain, 1)
	_, err = chainPEM([][]byte{make([]byte, certs.MaxInputSize)})
	require.ErrorIs(t, err, ErrCertificateTooLarge)
}

func TestCoversNames(t *testing.T) {
	sans := []string{"*.example.test", "Example.test"}
	assert.True(t, coversNames(sans, []string{"*.example.test", "example.test"}))
	assert.True(t, coversNames(sans, nil))
	assert.False(t, coversNames(sans, []string{"www.example.test"}), "a wildcard SAN is not a different ordered name")
	assert.False(t, coversNames(nil, []string{"example.test"}))
}
