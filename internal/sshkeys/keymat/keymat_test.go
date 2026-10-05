package keymat

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

func TestGenerateEveryType(t *testing.T) {
	cases := []struct {
		t         KeyType
		algorithm string
		bits      int
		sshType   string
	}{
		{Ed25519, "ed25519", 256, "ssh-ed25519"},
		{RSA3072, "rsa", 3072, "ssh-rsa"},
		{RSA4096, "rsa", 4096, "ssh-rsa"},
		{ECDSAP256, "ecdsa", 256, "ecdsa-sha2-nistp256"},
	}
	for _, c := range cases {
		t.Run(string(c.t), func(t *testing.T) {
			m, err := Generate(rand.Reader, c.t)
			require.NoError(t, err)
			defer m.PKCS8.Zero()
			assert.Equal(t, c.algorithm, m.Algorithm)
			assert.Equal(t, c.bits, m.Bits)
			assert.True(t, strings.HasPrefix(m.PublicKey, c.sshType+" "), m.PublicKey)
			assert.Regexp(t, `^SHA256:[A-Za-z0-9+/]{43}$`, m.Fingerprint)
			assert.Regexp(t, `^[0-9a-f]{64}$`, m.PublicKeySHA256)
			pub, fp, err := PublicOf(m.PKCS8)
			require.NoError(t, err)
			assert.Equal(t, m.PublicKey, pub)
			assert.Equal(t, m.Fingerprint, fp)
			assert.Equal(t, c.t, TypeOf(m.Algorithm, m.Bits))
		})
	}
}

func TestGenerateRefusesUnknownTypeAndShortRandomness(t *testing.T) {
	_, err := Generate(rand.Reader, KeyType("dsa"))
	assert.ErrorIs(t, err, ErrKeyType)
	_, err = Generate(bytes.NewReader(make([]byte, 5)), Ed25519)
	assert.Error(t, err)
	// Since Go 1.24 the standard library ignores the reader for RSA and ECDSA unless asked to use it.
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	for _, kt := range []KeyType{RSA3072, ECDSAP256} {
		_, err = Generate(bytes.NewReader(make([]byte, 5)), kt)
		assert.Error(t, err, kt)
	}
	assert.Equal(t, []KeyType{Ed25519, RSA3072, RSA4096, ECDSAP256}, KeyTypes())
	assert.False(t, KeyType("").Valid())
	for _, kt := range KeyTypes() {
		assert.True(t, kt.Valid(), kt)
	}
	assert.Equal(t, Ed25519, TypeOf("rsa", 2048), "an unknown size falls back to the default type")
}

func TestGenerateNilReaderUsesCryptoRand(t *testing.T) {
	m, err := Generate(nil, Ed25519)
	require.NoError(t, err)
	m.PKCS8.Zero()
	assert.NotEmpty(t, m.Fingerprint)
}

func TestEd25519IsDeterministicFromTheReader(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	a, err := Generate(bytes.NewReader(seed), Ed25519)
	require.NoError(t, err)
	defer a.PKCS8.Zero()
	b, err := Generate(bytes.NewReader(seed), Ed25519)
	require.NoError(t, err)
	defer b.PKCS8.Zero()
	assert.Equal(t, a.Fingerprint, b.Fingerprint)
}

// Review Focus 2: a Material never prints its private key, whatever renders it.
func TestMaterialNeverPrints(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	der := append([]byte(nil), m.PKCS8.Bytes()...)
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("m", "material", m)
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	for _, out := range []string{fmt.Sprint(m), fmt.Sprintf("%+v %#v %s %q %x", m, m, m, m, m), string(raw), logs.String()} {
		assert.Contains(t, out, m.Fingerprint)
		assert.NotContains(t, out, string(der))
		assert.NotContains(t, out, fmt.Sprintf("%x", der[len(der)-16:]))
	}
}

func TestOpenSSHFileRoundTrip(t *testing.T) {
	for _, kt := range KeyTypes() {
		t.Run(string(kt), func(t *testing.T) {
			m, err := Generate(rand.Reader, kt)
			require.NoError(t, err)
			defer m.PKCS8.Zero()
			plain, err := OpenSSHFile(m.PKCS8, "alice:web:2026-10-05", nil)
			require.NoError(t, err)
			defer plain.Zero()
			assert.True(t, bytes.HasPrefix(plain.Bytes(), []byte("-----BEGIN "+"OPENSSH PRIVATE KEY-----\n")))
			k, err := ssh.ParseRawPrivateKey(plain.Bytes())
			require.NoError(t, err)
			s, err := ssh.NewSignerFromKey(k)
			require.NoError(t, err)
			assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))

			pass := []byte("correct horse battery")
			locked, err := OpenSSHFile(m.PKCS8, "alice:web:2026-10-05", pass)
			require.NoError(t, err)
			defer locked.Zero()
			_, err = ssh.ParseRawPrivateKey(locked.Bytes())
			var missing *ssh.PassphraseMissingError
			assert.ErrorAs(t, err, &missing)
			_, err = ssh.ParseRawPrivateKeyWithPassphrase(locked.Bytes(), []byte("wrong passphrase!"))
			assert.Error(t, err)
			k2, err := ssh.ParseRawPrivateKeyWithPassphrase(locked.Bytes(), pass)
			require.NoError(t, err)
			s2, err := ssh.NewSignerFromKey(k2)
			require.NoError(t, err)
			assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s2.PublicKey()))
		})
	}
}

func TestOpenSSHFileRefusals(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	_, err = OpenSSHFile(m.PKCS8, "c", []byte("short"))
	assert.ErrorIs(t, err, ErrPassphrase)
	_, err = OpenSSHFile(m.PKCS8, "c", bytes.Repeat([]byte("x"), MaxPassphrase+1))
	assert.ErrorIs(t, err, ErrPassphrase)
	_, err = OpenSSHFile(m.PKCS8, "two words", nil)
	assert.ErrorIs(t, err, ErrLine)
	_, err = OpenSSHFile(secrets.NewPlaintext([]byte("not a key")), "c", nil)
	assert.ErrorIs(t, err, ErrKeyData)
	_, _, err = PublicOf(secrets.NewPlaintext([]byte{0x30, 0x00}))
	assert.ErrorIs(t, err, ErrKeyData)
}

// S-11: the PEM block's DER, which OpenSSHFile owns, is cleared before it returns.
func TestOpenSSHZeroesItsCopies(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	var seen []byte
	onBlock = func(b []byte) { seen = b }
	defer func() { onBlock = nil }()
	out, err := OpenSSHFile(m.PKCS8, "c", []byte("a long enough passphrase"))
	require.NoError(t, err)
	require.NotEmpty(t, seen)
	assert.Equal(t, make([]byte, len(seen)), seen, "the block's bytes were cleared")
	out.Zero()
	assert.Equal(t, make([]byte, len(out.Bytes())), out.Bytes())
}

func TestSignerSignsAndReleases(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	s, release, err := Signer(m.PKCS8)
	require.NoError(t, err)
	assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))
	sig, err := s.Sign(rand.Reader, []byte("data"))
	require.NoError(t, err)
	require.NoError(t, s.PublicKey().Verify([]byte("data"), sig))
	release()
	_, _, err = Signer(secrets.NewPlaintext([]byte("x")))
	assert.ErrorIs(t, err, ErrKeyData)
}

// The parsed Ed25519 key a signer holds is cleared by release.
func TestWipeClearsEd25519(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	priv, err := parse(m.PKCS8)
	require.NoError(t, err)
	k, ok := priv.(ed25519.PrivateKey)
	require.True(t, ok)
	require.NotEqual(t, make([]byte, len(k)), []byte(k))
	wipe(priv)
	assert.Equal(t, make([]byte, ed25519.PrivateKeySize), []byte(k), "the key bytes are zero after wipe")
}

// A stored key of an algorithm Alice does not generate (X25519 here) is refused everywhere.
func TestStoredKeyOfAnotherAlgorithmIsRefused(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	p := secrets.NewPlaintext(der)
	_, _, err = PublicOf(p)
	assert.ErrorIs(t, err, ErrKeyData)
	_, err = OpenSSHFile(p, "c", nil)
	assert.ErrorIs(t, err, ErrKeyData)
	_, _, err = Signer(p)
	assert.ErrorIs(t, err, ErrKeyData)
}

func TestMaterialGoString(t *testing.T) {
	m := Material{Fingerprint: "SHA256:x"}
	assert.Equal(t, "keymat.Material{SHA256:x}", m.GoString())
}
