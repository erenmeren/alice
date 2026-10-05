package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/pki"
)

func kvPFX(l pki.Leaf, ca *pki.CA) string {
	return base64.StdEncoding.EncodeToString(pki.PFX(l, ca, ""))
}

func TestParseKVSecretPFXAndPEM(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	pfx := kvPFX(leaf, ca)
	for name, tc := range map[string]struct{ ct, value string }{
		"pkcs12":                  {ContentTypePKCS12, pfx},
		"pkcs12 with spaces":      {ContentTypePKCS12, "\n" + pfx + "\n"},
		"pkcs12 with line breaks": {ContentTypePKCS12, strings.Join(chunks(pfx, 76), "\r\n")},
		"pem key first":           {ContentTypePEM, string(leaf.KeyPEM) + string(leaf.FullchainPEM)},
		"pem key last":            {ContentTypePEM, string(leaf.FullchainPEM) + string(leaf.KeyPEM)},
		"pem key between":         {ContentTypePEM, string(leaf.CertPEM) + string(leaf.KeyPEM) + string(ca.IntermediatePEM)},
		"pem with root":           {ContentTypePEM, string(leaf.FullchainPEM) + string(ca.RootPEM) + string(leaf.KeyPEM)},
		"pem with crlf":           {ContentTypePEM, strings.ReplaceAll(string(leaf.FullchainPEM)+string(leaf.KeyPEM), "\n", "\r\n")},
		"pem with text around":    {ContentTypePEM, "# exported\n" + string(leaf.FullchainPEM) + "\nsubject=x\n" + string(leaf.KeyPEM)},
	} {
		in := []byte(tc.value)
		keep := bytes.Clone(in)
		v, err := ParseKVSecret(tc.ct, in, now, nil)
		require.NoError(t, err, name)
		assert.Equal(t, pki.Fingerprint(leaf.Cert), v.Fingerprint, name)
		assert.Len(t, v.Chain, 1, "%s: the intermediate only; a self-signed root is dropped", name)
		assert.Equal(t, 2, strings.Count(v.PEMChain, "BEGIN CERTIFICATE"), name)
		assert.Equal(t, keep, in, "%s: the caller's value is never modified (the caller zeroes it)", name)
		key, kerr := KeyInfoOf(v.PrivateKeyDER)
		require.NoError(t, kerr, name)
		assert.Equal(t, v.PublicKeySHA256, key.PublicKeySHA256, name)
		v.PrivateKeyDER.Zero()
	}
}

func chunks(s string, n int) []string {
	var out []string
	for len(s) > n {
		out, s = append(out, s[:n]), s[n:]
	}
	return append(out, s)
}

func TestParseKVSecretKeepsTheUploadWarnings(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	v, err := ParseKVSecret(ContentTypePKCS12, []byte(kvPFX(leaf, ca)), now, nil)
	require.NoError(t, err)
	assert.Contains(t, v.Warnings, "chain_incomplete", "no roots were given")
	assert.False(t, v.ChainComplete)
	v.PrivateKeyDER.Zero()
	v, err = ParseKVSecret(ContentTypePKCS12, []byte(kvPFX(leaf, ca)), now, rootsOf(ca))
	require.NoError(t, err)
	assert.True(t, v.ChainComplete, "completeness is judged before the root is dropped")
	assert.NotContains(t, v.Warnings, "chain_incomplete")
	v.PrivateKeyDER.Zero()
}

func TestParseKVSecretRefusals(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	weak := pki.NewCA("Weak CA", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "weak.example.test", KeyType: pki.RSA1024}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, -1)}, now)
	canary := "CANARY-" + strings.Repeat("7f", 12)
	garbage := "-----BEGIN " + "PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte(canary)) + "\n-----END " + "PRIVATE KEY-----\n"
	pfxWithPassword, err := pkcs12.Modern.Encode(leaf.Key, leaf.Cert, []*x509.Certificate{ca.Intermediate}, "pw")
	require.NoError(t, err)
	many := bytes.Repeat(leaf.CertPEM, maxCertificates+1)

	trustStore, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{leaf.Cert, ca.Intermediate}, "")
	require.NoError(t, err)

	cases := []struct {
		name  string
		ct    string
		value []byte
		want  error
	}{
		// A non-exportable certificate's secret: a PFX with the certificates and no key (as the PEM form without a key).
		{"pfx without a key (a Java trust store)", ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(trustStore)), ErrNoKey},
		{"pfx without a key (openssl -nokeys, .NET: no trust attribute, encrypted safe, MAC)", ContentTypePKCS12,
			[]byte(base64.StdEncoding.EncodeToString(pki.CertificatesOnlyPFX("", leaf.Cert, ca.Intermediate))), ErrNoKey},
		// Pinned limit (final review re-review m-2): go-pkcs12 v0.7.3 reads only top-level key bags, so a PFX whose key
		// sits in a nested SafeContentsBag is read as one without a key (Monitor only), not as unreadable.
		{"pfx whose key is in a nested safe contents bag (read as without a key)", ContentTypePKCS12,
			[]byte(base64.StdEncoding.EncodeToString(pki.NestedKeyPFX("", leaf.Key, leaf.Cert, ca.Intermediate))), ErrNoKey},
		{"pfx without a key whose password is not empty", ContentTypePKCS12,
			[]byte(base64.StdEncoding.EncodeToString(pki.CertificatesOnlyPFX("pw", leaf.Cert))), ErrPFXPassword},
		{"unknown content type", "text/plain", []byte(kvPFX(leaf, ca)), ErrKVContentType},
		{"blank content type", "", []byte(kvPFX(leaf, ca)), ErrKVContentType},
		{"content type with a parameter", ContentTypePKCS12 + "; charset=utf-8", []byte(kvPFX(leaf, ca)), ErrKVContentType},
		{"content type in upper case", "APPLICATION/X-PKCS12", []byte(kvPFX(leaf, ca)), ErrKVContentType},
		{"json content type", "application/json", []byte(`{"a":"b"}`), ErrKVContentType},
		{"pfx that is not base64", ContentTypePKCS12, []byte("not base64 " + canary), ErrInvalid},
		{"pfx that is base64 of something else", ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString([]byte(canary))), ErrInvalid},
		{"empty pfx", ContentTypePKCS12, nil, ErrInvalid},
		{"pfx with a password", ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(pfxWithPassword)), ErrPFXPassword},
		{"pem without a key", ContentTypePEM, leaf.FullchainPEM, ErrNoKey},
		{"pem with an unparsable key", ContentTypePEM, []byte(string(leaf.FullchainPEM) + garbage), ErrInvalid},
		{"pem without a certificate", ContentTypePEM, leaf.KeyPEM, ErrInvalid},
		{"empty pem", ContentTypePEM, nil, ErrInvalid},
		{"pem with text only", ContentTypePEM, []byte(canary), ErrInvalid},
		{"pem whose key belongs to another certificate", ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), other.KeyPEM...), ErrKeyMismatch},
		{"pem with two keys", ContentTypePEM, append(append(append([]byte{}, leaf.FullchainPEM...), leaf.KeyPEM...), other.KeyPEM...), ErrInvalid},
		{"pem with an encrypted key", ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), pki.EncryptedKeyPEM(leaf)...), ErrKeyEncrypted},
		{"pem with an encrypted pkcs8 key", ContentTypePEM, []byte(string(leaf.FullchainPEM) + "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED " + "PRIVATE KEY-----\n"), ErrKeyEncrypted},
		{"pem with too many certificates", ContentTypePEM, append(append([]byte{}, many...), leaf.KeyPEM...), ErrInvalid},
		{"expired leaf", ContentTypePEM, append(append([]byte{}, expired.FullchainPEM...), expired.KeyPEM...), ErrExpired},
		{"expired leaf in a pfx", ContentTypePKCS12, []byte(kvPFX(expired, ca)), ErrExpired},
		{"rsa 1024 leaf", ContentTypePEM, append(append([]byte{}, weak.CertPEM...), weak.KeyPEM...), ErrWeak},
		{"value above the bound", ContentTypePEM, bytes.Repeat([]byte("a"), MaxKVSecretSize+1), ErrTooLarge},
		{"pfx above the bound", ContentTypePKCS12, bytes.Repeat([]byte("A"), MaxKVSecretSize+1), ErrTooLarge},
		{"oversized value with a wrong content type", "text/plain", bytes.Repeat([]byte("a"), MaxKVSecretSize+1), ErrTooLarge},
	}
	for _, tc := range cases {
		v, err := ParseKVSecret(tc.ct, tc.value, now, nil)
		require.ErrorIs(t, err, tc.want, tc.name)
		assert.Nil(t, v.Leaf, tc.name)
		assert.Empty(t, v.PrivateKeyDER.Bytes(), "%s: no key comes back with an error", tc.name)
		for _, text := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			assert.NotContains(t, text, canary, tc.name)
			assert.NotContains(t, text, "MII", tc.name, "no key bytes in the error")
		}
	}
	// The same value at exactly the bound is read (and refused for what it is, not for its size).
	_, err = ParseKVSecret(ContentTypePEM, bytes.Repeat([]byte("a"), MaxKVSecretSize), now, nil)
	assert.ErrorIs(t, err, ErrInvalid)
}

// The checks uploads apply to hostile files hold for a vault secret too: iteration bombs, oversized
// RSA moduli and dates outside the years 1 to 9999.
func TestParseKVSecretAppliesTheUploadBounds(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)

	base, err := pkcs12.LegacyDES.Encode(leaf.Key, leaf.Cert, []*x509.Certificate{ca.Intermediate}, "")
	require.NoError(t, err)
	_, err = ParseKVSecret(ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(base)), now, nil)
	require.NoError(t, err, "the unmodified file is fine")
	for _, where := range []string{"mac", "content", "key"} {
		hostile := hostilePFX(t, base, where, 1<<40)
		start := time.Now()
		_, err = ParseKVSecret(ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(hostile)), now, nil)
		assert.ErrorIs(t, err, ErrInvalid, where)
		assert.Less(t, time.Since(start), 2*time.Second, "%s: refused before any key derivation", where)
	}

	big := selfSignedLookingRSA(t, 4096/8*5, "big.example.test") // an RSA modulus of 20480 bits
	_, err = ParseKVSecret(ContentTypePEM, append(append([]byte{}, big...), leaf.KeyPEM...), now, nil)
	assert.ErrorIs(t, err, ErrUnsupportedKey)

	g := pki.GeneralizedTime
	edge := ca.IssueRawValidity(pki.Opts{CommonName: "edge.example.test"}, g("20260101000000Z"), g("99991231235959-2359"), now)
	_, err = ParseKVSecret(ContentTypePEM, append(append([]byte{}, edge.FullchainPEM...), edge.KeyPEM...), now, nil)
	assert.ErrorIs(t, err, ErrInvalid, "a certificate outside the years 1 to 9999")
	_, err = ParseKVSecret(ContentTypePKCS12, []byte(kvPFX(edge, ca)), now, nil)
	assert.ErrorIs(t, err, ErrInvalid)
}

// Every buffer ParseKVSecret owns holds key material at some point and is zero when it returns,
// on success and on every refusal; the caller's value is the caller's to clear.
func TestParseKVSecretClearsEveryBufferItOwns(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, -1)}, now)
	for name, tc := range map[string]struct {
		ct    string
		value []byte
		ok    bool
	}{
		"pfx":                   {ContentTypePKCS12, []byte(kvPFX(leaf, ca)), true},
		"pfx expired":           {ContentTypePKCS12, []byte(kvPFX(expired, ca)), false},
		"pfx not base64":        {ContentTypePKCS12, []byte("%%%%"), false},
		"pem":                   {ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), leaf.KeyPEM...), true},
		"pem key first":         {ContentTypePEM, append(append([]byte{}, leaf.KeyPEM...), leaf.FullchainPEM...), true},
		"pem key mismatch":      {ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), other.KeyPEM...), false},
		"pem expired":           {ContentTypePEM, append(append([]byte{}, expired.FullchainPEM...), expired.KeyPEM...), false},
		"pem two keys":          {ContentTypePEM, append(append(append([]byte{}, leaf.FullchainPEM...), leaf.KeyPEM...), other.KeyPEM...), false},
		"pem without a cert":    {ContentTypePEM, leaf.KeyPEM, false},
		"pem encrypted key":     {ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), pki.EncryptedKeyPEM(leaf)...), false},
		"pem key with junk":     {ContentTypePEM, append(append([]byte("junk\n"), leaf.KeyPEM...), leaf.FullchainPEM...), true},
		"unknown content type":  {"text/plain", leaf.KeyPEM, false},
		"too large":             {ContentTypePEM, bytes.Repeat(leaf.KeyPEM, MaxKVSecretSize/len(leaf.KeyPEM)+1), false},
		"too many cert blocks":  {ContentTypePEM, append(bytes.Repeat(leaf.CertPEM, maxCertificates+1), leaf.KeyPEM...), false},
		"hostile pem key block": {ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), []byte("-----BEGIN "+"EC PARAMETERS-----\nAAAA\n-----END "+"EC PARAMETERS-----\n")...), false},
	} {
		var scratch kvScratch
		var sawKey bool
		var decoded [][]byte
		scratch.onWipe = func(b []byte) { sawKey = sawKey || !allZero(b) }
		scratch.onDecode = func(b *pem.Block) {
			if b.Type != "CERTIFICATE" { // certificates are public
				decoded = append(decoded, b.Bytes)
			}
		}
		v, err := parseKVSecret(tc.ct, tc.value, now, nil, &scratch)
		for i, b := range decoded {
			assert.True(t, allZero(b), "%s: the bytes pem.Decode allocated for non-certificate block %d are cleared, a refused second key's too", name, i)
		}
		if tc.ok {
			require.NoError(t, err, name)
			v.PrivateKeyDER.Zero()
		} else {
			require.Error(t, err, name)
		}
		for i, b := range scratch.bufs {
			assert.True(t, allZero(b[:cap(b)]), "%s: scratch buffer %d is cleared on return", name, i)
		}
		if tc.ct == ContentTypePKCS12 && name == "pfx" || tc.ct == ContentTypePEM && tc.ok {
			assert.True(t, sawKey, "%s: the scratch buffers did hold the secret before they were cleared", name)
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestWithoutRootKeepsAChainWithoutRoot(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	p, err := describeForTest(leaf.Cert, ca.Intermediate)
	require.NoError(t, err)

	// [intermediate] stays as it is.
	same := WithoutRoot(p)
	assert.Equal(t, p.Chain, same.Chain)
	assert.Equal(t, p.PEMChain, same.PEMChain)

	// [intermediate, root] loses the self-signed root and PEMChain is re-encoded.
	withRoot := p
	withRoot.Chain = []*x509.Certificate{ca.Intermediate, ca.Root}
	got := WithoutRoot(withRoot)
	assert.Equal(t, []*x509.Certificate{ca.Intermediate}, got.Chain)
	assert.Equal(t, string(leaf.CertPEM)+string(ca.IntermediatePEM), got.PEMChain)
	assert.Len(t, withRoot.Chain, 2, "the argument is not modified")

	// [] stays empty.
	alone := p
	alone.Chain, alone.PEMChain = nil, string(leaf.CertPEM)
	assert.Equal(t, alone, WithoutRoot(alone))

	// A self-signed leaf alone is never dropped.
	ss := pki.SelfSigned("self.example.test", pki.ECDSA256, now)
	ps, err := describeForTest(ss.Cert)
	require.NoError(t, err)
	assert.Equal(t, ps, WithoutRoot(ps))
	assert.Equal(t, ss.Cert, WithoutRoot(ps).Leaf)

	// A last certificate that merely names itself, without a verifying self-signature, stays.
	liar := *ca.Root
	liar.Signature = bytes.Repeat([]byte{1}, len(ca.Root.Signature))
	spoof := p
	spoof.Chain = []*x509.Certificate{ca.Intermediate, &liar}
	assert.Len(t, WithoutRoot(spoof).Chain, 2)

	// A cross-signed intermediate that is not self-signed stays; only the last certificate is judged.
	middle := p
	middle.Chain = []*x509.Certificate{ca.Root, ca.Intermediate}
	assert.Len(t, WithoutRoot(middle).Chain, 2, "a root in the middle of a path is not dropped")

	// Zero value and a chain without a leaf do not panic.
	assert.NotPanics(t, func() { WithoutRoot(Parsed{}) })
	assert.NotPanics(t, func() { WithoutRoot(Parsed{Chain: []*x509.Certificate{ca.Root}}) })
}

func describeForTest(leaf *x509.Certificate, chain ...*x509.Certificate) (Parsed, error) {
	return describe(leaf, chain), nil
}

func FuzzParseKVSecret(f *testing.F) {
	ca := pki.NewCA("Fuzz CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "f.example.test"}, now)
	f.Add(ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(pki.PFX(leaf, ca, ""))))
	f.Add(ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), leaf.KeyPEM...))
	f.Add(ContentTypePEM, []byte("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"))
	f.Add(ContentTypePEM, []byte("-----BEGIN "+"PRIVATE KEY-----\n-----BEGIN "+"PRIVATE KEY-----\n-----END "+"PRIVATE KEY-----\n"))
	f.Add(ContentTypePKCS12, []byte("AAAA\n"))
	f.Fuzz(func(t *testing.T, ct string, value []byte) {
		keep := bytes.Clone(value)
		var scratch kvScratch
		v, err := parseKVSecret(ct, value, now, nil, &scratch)
		require.Equal(t, keep, value, "the caller's value is never modified")
		for _, b := range scratch.bufs {
			require.True(t, allZero(b[:cap(b)]), "every scratch buffer is cleared on return")
		}
		if err != nil {
			require.Nil(t, v.Leaf)
			require.Empty(t, v.PrivateKeyDER.Bytes())
			if len(value) >= 16 {
				require.NotContains(t, err.Error(), string(value), "an error never carries input")
			}
			return
		}
		require.NotNil(t, v.Leaf)
		require.NotEmpty(t, v.PrivateKeyDER.Bytes())
		v.PrivateKeyDER.Zero()
	})
}

func TestParseKVSecretSkipsAByteOrderMark(t *testing.T) {
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	in := append([]byte("\xef\xbb\xbf"), append(append([]byte{}, leaf.KeyPEM...), leaf.FullchainPEM...)...)
	keep := bytes.Clone(in)
	v, err := ParseKVSecret(ContentTypePEM, in, now, nil)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), v.Fingerprint)
	assert.Equal(t, keep, in, "the value is not modified")
	v.PrivateKeyDER.Zero()
}
