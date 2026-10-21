package inventory

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// verifyAddressCheck is certificate_locations.verify_address's CHECK (migration 00031).
var verifyAddressCheck = regexp.MustCompile(`^[A-Za-z0-9:][A-Za-z0-9.:-]{0,252}$`)

func TestValidProbeAddressAgreesWithTheCheck(t *testing.T) {
	for _, ok := range []string{"10.0.0.5", "2001:db8::7", "::1", "::ffff:10.0.0.1", "lb.internal.example.test", "a", "x-1.example"} {
		assert.True(t, validProbeAddress(ok), ok)
		assert.True(t, verifyAddressCheck.MatchString(ok), "the CHECK takes what Go takes: %s", ok)
	}
	for _, bad := range []string{"", "10.0.0.5%2", "fe80::1%eth0", "lb internal", "*.example.test", "a_b.example", "LB.example",
		"-a.example", strings.Repeat("a", 254), "example.test.", "ı.example"} {
		assert.False(t, validProbeAddress(bad), bad)
	}
}

func TestPrepareLocationOfAnotherKind(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	leaf := pki.NewCA("G", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	base := func() providers.DiscoveredCertificate {
		return providers.DiscoveredCertificate{Location: providers.CertLocation{Kind: providers.LocationF5ClientSSL,
			Locator:  providers.Locator{"partition": "Common", "profile": "/Common/www_clientssl", "entry": "default"},
			CertPath: "/Common/www_clientssl#default", Supported: true, KeyPath: "/x.key", KeyMode: "0600", KeyOwner: "root", KeyGroup: "root",
			ResolvedCertPath: "/y", Symlinked: true, Details: map[string]any{"cert": "/Common/www.crt"}},
			PEMChain: leaf.FullchainPEM, FileSHA256: strings.Repeat("ab", 32)}
	}
	p, ok := prepareLocation(base(), now)
	require.True(t, ok)
	assert.Equal(t, providers.LocationF5ClientSSL, p.kind)
	assert.Equal(t, `{"entry":"default","partition":"Common","profile":"/Common/www_clientssl"}`, string(p.locator))
	assert.Equal(t, `{"cert":"/Common/www.crt"}`, string(p.details))
	assert.Empty(t, p.loc.KeyPath+p.loc.KeyMode+p.loc.KeyOwner+p.loc.KeyGroup+p.loc.ResolvedCertPath)
	assert.False(t, p.loc.Symlinked)
	assert.True(t, p.loc.Supported)
	assert.Equal(t, providers.LocationF5ClientSSL+"\x00/Common/www_clientssl#default", providers.LocationKind(p.identity()))

	file, ok := prepareLocation(dcFile(leaf), now)
	require.True(t, ok)
	assert.Equal(t, providers.LocationServerFile, file.kind)
	assert.Nil(t, file.locator, "a file has no locator")
	assert.Nil(t, file.details)

	long := base()
	long.Location.CertPath = strings.Repeat("x", providers.MaxCanonicalLength+1)
	noLocator := base()
	noLocator.Location.Locator = nil
	unknown := base()
	unknown.Location.Kind = "nginx_file"
	for name, d := range map[string]providers.DiscoveredCertificate{"long text": long, "no locator": noLocator, "unknown kind": unknown} {
		_, ok := prepareLocation(d, now)
		assert.False(t, ok, name)
	}
}

func dcFile(leaf pki.Leaf) providers.DiscoveredCertificate {
	return providers.DiscoveredCertificate{Location: providers.CertLocation{CertPath: "/etc/ssl/a.crt", KeyPath: "/etc/ssl/a.key", Supported: true},
		PEMChain: leaf.FullchainPEM, FileSHA256: strings.Repeat("cd", 32)}
}

func TestHeldBackupPayload(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	ca := pki.NewCA("H", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "a.example.test"}, now)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "r.example.test", KeyType: pki.RSA2048}, now)
	for _, l := range []pki.Leaf{leaf, rsaLeaf} {
		b := providers.HeldBackup{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: secrets.NewPlaintext(bytes.Clone(l.KeyPEM))}
		got, spki, err := checkHeldBackup(b)
		require.NoError(t, err)
		assert.Equal(t, pki.Fingerprint(l.Cert), got)
		assert.Len(t, spki, 64)
		packed := packHeldBackup(b)
		back, ok := unpackHeldBackup(packed)
		require.True(t, ok)
		assert.Equal(t, l.FullchainPEM, back.CertificatePEM)
		assert.Equal(t, l.KeyPEM, back.PrivateKeyPEM.Bytes())
	}
	for name, b := range map[string]providers.HeldBackup{
		"another key":      {CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: secrets.NewPlaintext(bytes.Clone(rsaLeaf.KeyPEM))},
		"no certificate":   {CertificatePEM: leaf.KeyPEM, PrivateKeyPEM: secrets.NewPlaintext(bytes.Clone(leaf.KeyPEM))},
		"a bad cert":       {CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), PrivateKeyPEM: secrets.NewPlaintext(bytes.Clone(leaf.KeyPEM))},
		"no key":           {CertificatePEM: leaf.FullchainPEM},
		"an unknown block": {CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: secrets.NewPlaintext([]byte("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n"))},
		"a bad key":        {CertificatePEM: leaf.FullchainPEM, PrivateKeyPEM: secrets.NewPlaintext([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))},
		"too large":        {CertificatePEM: append(bytes.Clone(leaf.FullchainPEM), make([]byte, maxHeldBackupBytes)...), PrivateKeyPEM: secrets.NewPlaintext(bytes.Clone(leaf.KeyPEM))},
	} {
		_, _, err := checkHeldBackup(b)
		assert.ErrorIs(t, err, errHeldBackupInvalid, name)
	}
	for _, p := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 9, 'a'}} {
		_, ok := unpackHeldBackup(p)
		assert.False(t, ok)
	}
}

func TestTargetCredentialShape(t *testing.T) {
	for _, c := range []struct{ typ, secret, purpose, kind string }{
		{providers.TargetTypeF5BigIP, providers.TargetSecretPassword, "f5_device", "f5_password"},
		{providers.TargetTypeKubernetes, providers.TargetSecretToken, "kubernetes_cluster", "k8s_token"},
		{providers.TargetTypeKubernetes, providers.TargetSecretClientCertificate, "kubernetes_cluster", "k8s_client_cert"},
	} {
		p, k, ok := targetCredentialShape(c.typ, c.secret)
		assert.True(t, ok)
		assert.Equal(t, []string{c.purpose, c.kind}, []string{p, k})
	}
	for _, c := range [][2]string{{providers.TargetTypeWindows, providers.TargetSecretToken}, {"nginx", providers.TargetSecretPassword},
		{providers.TargetTypeF5BigIP, providers.TargetSecretToken}} {
		_, _, ok := targetCredentialShape(c[0], c[1])
		assert.False(t, ok, c)
	}
	assert.Contains(t, VerifyCommand(providers.HostKeyTypeTLSSPKI), "openssl dgst -sha256")
	assert.Contains(t, VerifyCommand("ssh-ed25519"), "ssh-keygen")
}
