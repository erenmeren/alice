package azurekv

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/providertest"
	"alice/internal/testutil/fakekv"
)

func TestProviderContract(t *testing.T) {
	p := New(Options{})
	providertest.CheckProvider(t, p)
	assert.Equal(t, providers.KindAzureKV, p.Kind())
	assert.Equal(t, "provider.azurekv.name", p.DisplayNameKey())
	for _, c := range []providers.Capability{providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDiscoverKVKeys,
		providers.CapDiscoverKVSecrets, providers.CapReadCertificateSecret, providers.CapImportCertificate} {
		assert.True(t, p.Capabilities().Has(c), c)
	}
	assert.False(t, p.Capabilities().Has(providers.CapDeployCertificate))
	var _ providers.ConnectionCache = p
	fields := p.CredentialSchema().Fields
	require.NotEmpty(t, fields)
	assert.Equal(t, "auth", fields[0].Name)
}

func TestValidateConfig(t *testing.T) {
	p := New(Options{})
	assert.Empty(t, p.ValidateConfig(providers.TargetConfig{"vault_url": "https://contoso.vault.azure.net"}))
	assert.Equal(t, []validate.FieldError{{Field: "vault_url", Code: validate.Required}}, p.ValidateConfig(providers.TargetConfig{}))
	assert.Equal(t, []validate.FieldError{{Field: "vault_url", Code: validate.Required}}, p.ValidateConfig(providers.TargetConfig{"vault_url": 7}))
	for _, bad := range []string{"http://contoso.vault.azure.net", "https://contoso.vault.azure.net:8443",
		"https://contoso.vault.azure.net.evil.test", "https://contoso.vault.azure.net/secrets", "contoso.vault.usgovcloudapi.net"} {
		assert.Equal(t, []validate.FieldError{{Field: "vault_url", Code: validate.Pattern}}, p.ValidateConfig(providers.TargetConfig{"vault_url": bad}), bad)
	}
	// The schema pattern agrees with ParseVault's normal form.
	f := p.ConfigSchema().Fields[0]
	assert.True(t, f.MatchPattern("https://contoso-prod.vault.azure.net"))
	assert.False(t, f.MatchPattern("https://contoso.vault.azure.net/"))
	assert.False(t, f.MatchPattern("https://contoso.vault.azure.net.evil.test"))
}

func TestSessionStaysUnsupportedBeyondItsCapabilities(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	providertest.CheckUnsupported(t, sess, providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts,
		providers.CapDiscoverKVKeys, providers.CapDiscoverKVSecrets, providers.CapReadCertificateSecret, providers.CapImportCertificate,
		providers.CapAuthorizedKeys))
	require.NoError(t, sess.Close())
	_, err := sess.TestConnection(context.Background())
	assert.NotErrorIs(t, err, providers.ErrUnsupported, "an advertised operation is implemented")
}

// The SDK implementation of kvAPI against the fake: every method once.
func TestSDKAPIAgainstTheFake(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := addSeed(s)
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	s.AddSecret("db-password", "text/plain")
	clk := nearNow()
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
	ctx := context.Background()

	var certs, versions, keys, secrets []string
	require.NoError(t, drive(clk, func() error {
		return sess.api.ListCertificates(ctx, func(p []*azcertificates.CertificateProperties) error {
			for _, x := range p {
				certs = append(certs, x.ID.Name())
			}
			return nil
		})
	}))
	assert.Equal(t, []string{"web-cert"}, certs)
	require.NoError(t, drive(clk, func() error {
		return sess.api.ListCertificateVersions(ctx, "web-cert", func(p []*azcertificates.CertificateProperties) error {
			for _, x := range p {
				versions = append(versions, x.ID.Version())
			}
			return nil
		})
	}))
	assert.Equal(t, []string{ver}, versions)
	require.NoError(t, drive(clk, func() error {
		return sess.api.ListKeys(ctx, func(p []*azkeys.KeyProperties) error {
			for _, x := range p {
				keys = append(keys, x.KID.Name())
			}
			return nil
		})
	}))
	assert.Contains(t, keys, "signing")
	require.NoError(t, drive(clk, func() error {
		return sess.api.ListSecrets(ctx, func(p []*azsecrets.SecretProperties) error {
			for _, x := range p {
				secrets = append(secrets, x.ID.Name())
			}
			return nil
		})
	}))
	assert.Contains(t, secrets, "db-password")
	kb, err := sess.api.GetKey(ctx, "signing")
	require.NoError(t, err)
	assert.NotNil(t, kb.Key)
	sec, err := sess.api.GetSecret(ctx, "web-cert", ver)
	require.NoError(t, err)
	assert.Equal(t, string(s.SecretValue("web-cert", ver)), *sec.Value)
	// A callback error stops the listing and comes back as it is.
	stop := assert.AnError
	err = drive(clk, func() error {
		return sess.api.ListCertificates(ctx, func([]*azcertificates.CertificateProperties) error { return stop })
	})
	assert.ErrorIs(t, err, stop)
}
