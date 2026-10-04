//go:build azure

package azurekv

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// The owner's optional suite against a real vault (R40 row 30). It never runs in make test, make
// coverage or make ci: `make test-azure`. Nothing here is claimed as verified until the owner ran it.
//
//	ALICE_AZURE_TEST_VAULT_URL     https://<name>.vault.azure.net
//	ALICE_AZURE_TEST_TENANT_ID     the tenant (a GUID)
//	ALICE_AZURE_TEST_CLIENT_ID     the application (client) ID
//	ALICE_AZURE_TEST_CLIENT_SECRET its client secret, or
//	ALICE_AZURE_TEST_CERT_FILE     a PEM file with its certificate and private key
//	ALICE_AZURE_TEST_CERT_NAME     an exportable certificate of the vault with at least one version
//	ALICE_AZURE_TEST_READER_CLIENT_ID / _READER_CLIENT_SECRET   (reader sufficiency, R22) an identity
//	                               that holds only Key Vault Reader on the vault
const envHelp = "ALICE_AZURE_TEST_VAULT_URL, ALICE_AZURE_TEST_TENANT_ID, ALICE_AZURE_TEST_CLIENT_ID, ALICE_AZURE_TEST_CLIENT_SECRET (or ALICE_AZURE_TEST_CERT_FILE), ALICE_AZURE_TEST_CERT_NAME"

type realVault struct {
	url, tenant, client, secret, certFile, certName string
}

func realConfig(t *testing.T) realVault {
	t.Helper()
	v := realVault{os.Getenv("ALICE_AZURE_TEST_VAULT_URL"), os.Getenv("ALICE_AZURE_TEST_TENANT_ID"), os.Getenv("ALICE_AZURE_TEST_CLIENT_ID"),
		os.Getenv("ALICE_AZURE_TEST_CLIENT_SECRET"), os.Getenv("ALICE_AZURE_TEST_CERT_FILE"), os.Getenv("ALICE_AZURE_TEST_CERT_NAME")}
	if v.url == "" || v.tenant == "" || v.client == "" || (v.secret == "" && v.certFile == "") || v.certName == "" {
		t.Skip("real Azure suite: set " + envHelp)
	}
	return v
}

func (v realVault) identity(t *testing.T) providers.AzureIdentity {
	t.Helper()
	if v.secret != "" {
		return providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: v.tenant, ClientID: v.client, ClientSecret: providers.NewSecret([]byte(v.secret))}
	}
	raw, err := os.ReadFile(v.certFile) //nolint:gosec // G304: the owner's own file, named in the environment
	require.NoError(t, err)
	id := providers.AzureIdentity{Auth: providers.AzureAuthCertificate, TenantID: v.tenant, ClientID: v.client}
	for len(raw) > 0 {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			if id.CertificateDER == nil {
				id.CertificateDER = b.Bytes
			}
		case "PRIVATE KEY":
			id.PrivateKeyDER = providers.NewSecret(b.Bytes)
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
			require.NoError(t, err)
			der, err := x509.MarshalPKCS8PrivateKey(k)
			require.NoError(t, err)
			id.PrivateKeyDER = providers.NewSecret(der)
		}
	}
	require.NotEmpty(t, id.CertificateDER, "the PEM file holds a CERTIFICATE block")
	require.NotEmpty(t, id.PrivateKeyDER.Bytes(), "the PEM file holds a PRIVATE KEY block")
	return id
}

func (v realVault) open(t *testing.T, id providers.AzureIdentity) *session {
	t.Helper()
	ref := providers.TargetRef{ID: uuid.New(), Kind: providers.KindAzureKV, Config: providers.TargetConfig{"vault_url": v.url}}
	sess, err := New(Options{}).Open(context.Background(), ref, &idSource{id: id}, providers.Env{Clock: clock.Real{}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	return sess.(*session)
}

func TestRealAzure(t *testing.T) {
	v := realConfig(t)
	runContract(t, contractEnv{
		certName: v.certName,
		open:     func(t *testing.T) providers.Session { return v.open(t, v.identity(t)) },
		// No renewal: a real certificate renews by its own policy.
	})
}

// TestRealAzureReaderSufficiency is R22: an identity with only Key Vault Reader lists certificates,
// keys and secrets and reads a certificate, and is refused a secret value. The result is printed for
// the owner's record; the product's access check and role messages rest on it.
func TestRealAzureReaderSufficiency(t *testing.T) {
	v := realConfig(t)
	rid, rsecret := os.Getenv("ALICE_AZURE_TEST_READER_CLIENT_ID"), os.Getenv("ALICE_AZURE_TEST_READER_CLIENT_SECRET")
	if rid == "" || rsecret == "" {
		t.Skip("reader sufficiency: set ALICE_AZURE_TEST_READER_CLIENT_ID and ALICE_AZURE_TEST_READER_CLIENT_SECRET")
	}
	sess := v.open(t, providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: v.tenant, ClientID: rid, ClientSecret: providers.NewSecret([]byte(rsecret))})
	ctx := context.Background()
	rep, err := sess.TestConnection(ctx)
	require.NoError(t, err)
	for _, c := range rep.Azure.Checks[:4] {
		t.Logf("reader: %s -> %s %s %s", c.Name, c.Result, c.Reason, c.Role)
		assert.Equal(t, providers.AzureResultOK, c.Result, c.Name)
	}
	cert, err := sess.api.GetCertificate(ctx, v.certName, "")
	require.NoError(t, err, "GetCertificate with Reader")
	t.Logf("reader: GetCertificate -> ok")
	ver := cert.ID.Version()
	_, err = sess.ReadCertificateSecret(ctx, providers.SecretRequest{Name: v.certName, Version: ver})
	pe := asProviderError(t, err)
	t.Logf("reader: GetSecret -> %s (want %s)", pe.Code, codeForbidden)
	assert.Equal(t, codeForbidden, pe.Code)
	if _, err := sess.api.GetKey(ctx, v.certName); err != nil {
		t.Logf("reader: GetKey of the certificate's key -> %s", asProviderError(t, err).Code)
	} else {
		t.Logf("reader: GetKey of the certificate's key -> ok")
	}
}
