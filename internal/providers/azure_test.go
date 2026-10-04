package providers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

func TestAzureIdentityNeverPrints(t *testing.T) {
	secret := "fake-" + strings.Repeat("ab", 20)
	key := []byte("-----BEGIN " + "PRIVATE KEY-----canary")
	id := providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: "t", ClientID: "c",
		ClientSecret: providers.NewSecret([]byte(secret)), PrivateKeyDER: providers.NewSecret(key)}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "id", id)
	raw, err := json.Marshal(id)
	require.NoError(t, err)
	for _, s := range []string{fmt.Sprintf("%v", id), fmt.Sprintf("%+v", id), fmt.Sprintf("%#v", id), fmt.Sprintf("%s", id),
		fmt.Sprintf("%x", id), fmt.Sprintf("%v", &id), buf.String(), string(raw)} {
		assert.NotContains(t, s, secret)
		assert.NotContains(t, s, "canary")
	}
	assert.Contains(t, fmt.Sprintf("%v", id), "auth:client_secret")
	assert.Contains(t, fmt.Sprintf("%v", id), "tenant:t")
	id.Zero()
	assert.Equal(t, make([]byte, len(secret)), id.ClientSecret.Bytes(), "Zero clears the secret in place")
	assert.Equal(t, make([]byte, len(key)), id.PrivateKeyDER.Bytes(), "Zero clears the private key in place")
	assert.NotPanics(t, func() { providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity}.Zero() }, "a holder that was never set")
}

func TestCertificateSecretAndImportRequestNeverPrint(t *testing.T) {
	value := "pfx-" + strings.Repeat("cd", 20)
	cs := providers.CertificateSecret{ContentType: "application/x-pkcs12", Value: providers.NewSecret([]byte(value))}
	op := uuid.New()
	req := providers.ImportRequest{OperationID: op, Name: "web-cert", PFX: providers.NewSecret([]byte(value)), KeyType: "rsa", KeySize: 2048}
	for name, v := range map[string]any{"secret": cs, "secret pointer": &cs, "request": req, "request pointer": &req} {
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "v", v)
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		texts := []string{logs.String(), string(raw)}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
			texts = append(texts, fmt.Sprintf(verb, v))
		}
		for _, s := range texts {
			assert.NotContains(t, s, value, name)
			assert.NotContains(t, s, fmt.Sprintf("%x", value), name)
		}
	}
	assert.Contains(t, fmt.Sprintf("%v", cs), "content_type:application/x-pkcs12")
	assert.Contains(t, fmt.Sprintf("%v", req), op.String())
	assert.Contains(t, fmt.Sprintf("%v", req), "name:web-cert")
	cs.Zero()
	req.Zero()
	assert.Equal(t, make([]byte, len(value)), cs.Value.Bytes())
	assert.Equal(t, make([]byte, len(value)), req.PFX.Bytes())
}

func TestNewSecretHoldsTheBytes(t *testing.T) {
	b := []byte("x")
	s := providers.NewSecret(b)
	s.Zero()
	assert.Equal(t, []byte{0}, b, "the holder shares the caller's bytes")
}

func TestReadAndImportAreUnsupportedByDefault(t *testing.T) {
	var s providers.Session = providers.UnsupportedSession{}
	_, err := s.ReadCertificateSecret(context.Background(), providers.SecretRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	res, err := s.ImportCertificate(context.Background(), providers.ImportRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	assert.Equal(t, providers.ImportResult{}, res, "ErrUnsupported is not an import outcome")
}

func TestReadCertificateSecretIsAKnownCapability(t *testing.T) {
	s := validStub(providers.KindAzureKV)
	s.caps = providers.NewCapabilitySet(providers.CapTestConnection, providers.CapReadCertificateSecret, providers.CapImportCertificate,
		providers.CapDiscoverKVKeys, providers.CapDiscoverKVSecrets)
	assert.NotPanics(t, func() { providers.NewRegistry().Register(s) })
	assert.Equal(t, providers.Capability("read_certificate_secret"), providers.CapReadCertificateSecret)
}

func TestAzureFactsHaveSnakeCaseJSON(t *testing.T) {
	raw, err := json.Marshal(providers.AzureFacts{ObjectID: "o", TenantID: "t", PermissionModel: "rbac",
		Checks: []providers.AzureCheck{{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultForbidden,
			Reason: "azure.forbidden", Role: providers.RoleKeyVaultSecretsUser}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"object_id":"o","tenant_id":"t","permission_model":"rbac","checks":[{"name":"read_secret","result":"forbidden","reason":"azure.forbidden","role":"Key Vault Secrets User"}],"checked_at":"0001-01-01T00:00:00Z"}`, string(raw))
}
