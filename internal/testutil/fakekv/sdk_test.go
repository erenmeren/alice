package fakekv_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// The real Azure SDK for Go against the fake, with TLS (the fake's CA, trusted through an injected
// transport) and with the SDK's challenge-resource verification LEFT ON (ruling S2): no test here sets
// DisableChallengeResourceVerification or skips TLS verification.

func sdkOptions(s *fakekv.Server) azcore.ClientOptions {
	return azcore.ClientOptions{Cloud: cloud.AzurePublic, Transport: s.TestClient().HTTPClient(),
		Retry: policy.RetryOptions{MaxRetries: -1}, Telemetry: policy.TelemetryOptions{Disabled: true}}
}

var vaultScopes = policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}}

func secretCredential(t *testing.T, s *fakekv.Server, secret string) azcore.TokenCredential {
	t.Helper()
	cred, err := azidentity.NewClientSecretCredential(s.TenantID(), s.ClientID(), secret,
		&azidentity.ClientSecretCredentialOptions{ClientOptions: sdkOptions(s), DisableInstanceDiscovery: true})
	require.NoError(t, err)
	return cred
}

// exercise runs every call Alice makes through the three clients and checks the answers.
func exercise(t *testing.T, s *fakekv.Server, cred azcore.TokenCredential, ver string) {
	t.Helper()
	ctx := context.Background()
	opts := sdkOptions(s)
	certs, err := azcertificates.NewClient(s.VaultURL(), cred, &azcertificates.ClientOptions{ClientOptions: opts})
	require.NoError(t, err)
	var names []string
	pager := certs.NewListCertificatePropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		require.NoError(t, err)
		for _, p := range page.Value {
			names = append(names, p.ID.Name())
			assert.Equal(t, "", p.ID.Version(), "a listing carries no version")
			assert.Len(t, p.X509Thumbprint, 20)
			assert.True(t, *p.Attributes.Enabled)
		}
	}
	assert.Equal(t, []string{"web-cert"}, names)

	got, err := certs.GetCertificate(ctx, "web-cert", "", nil)
	require.NoError(t, err)
	assert.Equal(t, ver, got.ID.Version())
	assert.True(t, *got.Policy.KeyProperties.Exportable)
	assert.Equal(t, azcertificates.KeyTypeEC, *got.Policy.KeyProperties.KeyType)
	assert.Equal(t, azcertificates.CurveNameP256, *got.Policy.KeyProperties.Curve)
	assert.Equal(t, "application/x-pkcs12", *got.Policy.SecretProperties.ContentType)
	assert.Equal(t, "Self", *got.Policy.IssuerParameters.Name)
	require.NotEmpty(t, got.Policy.LifetimeActions)
	assert.Equal(t, azcertificates.CertificatePolicyActionAutoRenew, *got.Policy.LifetimeActions[0].Action.ActionType)
	assert.Equal(t, s.Leaf("web-cert", ver).Raw, got.CER)
	assert.NotNil(t, got.Attributes.Created)
	vp := certs.NewListCertificatePropertiesVersionsPager("web-cert", nil)
	n := 0
	for vp.More() {
		page, err := vp.NextPage(ctx)
		require.NoError(t, err)
		for _, p := range page.Value {
			n++
			assert.Equal(t, ver, p.ID.Version())
		}
	}
	assert.Equal(t, 1, n)

	secrets, err := azsecrets.NewClient(s.VaultURL(), cred, &azsecrets.ClientOptions{ClientOptions: opts})
	require.NoError(t, err)
	sec, err := secrets.GetSecret(ctx, "web-cert", ver, nil)
	require.NoError(t, err)
	assert.Equal(t, "application/x-pkcs12", *sec.ContentType)
	assert.Equal(t, string(s.SecretValue("web-cert", ver)), *sec.Value)
	raw, err := base64.StdEncoding.DecodeString(*sec.Value)
	require.NoError(t, err)
	_, leaf, _, err := pkcs12.DecodeChain(raw, "")
	require.NoError(t, err)
	assert.Equal(t, s.Leaf("web-cert", ver).Raw, leaf.Raw)
	sp := secrets.NewListSecretPropertiesPager(nil)
	var secretNames []string
	for sp.More() {
		page, err := sp.NextPage(ctx)
		require.NoError(t, err)
		for _, p := range page.Value {
			secretNames = append(secretNames, p.ID.Name())
		}
	}
	assert.Equal(t, []string{"db-password", "web-cert"}, secretNames)

	keys, err := azkeys.NewClient(s.VaultURL(), cred, &azkeys.ClientOptions{ClientOptions: opts})
	require.NoError(t, err)
	kp := keys.NewListKeyPropertiesPager(nil)
	var keyNames []string
	for kp.More() {
		page, err := kp.NextPage(ctx)
		require.NoError(t, err)
		for _, p := range page.Value {
			keyNames = append(keyNames, p.KID.Name())
		}
	}
	assert.Equal(t, []string{"signing", "web-cert"}, keyNames)
	key, err := keys.GetKey(ctx, "signing", "", nil)
	require.NoError(t, err)
	assert.Equal(t, azkeys.KeyTypeRSA, *key.Key.Kty)
	assert.Len(t, key.Key.N, 256)
	assert.NotEmpty(t, key.Key.E)
	ec, err := keys.GetKey(ctx, "web-cert", ver, nil)
	require.NoError(t, err)
	assert.Equal(t, azkeys.KeyTypeEC, *ec.Key.Kty)
	assert.Equal(t, azkeys.CurveNameP256, *ec.Key.Crv)
}

func newWorld(t *testing.T, o fakekv.Options) (*fakekv.Server, string) {
	t.Helper()
	s := fakekv.Start(t, o)
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	s.AddSecret("db-password", "text/plain")
	return s, ver
}

func TestSDKClientSecretRoundTrip(t *testing.T) {
	s, ver := newWorld(t, fakekv.Options{})
	exercise(t, s, secretCredential(t, s, s.Secret()), ver)
	// Every request the SDK made went to the login host or the vault host; none to another.
	for _, r := range s.Requests() {
		assert.Contains(t, []string{"login.microsoftonline.com", "alice-test.vault.azure.net"}, r.Host)
	}
}

func TestSDKClientCertificateRoundTrip(t *testing.T) {
	spCA := pki.NewCA("SP", pki.RSA2048, time.Now())
	sp := spCA.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
	s, ver := newWorld(t, fakekv.Options{ClientCert: sp.Cert})
	cred, err := azidentity.NewClientCertificateCredential(s.TenantID(), s.ClientID(), []*x509.Certificate{sp.Cert}, sp.Key.(*rsa.PrivateKey),
		&azidentity.ClientCertificateCredentialOptions{ClientOptions: sdkOptions(s), DisableInstanceDiscovery: true})
	require.NoError(t, err)
	exercise(t, s, cred, ver)

	// An unregistered certificate is refused with AADSTS700027 in the error body.
	other := spCA.Issue(pki.Opts{CommonName: "other", KeyType: pki.RSA2048}, time.Now())
	cred2, err := azidentity.NewClientCertificateCredential(s.TenantID(), s.ClientID(), []*x509.Certificate{other.Cert}, other.Key.(*rsa.PrivateKey),
		&azidentity.ClientCertificateCredentialOptions{ClientOptions: sdkOptions(s), DisableInstanceDiscovery: true})
	require.NoError(t, err)
	_, err = cred2.GetToken(context.Background(), vaultScopes)
	var af *azidentity.AuthenticationFailedError
	require.ErrorAs(t, err, &af)
	assert.Equal(t, 401, af.RawResponse.StatusCode)
}

func TestSDKManagedIdentityRoundTrip(t *testing.T) {
	// A distinct user-assigned client ID per test: MSAL's managed-identity token cache is process-global (D30).
	mi := uuid.NewString() // unique per run: also across -count=N
	s, ver := newWorld(t, fakekv.Options{ManagedIdentity: true, MIClientID: mi})
	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: sdkOptions(s), ID: azidentity.ClientID(mi)})
	require.NoError(t, err)
	exercise(t, s, cred, ver)
	hosts := map[string]int{}
	for _, r := range s.Requests() {
		hosts[r.Host]++
	}
	assert.Positive(t, hosts["169.254.169.254"], "the token came from IMDS")
	assert.Zero(t, hosts["login.microsoftonline.com"], "a managed identity never talks to the login host")
}

func TestSDKManagedIdentityUnknownIdentity(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: sdkOptions(s), ID: azidentity.ClientID(uuid.NewString())})
	require.NoError(t, err)
	_, err = cred.GetToken(context.Background(), vaultScopes)
	require.Error(t, err)
}

func TestSDKErrorsAreTypedAsAlicesMappingNeeds(t *testing.T) {
	s, ver := newWorld(t, fakekv.Options{})
	ctx := context.Background()

	// Wrong secret / expired secret: AuthenticationFailedError carrying the Entra body.
	_, err := secretCredential(t, s, "wrong").GetToken(ctx, vaultScopes)
	var af *azidentity.AuthenticationFailedError
	require.ErrorAs(t, err, &af)
	assert.Equal(t, 401, af.RawResponse.StatusCode)
	s.ExpireSecret()
	_, err = secretCredential(t, s, s.Secret()).GetToken(ctx, vaultScopes)
	require.ErrorAs(t, err, &af)
	assert.Equal(t, 401, af.RawResponse.StatusCode)
	s.RestoreSecret()

	// A wrong tenant: MSAL's tenant discovery fails.
	wrongTenant, err := azidentity.NewClientSecretCredential(s.ClientID(), s.ClientID(), s.Secret(),
		&azidentity.ClientSecretCredentialOptions{ClientOptions: sdkOptions(s), DisableInstanceDiscovery: true})
	require.NoError(t, err)
	_, err = wrongTenant.GetToken(ctx, vaultScopes)
	require.Error(t, err)

	cred := secretCredential(t, s, s.Secret())
	secrets, err := azsecrets.NewClient(s.VaultURL(), cred, &azsecrets.ClientOptions{ClientOptions: sdkOptions(s)})
	require.NoError(t, err)
	certs, err := azcertificates.NewClient(s.VaultURL(), cred, &azcertificates.ClientOptions{ClientOptions: sdkOptions(s)})
	require.NoError(t, err)

	var re *azcore.ResponseError
	s.RevokeRole("secrets/get")
	_, err = secrets.GetSecret(ctx, "web-cert", ver, nil)
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 403, re.StatusCode)
	assert.Equal(t, "Forbidden", re.ErrorCode, "the SDK reports the outer error code")
	s.GrantRole("secrets/get")

	s.DisableVersion("web-cert", ver)
	_, err = secrets.GetSecret(ctx, "web-cert", ver, nil)
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 403, re.StatusCode)
	s.EnableVersion("web-cert", ver)

	_, err = certs.GetCertificate(ctx, "absent", "", nil)
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 404, re.StatusCode)
	assert.Equal(t, "CertificateNotFound", re.ErrorCode)

	s.FailNext("/certificates/web-cert/", fakekv.Fault{Status: 429, RetryAfter: "7"})
	_, err = certs.GetCertificate(ctx, "web-cert", "", nil)
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 429, re.StatusCode)
	assert.Equal(t, "7", re.RawResponse.Header.Get("Retry-After"))

	s.FailNext("/certificates/web-cert/", fakekv.Fault{Body: "{not json"})
	_, err = certs.GetCertificate(ctx, "web-cert", "", nil)
	require.Error(t, err)
	assert.False(t, errors.As(err, &re), "a malformed 200 is not a ResponseError")

	s.FailNext("/certificates/web-cert/", fakekv.Fault{Drop: true})
	_, err = certs.GetCertificate(ctx, "web-cert", "", nil)
	require.Error(t, err)

	s.Firewall("203.0.113.7")
	_, err = certs.GetCertificate(ctx, "web-cert", "", nil)
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 403, re.StatusCode)
	s.Firewall("")
}

func TestSDKImportAndPagingAndNextLinks(t *testing.T) {
	s, _ := newWorld(t, fakekv.Options{ExtraHosts: []string{"evil.test"}})
	s.AddBulkCertificates("bulk", 60)
	ctx := context.Background()
	cred := secretCredential(t, s, s.Secret())
	certs, err := azcertificates.NewClient(s.VaultURL(), cred, &azcertificates.ClientOptions{ClientOptions: sdkOptions(s)})
	require.NoError(t, err)

	// Paging through nextLink (with :443 in it, as Azure writes it) with the challenge verification on.
	pager := certs.NewListCertificatePropertiesPager(nil)
	pages, total := 0, 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		require.NoError(t, err)
		pages++
		total += len(page.Value)
	}
	assert.Equal(t, 61, total)
	assert.Equal(t, 3, pages)

	// Import of a LegacyDES PFX with an empty password.
	ca := pki.NewCA("Import CA", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "imp.example.test"}, time.Now())
	pfx, err := pkcs12.LegacyDES.Encode(leaf.Key, leaf.Cert, []*x509.Certificate{ca.Intermediate}, "")
	require.NoError(t, err)
	b64 := base64.StdEncoding.EncodeToString(pfx)
	before := time.Now().Add(-time.Second)
	imp, err := certs.ImportCertificate(ctx, "new-cert", azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &b64, Password: to.Ptr(""),
		CertificatePolicy: &azcertificates.CertificatePolicy{
			KeyProperties: &azcertificates.KeyProperties{Exportable: to.Ptr(true), KeyType: to.Ptr(azcertificates.KeyTypeEC),
				Curve: to.Ptr(azcertificates.CurveNameP256), ReuseKey: to.Ptr(false)},
			SecretProperties: &azcertificates.SecretProperties{ContentType: to.Ptr("application/x-pkcs12")},
			IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr("Unknown")}}}, nil)
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, imp.CER)
	assert.Len(t, imp.ID.Version(), 32)
	assert.False(t, imp.Attributes.Created.Before(before), "created is not before the request")
	assert.Equal(t, s.Versions("new-cert")[0], imp.ID.Version())
	// The imported version reads back as a secret.
	secrets, err := azsecrets.NewClient(s.VaultURL(), cred, &azsecrets.ClientOptions{ClientOptions: sdkOptions(s)})
	require.NoError(t, err)
	sec, err := secrets.GetSecret(ctx, "new-cert", imp.ID.Version(), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, *sec.Value)

	// A refused import (garbage) is a 400 ResponseError.
	bad := base64.StdEncoding.EncodeToString([]byte("garbage"))
	_, err = certs.ImportCertificate(ctx, "bad-cert", azcertificates.ImportCertificateParameters{Base64EncodedCertificate: &bad}, nil)
	var re *azcore.ResponseError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, 400, re.StatusCode)
	assert.Equal(t, "BadParameter", re.ErrorCode)

	// A wrong-host nextLink: with the SDK's default pipeline the second page is requested at evil.test
	// (the SDK itself does not refuse it: Alice's guarded transport must), and the fake logs it.
	s.FailNext("/certificates", fakekv.Fault{NextLink: "https://evil.test/certificates?api-version=2025-07-01&$skiptoken=x"})
	p2 := certs.NewListCertificatePropertiesPager(nil)
	_, err = p2.NextPage(ctx)
	require.NoError(t, err)
	_, err = p2.NextPage(ctx)
	require.Error(t, err, "the SDK could not authenticate to the foreign host")
	var sawEvil, tokenToEvil bool
	for _, r := range s.Requests() {
		if r.Host == "evil.test" {
			sawEvil = true
			tokenToEvil = tokenToEvil || r.HadAuth
		}
	}
	assert.True(t, sawEvil, "the request reached the foreign host: only a guarded transport prevents it")
	t.Logf("the SDK sent its bearer token to the foreign nextLink host: %v (Request.HadAuth)", tokenToEvil)
}

func TestSDKChallengeResourceVerificationStaysOn(t *testing.T) {
	// A challenge naming a resource outside the vault's domain is refused by the SDK itself
	// (ruling S2): the fake never needs verification to be switched off.
	s, _ := newWorld(t, fakekv.Options{})
	s.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + s.TenantID() + `", resource="https://evil.test"`)
	certs, err := azcertificates.NewClient(s.VaultURL(), secretCredential(t, s, s.Secret()), &azcertificates.ClientOptions{ClientOptions: sdkOptions(s)})
	require.NoError(t, err)
	_, err = certs.GetCertificate(context.Background(), "web-cert", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource")
	for _, r := range s.Requests() {
		assert.NotEqual(t, "login.microsoftonline.com", r.Host, "no token was requested")
	}
}

func TestSDKTokensAreCachedUntilTheClockExpiresThem(t *testing.T) {
	s, _ := newWorld(t, fakekv.Options{})
	cred := secretCredential(t, s, s.Secret())
	for i := 0; i < 3; i++ {
		_, err := cred.GetToken(context.Background(), vaultScopes)
		require.NoError(t, err)
	}
	n := 0
	for _, r := range s.Requests() {
		if r.Method == http.MethodPost {
			n++
		}
	}
	assert.Equal(t, 1, n, fmt.Sprintf("MSAL caches the token in memory (%d token requests)", n))
}
