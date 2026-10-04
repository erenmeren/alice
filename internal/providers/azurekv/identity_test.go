package azurekv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

func addSeed(s *fakekv.Server) string {
	return s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
}

func TestSessionOpensWithEachSignInMethod(t *testing.T) {
	sp := rsaSP(t)
	key, err := x509.MarshalPKCS8PrivateKey(sp.Key)
	require.NoError(t, err)
	mi := uuid.NewString() // a user-assigned identity per test: MSAL's managed-identity cache is process-global
	cases := []struct {
		name string
		opts fakekv.Options
		id   func(s *fakekv.Server) providers.AzureIdentity
	}{
		{"client secret", fakekv.Options{}, secretIdentity},
		{"certificate", fakekv.Options{ClientCert: sp.Cert}, func(s *fakekv.Server) providers.AzureIdentity {
			return providers.AzureIdentity{Auth: providers.AzureAuthCertificate, TenantID: s.TenantID(), ClientID: s.ClientID(),
				CertificateDER: sp.Cert.Raw, PrivateKeyDER: providers.NewSecret(append([]byte(nil), key...))}
		}},
		{"managed identity", fakekv.Options{ManagedIdentity: true, MIClientID: mi}, func(*fakekv.Server) providers.AzureIdentity {
			return providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: mi}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fakekv.Start(t, tc.opts)
			ver := addSeed(s)
			src := &idSource{id: tc.id(s)}
			sess := openSession(t, testProvider(s), src, nearNow())
			assert.Equal(t, int32(1), src.released.Load(), "release ran before Open returned")
			tok, err := sess.api.Token(context.Background())
			require.NoError(t, err)
			assert.NotEmpty(t, tok.Token)
			c, err := sess.api.GetCertificate(context.Background(), "web-cert", "")
			require.NoError(t, err)
			assert.Equal(t, ver, c.ID.Version())
			hosts := map[string]bool{}
			for _, r := range s.Requests() {
				hosts[r.Host] = true
			}
			if tc.id(s).Auth == providers.AzureAuthManagedIdentity {
				assert.True(t, hosts["169.254.169.254"])
				assert.False(t, hosts["login.microsoftonline.com"])
			} else {
				assert.True(t, hosts["login.microsoftonline.com"])
				assert.False(t, hosts["169.254.169.254"])
			}
			assert.True(t, hosts[testVaultHost])
		})
	}
}

func TestTokenRequestCarriesTheConfiguredTenantAndClient(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err := sess.api.Token(context.Background())
	require.NoError(t, err)
	var tokenPaths []string
	for _, r := range s.Requests() {
		if r.Host == "login.microsoftonline.com" && r.Method == "POST" {
			tokenPaths = append(tokenPaths, r.Path)
		}
	}
	assert.Equal(t, []string{"/" + s.TenantID() + "/oauth2/v2.0/token"}, tokenPaths)
	// A wrong client id is refused by the fake: the application is unknown.
	id := secretIdentity(s)
	id.ClientID = uuid.NewString()
	sess2 := openSession(t, testProvider(s), &idSource{id: id}, nearNow())
	_, err = sess2.api.Token(context.Background())
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.auth_failed", pe.Code)
	assert.Equal(t, "700016", pe.Params["aadsts"])
}

func TestOpenRefusals(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	p := testProvider(s)
	code := func(err error) string {
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		return pe.Code
	}
	// A credential source that is not an Azure one.
	_, err := p.Open(context.Background(), target(), sshSource{}, providers.Env{})
	assert.Equal(t, "azure.auth_failed", code(err))
	_, err = p.Open(context.Background(), target(), nil, providers.Env{})
	assert.Equal(t, "azure.auth_failed", code(err))
	// The database failed: no cause text, retryable.
	src := &idSource{err: errors.New("canary-db-error password=hunter2")}
	_, err = p.Open(context.Background(), target(), src, providers.Env{})
	require.Error(t, err)
	assert.Equal(t, "internal.unexpected", code(err))
	assert.NotContains(t, err.Error(), "canary")
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.True(t, pe.Retryable)
	assert.Nil(t, pe.Cause)
	// An ECDSA key: MSAL signs RSA only.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, err)
	sp := rsaSP(t)
	src = &idSource{id: providers.AzureIdentity{Auth: providers.AzureAuthCertificate, TenantID: s.TenantID(), ClientID: s.ClientID(),
		CertificateDER: sp.Cert.Raw, PrivateKeyDER: providers.NewSecret(der)}}
	_, err = p.Open(context.Background(), target(), src, providers.Env{})
	assert.Equal(t, "azure.auth_failed", code(err))
	assert.Equal(t, int32(1), src.released.Load(), "release also on a failed Open")
	// Unusable identities.
	for name, id := range map[string]providers.AzureIdentity{
		"empty secret":    {Auth: providers.AzureAuthClientSecret, TenantID: s.TenantID(), ClientID: s.ClientID()},
		"unknown method":  {Auth: "device_code"},
		"bad certificate": {Auth: providers.AzureAuthCertificate, CertificateDER: []byte{1}},
		"bad key":         {Auth: providers.AzureAuthCertificate, CertificateDER: sp.Cert.Raw, PrivateKeyDER: providers.NewSecret([]byte{1})},
		"bad tenant":      {Auth: providers.AzureAuthClientSecret, TenantID: "not a tenant!", ClientID: "x", ClientSecret: providers.NewSecret([]byte("x"))},
	} {
		src := &idSource{id: id}
		_, err := p.Open(context.Background(), target(), src, providers.Env{})
		assert.Equal(t, "azure.auth_failed", code(err), name)
		assert.Equal(t, int32(1), src.released.Load(), name)
	}
	// A bad vault address and a root pool that cannot be had.
	bad := target()
	bad.Config = providers.TargetConfig{"vault_url": "https://evil.test"}
	_, err = p.Open(context.Background(), bad, &idSource{id: secretIdentity(s)}, providers.Env{})
	assert.Equal(t, "azure.address_not_allowed", code(err))
	broken := New(Options{RootCAs: func() (*x509.CertPool, error) { return nil, errors.New("no file") }})
	_, err = broken.Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{})
	assert.Equal(t, "azure.tls_untrusted", code(err))
}

func TestOpenWithCancelledContextSendsNothing(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := testProvider(s).Open(ctx, target(), &idSource{id: secretIdentity(s)}, providers.Env{})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, s.Requests())
}

func TestManagedIdentityFailsClosedWhenTheSDKPicksAnotherSource(t *testing.T) {
	// App Service variables make the SDK look for a token at IDENTITY_ENDPOINT instead of IMDS.
	t.Setenv("IDENTITY_ENDPOINT", "https://evil.test/msi/token")
	t.Setenv("IDENTITY_HEADER", "canary-header")
	s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"evil.test"}, ManagedIdentity: true})
	id := providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: uuid.NewString()}
	sess := openSession(t, testProvider(s), &idSource{id: id}, nearNow())
	_, err := sess.api.Token(context.Background())
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.managed_identity_unavailable", pe.Code)
	assert.False(t, pe.Retryable)
	for _, r := range s.Requests() {
		assert.NotEqual(t, "evil.test", r.Host, "nothing was sent to the other host")
	}
}

func TestManagedIdentityUnknownIdentity(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{ManagedIdentity: true, MIClientID: uuid.NewString()})
	id := providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: uuid.NewString()}
	sess := openSession(t, testProvider(s), &idSource{id: id}, nearNow())
	_, err := sess.api.Token(context.Background())
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.managed_identity_unavailable", pe.Code)
}

// TestRegionEnvironmentNeverLeavesTheGuard: a region variable makes MSAL detect its region with a
// bare http.Client (http.DefaultTransport) against the metadata address. Open refuses it first.
func TestRegionEnvironmentNeverLeavesTheGuard(t *testing.T) { // also the SDK logging variable (N1)
	sp := rsaSP(t)
	key, err := x509.MarshalPKCS8PrivateKey(sp.Key)
	require.NoError(t, err)
	for _, env := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"} {
		for _, auth := range []string{providers.AzureAuthClientSecret, providers.AzureAuthCertificate, providers.AzureAuthManagedIdentity} {
			t.Run(env+"/"+auth, func(t *testing.T) {
				t.Setenv(env, "TryAutoDetect")
				s := fakekv.Start(t, fakekv.Options{ClientCert: sp.Cert, ManagedIdentity: true})
				id := secretIdentity(s)
				switch auth {
				case providers.AzureAuthCertificate:
					id = providers.AzureIdentity{Auth: auth, TenantID: s.TenantID(), ClientID: s.ClientID(),
						CertificateDER: sp.Cert.Raw, PrivateKeyDER: providers.NewSecret(append([]byte(nil), key...))}
				case providers.AzureAuthManagedIdentity:
					id = providers.AzureIdentity{Auth: auth}
				}
				before := bypassed.Load()
				src := &idSource{id: id}
				sess, err := testProvider(s).Open(context.Background(), target(), src, providers.Env{Clock: nearNow()})
				require.Error(t, err)
				assert.Nil(t, sess)
				var pe *providers.Error
				require.ErrorAs(t, err, &pe)
				assert.Equal(t, "azure.address_not_allowed", pe.Code)
				assert.False(t, pe.Retryable)
				assert.Equal(t, before, bypassed.Load(), "nothing reached http.DefaultTransport")
				assert.Empty(t, s.Requests(), "nothing was sent")
			})
		}
	}
}

// The SDK can pick another managed-identity source than IMDS from the environment: App Service,
// Service Fabric, the legacy MSI endpoint. Whatever stage fails, the answer is the same closed code
// and nothing leaves for another host.
func TestManagedIdentityOtherSourcesFailClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"MSI_ENDPOINT with a user-assigned identity": {"MSI_ENDPOINT": "https://evil.test/msi", "MSI_SECRET": "canary-secret"},
		"Service Fabric": {"IDENTITY_ENDPOINT": "https://evil.test/sf", "IDENTITY_HEADER": "canary-header", "IDENTITY_SERVER_THUMBPRINT": "AA"},
		"App Service":    {"IDENTITY_ENDPOINT": "https://evil.test/msi", "IDENTITY_HEADER": "canary-header"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"evil.test"}, ManagedIdentity: true})
			id := providers.AzureIdentity{Auth: providers.AzureAuthManagedIdentity, ClientID: uuid.NewString()}
			sess, err := testProvider(s).Open(context.Background(), target(), &idSource{id: id}, providers.Env{Clock: nearNow()})
			if err == nil {
				defer func() { _ = sess.Close() }()
				_, err = sess.(*session).api.Token(context.Background())
			}
			var pe *providers.Error
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, "azure.managed_identity_unavailable", pe.Code)
			assert.False(t, pe.Retryable)
			assertNoLeak(t, pe, s)
			for _, r := range s.Requests() {
				assert.NotEqual(t, "evil.test", r.Host)
			}
		})
	}
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// The vault names the tenant in upper case: the credential asks the SDK for its own spelling, so
// the SDK's case-sensitive comparison passes.
func TestChallengeTenantInUpperCaseWorks(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	addSeed(s)
	s.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + upperASCII(s.TenantID()) + `", resource="https://vault.azure.net"`)
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err := sess.api.GetCertificate(context.Background(), "web-cert", "")
	require.NoError(t, err)
}

func TestEveryTransportRequiresTLS12(t *testing.T) {
	for _, g := range []*guardedTransport{
		newGuardedTransport([]string{testVaultHost}, nil, nil), newGuardedTransport([]string{"login.microsoftonline.com"}, nil, nil),
	} {
		require.NotNil(t, g.tr.TLSClientConfig)
		assert.GreaterOrEqual(t, int(g.tr.TLSClientConfig.MinVersion), int(tls.VersionTLS12))
		assert.False(t, g.tr.TLSClientConfig.InsecureSkipVerify)
	}
	// The metadata transport speaks plain http to one address and has no TLS configuration to weaken.
	im := newIMDSTransport(nil, nil)
	assert.Nil(t, im.tr.TLSClientConfig)
}

// N2: MSAL reads MSAL_FORCE_REGION at the first token, after Open. The check is repeated before
// every token request, for every refused variable and every sign-in method.
func TestEnvironmentSetAfterOpenIsRefusedAtTheToken(t *testing.T) {
	for _, env := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"} {
		t.Run(env, func(t *testing.T) {
			w := newWorld(t, fakekv.Options{})
			before := bypassed.Load()
			t.Setenv(env, "TryAutoDetect")
			_, err := w.sess.api.Token(context.Background())
			pe := asProviderError(t, err)
			assert.Equal(t, codeAddressNotAllowed, pe.Code)
			assert.False(t, pe.Retryable)
			assertNoLeak(t, pe, w.s)
			assert.Equal(t, before, bypassed.Load(), "nothing reached http.DefaultTransport")
			assert.Empty(t, w.s.Requests(), "no token request was sent")
			_, err = w.sess.TestConnection(context.Background())
			assert.Equal(t, codeAddressNotAllowed, asProviderError(t, err).Code)
		})
	}
}
