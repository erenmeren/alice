package azurekv

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

var (
	errBadIdentity    = errors.New("azurekv: the sign-in identity cannot be used")
	errTenantMismatch = errors.New("azurekv: the vault asks for a token of another tenant")
	errChallengeScope = errors.New("azurekv: the vault asks for a token for another resource")
)

// tokenError marks an error of the credential's GetToken: a sign-in failure, not a vault answer.
// It keeps the SDK's error in the chain for errors.As (the type, the response) and prints nothing.
type tokenError struct {
	auth string
	err  error
}

func (e *tokenError) Error() string { return "azurekv: sign-in failed" }
func (e *tokenError) Unwrap() error { return e.err }

// signInCredential is the only credential the SDK clients see. It adds what the SDK does not
// check: a token is requested only for the configured tenant (the SDK's own tenant allow-list option
// stays unset; the refusal here carries a closed reason) and
// only for the vault resource of the public cloud, so a challenge cannot make Alice fetch a token
// for another audience (ruling S2).
type signInCredential struct {
	inner  azcore.TokenCredential
	auth   string
	tenant string
}

func (c *signInCredential) GetToken(ctx context.Context, tro policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.auth != providers.AzureAuthManagedIdentity && tro.TenantID != "" && foldASCII(tro.TenantID) != foldASCII(c.tenant) {
		return azcore.AccessToken{}, &tokenError{c.auth, errTenantMismatch}
	}
	if len(tro.Scopes) != 1 || tro.Scopes[0] != azureid.VaultScope {
		return azcore.AccessToken{}, &tokenError{c.auth, errChallengeScope}
	}
	if c.auth != providers.AzureAuthManagedIdentity {
		tro.TenantID = c.tenant // the SDK compares case-sensitively: ask for the configured spelling
	}
	tok, err := c.inner.GetToken(ctx, tro)
	if err != nil {
		return azcore.AccessToken{}, &tokenError{c.auth, err}
	}
	return tok, nil
}

// clientOptions is the one place SDK client options are built: the public cloud, the guarded
// transport of the client, no SDK retries (Alice's loop retries per page, and an import is never
// re-sent) and no telemetry. No log listener is ever set (TestAzureSDKSurface).
func clientOptions(t policy.Transporter) azcore.ClientOptions {
	return azcore.ClientOptions{
		Cloud:     cloud.AzurePublic,
		Transport: t,
		Retry:     policy.RetryOptions{MaxRetries: -1},
		Telemetry: policy.TelemetryOptions{Disabled: true},
	}
}

// newCredential builds the SDK credential of one session: opts carries the login-host transport,
// imds the metadata transport. This file is the only place that constructs one (TestAzureSDKSurface).
func newCredential(id providers.AzureIdentity, opts, imds azcore.ClientOptions) (azcore.TokenCredential, error) {
	var (
		inner azcore.TokenCredential
		err   error
	)
	switch id.Auth {
	case providers.AzureAuthClientSecret:
		if len(id.ClientSecret.Bytes()) == 0 {
			return nil, errBadIdentity
		}
		// The SDK keeps the secret as a Go string for this session's lifetime and Alice cannot zero
		// that copy (R40 row 33).
		inner, err = azidentity.NewClientSecretCredential(id.TenantID, id.ClientID, string(id.ClientSecret.Bytes()),
			&azidentity.ClientSecretCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	case providers.AzureAuthCertificate:
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(id.CertificateDER); err != nil {
			return nil, errBadIdentity
		}
		key, kerr := x509.ParsePKCS8PrivateKey(id.PrivateKeyDER.Bytes())
		rsaKey, ok := key.(*rsa.PrivateKey) // MSAL signs PS256: RSA only
		if kerr != nil || !ok {
			return nil, errBadIdentity
		}
		// Likewise the SDK keeps its own copy of the RSA private key (the *rsa.PrivateKey parsed
		// above and what MSAL derives from it) for the session's lifetime; Alice zeroes only the DER.
		inner, err = azidentity.NewClientCertificateCredential(id.TenantID, id.ClientID, []*x509.Certificate{cert}, rsaKey,
			&azidentity.ClientCertificateCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	case providers.AzureAuthManagedIdentity:
		o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: imds}
		if id.ClientID != "" {
			o.ID = azidentity.ClientID(id.ClientID)
		}
		inner, err = azidentity.NewManagedIdentityCredential(o)
	default:
		return nil, errBadIdentity
	}
	if err != nil {
		return nil, errBadIdentity
	}
	return &signInCredential{inner: inner, auth: id.Auth, tenant: id.TenantID}, nil
}
