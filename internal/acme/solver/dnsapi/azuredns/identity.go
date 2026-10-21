package azuredns

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi"
)

// The sign-in mirrors the Key Vault provider's (internal/providers/azurekv/identity.go, which this package may not
// import): the same azidentity credentials, the same options and the same guards around GetToken.

var (
	errTenantMismatch = errors.New("azuredns: a token of another tenant was asked for")
	errScope          = errors.New("azuredns: a token for another resource was asked for")
	errEnvironment    = errors.New("azuredns: the process environment makes the SDK act outside the guard")
)

// refusedEnv are environment variables that make the Azure SDK or MSAL act outside Alice's guard (the Key Vault
// provider refuses the same ones):
//   - AZURE_REGIONAL_AUTHORITY_NAME and MSAL_FORCE_REGION make MSAL detect its region with a bare http.Client: a
//     request to the metadata address outside every guard. MSAL reads them at the first token.
//   - AZURE_SDK_GO_LOGGING makes the SDK print every failed call (URL, status, the answer's JSON) to stderr.
var refusedEnv = []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"}

func refusedEnvironment() bool {
	for _, name := range refusedEnv {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// signInCredential is the only credential the provider uses. It adds what the SDK does not check: a token is asked
// for only for the configured tenant and only for the Resource Manager of the public cloud, and never while the
// environment would make the SDK act outside the guard.
type signInCredential struct {
	inner  azcore.TokenCredential
	auth   string
	tenant string
}

func (c *signInCredential) GetToken(ctx context.Context, tro policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if refusedEnvironment() { // MSAL reads its region variables at the first token, not at New
		return azcore.AccessToken{}, errEnvironment
	}
	if c.auth != AuthManagedIdentity && tro.TenantID != "" && foldASCII(tro.TenantID) != c.tenant {
		return azcore.AccessToken{}, errTenantMismatch
	}
	if len(tro.Scopes) != 1 || tro.Scopes[0] != ManagementScope {
		return azcore.AccessToken{}, errScope
	}
	if c.auth != AuthManagedIdentity {
		tro.TenantID = c.tenant
	}
	return c.inner.GetToken(ctx, tro)
}

// clientOptions is the one place SDK options are built: the public cloud, the guarded transport, no SDK retries
// (the order's renewal retries; a token request is cheap to repeat there) and no telemetry. No log listener is ever
// set.
func clientOptions(t policy.Transporter) azcore.ClientOptions {
	return azcore.ClientOptions{
		Cloud:     cloud.AzurePublic,
		Transport: t,
		Retry:     policy.RetryOptions{MaxRetries: -1},
		Telemetry: policy.TelemetryOptions{Disabled: true},
	}
}

// identity is a validated sign-in configuration (New's output).
type identity struct {
	auth, tenant, client string
	secret               []byte // AuthClientSecret: a copy, zeroed once the credential holds its own
	cert                 *x509.Certificate
	key                  *rsa.PrivateKey
}

// newCredential builds the SDK credential: opts carries the login-host transport, imds the metadata transport.
func newCredential(id identity, opts, imds azcore.ClientOptions) (azcore.TokenCredential, error) {
	var (
		inner azcore.TokenCredential
		err   error
	)
	switch id.auth {
	case AuthClientSecret:
		// The SDK keeps the secret as a Go string for the provider's lifetime; Alice cannot zero that copy.
		inner, err = azidentity.NewClientSecretCredential(id.tenant, id.client, string(id.secret),
			&azidentity.ClientSecretCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	case AuthCertificate:
		// Likewise the SDK keeps the parsed RSA key (MSAL signs its assertion PS256: RSA only).
		inner, err = azidentity.NewClientCertificateCredential(id.tenant, id.client, []*x509.Certificate{id.cert}, id.key,
			&azidentity.ClientCertificateCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	default: // AuthManagedIdentity (New admits nothing else)
		o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: imds}
		if id.client != "" {
			o.ID = azidentity.ClientID(id.client)
		}
		inner, err = azidentity.NewManagedIdentityCredential(o)
	}
	if err != nil {
		return nil, ErrIdentity
	}
	return &signInCredential{inner: inner, auth: id.auth, tenant: id.tenant}, nil
}

// signInWire records what the sign-in transports saw during one GetToken (the request context carries it): whether
// the last exchange got an answer and its status. azidentity does not hand back an answer for every failure (a
// system-assigned identity's 400 is a "credential unavailable" error without one), and a transport failure must be
// told apart from a refusal.
type signInWire struct {
	mu       sync.Mutex
	status   int  // the last answer's status
	failed   bool // the last exchange failed in transport (no answer, or its body was cut)
	refused  bool // a request to a host the transport may not reach
	exchange int
}

type wireKey struct{}

func withWire(ctx context.Context, w *signInWire) context.Context {
	return context.WithValue(ctx, wireKey{}, w)
}

func wireOf(ctx context.Context) *signInWire {
	if w, ok := ctx.Value(wireKey{}).(*signInWire); ok {
		return w
	}
	return &signInWire{} // a request outside a GetToken of this package records nowhere
}

func (w *signInWire) answered(status int) {
	w.mu.Lock()
	w.status, w.failed, w.exchange = status, false, w.exchange+1
	w.mu.Unlock()
}

func (w *signInWire) fail(refused bool) {
	w.mu.Lock()
	w.failed, w.refused, w.exchange = true, w.refused || refused, w.exchange+1
	w.mu.Unlock()
}

// recordingTransport wraps a sign-in transport with the wire record.
type recordingTransport struct{ next policy.Transporter }

func (t recordingTransport) Do(req *http.Request) (*http.Response, error) {
	w := wireOf(req.Context())
	res, err := t.next.Do(req)
	if err != nil {
		w.fail(errors.Is(err, dnsapi.ErrHostNotAllowed) || errors.Is(err, errIMDSOnly))
		return nil, err
	}
	w.answered(res.StatusCode)
	res.Body = &recordingBody{rc: res.Body, w: w}
	return res, nil
}

type recordingBody struct {
	rc io.ReadCloser
	w  *signInWire
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		b.w.fail(false)
	}
	return n, err
}

func (b *recordingBody) Close() error { return b.rc.Close() }

// signInFailure is the *acme.Error of a failed GetToken for identifier d. It never carries the SDK's error, whose
// text holds Entra's answer (the AADSTS description), the token endpoint's URL and the request.
func signInFailure(d string, err error, w *signInWire) error {
	var af *azidentity.AuthenticationFailedError
	if errors.As(err, &af) && af.RawResponse != nil {
		return acme.DNSSignInError(d, af.RawResponse.StatusCode, false)
	}
	w.mu.Lock()
	status, failed, refused, n := w.status, w.failed, w.refused, w.exchange
	w.mu.Unlock()
	switch {
	case n == 0 || refused:
		// Refused before anything was sent (the guard, the environment) or a request to a host the sign-in may
		// not reach (an SDK source other than the metadata endpoint): a setting, not an outage.
		return acme.DNSSignInError(d, 0, false)
	case failed:
		return acme.DNSSignInError(d, 0, true)
	}
	return acme.DNSSignInError(d, status, false)
}

// foldASCII lowercases ASCII letters only (strings.ToLower is banned in this repository).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
