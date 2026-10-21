package azuredns

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/platform/azureid"
)

type fixedCred struct{ calls int }

func (c *fixedCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls++
	return azcore.AccessToken{Token: "t"}, nil
}

func TestSignInGuardPinsTenantAndScope(t *testing.T) {
	inner := &fixedCred{}
	const tenant = "11111111-2222-3333-4444-555555555555"
	c := &signInCredential{inner: inner, auth: AuthClientSecret, tenant: tenant}
	ctx := context.Background()
	_, err := c.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{ManagementScope}, TenantID: "99999999-2222-3333-4444-555555555555"})
	assert.ErrorIs(t, err, errTenantMismatch)
	_, err = c.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureid.VaultScope}})
	assert.ErrorIs(t, err, errScope)
	_, err = c.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{ManagementScope, azureid.VaultScope}})
	assert.ErrorIs(t, err, errScope)
	assert.Zero(t, inner.calls, "nothing reached the SDK")
	_, err = c.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{ManagementScope}, TenantID: "11111111-2222-3333-4444-555555555555"})
	require.NoError(t, err)

	mi := &signInCredential{inner: inner, auth: AuthManagedIdentity}
	_, err = mi.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{ManagementScope}})
	require.NoError(t, err)
	assert.Equal(t, 2, inner.calls)
}

func TestSignInFailureKinds(t *testing.T) {
	const d = "example.test"
	none := &signInWire{}
	assert.Equal(t, acme.DNSSignInError(d, 0, false), signInFailure(d, errEnvironment, none), "refused before any request")

	refused := &signInWire{}
	refused.fail(true)
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(signInFailure(d, errors.New("x"), refused)))

	cut := &signInWire{}
	cut.answered(200)
	cut.fail(false)
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(signInFailure(d, errors.New("x"), cut)))

	answered := &signInWire{}
	answered.answered(http.StatusBadRequest)
	e := signInFailure(d, errors.New("x"), answered)
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(e))

	busy := &signInWire{}
	busy.answered(http.StatusServiceUnavailable)
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(signInFailure(d, errors.New("x"), busy)))

	assert.NotNil(t, wireOf(context.Background()), "a request outside a sign-in records nowhere")
}

func TestIMDSTransportReachesTheMetadataEndpointOnly(t *testing.T) {
	tr := newIMDSTransport(nil)
	for _, u := range []string{
		"https://169.254.169.254/metadata/identity/oauth2/token",
		"http://169.254.169.254:8080/metadata/identity/oauth2/token",
		"http://169.254.169.253/metadata/identity/oauth2/token",
		"http://user@169.254.169.254/metadata/identity/oauth2/token",
		"http://localhost/metadata/identity/oauth2/token",
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, strings.NewReader("x"))
		require.NoError(t, err)
		res, err := tr.Do(req) //nolint:bodyclose // refused: there is no answer
		assert.Nil(t, res)
		assert.ErrorIs(t, err, errIMDSOnly, u)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/x", nil)
	require.NoError(t, err)
	req.Host = "evil.test"
	_, err = tr.Do(req) //nolint:bodyclose // refused
	assert.ErrorIs(t, err, errIMDSOnly, "a Host header naming another host")

	dial := tr.client.Transport.(*http.Transport).DialContext
	_, err = dial(context.Background(), "tcp", "10.0.0.1:80")
	assert.ErrorIs(t, err, errIMDSOnly, "the dialer checks the address before any mapping")
}

func TestCappedBody(t *testing.T) {
	b := &cappedBody{rc: io.NopCloser(bytes.NewReader(make([]byte, 10))), left: 4}
	_, err := io.ReadAll(b)
	assert.ErrorIs(t, err, dnsapi.ErrTooLarge)
	require.NoError(t, b.Close())
	ok := &cappedBody{rc: io.NopCloser(bytes.NewReader(make([]byte, 4))), left: 4}
	got, err := io.ReadAll(ok)
	require.NoError(t, err)
	assert.Len(t, got, 4)
}

func TestConfigGoString(t *testing.T) {
	c := Config{Auth: AuthManagedIdentity, ResourceGroup: "rg"}
	assert.Equal(t, c.String(), c.GoString())
}
