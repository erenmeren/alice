package azurekv

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
)

func response(status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func TestCauseTypes(t *testing.T) {
	var ne net.Error = &transportError{timeout: true}
	assert.True(t, ne.Timeout())
	assert.False(t, (&transportError{}).Temporary())
	assert.NotContains(t, ne.Error(), "canary")
	assert.Equal(t, "azurekv: sign-in failed", (&tokenError{err: errors.New(canary)}).Error())
	_, _, ok := answerOf(errors.New("x"))
	assert.False(t, ok)
	assert.Equal(t, "", validCode("with_underscore"))
	assert.Nil(t, answerBody(nil))
	assert.Nil(t, answerBody(&http.Response{}))
	assert.Nil(t, answerBody(&http.Response{Body: io.NopCloser(iotestErrReader{})}), "an unreadable body gives no text")
}

func TestClassifyAuthenticationFailedErrorByHand(t *testing.T) {
	// An Entra answer as azidentity hands it over, without any wire state (mapError alone).
	af := &azidentity.AuthenticationFailedError{RawResponse: response( //nolint:bodyclose // in-memory body
		401, http.Header{"X-Ms-Request-Id": {"6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60"}},
		entraBody(7000215, "invalid_client"))}
	pe := mapError(af, actionSignIn)
	assert.Equal(t, codeAuthFailed, pe.Code)
	assert.Equal(t, map[string]string{"aadsts": "7000215", "azure_request_id": "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60"}, pe.Params)
	// A message-only AuthenticationFailedError carries nothing to classify.
	pe = mapError(&azidentity.AuthenticationFailedError{}, actionSignIn)
	assert.Equal(t, codeUnexpected, pe.Code)
	// A hand-built vault error.
	re := &azcore.ResponseError{StatusCode: 403, ErrorCode: "Forbidden", RawResponse: response(403, nil, kvBody("Forbidden", "ForbiddenByRbac", "x"))} //nolint:bodyclose // in-memory body
	pe = mapError(re, actionImport)
	assert.Equal(t, map[string]string{"role": "Key Vault Certificates Officer", "model": "rbac", "azure_code": "ForbiddenByRbac"}, pe.Params)
	// The outer code is used when the body has no inner code, and the body's code when the header has none.
	re = &azcore.ResponseError{StatusCode: 409, RawResponse: response(409, nil, kvBody("Conflict", "", "x"))} //nolint:bodyclose // in-memory body
	pe = mapError(re, actionImport)
	assert.Equal(t, codeUnexpected, pe.Code)
	assert.Equal(t, "Conflict", pe.Params["azure_code"])
	st, code, ok := answerOf(pe)
	assert.True(t, ok)
	assert.Equal(t, 409, st)
	assert.Equal(t, "Conflict", code)
	re = &azcore.ResponseError{StatusCode: 403, ErrorCode: "Forbidden", RawResponse: response(403, nil, "not json")} //nolint:bodyclose // in-memory body
	assert.Equal(t, "Forbidden", mapError(re, actionListKeys).Params["azure_code"])
	// A response whose body cannot be read gives no inner code.
	assert.Equal(t, codeForbidden, mapError(&azcore.ResponseError{StatusCode: 403}, actionListKeys).Code)
}

func TestClassifyFromTheWire(t *testing.T) {
	cases := []struct {
		name  string
		set   func(st *wireState)
		code  string
		retry bool
	}{
		{"context", func(st *wireState) { st.begin("x"); st.failCtx(context.DeadlineExceeded) }, codeUnreachable, true},
		{"other transport failure", func(st *wireState) { st.begin("x"); st.fail(wireOther) }, codeUnreachable, true},
		{"429 whose body broke", func(st *wireState) { st.begin("x"); st.answered(429, false); st.fail(wireBodyRead) }, codeThrottled, true},
		{"503 whose body broke", func(st *wireState) { st.begin("x"); st.answered(503, false); st.fail(wireBodyRead) }, codeUnreachable, true},
		{"nothing seen", func(st *wireState) {}, codeUnexpected, false},
		{"4xx without a typed error", func(st *wireState) { st.begin("x"); st.answered(418, false) }, codeUnexpected, false},
	}
	for _, tc := range cases {
		st := &wireState{}
		tc.set(st)
		f := classify(errors.New("opaque "+canary), actionGetCertificate, st)
		assert.Equal(t, tc.code, f.err.Code, tc.name)
		assert.Equal(t, tc.retry, f.retry, tc.name)
	}
	// kindOf on its remaining branches.
	assert.Equal(t, wireOther, kindOf(&net.OpError{Op: "read", Err: errors.New("reset")}))
	assert.Equal(t, wireTLSUntrusted, kindOf(&tls.CertificateVerificationError{}))
	assert.Equal(t, wireDial, kindOf(&net.OpError{Op: "dial", Err: errors.New("refused")}))
	// A nil state is a no-op everywhere.
	var nilState *wireState
	nilState.begin("x")
	nilState.fail(wireOther)
	nilState.failCtx(context.Canceled)
	nilState.answered(200, false)
	assert.Equal(t, wireSnapshot{}, nilState.snapshot())
	assert.Nil(t, wireOf(context.Background()))
}

func TestClassifySignInPaths(t *testing.T) {
	te := func(auth string, err error) error { return &tokenError{auth: auth, err: err} }
	assert.ErrorIs(t, mapError(te("client_secret", context.Canceled), actionSignIn), context.Canceled)
	assert.ErrorIs(t, mapError(te("client_secret", context.DeadlineExceeded), actionSignIn), context.DeadlineExceeded)
	// A sign-in error with no evidence at all.
	assert.Equal(t, codeAuthFailed, mapError(te(providers.AzureAuthClientSecret, errors.New(canary)), actionSignIn).Code)
	assert.Equal(t, codeManagedIdentityGone, mapError(te(providers.AzureAuthManagedIdentity, errors.New(canary)), actionSignIn).Code)
	// Managed identity with a malformed 200 is an unexpected answer, not "unavailable".
	st := &wireState{}
	st.begin("169.254.169.254")
	st.answered(200, false)
	f := classify(te(providers.AzureAuthManagedIdentity, errors.New("x")), actionSignIn, st)
	assert.Equal(t, codeUnexpected, f.err.Code)
	assert.True(t, f.retry)
}

func TestGuardedHostIsCaseInsensitive(t *testing.T) {
	assert.Equal(t, "alice-test.vault.azure.net", foldASCII("ALICE-Test.VAULT.azure.net"))
}

func TestCallStopsWhenTheContextEndsInFlight(t *testing.T) {
	clk := nearNow()
	r := &retryer{clock: clk, limiter: newVaultLimiter(clk, VaultRate, VaultConcurrency), log: nopLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := call(ctx, r, readBudget, actionGetCertificate, func(context.Context) (int, error) {
		cancel()
		return 0, errors.New("broken after the cancellation")
	})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.ErrorIs(t, pe, context.Canceled)
	// A context that ended before the call never takes a slot.
	_, err = call(ctx, r, readBudget, actionGetCertificate, func(context.Context) (int, error) { return 1, nil })
	assert.ErrorIs(t, err, context.Canceled)
}

func TestCallRespectsATotalBudget(t *testing.T) {
	clk := clock.NewFake(time.Now())
	r := &retryer{clock: clk, limiter: newVaultLimiter(clk, VaultRate, VaultConcurrency), log: nopLogger(), jitter: func(d time.Duration) time.Duration { return d }}
	tries := 0
	_, err := call(context.Background(), r, budget{attempts: 5, maxAfter: time.Minute, total: 4 * time.Second}, actionGetCertificate,
		func(context.Context) (int, error) {
			tries++
			return 0, &azidentity.AuthenticationFailedError{RawResponse: response(503, nil, "")} //nolint:bodyclose // in-memory body
		})
	assert.Equal(t, 1, tries, "the first wait (5 s) would not fit in the 4 s budget")
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, codeUnreachable, pe.Code)
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("broken") }
