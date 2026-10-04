package azurekv

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// left is the time remaining to the context's deadline; it fails the test when there is none.
func left(t *testing.T, ctx context.Context) time.Duration {
	t.Helper()
	require.NotNil(t, ctx)
	dl, ok := ctx.Deadline()
	require.True(t, ok, "a provider call has a deadline even when its caller gave none")
	return time.Until(dl)
}

// within asserts that a deadline lies in (budget-slack, budget].
func within(t *testing.T, got, budget time.Duration, what string) {
	t.Helper()
	assert.LessOrEqual(t, got, budget, what)
	assert.Greater(t, got, budget-10*time.Second, what)
}

// short is a caller's own deadline of five seconds: the provider keeps it.
func short(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestOwnBudgetsAreAppliedAndACallersShorterDeadlineIsKept(t *testing.T) {
	t.Run("TestConnection: 45 s", func(t *testing.T) {
		for _, caller := range []context.Context{context.Background(), short(t)} {
			api := &stubAPI{}
			sess, _ := stubSession(api)
			_, err := sess.TestConnection(caller)
			require.NoError(t, err)
			if caller == context.Background() {
				within(t, left(t, api.ctx), PreflightBudget, "TestConnection")
			} else {
				assert.LessOrEqual(t, left(t, api.ctx), 5*time.Second)
			}
		}
	})
	t.Run("Discover: 11 minutes", func(t *testing.T) {
		for _, caller := range []context.Context{context.Background(), short(t)} {
			api := &stubAPI{}
			var seen time.Duration
			api.certs = func(func([]*azcertificates.CertificateProperties) error) error { seen = left(t, api.ctx); return nil }
			sess, _ := stubSession(api)
			_, err := sess.Discover(caller, providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			if caller == context.Background() {
				within(t, seen, PollBudget, "Discover")
			} else {
				assert.LessOrEqual(t, seen, 5*time.Second)
			}
		}
	})
	t.Run("secret read: one minute", func(t *testing.T) {
		for _, caller := range []context.Context{context.Background(), short(t)} {
			api := &stubAPI{}
			var seen time.Duration
			api.secret = func(string, string) (azsecrets.Secret, error) {
				seen = left(t, api.ctx)
				return azsecrets.Secret{}, errors.New("x")
			}
			sess, _ := stubSession(api)
			_, _ = sess.ReadCertificateSecret(caller, providers.SecretRequest{Name: "web-cert", Version: strings.Repeat("a", 32)})
			if caller == context.Background() {
				within(t, seen, SecretReadBudget, "secret read")
			} else {
				assert.LessOrEqual(t, seen, 5*time.Second)
			}
		}
	})
	t.Run("import: sign-in and existence check 45 s, the POST one minute", func(t *testing.T) {
		pfx, _ := testPFX(t, pki.ECDSA256)
		for _, caller := range []context.Context{context.Background(), short(t)} {
			api := &stubAPI{}
			var token, get, post time.Duration
			api.token = func() (azcore.AccessToken, error) {
				token = left(t, api.ctx)
				return azcore.AccessToken{Token: "x"}, nil
			}
			api.get = func(string, string) (azcertificates.Certificate, error) {
				get = left(t, api.ctx)
				return azcertificates.Certificate{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
			}
			api.imp = func(string, azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error) {
				post = left(t, api.ctx)
				return azcertificates.Certificate{}, providers.NewError(codeUnreachable, true, nil, nil)
			}
			sess, _ := stubSession(api)
			_, _ = sess.ImportCertificate(caller, importReq("c", pfx, "ecdsa", 256), nil)
			if caller == context.Background() {
				within(t, token, PreflightBudget, "import sign-in")
				within(t, get, PreflightBudget, "import existence check")
				within(t, post, ImportSendBudget, "import POST")
			} else {
				for _, d := range []time.Duration{token, get, post} {
					assert.LessOrEqual(t, d, 5*time.Second)
				}
			}
		}
	})
}

// The deployment's secret read keeps its total: a Retry-After that does not fit in what is left of
// the minute ends the read instead of being waited for (S3).
func TestSecretBudgetHasATotal(t *testing.T) {
	assert.Equal(t, budget{attempts: SecretReadAttempts, maxAfter: SecretReadBudget, total: SecretReadBudget}, secretBudget)
	clk := nearNow()
	r := &retryer{clock: clk, limiter: newVaultLimiter(clk, 100, 4), log: nopLogger()}
	calls := 0
	fn := func(context.Context) (int, error) {
		calls++
		clk.Advance(10 * time.Second) // the first try took ten seconds
		hdr := http.Header{"Retry-After": {"55"}}
		return 0, &azcore.ResponseError{StatusCode: 429, RawResponse: response(429, hdr, "")} //nolint:bodyclose // in-memory body
	}
	done := make(chan error, 1)
	go func() { _, err := call(context.Background(), r, secretBudget, actionReadSecret, fn); done <- err }()
	select {
	case err := <-done:
		assert.Equal(t, codeThrottled, asProviderError(t, err).Code)
	case <-time.After(2 * time.Second):
		t.Fatal("the read waited for a Retry-After that does not fit in the minute")
	}
	assert.Equal(t, 1, calls)
}

// m5: where the transport's own record proves that no request body was handed to it, the import is
// refused, not uncertain: the name is not blocked for 24 hours.
func TestImportCancelledBeforeAnyBodyWasSentIsRefused(t *testing.T) {
	pfx, _ := testPFX(t, pki.ECDSA256)
	t.Run("cancelled between the existence check and the POST", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		steps := hookSteps{on: func(name string, st providers.StepStatus) {
			if name == "import" && st == providers.StepStarted {
				cancel()
			}
		}}
		res, err := w.doImport(t, ctx, importReq("new-cert", pfx, "ecdsa", 256), steps)
		pe := asProviderError(t, err)
		assert.Equal(t, providers.ImportRefused, res.Outcome)
		assert.Equal(t, codeUnreachable, pe.Code)
		assert.ErrorIs(t, err, errNotSent)
		assert.NotErrorIs(t, err, context.Canceled)
		assert.Equal(t, 0, w.posts())
		assert.Empty(t, w.s.Versions("new-cert"))
	})
	t.Run("the limiter wait ends with the context", func(t *testing.T) {
		clk := nearNow()
		r := &retryer{clock: clk, limiter: newVaultLimiter(clk, 1, 1), log: nopLogger()}
		rel, err := r.limiter.acquire(context.Background())
		require.NoError(t, err)
		rel()
		ctx, cancel := context.WithCancel(context.Background())
		ran := false
		done := make(chan error, 1)
		go func() {
			_, err := call(ctx, r, sendOnce, actionImport, func(context.Context) (int, error) { ran = true; return 0, nil })
			done <- err
		}()
		clk.BlockUntil(1, 0) // the call waits for the limiter's next slot
		cancel()
		err = <-done
		assert.False(t, ran, "nothing was handed to the SDK")
		assert.ErrorIs(t, err, errNoBody)
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("the same wait for a read carries no such marker", func(t *testing.T) {
		clk := nearNow()
		r := &retryer{clock: clk, limiter: newVaultLimiter(clk, 1, 1), log: nopLogger()}
		rel, _ := r.limiter.acquire(context.Background())
		rel()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := call(ctx, r, readBudget, actionGetCertificate, func(context.Context) (int, error) { return 0, nil })
			done <- err
		}()
		clk.BlockUntil(1, 0)
		cancel()
		assert.NotErrorIs(t, <-done, errNoBody)
	})
}

// m6: a failure before the send is a refusal whose cause is ours, never the context's or the transport's.
func TestRefusalBeforeTheSendDoesNotCarryTheContextError(t *testing.T) {
	pfx, _ := testPFX(t, pki.ECDSA256)
	w := newWorld(t, fakekv.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	steps := hookSteps{on: func(name string, st providers.StepStatus) {
		if name == "sign_in" && st == providers.StepStarted {
			cancel()
		}
	}}
	res, err := w.doImport(t, ctx, importReq("new-cert", pfx, "ecdsa", 256), steps)
	assert.Equal(t, providers.ImportRefused, res.Outcome)
	pe := asProviderError(t, err)
	assert.Equal(t, codeUnreachable, pe.Code)
	assert.Same(t, errNotSent, pe.Cause)
	assert.NotErrorIs(t, err, context.Canceled)
	assert.Empty(t, w.s.Requests())
}

func bodyReq(t *testing.T, body io.ReadCloser, length int64) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+testVaultHost+"/x", body)
	require.NoError(t, err)
	req.Body, req.ContentLength = body, length
	return req
}

// N1: what counts as "a body was handed on" depends on the body, not on a declared length: a body of
// unknown length (ContentLength 0 with a reader) is sent chunked.
func TestBodyEvidenceIgnoresTheDeclaredLength(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"a reader of unknown length": bodyReq(t, io.NopCloser(strings.NewReader("pfx")), 0),
		"a sized body":               bodyReq(t, io.NopCloser(strings.NewReader("pfx")), 3),
	} {
		st := &wireState{}
		assert.True(t, st.noBodySent(), name)
		st.bodyHandedOn(req)
		assert.False(t, st.noBodySent(), name)
	}
	for name, req := range map[string]*http.Request{"nil body": bodyReq(t, nil, 0), "NoBody": bodyReq(t, http.NoBody, 0)} {
		st := &wireState{}
		st.bodyHandedOn(req)
		assert.True(t, st.noBodySent(), name+": the challenge probe has no body")
	}
	var nilState *wireState
	nilState.bodyHandedOn(bodyReq(t, io.NopCloser(strings.NewReader("x")), 1))
	assert.False(t, nilState.noBodySent(), "no record, no evidence")
}

// N2: the record is sticky: a later request of the attempt (a retry of the probe, a token request)
// never clears it.
func TestBodyEvidenceIsStickyWithinAnAttempt(t *testing.T) {
	st := &wireState{}
	st.bodyHandedOn(bodyReq(t, io.NopCloser(strings.NewReader("pfx")), 3))
	st.begin("alice-test.vault.azure.net")
	st.bodyHandedOn(bodyReq(t, nil, 0))
	st.fail(wireOther)
	assert.False(t, st.noBodySent())
}

// N5: the IMDS transport's own request check refuses another port and another address before
// anything is dialed; the dialer's check is a second line, the wire record tells which one answered.
func TestIMDSTransportRefusesOtherAddressesInDo(t *testing.T) {
	dialed := 0
	g := newIMDSTransport(nil, func(context.Context, string, string) (net.Conn, error) { dialed++; return nil, errors.New("dial") })
	for _, raw := range []string{"http://169.254.169.254:8080/", "http://10.0.0.1/", "http://169.254.169.254:443/", "http://169.254.169.253/"} {
		ctx, st := withWire(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		require.NoError(t, err)
		resp, err := g.Do(req) //nolint:bodyclose // refused: no response
		assert.ErrorIs(t, err, errHostNotAllowed, raw)
		assert.Nil(t, resp)
		assert.Equal(t, wireHostNotAllowed, st.snapshot().kind, "%s: refused by Do, not by the dialer", raw)
	}
	assert.Zero(t, dialed)
}
