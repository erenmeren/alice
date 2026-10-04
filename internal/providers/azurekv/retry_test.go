package azurekv

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

// retryWorld is a vault with one certificate and a session on a fake clock.
type retryWorld struct {
	s    *fakekv.Server
	clk  *clock.Fake
	sess *session
	ver  string
}

func newRetryWorld(t *testing.T, try time.Duration) *retryWorld {
	t.Helper()
	s := fakekv.Start(t, fakekv.Options{})
	ver := addSeed(s)
	clk := clock.NewFake(time.Now().Truncate(time.Second))
	p := testProvider(s)
	p.o.try = try
	sess := openSession(t, p, &idSource{id: secretIdentity(s)}, clk)
	// Sign in and learn the challenge now, so the faults below meet only the call under test.
	_, err := sess.api.GetCertificate(context.Background(), "web-cert", "")
	require.NoError(t, err)
	s.ClearRequests()
	return &retryWorld{s: s, clk: clk, sess: sess, ver: ver}
}

// authed counts the vault requests that carried a token.
func (w *retryWorld) authed() int {
	n := 0
	for _, r := range w.s.Requests() {
		if r.Host == testVaultHost && r.HadAuth {
			n++
		}
	}
	return n
}

func (w *retryWorld) get(ctx context.Context) chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := w.sess.api.GetCertificate(ctx, "web-cert", "")
		ch <- err
	}()
	return ch
}

func (w *retryWorld) code(t *testing.T, err error) *providers.Error {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe
}

// waitsExactly checks that the call is waiting on the clock for d, no less and no more: it does not
// proceed after d-1ms and does after d.
func (w *retryWorld) waitsExactly(t *testing.T, d time.Duration, before int) {
	t.Helper()
	w.clk.BlockUntil(1, 0)
	w.clk.Advance(d - time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	require.Equal(t, before, w.authed(), "the call retried before %s", d)
	w.clk.Advance(time.Millisecond)
}

func TestRetryLoop(t *testing.T) {
	t.Run("Retry-After seconds", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 429, RetryAfter: "7"})
		ch := w.get(context.Background())
		w.waitsExactly(t, 7*time.Second, 1)
		require.NoError(t, <-ch)
		assert.Equal(t, 2, w.authed())
	})
	t.Run("Retry-After HTTP date", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 429, RetryAfter: w.clk.Now().Add(9 * time.Second).UTC().Format(http.TimeFormat)})
		ch := w.get(context.Background())
		w.waitsExactly(t, 9*time.Second, 1)
		require.NoError(t, <-ch)
	})
	t.Run("Retry-After above a minute gives up at once", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 429, RetryAfter: "61"})
		pe := w.code(t, <-w.get(context.Background()))
		assert.Equal(t, "azure.throttled", pe.Code)
		assert.True(t, pe.Retryable)
		assert.Equal(t, 1, w.authed())
	})
	t.Run("Retry-After of exactly a minute is honoured", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 429, RetryAfter: "60"})
		ch := w.get(context.Background())
		w.waitsExactly(t, 60*time.Second, 1)
		require.NoError(t, <-ch)
	})
	t.Run("an unreadable Retry-After falls back to the jittered delay", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 429, RetryAfter: "soon"})
		ch := w.get(context.Background())
		w.waitsExactly(t, 5*time.Second, 1)
		require.NoError(t, <-ch)
	})
	t.Run("429 without the header: jittered back-off, three attempts", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		var maxes []time.Duration
		w.sess.api.(*sdkAPI).r.jitter = func(d time.Duration) time.Duration { maxes = append(maxes, d); return d }
		w.s.FailAll("/certificates/web-cert", fakekv.Fault{Status: 429})
		ch := w.get(context.Background())
		w.waitsExactly(t, 5*time.Second, 1)
		w.waitsExactly(t, 10*time.Second, 2)
		pe := w.code(t, <-ch)
		assert.Equal(t, "azure.throttled", pe.Code)
		assert.Equal(t, 3, w.authed(), "exactly three attempts")
		assert.Equal(t, []time.Duration{5 * time.Second, 10 * time.Second}, maxes)
	})
	t.Run("503 and a truncated body are retried", func(t *testing.T) {
		for name, f := range map[string]fakekv.Fault{
			"503":       {Status: 503},
			"truncated": {Truncate: true},
			"dropped":   {Drop: true},
		} {
			w := newRetryWorld(t, 0)
			w.s.FailNext("/certificates/web-cert", f)
			ch := w.get(context.Background())
			w.waitsExactly(t, 5*time.Second, 1)
			require.NoError(t, <-ch, name)
			assert.Equal(t, 2, w.authed(), name)
		}
	})
	t.Run("403 and 404 are not retried", func(t *testing.T) {
		for _, status := range []int{403, 404, 400, 401} {
			w := newRetryWorld(t, 0)
			w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: status})
			err := <-w.get(context.Background())
			require.Error(t, err)
			assert.Equal(t, 1, w.authed(), status)
		}
	})
	t.Run("a cancelled context during a wait returns at once", func(t *testing.T) {
		w := newRetryWorld(t, 0)
		w.s.FailAll("/certificates/web-cert", fakekv.Fault{Status: 503})
		ctx, cancel := context.WithCancel(context.Background())
		ch := w.get(ctx)
		w.clk.BlockUntil(1, 0)
		cancel()
		err := <-ch
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, "azure.unreachable", w.code(t, err).Code)
		assert.Equal(t, 1, w.authed())
	})
	t.Run("each try has its own deadline", func(t *testing.T) {
		w := newRetryWorld(t, 150*time.Millisecond)
		w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 200, Delay: 5 * time.Second})
		ch := w.get(context.Background())
		w.clk.BlockUntil(1, 0) // the first try timed out and the loop waits to retry
		w.clk.Advance(5 * time.Second)
		require.NoError(t, <-ch)
		// A hanging vault ends every try as azure.unreachable.
		w2 := newRetryWorld(t, 100*time.Millisecond)
		w2.s.FailAll("/certificates/web-cert", fakekv.Fault{Status: 200, Delay: 5 * time.Second})
		ch = w2.get(context.Background())
		w2.waitsExactly(t, 5*time.Second, 1)
		w2.waitsExactly(t, 10*time.Second, 2)
		pe := w2.code(t, <-ch)
		assert.Equal(t, "azure.unreachable", pe.Code)
		assert.ErrorIs(t, pe, context.DeadlineExceeded)
	})
}

func TestReadWithAnOrdinaryFailureIsNotRetried(t *testing.T) {
	// A refused host is final: the retry flag is off even though the code is retryable.
	w := newRetryWorld(t, 0)
	w.s.FailNext("/certificates/web-cert", fakekv.Fault{Status: 302, Location: "https://evil.test/"})
	pe := w.code(t, <-w.get(context.Background()))
	assert.Equal(t, "azure.unexpected_response", pe.Code)
	assert.Equal(t, 1, w.authed())
}

func TestImportIsSentOnce(t *testing.T) {
	w := newRetryWorld(t, 0)
	w.s.FailAll("/certificates/new-cert/import", fakekv.Fault{Status: 503, Apply: false})
	_, err := w.sess.api.ImportCertificate(context.Background(), "new-cert",
		azcertificates.ImportCertificateParameters{Base64EncodedCertificate: to.Ptr("AA==")})
	assert.Equal(t, "azure.unreachable", w.code(t, err).Code)
	assert.Equal(t, 1, w.authed(), "an import is never sent twice")
	_, _, ok := answerOf(err)
	assert.True(t, ok)
}

func TestSecretReadHasAShortBudget(t *testing.T) {
	w := newRetryWorld(t, 0)
	w.s.FailAll("/secrets/web-cert/"+w.ver, fakekv.Fault{Status: 503})
	ch := make(chan error, 1)
	go func() { _, err := w.sess.api.GetSecret(context.Background(), "web-cert", w.ver); ch <- err }()
	w.waitsExactly(t, 5*time.Second, 1)
	assert.Equal(t, "azure.unreachable", w.code(t, <-ch).Code)
	assert.Equal(t, 2, w.authed(), "at most two attempts")
	// A Retry-After beyond the minute left ends the read at once.
	w2 := newRetryWorld(t, 0)
	w2.s.FailAll("/secrets/web-cert/"+w2.ver, fakekv.Fault{Status: 429, RetryAfter: "50"})
	ch2 := make(chan error, 1)
	go func() { _, err := w2.sess.api.GetSecret(context.Background(), "web-cert", w2.ver); ch2 <- err }()
	w2.waitsExactly(t, 50*time.Second, 1)
	assert.Equal(t, "azure.throttled", w2.code(t, <-ch2).Code)
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	d, ok := parseRetryAfter("7", now)
	assert.True(t, ok)
	assert.Equal(t, 7*time.Second, d)
	d, ok = parseRetryAfter(now.Add(-time.Hour).Format(http.TimeFormat), now)
	assert.True(t, ok)
	assert.Zero(t, d)
	for _, bad := range []string{"", "-3", "1.5", "soon", strings.Repeat("9", 30)} {
		_, ok = parseRetryAfter(bad, now)
		assert.False(t, ok, bad)
	}
}

func TestJitterIsWithinItsBound(t *testing.T) {
	r := &retryer{}
	for range 200 {
		assert.LessOrEqual(t, r.jittered(5*time.Second), 5*time.Second)
	}
}

func TestSDKPanicIsMappedNotPropagated(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	addSeed(s)
	s.SetChallenge(`Bearer authorization="x" resource="https://vault.azure.net"`) // the SDK indexes this value unchecked
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, nearNow())
	_, err := sess.api.GetCertificate(context.Background(), "web-cert", "")
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.unexpected_response", pe.Code)
}
