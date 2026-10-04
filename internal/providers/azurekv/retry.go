package azurekv

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/providers"
)

// budget is how hard one request (one page) is tried (ruling S15, S3).
type budget struct {
	attempts int           // at most this many attempts
	maxAfter time.Duration // a Retry-After above this ends the request at once
	total    time.Duration // 0: no limit; otherwise attempts plus waits must fit
}

var (
	readBudget   = budget{attempts: MaxAttempts, maxAfter: MaxRetryAfter}
	secretBudget = budget{attempts: SecretReadAttempts, maxAfter: SecretReadBudget, total: SecretReadBudget}
	// sendOnce is for a request that must never be sent twice (an import: the vault has no
	// idempotency key, and a lost answer may follow a created version).
	sendOnce = budget{attempts: 1}
)

const backoffBase = 5 * time.Second

// retryer is Alice's single retry loop of a session (the limiter counts attempts: one attempt can be
// the SDK's unauthenticated challenge probe, the token request and the call itself, and takes one
// rate token and one concurrency slot): it takes the vault's limiter slot, bounds
// each try, maps the error, honours Retry-After and waits on the injected clock.
type retryer struct {
	clock      clock.Clock
	limiter    *vaultLimiter
	log        *slog.Logger
	jitter     func(max time.Duration) time.Duration // a delay in [0, max]; nil: random
	tryTimeout time.Duration                         // 0: TryTimeout
	maxPages   int                                   // pages of one listing; 0: MaxListPages
}

func (r *retryer) jittered(max time.Duration) time.Duration {
	if r.jitter != nil {
		return r.jitter(max)
	}
	return time.Duration(rand.Int64N(int64(max) + 1)) //nolint:gosec // G404: retry spreading, not security
}

// parseRetryAfter reads delta-seconds or an HTTP date.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// call runs fn with the budget b: each attempt waits for the vault's slot, has its own deadline and
// its own wire state, and a panic of the SDK ends it as azure.unexpected_response. The error is
// always a *providers.Error.
func call[T any](ctx context.Context, r *retryer, b budget, action string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	start := r.clock.Now()
	for attempt := 1; ; attempt++ {
		res, f, err := attemptOnce(ctx, r, action, fn)
		if err == nil {
			return res, nil
		}
		if ctx.Err() != nil {
			return zero, evidence(action, f, perr(codeUnreachable, true, ctx.Err(), nil))
		}
		if !f.retry || attempt >= b.attempts {
			r.logFailure(ctx, action, f.err, attempt, false)
			return zero, evidence(action, f, f.err)
		}
		wait := r.jittered(backoffBase << (attempt - 1))
		if d, ok := parseRetryAfter(f.after, r.clock.Now()); ok {
			if d > b.maxAfter {
				r.logFailure(ctx, action, f.err, attempt, false)
				return zero, f.err
			}
			if d > 0 { // "0" or a date in the past asks for no pause: keep the jittered wait
				wait = d
			}
		}
		if b.total > 0 && r.clock.Now().Sub(start)+wait > b.total {
			r.logFailure(ctx, action, f.err, attempt, false)
			return zero, f.err
		}
		r.logFailure(ctx, action, f.err, attempt, true)
		if wait > 0 {
			select {
			case <-r.clock.After(wait):
			case <-ctx.Done():
				return zero, perr(codeUnreachable, true, ctx.Err(), nil)
			}
		}
	}
}

// evidence adds the "no body was sent" marker to an import's error: the one call whose caller needs
// to know whether the vault can have carried the request out.
func evidence(action string, f failure, e *providers.Error) *providers.Error {
	if action != actionImport || !f.noBody {
		return e
	}
	return perr(e.Code, e.Retryable, errors.Join(e.Cause, errNoBody), e.Params)
}

// attemptOnce is one attempt. The returned error is non-nil only with a failure.
func attemptOnce[T any](ctx context.Context, r *retryer, action string, fn func(context.Context) (T, error)) (res T, f failure, err error) {
	release, err := r.limiter.acquire(ctx)
	if err != nil { // the request never reached a transport
		f := ctxFailure(err)
		f.noBody = true
		return res, f, err
	}
	defer release()
	timeout := r.tryTimeout
	if timeout <= 0 {
		timeout = TryTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tctx, st := withWire(tctx)
	func() {
		defer func() {
			if p := recover(); p != nil { // the SDK indexes an unchecked challenge value; the panic text is dropped
				err = errPanic
			}
		}()
		res, err = fn(tctx)
	}()
	if err == nil {
		return res, failure{}, nil
	}
	var zero T
	noBody := st.noBodySent()
	if ctx.Err() == nil && tctx.Err() != nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
		return zero, failure{err: perr(codeUnreachable, true, context.DeadlineExceeded, nil), retry: true, noBody: noBody}, err
	}
	f = classify(err, action, st)
	f.noBody = noBody
	return zero, f, err
}

func (r *retryer) logFailure(ctx context.Context, action string, e *providers.Error, attempt int, willRetry bool) {
	level := slog.LevelDebug
	if e.Code == codeThrottled {
		level = slog.LevelWarn // F-44: a log line records throttling
	}
	attrs := []slog.Attr{slog.String("operation", action), slog.String("code", e.Code), slog.Int("attempt", attempt), slog.Bool("will_retry", willRetry)}
	if status, _, ok := answerOf(e); ok {
		attrs = append(attrs, slog.Int("status", status))
	}
	for _, k := range []string{paramAzureCode, paramRequestID} {
		if v, ok := e.Params[k]; ok {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	r.log.LogAttrs(ctx, level, "azure request failed", attrs...)
}
