package providertest_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/providertest"
)

type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

const canary = "CANARY-6b1f0e"

// ctxSession implements TestConnection only. By default it honours its context like a good
// provider; the fields break one rule each.
type ctxSession struct {
	providers.UnsupportedSession
	ignoreCtx   bool          // succeeds with a cancelled context
	hang        time.Duration // waits this long regardless of the context
	leak        bool          // puts the canary into an error parameter
	plainErr    bool          // returns a plain error instead of *providers.Error
	unsupported bool          // answers ErrUnsupported although advertised
}

func (s ctxSession) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	if s.hang > 0 {
		time.Sleep(s.hang)
	}
	switch {
	case s.unsupported:
		return providers.ConnectionReport{}, providers.ErrUnsupported
	case s.leak:
		return providers.ConnectionReport{}, providers.NewError("ssh.auth_failed", false, nil, map[string]string{"key": canary})
	case ctx.Err() != nil && !s.ignoreCtx:
		return providers.ConnectionReport{}, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
	case s.plainErr:
		return providers.ConnectionReport{}, errors.New("boom")
	}
	return providers.ConnectionReport{HelperVersion: "1"}, nil
}

func harness(s ctxSession) providertest.SessionHarness {
	return providertest.SessionHarness{
		Capabilities: providers.NewCapabilitySet(providers.CapTestConnection),
		Open: func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("ssh.timeout", true, err, nil)
			}
			return s, nil
		},
		Secrets:     []string{canary},
		CancelBound: 200 * time.Millisecond,
	}
}

func TestCheckSessionPassesAConformingSession(t *testing.T) {
	r := &recorder{TB: t}
	providertest.CheckSession(r, harness(ctxSession{}))
	assert.Empty(t, r.failures)
}

func TestCheckSessionCatchesBrokenSessions(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    ctxSession
		want string
	}{
		{"ignores the context", ctxSession{ignoreCtx: true}, "TestConnection with a cancelled context succeeded"},
		{"hangs", ctxSession{hang: time.Second}, "TestConnection with a cancelled context did not return within"},
		{"leaks a secret", ctxSession{leak: true}, "a secret appears in the output of *providers.Error"},
		{"plain error", ctxSession{plainErr: true, ignoreCtx: true}, "TestConnection returned *errors.errorString, want *providers.Error"},
		{"unsupported", ctxSession{unsupported: true}, "TestConnection answers ErrUnsupported although test_connection is advertised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{TB: t}
			providertest.CheckSession(r, harness(tc.s))
			require.NotEmpty(t, r.failures)
			assert.Contains(t, fmt.Sprint(r.failures), tc.want)
		})
	}

	t.Run("open ignores the context", func(t *testing.T) {
		r := &recorder{TB: t}
		h := harness(ctxSession{})
		h.Open = func(context.Context) (providers.Session, error) { return ctxSession{}, nil }
		providertest.CheckSession(r, h)
		assert.Contains(t, fmt.Sprint(r.failures), "Open with a cancelled context succeeded")
	})
}

func TestCheckNoSecretsLooksAtEveryRendering(t *testing.T) {
	type result struct{ Note string }
	r := &recorder{TB: t}
	providertest.CheckNoSecrets(r, []string{canary},
		result{Note: "x" + canary},                                          // JSON and %+v
		providers.NewError("x", false, errors.New(canary), nil),             // the cause is never rendered
		providers.NewError("x", false, nil, map[string]string{"p": canary}), // params are
	)
	assert.Len(t, r.failures, 2, "%v", r.failures)
}
