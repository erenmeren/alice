package canaryjobs

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/httpcheck"
)

// fakeInv scripts the inventory side of a round.
type fakeInv struct {
	target    inventory.Target
	refErr    error
	failures  []string
	failErr   error
	round     inventory.CanaryTarget
	roundErr  error
	recorded  []inventory.CanaryRound
	recordErr error
	claim     inventory.Claim
	advanced  int
	advErr    error
}

func (f *fakeInv) TargetRef(_ context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	return providers.TargetRef{ID: id, Name: "web-01", Kind: providers.KindNginx}, f.target, f.refErr
}
func (f *fakeInv) Credentials() providers.CredentialSource { return nil }
func (f *fakeInv) HostKeyStore() providers.HostKeyStore    { return nil }
func (f *fakeInv) RecordConnectionFailure(_ context.Context, _ uuid.UUID, reason string) error {
	f.failures = append(f.failures, reason)
	return f.failErr
}
func (f *fakeInv) CanaryRoundTarget(context.Context, uuid.UUID) (inventory.CanaryTarget, error) {
	return f.round, f.roundErr
}
func (f *fakeInv) RecordCanaryRound(ctx context.Context, _ uuid.UUID, r inventory.CanaryRound) error {
	f.claim, _ = inventory.ClaimFrom(ctx)
	f.recorded = append(f.recorded, r)
	return f.recordErr
}
func (f *fakeInv) AdvanceRollouts(context.Context) (int, error) { return f.advanced, f.advErr }

// fakeChecker answers res and records the request.
type fakeChecker struct {
	res  httpcheck.Result
	reqs []httpcheck.Request
}

func (c *fakeChecker) Check(_ context.Context, r httpcheck.Request) httpcheck.Result {
	c.reqs = append(c.reqs, r)
	return c.res
}

type world struct {
	inv     *fakeInv
	prov    *fake.Provider
	checker *fakeChecker
	h       *handlers
	dep     uuid.UUID
	job     jobs.Job
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{dep: uuid.New(), checker: &fakeChecker{res: httpcheck.Result{OK: true, HTTPStatus: 200, LatencyMS: 12}}}
	target := uuid.New()
	w.inv = &fakeInv{target: inventory.Target{ID: target, Name: "web-01", Type: inventory.TypeNginx, Status: inventory.StatusOK},
		round: inventory.CanaryTarget{Deployment: w.dep, TargetID: target, Verify: providers.VerifyRequest{Fingerprint: "aa"},
			Check: &inventory.CanaryCheckSpec{Address: "10.0.0.5", Port: 443, ServerName: "www.example.test", Path: "/healthz",
				ExpectStatus: []int{200}, Timeout: 5 * time.Second, ExpectLeafSHA256: "aa"}}}
	w.prov = fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapVerifyDeployment)
	w.prov.Configure(func(c *fake.Config) { c.OpenErr = nil })
	reg := providers.NewRegistry()
	reg.Register(w.prov)
	reg.Freeze()
	w.h = &handlers{d: Deps{Inventory: w.inv, Registry: reg, Checker: w.checker, Clock: clock.NewFake(time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)),
		UserAgent: "Alice-canary/test", Log: slog.New(slog.DiscardHandler)}}
	w.job = jobs.Job{ID: uuid.New(), Type: jobs.CanaryCheck, TargetID: target, Payload: map[string]string{"deployment_id": w.dep.String()},
		Attempt: 1, MaxAttempts: 1}
	return w
}

func (w *world) verify(res providers.VerifyResult, err error) {
	w.prov.Configure(func(c *fake.Config) {
		c.Verify = func(providers.VerifyRequest) (providers.VerifyResult, error) { return res, err }
	})
}

// CAN-21: a round's pass, fail and unknown (design §9.5).
func TestRoundPassFailUnknown(t *testing.T) {
	t.Run("baseline pass + HTTP pass: pass", func(t *testing.T) {
		w := newWorld(t)
		res, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "pass", res["outcome"])
		require.Len(t, w.inv.recorded, 1)
		assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass, HTTPStatus: 200, LatencyMS: 12}, w.inv.recorded[0])
		require.Len(t, w.checker.reqs, 1)
		assert.Equal(t, httpcheck.Request{Address: "10.0.0.5", Port: 443, ServerName: "www.example.test", Path: "/healthz",
			ExpectStatus: []int{200}, Timeout: 5 * time.Second, ExpectLeafSHA256: "aa", UserAgent: "Alice-canary/test"}, w.checker.reqs[0])
		assert.Equal(t, w.job.ID, w.inv.claim.JobID, "the record is fenced to the job's claim")
	})
	t.Run("baseline pass + 503: fail canary.http_status", func(t *testing.T) {
		w := newWorld(t)
		w.checker.res = httpcheck.Result{Reason: httpcheck.ReasonHTTPStatus, HTTPStatus: 503, LatencyMS: 3}
		res, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "fail", res["outcome"])
		assert.Equal(t, 503, res["http_status"])
		assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundFail, Reason: httpcheck.ReasonHTTPStatus, TLS: inventory.RoundPass,
			HTTPStatus: 503, LatencyMS: 3}, w.inv.recorded[0])
	})
	t.Run("baseline fails: fail with the provider's reason, no HTTP check", func(t *testing.T) {
		w := newWorld(t)
		w.verify(providers.VerifyResult{Mode: "remote", Reason: "deployment.verify_failed"}, nil)
		_, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundFail, Reason: "deployment.verify_failed", TLS: inventory.RoundFail}, w.inv.recorded[0])
		assert.Empty(t, w.checker.reqs)
	})
	t.Run("the provider answers an error: unknown", func(t *testing.T) {
		w := newWorld(t)
		w.verify(providers.VerifyResult{}, providers.NewError("ssh.unreachable", true, nil, nil))
		_, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundUnknown, Reason: "ssh.unreachable", TLS: inventory.RoundUnknown}, w.inv.recorded[0])
		w = newWorld(t)
		w.verify(providers.VerifyResult{}, errors.New("boom"))
		_, err = w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "internal.unexpected", w.inv.recorded[0].Reason)
	})
	t.Run("the session is refused: unknown, never a failure", func(t *testing.T) {
		for status, reason := range map[string]string{inventory.StatusDisabled: "target.disabled", inventory.StatusHostKeyChanged: "target.host_key_changed",
			inventory.StatusPendingHostKey: "target.host_key_unconfirmed"} {
			w := newWorld(t)
			w.inv.target.Status = status
			res, err := w.h.check(context.Background(), w.job, nil)
			require.NoError(t, err)
			assert.Equal(t, "unknown", res["outcome"])
			assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundUnknown, Reason: reason, TLS: inventory.RoundUnknown}, w.inv.recorded[0])
		}
		w := newWorld(t)
		w.inv.refErr = inventory.ErrNotFound
		_, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "system.not_found", w.inv.recorded[0].Reason)
		w = newWorld(t)
		w.inv.refErr = errors.New("db down")
		_, err = w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "internal.unexpected", w.inv.recorded[0].Reason)
	})
	t.Run("the connection fails: unknown, recorded on the server", func(t *testing.T) {
		w := newWorld(t)
		w.prov.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("ssh.unreachable", true, nil, nil) })
		w.inv.failErr = errors.New("db")
		_, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"ssh.unreachable"}, w.inv.failures)
		assert.Equal(t, inventory.RoundUnknown, w.inv.recorded[0].Result)
		w = newWorld(t)
		w.prov.Configure(func(c *fake.Config) { c.OpenErr = errors.New("plain") })
		_, err = w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, "internal.unexpected", w.inv.recorded[0].Reason)
	})
	t.Run("skipped baseline and no HTTP check: pass by time", func(t *testing.T) {
		w := newWorld(t)
		w.inv.round.Check = nil
		w.verify(providers.VerifyResult{OK: true, Mode: "skipped"}, nil)
		_, err := w.h.check(context.Background(), w.job, nil)
		require.NoError(t, err)
		assert.Equal(t, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundSkipped}, w.inv.recorded[0])
		assert.Empty(t, w.checker.reqs)
	})
}

// CAN-21: a deployment that no longer holds records nothing; the job's own failures.
func TestRoundIgnoresANonHoldingDeployment(t *testing.T) {
	w := newWorld(t)
	w.inv.roundErr = inventory.ErrDeploymentState
	res, err := w.h.check(context.Background(), w.job, nil)
	require.NoError(t, err)
	assert.Equal(t, "not_holding", res["outcome"])
	assert.Empty(t, w.inv.recorded)
	assert.Zero(t, w.prov.Count("VerifyDeployment"))

	w = newWorld(t)
	w.inv.roundErr = errors.New("db down")
	_, err = w.h.check(context.Background(), w.job, nil)
	assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)

	w = newWorld(t)
	j := w.job
	j.TargetID = uuid.New()
	_, err = w.h.check(context.Background(), j, nil)
	assert.Equal(t, "internal.unexpected", failureOf(t, err).Reason)
	assert.Empty(t, w.inv.recorded)

	w = newWorld(t)
	j = w.job
	j.Payload = map[string]string{}
	_, err = w.h.check(context.Background(), j, nil)
	assert.Equal(t, "system.not_found", failureOf(t, err).Reason)

	w = newWorld(t)
	w.inv.recordErr = errors.New("db down")
	_, err = w.h.check(context.Background(), w.job, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	w = newWorld(t)
	w.inv.recordErr = inventory.ErrClaimLost
	_, err = w.h.check(context.Background(), w.job, nil)
	assert.Equal(t, jobs.Permanent, failureOf(t, err).Class)
}

func failureOf(t *testing.T, err error) *jobs.Failure {
	t.Helper()
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	return f
}

// The task runs the advance; Register and AdvanceTask refuse missing dependencies.
func TestAdvanceTaskAndRegister(t *testing.T) {
	inv := &fakeInv{advanced: 2}
	task := AdvanceTask(inv, 10*time.Second, nil)
	assert.Equal(t, jobs.CanaryAdvance, task.Type)
	assert.Equal(t, 10*time.Second, task.Every)
	require.NoError(t, task.Run(context.Background()))
	inv.advErr = errors.New("x")
	assert.Error(t, task.Run(context.Background()))
	assert.Panics(t, func() { AdvanceTask(nil, time.Second, nil) })
	assert.Panics(t, func() { Register(nil, Deps{}) })
}
