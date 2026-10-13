package acmejobs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/http01"
	"alice/internal/acme/transport"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
)

// memPublisher is an HTTP-01 server's token directory: the session of the test nginx provider writes into it, and it
// serves the files for the fake CA's HTTP-01 validation.
type memPublisher struct {
	mu    sync.Mutex
	files map[string]string
	puts  int
}

func (m *memPublisher) PublishHTTP01Token(_ context.Context, token string, keyAuth []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[token] = string(keyAuth)
	m.puts++
	return nil
}

func (m *memPublisher) RemoveHTTP01Token(_ context.Context, token string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[token]
	delete(m.files, token)
	return ok, nil
}

func (m *memPublisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	body, ok := m.files[strings.TrimPrefix(r.URL.Path, solver.HTTPPathPrefix)]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(body))
}

func (m *memPublisher) live() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.files)
}

// pubProvider is the fake nginx provider whose sessions publish HTTP-01 tokens into pub.
type pubProvider struct {
	*fake.Provider
	pub *memPublisher
}

type pubSession struct {
	providers.Session
	*memPublisher
}

func (p pubProvider) Open(ctx context.Context, t providers.TargetRef, c providers.CredentialSource, e providers.Env) (providers.Session, error) {
	s, err := p.Provider.Open(ctx, t, c, e)
	if err != nil {
		return nil, err
	}
	return pubSession{Session: s, memPublisher: p.pub}, nil
}

// publishOnly is the HTTP-01 solver of these tests: the real one checks port 80 of the name itself, which a test
// cannot serve; this one publishes and removes through the same Publisher (the server's session).
type publishOnly struct{ pub http01.Publisher }

func (publishOnly) Types() []string { return []string{solver.HTTP01} }
func (p publishOnly) Present(ctx context.Context, ch solver.Challenge) error {
	return p.pub.PublishHTTP01Token(ctx, ch.Token, []byte(ch.KeyAuth))
}
func (p publishOnly) CleanUp(ctx context.Context, ch solver.Challenge) error {
	_, err := p.pub.RemoveHTTP01Token(ctx, ch.Token)
	return err
}

// stubInv is an Inventory whose answers a test sets; it records what was ended.
type stubInv struct {
	mu sync.Mutex

	work        inventory.ACMEOrderWork
	workErr     error
	client      *acme.Client
	clientErr   error
	key         crypto.Signer
	keyErr      error
	finishErrs  []error
	succeedErr  error
	failErr     error
	hookCfg     dns01.Config
	hookErr     error
	cleanupWork inventory.ACMECleanupWork
	cleanupErr  error
	removeErr   error
	recordErr   error
	stale       []inventory.ACMEStaleOrder
	staleErr    error
	enqueueN    int
	enqueueErr  error
	target      inventory.Target
	targetErr   error

	failed    []string
	recorded  []string
	finished  int
	succeeded int
}

func (s *stubInv) ACMEOrderWork(context.Context, uuid.UUID) (inventory.ACMEOrderWork, error) {
	return s.work, s.workErr
}
func (s *stubInv) ACMEOrderClient(context.Context, uuid.UUID) (*acme.Client, error) {
	return s.client, s.clientErr
}
func (s *stubInv) NewACMEOrderKey(context.Context, uuid.UUID) (crypto.Signer, error) {
	return s.key, s.keyErr
}
func (s *stubInv) LoadPendingKey(context.Context, uuid.UUID) (crypto.Signer, error) {
	return s.key, s.keyErr
}
func (s *stubInv) FinishACMEOrder(context.Context, uuid.UUID, [][]byte) (inventory.ACMEIssued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished++
	if len(s.finishErrs) > 0 {
		err := s.finishErrs[0]
		s.finishErrs = s.finishErrs[1:]
		return inventory.ACMEIssued{}, err
	}
	return inventory.ACMEIssued{CertificateID: uuid.New()}, nil
}
func (s *stubInv) SucceedACMETestOrder(context.Context, uuid.UUID) error {
	s.succeeded++
	return s.succeedErr
}
func (s *stubInv) FailACMEOrder(_ context.Context, _ uuid.UUID, code string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, code)
	return s.failErr
}
func (s *stubInv) RecordACMEOrderURL(context.Context, uuid.UUID, string) error { return nil }
func (s *stubInv) AddACMEPresented(context.Context, uuid.UUID, inventory.ACMEPresented) error {
	return nil
}
func (s *stubInv) RemoveACMEPresented(context.Context, uuid.UUID, inventory.ACMEPresented) error {
	return s.removeErr
}
func (s *stubInv) EnqueueACMECleanup(context.Context, uuid.UUID) error {
	return errors.New("queue down")
}
func (s *stubInv) ACMECleanupWork(context.Context, uuid.UUID) (inventory.ACMECleanupWork, error) {
	return s.cleanupWork, s.cleanupErr
}
func (s *stubInv) RecordACMECleanup(_ context.Context, _ uuid.UUID, code string, final bool) error {
	if final {
		code += "!"
	}
	s.recorded = append(s.recorded, code)
	return s.recordErr
}
func (s *stubInv) ACMEHookSolverConfig(context.Context, uuid.UUID) (dns01.Config, error) {
	return s.hookCfg, s.hookErr
}
func (s *stubInv) ACMEHookCleanupConfig(context.Context, uuid.UUID) (dns01.Config, error) {
	return s.hookCfg, s.hookErr
}
func (s *stubInv) StaleACMEOrders(context.Context, time.Duration) ([]inventory.ACMEStaleOrder, error) {
	return s.stale, s.staleErr
}
func (s *stubInv) EnqueueACMECleanups(context.Context, time.Duration) (int, error) {
	return s.enqueueN, s.enqueueErr
}
func (s *stubInv) TargetRef(_ context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error) {
	return providers.TargetRef{ID: id, Kind: providers.Kind(s.target.Type)}, s.target, s.targetErr
}
func (s *stubInv) Credentials() providers.CredentialSource { return nil }
func (s *stubInv) HostKeyStore() providers.HostKeyStore    { return nil }

type openGate struct{ err error }

func (g openGate) Allow(license.Class) error { return g.err }

func stubHandlers(t *testing.T, inv *stubInv, gate Gate, reg *providers.Registry) *handlers {
	t.Helper()
	if reg == nil {
		reg = providers.NewRegistry()
		reg.Freeze()
	}
	return newHandlers(Deps{Inventory: inv, Registry: reg, Gate: gate, Clock: clock.NewFake(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))})
}

func job(payload map[string]string) jobs.Job {
	return jobs.Job{ID: uuid.New(), Payload: payload, Attempt: 1, MaxAttempts: 1}
}

func failureOf(t *testing.T, err error) *jobs.Failure {
	t.Helper()
	var f *jobs.Failure
	require.ErrorAs(t, err, &f)
	return f
}

func runningWork(challenge string) inventory.ACMEOrderWork {
	hook, target := uuid.New(), uuid.New()
	w := inventory.ACMEOrderWork{Order: inventory.ACMEOrder{ID: uuid.New(), Kind: inventory.ACMEOrderIssue, State: inventory.ACMEOrderRunning},
		Names: []string{"www.example.test"}, Challenge: challenge, ProviderSuffixes: []string{"example.test"}, HookSuffixes: []string{"example.test"}}
	if challenge == inventory.ACMEChallengeDNS01 {
		w.HookID = &hook
	} else {
		w.HTTPTargetID = &target
	}
	return w
}

func TestRegisterNeedsEveryDependency(t *testing.T) {
	r := jobs.NewRunner(jobs.RunnerConfig{})
	reg := providers.NewRegistry()
	assert.Panics(t, func() { Register(r, Deps{}) })
	assert.Panics(t, func() {
		Register(nil, Deps{Inventory: &stubInv{}, Registry: reg, Gate: openGate{}, Clock: clock.Real{}})
	})
	Register(r, Deps{Inventory: &stubInv{}, Registry: reg, Gate: openGate{}, Clock: clock.Real{}})
	assert.True(t, r.Handles(jobs.ACMEIssue))
	assert.True(t, r.Handles(jobs.ACMECleanup))
}

func TestIssueBeforeTheOrder(t *testing.T) {
	inv := &stubInv{}
	h := stubHandlers(t, inv, openGate{}, nil)
	_, err := h.issue(context.Background(), job(map[string]string{"order_id": "nope"}), nil)
	assert.Equal(t, reasonNotFound, failureOf(t, err).Reason)
	ok := job(map[string]string{"order_id": uuid.NewString()})

	inv.workErr = inventory.ErrNotFound
	_, err = h.issue(context.Background(), ok, nil)
	assert.Equal(t, reasonNotFound, failureOf(t, err).Reason)
	inv.workErr = errors.New("database down")
	_, err = h.issue(context.Background(), ok, nil)
	assert.Equal(t, reasonUnexpected, failureOf(t, err).Reason)
	inv.workErr = nil
	inv.work.Order.State = inventory.ACMEOrderFailed
	res, err := h.issue(context.Background(), ok, nil)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEOrderFailed, res["state"], "an order the sweep ended is left alone")
	assert.Empty(t, inv.failed)
}

// Every refusal before the CA is asked ends the order with its code (FailACMEOrder), whatever FailACMEOrder answers.
func TestIssueRefusalsEndTheOrder(t *testing.T) {
	ok := job(map[string]string{"order_id": uuid.NewString()})
	for _, tc := range []struct {
		name string
		mut  func(*stubInv, *handlers)
		gate Gate
		code string
	}{
		{"locked", nil, openGate{err: license.ErrLocked}, inventory.ACMELicenseLocked},
		{"names no longer allowed", func(s *stubInv, _ *handlers) { s.work.ProviderSuffixes = nil }, openGate{}, acme.ReasonNameNotAllowed},
		{"no client", func(s *stubInv, _ *handlers) { s.clientErr = inventory.ErrACMEAccountState }, openGate{}, "acme.account_state"},
		{"hook config", func(s *stubInv, _ *handlers) { s.hookErr = inventory.ErrACMESecretUnreadable }, openGate{}, "acme.secret_unreadable"},
		{"hook config refused by the solver", func(s *stubInv, _ *handlers) { s.hookCfg = dns01.Config{URL: "http://x"} }, openGate{},
			acme.ReasonHookRefused},
		{"unknown method", func(s *stubInv, _ *handlers) { s.work.Challenge = "tlsalpn01" }, openGate{}, acme.ReasonChallengeUnavailable},
		{"server not found", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.targetErr = inventory.ErrNotFound
		}, openGate{}, acme.ReasonChallengeUnavailable},
		{"server error", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.targetErr = errors.New("db")
		}, openGate{}, "internal.unexpected"},
		{"not nginx", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.target = inventory.Target{Type: inventory.TypeLinux, Status: inventory.StatusOK}
		}, openGate{}, acme.ReasonChallengeUnavailable},
		{"disabled", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.target = inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusDisabled}
		}, openGate{}, "target.disabled"},
		{"host key changed", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.target = inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusHostKeyChanged}
		}, openGate{}, "target.host_key_changed"},
		{"host key unconfirmed", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.target = inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusPendingHostKey}
		}, openGate{}, "target.host_key_unconfirmed"},
		{"no nginx provider", func(s *stubInv, _ *handlers) {
			s.work = runningWork(inventory.ACMEChallengeHTTP01)
			s.target = inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusOK}
		}, openGate{}, acme.ReasonChallengeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := &stubInv{work: runningWork(inventory.ACMEChallengeDNS01), failErr: inventory.ErrACMEOrderNotRunning}
			h := stubHandlers(t, inv, tc.gate, nil)
			if tc.mut != nil {
				tc.mut(inv, h)
			}
			_, err := h.issue(context.Background(), ok, nil)
			assert.Equal(t, tc.code, failureOf(t, err).Reason)
			assert.Equal(t, []string{tc.code}, inv.failed)
		})
	}
}

// The HTTP-01 server's session: an open failure is the provider's code; a session that cannot publish is refused;
// a solver that cannot be built closes the session.
func TestOpenPublisher(t *testing.T) {
	ok := job(map[string]string{"order_id": uuid.NewString()})
	plain := fake.New(providers.KindNginx)
	reg := providers.NewRegistry()
	reg.Register(plain)
	reg.Freeze()
	inv := &stubInv{work: runningWork(inventory.ACMEChallengeHTTP01), target: inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusOK}}
	h := stubHandlers(t, inv, openGate{}, reg)
	_, err := h.issue(context.Background(), ok, nil)
	assert.Equal(t, acme.ReasonChallengeUnavailable, failureOf(t, err).Reason, "a session without the publisher methods")

	plain.Configure(func(c *fake.Config) { c.OpenErr = providers.NewError("ssh.unreachable", true, nil, nil) })
	_, err = h.issue(context.Background(), ok, nil)
	assert.Equal(t, "ssh.unreachable", failureOf(t, err).Reason)

	pubReg := providers.NewRegistry()
	pubReg.Register(pubProvider{Provider: fake.New(providers.KindNginx), pub: &memPublisher{files: map[string]string{}}})
	pubReg.Freeze()
	h = stubHandlers(t, inv, openGate{}, pubReg)
	h.newHTTP01 = func(http01.Config) (solver.Solver, error) { return nil, http01.ErrVerify }
	_, err = h.issue(context.Background(), ok, nil)
	assert.Equal(t, acme.ReasonChallengeUnavailable, failureOf(t, err).Reason)
	h.newHTTP01 = func(c http01.Config) (solver.Solver, error) { return http01.New(c) }
	s, closeFn, err := h.solverFor(context.Background(), inv.work)
	require.NoError(t, err)
	closeFn()
	assert.Equal(t, []string{solver.HTTP01}, s.Types())
}

// fakeCA is an in-process fake CA with a registered client.
func fakeCA(t *testing.T) (*fakeacme.Server, *acme.Client) {
	t.Helper()
	s, err := fakeacme.New(fakeacme.Options{NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(s.Close)
	hc, err := transport.New(string(s.CAPEM()))
	require.NoError(t, err)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c, err := acme.New(acme.Config{DirectoryURL: s.DirectoryURL(), Key: k, HTTPClient: hc})
	require.NoError(t, err)
	_, err = c.RegisterAccount(context.Background(), "", nil, false)
	require.NoError(t, err)
	return s, c
}

func hookConfig(s *fakeacme.Server) dns01.Config {
	return dns01.Config{URL: s.Credentials().HookURL, Secret: secrets.NewPlaintext([]byte(s.Credentials().HookSecret)),
		CABundlePEM: string(s.CAPEM()), PropagationWait: -1, AllowedSuffixes: []string{"example.test"}}
}

// After the CA issued: a refusal of the chain fails the order; a database that fails twice leaves it running for the
// sweep; one that fails once is tried again.
func TestIssueStoreOutcomes(t *testing.T) {
	ok := job(map[string]string{"order_id": uuid.NewString()})
	s, client := fakeCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		errs     []error
		reason   string
		failed   []string
		finished int
	}{
		{"stored", nil, "", nil, 1},
		{"stored on the second try", []error{errors.New("db")}, "", nil, 2},
		{"refused", []error{inventory.ErrACMEChainMismatch}, acme.ReasonDirectoryInvalid, []string{acme.ReasonDirectoryInvalid}, 1},
		{"left running", []error{errors.New("db"), errors.New("db")}, reasonUnexpected, nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := &stubInv{work: runningWork(inventory.ACMEChallengeDNS01), client: client, key: key, hookCfg: hookConfig(s),
				finishErrs: tc.errs}
			res, err := stubHandlers(t, inv, openGate{}, nil).issue(context.Background(), ok, nil)
			if tc.reason == "" {
				require.NoError(t, err)
				assert.Equal(t, inventory.ACMEOrderSucceeded, res["state"])
			} else {
				assert.Equal(t, tc.reason, failureOf(t, err).Reason)
			}
			assert.Equal(t, tc.failed, inv.failed)
			assert.Equal(t, tc.finished, inv.finished)
		})
	}

	// No key: the order fails before the CA is asked for an order.
	inv := &stubInv{work: runningWork(inventory.ACMEChallengeDNS01), client: client, keyErr: inventory.ErrACMEPendingKey, hookCfg: hookConfig(s)}
	_, err = stubHandlers(t, inv, openGate{}, nil).issue(context.Background(), ok, nil)
	assert.Equal(t, inventory.ACMEOrderAbandoned, failureOf(t, err).Reason)
	// A test run whose end cannot be recorded fails.
	inv = &stubInv{work: runningWork(inventory.ACMEChallengeDNS01), client: client, hookCfg: hookConfig(s), succeedErr: errors.New("db")}
	inv.work.Order.Kind = inventory.ACMEOrderTest
	_, err = stubHandlers(t, inv, openGate{}, nil).issue(context.Background(), ok, nil)
	assert.Equal(t, reasonUnexpected, failureOf(t, err).Reason)
	assert.Equal(t, 1, inv.succeeded)
}

func TestCleanupOutcomes(t *testing.T) {
	ok := jobs.Job{ID: uuid.New(), Payload: map[string]string{"order_id": uuid.NewString()}, Attempt: 1, MaxAttempts: 5}
	inv := &stubInv{}
	h := stubHandlers(t, inv, openGate{}, nil)
	_, err := h.cleanup(context.Background(), job(nil), nil)
	assert.Equal(t, reasonNotFound, failureOf(t, err).Reason)
	inv.cleanupErr = inventory.ErrNotFound
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, reasonNotFound, failureOf(t, err).Reason)
	inv.cleanupErr = errors.New("db")
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	inv.cleanupErr = nil
	inv.cleanupWork.Running = true
	res, err := h.cleanup(context.Background(), ok, nil)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEOrderRunning, res["state"])
	inv.cleanupWork.Running = false
	res, err = h.cleanup(context.Background(), ok, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, res["removed"])

	hook, target := uuid.New(), uuid.New()
	dns := inventory.ACMEPresented{Challenge: solver.Challenge{Type: solver.DNS01, Domain: "a.example.test", DNSName: "_acme-challenge.a.example.test",
		DNSValue: "v"}, HookID: &hook}
	web := inventory.ACMEPresented{Challenge: solver.Challenge{Type: solver.HTTP01, Domain: "a.example.test", Token: "t"}, TargetID: &target}
	odd := inventory.ACMEPresented{Challenge: solver.Challenge{Type: "tls-alpn-01"}}
	inv.cleanupWork.Records = []inventory.ACMEPresented{dns, web, odd}
	inv.hookErr = inventory.ErrNotFound
	inv.targetErr = inventory.ErrNotFound
	_, err = h.cleanup(context.Background(), ok, nil)
	f := failureOf(t, err)
	assert.Equal(t, jobs.Retryable, f.Class)
	assert.Equal(t, acme.ReasonChallengeUnavailable, f.Reason)
	assert.Equal(t, []string{acme.ReasonChallengeUnavailable}, inv.recorded, "an intermediate attempt")

	inv.hookErr = errors.New("db")
	ok.Attempt = 5
	inv.recordErr = errors.New("db")
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	assert.True(t, strings.HasSuffix(inv.recorded[1], "!"), "the final attempt")

	// A hook configuration the solver refuses, a server whose HTTP-01 solver cannot be built.
	inv.hookErr, inv.hookCfg = nil, dns01.Config{URL: "http://x"}
	pubReg := providers.NewRegistry()
	pubReg.Register(pubProvider{Provider: fake.New(providers.KindNginx), pub: &memPublisher{files: map[string]string{}}})
	pubReg.Freeze()
	h = stubHandlers(t, inv, openGate{}, pubReg)
	h.newHTTP01 = func(http01.Config) (solver.Solver, error) { return nil, http01.ErrVerify }
	inv.targetErr, inv.target = nil, inventory.Target{Type: inventory.TypeNginx, Status: inventory.StatusOK}
	inv.cleanupWork.Records = []inventory.ACMEPresented{dns, web}
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)

	// Removed through the server, but the record cannot be forgotten: retried.
	h.newHTTP01 = func(c http01.Config) (solver.Solver, error) { return publishOnly{pub: c.Publisher}, nil }
	inv.cleanupWork.Records = []inventory.ACMEPresented{web}
	inv.removeErr = errors.New("db")
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class)
	inv.removeErr, inv.recordErr = nil, errors.New("db")
	_, err = h.cleanup(context.Background(), ok, nil)
	assert.Equal(t, jobs.Retryable, failureOf(t, err).Class, "the success could not be recorded")
	inv.recordErr = nil
	res, err = h.cleanup(context.Background(), ok, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, res["removed"])
}

func TestSweepOutcomes(t *testing.T) {
	inv := &stubInv{staleErr: errors.New("db"), enqueueErr: errors.New("db")}
	h := stubHandlers(t, inv, openGate{}, nil)
	assert.ErrorIs(t, h.sweep(context.Background()), errSweepFailed)

	now := h.d.Clock.Now()
	young := inventory.ACMEStaleOrder{ID: uuid.New(), Kind: inventory.ACMEOrderIssue, Names: []string{"a.example.test"}, OrderURL: "https://x/o",
		HasKey: true, StartedAt: now}
	old := young
	old.ID, old.StartedAt = uuid.New(), now.Add(-2*ResumeFor)
	inv = &stubInv{stale: []inventory.ACMEStaleOrder{young, old}, enqueueN: 2,
		clientErr: &acme.Error{Reason: acme.ReasonProviderUnreachable}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	inv.key = key
	h = stubHandlers(t, inv, openGate{}, nil)
	require.NoError(t, h.sweep(context.Background()))
	assert.Equal(t, []string{inventory.ACMEOrderAbandoned}, inv.failed, "an unreachable CA is asked again for a day, then the order is abandoned")

	// A pending key that cannot be read: abandoned; a failure to abandon is the tick's error; an order its job
	// ended meanwhile is fine.
	inv = &stubInv{stale: []inventory.ACMEStaleOrder{young}, keyErr: inventory.ErrACMEPendingKey, failErr: errors.New("db")}
	h = stubHandlers(t, inv, openGate{}, nil)
	assert.ErrorIs(t, h.sweep(context.Background()), errSweepFailed)
	inv.failErr = inventory.ErrACMEOrderNotRunning
	require.NoError(t, h.sweep(context.Background()))
	assert.Len(t, inv.failed, 2)
}
