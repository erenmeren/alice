package lestaging

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/testutil/fakeacme"
)

const testDomain = "shop.example.test"

func startFake(t *testing.T, opts fakeacme.Options) *fakeacme.Server {
	t.Helper()
	s, err := fakeacme.New(opts)
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(s.Close)
	return s
}

type env map[string]string

func (e env) get(k string) string { return e[k] }

// fakeConfig is a DNS-01 run through the real dns01 hook solver against the fake's hook receiver.
func fakeConfig(t *testing.T, s *fakeacme.Server) Config {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "hook-ca.pem")
	require.NoError(t, os.WriteFile(caFile, s.CAPEM(), 0o600))
	cred := s.Credentials()
	e := env{EnvDNSHookURL: cred.HookURL, EnvDNSHookSecret: cred.HookSecret, EnvDNSHookCAFile: caFile, EnvDNSWait: "0"}
	return Config{DirectoryURL: s.DirectoryURL(), Domain: testDomain, Challenge: solver.DNS01, DNSProvider: "hook",
		AcceptTOS: true, StateDir: t.TempDir(), RootsPEM: s.IssuerRootPEM(), CABundlePEM: string(s.CAPEM()),
		KeyType: keygen.Default, Getenv: e.get}
}

func run(t *testing.T, cfg Config) (*Report, string) {
	t.Helper()
	var out bytes.Buffer
	r, err := NewRunner(cfg, &out)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep := r.Run(ctx)
	return rep, out.String()
}

func requireAll(t *testing.T, rep *Report, out string, status string, steps ...string) {
	t.Helper()
	for _, s := range steps {
		require.Equal(t, status, rep.Status(s), "step %s\n%s", s, out)
	}
}

func readState(t *testing.T, dir string) state {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	require.NoError(t, err)
	var st state
	require.NoError(t, json.Unmarshal(b, &st))
	return st
}

func TestFullRunWithTheDNSHookAndAWildcard(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.Wildcard = true
	rep, out := run(t, cfg)
	require.True(t, rep.OK(), out)
	requireAll(t, rep, out, Pass, StepPreflight, StepDirectory, StepRoots, StepAccount, StepLeftovers, StepOrder, StepChain,
		StepARI, StepRenewal, StepRevoke, StepCleanup)
	assert.Contains(t, out, "RESULT: PASS (11 passed, 0 failed")
	assert.Contains(t, out, "replaces sent")
	assert.Contains(t, out, "registered a new account")
	assert.Contains(t, out, "4 challenge(s) presented and removed")

	require.Len(t, s.Replacements(), 1, "the renewal carried replaces")
	assert.Empty(t, s.DNSRecords(), "every TXT value was removed through the hook")
	st := readState(t, cfg.StateDir)
	assert.Empty(t, st.Pending)
	assert.NotEmpty(t, st.AccountURL)
	files, err := os.ReadDir(filepath.Join(cfg.StateDir, certDir))
	require.NoError(t, err)
	require.Len(t, files, 2)
	for _, f := range files {
		cs, ok := s.CertificateStatus(strings.TrimSuffix(f.Name(), ".pem"))
		require.True(t, ok)
		assert.Equal(t, "revoked", cs.Status, f.Name())
	}
	info, err := os.Stat(filepath.Join(cfg.StateDir, accountKeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestARerunReusesTheAccount(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	rep, out := run(t, cfg)
	require.True(t, rep.OK(), out)
	rep, out = run(t, cfg)
	require.True(t, rep.OK(), out)
	assert.Contains(t, out, "the account key of an earlier run")
	assert.Contains(t, out, "the CA returned the existing account")
	assert.Equal(t, 1, s.Counters()["new-account"]-1, "one registration, one lookup of the existing account: %v", s.Counters())
}

func TestARateLimitIsHonouredByTheNextRun(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 2 * time.Hour}))
	rep, out := run(t, cfg)
	require.False(t, rep.OK())
	assert.Equal(t, Fail, rep.Status(StepOrder), out)
	assert.Equal(t, Skip, rep.Status(StepRevoke), out)
	assert.Contains(t, out, "the CA asked to wait until")
	assert.Contains(t, out, "hint: staging limits")
	st := readState(t, cfg.StateDir)
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), st.CANotBefore, time.Minute)

	before := s.Counters()["directory"]
	rep, out = run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepPreflight), out)
	assert.Contains(t, out, "an earlier run was rate-limited")
	assert.Equal(t, before, s.Counters()["directory"], "nothing was sent before the CA's time")
}

func TestCertificatesLeftUnrevokedAreRevokedByTheNextRun(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal}))
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepRevoke), out)
	assert.Equal(t, Fail, rep.Status(StepCleanup), out)
	assert.Contains(t, out, "2 certificate(s) not revoked yet")
	require.Len(t, readState(t, cfg.StateDir).Pending, 2)

	s.ClearFaults()
	rep, out = run(t, cfg)
	require.True(t, rep.OK(), out)
	assert.Contains(t, out, "revoked 2 of 2 certificate(s) left by earlier runs")
	assert.Empty(t, readState(t, cfg.StateDir).Pending)
}

func TestALeftoverThatCannotBeRevokedStopsTheRun(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultServerInternal}))
	_, _ = run(t, cfg)
	s.ClearFaults()
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultRateLimited, RetryAfter: time.Hour}))
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepLeftovers), out)
	assert.Equal(t, Skip, rep.Status(StepOrder), out)
}

func TestAMissingLeftoverFileIsDropped(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	st := &state{Pending: []string{"gone.pem"}}
	require.NoError(t, st.save(cfg.StateDir))
	rep, out := run(t, cfg)
	require.True(t, rep.OK(), out)
	assert.Contains(t, out, "revoked 1 of 1")
}

func TestWithoutRenewalInformationTheARIAndReplacesStepsFail(t *testing.T) {
	s := startFake(t, fakeacme.Options{NoARI: true})
	rep, out := run(t, fakeConfig(t, s))
	assert.Equal(t, Warn, rep.Status(StepDirectory), out)
	assert.Equal(t, Fail, rep.Status(StepARI), out)
	assert.Equal(t, Fail, rep.Status(StepRenewal), out)
	assert.Contains(t, out, "replaces no_ari")
	assert.Equal(t, Pass, rep.Status(StepRevoke), out)
}

func TestACAThatRequiresABindingIsRefused(t *testing.T) {
	s := startFake(t, fakeacme.Options{RequireEAB: true})
	rep, out := run(t, fakeConfig(t, s))
	assert.Equal(t, Fail, rep.Status(StepDirectory), out)
	assert.Equal(t, Skip, rep.Status(StepAccount), out)
}

func TestTermsNotAcceptedFailTheAccount(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.AcceptTOS = false
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepAccount), out)
	assert.Equal(t, Skip, rep.Status(StepOrder), out)
}

func TestAnUnreachableDirectoryFails(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	require.NoError(t, s.AddFault(fakeacme.Fault{Endpoint: "directory", Kind: fakeacme.FaultServerInternal}))
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepDirectory), out)
	assert.Equal(t, Skip, rep.Status(StepCleanup), out)
}

func TestARootThatDoesNotMatchFailsTheChain(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	other := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.RootsPEM = other.IssuerRootPEM()
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepChain), out)
	assert.Equal(t, Skip, rep.Status(StepRenewal), out)
	assert.Equal(t, Pass, rep.Status(StepRevoke), out, "what was issued is still revoked")
	assert.Equal(t, Pass, rep.Status(StepCleanup), out)
}

func TestRootsFileWithoutACertificateFails(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.RootsPEM = []byte("not a certificate")
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepRoots), out)
}

func TestAFailingHookFailsTheOrderWithAHint(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	e := env{EnvDNSHookURL: s.Credentials().HookURL, EnvDNSHookSecret: "wrong-secret-value-123", EnvDNSWait: "0"}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, s.CAPEM(), 0o600))
	e[EnvDNSHookCAFile] = caFile
	cfg.Getenv = e.get
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepOrder), out)
	assert.Contains(t, out, "hint: the DNS hook refused")
	assert.Equal(t, Skip, rep.Status(StepRevoke), out)
	assert.Equal(t, Fail, rep.Status(StepCleanup), out, "the clean-up was tried; the hook refused it too, which is reported")
	assert.Contains(t, out, "0 of 1 challenge(s) cleaned up, 1 with an error")
}

func TestDeactivateRemovesTheAccount(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	cfg.Deactivate = true
	rep, out := run(t, cfg)
	require.True(t, rep.OK(), out)
	assert.Contains(t, out, "account deactivated")
	_, err := os.Stat(filepath.Join(cfg.StateDir, accountKeyFile))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, readState(t, cfg.StateDir).AccountURL)
}

func TestADamagedStateFailsThePreflight(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	cfg := fakeConfig(t, s)
	require.NoError(t, os.MkdirAll(cfg.StateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.StateDir, stateFile), []byte("{"), 0o600))
	rep, out := run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepPreflight), out)
	assert.Contains(t, out, "is damaged")

	cfg = fakeConfig(t, s)
	require.NoError(t, os.MkdirAll(cfg.StateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.StateDir, accountKeyFile), []byte("junk"), 0o600))
	rep, out = run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepPreflight), out)

	cfg = fakeConfig(t, s)
	cfg.DirectoryURL = "http://insecure.example.test/directory"
	rep, out = run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepPreflight), out)

	cfg = fakeConfig(t, s)
	cfg.DNSProvider = "nope"
	rep, out = run(t, cfg)
	assert.Equal(t, Fail, rep.Status(StepPreflight), out)
}

func TestARegisteredDNSProviderIsUsed(t *testing.T) {
	s := startFake(t, fakeacme.Options{})
	var built []string
	RegisterDNSProvider("test-fake-table", func(p DNSParams) (solver.Solver, error) {
		built = append(built, p.Domain)
		m := solver.NewMemory(solver.DNS01)
		m.AfterPresent = func(_ context.Context, ch solver.Challenge) error { s.DNSSet(ch.DNSName, ch.DNSValue); return nil }
		m.AfterCleanUp = func(_ context.Context, ch solver.Challenge) error { s.DNSClear(ch.DNSName, ch.DNSValue); return nil }
		return m, nil
	})
	assert.Contains(t, DNSProviders(), "test-fake-table")
	assert.Panics(t, func() { RegisterDNSProvider("test-fake-table", hookProvider) })
	assert.Panics(t, func() { RegisterDNSProvider("", hookProvider) })

	cfg := fakeConfig(t, s)
	cfg.DNSProvider = "test-fake-table"
	cfg.Getenv = nil
	rep, out := run(t, cfg)
	require.True(t, rep.OK(), out)
	assert.Equal(t, []string{testDomain, testDomain}, built, "one solver per order")
	assert.Empty(t, s.DNSRecords())
}

func TestReportSummary(t *testing.T) {
	r := &Report{Results: []Result{{Step: "a", Status: Pass}, {Step: "b", Status: Warn}, {Step: "c", Status: Skip}}}
	assert.True(t, r.OK())
	assert.Equal(t, "RESULT: PASS (1 passed, 0 failed, 1 warnings, 1 skipped)", r.Summary())
	assert.Empty(t, r.Status("zzz"))
	r.Results = append(r.Results, Result{Step: "d", Status: Fail})
	assert.False(t, r.OK())
	assert.True(t, strings.HasPrefix(r.Summary(), "RESULT: FAIL"))
	assert.Len(t, Steps(), 11)
}

func TestHints(t *testing.T) {
	cfg := Config{Domain: testDomain}
	for _, reason := range []string{"acme.validation_failed_http", "acme.validation_failed_dns", "acme.tls_trust_failed",
		"acme.name_not_allowed", "acme.identifier_refused"} {
		assert.NotEmpty(t, hint(acmeErr(reason), cfg), reason)
	}
	assert.Empty(t, hint(os.ErrClosed, cfg))
}
