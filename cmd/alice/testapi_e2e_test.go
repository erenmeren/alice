//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/tlscert"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
	"alice/internal/testutil/seed"
	"alice/migrations"
)

func clockNow(t *testing.T, h http.Handler) time.Time {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/clock", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct{ Now string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	now, err := time.Parse(time.RFC3339Nano, body.Now)
	require.NoError(t, err)
	return now
}

func TestE2EClockCanBeAdvanced(t *testing.T) {
	t.Cleanup(e2eClock.Reset)
	h := testHandler(testDeps{})
	before := clockNow(t, h)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/clock", strings.NewReader(`{"advance_seconds":1860}`)))
	require.Equal(t, http.StatusOK, rec.Code)

	after := clockNow(t, h)
	assert.GreaterOrEqual(t, after.Sub(before), 31*time.Minute)
	assert.Less(t, after.Sub(before), 32*time.Minute)
	assert.GreaterOrEqual(t, newClock().Now().Sub(before), 31*time.Minute, "the server clock is the advanced clock")
}

func TestE2EClockRejectsMalformedInput(t *testing.T) {
	h := testHandler(testDeps{})
	big := `{"advance_seconds":1,"pad":"` + strings.Repeat("x", 1<<20) + `"}`
	for body, want := range map[string]int{
		`not json`:                       http.StatusBadRequest,
		big:                              http.StatusRequestEntityTooLarge,
		`{"advance_seconds":-315360001}`: http.StatusUnprocessableEntity,
		`{"advance_seconds":1e300}`:      http.StatusUnprocessableEntity,
		`{"advance_seconds":315360001}`:  http.StatusUnprocessableEntity, // just over 10 years (365-day years)
	} {
		t.Cleanup(e2eClock.Reset)
		before := e2eClock.Now()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/clock", strings.NewReader(body)))
		assert.Equal(t, want, rec.Code, body[:min(len(body), 40)])
		assert.Less(t, e2eClock.Now().Sub(before), time.Minute, "a rejected request never moves the clock")
	}
}

func TestE2EClockAcceptsTenYears(t *testing.T) {
	t.Cleanup(e2eClock.Reset)
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/clock", strings.NewReader(`{"advance_seconds":315360000}`)))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// The e2e build announces itself: a version suffix and a startup warning.
func TestE2EBuildIsMarkedInVersionAndWarnsAtStartup(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"version"}, env(nil), nil, &out, &errOut))
	assert.Contains(t, out.String(), "alice dev+e2e (")
	assert.Equal(t, "dev+e2e", buildVersion().Version)

	var logs bytes.Buffer
	warnIfTestBuild(slog.New(slog.NewTextHandler(&logs, nil)), testHandler(testDeps{}))
	assert.Contains(t, logs.String(), "e2e build: test-only /test endpoints are enabled; never use for real data")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Equal(t, license.TestKeyTrusted, strings.Contains(logs.String(), "test license key trusted"),
		"the e2e image is built with testlicense and says so")
}

func TestE2EUnknownTestEndpointIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/nope", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// The test endpoints change server state, so a cross-site page must not be able to
// drive them from a browser: unsafe methods get the same-origin check of the API guard.
func TestE2ETestEndpointsRejectCrossSiteRequests(t *testing.T) {
	t.Cleanup(e2eClock.Reset)
	h := testHandler(testDeps{})
	before := e2eClock.Now()
	for name, hdr := range map[string][2]string{
		"foreign Origin":         {"Origin", "https://evil.example"},
		"cross-site fetch":       {"Sec-Fetch-Site", "cross-site"},
		"same-site other origin": {"Sec-Fetch-Site", "same-site"},
	} {
		for _, path := range []string{"/test/clock", "/test/reset", "/test/setup-token", "/test/license/tamper", "/test/jobs/drain",
			"/test/rotation/overlap"} {
			req := httptest.NewRequest(http.MethodPost, "https://alice.test"+path, strings.NewReader(`{"advance_seconds":3600}`))
			req.Header.Set(hdr[0], hdr[1])
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", name, path)
		}
	}
	assert.Less(t, e2eClock.Now().Sub(before), time.Minute, "a refused request never moves the clock")

	req := httptest.NewRequest(http.MethodPost, "https://alice.test/test/clock", strings.NewReader(`{"advance_seconds":60}`))
	req.Header.Set("Origin", "https://alice.test")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "a same-origin request is accepted")

	req = httptest.NewRequest(http.MethodGet, "https://alice.test/test/clock", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "reading the clock is a safe method")
}

func postTest(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

// Owner step 5: the demo clock can move back; a wall-only jump adds no uptime.
func TestE2EClockMovesBackAndJumps(t *testing.T) {
	t.Cleanup(e2eClock.Reset)
	h := testHandler(testDeps{})
	before, up := e2eClock.Now(), e2eClock.Elapsed()

	require.Equal(t, http.StatusOK, postTest(t, h, "/test/clock", `{"advance_seconds":-86400}`).Code)
	assert.Less(t, e2eClock.Now().Sub(before), -23*time.Hour)
	assert.GreaterOrEqual(t, e2eClock.Elapsed(), up, "uptime never decreases")

	up = e2eClock.Elapsed()
	require.Equal(t, http.StatusOK, postTest(t, h, "/test/clock", `{"advance_seconds":864000,"wall_only":true}`).Code)
	assert.Less(t, e2eClock.Elapsed()-up, time.Second, "a wall-only jump is not uptime")

	assert.Equal(t, http.StatusBadRequest, postTest(t, h, "/test/clock", `{"advance_seconds":1,"extra":true}`).Code)
}

// Only the testlicense build trusts what /test/license signs.
func TestE2ETestLicenseIsSignedWithTheTestKey(t *testing.T) {
	h := testHandler(testDeps{})
	id := license.NewInstallationID()
	rec := postTest(t, h, "/test/license", `{"installation_id":"`+id+`","max_targets":7,"valid_days":30,"customer":"Örnek A.Ş."}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		License   string `json:"license"`
		LicenseID string `json:"license_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	f, err := license.Check([]byte(body.License), license.EmbeddedKeys())
	require.NoError(t, err)
	assert.Equal(t, id, f.Payload.InstallationID)
	assert.Equal(t, 7, f.Payload.MaxTargets)
	assert.Equal(t, "Örnek A.Ş.", f.Payload.Customer)
	assert.Equal(t, body.LicenseID, f.Payload.LicenseID)
	assert.Equal(t, 30*24*time.Hour, f.Payload.ValidUntil.Sub(f.Payload.ValidFrom))

	assert.Equal(t, http.StatusConflict, postTest(t, h, "/test/license", `{}`).Code, "no running license service: the installation is unknown")
	assert.Equal(t, http.StatusUnprocessableEntity, postTest(t, h, "/test/license", `{"installation_id":"`+id+`","max_targets":0}`).Code)
}

func TestE2EMailboxListsSentEmail(t *testing.T) {
	t.Cleanup(e2eMailbox.reset)
	require.NoError(t, testMailer.Send(context.Background(), notify.Message{To: "ada@example.com", Subject: "Hi", Body: "Body"}))
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/mail", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"messages":[{"to":"ada@example.com","subject":"Hi","body":"Body"}]}`, rec.Body.String())
}

// Without a database or a job runner the new endpoints refuse instead of panicking.
func TestE2EPhase3EndpointsNeedTheirServices(t *testing.T) {
	h := testHandler(testDeps{})
	for _, path := range []string{"/test/license/tamper", "/test/jobs/drain"} {
		rec := postTest(t, h, path, ``)
		assert.Equal(t, http.StatusConflict, rec.Code, path)
		assert.Contains(t, rec.Body.String(), `"error"`, path)
	}
	assert.Less(t, drainBudget, 60*time.Second, "a drain answers before the server's WriteTimeout")
}

// damageLicenseFile changes the signed customer name and nothing else, so the file still parses
// but no longer verifies (L-49).
func TestDamageLicenseFileChangesOnlyTheCustomer(t *testing.T) {
	raw := []byte("{\n  \"payload\": {\n    \"customer\": \"Test Company\",\n    \"max_targets\": 10\n  }\n}\n")
	out, err := damageLicenseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(string(raw), `"customer": "Test Company"`, `"customer": "tampered-Test Company"`, 1), string(out))
	_, err = damageLicenseFile([]byte(`{"payload":{}}`))
	assert.Error(t, err, "a file without a customer field cannot be damaged this way")
}

// I-4: the e2e build starts no job workers, so jobs run only when a test drains them
// (POST /test/jobs/drain) and the journeys see every state deterministically.
func TestE2EBuildStartsNoJobWorkers(t *testing.T) {
	assert.False(t, startJobWorkers)
}

// The e2e build never ticks the deployment recovery sweep on the wall clock (the demo clock moves
// recover_after past by itself); tests run it with POST /test/scheduler/run.
func TestE2EBuildNeverTicksTheSweep(t *testing.T) {
	assert.GreaterOrEqual(t, sweepEvery, 50*365*24*time.Hour)
}

// Nor does it tick the poll scheduler or the automatic deployment planner on the wall clock: the
// journeys run them with POST /test/scheduler/run, so nothing polls or deploys between two steps.
func TestE2EBuildNeverTicksTheKeyVaultTasks(t *testing.T) {
	assert.GreaterOrEqual(t, kvScheduleEvery, 50*365*24*time.Hour)
	assert.GreaterOrEqual(t, kvAutoDeployEvery, 50*365*24*time.Hour)
}

// Nor does it tick the ACME sweep: the journeys run it with POST /test/scheduler/run.
func TestE2EBuildNeverTicksTheACMESweep(t *testing.T) {
	assert.GreaterOrEqual(t, acmeSweepEvery, 50*365*24*time.Hour)
}

type countingGate struct {
	locked bool
	calls  int
}

func (g *countingGate) Allow(license.Class) error {
	g.calls++
	if g.locked {
		return license.ErrLocked
	}
	return nil
}

// POST /test/scheduler/run runs exactly the named periodic task once, through the license gate.
func TestE2ESchedulerRunRunsTheNamedTask(t *testing.T) {
	runs := 0
	gate := &countingGate{}
	sched := jobs.NewScheduler(clock.Real{}, gate, slog.New(slog.DiscardHandler),
		jobs.Task{Type: jobs.DeploymentRecoverySweep, Every: time.Minute, Run: func(context.Context) error { runs++; return nil }},
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(context.Context) error { return errors.New("smtp down") }})
	h := testHandler(testDeps{Scheduler: sched, Log: slog.New(slog.DiscardHandler)})

	rec := postTest(t, h, "/test/scheduler/run", `{"task":"deployment.recovery_sweep"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"task":"deployment.recovery_sweep"}`, rec.Body.String())
	assert.Equal(t, 1, runs)
	assert.Equal(t, 1, gate.calls, "the run passed the license gate")

	for body, want := range map[string]int{
		`{"task":"license.evaluate"}`: http.StatusNotFound, // a job type, but not a task of this scheduler
		`{"task":"no.such.task"}`:     http.StatusNotFound,
		`{}`:                          http.StatusBadRequest,
		`{"task":"x","extra":true}`:   http.StatusBadRequest,
		`{"task":"notify.send"}`:      http.StatusInternalServerError,
	} {
		rec := postTest(t, h, "/test/scheduler/run", body)
		assert.Equal(t, want, rec.Code, body)
		assert.Contains(t, rec.Body.String(), `"error"`, body)
	}
	gate.locked = true
	assert.Equal(t, http.StatusConflict, postTest(t, h, "/test/scheduler/run", `{"task":"deployment.recovery_sweep"}`).Code)
	assert.Equal(t, 1, runs, "nothing ran while paused")

	assert.Equal(t, http.StatusConflict, postTest(t, testHandler(testDeps{}), "/test/scheduler/run", `{"task":"deployment.recovery_sweep"}`).Code,
		"no scheduler")
}

// A drain claims jobs only during its claim window and lets the last job run until drainBudget,
// which stays below the server's WriteTimeout.
func TestE2EDrainBudgets(t *testing.T) {
	assert.Less(t, drainClaimWindow, drainBudget)
	assert.Less(t, drainBudget, 60*time.Second, "a drain answers before the server's WriteTimeout")
	assert.GreaterOrEqual(t, drainBudget-drainClaimWindow, 30*time.Second, "a deployment claimed last can still verify and record")
}

// fakeRunner runs one job that blocks until its context ends or release is closed, and then has
// nothing more to run.
type fakeRunner struct {
	release   chan struct{}
	started   chan struct{}
	calls     int
	cancelled chan bool // the running job's context ended before release
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{release: make(chan struct{}), started: make(chan struct{}), cancelled: make(chan bool, 1)}
}

func (f *fakeRunner) RunOnce(ctx context.Context) (bool, error) {
	f.calls++
	if f.calls > 1 {
		return false, nil
	}
	close(f.started)
	select {
	case <-ctx.Done():
		f.cancelled <- true
	case <-f.release:
		f.cancelled <- false
	}
	return true, nil
}

func withDrainBudgets(t *testing.T, claim, budget time.Duration) {
	t.Helper()
	savedClaim, savedBudget := drainClaimWindow, drainBudget
	drainClaimWindow, drainBudget = claim, budget
	t.Cleanup(func() { drainClaimWindow, drainBudget = savedClaim, savedBudget })
}

// A client that gives up (Playwright's request timeout) does not cancel the job the drain runs:
// the job keeps its own budget, so a deployment is never cut off by a test's HTTP timeout.
func TestE2EDrainOutlivesTheClient(t *testing.T) {
	withDrainBudgets(t, 5*time.Second, 10*time.Second)
	f := newFakeRunner()
	h := testHandler(testDeps{Runner: f, Log: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/test/jobs/drain", nil)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	<-f.started
	cancel() // the client went away
	time.Sleep(50 * time.Millisecond)
	close(f.release)
	assert.False(t, <-f.cancelled, "the job's context did not end with the request")
	<-done
	assert.JSONEq(t, `{"ran":1}`, rec.Body.String())
}

// A drain whose budget ends while a job still runs says so ("cut_off"), so a test can tell that
// the job was interrupted (a deployment then goes to recovery).
func TestE2EDrainReportsACutOff(t *testing.T) {
	withDrainBudgets(t, 20*time.Millisecond, 50*time.Millisecond)
	f := newFakeRunner()
	rec := postTest(t, testHandler(testDeps{Runner: f, Log: slog.New(slog.DiscardHandler)}), "/test/jobs/drain", ``)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"ran":0,"cut_off":true}`, rec.Body.String())
	assert.True(t, <-f.cancelled)
}

// A second drain while one runs is refused with 409 (a client that timed out and retries must not
// start a drain beside the first one, which may still be recording a cut-off job); once the first
// one ended, draining works again.
func TestE2EDrainRefusesASecondDrain(t *testing.T) {
	withDrainBudgets(t, 5*time.Second, 10*time.Second)
	f := newFakeRunner()
	h := testHandler(testDeps{Runner: f, Log: slog.New(slog.DiscardHandler)})
	first := make(chan *httptest.ResponseRecorder)
	go func() { first <- postTest(t, h, "/test/jobs/drain", ``) }()
	<-f.started
	second := postTest(t, h, "/test/jobs/drain", ``)
	assert.Equal(t, http.StatusConflict, second.Code)
	assert.Contains(t, second.Body.String(), "a drain is already running")
	close(f.release)
	assert.JSONEq(t, `{"ran":1}`, (<-first).Body.String())
	third := postTest(t, h, "/test/jobs/drain", ``)
	assert.Equal(t, http.StatusOK, third.Code)
	assert.JSONEq(t, `{"ran":0}`, third.Body.String())
}

// edgeRunner runs one job that ignores its context and returns after d (a job finishing right at
// the drain's deadline), then has nothing more to run. It keeps the job's context.
type edgeRunner struct {
	d     time.Duration
	calls int
	ctx   context.Context
}

func (e *edgeRunner) RunOnce(ctx context.Context) (bool, error) {
	e.calls++
	if e.calls > 1 {
		return false, nil
	}
	e.ctx = ctx
	time.Sleep(e.d)
	return true, nil
}

// cut_off is exact at the deadline: it is reported exactly when the drain cancelled the context of
// the job while the job ran, and otherwise the job is counted. Jobs finishing right at the
// deadline land on both sides; neither side may be misreported.
func TestE2EDrainCutOffIsExactAtTheDeadline(t *testing.T) {
	const budget = 2 * time.Millisecond
	withDrainBudgets(t, budget, budget)
	var cut, ran int
	for i := 0; i < 200; i++ {
		e := &edgeRunner{d: budget}
		res, err := drainJobs(context.Background(), e)
		require.NoError(t, err)
		cancelled := errors.Is(context.Cause(e.ctx), errDrainBudget)
		require.Equal(t, cancelled, res.CutOff, "run %d: cut_off must say whether the job's context was cancelled while it ran", i)
		require.Equal(t, !cancelled, res.Ran == 1, "run %d: a job not cut off is counted", i)
		if cancelled {
			cut++
		} else {
			ran++
		}
	}
	t.Logf("at the deadline: %d cut off, %d counted", cut, ran)
}

// azureSource is a service principal credential source for the Key Vault provider.
type azureSource struct{}

func (azureSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errors.New("not an SSH credential")
}

func (azureSource) AzureIdentity(context.Context) (providers.AzureIdentity, func(), error) {
	return providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: uuid.NewString(), ClientID: uuid.NewString(),
		ClientSecret: providers.NewSecret([]byte("fake-" + strings.Repeat("0", 40)))}, func() {}, nil
}

// useAzureCAFile points the e2e trust hook at a file for one test.
func useAzureCAFile(t *testing.T, path string) {
	t.Helper()
	old := azureCAFile
	azureCAFile = path
	t.Cleanup(func() { azureCAFile = old })
}

// The e2e build trusts ONLY the fake Azure service's CA for the Azure hosts (R40 row 35, ruling S10):
// the pool holds that one root and no system root, and a certificate of any other CA does not verify.
func TestAzureRootsTrustOnlyTheFakeCA(t *testing.T) {
	now := time.Now()
	fake := pki.NewCA("fake azure", pki.ECDSA256, now)
	other := pki.NewCA("some other CA", pki.ECDSA256, now)
	file := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(file, fake.RootPEM, 0o600))
	useAzureCAFile(t, file)

	pool, err := azureRoots()
	require.NoError(t, err)
	require.NotNil(t, pool)
	want := x509.NewCertPool()
	require.True(t, want.AppendCertsFromPEM(fake.RootPEM))
	assert.True(t, pool.Equal(want), "the pool holds the fake CA and nothing else (no system roots)")

	verify := func(ca *pki.CA) error {
		leaf := ca.Issue(pki.Opts{CommonName: "login.microsoftonline.com", SANs: []string{"login.microsoftonline.com"}}, now)
		inter := x509.NewCertPool()
		inter.AddCert(ca.Intermediate)
		_, err := leaf.Cert.Verify(x509.VerifyOptions{DNSName: "login.microsoftonline.com", Roots: pool, Intermediates: inter, CurrentTime: now.Add(time.Minute)})
		return err
	}
	assert.NoError(t, verify(fake))
	assert.Error(t, verify(other))
}

// A trust file that is missing, empty or not a certificate fails closed: the provider's session
// cannot open (azure.tls_untrusted) and nothing falls back to the system roots. The file is read at
// each session, so a fake service that starts after Alice (or renews its CA) is trusted at once.
func TestAzureRootsFailClosedWithoutTheFakeCA(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	fake := pki.NewCA("fake azure", pki.ECDSA256, now)
	leaf := fake.Issue(pki.Opts{CommonName: "login.microsoftonline.com", SANs: []string{"login.microsoftonline.com"}}, now)
	good := filepath.Join(dir, "good.pem")
	require.NoError(t, os.WriteFile(good, fake.RootPEM, 0o600))
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(good, link))
	sysLink := filepath.Join(dir, "system.pem")
	system := "/etc/ssl/certs/ca-certificates.crt"
	if _, err := os.Stat(system); err != nil {
		system = good // no system bundle on this host: any symlink must still be refused
	}
	require.NoError(t, os.Symlink(system, sysLink))
	write := func(name string, content []byte) string {
		f := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(f, content, 0o600))
		return f
	}
	key := "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n"
	rows := map[string]string{
		"missing":                     filepath.Join(dir, "missing.pem"),
		"a directory":                 dir,
		"empty":                       write("empty.pem", nil),
		"not pem":                     write("notpem.pem", []byte("this is not a certificate")),
		"only a key":                  write("key.pem", []byte(key)),
		"two certificates":            write("two.pem", append(append([]byte{}, fake.RootPEM...), fake.IntermediatePEM...)),
		"the same twice":              write("twice.pem", append(append([]byte{}, fake.RootPEM...), fake.RootPEM...)),
		"a leaf":                      write("leaf.pem", leaf.CertPEM),
		"a certificate and a key":     write("withkey.pem", append(append([]byte{}, fake.RootPEM...), key...)),
		"text before":                 write("before.pem", append([]byte("# the fake CA\n"), fake.RootPEM...)),
		"text after":                  write("after.pem", append(append([]byte{}, fake.RootPEM...), "trailing words\n"...)),
		"megabytes of junk":           write("junk.pem", append(append([]byte{}, fake.RootPEM...), bytes.Repeat([]byte("x"), 2<<20)...)),
		"a symlink":                   link,
		"a link to the system bundle": sysLink,
	}
	reg := providers.NewRegistry()
	pool := newTestPool()
	t.Cleanup(pool.Close)
	registerProviders(reg, pool, slog.New(slog.DiscardHandler))
	kv, ok := reg.Get(providers.KindAzureKV)
	require.True(t, ok)
	target := providers.TargetRef{ID: uuid.New(), Kind: providers.KindAzureKV,
		Config: providers.TargetConfig{"vault_url": "https://alice-e2e.vault.azure.net"}}
	for name, file := range rows {
		useAzureCAFile(t, file)
		roots, err := azureRoots()
		assert.Nil(t, roots, name)
		assert.Error(t, err, name)
		// Through the registered provider: no usable file, no session, no request, no fallback.
		_, err = kv.Open(context.Background(), target, azureSource{}, providers.Env{Clock: clock.Real{}})
		var pe *providers.Error
		if assert.ErrorAs(t, err, &pe, name) {
			assert.Equal(t, "azure.tls_untrusted", pe.Code, name)
		}
	}

	// A single regular CA certificate is accepted, also with blank lines around it; the file is read at
	// each session, so a fake that starts after Alice is trusted at once.
	late := filepath.Join(dir, "late.pem")
	useAzureCAFile(t, late)
	_, err := azureRoots()
	require.Error(t, err)
	require.NoError(t, os.WriteFile(late, append(append([]byte("\n"), fake.RootPEM...), "\n\n"...), 0o600))
	p, err := azureRoots()
	require.NoError(t, err)
	assert.NotNil(t, p)
}

// The fake service sits on the compose network at a private address (a Docker bridge, 172.16.0.0/12 by
// default): the connection rule of the vault transport allows private endpoints, so no dial mapping
// is needed in the e2e build. IMDS (169.254.169.254) is link-local and not reachable in compose:
// managed identity is simply not offered by the e2e stack.
func TestComposeAddressesAreAllowedForTheFake(t *testing.T) {
	for _, a := range []string{"172.18.0.3", "172.31.255.254", "10.0.0.5", "192.168.64.2", "fd00::2"} {
		assert.True(t, netaddr.Allowed(netip.MustParseAddr(a)), a)
	}
	assert.False(t, netaddr.Allowed(netip.MustParseAddr("169.254.169.254")))
}

// Every table a migration creates is emptied by the reset, except master_key_versions (the key file
// on the volume stays). The SSH key rotation tables of migration 00010 reference ssh_keys, targets
// and users, so a reset without them fails on a foreign key (0A000) and every journey after it starts
// on the previous one's data. TestE2EResetCoversEveryTable checks the same against a migrated database.
func TestResetSQLCoversPhase6Tables(t *testing.T) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	create := regexp.MustCompile(`(?m)^CREATE TABLE (\w+)`)
	var tables []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := fs.ReadFile(migrations.FS, e.Name())
		require.NoError(t, err)
		for _, m := range create.FindAllStringSubmatch(string(raw), -1) {
			tables = append(tables, m[1])
		}
	}
	for _, phase6 := range []string{"rotation_policies", "rotations", "rotation_locations", "rotation_op_ids", "rotation_steps"} {
		require.Contains(t, tables, phase6, "migration 00010 creates %s", phase6)
	}
	for _, name := range tables {
		inReset := regexp.MustCompile(`(^|[\s,])` + regexp.QuoteMeta(name) + `([\s,]|$)`).MatchString(strings.TrimPrefix(resetSQL, "TRUNCATE "))
		if name == "master_key_versions" {
			assert.False(t, inReset, "the reset keeps the master key versions")
			continue
		}
		assert.True(t, inReset, "resetSQL empties %s", name)
	}
}

// The rotation tasks never tick on the wall clock in the e2e build either: the journeys run them with
// POST /test/scheduler/run.
func TestE2EBuildNeverTicksTheRotationTasks(t *testing.T) {
	assert.GreaterOrEqual(t, rotationPlanEvery, 50*365*24*time.Hour)
	assert.GreaterOrEqual(t, rotationSweepEvery, 50*365*24*time.Hour)
	assert.GreaterOrEqual(t, destroyRetiredEvery, 50*365*24*time.Hour)
}

// fakeOverlap records the writes of POST /test/rotation/overlap.
type fakeOverlap struct {
	known   uuid.UUID
	err     error
	calls   int
	policy  uuid.UUID
	minutes int
}

func (f *fakeOverlap) set(_ context.Context, policy uuid.UUID, minutes int) (bool, error) {
	f.calls++
	f.policy, f.minutes = policy, minutes
	if f.err != nil {
		return false, f.err
	}
	return policy == f.known, nil
}

// POST /test/rotation/overlap sets a policy's overlap in minutes (the journey's one-minute overlap):
// a strict body, minutes in the schema's range, 404 for an unknown policy, 400 for anything else, and
// nothing is written for a refused request.
func TestRotationOverlapEndpoint(t *testing.T) {
	known := uuid.New()
	f := &fakeOverlap{known: known}
	h := rotationOverlapHandler(f.set, slog.New(slog.DiscardHandler))

	rec := postTest(t, h, "/test/rotation/overlap", `{"policy_id":"`+known.String()+`","minutes":1}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"overlap_minutes":1}`, rec.Body.String())
	assert.Equal(t, known, f.policy)
	assert.Equal(t, 1, f.minutes)

	for _, m := range []string{"0", "129600"} {
		rec := postTest(t, h, "/test/rotation/overlap", `{"policy_id":"`+known.String()+`","minutes":`+m+`}`)
		assert.Equal(t, http.StatusOK, rec.Code, m)
		assert.JSONEq(t, `{"overlap_minutes":`+m+`}`, rec.Body.String())
	}

	rec = postTest(t, h, "/test/rotation/overlap", `{"policy_id":"`+uuid.NewString()+`","minutes":1}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error"`)

	calls := f.calls
	for _, body := range []string{
		``,
		`{}`,
		`not json`,
		`{"policy_id":"` + known.String() + `"}`,
		`{"minutes":1}`,
		`{"policy_id":"not-a-uuid","minutes":1}`,
		`{"policy_id":"00000000-0000-0000-0000-000000000000","minutes":1}`,
		`{"policy_id":"` + known.String() + `","minutes":-1}`,
		`{"policy_id":"` + known.String() + `","minutes":129601}`,
		`{"policy_id":"` + known.String() + `","minutes":1.5}`,
		`{"policy_id":"` + known.String() + `","minutes":"1"}`,
		`{"policy_id":"` + known.String() + `","minutes":1,"rotation_id":"x"}`,
	} {
		rec := postTest(t, h, "/test/rotation/overlap", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, body)
		assert.Contains(t, rec.Body.String(), `"error"`, body)
	}
	assert.Equal(t, calls, f.calls, "a refused request writes nothing")

	f.err = errors.New("database down")
	rec = postTest(t, h, "/test/rotation/overlap", `{"policy_id":"`+known.String()+`","minutes":1}`)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "database down")
}

// The route is served by the e2e test handler (its same-origin guard: TestE2ETestEndpointsRejectCrossSiteRequests)
// and needs the database.
func TestRotationOverlapRouteNeedsTheDatabase(t *testing.T) {
	h := testHandler(testDeps{Log: slog.New(slog.DiscardHandler)})
	rec := postTest(t, h, "/test/rotation/overlap", `{"policy_id":"`+uuid.NewString()+`","minutes":1}`)
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

// The e2e build never ticks the expiry scan: the demo clock would otherwise send expiry notices between two
// Playwright steps. The task stays scheduled (checkWiring, RunNow).
func TestE2EBuildNeverTicksTheAlertScan(t *testing.T) {
	assert.Greater(t, alertsScanEvery, 50*365*24*time.Hour, "journeys run alerts.scan with POST /test/scheduler/run")
}

// POST /test/seed/dashboard seeds C17's data set and answers what the dashboard must show: the body is exactly {},
// 409 without a database, 500 (with no error text of the database) when the seed fails.
func TestSeedDashboardEndpoint(t *testing.T) {
	answer := seed.DashboardAnswer{Certificates: map[string]int{"monitored": 8}}
	h := seedDashboardHandler(func(context.Context) (seed.DashboardAnswer, error) { return answer, nil }, slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{}`))
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"certificates":{"monitored":8},"targets":null,"deployments":null,"expiring_30":null,"server_filter":null}`, rec.Body.String())
	h = seedDashboardHandler(func(context.Context) (seed.DashboardAnswer, error) { return seed.DashboardAnswer{}, errNoTestDatabase },
		slog.New(slog.DiscardHandler))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusConflict, rec.Code)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{"x":1}`)))
	assert.Equal(t, http.StatusBadRequest, rec.Code, "the body is exactly {}")

	h = seedDashboardHandler(func(context.Context) (seed.DashboardAnswer, error) {
		return seed.DashboardAnswer{}, errors.New("duplicate key value violates unique constraint")
	}, slog.New(slog.DiscardHandler))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "duplicate key")
}

// The route is served by the e2e test handler and needs the database.
func TestSeedDashboardRouteNeedsTheDatabase(t *testing.T) {
	h := testHandler(testDeps{Log: slog.New(slog.DiscardHandler)})
	rec := postTest(t, h, "/test/seed/dashboard", `{}`)
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

// The e2e build's mail settings fall back to the test mailbox while no SMTP server is configured (the release build
// has none: services_test.go), and dial like the release build, through netaddr (no override in any build).
func TestE2EMailSettingsFallBackToTheMailbox(t *testing.T) {
	cfg := notifySettingsConfig(nil, &services{}, nil, e2eClock, slog.New(slog.DiscardHandler))
	assert.Same(t, e2eMailbox, cfg.Fallback)
	assert.Nil(t, cfg.Dial)
}

// A reset installation serves Alice's temporary HTTPS certificate again: a journey that uploads its own certificate
// (Phase 8 wizard and Settings → HTTPS certificate) must not leave it for the next one, which expects the temporary
// state. The pair on disk and the served pair both change; a temporary certificate is left as it is.
func TestResetRestoresTheTemporaryCertificate(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost", "127.0.0.1"}
	now := time.Now()
	store, err := tlscert.NewStore(dir, hosts, time.Now)
	require.NoError(t, err)
	require.True(t, store.Info().Temporary)
	temporary := store.Info().FingerprintSHA256

	require.NoError(t, resetTemporaryCertificate(store, dir, hosts, now))
	assert.Equal(t, temporary, store.Info().FingerprintSHA256, "a temporary certificate is kept")

	leaf := pki.SelfSigned("localhost", pki.ECDSA256, now)
	info, err := store.Install(tlscert.Upload{CertPEM: leaf.CertPEM, KeyPEM: leaf.KeyPEM})
	require.NoError(t, err)
	require.False(t, store.Info().Temporary)

	require.NoError(t, resetTemporaryCertificate(store, dir, hosts, now))
	got := store.Info()
	assert.True(t, got.Temporary, "the store serves a temporary certificate again")
	assert.NotEqual(t, info.FingerprintSHA256, got.FingerprintSHA256)
	served, err := store.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, got.FingerprintSHA256, fmt.Sprintf("%x", sha256.Sum256(served.Certificate[0])))
	// The pair on disk is the temporary one too: a restart keeps serving it.
	again, err := tlscert.NewStore(dir, hosts, time.Now)
	require.NoError(t, err)
	assert.True(t, again.Info().Temporary)
	assert.Equal(t, got.FingerprintSHA256, again.Info().FingerprintSHA256)
	// The replaced customer pair is not left behind.
	for _, name := range []string{"tls.crt.prev", "tls.key.prev", "tls.crt.new", "tls.key.new"} {
		assert.NoFileExists(t, filepath.Join(dir, name))
	}

	// Without a store (a unit test's dependencies) the reset does nothing.
	require.NoError(t, resetTemporaryCertificate(nil, dir, hosts, now))
}

// The ACME hook reads the fake ACME CA's file by the same rules as the Azure one: only that CA is
// trusted, never the system roots, and anything but one regular file with one CA certificate fails closed.
func TestACMERootsTrustOnlyTheFakeCAAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	fake := pki.NewCA("fake acme", pki.ECDSA256, now)
	other := pki.NewCA("some other CA", pki.ECDSA256, now)
	use := func(path string) {
		old := acmeCAFile
		acmeCAFile = path
		t.Cleanup(func() { acmeCAFile = old })
	}
	good := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(good, fake.RootPEM, 0o600))
	use(good)
	pool, err := acmeRoots()
	require.NoError(t, err)
	want := x509.NewCertPool()
	require.True(t, want.AppendCertsFromPEM(fake.RootPEM))
	assert.True(t, pool.Equal(want), "the pool holds the fake CA and nothing else (no system roots)")
	leaf := other.Issue(pki.Opts{CommonName: "acme.test.alice", SANs: []string{"acme.test.alice"}}, now)
	inter := x509.NewCertPool()
	inter.AddCert(other.Intermediate)
	_, err = leaf.Cert.Verify(x509.VerifyOptions{DNSName: "acme.test.alice", Roots: pool, Intermediates: inter, CurrentTime: now.Add(time.Minute)})
	assert.Error(t, err, "another CA's certificate does not verify")

	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(good, link))
	two := filepath.Join(dir, "two.pem")
	require.NoError(t, os.WriteFile(two, append(append([]byte{}, fake.RootPEM...), other.RootPEM...), 0o600))
	leafFile := filepath.Join(dir, "leaf.pem")
	require.NoError(t, os.WriteFile(leafFile, leaf.CertPEM, 0o600))
	big := filepath.Join(dir, "big.pem")
	require.NoError(t, os.WriteFile(big, append(append([]byte{}, fake.RootPEM...), bytes.Repeat([]byte("x"), 2<<20)...), 0o600))
	for name, file := range map[string]string{"missing": filepath.Join(dir, "missing.pem"), "a directory": dir, "a symlink": link,
		"two certificates": two, "a leaf": leafFile, "too large": big} {
		use(file)
		roots, err := acmeRoots()
		assert.Nil(t, roots, name)
		assert.ErrorContains(t, err, "fake ACME CA", name)
	}
}

// GET /test/acme/ca answers whether the e2e build trusts the fake ACME CA yet, without revealing anything.
func TestTestAPIACMECATrustProbe(t *testing.T) {
	old := acmeCAFile
	t.Cleanup(func() { acmeCAFile = old })
	h := testHandler(testDeps{})
	ask := func() (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/acme/ca", nil))
		return rec.Code, strings.TrimSpace(rec.Body.String())
	}
	acmeCAFile = filepath.Join(t.TempDir(), "missing.pem")
	code, body := ask()
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.JSONEq(t, `{"trusted":false}`, body)
	file := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(file, pki.NewCA("fake acme", pki.ECDSA256, time.Now()).RootPEM, 0o600))
	acmeCAFile = file
	code, body = ask()
	assert.Equal(t, http.StatusOK, code)
	assert.JSONEq(t, `{"trusted":true}`, body)
}
