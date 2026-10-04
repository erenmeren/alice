//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
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
	require.Equal(t, 0, run([]string{"version"}, env(nil), &out, &errOut))
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
		for _, path := range []string{"/test/clock", "/test/reset", "/test/setup-token", "/test/license/tamper", "/test/jobs/drain"} {
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
