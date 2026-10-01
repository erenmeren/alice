//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/notify"
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
