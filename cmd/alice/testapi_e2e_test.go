//go:build e2e

package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		`not json`:                      http.StatusBadRequest,
		big:                             http.StatusRequestEntityTooLarge,
		`{"advance_seconds":-5}`:        http.StatusUnprocessableEntity,
		`{"advance_seconds":1e300}`:     http.StatusUnprocessableEntity,
		`{"advance_seconds":315360001}`: http.StatusUnprocessableEntity, // just over 10 years (365-day years)
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
}

func TestE2EUnknownTestEndpointIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/nope", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
