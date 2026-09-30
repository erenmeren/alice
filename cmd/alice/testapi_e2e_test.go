//go:build e2e

package main

import (
	"encoding/json"
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

func TestE2EClockRejectsNegativeOrMalformedInput(t *testing.T) {
	h := testHandler(testDeps{})
	for _, body := range []string{`{"advance_seconds":-5}`, `not json`} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/clock", strings.NewReader(body)))
		assert.Equal(t, http.StatusBadRequest, rec.Code, body)
	}
}

func TestE2EUnknownTestEndpointIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/nope", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
