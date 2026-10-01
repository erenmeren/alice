//go:build !e2e

package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/api"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/locales"
)

// The demo clock and /test endpoints must never exist in a release build.
func TestReleaseBuildHasNoTestEndpointsOrDemoClock(t *testing.T) {
	assert.Nil(t, testHandler(testDeps{}))
	_, isReal := newClock().(clock.Real)
	assert.True(t, isReal, "release builds use the wall clock")
}

// Wired the way serve wires it, a release server answers every /test/ path
// with the JSON 404 of the API, never a test endpoint or the SPA.
func TestReleaseServerAnswersTestPathsWithJSON404(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	h := api.New(api.Deps{
		Catalog:     cat,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:       newClock(),
		TestHandler: testHandler(testDeps{}),
	}).Handler()
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/test/clock", nil),
		httptest.NewRequest(http.MethodPost, "/test/reset", nil),
		httptest.NewRequest(http.MethodPost, "/test/setup-token", nil),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, req.URL.Path)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json", req.URL.Path)
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), req.URL.Path)
		assert.Equal(t, "ALC-SYS-0001", body.Error.Code, req.URL.Path)
	}
}

// The release build runs the job workers; only the e2e build drives jobs through /test/jobs/drain.
func TestReleaseBuildStartsJobWorkers(t *testing.T) {
	assert.True(t, startJobWorkers)
}
