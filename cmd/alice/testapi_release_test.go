//go:build !e2e

package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
		httptest.NewRequest(http.MethodPost, "/test/rotation/overlap", strings.NewReader(`{"policy_id":"00000000-0000-0000-0000-000000000001","minutes":1}`)),
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

// S-10: the release server serves no debug or metrics endpoint. API paths answer the JSON 404; other paths
// are the web application's (the SPA shell, never profile, variable or metric data). internal/archtest
// TestS10ReleaseLinksNoDebugOrMetricsEndpoints proves no build links pprof, expvar or a metrics library.
func TestS10ReleaseServerHasNoDebugOrMetricsEndpoints(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	h := api.New(api.Deps{
		Catalog:     cat,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:       newClock(),
		TestHandler: testHandler(testDeps{}),
	}).Handler()
	for _, p := range []string{"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=2", "/debug/vars",
		"/metrics", "/api/v1/metrics", "/api/v1/debug/pprof/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		body := rec.Body.String()
		for _, marker := range []string{"Types of profiles available", "goroutine profile", "cmdline", "memstats", "# TYPE", "# HELP"} {
			assert.NotContains(t, body, marker, p)
		}
		if strings.HasPrefix(p, "/api/") {
			assert.Equal(t, http.StatusNotFound, rec.Code, p)
		} else {
			assert.NotEqual(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"), p)
		}
	}
}

// The release build runs the job workers; only the e2e build drives jobs through /test/jobs/drain.
func TestReleaseBuildStartsJobWorkers(t *testing.T) {
	assert.True(t, startJobWorkers)
}

// A release build verifies Azure's certificates with the system roots: no root function result, no
// file read, so no fake service can be trusted by it.
func TestReleaseAzureRootsAreTheSystemRoots(t *testing.T) {
	pool, err := azureRoots()
	require.NoError(t, err)
	assert.Nil(t, pool, "a nil pool means the system roots")
}

// The release build has no rotation test endpoint: the e2e-only POST /test/rotation/overlap lives in a
// file that requires the e2e tag (its handler symbol is in E2E_SYMBOLS, so make release-symcheck fails
// if a release binary ever links it), and the release test handler is nil, so the API answers the
// path with its JSON 404 (TestReleaseServerAnswersTestPathsWithJSON404).
func TestReleaseHasNoRotationTestEndpoint(t *testing.T) {
	assert.Nil(t, testHandler(testDeps{}))
}
