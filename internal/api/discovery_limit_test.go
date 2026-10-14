package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

// limitDiscovery (plan contract): starting and cancelling scans is 10 a minute, keyed like limitACME: per user for a
// browser session ("u:"), per token for an API token ("t:"), each identity on its own.
func TestDiscoveryLimitIsPerUserAndPerToken(t *testing.T) {
	for _, c := range []struct{ name, caller, other string }{
		{"session", "operator", "admin"},
		{"token", "alice_operate_operator", "alice_operate_admin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := guardedHandler(t, testDeps(t, nil), rbac.DiscoveryOperate, limitDiscovery)
			for i := range 10 {
				require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", c.caller, "").Code, "request %d", i+1)
			}
			rec := call(h, http.MethodGet, "/api/v1/probe", c.caller, "")
			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "the 11th request in a minute")
			assert.NotEmpty(t, rec.Header().Get("Retry-After"))
			assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", c.other, "").Code, "another identity has its own budget")
		})
	}
}

// Start and cancel share one budget: every route of the class spends the same per-identity bucket, so alternating
// start and cancel does not double the rate.
func TestDiscoveryLimitIsSharedAcrossTheDiscoveryActions(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.DiscoveryOperate, limitDiscovery)
	for i := range 10 {
		method := http.MethodGet
		if i%2 == 1 {
			method = http.MethodPost
		}
		require.Less(t, call(h, method, "/api/v1/probe", "operator", "").Code, 300, "request %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodPost, "/api/v1/probe", "operator", "").Code)
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodGet, "/api/v1/probe", "operator", "").Code)
}

// limitDiscoveryResolve (A3): the save-time check that a listed name resolves (ALC-DSC-0010) asks the system resolver,
// so it has a bucket of its own: 30 a minute per user or token.
func TestDiscoveryResolveLimitIs30PerIdentity(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.Session, limitDiscoveryResolve)
	for i := range 30 {
		require.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "admin", "").Code, "request %d", i+1)
	}
	rec := call(h, http.MethodGet, "/api/v1/probe", "admin", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "the 31st resolution in a minute")
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", "operator", "").Code, "another identity has its own budget")
}

// Each class has a bucket of its own: discovery never spends the ACME, export or Phase 8 action budgets, the resolve
// check never spends the start/cancel budget, and ResetLimits clears both.
func TestDiscoveryLimitsHaveBucketsOfTheirOwn(t *testing.T) {
	s := newServer(testDeps(t, nil))
	disc, resolve := s.actions[limitDiscovery], s.actions[limitDiscoveryResolve]
	require.NotNil(t, disc)
	require.NotNil(t, resolve)
	for _, other := range []limitClass{limitACME, limitBackupNow, limitHTTPSUpload, limitForwardTest} {
		assert.NotSame(t, disc, s.actions[other])
		assert.NotSame(t, resolve, s.actions[other])
	}
	assert.NotSame(t, disc, resolve)
	assert.NotSame(t, disc, s.export)
	for range 10 {
		disc.Allow("u:x")
	}
	for range 30 {
		resolve.Allow("u:x")
	}
	(&Server{s: s}).ResetLimits()
	for range 10 {
		ok, _ := disc.Allow("u:x")
		require.True(t, ok, "ResetLimits clears the discovery bucket")
	}
	for range 30 {
		ok, _ := resolve.Allow("u:x")
		require.True(t, ok, "ResetLimits clears the resolve bucket")
	}
}
