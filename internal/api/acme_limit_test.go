package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

// A5: limitACME is 10 a minute for an order or a test run, keyed like limitExport: per user for a browser session
// ("u:"), per token for an API token ("t:"), each identity on its own, so neither can drain the other's budget.
func TestACMELimitIsPerUserAndPerToken(t *testing.T) {
	for _, c := range []struct{ name, caller, other string }{
		{"session", "operator", "admin"},
		{"token", "alice_operate_operator", "alice_operate_admin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := guardedHandler(t, testDeps(t, nil), rbac.AcmeOperate, limitACME)
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

// The bucket is the ACME class's own: the 5-a-minute action buckets and the export bucket are not spent by it.
func TestACMELimitHasABucketOfItsOwn(t *testing.T) {
	d := testDeps(t, nil)
	s := newServer(d)
	assert.NotSame(t, s.actions[limitACME], s.actions[limitBackupNow])
	assert.NotSame(t, s.actions[limitACME], s.export)
	require.NotNil(t, s.actions[limitACME])
	s.actions[limitACME].Allow("u:x")
	(&Server{s: s}).ResetLimits()
	for range 10 {
		ok, _ := s.actions[limitACME].Allow("u:x")
		require.True(t, ok, "ResetLimits clears the ACME bucket")
	}
}
