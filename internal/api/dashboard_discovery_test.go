package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery/discoverysvc"
	"alice/internal/reports"
)

// Decision D2: the Overview carries a separate quiet metric, the unmanaged certificates found on the network that expire
// within 30 days, from the discovery summary (Task 9's query); only when a scope exists, never inside the managed
// counts, and only for a caller with DiscoveryView (D7: a read-scope API token does not get it, nor the discovery
// summary is read for it).
func TestDashboardDiscoveryMetric(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	fd := &fakeDiscovery{}
	d.Discovery = fd
	fr.SummaryFn = func(context.Context, reports.Viewer) (reports.Summary, error) {
		return reports.Summary{GeneratedAt: testNow, Certificates: alertsCounts()}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	summary := discoverysvc.Summary{UnmanagedTotal: 9, UnmanagedExpiring30d: 3, Scopes: 2}
	fd.SummaryFn = func(context.Context) (discoverysvc.Summary, error) { return summary, nil }
	body := func(id string) map[string]json.RawMessage {
		t.Helper()
		rec := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", id, "", nil)
		require.Equal(t, http.StatusOK, rec.Code, id+": "+rec.Body.String())
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
		return m
	}
	managed := `{"monitored":10,"expired":1,"within_7":2,"within_30":3,"within_60":4,"kv_expired":5,"kv_within_30":6}`
	for _, id := range []string{"admin", "operator", "auditor", "alice_operate_operator", "alice_operate_admin"} {
		m := body(id)
		assert.JSONEq(t, `{"unmanaged_expiring_30d":3}`, string(m["discovery"]), id)
		assert.JSONEq(t, managed, string(m["certificates"]), "%s: the managed counts are not mixed with it", id)
	}
	before := fd.calls()
	for _, id := range []string{"alice_read_admin", "alice_read_auditor"} {
		m := body(id)
		assert.NotContains(t, m, "discovery", "%s: D7, the network map is not for read tokens", id)
		assert.JSONEq(t, managed, string(m["certificates"]), id)
	}
	assert.Equal(t, before, fd.calls(), "the discovery summary is not read for a caller without DiscoveryView")

	// No scope: the metric is absent, and the answer is the one of a build without discovery, byte for byte.
	summary = discoverysvc.Summary{}
	withoutScope := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "admin", "", nil).Body.String()
	assert.NotContains(t, withoutScope, "discovery")
	d.Discovery = nil
	s2 := newServer(d)
	bare := callWith(s2.handler(s2.apiRoutes()), http.MethodGet, "/api/v1/dashboard/summary", "admin", "", nil)
	require.Equal(t, http.StatusOK, bare.Code)
	assert.Equal(t, bare.Body.String(), withoutScope)

	// A discovery read that fails fails the Overview like its other sections (never a silent 0).
	fd.SummaryFn = func(context.Context) (discoverysvc.Summary, error) { return discoverysvc.Summary{}, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "admin", "", nil).Code)
}
