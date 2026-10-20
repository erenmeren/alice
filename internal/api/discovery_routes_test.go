package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/license"
	"alice/internal/rbac"
)

// discoveryRouteTable is the network discovery route table written out by hand (Task 9; D1, D7, A3, A5): permission,
// licence class and rate class of every route. The table in discovery_handlers.go must equal it.
var discoveryRouteTable = map[string]struct {
	perm  rbac.Permission
	lic   license.Class
	limit limitClass
}{
	"GET /api/v1/discovery/summary":                    {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"GET /api/v1/discovery/scopes":                     {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"POST /api/v1/discovery/scopes":                    {rbac.DiscoveryManage, license.ClassAlways, limitDiscoveryResolve},
	"POST /api/v1/discovery/scopes/preview":            {rbac.DiscoveryManage, license.ClassAlways, limitDiscoveryPreview},
	"GET /api/v1/discovery/scopes/{id}":                {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"PATCH /api/v1/discovery/scopes/{id}":              {rbac.DiscoveryManage, license.ClassAlways, limitDiscoveryResolve},
	"DELETE /api/v1/discovery/scopes/{id}":             {rbac.DiscoveryManage, license.ClassAlways, limitDefault},
	"POST /api/v1/discovery/scopes/{id}/scans":         {rbac.DiscoveryOperate, license.ClassReadOnly, limitDiscovery},
	"GET /api/v1/discovery/scans":                      {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"GET /api/v1/discovery/scans/{id}":                 {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"POST /api/v1/discovery/scans/{id}/cancel":         {rbac.DiscoveryOperate, license.ClassAlways, limitDiscovery},
	"GET /api/v1/discovery/certificates":               {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"GET /api/v1/discovery/certificates/export":        {rbac.DiscoveryView, license.ClassUnset, limitExport},
	"GET /api/v1/discovery/certificates/{fingerprint}": {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"GET /api/v1/discovery/endpoints":                  {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"GET /api/v1/discovery/settings":                   {rbac.DiscoveryView, license.ClassUnset, limitDefault},
	"PUT /api/v1/discovery/settings":                   {rbac.DiscoveryManage, license.ClassAlways, limitDefault},
}

func TestDiscoveryRouteTable(t *testing.T) {
	seen := 0
	for _, rt := range newServer(Deps{}).apiRoutes() {
		if !under(rt.pattern, "/api/v1/discovery") {
			continue
		}
		key := rt.method + " " + rt.pattern
		want, ok := discoveryRouteTable[key]
		if !assert.True(t, ok, "unexpected discovery route %s", key) {
			continue
		}
		seen++
		assert.Equal(t, want.perm, rt.perm, key)
		assert.Equal(t, want.lic, rt.lic, key)
		assert.Equal(t, want.limit, rt.limit, key)
		assert.Equal(t, key == "GET /api/v1/discovery/certificates/export", rt.getOnly, "only the audited export refuses HEAD: %s", key)
	}
	assert.Equal(t, len(discoveryRouteTable), seen)
}

// discoveryLimitViolations are the route-table rules of the discovery rate classes (carries of Tasks 4 and 5):
// limitDiscoveryResolve (the save-time look-up of a listed name) only on discovery.manage routes; limitDiscovery only on
// discovery.operate routes; the scope preview has a limiter; the discovery export is limitExport.
func discoveryLimitViolations(routes []route) []string {
	var out []string
	for _, rt := range routes {
		key := rt.method + " " + rt.pattern
		switch {
		case rt.limit == limitDiscoveryResolve && rt.perm != rbac.DiscoveryManage:
			out = append(out, key+": limitDiscoveryResolve only on discovery.manage routes")
		case rt.limit == limitDiscoveryPreview && (rt.perm != rbac.DiscoveryManage || !strings.HasSuffix(rt.pattern, "/discovery/scopes/preview")):
			out = append(out, key+": limitDiscoveryPreview only on the discovery.manage scope preview")
		case strings.HasSuffix(rt.pattern, "/discovery/scopes/preview") && rt.limit != limitDiscoveryPreview:
			out = append(out, key+": the scope preview has its own limiter (limitDiscoveryPreview)")
		case rt.limit == limitDiscovery && rt.perm != rbac.DiscoveryOperate:
			out = append(out, key+": limitDiscovery only on discovery.operate routes")
		case strings.HasSuffix(rt.pattern, "/discovery/certificates/export") && (rt.limit != limitExport || !rt.getOnly):
			out = append(out, key+": the discovery export is limitExport and GET only")
		case under(rt.pattern, "/api/v1/discovery") && rt.perm == rbac.DiscoveryOperate && rt.limit != limitDiscovery:
			out = append(out, key+": starting and cancelling scans is limitDiscovery")
		}
	}
	return out
}

func TestDiscoveryLimitsFollowTheirPermissions(t *testing.T) {
	routes := newServer(Deps{}).apiRoutes()
	assert.Empty(t, discoveryLimitViolations(routes))
	n, p := 0, 0
	for _, rt := range routes {
		switch rt.limit {
		case limitDiscoveryResolve:
			n++
		case limitDiscoveryPreview:
			p++
		}
	}
	assert.Equal(t, 2, n, "create and change of a scope (the name look-ups)")
	assert.Equal(t, 1, p, "the scope preview only")
}

func TestDiscoveryLimitViolationsCatchMistakes(t *testing.T) {
	bad := []route{
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/{id}/scans", scope: scopeAny, perm: rbac.DiscoveryOperate, limit: limitDiscoveryResolve},
		{method: http.MethodGet, pattern: "/api/v1/discovery/certificates", scope: scopeAny, perm: rbac.DiscoveryView, limit: limitDiscoveryResolve},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes", scope: scopeAny, perm: rbac.DiscoveryManage, limit: limitDiscovery},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/preview", scope: scopeAny, perm: rbac.DiscoveryManage},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/preview", scope: scopeAny, perm: rbac.DiscoveryManage, limit: limitDiscoveryResolve},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes", scope: scopeAny, perm: rbac.DiscoveryManage, limit: limitDiscoveryPreview},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scopes/preview", scope: scopeAny, perm: rbac.DiscoveryOperate, limit: limitDiscoveryPreview},
		{method: http.MethodGet, pattern: "/api/v1/discovery/certificates/export", scope: scopeAny, perm: rbac.DiscoveryView, getOnly: true},
		{method: http.MethodGet, pattern: "/api/v1/discovery/certificates/export", scope: scopeAny, perm: rbac.DiscoveryView, limit: limitExport},
		{method: http.MethodPost, pattern: "/api/v1/discovery/scans/{id}/cancel", scope: scopeAny, perm: rbac.DiscoveryOperate},
	}
	for _, rt := range bad {
		assert.Len(t, discoveryLimitViolations([]route{rt}), 1, fmt.Sprintf("%+v", rt))
	}
}

// Every discovery route through the real guard as every matrix identity: the hand-written matrix holds (D7: read tokens
// never read the network map; manage is a stepped-up Administrator, never a token), denials are audited, and nothing
// reaches the handler unless allowed (TestAuthzMatrix covers the whole table; this pins the discovery part by name).
func TestDiscoveryRoutesAsEveryIdentity(t *testing.T) {
	want := map[rbac.Permission]map[string]int{}
	for p := range map[rbac.Permission]bool{rbac.DiscoveryView: true, rbac.DiscoveryOperate: true, rbac.DiscoveryManage: true} {
		want[p] = expectedMatrix[p]
	}
	assert.Equal(t, forb, want[rbac.DiscoveryView]["alice_read_admin"], "D7")
	assert.Equal(t, forb, want[rbac.DiscoveryView]["alice_read_auditor"], "D7")
	assert.Equal(t, allw, want[rbac.DiscoveryView]["alice_operate_operator"])
	assert.Equal(t, allw, want[rbac.DiscoveryView]["auditor"])
	assert.Equal(t, forb, want[rbac.DiscoveryOperate]["auditor"])
	assert.Equal(t, forb, want[rbac.DiscoveryManage]["alice_operate_admin"], "manage never a token")
	assert.Equal(t, step, want[rbac.DiscoveryManage]["admin"])
	assert.Equal(t, forb, want[rbac.DiscoveryManage]["operator-stepup"], "D1: Operators do not define scopes")
}
