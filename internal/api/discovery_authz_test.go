package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/rbac"
)

// The network discovery permissions have no route before Task 9, so TestAuthzMatrix cannot check their hand-written
// rows yet. This sends a request through the real guard (session, step-up, token scope) as every matrix identity, so a
// wrong policy fails now and not only when the routes arrive (A5, D7).
func TestDiscoveryPermissionsThroughTheGuard(t *testing.T) {
	for _, p := range []rbac.Permission{rbac.DiscoveryView, rbac.DiscoveryOperate, rbac.DiscoveryManage} {
		want, ok := expectedMatrix[p]
		if !assert.True(t, ok, "expectedMatrix lacks %q", p) {
			continue
		}
		h, s := guardedHandler(t, testDeps(t, nil), p, limitDefault)
		for _, id := range identities {
			(&Server{s: s}).ResetLimits()
			rec := call(h, http.MethodGet, "/api/v1/probe", id, "")
			name := fmt.Sprintf("%s as %q", p, id)
			switch w := want[id]; w {
			case step:
				assert.Equal(t, http.StatusForbidden, rec.Code, name)
				assert.Equal(t, "auth.stepup_required", decodeErr(t, rec).Error.Reason, name)
			default:
				assert.Equal(t, w, rec.Code, name)
			}
		}
	}
}

// D7 in one line each: a read token (any role) never reads the network map; an operate token does.
func TestReadTokensDoNotReadTheNetworkMap(t *testing.T) {
	h, _ := guardedHandler(t, testDeps(t, nil), rbac.DiscoveryView, limitDefault)
	for _, id := range []string{"alice_read_admin", "alice_read_auditor"} {
		assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/probe", id, "").Code, id)
	}
	for _, id := range []string{"alice_operate_admin", "alice_operate_operator"} {
		assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/probe", id, "").Code, id)
	}
}
