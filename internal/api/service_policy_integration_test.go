//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz/services"
)

// Service policy (R55, design §12 Phase 5, SR-31, SR-32): an Administrator of service B changes B's policy with step-up
// except its domains (403 ALC-SVC-0011), which a global Administrator changes; a stale version is 409 ALC-SVC-0010; a
// reserved key 422 ALC-SVC-0015; the history lists every version with its author; the audit row names the changed
// keys; an action outside the policy is refused with its code before anything is stored.
func TestServicePolicyThroughTheAPI(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	ctx := context.Background()
	b, err := s.serviceStore.CreateService(ctx, sysActor, services.ServiceInput{Name: "Bravo"})
	require.NoError(t, err)
	path := "/api/v1/services/" + b.ID.String() + "/policy"

	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPut, path, map[string]any{"version": 1, "body": map[string]any{"schema": 1,
		"domains": []string{"*.bravo.example.test"}, "certificate_sources": []string{"csr", "uploaded"}}})
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, 2, decodeBody[map[string]any](t, rec)["version"])

	admB := s.createScopedPerson(admin, adminAcct, "admb", "admin", b.ID)
	c := s.freshClient()
	s.firstSignIn(c, admB)
	s.stepUp(c, admB)
	requireError(t, c.do(http.MethodPut, path, map[string]any{"version": 2, "body": map[string]any{"schema": 1,
		"domains": []string{"*.example.test"}}}), http.StatusForbidden, ErrSVCDomainsGlobalOnly.Code)
	rec = c.do(http.MethodPut, path, map[string]any{"version": 2, "body": map[string]any{"schema": 1,
		"domains": []string{"*.bravo.example.test"}, "certificate_sources": []string{"csr", "uploaded"}, "incident": map[string]any{"revoke_mode": "now"}}})
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, 3, decodeBody[map[string]any](t, rec)["version"], "the service's Administrator changes the other fields")
	requireError(t, c.do(http.MethodPut, path, map[string]any{"version": 2, "body": map[string]any{"schema": 1}}),
		http.StatusConflict, ErrSVCVersionConflict.Code)
	requireError(t, c.do(http.MethodPut, path, map[string]any{"version": 3, "body": map[string]any{"schema": 1, "drift": map[string]any{}}}),
		http.StatusUnprocessableEntity, ErrSVCPolicyFieldUnavailable.Code)
	requireError(t, c.do(http.MethodPut, path, map[string]any{"version": 3, "body": map[string]any{"schema": 1, "nope": 1}}),
		http.StatusBadRequest, ErrBadRequest.Code)

	rec = c.do(http.MethodGet, path+"/versions", nil)
	requireStatus(t, rec, http.StatusOK)
	versions := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items
	require.Len(t, versions, 3)
	assert.Equal(t, "User admb", versions[0]["created_by_name"])
	assert.Equal(t, "Ada Admin", versions[1]["created_by_name"])
	var fields string
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT details->>'fields' FROM audit_log WHERE action = 'service.policy_changed'
ORDER BY seq DESC LIMIT 1`).Scan(&fields))
	assert.Equal(t, "incident", fields)

	// Enforcement: a signing request outside the domains is refused with the name and the field, nothing stored.
	rec = c.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "shop.example.test", "key_type": "ecdsa-p256",
		"service_id": b.ID})
	requireError(t, rec, http.StatusUnprocessableEntity, ErrSVCDomainNotAllowed.Code)
	e := decodeBody[struct {
		Error struct {
			Params  map[string]string `json:"params"`
			Details []struct {
				Field string `json:"field"`
			} `json:"details"`
		} `json:"error"`
	}](t, rec)
	assert.Equal(t, "shop.example.test", e.Error.Params["name"])
	require.Len(t, e.Error.Details, 1)
	assert.Equal(t, "common_name", e.Error.Details[0].Field)
	var n int
	require.NoError(t, s.db.Owner.QueryRow(ctx, "SELECT count(*) FROM csr_requests WHERE service_id = $1", b.ID).Scan(&n))
	assert.Zero(t, n)
	rec = c.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "api.bravo.example.test", "key_type": "ecdsa-p256",
		"service_id": b.ID})
	requireStatus(t, rec, http.StatusCreated)

	// The source: ACME certificates are not among B's sources (the service is checked first, the policy before the
	// references).
	rec = c.do(http.MethodPost, "/api/v1/acme/certificates", map[string]any{"provider_id": b.ID, "names": []string{"x.bravo.example.test"},
		"challenge": "dns01", "hook_id": b.ID, "service_id": b.ID})
	requireError(t, rec, http.StatusUnprocessableEntity, ErrSVCSourceNotAllowed.Code)
}
