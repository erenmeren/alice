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

// Owners (R56, design §7.1, §12 Phase 4, SR-28, SR-29): a global Administrator replaces a service's owners with step-up
// and the service's version; a service's own Administrator and a token cannot; everyone who sees the service reads its
// owners, only a reader of people learns whether a role reaches the service; an automation account is refused; a stale
// version is 409.
func TestServiceOwnersThroughTheAPI(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	ctx := context.Background()
	b, err := s.serviceStore.CreateService(ctx, sysActor, services.ServiceInput{Name: "Bravo"})
	require.NoError(t, err)
	path := "/api/v1/services/" + b.ID.String() + "/owners"

	admB := s.createScopedPerson(admin, adminAcct, "admb", "admin", b.ID)
	c := s.freshClient()
	s.firstSignIn(c, admB)
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/automation-accounts", map[string]any{"username": "deployer", "display_name": "Deployer"})
	requireStatus(t, rec, http.StatusCreated)
	robot := decodeBody[map[string]any](t, rec)["id"].(string)

	rec = admin.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	version := got["version"]
	assert.Empty(t, got["items"])

	requireError(t, admin.do(http.MethodPut, path, map[string]any{"version": version, "owners": []map[string]any{{"user_id": robot}}}),
		http.StatusUnprocessableEntity, ErrSVCOwnerNotAPerson.Code)
	rec = admin.do(http.MethodPut, path, map[string]any{"version": version, "owners": []map[string]any{{"user_id": admB.id}, {"user_id": adminAcct.id}}})
	requireStatus(t, rec, http.StatusOK)
	got = decodeBody[map[string]any](t, rec)
	require.Len(t, got["items"], 2)
	assert.NotEqual(t, version, got["version"], "a change raises the service's version")
	requireError(t, admin.do(http.MethodPut, path, map[string]any{"version": version, "owners": []map[string]any{}}),
		http.StatusConflict, ErrSVCVersionConflict.Code)
	var n int
	require.NoError(t, s.db.Owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'service.owners_changed'").Scan(&n))
	assert.Equal(t, 1, n)

	// The service's own Administrator reads them (without who holds a role) and cannot change them (a platform act).
	s.stepUp(c, admB)
	rec = c.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, rec.Body.String(), "reaches_service")
	assert.Contains(t, rec.Body.String(), `"username":"admb"`)
	requireError(t, c.do(http.MethodPut, path, map[string]any{"version": got["version"], "owners": []map[string]any{}}),
		http.StatusForbidden, ErrForbidden.Code)
	// A token never changes them.
	rec = admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "ci", "scope": "operate", "expires_in_days": 30})
	requireStatus(t, rec, http.StatusCreated)
	tok := s.freshClient()
	tok.bearer = decodeBody[map[string]any](t, rec)["token"].(string)
	requireStatus(t, tok.do(http.MethodGet, path, nil), http.StatusOK)
	requireError(t, tok.do(http.MethodPut, path, map[string]any{"version": got["version"], "owners": []map[string]any{}}),
		http.StatusForbidden, ErrForbidden.Code)
}
