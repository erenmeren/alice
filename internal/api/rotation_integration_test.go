//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEditOfEnabledPolicySwitchesItOffOverTheWire (S2) with the real service: an Administrator's operate token
// prepares a policy, the Administrator switches it on with step-up, the token changes how it rotates and the answer
// and the stored policy show it switched off and audited; the token can never switch it on again, nor can the
// browser session once its step-up has expired. A name-only change leaves a policy that is on as it is.
func TestEditOfEnabledPolicySwitchesItOffOverTheWire(t *testing.T) {
	s, browser, admin := installed(t)
	token, _ := createToken(t, s, browser, admin, "operate", 1)
	api := s.client("198.51.100.60")
	api.bearer = token

	rec := api.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "ci deploy", "key_type": "ed25519"})
	requireStatus(t, rec, http.StatusCreated)
	key := decodeBody[map[string]any](t, rec)
	require.NotNil(t, key["managed_key"])
	rec = api.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": key["id"], "name": "ci", "interval_days": 90})
	requireStatus(t, rec, http.StatusCreated)
	pol := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, pol["enabled"])
	path := "/api/v1/rotation/policies/" + pol["id"].(string)
	etag := rec.Header().Get("ETag")
	require.Equal(t, `"1"`, etag)

	// Switching on: never the token, never without a fresh step-up.
	requireError(t, api.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0002")
	s.stepUp(browser, admin)
	rec = browser.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["enabled"])
	etag = rec.Header().Get("ETag")

	// A name-only change leaves it on.
	rec = api.do(http.MethodPatch, path, map[string]any{"name": "ci runners"}, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["enabled"])
	etag = rec.Header().Get("ETag")

	// Any change of how it rotates switches it off in the same step.
	rec = api.do(http.MethodPatch, path, map[string]any{"interval_days": 1, "overlap_days": 0, "notify_before_hours": 1}, withHeader("If-Match", etag))
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, got["enabled"])
	assert.Nil(t, got["next_run_at"])
	assert.EqualValues(t, 1, got["interval_days"])
	etag = rec.Header().Get("ETag")
	rec = api.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["enabled"], "the stored policy is off")
	var reason string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT details->>'reason' FROM audit_log
WHERE action = 'rotation.policy_disabled' ORDER BY seq DESC LIMIT 1`).Scan(&reason))
	assert.Equal(t, "edited", reason)

	// The token cannot switch it back on; the session without a fresh step-up cannot either.
	requireError(t, api.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0002")
	s.clock.Advance(10 * time.Minute)
	requireError(t, browser.do(http.MethodPost, path+"/actions/enable", nil, withHeader("If-Match", etag)), http.StatusForbidden, "ALC-AUTH-0003")
	rec = api.do(http.MethodGet, path, nil)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["enabled"])
}

// phase6Records makes one generated key, its rotation policy (through the API) and a previewed run (written as the
// service writes it), so every Phase 6 GET of an item answers 200 with a real record.
func phase6Records(t *testing.T, s *stack, c *client) map[string]string {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "records", "key_type": "ed25519"})
	requireStatus(t, rec, http.StatusCreated)
	key := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = c.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": key, "name": "records", "interval_days": 30})
	requireStatus(t, rec, http.StatusCreated)
	policy := decodeBody[map[string]any](t, rec)["id"].(string)
	run := uuid.Must(uuid.NewV7())
	_, err := s.db.Owner.Exec(context.Background(), `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest,
    new_key_type, overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES ($1, $2, $3, 'manual', 'dry_run_notified', '{}', repeat('a', 64), 'ed25519', 0, $4, $4, $4, $4)`, run, policy, key, s.clock.Now())
	require.NoError(t, err)
	return map[string]string{"/api/v1/rotation/policies/": policy, "/api/v1/rotation/runs/": run.String()}
}
