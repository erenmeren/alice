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

	"alice/internal/inventory"
)

// rolloutView is the part of a rollout answer the journey asserts.
type rolloutView struct {
	ID             string   `json:"id"`
	State          string   `json:"state"`
	AllowedActions []string `json:"allowed_actions"`
	Waves          []struct {
		Wave      int `json:"wave"`
		Locations []struct {
			LocationID      string  `json:"location_id"`
			DeploymentID    *string `json:"deployment_id"`
			DeploymentState *string `json:"deployment_state"`
		} `json:"locations"`
	} `json:"waves"`
}

// CAN-29 over the wire (R65): the Default service asks for a canary; a deploy to two websites answers the rollout and
// wave 1 only; wave 1 holds after its verified send; the rollout is read, continued with a fresh step-up (an Operator
// without one is refused), wave 2 is deployed and the rollout completes. An override needs the step-up too.
func TestCanaryThroughTheAPI(t *testing.T) {
	n := newNJ(t, wwwSite(), apiSite())
	ctx := context.Background()
	var def uuid.UUID
	require.NoError(t, n.db.Owner.QueryRow(ctx, "SELECT id FROM services WHERE is_default").Scan(&def))
	n.stepUp(n.admin, n.adminAcct)
	rec := n.admin.do(http.MethodPut, "/api/v1/services/"+def.String()+"/policy", map[string]any{"version": 1, "body": map[string]any{"schema": 1,
		"canary": map[string]any{"enabled": true, "hold": "1m", "interval": "15s"}}})
	requireStatus(t, rec, http.StatusOK)
	// A browser session of the Operator whose sign-in step-up has lapsed (5 minutes).
	stale := n.freshClient()
	n.signIn(stale, n.opAcct)
	n.clock.Advance(6 * time.Minute)

	leaf := n.issue()
	certID := n.uploadCertificate(n.op, certBody(leaf, "Canary"))
	rec = n.requestDeploy(n.op, certID, n.locs[wwwCert], n.locs[apiCert])
	requireStatus(t, rec, http.StatusAccepted)
	answer := decodeBody[struct {
		Deployments []deployRef `json:"deployments"`
		Rollout     *struct {
			ID    string   `json:"id"`
			State string   `json:"state"`
			Wave1 []string `json:"wave1"`
			Wave2 []string `json:"wave2"`
		} `json:"rollout"`
	}](t, rec)
	require.NotNil(t, answer.Rollout)
	require.Len(t, answer.Deployments, 1, "wave 1 only")
	assert.Equal(t, "wave1", answer.Rollout.State)
	assert.Len(t, answer.Rollout.Wave2, 1)
	n.runJobs()
	hold := answer.Deployments[0].ID
	assert.Equal(t, "holding", n.deployment(n.op, hold).State)

	path := "/api/v1/deployment-rollouts/" + answer.Rollout.ID
	_, err := n.inv.AdvanceRollouts(ctx)
	require.NoError(t, err)
	rv := decodeBody[rolloutView](t, n.op.do(http.MethodGet, path, nil))
	assert.Equal(t, "hold", rv.State)
	assert.Equal(t, []string{"abort"}, rv.AllowedActions)
	holdID := uuid.MustParse(hold)
	require.NoError(t, n.inv.RecordCanaryRound(ctx, holdID, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}))
	rv = decodeBody[rolloutView](t, n.op.do(http.MethodGet, path, nil))
	assert.Equal(t, []string{"continue", "abort"}, rv.AllowedActions)

	// Without a fresh step-up Continue is refused; with one it releases wave 1.
	requireError(t, stale.do(http.MethodPost, path+"/actions/continue", nil), http.StatusForbidden, ErrStepUpRequired.Code)
	n.stepUp(stale, n.opAcct)
	rv = decodeBody[rolloutView](t, stale.do(http.MethodPost, path+"/actions/continue", nil))
	assert.Equal(t, "wave2", rv.State)
	require.Len(t, rv.Waves, 2)
	require.Len(t, rv.Waves[1].Locations, 1)
	require.NotNil(t, rv.Waves[1].Locations[0].DeploymentID, "wave 2 was inserted")
	requireError(t, n.op.do(http.MethodPost, path+"/actions/abort", nil), http.StatusConflict, ErrDeployRolloutState.Code)
	n.runJobs()
	_, err = n.inv.AdvanceRollouts(ctx)
	require.NoError(t, err)
	rv = decodeBody[rolloutView](t, n.op.do(http.MethodGet, path, nil))
	assert.Equal(t, "completed", rv.State)
	assert.Equal(t, "succeeded", n.deployment(n.op, hold).Status)

	// The deployment list filters by the rollout.
	page := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, n.op.do(http.MethodGet, "/api/v1/deployments?rollout_id="+answer.Rollout.ID, nil))
	assert.Len(t, page.Items, 2)

	// Deploying to all at once: the operator's step-up is still fresh; a new browser without it is refused.
	n.clock.Advance(time.Minute)
	other := n.issue()
	otherID := n.uploadCertificate(n.op, certBody(other, "All at once"))
	oc := n.freshClient()
	n.signIn(oc, n.opAcct)
	n.clock.Advance(6 * time.Minute)
	requireError(t, oc.do(http.MethodPost, "/api/v1/certificates/"+otherID+"/deploy", map[string]any{"location_ids": []string{n.locs[wwwCert],
		n.locs[apiCert]}, "canary_override": true}), http.StatusForbidden, ErrStepUpRequired.Code)
	n.stepUp(oc, n.opAcct)
	rec = oc.do(http.MethodPost, "/api/v1/certificates/"+otherID+"/deploy", map[string]any{"location_ids": []string{n.locs[wwwCert],
		n.locs[apiCert]}, "canary_override": true})
	requireStatus(t, rec, http.StatusAccepted)
	all := decodeBody[map[string]any](t, rec)
	assert.Nil(t, all["rollout"])
	assert.Len(t, all["deployments"], 2)
}
