//go:build integration

package inventory_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

// CAN-29 in the engine (R65, design §13.2, §13.3, §17.1): the rollout's detail and the actions its state allows;
// Continue now only after the last round passed, then wave 2; Abort reverts wave 1; a state that moved on refuses both.
func TestRolloutDetailContinueAndAbort(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()

	d, err := w.h.svc.RolloutDetail(w.h.ctx, w.rollout.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutHold, d.State)
	assert.Equal(t, []string{"abort"}, d.AllowedRolloutActions(), "no round passed yet")
	assert.NotEmpty(t, d.CertificateName)
	assert.Equal(t, "Default", d.ServiceName)
	require.Len(t, d.Locations, 3)
	assert.Equal(t, 1, d.Locations[0].Wave)
	require.NotNil(t, d.Locations[0].DeploymentID)
	assert.Equal(t, w.hold, *d.Locations[0].DeploymentID)
	assert.Nil(t, d.Locations[1].DeploymentID, "wave 2 has no deployment yet")
	assert.Equal(t, w.h.clock.Now().UTC(), d.Now)

	_, err = w.h.svc.ContinueRollout(w.h.ctx, w.admin, w.rollout.ID)
	var se *inventory.RolloutStateError
	require.ErrorAs(t, err, &se, "the last round has not passed")
	assert.True(t, errors.Is(err, inventory.ErrRolloutState))
	assert.Equal(t, inventory.RolloutHold, se.State)
	assert.Contains(t, se.Error(), inventory.RolloutHold)

	w.round(inventory.RoundPass, "", 200)
	d, err = w.h.svc.RolloutDetail(w.h.ctx, w.rollout.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"continue", "abort"}, d.AllowedRolloutActions())
	require.NotNil(t, d.Locations[0].Canary)
	assert.Equal(t, inventory.RoundPass, d.Locations[0].Canary.LastResult)

	r, err := w.h.svc.ContinueRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutWave2, r.State)
	assert.Equal(t, inventory.DeployStatusSucceeded, w.get(w.hold).Status)
	assert.Len(t, w.wave2(), 2)
	cont := w.h.auditDetails("deployment.rollout_continued")
	require.Len(t, cont, 1)
	assert.NotEqual(t, "0", cont[0]["remaining_seconds"])

	_, err = w.h.svc.AbortRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.ErrorAs(t, err, &se)
	assert.Equal(t, inventory.RolloutWave2, se.State)
	_, err = w.h.svc.ContinueRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.ErrorIs(t, err, inventory.ErrRolloutState)

	_, err = w.h.svc.RolloutDetail(w.h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrRolloutNotFound)
	_, err = w.h.svc.ContinueRollout(w.h.ctx, w.admin, uuid.New())
	require.ErrorIs(t, err, inventory.ErrRolloutNotFound)
	_, err = w.h.svc.AbortRollout(w.h.ctx, w.admin, uuid.New())
	require.ErrorIs(t, err, inventory.ErrRolloutNotFound)
}

func TestAbortRevertsTheHoldingWaveOne(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	r, err := w.h.svc.AbortRollout(w.h.ctx, w.admin, w.rollout.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutAborted, r.State)
	assert.Equal(t, inventory.RolloutReasonAborted, r.Reason)
	d := w.get(w.hold)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.ReasonCanaryAborted, d.RevertReason)
	assert.Empty(t, w.wave2())
	assert.Equal(t, 1, w.h.audits("deployment.rollout_aborted"))
	det, err := w.h.svc.RolloutDetail(w.h.ctx, w.rollout.ID)
	require.NoError(t, err)
	assert.Empty(t, det.AllowedRolloutActions())
}

// An abort in wave 1 ends a wave-1 deployment that was never sent.
func TestAbortInWaveOneEndsTheQueuedDeployment(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryTenMinutes)
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}})
	require.NoError(t, err)
	require.NotNil(t, r)
	out, err := f.h.svc.AbortRollout(f.h.ctx, f.admin, r.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutAborted, out.State)
	d := f.get(got[0].ID)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.ReasonCanaryAborted, d.ErrorCode)
}

func TestCanaryTemplatesAreTheStopMail(t *testing.T) {
	ts := inventory.CanaryTemplates()
	require.NotEmpty(t, ts)
	assert.Contains(t, ts, inventory.TemplateDeploymentRolloutStopped)
}
