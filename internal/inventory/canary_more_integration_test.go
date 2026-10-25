//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
)

// Continue now on an automatic rollout completes it at the release (design §12: the planner deploys the rest).
func TestContinuedAutomaticRolloutCompletesAtRelease(t *testing.T) {
	w := newACMEDeployWorld(t)
	w.h.setPolicy(w.h.defaultService(), canaryTenMinutes)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2, w.loc3onTarget2)
	require.Equal(t, 1, w.plan().Created)
	deps := w.deps(cur)
	require.Len(t, deps, 1)
	w.start(deps[0].ID)
	require.NoError(t, w.succeed(deps[0].ID, stringOf('e', 64)))
	_, err := w.h.svc.AdvanceRollouts(w.h.ctx)
	require.NoError(t, err)
	require.NoError(t, w.h.svc.RecordCanaryRound(w.h.ctx, deps[0].ID, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}))
	r := w.h.rolloutOf(deps[0].ID)
	got, err := w.h.svc.ContinueRollout(w.h.ctx, w.admin, r.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutCompleted, got.State)
	assert.Empty(t, w.wave2Of(cur), "the planner deploys the rest, not the rollout")
	rel := w.h.auditDetails("deployment.rollout_released")
	require.Len(t, rel, 1)
	assert.Equal(t, "true", rel[0]["early"])
}

// The planner skips the canary when a destination's current certificate ends within hold + 24 h, and audits it.
func TestPlannerSkipsTheCanaryWhenACertificateEndsSoon(t *testing.T) {
	w := newACMEDeployWorld(t)
	w.h.setPolicy(w.h.defaultService(), canaryTenMinutes)
	c, cur := w.issued("www.example.test")
	w.bind(c, true, w.loc1, w.loc2, w.loc3onTarget2)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificates SET not_after = $2 WHERE id = (SELECT certificate_id FROM certificate_locations WHERE id = $1)",
		w.loc2, w.h.clock.Now().Add(2*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 3, w.plan().Created, "all at once")
	assert.Zero(t, w.h.count("SELECT count(*) FROM deployment_rollouts WHERE acme_certificate_id = $1", c.ID))
	skipped := w.h.auditDetails("deployment.canary_skipped")
	require.Len(t, skipped, 1)
	assert.Equal(t, inventory.CanarySkipExpiry, skipped[0]["reason"])
	assert.NotEmpty(t, w.deps(cur))
}

// A round of a hold whose snapshot names no interval waits the default; a deployment that does not hold has no round
// target; the detail of a rollout in wave 1 shows a queued deployment without an observation and offers Abort only.
func TestRoundDefaultsAndAWaveOneDetail(t *testing.T) {
	f := newDeployFixture(t)
	id, _ := f.holding(f.loc1)
	require.NoError(t, f.h.svc.RecordCanaryRound(f.h.ctx, id, inventory.CanaryRound{Result: inventory.RoundPass, TLS: inventory.RoundPass}))
	var next time.Time
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT next_check_at FROM canary_checks WHERE deployment_id = $1", id).Scan(&next))
	assert.WithinDuration(t, f.h.clock.Now().Add(30*time.Second), next, time.Second)

	plain := f.request(f.admin, f.cert.ID, f.loc3onTarget2)
	_, err := f.h.svc.CanaryRoundTarget(f.h.ctx, plain)
	require.ErrorIs(t, err, inventory.ErrDeploymentState)

	g := newDeployFixture(t)
	g.h.setPolicy(g.h.defaultService(), canaryTenMinutes)
	_, r, err := g.h.svc.RequestDeploymentWithRollout(g.h.ctx, g.admin, inventory.DeployRequestInput{CertificateID: g.cert.ID,
		LocationIDs: []uuid.UUID{g.loc1, g.loc2, g.loc3onTarget2}})
	require.NoError(t, err)
	d, err := g.h.svc.RolloutDetail(g.h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutWave1, d.State)
	assert.Equal(t, []string{"abort"}, d.AllowedRolloutActions())
	require.NotEmpty(t, d.Locations)
	assert.Nil(t, d.Locations[0].Canary)
}
