package inventory

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/authz"
)

func canaryState(rollout *Rollout) *canaryPlanState {
	return &canaryPlanState{enabled: true, version: 2, settings: authz.CanarySettings{Count: 1, Hold: 10 * time.Minute, Interval: 30 * time.Second,
		Timeout: 5 * time.Second, Failures: 2}, rollout: rollout, reserved: map[uuid.UUID]bool{}, currentNotAfter: map[uuid.UUID]time.Time{}}
}

func sortedIDs(ids ...uuid.UUID) []uuid.UUID {
	out := slices.Clone(ids)
	slices.SortFunc(out, compareUUID)
	return out
}

// CAN-26 (design §12): the canary's rule for the automatic planners.
func TestCanaryFilter(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	order := sortedIDs(a, b, c)
	never := func(uuid.UUID) bool { return false }
	now := planNow

	got, create, skip := canaryFilter(nil, order, never, now)
	assert.Equal(t, order, got, "no canary read: today's plan")
	assert.Nil(t, create)
	assert.Empty(t, skip)

	off := canaryState(nil)
	off.enabled = false
	off.reserved[order[1]] = true
	got, create, _ = canaryFilter(off, order, never, now)
	assert.Equal(t, []uuid.UUID{order[0], order[2]}, got, "a reserved location is never a candidate, canary or not")
	assert.Nil(t, create)

	got, create, skip = canaryFilter(canaryState(nil), order, never, now)
	assert.Equal(t, []uuid.UUID{order[0]}, got, "three destinations, no rollout: wave 1 only")
	assert.Equal(t, &rolloutWaves{wave1: []uuid.UUID{order[0]}, wave2: []uuid.UUID{order[1], order[2]}}, create)
	assert.Empty(t, skip)

	got, create, _ = canaryFilter(canaryState(nil), order[:1], never, now)
	assert.Equal(t, order[:1], got, "one destination: today's plan")
	assert.Nil(t, create)

	soon := canaryState(nil)
	soon.currentNotAfter[order[2]] = now.Add(10*time.Minute + 23*time.Hour)
	got, create, skip = canaryFilter(soon, order, never, now)
	assert.Equal(t, order, got, "the expiry guard: all at once")
	assert.Nil(t, create)
	assert.Equal(t, CanarySkipExpiry, skip)

	for _, state := range []string{RolloutWave1, RolloutHold} {
		r := &Rollout{State: state, Wave1: []uuid.UUID{order[0], order[1]}, Wave2: []uuid.UUID{order[2]}}
		got, create, _ = canaryFilter(canaryState(r), order, func(l uuid.UUID) bool { return l == order[1] }, now)
		assert.Equal(t, []uuid.UUID{order[0]}, got, "%s: only unattempted wave-1 locations", state)
		assert.Nil(t, create)
	}
	for _, state := range []string{RolloutCompleted, RolloutPreempted, RolloutStopped} {
		r := &Rollout{State: state, Wave1: []uuid.UUID{order[0]}, Wave2: []uuid.UUID{order[1], order[2]}}
		got, create, _ = canaryFilter(canaryState(r), order[1:], never, now)
		assert.Equal(t, order[1:], got, "%s: the rest as today", state)
		assert.Nil(t, create, "%s: no new rollout", state)
	}
	r := &Rollout{State: RolloutFailed, Wave1: []uuid.UUID{order[0]}, Wave2: []uuid.UUID{order[1], order[2]}}
	_, create, _ = canaryFilter(canaryState(r), order, never, now)
	assert.NotNil(t, create, "a failed rollout that was re-armed: a new rollout")
}

// CAN-26: the ACME planner with the canary on.
func TestPlanCanaryACME(t *testing.T) {
	f := newACMEPlanFixture()
	f.sn.canary = canaryState(nil)
	p := planACMEAutoDeploy(f.sn)
	assert.Equal(t, []uuid.UUID{f.a}, p.deploy, "wave 1 first (the fixture's locations are in id order)")
	if assert.NotNil(t, p.createRollout) {
		assert.Equal(t, []uuid.UUID{f.b, f.c}, sortedIDs(p.createRollout.wave2...))
	}

	f = newACMEPlanFixture()
	f.sn.canary = canaryState(&Rollout{State: RolloutHold, Wave1: []uuid.UUID{f.a}, Wave2: []uuid.UUID{f.b, f.c}})
	f.sn.deployments = append(f.sn.deployments, acmeDeployment{location: f.a, certificate: f.cur, automatic: true, status: "running",
		createdAt: planNow.Add(-time.Minute)})
	p = planACMEAutoDeploy(f.sn)
	assert.Empty(t, p.deploy, "during the hold nothing else of the certificate is deployed")
	assert.Nil(t, p.createRollout)

	f = newACMEPlanFixture()
	f.sn.canary = canaryState(nil)
	f.sn.canary.reserved[f.b] = true
	f.binding(f.b).attentionCode = "deployment.verify_failed"
	p = planACMEAutoDeploy(f.sn)
	assert.NotContains(t, p.deploy, f.b)
	for _, m := range p.attention {
		assert.NotEqual(t, f.b, m.location, "no attention mark at a reserved location")
	}

	f = newACMEPlanFixture()
	f.sn.canary = canaryState(nil)
	f.sn.canary.currentNotAfter[f.c] = planNow.Add(time.Hour)
	p = planACMEAutoDeploy(f.sn)
	assert.Equal(t, []uuid.UUID{f.a, f.b, f.c}, p.deploy)
	assert.Equal(t, CanarySkipExpiry, p.canarySkipped)
}

// CAN-26: the Key Vault planner with the canary on.
func TestPlanCanaryKV(t *testing.T) {
	f := newPlanFixture()
	f.sn.canary = canaryState(nil)
	order := sortedIDs(f.a, f.b, f.c)
	p := planAutoDeploy(f.sn)
	if assert.NotNil(t, p.createRollout) {
		assert.Len(t, p.deploy, 1)
		assert.Equal(t, p.createRollout.wave1, p.deploy)
		assert.Equal(t, order[0], p.deploy[0], "wave 1 is the first location in UUID byte order")
	}

	f = newPlanFixture()
	f.sn.canary = canaryState(&Rollout{State: RolloutCompleted, Wave1: []uuid.UUID{order[0]}, Wave2: order[1:]})
	p = planAutoDeploy(f.sn)
	assert.Len(t, p.deploy, 3, "after completion the planner plans as today")
	assert.Nil(t, p.createRollout)

	f = newPlanFixture()
	f.sn.canary = canaryState(&Rollout{State: RolloutWave1, Wave1: []uuid.UUID{order[0]}, Wave2: order[1:]})
	f.failed(order[0], 2*time.Hour, "deployment.verify_failed")
	p = planAutoDeploy(f.sn)
	assert.Empty(t, p.deploy, "a wave-1 failure is not retried")
}
