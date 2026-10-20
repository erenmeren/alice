//go:build integration

package jobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// Owner decision 2026-10-20: in the continuity window of a licensed lock the runner still claims continuity work (a
// renewal order, an automatic deployment, a Key Vault poll) while a person's change is held and read-only work is
// cancelled. Once an evaluation found the window ended, queued continuity work that changes something is held for an
// Administrator (as a change) and a poll is cancelled (as read-only work).
func TestContinuityWorkRunsInTheWindowAndIsHeldAfterIt(t *testing.T) {
	e := newQEnv(t)
	target := insertTarget(t, e.d)
	var mu sync.Mutex
	ran := map[string]int{}
	r := e.runner(t, "w1")
	for _, typ := range []Type{ACMERenew, CertificateDeployAuto, KVPoll, CertificateDeploy, testReadOnlyJob} {
		r.Handle(typ, func(_ context.Context, j Job, _ StepRecorder) (map[string]any, error) {
			mu.Lock()
			defer mu.Unlock()
			ran[j.Type.Name]++
			return nil, nil
		})
	}
	drain := func() {
		for {
			ok, err := r.RunOnce(e.ctx)
			require.NoError(t, err)
			if !ok {
				return
			}
		}
	}
	runs := func(typ Type) int {
		mu.Lock()
		defer mu.Unlock()
		return ran[typ.Name]
	}

	e.gate.setWindow(true)
	renew := e.enqueue(t, Spec{Type: ACMERenew, Kind: KindSystem, DedupeKey: "acme.issue:c1"})
	auto := e.enqueue(t, Spec{Type: CertificateDeployAuto, Kind: KindSystem, TargetID: target, DedupeKey: "certificate.deploy:d1"})
	poll := e.enqueue(t, Spec{Type: KVPoll, Kind: KindScheduled, DedupeKey: "kv.poll:v1"})
	manual := e.enqueue(t, Spec{Type: CertificateDeploy, Kind: KindUser, TargetID: insertTarget(t, e.d), DedupeKey: "certificate.deploy:d2"})
	read := e.enqueue(t, Spec{Type: testReadOnlyJob, Kind: KindScheduled})
	drain()
	for id, want := range map[uuid.UUID]string{renew: "succeeded", auto: "succeeded", poll: "succeeded", manual: "blocked_license",
		read: "cancelled"} {
		assert.Equal(t, want, e.row(t, id).status, id.String())
	}
	assert.Equal(t, 1, runs(ACMERenew))
	assert.Equal(t, 1, runs(CertificateDeployAuto))
	assert.Equal(t, 1, runs(KVPoll))
	assert.Zero(t, runs(CertificateDeploy), "a person's deployment is held in the window")

	// The window ends: what is queued now is held (changes) or cancelled (the poll), nothing runs.
	e.gate.setWindow(false)
	e.fake.Advance(time.Minute) // the lock sweep runs at most once per poll interval
	renew2 := e.enqueue(t, Spec{Type: ACMERenew, Kind: KindSystem, DedupeKey: "acme.issue:c2"})
	auto2 := e.enqueue(t, Spec{Type: CertificateDeployAuto, Kind: KindSystem, TargetID: target, DedupeKey: "certificate.deploy:d3"})
	poll2 := e.enqueue(t, Spec{Type: KVPoll, Kind: KindScheduled, DedupeKey: "kv.poll:v2"})
	drain()
	assert.Equal(t, "blocked_license", e.row(t, renew2).status)
	assert.Equal(t, "blocked_license", e.row(t, auto2).status)
	got := e.row(t, poll2)
	assert.Equal(t, "cancelled", got.status, "a poll only reads: cancelled, and queued again by kv.schedule after a renewal")
	assert.Equal(t, "license.locked", got.lastError)
	assert.Equal(t, 1, runs(ACMERenew))
	assert.Equal(t, 1, runs(KVPoll))
	assert.Equal(t, 3, e.audits(t, "job.blocked_license"), "the manual deployment, the order and the automatic deployment")
	assert.ErrorIs(t, e.q.Confirm(e.ctx, admin, admin.ID, renew2), license.ErrLocked, "confirming waits for a renewal")

	// After a renewal a held continuity job waits for an Administrator, like a change.
	e.gate.set(false)
	drain()
	assert.Equal(t, "blocked_license", e.row(t, auto2).status)
	require.NoError(t, e.q.Confirm(e.ctx, admin, admin.ID, auto2))
	drain()
	assert.Equal(t, "succeeded", e.row(t, auto2).status)
	assert.Equal(t, 2, runs(CertificateDeployAuto))
}

// A continuity job claimed just before the window ended is held (it changes something) when the gate is asked again
// at run time; a continuity poll is cancelled.
func TestContinuityJobRefusedAfterTheClaim(t *testing.T) {
	e := newQEnv(t)
	gate := classFlipGate{}
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = gate })
	r.Handle(ACMERenew, func(context.Context, Job, StepRecorder) (map[string]any, error) { return nil, nil })
	r.Handle(KVPoll, func(context.Context, Job, StepRecorder) (map[string]any, error) { return nil, nil })
	renew := e.enqueue(t, Spec{Type: ACMERenew, Kind: KindSystem})
	ok, err := r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ok)
	got := e.row(t, renew)
	assert.Equal(t, "blocked_license", got.status)
	assert.Zero(t, got.attempts, "the refused claim is not an attempt")

	poll := e.enqueue(t, Spec{Type: KVPoll, Kind: KindScheduled})
	ok, err = r.RunOnce(e.ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "cancelled", e.row(t, poll).status)
}

// classFlipGate allows everything but continuity work, which it refuses as a confirmed lock: the claim (which asks
// about changes first) takes the job, and the gate asked again at run time refuses it, as when the continuity window
// ends between the claim and the run.
type classFlipGate struct{}

func (classFlipGate) Allow(c license.Class) error {
	if c == license.ClassContinuity {
		return license.ErrLocked
	}
	return nil
}
