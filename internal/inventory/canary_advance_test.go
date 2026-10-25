package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/authz"
)

// advanceWorld is a rollout with three wave-1 and two wave-2 locations, created an hour ago, interval 30 s, hold 10 min,
// failures 2.
type advanceWorld struct {
	now          time.Time
	w1           [3]uuid.UUID // locations
	w2           [2]uuid.UUID
	dep          [5]uuid.UUID // deployments of w1[0..2], w2[0..1]
	target       uuid.UUID
	holdStarted  time.Time
	holdUntil    time.Time
	settingsHold time.Duration
}

func newAdvanceWorld() advanceWorld {
	w := advanceWorld{now: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), target: uuid.New(), settingsHold: 10 * time.Minute}
	for i := range w.w1 {
		w.w1[i] = uuid.New()
	}
	for i := range w.w2 {
		w.w2[i] = uuid.New()
	}
	for i := range w.dep {
		w.dep[i] = uuid.New()
	}
	w.holdStarted = w.now.Add(-11 * time.Minute)
	w.holdUntil = w.holdStarted.Add(w.settingsHold)
	return w
}

func (w advanceWorld) rollout(state, origin string) Rollout {
	r := Rollout{ID: uuid.New(), State: state, Origin: origin, Wave1: w.w1[:], Wave2: w.w2[:], ReasonParams: map[string]string{},
		Settings: authz.CanarySettings{Count: 3, Hold: w.settingsHold, Interval: 30 * time.Second, Timeout: 5 * time.Second, Failures: 2}}
	if state != RolloutWave1 {
		r.HoldStartedAt, r.HoldUntil = &w.holdStarted, &w.holdUntil
	}
	switch state {
	case RolloutCompleted, RolloutFailed, RolloutAborted, RolloutStopped, RolloutPreempted:
		r.FinishedAt = &w.now
	}
	return r
}

// holding is wave-1 deployment i holding, its last round result taken `ago` before now.
func (w advanceWorld) holding(i int, result string, ago time.Duration, failures int) rolloutDeployment {
	at := w.now.Add(-ago)
	c := &canaryCheck{rounds: 3, consecutiveFailures: failures, nextCheckAt: at.Add(30 * time.Second), lastResult: result, lastAt: &at}
	if result == "pass" {
		c.lastPassAt = &at
	}
	return rolloutDeployment{id: w.dep[i], location: w.w1[i], target: w.target, wave: 1, state: DeployStateHolding, status: DeployStatusRunning, check: c}
}

func (w advanceWorld) dep1(i int, state, status, code string) rolloutDeployment {
	return rolloutDeployment{id: w.dep[i], location: w.w1[i], target: w.target, wave: 1, state: state, status: status, errorCode: code}
}

func (w advanceWorld) dep2(i int, state, status string) rolloutDeployment {
	return rolloutDeployment{id: w.dep[3+i], location: w.w2[i], target: w.target, wave: 2, state: state, status: status}
}

// CAN-20: the rollout's decisions, one row per transition of design §9.1 and §11.
func TestDecideRollout(t *testing.T) {
	w := newAdvanceWorld()
	pass := func(i int) rolloutDeployment { return w.holding(i, "pass", 10*time.Second, 0) } // next round in 20 s
	type want struct {
		next, reason string
		release      map[uuid.UUID]string
		revert       map[uuid.UUID]string
		endQueued    map[uuid.UUID]string
		rounds       []uuid.UUID
		holdStart    bool
		insertWave2  bool
		checkFailed  bool
		params       map[string]string
	}
	for _, tc := range []struct {
		name   string
		r      Rollout
		deps   []rolloutDeployment
		forbid bool
		now    time.Time
		want   want
	}{
		{name: "wave1, one still running: nothing", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), pass(1), w.dep1(2, DeployStateDeploying, DeployStatusRunning, "")},
			want: want{next: RolloutWave1}},
		{name: "wave1, a location not yet deployed (automatic budget): nothing", r: w.rollout(RolloutWave1, RolloutOriginACME),
			deps: []rolloutDeployment{pass(0), pass(1)}, want: want{next: RolloutWave1}},
		{name: "wave1, all holding or unchanged: hold starts", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), pass(1), w.dep1(2, DeployStateDone, DeployStatusUnchanged, "")},
			want: want{next: RolloutHold, holdStart: true}},
		{name: "wave1, a failed deployment: failed, the holds reverted, the queued ended", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), w.dep1(1, DeployStateDone, DeployStatusFailed, "deployment.verify_failed"),
				w.dep1(2, DeployStateQueued, DeployStatusPending, "")},
			want: want{next: RolloutFailed, reason: "canary.wave1_failed", revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryWaveFailed},
				endQueued: map[uuid.UUID]string{w.dep[2]: ReasonCanaryWaveFailed}, params: map[string]string{"cause": "deployment_failed"}}},
		{name: "hold, two failed rounds in a row: failed check_failed", r: w.rollout(RolloutHold, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), w.holding(1, "fail", time.Second, 2), pass(2)},
			want: want{next: RolloutFailed, reason: "canary.check_failed", checkFailed: true,
				revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryCheckFailed, w.dep[1]: ReasonCanaryCheckFailed, w.dep[2]: ReasonCanaryCheckFailed}}},
		{name: "hold, one failed round: rounds go on", r: w.rollout(RolloutHold, RolloutOriginManual), now: w.holdUntil.Add(-time.Minute),
			deps: []rolloutDeployment{w.holding(0, "fail", 3*time.Minute, 1), pass(1), pass(2)},
			want: want{next: RolloutHold, rounds: []uuid.UUID{w.dep[0]}}},
		{name: "hold elapsed, every last round passed: manual starts wave 2", r: w.rollout(RolloutHold, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), pass(1), pass(2)},
			want: want{next: RolloutWave2, insertWave2: true,
				release: map[uuid.UUID]string{w.dep[0]: HoldCauseRelease, w.dep[1]: HoldCauseRelease, w.dep[2]: HoldCauseRelease}}},
		{name: "hold elapsed, every last round passed: automatic completes", r: w.rollout(RolloutHold, RolloutOriginKeyVault),
			deps: []rolloutDeployment{pass(0), pass(1), w.dep1(2, DeployStateDone, DeployStatusUnchanged, "")},
			want: want{next: RolloutCompleted, release: map[uuid.UUID]string{w.dep[0]: HoldCauseRelease, w.dep[1]: HoldCauseRelease}}},
		{name: "hold elapsed, a last round unknown, before the grace: wait", r: w.rollout(RolloutHold, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), w.holding(1, "unknown", time.Second, 0), pass(2)},
			want: want{next: RolloutHold}},
		{name: "hold elapsed, a last round unknown, after the grace: failed check_unavailable", r: w.rollout(RolloutHold, RolloutOriginManual),
			now:  w.holdUntil.Add(5*time.Minute + time.Second),
			deps: []rolloutDeployment{pass(0), w.holding(1, "unknown", time.Second, 0), pass(2)},
			want: want{next: RolloutFailed, reason: "canary.check_unavailable", params: map[string]string{"cause": "check_unavailable"},
				revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryWaveFailed, w.dep[1]: ReasonCanaryWaveFailed, w.dep[2]: ReasonCanaryWaveFailed}}},
		{name: "hold elapsed, a pass taken before the hold started does not count", r: w.rollout(RolloutHold, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), w.holding(1, "pass", 12*time.Minute, 0), pass(2)},
			want: want{next: RolloutHold, rounds: []uuid.UUID{w.dep[1]}}},
		{name: "the deployed certificate was revoked: failed certificate_revoked", r: w.rollout(RolloutHold, RolloutOriginManual), forbid: true,
			deps: []rolloutDeployment{pass(0), pass(1), pass(2)},
			want: want{next: RolloutFailed, reason: "canary.certificate_revoked", params: map[string]string{"cause": "certificate_revoked"},
				revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryWaveFailed, w.dep[1]: ReasonCanaryWaveFailed, w.dep[2]: ReasonCanaryWaveFailed}}},
		{name: "a hold of a failed rollout (it arrived after the verdict): reverted", r: w.rollout(RolloutFailed, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0)},
			want: want{next: RolloutFailed, revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryWaveFailed}}},
		{name: "a hold of an aborted rollout: reverted aborted", r: w.rollout(RolloutAborted, RolloutOriginManual),
			deps: []rolloutDeployment{pass(0), w.dep1(1, DeployStateQueued, DeployStatusPending, "")},
			want: want{next: RolloutAborted, revert: map[uuid.UUID]string{w.dep[0]: ReasonCanaryAborted},
				endQueued: map[uuid.UUID]string{w.dep[1]: ReasonCanaryAborted}}},
		{name: "a hold of a completed rollout: released", r: w.rollout(RolloutCompleted, RolloutOriginACME), deps: []rolloutDeployment{pass(0)},
			want: want{next: RolloutCompleted, release: map[uuid.UUID]string{w.dep[0]: HoldCauseRelease}}},
		{name: "a hold of a stopped rollout: released", r: w.rollout(RolloutStopped, RolloutOriginManual), deps: []rolloutDeployment{pass(0)},
			want: want{next: RolloutStopped, release: map[uuid.UUID]string{w.dep[0]: HoldCauseRelease}}},
		{name: "a hold of a preempted rollout: released", r: w.rollout(RolloutPreempted, RolloutOriginManual), deps: []rolloutDeployment{pass(0)},
			want: want{next: RolloutPreempted, release: map[uuid.UUID]string{w.dep[0]: HoldCauseRelease}}},
		{name: "a hold on a deleted server: released, the location leaves wave 1", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{func() rolloutDeployment { d := pass(0); d.targetDeleted = true; return d }(), pass(1), pass(2)},
			want: want{next: RolloutHold, holdStart: true, release: map[uuid.UUID]string{w.dep[0]: HoldCauseTargetDeleted}}},
		{name: "every wave-1 location gone: failed wave_gone", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{func() rolloutDeployment { d := pass(0); d.targetDeleted = true; return d }(),
				w.dep1(1, DeployStateDone, DeployStatusFailed, "deployment.target_deleted"),
				w.dep1(2, DeployStateDone, DeployStatusRollbackFailed, "deployment.target_deleted")},
			want: want{next: RolloutFailed, reason: "canary.wave_gone", params: map[string]string{"cause": "wave_gone"},
				release: map[uuid.UUID]string{w.dep[0]: HoldCauseTargetDeleted}}},
		{name: "wave2, every wave-2 deployment done: completed", r: w.rollout(RolloutWave2, RolloutOriginManual),
			deps: []rolloutDeployment{w.dep1(0, DeployStateDone, DeployStatusSucceeded, ""), w.dep2(0, DeployStateDone, DeployStatusSucceeded),
				w.dep2(1, DeployStateDone, DeployStatusFailed)},
			want: want{next: RolloutCompleted}},
		{name: "wave2, one still running: nothing", r: w.rollout(RolloutWave2, RolloutOriginManual),
			deps: []rolloutDeployment{w.dep2(0, DeployStateDone, DeployStatusSucceeded), w.dep2(1, DeployStateDeploying, DeployStatusRunning)},
			want: want{next: RolloutWave2}},
		{name: "due rounds only for holds whose next round is due", r: w.rollout(RolloutWave1, RolloutOriginManual),
			deps: []rolloutDeployment{w.holding(0, "pass", time.Second, 0), w.holding(1, "", time.Minute, 0),
				w.dep1(2, DeployStateDeploying, DeployStatusRunning, "")},
			want: want{next: RolloutWave1, rounds: []uuid.UUID{w.dep[1]}}},
	} {
		now := tc.now
		if now.IsZero() {
			now = w.now
		}
		got := decideRollout(rolloutSnapshot{r: tc.r, now: now, deployments: tc.deps, certificateForbidden: tc.forbid})
		assert.Equal(t, tc.want.next, got.next, tc.name)
		assert.Equal(t, tc.want.reason, got.reason, tc.name)
		assert.Equal(t, orEmpty(tc.want.release), got.release, tc.name)
		assert.Equal(t, orEmpty(tc.want.revert), got.revert, tc.name)
		assert.Equal(t, orEmpty(tc.want.endQueued), got.endQueued, tc.name)
		assert.ElementsMatch(t, tc.want.rounds, got.queueRounds, tc.name)
		assert.Equal(t, tc.want.holdStart, got.holdStart, tc.name)
		assert.Equal(t, tc.want.insertWave2, got.insertWave2, tc.name)
		assert.Equal(t, tc.want.checkFailed, got.checkFailed, tc.name)
		if tc.want.params != nil {
			for k, v := range tc.want.params {
				assert.Equal(t, v, got.reasonParams[k], tc.name)
			}
		}
	}
}

func orEmpty(m map[uuid.UUID]string) map[uuid.UUID]string {
	if m == nil {
		return map[uuid.UUID]string{}
	}
	return m
}

// The round that fails a rollout is named in its reason params.
func TestDecideRolloutNamesTheFailingRound(t *testing.T) {
	w := newAdvanceWorld()
	failing := w.holding(1, "fail", time.Second, 2)
	status := 503
	failing.check.lastReason, failing.check.lastHTTPStatus = "canary.http_status", &status
	got := decideRollout(rolloutSnapshot{r: w.rollout(RolloutHold, RolloutOriginManual), now: w.now, deployments: []rolloutDeployment{failing}})
	assert.Equal(t, map[string]string{"location_id": w.w1[1].String(), "reason": "canary.http_status", "http_status": "503"}, got.reasonParams)
}

// Design §15: a clock jump that makes a wave-2 certificate end within the hold + 24 h releases the hold early.
func TestDecideRolloutReleasesEarlyBeforeAWaveTwoCertificateExpires(t *testing.T) {
	w := newAdvanceWorld()
	r := w.rollout(RolloutHold, RolloutOriginManual)
	until := w.now.Add(5 * time.Minute)
	r.HoldUntil = &until
	soon := until.Add(CanaryExpiryMargin - time.Hour)
	pass := w.holding(0, "pass", 10*time.Second, 0)
	got := decideRollout(rolloutSnapshot{r: r, now: w.now, deployments: []rolloutDeployment{pass}, earliestWave2NotAfter: &soon})
	assert.Equal(t, RolloutWave2, got.next)
	assert.True(t, got.insertWave2)
	assert.Equal(t, CanarySkipExpiry, got.reasonParams["early"])
	assert.Equal(t, map[uuid.UUID]string{w.dep[0]: HoldCauseRelease}, got.release)
	later := until.Add(CanaryExpiryMargin + time.Hour)
	got = decideRollout(rolloutSnapshot{r: r, now: w.now, deployments: []rolloutDeployment{pass}, earliestWave2NotAfter: &later})
	assert.Equal(t, RolloutHold, got.next, "the guard holds: wait")
	r.Origin = RolloutOriginACME
	got = decideRollout(rolloutSnapshot{r: r, now: w.now, deployments: []rolloutDeployment{pass}, earliestWave2NotAfter: &soon})
	assert.Equal(t, RolloutCompleted, got.next)
}

// The grace is max(2 x interval, 5 min).
func TestCanaryGrace(t *testing.T) {
	assert.Equal(t, 5*time.Minute, canaryGrace(30*time.Second))
	assert.Equal(t, 20*time.Minute, canaryGrace(10*time.Minute))
}
