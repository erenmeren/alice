//go:build integration

package inventory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
)

const canaryTenMinutes = `{"schema":1,"canary":{"enabled":true,"hold":"10m","interval":"30s","failures":2}}`

// canaryWorld is a person's rollout of nw to three websites (wave 1: one, wave 2: two) with its wave-1 deployment
// holding.
type canaryWorld struct {
	*deployFixture
	rollout inventory.Rollout
	hold    uuid.UUID // the wave-1 deployment
}

func newCanaryWorld(t *testing.T, policy string, locs ...uuid.UUID) *canaryWorld {
	t.Helper()
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), policy)
	if len(locs) == 0 {
		locs = []uuid.UUID{f.loc1, f.loc2, f.loc3onTarget2}
	}
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: locs})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Len(t, got, 1)
	w := &canaryWorld{deployFixture: f, rollout: *r, hold: got[0].ID}
	f.start(w.hold)
	require.NoError(t, f.succeed(w.hold, stringOf('e', 64)))
	require.Equal(t, inventory.DeployStateHolding, f.get(w.hold).State)
	return w
}

func (w *canaryWorld) advance() int {
	w.h.t.Helper()
	n, err := w.h.svc.AdvanceRollouts(w.h.ctx)
	require.NoError(w.h.t, err)
	return n
}

func (w *canaryWorld) read() inventory.Rollout {
	w.h.t.Helper()
	r, err := w.h.svc.Rollout(w.h.ctx, w.rollout.ID)
	require.NoError(w.h.t, err)
	return r
}

func (w *canaryWorld) round(result, reason string, status int) {
	w.h.t.Helper()
	require.NoError(w.h.t, w.h.svc.RecordCanaryRound(w.h.ctx, w.hold, inventory.CanaryRound{Result: result, Reason: reason, TLS: inventory.RoundPass,
		HTTPStatus: status}))
}

func (w *canaryWorld) wave2() []inventory.Deployment {
	w.h.t.Helper()
	page, err := w.h.svc.ListDeployments(w.h.ctx, inventory.DeploymentFilter{CertificateID: w.cert.ID, Limit: 50})
	require.NoError(w.h.t, err)
	var out []inventory.Deployment
	for _, d := range page.Items {
		if d.Wave == 2 {
			out = append(out, d)
		}
	}
	return out
}

func (h *harness) jobType(id uuid.UUID) string {
	h.t.Helper()
	var typ string
	require.NoError(h.t, h.db.Owner.QueryRow(h.ctx, "SELECT type FROM jobs WHERE id = $1", id).Scan(&typ))
	return typ
}

func (w *canaryWorld) jobsOf(typ string) int {
	return w.h.count("SELECT count(*) FROM jobs WHERE type = $1", typ)
}

// passHold starts the hold, records a pass after it started and moves the clock past it.
func (w *canaryWorld) passHold() {
	w.h.t.Helper()
	w.advance()
	require.Equal(w.h.t, inventory.RolloutHold, w.read().State)
	w.round(inventory.RoundPass, "", 200)
	w.h.clock.Advance(11 * time.Minute)
	w.round(inventory.RoundPass, "", 200)
}

// CAN-21: the hold starts, rounds are queued, a passing hold releases wave 1 and deploys wave 2; then completed.
func TestRolloutPassesAndStartsWaveTwo(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	assert.Equal(t, 1, w.advance())
	r := w.read()
	assert.Equal(t, inventory.RolloutHold, r.State)
	require.NotNil(t, r.HoldUntil)
	assert.Equal(t, w.h.clock.Now().Add(10*time.Minute).UTC(), r.HoldUntil.UTC())
	assert.Equal(t, 1, w.jobsOf(inventory.JobCanaryCheck), "the first round is due at once")
	assert.Equal(t, 1, w.h.audits("deployment.rollout_hold_started"))
	w.advance()
	assert.Equal(t, 1, w.jobsOf(inventory.JobCanaryCheck), "a live round job answers its dedupe key")

	w.round(inventory.RoundPass, "", 200)
	w.h.clock.Advance(5 * time.Minute)
	w.advance()
	assert.Equal(t, inventory.RolloutHold, w.read().State, "the hold has not elapsed")
	w.h.clock.Advance(6 * time.Minute)
	w.round(inventory.RoundPass, "", 200)
	assert.Equal(t, 1, w.advance())

	d := w.get(w.hold)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	loc, err := w.h.svc.GetLocation(w.h.ctx, d.LocationID)
	require.NoError(t, err)
	require.NotNil(t, loc.Certificate)
	assert.Equal(t, w.cert.ID, loc.Certificate.ID, "the location names the released certificate")
	r = w.read()
	assert.Equal(t, inventory.RolloutWave2, r.State)
	two := w.wave2()
	require.Len(t, two, 2)
	for _, d := range two {
		assert.Equal(t, "manual", d.Trigger)
		require.NotNil(t, d.RequestedBy)
		assert.Equal(t, w.admin.UserID, *d.RequestedBy)
		require.NotNil(t, d.RolloutID)
		assert.Equal(t, r.ID, *d.RolloutID)
		assert.Equal(t, inventory.JobCertificateDeploy, w.h.jobType(*d.JobID))
	}
	assert.Equal(t, 1, w.h.audits("deployment.rollout_released"))
	started := w.h.auditDetails("deployment.rollout_wave2_started")
	require.Len(t, started, 1)
	assert.Equal(t, "2", started[0]["inserted"])

	for _, d := range two {
		w.start(d.ID)
		require.NoError(t, w.succeed(d.ID, stringOf('e', 64)))
		assert.Equal(t, inventory.DeployStatusSucceeded, w.get(d.ID).Status, "wave 2 never holds")
	}
	w.advance()
	assert.Equal(t, inventory.RolloutCompleted, w.read().State)
	assert.NotNil(t, w.read().FinishedAt)
	assert.Equal(t, 1, w.h.audits("deployment.rollout_completed"))
	assert.Zero(t, w.advance(), "a finished rollout without holds is not touched")
}

// CAN-22: two failed rounds in a row fail the rollout: wave 1 reverted, wave 2 never inserted, the deciding round
// audited once.
func TestRolloutFailsAndRevertsWaveOneOnly(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.advance()
	w.round(inventory.RoundFail, "canary.http_status", 503)
	w.advance()
	assert.Equal(t, inventory.RolloutHold, w.read().State, "one failure is not enough")
	w.round(inventory.RoundUnknown, "ssh.unreachable", 0)
	w.advance()
	assert.Equal(t, inventory.RolloutHold, w.read().State, "an unknown round resets nothing and fails nothing")
	w.round(inventory.RoundFail, "canary.http_status", 503)
	assert.Equal(t, 1, w.advance())
	d := w.get(w.hold)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.ReasonCanaryCheckFailed, d.RevertReason)
	assert.Equal(t, []string{"queued"}, w.recoverJobs(w.hold))
	r := w.read()
	assert.Equal(t, inventory.RolloutFailed, r.State)
	assert.Equal(t, inventory.RolloutReasonCheckFailed, r.Reason)
	assert.Equal(t, "503", r.ReasonParams["http_status"])
	assert.Equal(t, "canary.http_status", r.ReasonParams["reason"])
	assert.Empty(t, w.wave2())
	assert.Equal(t, 1, w.h.audits("deployment.rollout_check_failed"))
	assert.Equal(t, 1, w.h.audits("deployment.rollout_failed"))
	w.advance()
	assert.Equal(t, 1, w.h.audits("deployment.rollout_check_failed"), "once")
}

// CAN-23 (Review Focus 1): a wave-1 deployment still sending when the rollout is aborted holds after the verdict; the
// next advance reverts it.
func TestRolloutRevertsAHoldThatArrivesAfterTheVerdict(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), canaryTenMinutes)
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2}})
	require.NoError(t, err)
	f.start(got[0].ID) // deploying: a send may be under way
	_, err = f.h.db.Owner.Exec(f.h.ctx, `UPDATE deployment_rollouts SET state = 'aborted', reason = 'canary.aborted', finished_at = now()
WHERE id = $1`, r.ID)
	require.NoError(t, err)
	require.NoError(t, f.succeed(got[0].ID, stringOf('e', 64)))
	require.Equal(t, inventory.DeployStateHolding, f.get(got[0].ID).State, "the engine always holds; the canary decides")
	_, err = f.h.svc.AdvanceRollouts(f.h.ctx)
	require.NoError(t, err)
	d := f.get(got[0].ID)
	assert.Equal(t, inventory.DeployStateRecovering, d.State)
	assert.Equal(t, inventory.ReasonCanaryAborted, d.RevertReason)
}

// lockDueGate answers a transient refusal (lock_due) for changes.
type lockDueGate struct{ inventory.LicenseGate }

func (g lockDueGate) Allow(c license.Class) error {
	if c == license.ClassChange {
		return license.ErrLockDue
	}
	return g.LicenseGate.Allow(c)
}

// CAN-24 (Review Focus 4): the licence locks during a person's hold: wave 1 is released and stays, wave 2 is not
// started, the rollout stops with one e-mail; a transient answer waits CanaryGateWait first.
func TestManualRolloutStopsAfterWaveOneInLock(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.passHold()
	lock := &lockableLicense{LicenseGate: w.h.lic}
	lock.locked.Store(true)
	_, err := w.h.svcWith(lock).AdvanceRollouts(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatusSucceeded, w.get(w.hold).Status, "wave 1 passed and stays")
	assert.Empty(t, w.wave2())
	r := w.read()
	assert.Equal(t, inventory.RolloutStopped, r.State)
	assert.Equal(t, inventory.RolloutReasonLicenseLocked, r.Reason)
	assert.Equal(t, 1, w.h.audits("deployment.rollout_stopped"))
	assert.Positive(t, w.h.emails(inventory.TemplateDeploymentRolloutStopped))
	sent := w.h.emails(inventory.TemplateDeploymentRolloutStopped)
	_, err = w.h.svcWith(lock).AdvanceRollouts(w.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, sent, w.h.emails(inventory.TemplateDeploymentRolloutStopped), "once")

	v := newCanaryWorld(t, canaryTenMinutes)
	v.passHold()
	due := v.h.svcWith(lockDueGate{LicenseGate: v.h.lic})
	_, err = due.AdvanceRollouts(v.h.ctx)
	require.NoError(t, err)
	r = v.read()
	assert.Equal(t, inventory.RolloutHold, r.State, "a transient answer waits")
	require.NotNil(t, r.GateWaitingSince)
	assert.Equal(t, inventory.DeployStateHolding, v.get(v.hold).State)
	v.h.clock.Advance(30 * time.Minute)
	_, err = due.AdvanceRollouts(v.h.ctx)
	require.NoError(t, err)
	assert.Equal(t, inventory.RolloutHold, v.read().State)
	v.h.clock.Advance(31 * time.Minute)
	_, err = due.AdvanceRollouts(v.h.ctx)
	require.NoError(t, err)
	r = v.read()
	assert.Equal(t, inventory.RolloutStopped, r.State)
	assert.Equal(t, "lock_due", r.Reason)
	assert.Equal(t, inventory.DeployStatusSucceeded, v.get(v.hold).Status)
}

// CAN-25: wave 2 checks every location again; a refused one is skipped with its reason, the others are deployed.
func TestWaveTwoRechecksEachLocation(t *testing.T) {
	f := newDeployFixture(t)
	f.h.setPolicy(f.h.defaultService(), `{"schema":1,"canary":{"enabled":true,"hold":"10m","first":["`+f.loc1.String()+`"]}}`)
	got, r, err := f.h.svc.RequestDeploymentWithRollout(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc5, f.loc2}})
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{f.loc1}, r.Wave1)
	w := &canaryWorld{deployFixture: f, rollout: *r, hold: got[0].ID}
	f.start(w.hold)
	require.NoError(t, f.succeed(w.hold, stringOf('e', 64)))
	w.passHold()
	f.setTargetStatus(f.target2, inventory.StatusDisabled)
	w.advance()
	two := w.wave2()
	require.Len(t, two, 1)
	assert.Equal(t, f.loc5, two[0].LocationID)
	read := w.read()
	assert.Equal(t, []inventory.RolloutSkip{{LocationID: f.loc2, Reason: "target_disabled"}}, read.Skipped)
	denied := f.h.auditDetails("deployment.denied")
	require.Len(t, denied, 1)
	assert.Equal(t, "target_disabled", denied[0]["reason"])
	assert.Equal(t, f.loc2.String(), denied[0]["location_id"])
	assert.Equal(t, 1, f.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND actor_type = 'system'"))
}

// Two advancers never move one rollout twice.
func TestTwoAdvancersDoNotDoubleTransition(t *testing.T) {
	w := newCanaryWorld(t, canaryTenMinutes)
	w.passHold()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.h.svc.AdvanceRollouts(context.Background())
		}()
	}
	wg.Wait()
	w.advance()
	assert.Equal(t, 1, w.h.audits("deployment.rollout_released"))
	assert.Equal(t, 1, w.h.audits("deployment.rollout_wave2_started"))
	assert.Len(t, w.wave2(), 2)
}

// Review Focus 2: a round dials the location's server (its host), on the location's SSL port, with the check's path,
// the deployed leaf expected and the name the post-deploy probe sends; a policy's host and port win.
func TestRoundUsesTheLocationsVerifyAddress(t *testing.T) {
	w := newCanaryWorld(t, `{"schema":1,"canary":{"enabled":true,"hold":"10m","check":{"path":"/healthz"}}}`)
	tg, err := w.h.svc.GetTarget(w.h.ctx, w.get(w.hold).TargetID)
	require.NoError(t, err)
	got, err := w.h.svc.CanaryRoundTarget(w.h.ctx, w.hold)
	require.NoError(t, err)
	require.NotNil(t, got.Check)
	assert.Equal(t, tg.Host, got.Check.Address)
	assert.Equal(t, 443, got.Check.Port)
	assert.Equal(t, "www.example.test", got.Check.ServerName)
	assert.Equal(t, "/healthz", got.Check.Path)
	assert.Equal(t, []int{200}, got.Check.ExpectStatus)
	assert.Equal(t, 5*time.Second, got.Check.Timeout)
	assert.Equal(t, w.cert.Fingerprint, got.Check.ExpectLeafSHA256)
	assert.Equal(t, w.cert.Fingerprint, got.Verify.Fingerprint)
	assert.Equal(t, w.rollout.ID, got.RolloutID)

	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificate_locations SET verify_port = 8443, verify_sni = 'probe.example.test' WHERE id = $1",
		w.get(w.hold).LocationID)
	require.NoError(t, err)
	got, err = w.h.svc.CanaryRoundTarget(w.h.ctx, w.hold)
	require.NoError(t, err)
	assert.Equal(t, 8443, got.Check.Port)
	assert.Equal(t, "probe.example.test", got.Check.ServerName)

	_, err = w.h.db.Owner.Exec(w.h.ctx, `UPDATE deployment_rollouts SET settings = jsonb_set(jsonb_set(settings, '{check,port}', '9443'),
'{check,host}', '"app.example.test"') WHERE id = $1`, w.rollout.ID)
	require.NoError(t, err)
	got, err = w.h.svc.CanaryRoundTarget(w.h.ctx, w.hold)
	require.NoError(t, err)
	assert.Equal(t, 9443, got.Check.Port)
	assert.Equal(t, "app.example.test", got.Check.ServerName, "the policy's host is a name only")
	assert.Equal(t, tg.Host, got.Check.Address, "never the policy's host")

	// A deployment that does not hold has no round.
	done := w.deploying(w.loc4)
	_, err = w.h.svc.CanaryRoundTarget(w.h.ctx, done)
	assert.ErrorIs(t, err, inventory.ErrDeploymentState)
	// A round recorded for a deployment that no longer holds is ignored.
	require.NoError(t, w.h.svc.RecordCanaryRound(w.h.ctx, done, inventory.CanaryRound{Result: inventory.RoundFail}))
	assert.Error(t, w.h.svc.RecordCanaryRound(w.h.ctx, w.hold, inventory.CanaryRound{Result: "maybe"}))
}
