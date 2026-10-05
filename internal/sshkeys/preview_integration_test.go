//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

func TestPreviewEmailsAdmins(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.True(t, pv.Emailed)
	assert.Equal(t, 1, pv.Plan.Changes)
	assert.Regexp(t, `^[0-9a-f]{64}$`, pv.Digest)
	assert.Equal(t, pv.Plan.Digest(), pv.Digest)
	assert.Equal(t, e.clock.Now(), pv.PlannedFor, "a policy that is off previews for now")
	m := e.mails("rotation.preview")
	require.Len(t, m, 1)
	assert.Equal(t, map[string]string{"key_label": "ci", "fingerprint": k.Fingerprint, "planned_for": "2026-10-05 12:00 UTC",
		"change_count": "1", "skip_count": "0"}, m[0])
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'rotation.preview'"))
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.False(t, pv.Emailed, "at most one email per policy per 10 minutes")
	e.clock.Advance(10 * time.Minute)
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.True(t, pv.Emailed)
	assert.Equal(t, 3, e.audits("rotation.previewed"))
	assert.Equal(t, "true", e.lastAuditDetail("rotation.previewed", "emailed"))
	assert.Equal(t, pv.Digest, e.lastAuditDetail("rotation.previewed", "plan_digest"))
	assert.Zero(t, e.count("SELECT count(*) FROM rotations"), "a preview creates no run")
	// An enabled policy previews for its next run.
	p, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version, true)
	require.NoError(t, err)
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.Equal(t, *p.NextRunAt, pv.PlannedFor)
}

func TestPreviewRefusedInLockSendsNothing(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	e.gate.lock()
	_, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Empty(t, e.mails("rotation.preview"))
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, "x")
	assert.ErrorIs(t, err, license.ErrLocked)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestPreviewShowsSkipsWhenNothingCanChange(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	e.setTargetStatus(srv, "unreachable")
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.Zero(t, pv.Plan.Changes)
	assert.Equal(t, plan.SkipTargetNotConnected, pv.Plan.Actions[0].Skip)
	assert.Equal(t, "1", e.mails("rotation.preview")[0]["skip_count"])
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrNothingToRotate)
	// A scheduled plan with nothing to change creates no run and sends no email.
	p, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version, true)
	require.NoError(t, err)
	e.clock.Advance(89 * 24 * time.Hour)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Len(t, e.mails("rotation.preview"), 1)
	assert.Len(t, e.mails("rotation.nothing_to_rotate"), 1, "told once for the interval (re-review M6)")
	assert.True(t, e.reloadPolicy(p.ID).Enabled, "the policy stays on; the next interval plans again")
}

// The planner's skip reasons pass through as the planner names them (no closed list here):
// a location in a file the connection account reads is skipped, the other one changes.
func TestPreviewCarriesThePlannersSkips(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.addLocation(k.ID, srv, "root")
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE targets SET facts = jsonb_set(facts, '{sshd,PermitRootLogin}', '"forced-commands-only"') WHERE id = $1`, srv)
	require.NoError(t, err)
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	require.Len(t, pv.Plan.Actions, 2)
	skips := map[string]string{}
	for _, a := range pv.Plan.Actions {
		skips[a.OSUser] = a.Skip
	}
	assert.Equal(t, map[string]string{"deploy": "", "root": plan.SkipRootForcedCommands}, skips)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	states := map[string]string{}
	for _, l := range r.Locations {
		states[l.OSUser] = l.State + "/" + l.SkipReason
	}
	assert.Equal(t, map[string]string{"deploy": "planned/", "root": "skipped/root_forced_commands_only"}, states)
}

// §13.6 item 1: the scheduled run is created only together with its notice, and starts only after it.
func TestScheduledRunNotifiesBeforeStart(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24) // next run at +90 d
	e.clock.Advance(89*24*time.Hour - time.Second)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "the notice is not due yet")
	e.clock.Advance(time.Second)
	n, err = e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	r := e.onlyRun(p.ID)
	assert.Equal(t, "dry_run_notified", r.Status)
	assert.Equal(t, "scheduled", r.Trigger)
	assert.Equal(t, e.clock.Now(), r.NotifiedAt)
	assert.Equal(t, e.clock.Now().Add(24*time.Hour), r.PlannedFor)
	assert.Equal(t, r.Plan.Digest(), r.Digest)
	require.Len(t, r.Locations, 1)
	assert.Equal(t, "planned", r.Locations[0].State)
	require.Len(t, r.Steps, 1)
	assert.Equal(t, "dry_run_notified", r.Steps[0].Name)
	m := e.mails("rotation.preview")
	require.Len(t, m, 1, "the notice was queued with the run")
	assert.Equal(t, r.ID.String(), m[0]["rotation_id"])
	assert.Equal(t, "2027-01-03 12:00 UTC", m[0]["planned_for"])
	assert.Equal(t, 1, e.audits("rotation.created"))
	assert.Equal(t, "scheduled", e.lastAuditDetail("rotation.created", "trigger"))
	n, err = e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "one open run per policy")
	// Before planned_for nothing starts.
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "dry_run_notified", e.run(r.ID).Status)
}

// S1 with review M1 and M4: a scheduled run starts only after its rotation.preview was delivered to
// at least one Administrator no later than planned_for (sent at planned_for counts; a second later
// does not); skipped_no_smtp, pending and failed are not delivered. Without such a delivery the run is
// cancelled at planned_for (rotation.notice_undelivered) and counts as that interval's run: the next
// run is planned one interval later. Run now is exempt.
func TestScheduledStartWaitsForADeliveredNotice(t *testing.T) {
	scheduled := func(t *testing.T) (*env, sshkeys.Policy, sshkeys.Rotation) {
		e := newEnv(t)
		e.tick.on.Store(true)   // a clock that moves between reads (re-review C1)
		e.user("ada2", "admin") // a second Administrator: one delivered copy is enough
		k := e.deployed("ci", e.server("web-01"), "deploy")
		p := e.enabledPolicy(k.ID, 90, 7, 24)
		e.clock.Advance(89 * 24 * time.Hour)
		_, err := e.svc.PlanDue(e.ctx)
		require.NoError(t, err)
		r := e.onlyRun(p.ID)
		require.Equal(t, 2, e.count("SELECT count(*) FROM notifications_outbox WHERE params->>'rotation_id' = $1", r.ID.String()))
		// An on-demand preview's delivered email is not this run's notice.
		_, err = e.svc.Preview(e.ctx, e.admin, p.ID)
		require.NoError(t, err)
		_, err = e.db.Owner.Exec(e.ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $1 WHERE NOT params ? 'rotation_id'`,
			e.clock.Now())
		require.NoError(t, err)
		return e, p, r
	}
	setOne := func(e *env, r sshkeys.Rotation, status string, sentAt *time.Time) {
		_, err := e.db.Owner.Exec(e.ctx, `UPDATE notifications_outbox SET status = $2, sent_at = $3 WHERE id = (SELECT id
FROM notifications_outbox WHERE params->>'rotation_id' = $1 ORDER BY id LIMIT 1)`, r.ID.String(), status, sentAt)
		require.NoError(e.t, err)
	}

	t.Run("delivered at planned_for", func(t *testing.T) {
		e, _, r := scheduled(t)
		at := r.PlannedFor
		setOne(e, r, "sent", &at)
		e.clock.Set(r.PlannedFor)
		require.NoError(t, e.svc.Advance(e.ctx, r.ID))
		assert.Equal(t, "adding_new", e.run(r.ID).Status, "one copy delivered in time")
		assert.Equal(t, 1, e.jobsOf("add"))
	})
	for _, c := range []struct {
		status string
		late   time.Duration // sent_at - planned_for
	}{{"pending", 0}, {"skipped_no_smtp", 0}, {"failed", 0}, {"sent", time.Second}} {
		t.Run(c.status, func(t *testing.T) {
			e, p, r := scheduled(t)
			next := *p.NextRunAt
			if c.status == "sent" {
				at := r.PlannedFor.Add(c.late)
				setOne(e, r, "sent", &at)
				e.clock.Set(at)
			} else {
				setOne(e, r, c.status, nil)
				e.clock.Set(r.PlannedFor)
			}
			require.NoError(t, e.svc.Advance(e.ctx, r.ID))
			got := e.run(r.ID)
			assert.Equal(t, "cancelled", got.Status)
			assert.Equal(t, sshkeys.ReasonNoticeUndelivered, got.ResultCode)
			pol := e.reloadPolicy(p.ID)
			assert.Equal(t, next.Add(90*24*time.Hour), *pol.NextRunAt, "the next run is the next interval's (M4)")
			assert.Equal(t, "cancelled", pol.LastRunStatus)
			assert.Equal(t, "rotation.notice_undelivered", pol.LastRunResult)
			n, err := e.svc.PlanDue(e.ctx)
			require.NoError(t, err)
			assert.Zero(t, n, "no new run in the same interval")
		})
	}
	t.Run("run now is exempt", func(t *testing.T) {
		e, p, r := scheduled(t)
		started, err := e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
		require.NoError(t, err)
		assert.Equal(t, "adding_new", started.Status)
	})
}

// Review M3: when Run now cannot start the run it created (here: every generation slot is taken), that
// run is cancelled in the same call; a previewed scheduled run it tried to start early stays as it was.
func TestRunNowThatCannotStartLeavesNothingBehind(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	release := sshkeys.HoldGenerationSlots(t)
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrGenerateBusy)
	got := e.onlyRun(p.ID)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.start_failed", got.ResultCode)
	release()

	e2 := newEnv(t)
	k2 := e2.deployed("ci", e2.server("web-01"), "deploy")
	p2 := e2.enabledPolicy(k2.ID, 90, 7, 24)
	e2.clock.Advance(89 * 24 * time.Hour)
	_, err = e2.svc.PlanDue(e2.ctx)
	require.NoError(t, err)
	r2 := e2.onlyRun(p2.ID)
	release = sshkeys.HoldGenerationSlots(t)
	_, err = e2.svc.RunNow(e2.ctx, e2.admin, p2.ID, r2.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrGenerateBusy)
	release()
	assert.Equal(t, "dry_run_notified", e2.run(r2.ID).Status, "the scheduled run stays scheduled")
}

// Review M5 and M6: a preview never announces a start in the past; the 10-minute mail limit belongs to
// the key, so deleting and re-creating the policy does not bypass it.
func TestPreviewTimeAndMailLimitPerKey(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 1, 7, 24) // next run in one day; notice 24 h
	e.clock.Advance(23 * time.Hour)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.Equal(t, e.clock.Now().Add(24*time.Hour), pv.PlannedFor, "the full notice period from now")
	require.True(t, pv.Emailed)
	require.NoError(t, e.svc.DeletePolicy(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version))
	q := e.policy(k.ID, 90, 7, 24)
	pv, err = e.svc.Preview(e.ctx, e.admin, q.ID)
	require.NoError(t, err)
	assert.False(t, pv.Emailed, "the same key within 10 minutes")
}

// In lock a previewed run is cancelled at its start (L-88); its plan changing cancels it too.
func TestScheduledStartCancelledInLockOrWhenThePlanChanged(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "rotation.cancelled_license", e.run(r.ID).ResultCode)
	e.gate.unlock()

	e.clock.Advance(time.Minute)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	id := e.openRun(p.ID)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE notifications_outbox SET status = 'sent', sent_at = $1", e.clock.Now())
	require.NoError(t, err)
	e.addLocation(k.ID, e.server("web-02"), "deploy")
	e.clock.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	got := e.run(id)
	assert.Equal(t, "cancelled", got.Status)
	assert.Equal(t, "rotation.plan_changed", got.ResultCode)
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_keys WHERE rotated_from = $1", k.ID), "no new key was stored")
}

func TestRunNowNeedsThePreviewedDigest(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	e.addLocation(k.ID, e.server("web-02"), "deploy") // the fleet changes after the preview
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrPlanChanged)
	assert.Zero(t, e.count("SELECT count(*) FROM rotations"))
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	assert.Equal(t, "adding_new", r.Status)
	assert.Equal(t, "manual", r.Trigger)
	assert.Equal(t, pv.Digest, r.Digest)
	assert.Len(t, r.Locations, 2)
	assert.Equal(t, 2, e.count("SELECT count(*) FROM jobs WHERE type = 'rotation.location'"))
	require.NotNil(t, r.NewKeyID)
	require.NotNil(t, r.StartedAt)
	nk, err := e.svc.ManagedKey(e.ctx, *r.NewKeyID)
	require.NoError(t, err)
	assert.Equal(t, k.ID, *nk.RotatedFrom)
	assert.Equal(t, "ci", nk.Label)
	assert.Equal(t, "alice:ci:2026-10-05", nk.Comment)
	assert.NotEqual(t, k.Fingerprint, nk.Fingerprint)
	assert.Equal(t, nk.Fingerprint, r.NewFingerprint)
	assert.Equal(t, k.Fingerprint, r.OldFingerprint)
	var payload map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT payload FROM jobs WHERE type = 'rotation.location' LIMIT 1").Scan(&payload))
	assert.Equal(t, r.ID.String(), payload["rotation_id"])
	assert.Equal(t, "add", payload["phase"])
	assert.Equal(t, "adding_new", e.lastAuditDetail("rotation.status_changed", "to"))
	assert.Equal(t, 1, e.audits("rotation.created"))
	assert.Equal(t, "manual", e.lastAuditDetail("rotation.created", "trigger"))
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
}

func TestRunNowStartsAPreviewedScheduledRun(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	other := "0" + r.Digest[1:]
	if other == r.Digest {
		other = "1" + r.Digest[1:]
	}
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, other)
	assert.ErrorIs(t, err, sshkeys.ErrPlanChanged, "another digest than the previewed run's")
	started, err := e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
	require.NoError(t, err)
	assert.Equal(t, r.ID, started.ID, "the previewed run starts, no second run")
	assert.Equal(t, "adding_new", started.Status)
	assert.Equal(t, e.clock.Now().Add(90*24*time.Hour), *e.reloadPolicy(p.ID).NextRunAt, "the next run counts from this start")
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
}

// A previewed scheduled run whose servers changed is not started by Run now with the old digest,
// and is not silently re-planned.
func TestRunNowRefusesAScheduledRunWhosePlanChanged(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	e.addLocation(k.ID, e.server("web-02"), "deploy")
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrPlanChanged)
	assert.Equal(t, "dry_run_notified", e.run(r.ID).Status, "nothing changed")
}
