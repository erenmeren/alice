//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/sshkeys"
)

func TestPolicyDefaults(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	p, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "CI key", IntervalDays: 90, OverlapDays: 7})
	require.NoError(t, err)
	assert.False(t, p.Enabled, "off by default")
	assert.Equal(t, 7*1440, p.OverlapMinutes)
	assert.Equal(t, 24, p.NotifyBeforeHours)
	assert.Equal(t, "same", p.NewKeyType)
	assert.Nil(t, p.NextRunAt)
	assert.Nil(t, p.OpenRotationID)
	assert.Equal(t, 1, p.Version)
	assert.Equal(t, k.ID, p.SSHKeyID)
	assert.Equal(t, 1, e.audits("rotation.policy_created"))
	assert.Equal(t, "10080", e.lastAuditDetail("rotation.policy_created", "overlap_minutes"))
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "again", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrPolicyExists)
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, p.ID, *got.PolicyID)
	list, err := e.svc.Policies(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, []sshkeys.Policy{p}, list)
	_, err = e.svc.Policy(e.ctx, uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	e.gate.lock()
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: e.generateUnlocked("x"), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, license.ErrLocked)
}

func TestPolicyOnlyForGeneratedKeys(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: e.platformKeyRow(), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrOwnKeyProtected, "F-36 for rotation")
	assert.Equal(t, "own_key", e.lastAuditDetail("rotation.policy.denied", "reason"))
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: e.discoveredKey(), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	assert.Equal(t, "not_managed", e.lastAuditDetail("rotation.policy.denied", "reason"))
	k := e.generate("old")
	e.retire(k.ID)
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	assert.Equal(t, "retired", e.lastAuditDetail("rotation.policy.denied", "reason"))
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: uuid.New(), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	assert.Equal(t, 3, e.audits("rotation.policy.denied"))
	assert.Zero(t, e.count("SELECT count(*) FROM rotation_policies"))
}

// S9: the new key of a live run gets no policy of its own (the run's completion moves the old
// key's policy onto it).
func TestNoPolicyForTheNewKeyOfALiveRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	require.NotNil(t, r.NewKeyID)
	_, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: *r.NewKeyID, Name: "new", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotation_policies"))
}

func TestPolicyValidationAndVersions(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	for _, c := range []struct {
		in    sshkeys.PolicyInput
		field string
	}{
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "", IntervalDays: 90}, "name"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "a\u202eb", IntervalDays: 90}, "name"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 0}, "interval_days"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 3651}, "interval_days"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, OverlapDays: 91}, "overlap_days"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, OverlapDays: -1}, "overlap_days"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, NotifyBeforeHours: 169}, "notify_before_hours"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, NotifyBeforeHours: -1}, "notify_before_hours"},
		{sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, NewKeyType: "dsa"}, "new_key_type"},
	} {
		_, err := e.svc.CreatePolicy(e.ctx, e.admin, c.in)
		var verr validate.Errors
		require.ErrorAs(t, err, &verr, "%+v", c.in)
		assert.Equal(t, c.field, verr[0].Field, "%+v", c.in)
	}
	p, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, OverlapDays: 0,
		NewKeyType: "rsa-3072"})
	require.NoError(t, err)
	assert.Zero(t, p.OverlapMinutes, "an overlap of 0 is allowed (§7.3 CHECK overlap_days >= 0)")
	assert.Equal(t, "rsa-3072", p.NewKeyType)
	name := "renamed"
	p2, err := e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p.Version, sshkeys.PolicyPatch{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, 2, p2.Version)
	assert.Equal(t, "renamed", p2.Name)
	assert.Equal(t, "renamed", e.lastAuditDetail("rotation.policy_updated", "name"))
	assert.Equal(t, "", e.lastAuditDetail("rotation.policy_updated", "interval_days"), "only the changed fields")
	_, err = e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p.Version, sshkeys.PolicyPatch{Name: &name})
	assert.ErrorIs(t, err, sshkeys.ErrVersionMismatch)
	bad := 0
	_, err = e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p2.Version, sshkeys.PolicyPatch{IntervalDays: &bad})
	var verr validate.Errors
	assert.ErrorAs(t, err, &verr)
	days, hours, typ := 10, 48, "same"
	p3, err := e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p2.Version, sshkeys.PolicyPatch{OverlapDays: &days, NotifyBeforeHours: &hours,
		NewKeyType: &typ})
	require.NoError(t, err)
	assert.Equal(t, 10*1440, p3.OverlapMinutes)
	assert.Equal(t, 48, p3.NotifyBeforeHours)
	assert.Equal(t, "same", p3.NewKeyType)
	assert.Equal(t, "14400", e.lastAuditDetail("rotation.policy_updated", "overlap_minutes"))
	same, err := e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p3.Version, sshkeys.PolicyPatch{OverlapDays: &days})
	require.NoError(t, err)
	assert.Equal(t, p3.Version, same.Version, "nothing changed: no new version")
	_, err = e.svc.UpdatePolicy(e.ctx, e.admin, uuid.New(), 1, sshkeys.PolicyPatch{Name: &name})
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
}

// S2: an edit of what an enabled policy does switches it off (switching on again needs an
// Administrator with step-up, SetPolicyEnabled); a name-only edit leaves it on.
func TestEditOfEnabledPolicySwitchesItOff(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	name := "renamed"
	p, err := e.svc.UpdatePolicy(e.ctx, e.operator, p.ID, p.Version, sshkeys.PolicyPatch{Name: &name})
	require.NoError(t, err)
	assert.True(t, p.Enabled, "a name-only edit leaves it on")
	require.NotNil(t, p.NextRunAt)
	e.clock.Advance(89 * 24 * time.Hour)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	p = e.reloadPolicy(p.ID)
	for _, patch := range []func(v *sshkeys.PolicyPatch){
		func(v *sshkeys.PolicyPatch) { d := 1; v.IntervalDays = &d },
		func(v *sshkeys.PolicyPatch) { d := 0; v.OverlapDays = &d },
		func(v *sshkeys.PolicyPatch) { h := 1; v.NotifyBeforeHours = &h },
		func(v *sshkeys.PolicyPatch) { s := "rsa-4096"; v.NewKeyType = &s },
	} {
		if !p.Enabled {
			p, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
			require.NoError(t, err)
		}
		var v sshkeys.PolicyPatch
		patch(&v)
		before := e.audits("rotation.policy_disabled")
		p, err = e.svc.UpdatePolicy(e.ctx, e.operator, p.ID, p.Version, v)
		require.NoError(t, err)
		assert.False(t, p.Enabled, "%+v", v)
		assert.Nil(t, p.NextRunAt)
		assert.Equal(t, before+1, e.audits("rotation.policy_disabled"))
		assert.Equal(t, "edited", e.lastAuditDetail("rotation.policy_disabled", "reason"))
	}
	r := e.onlyRun(p.ID)
	assert.Equal(t, "cancelled", r.Status, "the previewed run is cancelled with the policy")
	assert.Equal(t, "rotation.policy_off", r.ResultCode)
	assert.Equal(t, 1, p.IntervalDays)
	assert.Equal(t, "rsa-4096", p.NewKeyType)
}

func TestEnableSetsTheFirstRunAndDisableCancelsAPreview(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	e.gate.lock()
	_, err := e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	assert.ErrorIs(t, err, license.ErrLocked)
	e.gate.unlock()
	p, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	require.NoError(t, err)
	assert.True(t, p.Enabled)
	assert.Equal(t, e.clock.Now().Add(90*24*time.Hour), *p.NextRunAt)
	assert.Equal(t, 1, e.audits("rotation.policy_enabled"))
	_, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version-1, false)
	assert.ErrorIs(t, err, sshkeys.ErrVersionMismatch)
	e.clock.Advance(89 * 24 * time.Hour) // notice due
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	p = e.reloadPolicy(p.ID)
	require.NotNil(t, p.OpenRotationID)
	p, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, false)
	require.NoError(t, err)
	assert.False(t, p.Enabled)
	assert.Nil(t, p.NextRunAt)
	assert.Nil(t, p.OpenRotationID)
	r := e.onlyRun(p.ID)
	assert.Equal(t, "cancelled", r.Status)
	assert.Equal(t, "rotation.policy_off", r.ResultCode)
	require.NotNil(t, r.FinishedAt)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotation_locations WHERE state = 'cancelled'"))
	assert.Equal(t, "cancelled", e.lastAuditDetail("rotation.status_changed", "to"))
	assert.Equal(t, "rotation.policy_off", e.lastAuditDetail("rotation.status_changed", "reason"))
	assert.Equal(t, "cancelled", e.lastAuditDetail("rotation.location_changed", "to"))
	assert.Equal(t, "cancelled", r.Steps[len(r.Steps)-1].Name)
}

func TestDeleteRefusedWhileARunIsStarted(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	r := e.runNow(p) // preview + RunNow: the run starts (adding_new; location jobs queued)
	require.Equal(t, "adding_new", r.Status)
	err := e.svc.DeletePolicy(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version)
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
}

func TestDeletePolicyCancelsAPreview(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.ErrorIs(t, e.svc.DeletePolicy(e.ctx, e.admin, p.ID, p.Version-1), sshkeys.ErrVersionMismatch)
	require.NoError(t, e.svc.DeletePolicy(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version))
	_, err = e.svc.Policy(e.ctx, p.ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	assert.Equal(t, "cancelled", e.onlyRun(p.ID).Status)
	assert.Equal(t, 1, e.audits("rotation.policy_deleted"))
	// The key can get a new policy.
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "again", IntervalDays: 30})
	assert.NoError(t, err)
}

// A key that can no longer be rotated: switching on is refused by the database's key check, and a
// policy that is on is switched off by the planner (audited with the planner's reason).
func TestRetiredKeysPolicyCannotRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	q := e.enabledPolicy(e.deployed("ci2", e.server("web-02"), "deploy").ID, 90, 7, 24)
	e.retire(k.ID)
	_, err := e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	_, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	e.retire(q.SSHKeyID)
	e.clock.Advance(89 * 24 * time.Hour)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	q = e.reloadPolicy(q.ID)
	assert.False(t, q.Enabled)
	assert.Nil(t, q.NextRunAt)
	assert.Equal(t, "retired", e.lastAuditDetail("rotation.policy_disabled", "reason"))
	_, err = e.svc.RunNow(e.ctx, e.admin, uuid.New(), "x")
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	assert.ErrorIs(t, e.svc.Advance(e.ctx, uuid.New()), sshkeys.ErrNotFound)
	_, err = e.svc.Rotation(e.ctx, uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
}
