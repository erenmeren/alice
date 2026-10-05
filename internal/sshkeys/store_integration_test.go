//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// The whole happy path through the store, by hand: add, verify, overlap, re-verify, remove.
func TestRotationHappyPathThroughTheStore(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 1, 24) // overlap 1 day
	r := e.runNow(p)
	loc := r.Locations[0].ID
	w, err := e.svc.LocationWork(e.claimed(), loc)
	require.NoError(t, err)
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(w.NewLine))
	require.NoError(t, err)
	assert.Equal(t, w.NewFingerprint, ssh.FingerprintSHA256(pk), "the line carries the new key")
	assert.Equal(t, "alice:ci:2026-10-05", comment)
	assert.Equal(t, k.Fingerprint, w.OldFingerprint)
	assert.Equal(t, loc, w.Location.ID)
	op, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, op)
	again, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	assert.Equal(t, op, again, "a resumed add keeps its operation id")
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", w.NewKeyID), "the new line is recorded")
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status)
	assert.Equal(t, e.clock.Now().Add(24*time.Hour), *r.OverlapUntil)
	assert.Len(t, e.mails("rotation.overlap_started"), 1)

	_, err = e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "no removal during the overlap")
	e.clock.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "removing_old", e.run(r.ID).Status)
	assert.Equal(t, 1, e.jobsOf("remove"))
	_, err = e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "no removal without a fresh login")
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	rop, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, rop)
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Removed: 1,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "completed", r.Status)
	assert.Zero(t, r.KeptCount)
	assert.Equal(t, *r.NewKeyID, e.reloadPolicy(p.ID).SSHKeyID, "the policy follows the new key")
	old, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.NotNil(t, old.RetiredAt, "no live location left: retired")
	assert.Equal(t, 1, e.audits("sshkey.retired"))
	assert.Len(t, e.mails("rotation.completed"), 1)
	assert.GreaterOrEqual(t, len(r.Steps), 8, "every transition is a recorded step (§26.8)")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", k.ID))
}

func TestBeginRemoveRefusals(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r, loc := e.runInRemoving(k)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	e.clock.Advance(15*time.Minute + time.Second)
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a re-verification older than 15 minutes is stale")
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	e.gate.lock()
	_, err = e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrPaused)
	e.gate.unlock()
	_, err = e.svc.BeginRemove(e.lostClaim(), loc)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	// The new key's line disappeared (someone deleted it, a scan marked it missing): no removal.
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET missing_since = $2 WHERE id = (SELECT new_location_id
FROM rotation_locations WHERE id = $1)`, loc, e.clock.Now())
	require.NoError(t, err)
	_, err = e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET missing_since = NULL WHERE id = (SELECT new_location_id
FROM rotation_locations WHERE id = $1)`, loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.Advance(e.ctx, r))
	op, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	// A resumed removal re-checks and re-sends with the same operation id.
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	op2, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	assert.Equal(t, op, op2)
	assert.Equal(t, "removing", e.locState(e.run(r), "deploy"))
	// Not from verified (A4): FinishRemove needs removing.
	assert.ErrorIs(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), uuid.New(), sshkeys.RemoveRecord{Definite: true}), sshkeys.ErrNotFound)
}

// F3 and G3: a failed re-check ends the location remove_failed (the old key stays); the sweep
// retries it, and a retry passes the same gate; a run whose failed removals are exhausted needs
// attention and counts them where the old key stays.
func TestReverifyFailureKeepsTheOldKeyAndIsRetried(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, loc := e.runInRemoving(k)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Reason: "ssh.unreachable"}))
	got := e.run(r)
	assert.Equal(t, "remove_failed", got.Locations[0].State)
	assert.Equal(t, "ssh.unreachable", got.Locations[0].ErrorCode)
	require.NoError(t, e.svc.Advance(e.ctx, r))
	assert.Equal(t, "removing_old", e.run(r).Status, "a failed removal is retried before the run needs attention")
	// A refused re-check on the failed location keeps it failed; nothing is written.
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginRefused}))
	assert.Equal(t, "remove_failed", e.run(r).Locations[0].State)
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a retry starts with an accepted re-check")
	// A retry: fresh re-check, then the gate.
	e.clock.Advance(time.Minute)
	e.removeAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, r))
	assert.Equal(t, "completed", e.run(r).Status)

	// Exhausted: the sweep re-queues MaxLocationJobs times, then the run needs attention.
	e2 := newEnv(t)
	k2 := e2.deployed("ci", e2.server("web-01"), "deploy")
	r2, loc2 := e2.runInRemoving(k2)
	require.NoError(t, e2.svc.RecordReverify(e2.claimed(), loc2, sshkeys.VerifyRecord{Outcome: providers.KeyLoginRefused}))
	for range sshkeys.MaxLocationJobs + 1 {
		_, err = e2.db.Owner.Exec(e2.ctx, "UPDATE jobs SET status = 'failed' WHERE type = 'rotation.location' AND payload ? 'phase' AND status = 'queued'")
		require.NoError(t, err)
		_, err = e2.svc.Sweep(e2.ctx)
		require.NoError(t, err)
	}
	got = e2.run(r2)
	assert.Equal(t, "needs_attention", got.Status)
	assert.Equal(t, "rotation.remove_incomplete", got.ResultCode)
	assert.Equal(t, 1, got.KeptCount, "the old key stays there")
	assert.Len(t, e2.mails("rotation.needs_attention"), 1)
	old, err := e2.svc.ManagedKey(e2.ctx, k2.ID)
	require.NoError(t, err)
	assert.Nil(t, old.RetiredAt)
}

func TestUndoNeverTouchesTheOldKey(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginRefused}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "rolling_back", e.run(r.ID).Status)
	assert.Equal(t, 1, e.jobsOf("undo"))
	w, err := e.svc.LocationWork(e.claimed(), loc)
	require.NoError(t, err)
	op, err := e.svc.BeginUndo(e.claimed(), loc)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, op)
	assert.NotEqual(t, w.OldFingerprint, w.NewFingerprint)
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1}}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.verify_failed", r.ResultCode)
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", k.ID),
		"the old key's location was never marked removed")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", w.NewKeyID),
		"the new key's line was removed")
	assert.Len(t, e.mails("rotation.aborted"), 1)
}

// S4 (F-67 path): the add's answer was lost; the login proves the line is there, so the inventory
// records the new key's location and the sshkey.added audit row.
func TestAddConfirmedOnlyByTheLoginIsRecorded(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: false}), "uncertain: stays adding")
	assert.Equal(t, "adding", e.locState(r, "deploy"))
	before := e.audits("sshkey.added")
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	got := e.run(r.ID)
	assert.Equal(t, "verified", got.Locations[0].State)
	require.NotNil(t, got.Locations[0].NewLocationID)
	assert.Equal(t, before+1, e.audits("sshkey.added"))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.added", "verified"))
}

// C8 verify rules (F2): unprovable → unverifiable (login_without_key); refused on a line with from=
// → unverifiable (from_option); a connection failure while adding → verify_failed with its reason.
func TestVerifyOutcomes(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.addLocation(k.ID, srv, "root")
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET options = 'from="10.0.0.0/8"' WHERE ssh_key_id = $1 AND os_user = 'root'`, k.ID)
	require.NoError(t, err)
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginUnprovable,
		"root": providers.KeyLoginRefused})
	assert.Equal(t, "verifying_new", r.Status)
	notes := map[string]string{}
	for _, l := range r.Locations {
		assert.Equal(t, "unverifiable", l.State)
		notes[l.OSUser] = l.VerifyNote
	}
	assert.Equal(t, map[string]string{"deploy": "login_without_key", "root": "from_option"}, notes)
	assert.Len(t, e.mails("rotation.decision_needed"), 1)
	assert.Equal(t, "2", e.mails("rotation.decision_needed")[0]["count"])
	assert.ErrorIs(t, e.svc.RecordVerify(e.claimed(), ids["deploy"], sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}),
		sshkeys.ErrNotYourTurn)

	e2 := newEnv(t)
	k2 := e2.deployed("ci", e2.server("web-01"), "deploy")
	r2 := e2.runNow(e2.policy(k2.ID, 90, 7, 24))
	loc := r2.Locations[0].ID
	_, err = e2.svc.BeginAdd(e2.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e2.svc.RecordVerify(e2.claimed(), loc, sshkeys.VerifyRecord{Reason: "ssh.unreachable"}))
	got := e2.run(r2.ID).Locations[0]
	assert.Equal(t, "verify_failed", got.State)
	assert.Equal(t, "ssh.unreachable", got.ErrorCode)
	assert.Error(t, e2.svc.RecordVerify(e2.claimed(), loc, sshkeys.VerifyRecord{}), "state checked first")
}

// A location the plan does not verify (root under PermitRootLogin no) is unverifiable once added.
func TestRootLoginDisabledIsUnverifiableAfterTheAdd(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE targets SET facts = jsonb_set(facts, '{sshd,PermitRootLogin}', '"no"') WHERE id = $1`, srv)
	require.NoError(t, err)
	k := e.deployed("ci", srv, "root")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{})
	assert.Equal(t, "unverifiable", r.Locations[0].State)
	assert.Equal(t, "root_login_disabled", r.Locations[0].VerifyNote)
	assert.Equal(t, "verifying_new", r.Status)
}

// S3: the undo of an add that never had a definite answer waits until add_sent_at + the helper's
// budget + 30 s: a stalled helper may still write until then.
func TestUndoWaitsAfterAnUncertainAdd(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	assert.Equal(t, "rolling_back", e.run(r.ID).Status)
	assert.ErrorIs(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true}), sshkeys.ErrNotYourTurn,
		"adds only while adding_new (G8): the undo takes over")
	e.clock.Advance(helperproto.HelperBudget + 30*time.Second - time.Second)
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc), "the wait does not count toward the bound")
	e.clock.Advance(time.Second)
	e.undoAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "aborted", got.Status)
	assert.Equal(t, "rotation.stopped", got.ResultCode)
}

// S12 at the store: an undo that finds the old key gone sends nothing and ends undo_failed with
// rotation.old_key_gone (from undoing, or straight from a location pending its undo, G2); the run
// needs attention.
func TestUndoWhereTheOldKeyIsGone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.addLocation(k.ID, srv, "root")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted,
		"root": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	_, err := e.svc.BeginUndo(e.claimed(), ids["deploy"])
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), ids["deploy"], sshkeys.UndoRecord{Definite: true, Reason: sshkeys.ReasonOldKeyGone}))
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), ids["root"], sshkeys.UndoRecord{Definite: true, Reason: sshkeys.ReasonOldKeyGone}))
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), ids["root"], sshkeys.UndoRecord{Definite: false}), "uncertain: nothing")
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "needs_attention", got.Status)
	assert.Equal(t, "rotation.undo_failed", got.ResultCode)
	for _, l := range got.Locations {
		assert.Equal(t, "undo_failed", l.State)
		assert.Equal(t, "rotation.old_key_gone", l.ErrorCode)
	}
	assert.Equal(t, 2, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NULL", *got.NewKeyID),
		"nothing was removed: the new key's lines stay recorded")
	assert.Len(t, e.mails("rotation.needs_attention"), 1)
}

// Every store method refuses a step out of turn, writes nothing for a job that lost its claim, and
// rejects free text as a reason.
func TestStoreRefusesOutOfTurn(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	assert.ErrorIs(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true}), sshkeys.ErrNotYourTurn, "not adding")
	assert.ErrorIs(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}), sshkeys.ErrNotYourTurn)
	assert.ErrorIs(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}), sshkeys.ErrNotYourTurn)
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	assert.ErrorIs(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true}), sshkeys.ErrNotYourTurn)
	assert.ErrorIs(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true}), sshkeys.ErrNotYourTurn)
	_, err = e.svc.BeginAdd(e.lostClaim(), loc)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Equal(t, "planned", e.locState(r, "deploy"))
	e.gate.lock()
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrPaused)
	e.gate.unlock()
	_, err = e.svc.BeginAdd(e.claimed(), uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	_, err = e.svc.LocationWork(e.ctx, uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: false, Reason: "free text"}))
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, "add_failed", got.State)
	assert.Equal(t, "internal.unexpected", got.ErrorCode)
	assert.Error(t, e.svc.Step(e.claimed(), r.ID, nil, "Bad Name", providers.StepOK, nil))
	require.NoError(t, e.svc.Step(e.claimed(), r.ID, &loc, "add_sent", providers.StepStarted, map[string]string{"op": "x"}))
	assert.Equal(t, "add_sent", e.run(r.ID).Steps[len(e.run(r.ID).Steps)-1].Name)
	assert.ErrorIs(t, e.svc.Step(e.claimed(), uuid.New(), nil, "x", providers.StepOK, nil), sshkeys.ErrNotFound)
}

// A target whose host key changed after the start: the add is not sent and the location ends at once
// with the planner's skip reason (re-review M7).
func TestBeginAddOnAChangedHostKey(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	e.setTargetStatus(r.Locations[0].TargetID, "host_key_changed")
	_, err := e.svc.BeginAdd(e.claimed(), r.Locations[0].ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "the target refuses key changes")
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, "cancelled", got.State)
	assert.Equal(t, "host_key_changed", got.SkipReason)
}
