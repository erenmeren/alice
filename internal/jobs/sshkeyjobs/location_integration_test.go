//go:build integration

package sshkeyjobs_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// One rotation end to end through the real queue, three locations on two servers.
func TestRotationHappyPath(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, web, "app")
	e.place(k, db, "deploy")
	p := e.policy(k.ID, 1) // overlap 1 day
	r := e.runNow(p)
	e.drain() // three location jobs: add + verify each
	r = e.run(r.ID)
	require.Equal(t, "overlap", r.Status)
	newFP := r.NewFingerprint
	for _, f := range e.files(k) { // every (target, file) of the old key
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint), "the old key stays during the overlap")
		assert.True(t, e.world.Has(f.target, f.path, newFP))
	}
	assert.Equal(t, 3, e.countEvents("AddAuthorizedKey"))
	assert.Equal(t, 3, e.countEvents("VerifyKeyLogin"))
	assert.Equal(t, 3, e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.added' AND details->>'ssh_key_id' = $1",
		r.NewKeyID.String()), "every new line is recorded in the inventory")
	e.clock.Advance(24*time.Hour - time.Second)
	e.sweep()
	e.drain()
	assert.Equal(t, "overlap", e.run(r.ID).Status, "nothing before the overlap ends")
	e.clock.Advance(time.Second)
	e.sweep()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "completed", r.Status)
	for _, f := range e.files(k) {
		assert.False(t, e.world.Has(f.target, f.path, k.Fingerprint))
		assert.True(t, e.world.Has(f.target, f.path, newFP))
	}
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, newFP) // invariant I1 of Task 12
	assert.Equal(t, 3, e.removalsOf(k.Fingerprint))
	assert.Len(t, e.mails("rotation.completed"), 1)
	assert.Equal(t, 6, e.countEvents("VerifyKeyLogin"), "one login after each add, one before each removal")
}

func TestAddRefusedRollsBack(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" && p.Target == db {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.add_failed", r.ResultCode)
	for _, f := range e.files(k) {
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint), "old key untouched everywhere")
		assert.False(t, e.world.Has(f.target, f.path, r.NewFingerprint), "new key removed where this run added it")
	}
	assert.Zero(t, e.removalsOf(k.Fingerprint))
	assert.Equal(t, 1, e.removalsOf(r.NewFingerprint), "only web-01 held the new key")
	assert.Equal(t, "undone", e.loc(r.ID, db, "deploy").State, "nothing was there to remove")
	assert.Len(t, e.mails("rotation.aborted"), 1)
}

func TestUnverifiableWaitsForDecision(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.placeWithOptions(k, web, "deploy", `from="10.0.0.0/8"`)
	e.place(k, web, "app")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" && p.OSUser == "deploy" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 0))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "verifying_new", r.Status)
	assert.True(t, r.AwaitingDecision)
	assert.Equal(t, "unverifiable", e.loc(r.ID, web, "deploy").State)
	assert.Equal(t, "from_option", e.loc(r.ID, web, "deploy").VerifyNote)
	assert.Len(t, e.mails("rotation.decision_needed"), 1)
	assert.Zero(t, e.removalsOf(k.Fingerprint), "no removal while a decision is open")
	assert.Equal(t, 2, e.countEvents("AddAuthorizedKey"), "a definite add is never sent again")
}

func TestReverifyFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 0))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse // someone broke the new key during the overlap
		}
		return fake.FaultNone
	})
	e.clock.Advance(time.Minute)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.remove_incomplete", r.ResultCode)
	assert.Equal(t, "rotation.new_key_failed", e.loc(r.ID, web, "deploy").ErrorCode)
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "the old key stays")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Equal(t, 1, r.KeptCount)
	assert.Len(t, e.mails("rotation.needs_attention"), 1)
}

// Owner step 6: the network goes away in the middle of a rotation.
func TestOwnerStep6NetworkLoss(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	added := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Target == db && p.Method == "AddAuthorizedKey" {
			added++
			return fake.FaultAfterWrite // the line arrived, then the network went
		}
		if p.Target == db {
			return fake.FaultUnreachable
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.Equal(t, "rolling_back", e.run(r.ID).Status)
	assert.Equal(t, "undone", e.loc(r.ID, web, "deploy").State, "web-01's own addition is undone at once")
	assert.Equal(t, "verify_failed", e.loc(r.ID, db, "deploy").State, "the uncertain add waits out the helper's budget (S3)")
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.undo_failed", r.ResultCode, "the new key stays on db-01 until it can be reached")
	assert.True(t, e.world.Has(db, keyFile("deploy"), k.Fingerprint))
	assert.True(t, e.world.Has(db, keyFile("deploy"), r.NewFingerprint), "the uncertain line is still there")
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	assert.False(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint))
	assert.Equal(t, 1, added)
	assert.Equal(t, "undo_failed", e.loc(r.ID, db, "deploy").State)
	assert.Len(t, e.mails("rotation.needs_attention"), 1)
}

// The world deletes the new line during the overlap: the re-check is refused, the old key stays.
func TestNewKeyDeletedDuringOverlapKeepsOld(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	r = e.run(r.ID)
	require.Equal(t, "overlap", r.Status)
	e.removeLine(web, "deploy", keyFile("deploy"), r.NewFingerprint)
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "the old key stays")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}

// The server's host key changes during the overlap: nothing is sent to it, the old key stays.
func TestHostKeyChangeMidRotationRemovesNothing(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'host_key_changed' WHERE id = $1", web)
	require.NoError(t, err)
	logins := e.countEvents("VerifyKeyLogin")
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, "remove_failed", l.State)
	assert.Equal(t, "target.host_key_changed", l.ErrorCode)
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Equal(t, logins, e.countEvents("VerifyKeyLogin"), "nothing at all is sent to a server whose identity changed")
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
}

// A server deleted from Alice during the overlap: its location fails with system.not_found, the others
// complete their removal.
func TestTargetDeletedMidRotation(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", db, e.clock.Now())
	require.NoError(t, err)
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.remove_incomplete", r.ResultCode)
	l := e.loc(r.ID, db, "deploy")
	assert.Equal(t, "remove_failed", l.State)
	assert.Equal(t, "system.not_found", l.ErrorCode)
	assert.True(t, e.world.Has(db, keyFile("deploy"), k.Fingerprint))
	assert.Equal(t, "removed", e.loc(r.ID, web, "deploy").State)
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}

// An aborted run's undo removes the new key, and only the new key, everywhere it was added.
func TestUndoRemovesOnlyTheNewKey(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, web, "app")
	e.place(k, db, "deploy")
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	require.NoError(t, e.keys.Abort(e.ctx, e.admin, r.ID))
	r = e.settleRun(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.stopped", r.ResultCode)
	removals := e.events("RemoveAuthorizedKey")
	require.Len(t, removals, 3)
	for _, ev := range removals {
		assert.Equal(t, r.NewFingerprint, ev.Fingerprint, "the undo never names another key")
	}
	for _, f := range e.files(k) {
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint))
		assert.False(t, e.world.Has(f.target, f.path, r.NewFingerprint))
	}
	assert.Equal(t, 3, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL",
		*r.NewKeyID), "the inventory records the new key's lines as removed")
}

// S12: where the old key is already gone, the undo does not remove the new key (the account would be
// left without a key): the location ends undo_failed with rotation.old_key_gone.
func TestUndoKeepsTheNewKeyWhereTheOldOneIsGone(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, web, "app")
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	e.removeLine(web, "deploy", keyFile("deploy"), k.Fingerprint) // a person removed the old key by hand
	require.NoError(t, e.keys.Abort(e.ctx, e.admin, r.ID))
	r = e.settleRun(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.undo_failed", r.ResultCode)
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, "undo_failed", l.State)
	assert.Equal(t, sshkeys.ReasonOldKeyGone, l.ErrorCode)
	assert.True(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint), "the account keeps a key")
	assert.Equal(t, "undone", e.loc(r.ID, web, "app").State)
	assert.False(t, e.world.Has(web, keyFile("app"), r.NewFingerprint))
}

// S3: an add that timed out and lands later is still undone: the undo waits until the latest send plus
// the helper's budget and 30 s, then finds the line and removes it.
func TestLateWriteAfterUndoIsStillUndone(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch {
		case p.Target == db && p.Method == "AddAuthorizedKey":
			return fake.FaultLateWrite // every send to db-01 stalls and lands later
		case p.Target == db && p.Method == "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.Equal(t, "rolling_back", e.run(r.ID).Status)
	l := e.loc(r.ID, db, "deploy")
	assert.Equal(t, "verify_failed", l.State, "an uncertain add whose login proved nothing")
	assert.Equal(t, 3, e.countEvents("AddAuthorizedKey"), "web-01 once; db-01 sent once more after the refused login")
	e.sweep()
	e.drain()
	assert.Equal(t, "verify_failed", e.loc(r.ID, db, "deploy").State, "the undo waits while a send may still land")
	assert.False(t, e.world.Has(db, keyFile("deploy"), r.NewFingerprint))
	e.clock.Advance(helperproto.HelperBudget + 30*time.Second)
	require.Equal(t, 1, e.world.LateLanded(), "the stalled write landed after the call gave up")
	require.True(t, e.world.Has(db, keyFile("deploy"), r.NewFingerprint))
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "undone", e.loc(r.ID, db, "deploy").State)
	assert.False(t, e.world.Has(db, keyFile("deploy"), r.NewFingerprint), "the late line was removed")
	assert.True(t, e.world.Has(db, keyFile("deploy"), k.Fingerprint))
	assert.Zero(t, e.world.PendingLate())
}

// A removal whose answer was lost: the next job lists the file and records what it finds.
func TestLostRemovalAnswerIsReadFromTheFile(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "RemoveAuthorizedKey" {
			removes++
			if removes == 1 {
				return fake.FaultAfterWrite // removed, then the connection dropped
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	assert.Equal(t, "removing", e.loc(r.ID, web, "deploy").State, "the answer was lost")
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	r = e.settleRun(r.ID)
	assert.Equal(t, "completed", r.Status)
	assert.Equal(t, "removed", e.loc(r.ID, web, "deploy").State)
	assert.Equal(t, 1, removes, "the file showed the key gone: nothing was sent again")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", k.ID))
}

// A removal refused before it was written is retried with a newer re-check (G3') and then succeeds.
func TestFailedRemovalIsRetriedWithANewerRecheck(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "RemoveAuthorizedKey" {
			removes++
			if removes == 1 {
				return fake.FaultUnreachable
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, "remove_failed", l.State)
	assert.Equal(t, "ssh.unreachable", l.ErrorCode)
	r = e.settleRun(r.ID)
	assert.Equal(t, "completed", r.Status)
	assert.Equal(t, 2, removes)
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}

// F-67's add side: an add in flight is verified first by the next job, never sent blindly again; S4: the
// line proved by the login alone is recorded with its audit row.
func TestResumedAddIsVerifiedAndRecorded(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" {
			return fake.FaultAfterWrite // written, answer lost
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status)
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, "verified", l.State)
	require.NotNil(t, l.NewLocationID, "S4: the new line is recorded")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.added' AND details->>'ssh_key_id' = $1",
		r.NewKeyID.String()))
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
}

// Review I1: an add whose answer was lost, followed by a login that proves nothing (refused where the
// line has from=, or unprovable), is still uncertain: the location fails (never "unverifiable" with a
// recorded line) and the undo waits out S3 before it looks.
func TestUnprovenLoginAfterALostAddStillWaits(t *testing.T) {
	for name, login := range map[string]fake.Fault{"refused with from=": fake.FaultRefuse, "unprovable": fake.FaultUnprovable} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			web, db := e.server("web-01"), e.server("db-01")
			k := e.generate("ci")
			e.place(k, web, "deploy")
			e.placeWithOptions(k, db, "deploy", `from="10.0.0.0/8"`)
			e.setFault(func(p fake.FaultPoint) fake.Fault {
				switch {
				case p.Target == db && p.Method == "AddAuthorizedKey":
					return fake.FaultLateWrite
				case p.Target == db && p.Method == "VerifyKeyLogin":
					return login
				}
				return fake.FaultNone
			})
			r := e.runNow(e.policy(k.ID, 7))
			e.drain()
			l := e.loc(r.ID, db, "deploy")
			assert.Equal(t, "verify_failed", l.State)
			assert.Equal(t, sshkeys.ReasonLoginFailed, l.ErrorCode)
			assert.Nil(t, l.NewLocationID, "nothing proved the line: no inventory location")
			require.Equal(t, "rolling_back", e.run(r.ID).Status)
			e.sweep()
			e.drain()
			assert.Equal(t, "verify_failed", e.loc(r.ID, db, "deploy").State, "the undo waits while a send may still land")
			e.clock.Advance(helperproto.HelperBudget + 30*time.Second)
			e.sweep()
			r = e.settleRun(r.ID)
			assert.Equal(t, "aborted", r.Status)
			assert.False(t, e.world.Has(db, keyFile("deploy"), r.NewFingerprint), "the late line was found and removed")
		})
	}
}

// newLine is the authorized_keys line of the run's new key as the add sends it (no options).
func (e *env) newLine(r sshkeys.Rotation) string {
	e.t.Helper()
	var pub, comment string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT public_key, key_comment FROM ssh_keys WHERE id = $1", *r.NewKeyID).Scan(&pub, &comment))
	return pub + " " + comment
}

// Review I3 (controller ruling): a lock never changes a location's state. An add whose job died before
// the send is recovered in lock: its login is refused (nothing there), the one re-send is refused by the
// gate, and the row stays adding; the run pauses; after the renewal and Continue it is sent and verified.
func TestLockDuringALostAddChangesNothing(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	kill := newKiller("after:BeginAdd")
	e.setKiller(kill)
	r := e.runNow(e.policy(k.ID, 1))
	e.drainDying()
	require.Equal(t, "after:BeginAdd", kill.firedAt())
	e.setKiller(nil)
	e.gate.lock()
	e.restart()
	e.drain()
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocAdding, l.State, "nothing recorded in lock")
	assert.Empty(t, l.ErrorCode)
	assert.Zero(t, e.countEvents("AddAuthorizedKey"), "no send in lock")
	assert.Equal(t, 0, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", l.ID), "the lock used up no retry")
	e.sweep()
	r = e.run(r.ID)
	assert.Equal(t, sshkeys.StatusAddingNew, r.Status, "no rollback in lock")
	assert.True(t, r.PausedLicense)
	e.gate.unlock()
	e.sweep()
	require.NoError(t, e.keys.Continue(e.ctx, e.admin, r.ID))
	e.clock.Advance(time.Minute)
	e.sweep()
	e.drain()
	assert.Equal(t, sshkeys.StatusOverlap, e.run(r.ID).Status)
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
}

// Review C1: a removal whose answer was lost while the old key is still there, and a listing that did
// not read the file: nothing is recorded "removed"; a fresh re-check and a re-send give the truth.
func TestUnreadListingNeverRecordsARemoval(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes, lists := 0, 0
	e.world.SetLateDelay(24 * time.Hour) // the stalled removal does not land during the test
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "RemoveAuthorizedKey":
			if removes++; removes == 1 {
				return fake.FaultLateWrite // timed out, nothing changed yet: the old key is still there
			}
		case "ListKeys":
			if lists++; lists == 1 {
				return fake.FaultUnread
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	require.Equal(t, sshkeys.LocRemoving, e.loc(r.ID, web, "deploy").State)
	require.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
	e.clock.Advance(time.Minute)
	e.sweep()
	e.drain()
	assert.Equal(t, 1, lists, "the next job listed the file first")
	assert.Equal(t, 2, removes, "an unread file proves nothing: re-checked and sent again")
	assert.Equal(t, sshkeys.LocRemoved, e.loc(r.ID, web, "deploy").State)
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "removed for real, not on a listing's word")
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, e.run(r.ID).NewFingerprint)
}

// Review C1: an undo whose listing is partial concludes nothing (neither "nothing there" nor S12): the
// row stays undoing, and the next job's complete listing lets it remove the new key.
func TestPartialListingNeverRecordsAnUndo(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	lists := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "ListKeys" {
			if lists++; lists == 1 {
				return fake.FaultPartial
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.NoError(t, e.keys.Abort(e.ctx, e.admin, r.ID))
	e.drain()
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocUndoing, l.State, "a partial listing proves nothing")
	assert.True(t, e.world.Has(web, keyFile("deploy"), e.run(r.ID).NewFingerprint))
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusAborted, r.Status)
	assert.Equal(t, sshkeys.LocUndone, e.loc(r.ID, web, "deploy").State)
	assert.False(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint), "removed for real")
	assert.Equal(t, 1, e.removalsOf(r.NewFingerprint))
}

// Review M1: a removal in flight whose next re-check cannot connect stays removing (the removal may have
// landed), never remove_failed on the word of a connection failure.
func TestRemovingRowKeepsItsStateOnAConnectionFailure(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes, logins := 0, 0
	e.world.SetLateDelay(24 * time.Hour)
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "RemoveAuthorizedKey":
			if removes++; removes == 1 {
				return fake.FaultLateWrite
			}
		case "VerifyKeyLogin":
			if logins++; logins == 3 { // the login after the lost removal
				return fake.FaultUnreachable
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	e.drain()
	require.Equal(t, sshkeys.LocRemoving, e.loc(r.ID, web, "deploy").State)
	e.clock.Advance(time.Minute)
	e.sweep()
	e.drain()
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocRemoving, l.State, "not remove_failed on a connection failure")
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	assert.False(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint))
}

// Review M2: an undo that cannot reach the server once is retried by the sweep, not ended at once.
func TestUndoRetriesATransientFailure(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	removes := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "RemoveAuthorizedKey" {
			if removes++; removes == 1 {
				return fake.FaultUnreachable
			}
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.NoError(t, e.keys.Abort(e.ctx, e.admin, r.ID))
	e.drain()
	assert.Equal(t, sshkeys.LocUndoing, e.loc(r.ID, web, "deploy").State)
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusAborted, r.Status, "undone on the retry")
	assert.Equal(t, 2, removes)
	assert.False(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint))
}

// Review M3: a lost add whose login is accepted through ANOTHER key file of the same user is not
// recorded for this file: the add is sent once more for a definite answer, then verified.
func TestLoginThroughAnotherFileDoesNotProveTheAdd(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	p := e.policy(k.ID, 1)
	pv, err := e.keys.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	r, err := e.keys.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	other := "/home/deploy/.ssh/authorized_keys2"
	adds := 0
	e.world.SetLateDelay(24 * time.Hour)
	e.setFault(func(fp fake.FaultPoint) fake.Fault {
		if fp.Method == "AddAuthorizedKey" {
			if adds++; adds == 1 {
				e.world.Put(web, "deploy", other, e.newLine(r)) // the user reads the new key from another file
				return fake.FaultLateWrite
			}
		}
		return fake.FaultNone
	})
	e.drain()
	assert.Equal(t, 2, adds, "not proven by the login: sent once more")
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocVerified, l.State)
	assert.True(t, e.world.Has(web, keyFile("deploy"), r.NewFingerprint), "the line is in this file now")
}

// N-m9: an undo whose listing never reads the file completely ends with the closed reason
// rotation.listing_incomplete (the job records the step each time; the sweep's bound ends the place).
func TestUndoWithANeverCompleteListingSaysWhy(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	e.world.SetCoverage(web, keyFile("deploy"), providers.CoveragePartial)
	require.NoError(t, e.keys.Abort(e.ctx, e.admin, r.ID))
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusNeedsAttention, r.Status)
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocUndoFailed, l.State)
	assert.Equal(t, sshkeys.ReasonListingIncomplete, l.ErrorCode)
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "the old key stays")
	assert.Zero(t, e.removalsOf(r.NewFingerprint), "nothing removed on a partial listing's word")
}

// FB-1 (old-key rule 2): during the overlap a scan finds the old key for a second user in the shared file of
// the run's verified location (an account whose sshd reads the same absolute AuthorizedKeysFile, created
// meanwhile). The run never verified that user, so the old key stays in the file: the place ends kept_old,
// no removal reaches the server, and the run completes with the place counted and listed as kept.
func TestSiblingOfOldKeyDuringOverlapKeepsOld(t *testing.T) {
	e := newEnv(t)
	const shared = "/etc/ssh/keys/shared"
	web := e.server("web-01", providers.UserKeyFiles{OSUser: "deploy2", Files: []string{shared}, Complete: true},
		providers.UserKeyFiles{OSUser: "bob", Files: []string{shared}, Complete: true})
	k := e.generate("ci")
	e.placeIn(k, web, "deploy2", shared, "")
	r := e.runNow(e.policy(k.ID, 1))
	require.Len(t, r.Locations, 1, "one user of the file at the start: the file is not skipped")
	e.drain()
	r = e.run(r.ID)
	require.Equal(t, "overlap", r.Status)
	require.Equal(t, sshkeys.LocVerified, e.loc(r.ID, web, "deploy2").State)
	e.placeIn(k, web, "bob", shared, "") // the next scan records bob's place of the old key (same line, same file)
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	assert.Equal(t, 1, r.KeptCount)
	l := e.loc(r.ID, web, "deploy2")
	assert.Equal(t, sshkeys.LocKeptOld, l.State, "the kept place is listed on the run")
	assert.True(t, e.world.Has(web, shared, k.Fingerprint), "the old key stays in the file")
	assert.True(t, e.world.Has(web, shared, r.NewFingerprint))
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Len(t, e.mails(sshkeys.TemplateCompletedPartial), 1)
}
