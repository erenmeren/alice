//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

// at is rotNow plus m minutes.
func at(m float64) time.Time { return rotNow.Add(time.Duration(m * float64(time.Minute))) }

func (f *rotFx) col(i int, name string) any {
	f.t.Helper()
	var v any
	require.NoError(f.t, f.db.Owner.QueryRow(context.Background(), "SELECT "+name+" FROM rotation_locations WHERE id = $1", f.locs[i]).Scan(&v))
	return v
}

func (f *rotFx) opID(i int, name string) uuid.UUID {
	f.t.Helper()
	var v uuid.UUID
	require.NoError(f.t, f.db.Owner.QueryRow(context.Background(), "SELECT "+name+" FROM rotation_locations WHERE id = $1", f.locs[i]).Scan(&v))
	return v
}

// G20 (N9): reverified_at never goes back and is never cleared; it changes only on a verified row or with a
// statement whose new state is removing; a retry needs a re-check strictly later than the row's failure time,
// which the guard stamps itself.
func TestRotationRecheckIsKeptAcrossAFailure(t *testing.T) {
	retry := `state = 'removing', reverified_at = $2, remove_op_id = gen_random_uuid(), remove_verified_at = $2, remove_sent_at = $3`
	// The review's exact sequence (re-checked at t0 = +1m, the login at +2m refused): the failure statement may not
	// clear or lower reverified_at, so the retry cannot rest on the older success.
	f := readyToRemove(t, pgtest.New(t), 1)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'remove_failed', error_code = 'rotation.new_key_failed', reverified_at = NULL, updated_at = $2`, at(2))),
		"the failure statement clears the re-check")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'remove_failed', error_code = 'rotation.new_key_failed', reverified_at = $2, updated_at = $3`, at(0.5), at(2))),
		"the failure statement lowers the re-check (still later than the verification)")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'remove_failed', error_code = 'rotation.new_key_failed', reverified_at = $2, updated_at = $3`, at(3), at(2))),
		"nor raises it: only the edge into removing writes a re-check")
	require.NoError(t, f.locSet(0, `state = 'remove_failed', error_code = 'rotation.new_key_failed', updated_at = $2`, at(2)))
	assert.Equal(t, at(2), f.col(0, "remove_failed_at").(time.Time).UTC(), "the guard stamps the failure time")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', reverified_at = $2, remove_op_id = gen_random_uuid(), remove_verified_at = $2, remove_sent_at = $3`,
		at(1), at(3))), "the review's second statement: the older success")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, retry, at(1.5), at(3))), "a re-check between the older success and the failed login")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, retry, at(2), at(3))), "a re-check at the failure time")
	require.NoError(t, f.locSet(0, retry, at(2.5), at(3)), "a re-check after the failure")
	assert.Equal(t, at(2), f.col(0, "remove_failed_at").(time.Time).UTC(), "the failure time is kept as history")

	// A failure statement that supplies an old updated_at cannot place the failure before what the row recorded.
	g := readyToRemove(t, pgtest.New(t), 1)
	require.NoError(t, g.startRemoving(0, at(1), at(4)))
	require.NoError(t, g.locSet(0, `state = 'remove_failed', error_code = 'ssh.timeout', updated_at = $2`, at(-60)))
	assert.Equal(t, at(4), g.col(0, "remove_failed_at").(time.Time).UTC(), "not earlier than the failed send")
	assert.Equal(t, "Z1011", sqlState(g.locSet(0, retry, at(4), at(5))), "the re-check is later than the failure")
	// Nobody writes the failure time: no grant for the application, and the guard refuses every role.
	assert.Equal(t, "42501", sqlState(g.locSet(0, "remove_failed_at = $2", at(9))))
	_, err := g.db.Owner.Exec(context.Background(), "UPDATE rotation_locations SET remove_failed_at = $2 WHERE id = $1", g.locs[0], at(-1))
	assert.Equal(t, "Z1011", sqlState(err))

	// On a verified row the re-check only moves forward; it is never cleared; the other edges keep it.
	h := readyToRemove(t, pgtest.New(t), 2) // location 0 re-checked at +1m
	assert.Equal(t, "Z1011", sqlState(h.locSet(0, "reverified_at = NULL")), "cleared")
	assert.Equal(t, "Z1011", sqlState(h.locSet(0, "reverified_at = $2", at(0.5))), "lowered")
	require.NoError(t, h.locSet(0, "reverified_at = $2", at(3)), "a later re-check")
	assert.Equal(t, "Z1011", sqlState(h.locSet(0, "state = 'kept_old', reverified_at = $2", at(4))), "the edge into kept_old keeps it")
	require.NoError(t, h.startRemoving(0, at(3), at(5)))
	assert.Equal(t, "Z1011", sqlState(h.locSet(0, "reverified_at = $2", at(2))), "a removing row's re-check does not go back")
	require.NoError(t, h.locSet(0, "reverified_at = $2", at(6)), "a removing row takes a newer re-check")
	assert.Equal(t, "Z1011", sqlState(h.locSet(0, "state = 'removed', removed_at = $2, reverified_at = $3", at(7), at(7))), "finishing keeps it")
	require.NoError(t, h.locSet(0, "state = 'removed', removed_at = $2", at(7)))
}

// G21 (N10): the undo columns are required on undoing and undone, never cleared, and an undo that fails says why.
func TestRotationUndoColumnsAreRequiredAndKept(t *testing.T) {
	f := newRotFx(t, pgtest.New(t), 3)
	f.start()
	f.verified(0)
	f.verified(1)
	f.verified(2)
	require.NoError(t, f.runSet("status = 'rolling_back'"))
	assert.Equal(t, "rotation_locations_undo_sent", constraintOf(f.locSet(0, "state = 'undoing'")), "the review's statement: undoing with no op id, no time")
	assert.Equal(t, "rotation_locations_undo_sent", constraintOf(f.locSet(0, "state = 'undoing', undo_op_id = gen_random_uuid()")), "no time")
	require.NoError(t, f.locSet(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", at(1)))
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "undo_op_id = NULL")), "the op id is not cleared while undoing")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "undo_sent_at = NULL")), "nor the time")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'undo_failed'")), "the review's statement: undoing -> undo_failed without a reason")
	require.NoError(t, f.locSet(0, "state = 'undo_failed', error_code = 'ssh.timeout'"))
	require.NoError(t, f.locSet(1, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", at(1)))
	require.NoError(t, f.locSet(1, "undo_sent_at = $2", at(2)), "a re-sent undo moves its time")
	require.NoError(t, f.locSet(1, "state = 'undone'"))
	guardOff(t, f.db, "rotation_locations", "rotation_locations_guard", func() {
		_, err := f.db.Owner.Exec(context.Background(), "UPDATE rotation_locations SET state = 'undone' WHERE id = $1", f.locs[2])
		assert.Equal(t, "rotation_locations_undo_sent", constraintOf(err), "undone needs the undo it finished")
	})
}

// sharedFile: locations 0 and 1 are two users of one file, both verified and re-checked at +1m, the run removing_old.
func sharedFile(t *testing.T) *rotFx {
	t.Helper()
	f := newRotFx(t, pgtest.New(t), 1)
	shared := insertKeyLocation(t, f.db, f.oldKey, f.target, "ub", f.files[0])
	sib := uuid.New()
	f.must(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES ($1, $2, 2, $3, $4, 'ub', $5, 'planned', $6)`, sib, f.run, shared, f.target, f.files[0], rotNow)
	f.locs = append(f.locs, sib)
	f.start()
	f.verified(0)
	f.verified(1)
	f.overlap()
	f.removingOld()
	f.recheck(0, at(1))
	f.recheck(1, at(1))
	return f
}

// G22 (N11): a sibling already removing exempts the file only while its own re-check is within 15 minutes of this
// row's send; a removed sibling always does.
func TestRotationRemovingSiblingNeedsAFreshRecheck(t *testing.T) {
	f := sharedFile(t)
	require.NoError(t, f.startRemoving(0, at(1), at(2)))
	f.recheck(1, at(20))
	assert.Equal(t, "Z1011", sqlState(f.startRemoving(1, at(20), at(20.5))), "the removing sibling's re-check is 19.5 minutes old")
	f.recheck(0, at(19))
	require.NoError(t, f.startRemoving(1, at(20), at(20.5)), "the sibling re-checked again")

	g := sharedFile(t)
	require.NoError(t, g.startRemoving(0, at(1), at(2)))
	g.recheck(1, at(16))
	assert.Equal(t, "Z1011", sqlState(g.startRemoving(1, at(16), at(16).Add(time.Microsecond))), "just over 15 minutes")
	require.NoError(t, g.startRemoving(1, at(16), at(16)), "exactly 15 minutes is still fresh")

	h := sharedFile(t)
	require.NoError(t, h.startRemoving(0, at(1), at(2)))
	h.mustLoc(0, "state = 'removed', removed_at = $2", at(3))
	h.recheck(1, at(40))
	require.NoError(t, h.startRemoving(1, at(40), at(40.5)), "a removed sibling exempts the file whatever its age")
}

// G23 (N12): an operation id is used once, across locations, kinds and attempts.
func TestRotationOperationIdsAreNeverReused(t *testing.T) {
	f := newRotFx(t, pgtest.New(t), 3)
	f.start()
	op := uuid.New()
	require.NoError(t, f.locSet(0, "state = 'adding', add_op_id = $2, add_sent_at = $3", op, rotNow))
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(f.locSet(1, "state = 'adding', add_op_id = $2, add_sent_at = $3", op, rotNow)),
		"another location's add op id")
	nl := insertKeyLocation(t, f.db, f.newKey, f.target, "ua", f.files[0])
	f.mustLoc(0, "state = 'verified', verified_at = $2, new_location_id = $3", rotNow, nl)
	f.verified(1)
	f.mustLoc(2, "state = 'cancelled'")
	f.overlap()
	f.removingOld()
	f.recheck(0, at(1))
	f.recheck(1, at(1))
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op, at(2))), "this row's add op id as a removal op id")
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		f.opID(1, "add_op_id"), at(2))), "another row's add op id")
	op1, op2 := uuid.New(), uuid.New()
	retry := `state = 'removing', reverified_at = $2, remove_op_id = $4, remove_verified_at = $2, remove_sent_at = $3`
	require.NoError(t, f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`, op1, at(2)))
	f.mustLoc(0, "state = 'remove_failed', error_code = 'ssh.timeout', updated_at = $2", at(3))
	require.NoError(t, f.locSet(0, retry, at(4), at(5), op2))
	f.mustLoc(0, "state = 'remove_failed', error_code = 'ssh.timeout', updated_at = $2", at(6))
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(f.locSet(0, retry, at(7), at(8), op1)), "op1 -> op2 -> op1")
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(f.locSet(1, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op2, at(2))), "another row's earlier removal op id")
	require.NoError(t, f.locSet(0, retry, at(7), at(8), uuid.New()))

	g := newRotFx(t, pgtest.New(t), 1)
	g.start()
	g.verified(0)
	require.NoError(t, g.runSet("status = 'rolling_back'"))
	assert.Equal(t, "rotation_op_ids_pkey", constraintOf(g.locSet(0, "state = 'undoing', undo_op_id = $2, undo_sent_at = $3", g.opID(0, "add_op_id"), at(1))),
		"an add op id as an undo op id")
	require.NoError(t, g.locSet(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", at(1)))
	require.NoError(t, g.locSet(0, "undo_sent_at = $2", at(2)), "a re-sent undo keeps its op id")
	var n int
	require.NoError(t, g.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM rotation_op_ids WHERE location_id = $1", g.locs[0]).Scan(&n))
	assert.Equal(t, 2, n, "the add and the undo, once each")
	_, err := g.db.App.Exec(context.Background(), "UPDATE rotation_op_ids SET kind = 'add'")
	assert.Equal(t, "42501", sqlState(err), "the record is append-only")
	_, err = g.db.App.Exec(context.Background(), "DELETE FROM rotation_op_ids")
	assert.Equal(t, "42501", sqlState(err))
}

// G24: no overlap while a location is planned, adding or added; no completed over a failed verification or a sent
// failed add (the new key may be on the server).
func TestRotationOverlapAndCompletionNeedSettledLocations(t *testing.T) {
	f := newRotFx(t, pgtest.New(t), 2)
	f.start()
	f.verified(1)
	overlap := func(g *rotFx) error { return g.runSet("status = 'overlap', verified_at = $2", rotNow) }
	assert.Equal(t, "Z1013", sqlState(overlap(f)), "a planned location")
	f.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	assert.Equal(t, "Z1013", sqlState(overlap(f)), "an adding location")
	f.mustLoc(0, "state = 'added'")
	assert.Equal(t, "Z1013", sqlState(overlap(f)), "an added location")
	require.NoError(t, f.runSet("status = 'verifying_new', awaiting_decision = true, decision_due_at = $2", at(60)))
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'overlap', verified_at = $2, awaiting_decision = false, decision_due_at = NULL", rotNow)),
		"verifying_new -> overlap too")
	f.mustLoc(0, "state = 'verified', verified_at = $2", rotNow)
	require.NoError(t, f.runSet("status = 'overlap', verified_at = $2, awaiting_decision = false, decision_due_at = NULL", rotNow))

	for _, c := range []struct {
		name, set  string
		sent, want bool
	}{
		{"verify_failed", "state = 'verify_failed', error_code = 'sshkey.login_failed'", true, false},
		{"a sent add_failed", "state = 'add_failed', error_code = 'ssh.timeout'", true, false},
		{"an add_failed never sent", "state = 'add_failed', error_code = 'ssh.timeout'", false, true},
	} {
		g := newRotFx(t, pgtest.New(t), 2)
		g.start()
		g.verified(0)
		if c.sent {
			g.mustLoc(1, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
		}
		g.mustLoc(1, c.set)
		require.NoError(t, overlap(g))
		g.removingOld()
		g.recheck(0, at(1))
		require.NoError(t, g.startRemoving(0, at(1), at(2)))
		g.mustLoc(0, "state = 'removed', removed_at = $2", at(3))
		err := g.runSet("status = 'completed', finished_at = $2", at(4))
		if c.want {
			assert.NoError(t, err, c.name)
			continue
		}
		assert.Equal(t, "Z1013", sqlState(err), c.name+" is not completed over")
		assert.NoError(t, g.runSet("status = 'needs_attention', finished_at = $2, result_code = 'rotation.remove_incomplete'", at(4)), c.name)
	}
}

// G25 (N13): an add re-send is a recorded statement: the counter rises by one with the re-send time, only on an
// adding row of a run that is adding_new and not paused; the op id changes only with a re-send; an undo follows
// the latest send.
func TestRotationAddResendIsRecorded(t *testing.T) {
	f := newRotFx(t, pgtest.New(t), 2)
	f.start()
	f.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	resend := "add_resend_count = add_resend_count + 1, add_resent_at = $2"
	require.NoError(t, f.locSet(0, resend, at(2)))
	assert.EqualValues(t, 1, f.col(0, "add_resend_count"))
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, resend, at(1))), "earlier than the latest re-send")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "add_resend_count = add_resend_count + 2, add_resent_at = $2", at(3))), "one re-send at a time")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "add_resent_at = $2", at(3))), "a time without the count")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "add_resend_count = 0, add_resent_at = NULL")), "never cleared")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "add_op_id = gen_random_uuid()")), "a new op id without a re-send")
	require.NoError(t, f.locSet(0, resend+", add_op_id = gen_random_uuid()", at(3)), "a re-send may carry a new op id")
	require.NoError(t, f.locSet(0, resend, at(3)), "a re-send at the same instant (a frozen clock) still counts")
	require.NoError(t, f.runSet("paused_license = true, paused_at = $2", at(4)))
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, resend, at(5))), "no re-send while paused for the licence")
	require.NoError(t, f.runSet("paused_license = false, paused_at = NULL"))
	f.added(1)
	assert.Equal(t, "Z1011", sqlState(f.locSet(1, resend, at(5))), "an added row is not re-sent")
	g := newRotFx(t, pgtest.New(t), 1)
	g.start()
	g.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	assert.Equal(t, "rotation_locations_times", constraintOf(g.locSet(0, resend, at(-1))), "not before the first send")
	guardOff(t, g.db, "rotation_locations", "rotation_locations_guard", func() {
		_, err := g.db.Owner.Exec(context.Background(), "UPDATE rotation_locations SET add_resend_count = 1 WHERE id = $1", g.locs[0])
		assert.Equal(t, "rotation_locations_add_resent", constraintOf(err), "a counted re-send has its time")
	})
	require.NoError(t, g.locSet(0, resend, at(5)))
	require.NoError(t, g.runSet("status = 'rolling_back'"))
	assert.Equal(t, "Z1011", sqlState(g.locSet(0, resend, at(6))), "no re-send outside adding_new")
	assert.Equal(t, "rotation_locations_times", constraintOf(g.locSet(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", at(4))),
		"the undo follows the latest send")
	require.NoError(t, g.locSet(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", at(6)))

	// A location is born without a re-send or a failure time.
	h := newRotFx(t, pgtest.New(t), 0)
	extra := insertKeyLocation(t, h.db, h.oldKey, h.target, "ux", "/home/ux/.ssh/authorized_keys")
	for _, c := range []string{"add_resend_count", "add_resent_at", "remove_failed_at"} {
		v := map[string]any{"add_resend_count": 1, "add_resent_at": rotNow, "remove_failed_at": rotNow}[c]
		err := h.x(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at, `+c+`)
VALUES (gen_random_uuid(), $1, 1, $2, $3, 'ux', '/home/ux/.ssh/authorized_keys', 'planned', $4, $5)`, h.run, extra, h.target, rotNow, v)
		assert.Equal(t, "Z1011", sqlState(err), c)
	}
}

// The delivered-notice lookup (schedule.go noticeDelivered) has its expression index.
func TestRotationPreviewNoticeIndex(t *testing.T) {
	db := pgtest.New(t)
	var def string
	require.NoError(t, db.Owner.QueryRow(context.Background(),
		"SELECT indexdef FROM pg_indexes WHERE tablename = 'notifications_outbox' AND indexname = 'notifications_outbox_rotation_preview'").Scan(&def))
	assert.Contains(t, def, "((params ->> 'rotation_id'::text))")
	assert.Contains(t, def, "WHERE (template_key = 'rotation.preview'::text)")
}

// FB-1 (old-key rule 2): a removal is not sent while the old key has a live place in the file that is not a
// location of the run (a user the run never verified); a place of another key, a place in another file and a
// place that is missing or that Alice removed do not block.
func TestRotationRemovalRefusesAPlaceOutsideTheRun(t *testing.T) {
	f := readyToRemove(t, pgtest.New(t), 1)
	other, _ := seedSSHKey(t, f.db, "SHA256:"+repeat43("X"))
	insertKeyLocation(t, f.db, other, f.target, "ub", f.files[0])
	insertKeyLocation(t, f.db, f.oldKey, f.target, "uc", "/etc/ssh/keys/elsewhere")
	sib := insertKeyLocation(t, f.db, f.oldKey, f.target, "ub", f.files[0])
	assert.Equal(t, "Z1011", sqlState(f.startRemoving(0, at(1), at(2))), "a live place of the old key outside the run")
	_, err := f.db.Owner.Exec(context.Background(), "UPDATE ssh_key_locations SET missing_since = $2 WHERE id = $1", sib, rotNow)
	require.NoError(t, err)
	require.NoError(t, f.startRemoving(0, at(1), at(2)), "a missing place does not block")

	g := readyToRemove(t, pgtest.New(t), 1)
	gone := insertKeyLocation(t, g.db, g.oldKey, g.target, "ub", g.files[0])
	_, err = g.db.Owner.Exec(context.Background(), "UPDATE ssh_key_locations SET removed_by_alice_at = $2 WHERE id = $1", gone, rotNow)
	require.NoError(t, err)
	require.NoError(t, g.startRemoving(0, at(1), at(2)), "a place Alice removed does not block")
}
