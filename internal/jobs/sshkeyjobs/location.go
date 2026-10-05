package sshkeyjobs

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

// rotation.location (C9): one phase of one location of a rotation run. Every phase reads the location
// again (LocationWork) and works from its recorded state, so a job that runs again after a crash, a lost
// lease or a timeout carries on from what was recorded:
//
//	add     planned → BeginAdd → send (op) → FinishAdd → login with the new key → RecordVerify
//	        adding (a send whose answer was not recorded) → login first; anything but an accepted login →
//	        BeginAdd again (same op, add_resent) → send → FinishAdd → login → RecordVerify
//	        added → login → RecordVerify; a location the plan does not verify (root_login_disabled) is
//	        never logged in to
//	remove  verified / remove_failed → login → RecordReverify → BeginRemove → send (op) → FinishRemove
//	        removing (a removal whose answer was not recorded) → list the file first: the old key gone →
//	        FinishRemove (removed); else as verified
//	undo    BeginUndo (S3: an uncertain add waits) → list the file → the new key absent → undone; the
//	        old key gone → undo_failed rotation.old_key_gone (S12; the new key stays) → else send the
//	        removal of the NEW fingerprint (op) → FinishUndo
//
// The store answers ErrNotYourTurn or ErrPaused when a step is not this job's to take (the run moved on,
// the license gate, the S3 wait, a clock stepped back): the job records nothing more and ends; the sweep
// re-queues what still waits. A job whose context ends after a remote call records nothing either (the
// state stays "in flight" and the next job resolves it as above). Any other store failure is surfaced as a
// retryable failure (the next attempt reads the state again). Advance runs after every recorded outcome.

// reasonNotWaiting: a payload that names no location of the run, or another server.
const reasonNotWaiting = "rotation.not_waiting"

// location runs one phase of one rotation location.
func (h *handlers) location(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	locID, err1 := uuid.Parse(j.Payload["location_id"])
	runID, err2 := uuid.Parse(j.Payload["rotation_id"])
	if err := errors.Join(err1, err2); err != nil {
		return nil, jobs.Fail(reasonNotWaiting, nil, err)
	}
	// Every store write checks that this run still holds the job (a run that lost its lease writes nothing).
	ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt})
	w, err := h.d.Keys.LocationWork(ctx, locID)
	if errors.Is(err, sshkeys.ErrNotFound) {
		return nil, jobs.Fail(reasonNotWaiting, nil, err)
	}
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if w.Rotation.ID != runID || w.Location.ID != locID || w.Location.TargetID != j.TargetID {
		return nil, jobs.Fail(reasonNotWaiting, nil, nil) // a payload that names another run or server
	}
	r := &locJob{h: h, w: w, loc: w.Location, actor: systemActor(j), steps: steps}
	var res map[string]any
	switch j.Payload["phase"] {
	case "add":
		res, err = r.add(ctx)
	case "remove":
		res, err = r.remove(ctx)
	case "undo":
		res, err = r.undo(ctx)
	default:
		return nil, jobs.Fail(reasonNotWaiting, nil, nil)
	}
	if err != nil {
		return res, err
	}
	if ctx.Err() == nil {
		if err := h.d.Keys.Advance(ctx, runID); err != nil {
			h.d.Log.Warn("rotation could not advance; the sweep retries", "rotation_id", runID.String(), "error_type", errType(err))
		}
	}
	return res, nil
}

// locJob is one run of a location job.
type locJob struct {
	h     *handlers
	w     sshkeys.LocationWork
	loc   sshkeys.RotationLocation
	actor audit.Actor
	steps jobs.StepRecorder
}

func stopped(why string) map[string]any { return map[string]any{"stopped": why} }

func stateResult(state string) map[string]any { return map[string]any{"state": state} }

// storeStop is the job's answer to a store call that did not record: the store's "not this job's turn"
// answers end the job (nothing more is recorded); a lost claim stops it; anything else is surfaced as a
// retryable failure (the next attempt reads the recorded state again).
func (r *locJob) storeStop(err error) (map[string]any, error) {
	switch {
	case errors.Is(err, sshkeys.ErrNotYourTurn):
		return stopped("not_your_turn"), nil
	case errors.Is(err, sshkeys.ErrPaused):
		return stopped("paused"), nil
	case errors.Is(err, sshkeys.ErrOwnKeyProtected):
		return stopped("own_key_protected"), nil
	case errors.Is(err, inventory.ErrNotFound):
		return stopped("not_found"), nil // the server was deleted from Alice meanwhile
	case errors.Is(err, inventory.ErrClaimLost):
		return nil, jobs.Retry("job.lease_expired", nil, err)
	}
	r.h.d.Log.Error("a rotation step could not be recorded", "location_id", r.loc.ID.String(), "error_type", errType(err))
	return nil, jobs.Retry("internal.unexpected", nil, err)
}

// record is the job's answer after a store call: onOK when it recorded, else storeStop's.
func (r *locJob) record(err error, onOK map[string]any) (map[string]any, error) {
	if err != nil {
		return r.storeStop(err)
	}
	return onOK, nil
}

func (r *locJob) noVerify() bool { return r.loc.VerifyNote == plan.NoteRootLoginDisabled }

// add is the add phase.
func (r *locJob) add(ctx context.Context) (map[string]any, error) {
	keys := r.h.d.Keys
	state, op, began := r.loc.State, r.loc.AddOpID, false
	switch state {
	case sshkeys.LocPlanned:
		var err error
		if op, err = keys.BeginAdd(ctx, r.loc.ID); err != nil {
			return r.storeStop(err) // paused or not this job's turn: nothing was sent
		}
		state, began = sshkeys.LocAdding, true
	case sshkeys.LocAdding, sshkeys.LocAdded:
	default:
		return stateResult(state), nil
	}
	sess, err := r.h.open(ctx, r.loc.TargetID)
	if err != nil {
		reason := reasonOf(err)
		if began { // nothing was sent: the add failed definitely
			err = keys.FinishAdd(ctx, r.loc.ID, sshkeys.AddRecord{Definite: true, Reason: reason, Actor: r.actor})
		} else { // in flight and unreachable (A3): the undo removes what may have been written
			err = keys.RecordVerify(ctx, r.loc.ID, sshkeys.VerifyRecord{Reason: reason})
		}
		res, ferr := r.record(err, map[string]any{"reason": reason})
		return res, ferr
	}
	defer r.h.close(sess)
	resent := false
	if began {
		res, ok, err := r.sendAdd(ctx, sess, op, &state)
		if !ok {
			return res, err
		}
	}
	for {
		if r.noVerify() {
			// No login is tried here (PermitRootLogin no): a definite add went to unverifiable in
			// FinishAdd; an uncertain one is sent once more for a definite answer, else the sweep resumes it.
			if state != sshkeys.LocAdding || resent {
				return stateResult(state), nil
			}
		} else {
			outcome, lerr := r.h.login(ctx, sess, r.loc.OSUser, r.w.NewKeyID)
			if ctx.Err() != nil {
				return stopped("interrupted"), nil
			}
			accepted := lerr == nil && outcome == providers.KeyLoginAccepted
			// A login that could not connect is recorded as it is (A3: verify_failed with its reason;
			// sending again over the same connection would not answer either).
			if accepted || lerr != nil || state != sshkeys.LocAdding || resent {
				return r.recordVerify(ctx, state, outcome, lerr)
			}
		}
		// An add whose answer was lost, and whose line nothing proved: send it once more (same operation
		// id; the add is idempotent by fingerprint) when the gate allows, then decide.
		var err error
		if op, err = keys.BeginAdd(ctx, r.loc.ID); err != nil {
			if errors.Is(err, sshkeys.ErrPaused) && !r.noVerify() {
				// Cannot send again in lock: the login did not prove the line, so the location fails and
				// the undo (after S3's wait) removes whatever may have landed.
				return r.recordVerify(ctx, state, providers.KeyLoginRefused, errNotProven)
			}
			return r.storeStop(err)
		}
		resent = true
		if res, ok, err := r.sendAdd(ctx, sess, op, &state); !ok {
			return res, err
		}
	}
}

// errNotProven: a login after an add whose answer was lost proved nothing (refused, unprovable or a
// refusal with from=; review I1): the location is recorded as failed, never as unverifiable.
var errNotProven = jobs.Fail(sshkeys.ReasonLoginFailed, nil, nil)

// recordVerify records a login after the add. From adding (the add's answer was lost) only an accepted
// login proves the line: anything else is recorded as a failure with its reason.
func (r *locJob) recordVerify(ctx context.Context, state string, outcome providers.KeyLoginOutcome, lerr error) (map[string]any, error) {
	rec := sshkeys.VerifyRecord{Outcome: outcome}
	switch {
	case lerr != nil:
		rec = sshkeys.VerifyRecord{Reason: reasonOf(lerr)}
	case state == sshkeys.LocAdding && outcome != providers.KeyLoginAccepted:
		rec = sshkeys.VerifyRecord{Reason: sshkeys.ReasonLoginFailed}
	}
	return r.record(r.h.d.Keys.RecordVerify(ctx, r.loc.ID, rec), map[string]any{"login": string(outcome), "reason": rec.Reason})
}

// sendAdd sends the add with the operation id and records a definite answer (state becomes added, or
// add_failed: ok false then). An uncertain answer records nothing (the state stays adding). ok false
// ends the job with the result and the error.
func (r *locJob) sendAdd(ctx context.Context, sess providers.Session, op uuid.UUID, state *string) (map[string]any, bool, error) {
	rec := &writeTracker{next: r.steps}
	res, err := sess.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: op, OSUser: r.loc.OSUser, FilePath: r.loc.FilePath,
		Line: r.w.NewLine, ProtectedFingerprints: r.w.Protected}, rec)
	if ctx.Err() != nil {
		return stopped("interrupted"), false, nil // in flight: the next job verifies first
	}
	if err != nil {
		r.h.recordIfConnection(ctx, r.loc.TargetID, err)
	}
	switch {
	case err == nil && (!res.Changed || res.Verified):
		ferr := r.h.d.Keys.FinishAdd(ctx, r.loc.ID, sshkeys.AddRecord{Definite: true, Added: true, LineNo: res.LineNo, Backup: res.Backup,
			Actor: r.actor})
		if ferr != nil {
			res, err := r.storeStop(ferr)
			return res, false, err
		}
		*state = sshkeys.LocAdded
		if r.noVerify() {
			*state = sshkeys.LocUnverifiable // FinishAdd moved it there: no login is tried
		}
		return nil, true, nil
	case err != nil && definiteNoChange(rec.wrote, res, err):
		reason := reasonOf(err)
		res, ferr := r.record(r.h.d.Keys.FinishAdd(ctx, r.loc.ID, sshkeys.AddRecord{Definite: true, Reason: reason, Actor: r.actor}),
			map[string]any{"state": sshkeys.LocAddFailed, "reason": reason})
		return res, false, ferr
	}
	return nil, true, nil // uncertain (or written but read back differently): the login decides
}

// holds lists the location's file and reports which of the fingerprints it holds.
func (r *locJob) holds(ctx context.Context, sess providers.Session, fps ...string) (map[string]bool, error) {
	keys, err := sess.ListAuthorizedKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, k := range keys {
		if k.FilePath != r.loc.FilePath {
			continue
		}
		for _, fp := range fps {
			if k.Fingerprint == fp {
				out[fp] = true
			}
		}
	}
	return out, nil
}

// remove is the remove phase.
func (r *locJob) remove(ctx context.Context) (map[string]any, error) {
	keys := r.h.d.Keys
	state := r.loc.State
	if state != sshkeys.LocVerified && state != sshkeys.LocRemoving && state != sshkeys.LocRemoveFailed {
		return stateResult(state), nil
	}
	sess, err := r.h.open(ctx, r.loc.TargetID)
	if err != nil {
		reason := reasonOf(err)
		res, ferr := r.record(keys.RecordReverify(ctx, r.loc.ID, sshkeys.VerifyRecord{Reason: reason}), map[string]any{"reason": reason})
		return res, ferr
	}
	defer r.h.close(sess)
	if state == sshkeys.LocRemoving {
		// A removal was sent and its answer never recorded: what the file holds is the truth.
		if res, done, err := r.removedAlready(ctx, sess); done {
			return res, err
		}
	}
	outcome, lerr := r.h.login(ctx, sess, r.loc.OSUser, r.w.NewKeyID)
	if ctx.Err() != nil {
		return stopped("interrupted"), nil
	}
	rec := sshkeys.VerifyRecord{Outcome: outcome}
	if lerr != nil {
		rec = sshkeys.VerifyRecord{Reason: reasonOf(lerr)}
	}
	if err := keys.RecordReverify(ctx, r.loc.ID, rec); err != nil {
		return r.storeStop(err)
	}
	if lerr != nil || outcome != providers.KeyLoginAccepted {
		return map[string]any{"login": string(outcome), "reason": rec.Reason}, nil // the old key stays
	}
	op, err := keys.BeginRemove(ctx, r.loc.ID)
	if err != nil {
		if state == sshkeys.LocRemoving {
			// The gate refuses a re-send of a removal that was sent before: never record "kept" blindly.
			if res, done, ferr := r.removedAlready(ctx, sess); done {
				return res, ferr
			}
		}
		return r.storeStop(err)
	}
	rec2 := &writeTracker{next: r.steps}
	res, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: op, OSUser: r.loc.OSUser, FilePath: r.loc.FilePath,
		Fingerprint: r.w.OldFingerprint, ProtectedFingerprints: r.w.Protected, AllowLastRootKey: false}, rec2)
	if ctx.Err() != nil {
		return stopped("interrupted"), nil // removing: the next job lists the file first
	}
	if err != nil {
		r.h.recordIfConnection(ctx, r.loc.TargetID, err)
	}
	var fin sshkeys.RemoveRecord
	switch {
	case err == nil && (!res.Changed || res.Verified):
		fin = sshkeys.RemoveRecord{Definite: true, Removed: res.Removed, Backup: res.Backup, Res: res}
	case err != nil && definiteNoChange(rec2.wrote, res, err):
		fin = sshkeys.RemoveRecord{Definite: true, Reason: reasonOf(err), Backup: res.Backup, Res: res}
	default:
		return stateResult(sshkeys.LocRemoving), nil // uncertain: the next job lists the file first
	}
	out, ferr := r.record(keys.FinishRemove(ctx, r.actor, r.loc.ID, fin), map[string]any{"removed": fin.Removed, "reason": fin.Reason})
	return out, ferr
}

// removedAlready lists the file of a location whose removal was sent; when the old key is gone it records
// the removal (done). A failed listing or a key still there continues the normal path (done false).
func (r *locJob) removedAlready(ctx context.Context, sess providers.Session) (map[string]any, bool, error) {
	held, err := r.holds(ctx, sess, r.w.OldFingerprint)
	if err != nil || held[r.w.OldFingerprint] || ctx.Err() != nil {
		return nil, false, nil
	}
	// The earlier send removed it (Alice's change: the inventory marks the old location removed).
	gone := providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}
	res, ferr := r.record(r.h.d.Keys.FinishRemove(ctx, r.actor, r.loc.ID, sshkeys.RemoveRecord{Definite: true, Removed: 1, Res: gone}),
		map[string]any{"removed": 1, "found": "old_key_gone"})
	return res, true, ferr
}

// undo is the undo phase: it removes the NEW key's line where this run's add was sent, never the old
// key's. BeginUndo comes first, before any network step (S3's wait for an uncertain add; review I3).
func (r *locJob) undo(ctx context.Context) (map[string]any, error) {
	keys := r.h.d.Keys
	op, err := keys.BeginUndo(ctx, r.loc.ID)
	if err != nil {
		return r.storeStop(err) // the S3 wait, or nothing to undo
	}
	fail := func(reason string) (map[string]any, error) {
		res, ferr := r.record(keys.FinishUndo(ctx, r.actor, r.loc.ID, sshkeys.UndoRecord{Definite: true, Reason: reason}),
			map[string]any{"state": sshkeys.LocUndoFailed, "reason": reason})
		return res, ferr
	}
	sess, err := r.h.open(ctx, r.loc.TargetID)
	if err != nil {
		return fail(reasonOf(err))
	}
	defer r.h.close(sess)
	held, err := r.holds(ctx, sess, r.w.OldFingerprint, r.w.NewFingerprint)
	if ctx.Err() != nil {
		return stopped("interrupted"), nil
	}
	if err != nil {
		r.h.recordIfConnection(ctx, r.loc.TargetID, err)
		return fail(reasonOf(err))
	}
	switch {
	case !held[r.w.NewFingerprint]:
		// Nothing to remove (S3's wait is over: an uncertain add cannot land any more).
		res, ferr := r.record(keys.FinishUndo(ctx, r.actor, r.loc.ID, sshkeys.UndoRecord{Definite: true}),
			map[string]any{"state": sshkeys.LocUndone, "found": "new_key_absent"})
		return res, ferr
	case !held[r.w.OldFingerprint]:
		// S12: the old key is already gone; removing the new one could leave the account without a key.
		return fail(sshkeys.ReasonOldKeyGone)
	}
	rec := &writeTracker{next: r.steps}
	res, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: op, OSUser: r.loc.OSUser, FilePath: r.loc.FilePath,
		Fingerprint: r.w.NewFingerprint, ProtectedFingerprints: r.w.Protected, AllowLastRootKey: false}, rec)
	if ctx.Err() != nil {
		return stopped("interrupted"), nil // undoing: the next job lists the file first
	}
	if err != nil {
		r.h.recordIfConnection(ctx, r.loc.TargetID, err)
	}
	switch {
	case err == nil && (!res.Changed || res.Verified):
		out, ferr := r.record(keys.FinishUndo(ctx, r.actor, r.loc.ID, sshkeys.UndoRecord{Definite: true, Res: res}),
			map[string]any{"state": sshkeys.LocUndone, "removed": res.Removed})
		return out, ferr
	case err != nil && definiteNoChange(rec.wrote, res, err):
		return fail(reasonOf(err))
	}
	return stateResult(sshkeys.LocUndoing), nil // uncertain: the next job lists the file first
}
