package sshkeys

import (
	"context"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
)

// The Administrator's decisions on a run (C8). Each takes the run's row lock first and reads its
// state again, so a decision that arrives while a location job works leaves a state that job can
// finish or undo; none of them removes an old key itself (removals pass BeginRemove's gate only).

// decide runs fn on the locked run and calls Advance after the commit.
func (s *Service) decide(ctx context.Context, id uuid.UUID, fn func(tx pgx.Tx, run runRow) error) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		run, err := lockRun(ctx, tx, id)
		if err != nil {
			return err
		}
		return fn(tx, run)
	})
	if err != nil {
		return err
	}
	// The decision is committed: it succeeded. The sweep advances the run if this call cannot
	// (review M5); a retry of the decision answers ErrNotWaiting or does the same again.
	if err := s.Advance(ctx, id); err != nil {
		s.logError("could not advance the rotation after a decision", id, err)
	}
	return nil
}

func (s *Service) auditDecision(ctx context.Context, tx pgx.Tx, a inventory.Actor, run runRow, action string, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	details["rotation_id"] = run.id.String()
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: "rotation", ObjectID: run.id.String(),
		Result: audit.Success, Details: details}); err != nil {
		return err
	}
	return appendStep(ctx, tx, run.id, nil, stepOf(action), "ok", nil, s.clock.Now().UTC())
}

// stepOf is the step name of a decision ("rotation.continued" → "continued").
func stepOf(action string) string {
	for i := len(action) - 1; i >= 0; i-- {
		if action[i] == '.' {
			return action[i+1:]
		}
	}
	return action
}

// Continue lifts the license pause of a run after a renewal (L-84, S6): the license must allow
// changes, and the renewal notice of this pause must already be queued (the first sweep after the
// renewal queues it; before that ErrNoticePending, review I2). Continue never queues the notice
// itself. A waiting decision's deadline moves by the time the run was paused; a paused overlap resumes
// with the duration that remained when the pause began (L-83), its reminder sent again for the new end.
// Then the run advances;
// every removal still needs a fresh re-check of the new key (BeginRemove).
func (s *Service) Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		if err := s.allowedNow(ctx, tx, ActionContinue, run); err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		due := run.decisionDueAt
		if due != nil && run.pausedAt != nil {
			d := due.Add(now.Sub(*run.pausedAt))
			due = &d
		}
		// L-83: an overlap paused in lock resumes with the duration that remained when the pause began
		// (never less than none): its end moves to now + remaining. The end reminder is cleared so that it
		// goes out again for the new end.
		until, reminder := run.overlapUntil, run.reminderSentAt
		if run.status == StatusOverlap && until != nil && run.pausedAt != nil {
			u := now.Add(max(until.Sub(*run.pausedAt), 0))
			until, reminder = &u, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE rotations SET paused_license = false, paused_at = NULL, continued_by = $2, continued_at = $3,
    decision_due_at = $4, overlap_until = $5, reminder_sent_at = $6, updated_at = $3, version = version + 1 WHERE id = $1`,
			id, nullableUser(a.UserID), now, due, until, reminder); err != nil {
			return err
		}
		return s.auditDecision(ctx, tx, a, run, "rotation.continued", nil)
	})
}

// FinishNow ends the overlap at once (status overlap, not paused, the license allows changes) and
// mails the new removal time (row 31); the next Advance enters removing_old.
func (s *Service) FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		if err := s.allowedNow(ctx, tx, ActionFinishNow, run); err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE rotations SET overlap_until = $2, updated_at = $2, version = version + 1 WHERE id = $1", id, now); err != nil {
			return err
		}
		if err := s.mail(ctx, tx, run.policyID, run.oldKeyID, TemplateOverlapEnding, map[string]string{"key_label": run.oldLabel, "overlap_until": mailTime(now)}); err != nil {
			return err
		}
		return s.auditDecision(ctx, tx, a, run, "rotation.finish_requested", nil)
	})
}

// KeepOld keeps the old key where Alice could not test the new one (C8): the run waits for a
// decision, every id is an unverifiable location of the run; those locations and every other
// location of the run in the same (target, file) become kept_old (a shared file is kept as a whole).
// At least one verified location must remain, else ErrNotWaiting and nothing changes. When no
// unverifiable location is left the overlap begins.
func (s *Service) KeepOld(ctx context.Context, a inventory.Actor, id uuid.UUID, locationIDs []uuid.UUID) error {
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		if err := s.allowedNow(ctx, tx, ActionKeepOld, run); err != nil {
			return err
		}
		if len(locationIDs) == 0 {
			return ErrNotWaiting
		}
		locs, err := runLocations(ctx, tx, id)
		if err != nil {
			return err
		}
		type file struct {
			target uuid.UUID
			path   string
		}
		files := map[file]bool{}
		for _, lid := range locationIDs {
			i := slices.IndexFunc(locs, func(l locRow) bool { return l.id == lid })
			if i < 0 || locs[i].state != LocUnverifiable {
				return ErrNotWaiting
			}
			files[file{locs[i].targetID, locs[i].filePath}] = true
		}
		var keep []locRow
		verifiedLeft, unverifiableLeft := 0, 0
		for _, l := range locs {
			inFile := files[file{l.targetID, l.filePath}]
			switch {
			case inFile && (l.state == LocUnverifiable || l.state == LocVerified):
				keep = append(keep, l)
			case l.state == LocVerified:
				verifiedLeft++
			case l.state == LocUnverifiable:
				unverifiableLeft++
			}
		}
		if verifiedLeft == 0 {
			return ErrNotWaiting
		}
		now := s.clock.Now().UTC()
		for _, l := range keep {
			if err := s.setLocation(ctx, tx, a.Audit, l, LocKeptOld, "rotation.old_kept", now, ""); err != nil {
				return err
			}
		}
		if err := s.auditDecision(ctx, tx, a, run, "rotation.old_kept", map[string]string{"location_count": strconv.Itoa(len(keep))}); err != nil {
			return err
		}
		if unverifiableLeft == 0 {
			return s.toOverlap(ctx, tx, a.Audit, run, now)
		}
		return nil
	})
}

// Abort stops a run (C8): previewed → cancelled (rotation.stopped); adding_new, verifying_new or
// overlap → rolling_back (rotation.stopped): planned locations are cancelled and the new key is
// removed again wherever it was added (kept_old included); removing_old or later → ErrNotWaiting.
// The old key is never touched. Abort is the one decision accepted in lock and while paused (Task 13
// review): its undo sends never ask the licence (L-86).
func (s *Service) Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		now := s.clock.Now().UTC()
		if err := s.allowedNow(ctx, tx, ActionAbort, run); err != nil {
			return err
		}
		// The decision's audit row and step first, while the run is live (review M6).
		if err := s.auditDecision(ctx, tx, a, run, "rotation.stop_requested", nil); err != nil {
			return err
		}
		if run.status == StatusDryRunNotified {
			return s.cancelRun(ctx, tx, a.Audit, run, ReasonStopped)
		}
		locs, err := runLocations(ctx, tx, id)
		if err != nil {
			return err
		}
		return s.rollBack(ctx, tx, a.Audit, run, locs, ReasonStopped, now)
	})
}

// Decisions (AllowedActions' names).
const (
	ActionContinue  = "continue"
	ActionFinishNow = "finish_now"
	ActionKeepOld   = "keep_old"
	ActionAbort     = "abort"
)

// decisionView is what decides whether a decision is allowed; AllowedActions and the decision
// functions build it from the same columns and ask the same predicate, so the offer and the call
// cannot drift apart (Task 13 review).
type decisionView struct {
	status                                    string
	paused, renotified, awaiting, anyVerified bool
}

// decisionAllowed is the one predicate per decision: nil, or why not. While the run is paused for the
// licence the only decision is Abort (its undo sends follow L-86); Continue needs the licence and the
// renewal notice queued; Finish now and Keep old need the licence and an unpaused run.
func decisionAllowed(action string, v decisionView, gateOK bool) error {
	switch action {
	case ActionAbort:
		if !slices.Contains([]string{StatusDryRunNotified, StatusAddingNew, StatusVerifyingNew, StatusOverlap}, v.status) {
			return ErrNotWaiting
		}
		return nil
	case ActionContinue:
		switch {
		case slices.Contains(finishedList, v.status) || !v.paused:
			return ErrNotWaiting
		case !gateOK:
			return license.ErrLocked
		case !v.renotified:
			return ErrNoticePending
		}
		return nil
	case ActionFinishNow:
		switch {
		case v.status != StatusOverlap || v.paused:
			return ErrNotWaiting
		case !gateOK:
			return license.ErrLocked
		}
		return nil
	case ActionKeepOld:
		switch {
		case v.status != StatusVerifyingNew || !v.awaiting || !v.anyVerified || v.paused:
			return ErrNotWaiting
		case !gateOK:
			return license.ErrLocked
		}
		return nil
	}
	return ErrNotWaiting
}

// AllowedActions are the decisions the run offers now (the UI's buttons): exactly those
// decisionAllowed accepts.
func AllowedActions(r Rotation, gateOK bool) []string {
	v := decisionView{status: r.Status, paused: r.PausedLicense, renotified: r.RenotifiedAt != nil, awaiting: r.AwaitingDecision,
		anyVerified: slices.ContainsFunc(r.Locations, func(l RotationLocation) bool { return l.State == LocVerified })}
	out := []string{}
	for _, a := range []string{ActionContinue, ActionFinishNow, ActionKeepOld, ActionAbort} {
		if decisionAllowed(a, v, gateOK) == nil {
			out = append(out, a)
		}
	}
	return out
}

// viewOf builds the decision view of a locked run.
func viewOf(ctx context.Context, tx pgx.Tx, run runRow) (decisionView, error) {
	v := decisionView{status: run.status, paused: run.pausedLicense, renotified: run.renotifiedAt != nil, awaiting: run.awaitingDecision}
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM rotation_locations WHERE rotation_id = $1 AND state = 'verified')", run.id).
		Scan(&v.anyVerified)
	return v, err
}

// allowedNow applies the decision's predicate to the locked run.
func (s *Service) allowedNow(ctx context.Context, tx pgx.Tx, action string, run runRow) error {
	v, err := viewOf(ctx, tx, run)
	if err != nil {
		return err
	}
	return decisionAllowed(action, v, s.gateOK())
}
