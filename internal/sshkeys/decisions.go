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
	return s.Advance(ctx, id)
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

// Continue lifts the license pause of a run after a renewal (L-84): the license must allow changes;
// the renewal notice (rotation.preview_after_license) is sent now unless the sweep already sent it; a
// waiting decision's deadline moves by the time the run was paused (S6). Then the run advances; every
// removal still needs a fresh re-check of the new key (BeginRemove).
func (s *Service) Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return err
	}
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		if run.finished() || !run.pausedLicense {
			return ErrNotWaiting
		}
		now := s.clock.Now().UTC()
		due := run.decisionDueAt
		if due != nil && run.pausedAt != nil {
			d := due.Add(now.Sub(*run.pausedAt))
			due = &d
		}
		if _, err := tx.Exec(ctx, `UPDATE rotations SET paused_license = false, paused_at = NULL, continued_by = $2, continued_at = $3,
    decision_due_at = $4, updated_at = $3, version = version + 1 WHERE id = $1`, id, nullableUser(a.UserID), now, due); err != nil {
			return err
		}
		if run.renotifiedAt == nil {
			if err := s.renotify(ctx, tx, run, now); err != nil {
				return err
			}
		}
		return s.auditDecision(ctx, tx, a, run, "rotation.continued", nil)
	})
}

// FinishNow ends the overlap at once (status overlap, not paused, the license allows changes) and
// mails the new removal time (row 31); the next Advance enters removing_old.
func (s *Service) FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return err
	}
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		if run.status != StatusOverlap || run.pausedLicense {
			return ErrNotWaiting
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE rotations SET overlap_until = $2, updated_at = $2, version = version + 1 WHERE id = $1", id, now); err != nil {
			return err
		}
		if err := s.mail(ctx, tx, TemplateOverlapEnding, map[string]string{"key_label": run.oldLabel, "overlap_until": mailTime(now)}); err != nil {
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
		if run.status != StatusVerifyingNew || !run.awaitingDecision || len(locationIDs) == 0 {
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
// The old key is never touched. The license must allow changes (AllowedActions).
func (s *Service) Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return err
	}
	return s.decide(ctx, id, func(tx pgx.Tx, run runRow) error {
		now := s.clock.Now().UTC()
		switch run.status {
		case StatusDryRunNotified:
			if err := s.cancelRun(ctx, tx, a.Audit, run, ReasonStopped); err != nil {
				return err
			}
		case StatusAddingNew, StatusVerifyingNew, StatusOverlap:
			locs, err := runLocations(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := s.rollBack(ctx, tx, a.Audit, run, locs, ReasonStopped, now); err != nil {
				return err
			}
		default:
			return ErrNotWaiting
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.stop_requested", ObjectType: "rotation",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"rotation_id": id.String()}})
		return err
	})
}

// AllowedActions are the decisions the run offers now (the UI's buttons).
func AllowedActions(r Rotation, gateOK bool) []string {
	out := []string{}
	if r.PausedLicense && gateOK && !slices.Contains(finishedList, r.Status) {
		out = append(out, "continue")
	}
	if r.Status == StatusOverlap && !r.PausedLicense && gateOK {
		out = append(out, "finish_now")
	}
	if r.Status == StatusVerifyingNew && r.AwaitingDecision && slices.ContainsFunc(r.Locations, func(l RotationLocation) bool {
		return l.State == LocVerified
	}) {
		out = append(out, "keep_old")
	}
	if gateOK && slices.Contains([]string{StatusDryRunNotified, StatusAddingNew, StatusVerifyingNew, StatusOverlap}, r.Status) {
		out = append(out, "abort")
	}
	return out
}
