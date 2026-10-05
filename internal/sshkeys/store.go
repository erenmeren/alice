package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/sshkeys/keymat"
	"alice/internal/sshkeys/plan"
)

// The runner-facing store (C7, C8). Every method: checks the job's claim (inventory.CheckClaimTx:
// a job run that lost its lease writes nothing), locks the run row, then (when it records an
// inventory change) the target, then the location row; applies the rule of C8 for the location's
// state; makes one compare-and-set update; appends the audit row and the step. A rule that does not
// hold answers ErrNotYourTurn (the job stops; the controller or the sweep decides) or ErrPaused.

// Location states of C8 beyond Task 8's.
const (
	LocAdding       = "adding"
	LocAdded        = "added"
	LocAddFailed    = "add_failed"
	LocVerified     = "verified"
	LocUnverifiable = "unverifiable"
	LocVerifyFailed = "verify_failed"
	LocKeptOld      = "kept_old"
	LocRemoving     = "removing"
	LocRemoved      = "removed"
	LocRemoveFailed = "remove_failed"
	LocUndoing      = "undoing"
	LocUndone       = "undone"
	LocUndoFailed   = "undo_failed"
)

// Verify notes (rotation_locations.verify_note) besides the planner's.
const NoteLoginWithoutKey = "login_without_key"

// Store errors the runner treats as "stop here, the controller decides" (no remote call is made).
var (
	ErrNotYourTurn = errors.New("sshkeys: the location is not in the state this step needs")
	ErrPaused      = errors.New("sshkeys: the rotation is paused or the license refuses changes")
)

// LocationWork is what a location job needs (C7).
type LocationWork struct {
	Rotation                       Rotation // without Steps
	Location                       RotationLocation
	OldKeyID                       uuid.UUID
	NewKeyID                       uuid.UUID
	OldFingerprint, NewFingerprint string
	NewLine                        string // the exact line to add: options, new public key, new comment
	Protected                      []string
}

// AddRecord is the outcome of an add (C7).
type AddRecord struct {
	Definite bool // true: the add answered (added or refused); false: uncertain (stays adding)
	Added    bool // the line is in the file (changed or already present)
	LineNo   int
	Reason   string // when !Added and Definite
	Backup   string
	Actor    audit.Actor
}

// VerifyRecord is the outcome of a test login.
type VerifyRecord struct {
	Outcome providers.KeyLoginOutcome // "" when Reason is set
	Reason  string                    // closed reason of a connection failure
}

// RemoveRecord is the outcome of a removal of the old key.
type RemoveRecord struct {
	Definite bool
	Removed  int
	Reason   string
	Backup   string
	Res      providers.AuthKeyResult
}

// UndoRecord is the outcome of an undo (the removal of the new key).
type UndoRecord struct {
	Definite bool
	Reason   string // rotation.old_key_gone (S12): nothing was sent
	Res      providers.AuthKeyResult
}

// locRow is a rotation location as the store reads it.
type locRow struct {
	id, runID, oldLocationID, targetID          uuid.UUID
	n                                           int
	osUser, filePath, options                   string
	state, verifyNote, errorCode                string
	addOpID, removeOpID, undoOpID, newLocation  *uuid.UUID
	addSentAt, verifiedAt, reverified, removeAt *time.Time
	jobCount                                    int
	retries                                     int // remove_retry steps: re-queues of a failed removal (G3)
}

const locSelect = `SELECT id, rotation_id, old_location_id, target_id, n, os_user, file_path, options, state, verify_note, error_code,
    add_op_id, remove_op_id, undo_op_id, new_location_id, add_sent_at, verified_at, reverified_at, remove_sent_at, job_count,
    (SELECT count(*) FROM rotation_steps s WHERE s.location_id = rotation_locations.id AND s.name = 'remove_retry')
FROM rotation_locations`

func scanLoc(row pgx.Row) (locRow, error) {
	var l locRow
	err := row.Scan(&l.id, &l.runID, &l.oldLocationID, &l.targetID, &l.n, &l.osUser, &l.filePath, &l.options, &l.state, &l.verifyNote,
		&l.errorCode, &l.addOpID, &l.removeOpID, &l.undoOpID, &l.newLocation, &l.addSentAt, &l.verifiedAt, &l.reverified, &l.removeAt,
		&l.jobCount, &l.retries)
	if errors.Is(err, pgx.ErrNoRows) {
		return locRow{}, ErrNotFound
	}
	if err != nil {
		return locRow{}, fmt.Errorf("sshkeys: read the rotation location: %w", err)
	}
	return l, nil
}

func (l locRow) ref() locRef {
	return locRef{id: l.id, targetID: l.targetID, osUser: l.osUser, filePath: l.filePath}
}

// lockLocation locks, in the module's order, the location's run, then (lockTarget) its target, then
// the location row.
func lockLocation(ctx context.Context, tx pgx.Tx, id uuid.UUID, lockTarget bool) (runRow, locRow, error) {
	var runID, targetID uuid.UUID
	err := tx.QueryRow(ctx, "SELECT rotation_id, target_id FROM rotation_locations WHERE id = $1", id).Scan(&runID, &targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return runRow{}, locRow{}, ErrNotFound
	}
	if err != nil {
		return runRow{}, locRow{}, fmt.Errorf("sshkeys: read the rotation location: %w", err)
	}
	run, err := lockRun(ctx, tx, runID)
	if err != nil {
		return runRow{}, locRow{}, err
	}
	if lockTarget {
		if _, err := tx.Exec(ctx, "SELECT id FROM targets WHERE id = $1 FOR UPDATE", targetID); err != nil {
			return runRow{}, locRow{}, fmt.Errorf("sshkeys: lock the target: %w", err)
		}
	}
	loc, err := scanLoc(tx.QueryRow(ctx, locSelect+" WHERE id = $1 FOR UPDATE", id))
	return run, loc, err
}

// storeTx runs fn after the claim check, in one transaction.
func (s *Service) storeTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := inventory.CheckClaimTx(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

// jobActor is the audit actor of the store's records: the system actor "jobs" with the job id of
// the context's claim as request id.
func jobActor(ctx context.Context) audit.Actor {
	a := audit.SystemActor("jobs")
	if c, ok := inventory.ClaimFrom(ctx); ok {
		a.RequestID = c.JobID.String()
	}
	return a
}

// closedReason returns r when it is a closed reason ("area.code"), else internal.unexpected: a
// reason never carries free text into the record.
func closedReason(r, fallback string) string {
	if r == "" {
		return fallback
	}
	if !closedReasonRE.MatchString(r) {
		return "internal.unexpected"
	}
	return r
}

// setLocation moves the locked location from its current state to "to" with one compare-and-set
// update (sets: extra assignments from $5 on, constants of this file only) and records the change.
func (s *Service) setLocation(ctx context.Context, tx pgx.Tx, actor audit.Actor, loc locRow, to, reason string, now time.Time,
	sets string, args ...any) error {
	sql := "UPDATE rotation_locations SET state = $2, updated_at = $3" + sets + " WHERE id = $1 AND state = $4"
	tag, err := tx.Exec(ctx, sql, append([]any{loc.id, to, now, loc.state}, args...)...)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "Z1011" {
		// The database refused the location step (the run left the status that allowed it, or a
		// timestamp would go back after a clock step): not this job's turn; the transaction is rolled
		// back and nothing is written.
		return fmt.Errorf("%w (%s)", ErrNotYourTurn, pg.Code)
	}
	if err != nil {
		return fmt.Errorf("sshkeys: update the rotation location: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotYourTurn
	}
	if to == loc.state {
		return nil
	}
	return s.recordLocationState(ctx, tx, actor, loc.runID, loc.ref(), loc.state, to, reason, now)
}

// gateOK is G of C8.
func (s *Service) gateOK() bool { return s.license.Allow(license.ClassChange) == nil }

// LocationWork returns what a location job needs, read now.
func (s *Service) LocationWork(ctx context.Context, locationID uuid.UUID) (LocationWork, error) {
	var w LocationWork
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var runID uuid.UUID
		if err := tx.QueryRow(ctx, "SELECT rotation_id FROM rotation_locations WHERE id = $1", locationID).Scan(&runID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("sshkeys: read the rotation location: %w", err)
		}
		r, err := readRotation(ctx, tx, runID, false)
		if err != nil {
			return err
		}
		w.Rotation, w.OldKeyID, w.OldFingerprint, w.NewFingerprint = r, r.OldKeyID, r.OldFingerprint, r.NewFingerprint
		for _, l := range r.Locations {
			if l.ID == locationID {
				w.Location = l
			}
		}
		if r.NewKeyID != nil {
			w.NewKeyID = *r.NewKeyID
			var pub, comment string
			if err := tx.QueryRow(ctx, "SELECT public_key, key_comment FROM ssh_keys WHERE id = $1", w.NewKeyID).Scan(&pub, &comment); err != nil {
				return fmt.Errorf("sshkeys: read the new key: %w", err)
			}
			if w.NewLine, err = keymat.Line(w.Location.Options, pub, comment); err != nil {
				return fmt.Errorf("sshkeys: build the new key's line: %w", err)
			}
		}
		w.Protected, err = inventory.ProtectedFingerprintsTx(ctx, tx)
		return err
	})
	return w, err
}

// BeginAdd moves a planned location to adding just before its add is sent (C8): the run is adding_new,
// not paused, the license allows changes, the target passes KeyChangeRefusal. A resumed job (state
// adding) gets the same operation id; add_sent_at moves to now (the latest send). Else ErrPaused or
// ErrNotYourTurn.
func (s *Service) BeginAdd(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error) {
	var op uuid.UUID
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, true)
		if err != nil {
			return err
		}
		if run.status != StatusAddingNew || (loc.state != LocPlanned && loc.state != LocAdding) {
			return ErrNotYourTurn
		}
		if !s.gateOK() || run.pausedLicense {
			return ErrPaused
		}
		t, err := s.inv.TargetTx(ctx, tx, loc.targetID, true)
		if err != nil {
			if errors.Is(err, inventory.ErrNotFound) {
				return ErrNotYourTurn
			}
			return err
		}
		if inventory.KeyChangeRefusal(t, loc.osUser) != nil {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if loc.addSentAt != nil && now.Before(*loc.addSentAt) {
			return ErrNotYourTurn // the clock went back: retried later (G14)
		}
		op = uuid.Must(uuid.NewV7())
		if loc.addOpID != nil {
			op = *loc.addOpID
		}
		return s.setLocation(ctx, tx, jobActor(ctx), loc, LocAdding, "", now, ", add_op_id = $5, add_sent_at = $3", op)
	})
	return op, err
}

// recordNewLocation records the new key's line at the location in the inventory (RecordKeyAddedTx)
// and returns the inventory location id.
func (s *Service) recordNewLocation(ctx context.Context, tx pgx.Tx, run runRow, loc locRow, lineNo int, verified bool,
	actor audit.Actor) (uuid.UUID, error) {
	if run.newKeyID == nil {
		return uuid.Nil, ErrNotYourTurn
	}
	var comment string
	if err := tx.QueryRow(ctx, "SELECT key_comment FROM ssh_keys WHERE id = $1", *run.newKeyID).Scan(&comment); err != nil {
		return uuid.Nil, fmt.Errorf("sshkeys: read the new key: %w", err)
	}
	return s.inv.RecordKeyAddedTx(ctx, tx, inventory.KeyAdded{SSHKeyID: *run.newKeyID, TargetID: loc.targetID, OSUser: loc.osUser,
		FilePath: loc.filePath, Options: loc.options, Comment: comment, LineNo: lineNo, Actor: actor, Verified: verified})
}

// FinishAdd records the add's answer (C8): definite and added → added (the inventory records the
// line; a location the plan does not verify, root_login_disabled, goes to unverifiable at once);
// definite and not added → add_failed with the reason; uncertain → stays adding (the login decides).
// Only while the run is adding_new (G8); a run that rolls back undoes the location instead.
func (s *Service) FinishAdd(ctx context.Context, locationID uuid.UUID, r AddRecord) error {
	if !r.Definite {
		return nil
	}
	return s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, true)
		if err != nil {
			return err
		}
		if run.status != StatusAddingNew || loc.state != LocAdding {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		actor := r.Actor
		if actor.Type == "" {
			actor = jobActor(ctx)
		}
		if !r.Added {
			return s.setLocation(ctx, tx, actor, loc, LocAddFailed, closedReason(r.Reason, "rotation.add_failed"), now,
				", error_code = $5, backup = $6", closedReason(r.Reason, "rotation.add_failed"), backupText(r.Backup))
		}
		newLoc, err := s.recordNewLocation(ctx, tx, run, loc, r.LineNo, false, actor)
		if err != nil {
			return err
		}
		to := LocAdded
		if loc.verifyNote == plan.NoteRootLoginDisabled {
			to = LocUnverifiable // the plan tries no login here (C8)
		}
		return s.setLocation(ctx, tx, actor, loc, to, "", now, ", added_line_no = $5, backup = $6, new_location_id = $7",
			lineNoOrNil(r.LineNo), backupText(r.Backup), newLoc)
	})
}

func lineNoOrNil(n int) *int {
	if n < 1 {
		return nil
	}
	return &n
}

// backupText bounds the provider's backup name to the column (it is a path the helper chose).
func backupText(b string) string {
	if len(b) > 200 || !plainText(b) {
		return ""
	}
	return b
}

// RecordVerify records the test login after the add (C8, F2, S4), while the run is adding_new or
// verifying_new (G8): accepted → verified; unprovable, or refused where the line has from= →
// unverifiable (a note the plan set is kept); refused otherwise → verify_failed
// (sshkey.login_failed); a connection failure (Reason) → verify_failed with that reason. From adding
// (the add's answer was lost: F-67) an accepted or unprovable login proves the line is there: the
// inventory records it (S4).
func (s *Service) RecordVerify(ctx context.Context, locationID uuid.UUID, r VerifyRecord) error {
	return s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, true)
		if err != nil {
			return err
		}
		if (run.status != StatusAddingNew && run.status != StatusVerifyingNew) || (loc.state != LocAdding && loc.state != LocAdded) {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if loc.addSentAt != nil && now.Before(*loc.addSentAt) {
			return ErrNotYourTurn // the clock went back (G14)
		}
		actor := jobActor(ctx)
		if r.Reason != "" {
			reason := closedReason(r.Reason, "")
			return s.setLocation(ctx, tx, actor, loc, LocVerifyFailed, reason, now, ", error_code = $5", reason)
		}
		var to, note string
		switch r.Outcome {
		case providers.KeyLoginAccepted:
			to, note = LocVerified, loc.verifyNote
		case providers.KeyLoginUnprovable:
			to, note = LocUnverifiable, loc.verifyNote
			if note == "" {
				note = NoteLoginWithoutKey
			}
		case providers.KeyLoginRefused:
			if !keymat.HasFromOption(loc.options) {
				return s.setLocation(ctx, tx, actor, loc, LocVerifyFailed, ReasonLoginFailed, now, ", error_code = $5", ReasonLoginFailed)
			}
			to, note = LocUnverifiable, plan.NoteFromOption
		default:
			return fmt.Errorf("sshkeys: a verification without outcome or reason")
		}
		newLoc := loc.newLocation
		if loc.state == LocAdding && newLoc == nil {
			id, err := s.recordNewLocation(ctx, tx, run, loc, 0, to == LocVerified, actor)
			if err != nil {
				return err
			}
			newLoc = &id
		}
		if to == LocVerified {
			return s.setLocation(ctx, tx, actor, loc, to, "", now, ", verify_note = $5, new_location_id = $6, verified_at = $3", note, newLoc)
		}
		return s.setLocation(ctx, tx, actor, loc, to, "", now, ", verify_note = $5, new_location_id = $6", note, newLoc)
	})
}

// RecordReverify records the fresh login before a removal (C8, F3): accepted → reverified_at = now
// (strictly after the verification, G4); refused, unprovable or a connection failure → remove_failed
// (rotation.new_key_failed, or the connection reason): the old key stays. Only while the run is
// removing_old, for a location verified or removing. A failed removal (remove_failed, G3) can only
// change into removing: an accepted re-check of it is recorded together with the retried send
// (removing, a new operation id) after every condition of BeginRemove's gate held; a failed re-check
// of it leaves it failed.
func (s *Service) RecordReverify(ctx context.Context, locationID uuid.UUID, r VerifyRecord) error {
	return s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		if run.status != StatusRemovingOld || (loc.state != LocVerified && loc.state != LocRemoving && loc.state != LocRemoveFailed) {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if loc.verifiedAt == nil || !now.After(*loc.verifiedAt) || (loc.reverified != nil && now.Before(*loc.reverified)) {
			return ErrNotYourTurn // not a later login than the verification, or the clock went back (G4, G14)
		}
		actor := jobActor(ctx)
		accepted := r.Outcome == providers.KeyLoginAccepted && r.Reason == ""
		switch {
		case loc.state == LocRemoveFailed && !accepted:
			return nil // stays failed; the old key stays
		case loc.state == LocRemoveFailed:
			if err := s.removeGate(ctx, tx, run, loc, now, now); err != nil {
				return err
			}
			return s.setLocation(ctx, tx, actor, loc, LocRemoving, "", now,
				", reverified_at = $3, remove_op_id = $5, remove_verified_at = $3, remove_sent_at = $3", uuid.Must(uuid.NewV7()))
		case accepted:
			return s.setLocation(ctx, tx, actor, loc, loc.state, "", now, ", reverified_at = $3")
		}
		reason := closedReason(r.Reason, ReasonNewKeyFailed)
		return s.setLocation(ctx, tx, actor, loc, LocRemoveFailed, reason, now, ", error_code = $5", reason)
	})
}

// fileReady reports whether every location of the run in the location's (target, file) is verified,
// removing, removed or (retried) remove_failed: a shared file loses the old key only when every one of
// its users verified (R41 row 29, G9).
func fileReady(ctx context.Context, tx pgx.Tx, loc locRow) (bool, error) {
	var blocked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rotation_locations WHERE rotation_id = $1 AND target_id = $2 AND file_path = $3
AND state NOT IN ('verified', 'removing', 'removed', 'remove_failed'))`, loc.runID, loc.targetID, loc.filePath).Scan(&blocked)
	if err != nil {
		return false, fmt.Errorf("sshkeys: read the file's locations: %w", err)
	}
	return !blocked, nil
}

// BeginRemove moves a verified location to removing just before the old key's removal is sent (C8):
// the one way to obtain the operation id RemoveAuthorizedKey of the old key is called with. It needs
// the run removing_old with removal_allowed, not paused, the license gate, a re-check of the new key
// at most ReverifyFreshness old and later than the verification, every location of the run in that
// file verified, the new key's line recorded and live, and an old key that is not Alice's own. A
// resumed removal (removing) keeps its operation id; a retried one (remove_failed, G3) passes the same
// gate. The database checks all of it again.
func (s *Service) BeginRemove(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error) {
	var op uuid.UUID
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if loc.state != LocVerified && loc.state != LocRemoving {
			return ErrNotYourTurn // a failed removal is retried through RecordReverify (G3)
		}
		if loc.reverified == nil {
			return ErrNotYourTurn
		}
		if err := s.removeGate(ctx, tx, run, loc, *loc.reverified, now); err != nil {
			return err
		}
		op = uuid.Must(uuid.NewV7())
		reset := ", job_count = 0"
		if loc.state == LocRemoving && loc.removeOpID != nil {
			op, reset = *loc.removeOpID, ""
		}
		return s.setLocation(ctx, tx, jobActor(ctx), loc, LocRemoving, "", now,
			", remove_op_id = $5, remove_verified_at = reverified_at, remove_sent_at = $3"+reset, op)
	})
	return op, err
}

// removeGate is every condition of the old-key gate the store checks before a removal is sent
// (C8, G3-G9): the run removing_old with removal_allowed, not paused, the license gate; a re-check at
// reverified that is later than the verification and fresh at now; the clock not gone back; every
// location of the run in that file verified; the new key's line recorded and live; an old key that is
// not Alice's own. The database checks all of it again.
func (s *Service) removeGate(ctx context.Context, tx pgx.Tx, run runRow, loc locRow, reverified, now time.Time) error {
	if run.status != StatusRemovingOld || !run.removalAllowed {
		return ErrNotYourTurn
	}
	if !s.gateOK() || run.pausedLicense {
		return ErrPaused
	}
	switch {
	case loc.verifiedAt == nil || !reverified.After(*loc.verifiedAt):
		return ErrNotYourTurn
	case !plan.Fresh(now, reverified):
		return ErrNotYourTurn
	case loc.removeAt != nil && now.Before(*loc.removeAt):
		return ErrNotYourTurn // the clock went back (G14)
	case loc.newLocation == nil:
		return ErrNotYourTurn
	}
	ready, err := fileReady(ctx, tx, loc)
	if err != nil {
		return err
	}
	if !ready {
		return ErrNotYourTurn
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ssh_key_locations WHERE id = $1 AND missing_since IS NULL
AND removed_by_alice_at IS NULL)`, *loc.newLocation).Scan(&live); err != nil {
		return fmt.Errorf("sshkeys: read the new key's location: %w", err)
	}
	if !live {
		return ErrNotYourTurn
	}
	protected, err := inventory.ProtectedFingerprintsTx(ctx, tx)
	if err != nil {
		return err
	}
	if slices.Contains(protected, run.oldFingerprint) {
		return ErrOwnKeyProtected
	}
	return nil
}

func errIf(cond bool, err error) error {
	if cond {
		return err
	}
	return nil
}

// FinishRemove records the removal's answer (C8): definite without a reason → removed (the inventory
// marks the old location removed when lines were removed); definite with a reason → remove_failed;
// uncertain → stays removing (a later job re-checks the new key and sends again).
func (s *Service) FinishRemove(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r RemoveRecord) error {
	if !r.Definite {
		return nil
	}
	var oldLocation uuid.UUID
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		if run.status != StatusRemovingOld || loc.state != LocRemoving {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if loc.removeAt != nil && now.Before(*loc.removeAt) {
			return ErrNotYourTurn // the clock went back (G14)
		}
		oldLocation = loc.oldLocationID
		if r.Reason != "" {
			reason := closedReason(r.Reason, "")
			return s.setLocation(ctx, tx, actor, loc, LocRemoveFailed, reason, now, ", error_code = $5, backup = $6", reason,
				backupText(r.Backup))
		}
		return s.setLocation(ctx, tx, actor, loc, LocRemoved, "", now, ", removed_at = $3, backup = $5", backupText(r.Backup))
	})
	if err != nil || r.Reason != "" || r.Removed < 1 {
		return err
	}
	// The inventory records the removal in its own transaction; when this fails the next scan finds
	// the location missing (the run is not affected).
	if err := s.inv.MarkKeyRemoved(ctx, oldLocation, actor, r.Res); err != nil {
		s.log.Warn("could not record a removal in the inventory", "location_id", oldLocation.String(), "error_type", fmt.Sprintf("%T", err))
	}
	return nil
}

// undoWait is how long after the add was sent an undo of an add that never had a definite answer
// waits (S3): a helper still working may write until its budget ends.
func (s *Service) undoWait() time.Duration { return s.helperBudget + undoGrace }

// undoGrace is the margin after the helper's budget (S3).
const undoGrace = 30 * time.Second

// uncertainAdd reports whether the location's add never had a definite answer: no recorded line and
// the add was sent (adding, a refused or failed login after it, or retries exhausted while adding).
func uncertainAdd(loc locRow) bool {
	if loc.newLocation != nil || loc.addSentAt == nil {
		return false
	}
	switch loc.state {
	case LocAdding, LocVerifyFailed:
		return true
	case LocAddFailed:
		return loc.errorCode == ReasonRetriesExhausted
	}
	return false
}

// undoable are the states from which the new key is removed again (C8).
var undoable = []string{LocAdding, LocAdded, LocVerified, LocUnverifiable, LocVerifyFailed, LocAddFailed, LocKeptOld, LocUndoing}

// BeginUndo moves a location whose add was sent to undoing just before the new key's removal is sent
// (C8): only while the run rolls back; never asks the license (L-86); never for the old key (the
// undo removes the new fingerprint). An add that never had a definite answer waits until add_sent_at
// + the helper's budget + 30 s (S3), answering ErrNotYourTurn until then. A resumed undo keeps its
// operation id.
func (s *Service) BeginUndo(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error) {
	var op uuid.UUID
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		if run.status != StatusRollingBack || loc.addSentAt == nil || !slices.Contains(undoable, loc.state) {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if uncertainAdd(loc) && now.Before(loc.addSentAt.Add(s.undoWait())) {
			return ErrNotYourTurn
		}
		if now.Before(*loc.addSentAt) {
			return ErrNotYourTurn // the clock went back (G14)
		}
		op = uuid.Must(uuid.NewV7())
		reset := ", job_count = 0"
		if loc.undoOpID != nil {
			op, reset = *loc.undoOpID, ""
		}
		return s.setLocation(ctx, tx, jobActor(ctx), loc, LocUndoing, "", now, ", undo_op_id = $5, undo_sent_at = $3"+reset, op)
	})
	return op, err
}

// FinishUndo records the undo's answer (C8): definite without a reason → undone (the inventory marks
// the new key's location removed when lines were removed); definite with a reason → undo_failed
// (rotation.old_key_gone when the old key was already gone and nothing was sent, S12); uncertain →
// stays undoing. A location still pending its undo (no BeginUndo: nothing was sent) may end
// undo_failed with a reason directly (G2).
func (s *Service) FinishUndo(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r UndoRecord) error {
	if !r.Definite {
		return nil
	}
	var newLocation *uuid.UUID
	err := s.storeTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		if run.status != StatusRollingBack {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		switch {
		case loc.state == LocUndoing && r.Reason == "":
			newLocation = loc.newLocation
			return s.setLocation(ctx, tx, actor, loc, LocUndone, "", now, "")
		case r.Reason != "" && (loc.state == LocUndoing || (loc.addSentAt != nil && slices.Contains(undoable, loc.state))):
			reason := closedReason(r.Reason, "")
			return s.setLocation(ctx, tx, actor, loc, LocUndoFailed, reason, now, ", error_code = $5", reason)
		}
		return ErrNotYourTurn
	})
	if err != nil || newLocation == nil || r.Res.Removed < 1 {
		return err
	}
	if err := s.inv.MarkKeyRemoved(ctx, *newLocation, actor, r.Res); err != nil {
		s.log.Warn("could not record an undo in the inventory", "location_id", newLocation.String(), "error_type", fmt.Sprintf("%T", err))
	}
	return nil
}

// stepNameRE is rotation_steps.name.
var stepNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Step records one externally visible step of a location job (params are public: ids, codes,
// counts; never a secret).
func (s *Service) Step(ctx context.Context, rotationID uuid.UUID, locationID *uuid.UUID, name string, status providers.StepStatus,
	params map[string]string) error {
	if !stepNameRE.MatchString(name) {
		return fmt.Errorf("sshkeys: %q is not a step name", name)
	}
	return s.storeTx(ctx, func(tx pgx.Tx) error {
		if _, err := lockRun(ctx, tx, rotationID); err != nil {
			return err
		}
		return appendStep(ctx, tx, rotationID, locationID, name, string(status), params, s.clock.Now().UTC())
	})
}
