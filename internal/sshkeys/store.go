package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
	retries                                     int        // remove_retry steps: re-queues of a failed removal (G3)
	lastResend                                  *time.Time // add_resent_at: the latest add re-send (G25)
	resendCount                                 int        // add_resend_count
	removeFailedAt                              *time.Time // remove_failed_at, stamped by the database (G20)
	addAnswered                                 bool       // FinishAdd recorded a definite answer (add_answered step)
}

const locSelect = `SELECT id, rotation_id, old_location_id, target_id, n, os_user, file_path, options, state, verify_note, error_code,
    add_op_id, remove_op_id, undo_op_id, new_location_id, add_sent_at, verified_at, reverified_at, remove_sent_at, job_count,
    (SELECT count(*) FILTER (WHERE s.name = 'remove_retry') - count(*) FILTER (WHERE s.name = 'retry_returned') FROM rotation_steps s
        WHERE s.location_id = rotation_locations.id AND s.name IN ('remove_retry', 'retry_returned')
        AND s.n > coalesce((SELECT max(p.n) FROM rotation_steps p WHERE p.rotation_id = rotation_locations.rotation_id AND p.name = 'paused'), 0)),
    add_resent_at, add_resend_count, remove_failed_at,
    EXISTS (SELECT 1 FROM rotation_steps s WHERE s.location_id = rotation_locations.id AND s.name = 'add_answered')
FROM rotation_locations`

func scanLoc(row pgx.Row) (locRow, error) {
	var l locRow
	err := row.Scan(&l.id, &l.runID, &l.oldLocationID, &l.targetID, &l.n, &l.osUser, &l.filePath, &l.options, &l.state, &l.verifyNote,
		&l.errorCode, &l.addOpID, &l.removeOpID, &l.undoOpID, &l.newLocation, &l.addSentAt, &l.verifiedAt, &l.reverified, &l.removeAt,
		&l.jobCount, &l.retries, &l.lastResend, &l.resendCount, &l.removeFailedAt, &l.addAnswered)
	if errors.Is(err, pgx.ErrNoRows) {
		return locRow{}, ErrNotFound
	}
	if err != nil {
		return locRow{}, fmt.Errorf("sshkeys: read the rotation location: %w", err)
	}
	l.lastResend, l.removeFailedAt = utcPtr(l.lastResend), utcPtr(l.removeFailedAt)
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

// GuardRefusal is a location step the database refused (SQLSTATE Z1011, its constraint and fixed
// message; never data). For a location job it means "not your turn" (a late result: the run left the
// status that allowed it, or a clock step); for the controller, a decision or the sweep it is a store
// bug and returned as an error (review M1).
type GuardRefusal struct{ Code, Constraint, Message string }

func (g *GuardRefusal) Error() string {
	return "sshkeys: the database refused a rotation step (" + g.Code + " " + g.Constraint + ": " + g.Message + ")"
}

// jobTx is storeTx for the location jobs' store calls: a guard refusal is logged at warn and answered
// ErrNotYourTurn (nothing was written).
func (s *Service) jobTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	err := s.storeTx(ctx, fn)
	var g *GuardRefusal
	if errors.As(err, &g) {
		s.log.Warn("the database refused a rotation step", "sqlstate", g.Code, "constraint", g.Constraint, "guard", g.Message)
		return fmt.Errorf("%w (%s)", ErrNotYourTurn, g.Code)
	}
	return err
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
		return &GuardRefusal{Code: pg.Code, Constraint: pg.ConstraintName, Message: pg.Message}
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
// not paused, the license allows changes, and the planner's send-time rule finds no reason to skip it
// (skipAtSend: the durable skip reasons, KeyChangeRefusal's and the connection-account rule's among
// them; review M4, re-review A-m2). A resumed job (state adding) gets the same operation id;
// add_sent_at keeps the first send and the re-send is recorded in add_resend_count/add_resent_at (G16, G25). Else ErrPaused or
// ErrNotYourTurn.
func (s *Service) BeginAdd(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error) {
	var op uuid.UUID
	refused, paused := "", false
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		refused, paused = "", false
		run, loc, err := lockLocation(ctx, tx, locationID, true)
		if err != nil {
			return err
		}
		if run.status != StatusAddingNew || (loc.state != LocPlanned && loc.state != LocAdding) {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if !s.gateOK() || run.pausedLicense {
			paused = true
			return s.giveRetryBack(ctx, tx, loc, now) // a lock shorter than a sweep uses up no retry (M11)
		}
		skip, err := s.skipAtSend(ctx, tx, run, loc)
		if err != nil {
			return err
		}
		if skip != "" {
			// A cause the planner skips, found at send time (the scan changed since the start): the
			// location ends at once, definitely, with its reason; no retry is used and the others carry
			// on (re-review N1, M7). A planned row was never sent: cancelled; a row already adding failed
			// definitely (its earlier send is undone if the run rolls back, ruling 2).
			code := ReasonSkippedAtSend
			switch skip {
			case plan.SkipConnectionFilesUnknown:
				code = ReasonConnectionFilesUnknown
			case plan.SkipConnectionAccount, plan.SkipConnectionAccountFile:
				code = ReasonConnectionAccountFile
			}
			refused = code
			if loc.state == LocPlanned {
				return s.setLocation(ctx, tx, jobActor(ctx), loc, LocCancelled, code, now, ", error_code = $5, skip_reason = $6", code, skip)
			}
			return s.setLocation(ctx, tx, jobActor(ctx), loc, LocAddFailed, code, now, ", error_code = $5, skip_reason = $6", code, skip)
		}
		if loc.addSentAt != nil && now.Before(lastAddSend(loc)) {
			return ErrNotYourTurn // the clock went back: retried later (G14)
		}
		if loc.state == LocAdding && loc.addOpID != nil {
			// A resumed add re-sends with the same operation id. add_sent_at keeps the first send
			// (G16); the re-send is recorded on the row (add_resend_count, add_resent_at: G25), which
			// the undo's wait counts from (S3).
			op = *loc.addOpID
			return s.setLocation(ctx, tx, jobActor(ctx), loc, LocAdding, "", now,
				", add_resend_count = add_resend_count + 1, add_resent_at = $3")
		}
		op = uuid.Must(uuid.NewV7())
		return s.setLocation(ctx, tx, jobActor(ctx), loc, LocAdding, "", now, ", add_op_id = $5, add_sent_at = $3", op)
	})
	switch {
	case err == nil && paused:
		return uuid.Nil, ErrPaused
	case err == nil && refused != "":
		return uuid.Nil, fmt.Errorf("%w (%s)", ErrNotYourTurn, refused)
	}
	return op, err
}

// skipAtSend is the planner's skip reason for the location now, "" when it may be sent: plan.SkipAtSend
// on the facts the planner reads (toPlanInput of its target and the key's locations), so a preview
// made now would show the same reason (preview = run). The durable reasons are re-evaluated
// (plan.SkipsAtSend, the shared-file rule included); a connection state is not (re-review A-m2).
func (s *Service) skipAtSend(ctx context.Context, tx pgx.Tx, run runRow, loc locRow) (string, error) {
	t, err := s.inv.TargetTx(ctx, tx, loc.targetID, true)
	known := err == nil
	if err != nil && !errors.Is(err, inventory.ErrNotFound) {
		return "", err
	}
	locs, err := s.inv.KeyLocationsTx(ctx, tx, run.oldKeyID, false)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(locs, func(l inventory.KeyLocation) bool { return l.ID == loc.oldLocationID })
	if i < 0 {
		return plan.SkipMissing, nil // removed by Alice, or its server is deleted
	}
	inFile := 0
	for _, l := range locs {
		if l.TargetID == loc.targetID && l.FilePath == locs[i].FilePath {
			inFile++
		}
	}
	in := toPlanInput(keyRow{}, locs[i:i+1], map[uuid.UUID]inventory.Target{loc.targetID: t}, nil, Policy{}, time.Time{})
	return plan.SkipAtSend(in.Targets[loc.targetID], known, in.Locations[0], inFile), nil
}

// giveRetryBack returns the retry a job answered ErrPaused with (M11): its job_count goes down by one.
func (s *Service) giveRetryBack(ctx context.Context, tx pgx.Tx, loc locRow, now time.Time) error {
	if loc.jobCount == 0 || !slices.Contains([]string{LocPlanned, LocAdding, LocAdded, LocVerified, LocRemoving}, loc.state) {
		return nil
	}
	return s.setLocation(ctx, tx, jobActor(ctx), loc, loc.state, "", now, ", job_count = job_count - 1")
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
	return s.jobTx(ctx, func(tx pgx.Tx) error {
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
		id := loc.id
		if err := appendStep(ctx, tx, loc.runID, &id, "add_answered", "ok", map[string]string{"added": strconv.FormatBool(r.Added)},
			now); err != nil {
			return err
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
	return s.jobTx(ctx, func(tx pgx.Tx) error {
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
		if loc.state == LocAdding && newLoc == nil && r.Outcome != providers.KeyLoginRefused {
			// S4: an accepted or unprovable login after an add without an answer records the line.
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
	pausedRetry := false
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		pausedRetry = false
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
			if (loc.reverified != nil && !now.After(*loc.reverified)) || (loc.removeAt != nil && !now.After(*loc.removeAt)) ||
				(loc.removeFailedAt != nil && !now.After(*loc.removeFailedAt)) {
				return ErrNotYourTurn // G3', G20: a strictly newer re-check, later than the failed send and the failure
			}
			if err := s.removeGate(ctx, tx, run, loc, now, now); err != nil {
				if errors.Is(err, ErrPaused) && loc.retries > 0 {
					// A short lock uses up no retry (M11): the retry is given back as a step.
					id := loc.id
					if serr := appendStep(ctx, tx, loc.runID, &id, "retry_returned", "skipped", nil, now); serr != nil {
						return serr
					}
					pausedRetry = true
					return nil
				}
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
	if err == nil && pausedRetry {
		return ErrPaused
	}
	return err
}

// fileReady reports whether every other location of the run in the location's (target, file) is
// verified, removed, or removing on a re-check of its own at most ReverifyFreshness before now (G22): a shared file loses the old key only when every one of its users
// verified (R41 row 29; G18 as built: a skipped, kept, unverifiable or failed sibling blocks the whole
// file, a sibling already removing or removed does not).
func fileReady(ctx context.Context, tx pgx.Tx, loc locRow, now time.Time) (bool, error) {
	var blocked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rotation_locations WHERE rotation_id = $1 AND target_id = $2 AND file_path = $3
AND id <> $4 AND (state NOT IN ('verified', 'removing', 'removed')
    OR (state = 'removing' AND (reverified_at IS NULL OR reverified_at < $5))))`, loc.runID, loc.targetID, loc.filePath, loc.id,
		now.Add(-ReverifyFreshness)).Scan(&blocked)
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
	paused := false
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		paused = false
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
			if errors.Is(err, ErrPaused) {
				paused = true
				return s.giveRetryBack(ctx, tx, loc, now)
			}
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
	if err == nil && paused {
		return uuid.Nil, ErrPaused
	}
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
	ready, err := fileReady(ctx, tx, loc, now)
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
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if loc.state == LocRemoveFailed && loc.errorCode == ReasonRetriesExhausted && r.Reason == "" {
			// A definite answer after the sweep gave up on the row (review M9): the server changed.
			oldLocation = loc.oldLocationID
			return s.lateResult(ctx, tx, run, loc, LocRemoved, r.Removed, now)
		}
		if run.status != StatusRemovingOld || loc.state != LocRemoving {
			return ErrNotYourTurn
		}
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

// lateResult records a definite remove or undo answer that arrived after the sweep exhausted the
// location (review M9): the row stays as the guards require; a late_result step says what the server
// did, a scan of the server is queued so the inventory catches up, and a run that already needs
// attention mails it again (code rotation.late_result). The caller marks the inventory location.
func (s *Service) lateResult(ctx context.Context, tx pgx.Tx, run runRow, loc locRow, result string, removed int, now time.Time) error {
	id := loc.id
	var seen bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM rotation_steps WHERE location_id = $1 AND name = 'late_result')", id).
		Scan(&seen); err != nil {
		return fmt.Errorf("sshkeys: read the location's late results: %w", err)
	}
	if seen {
		return nil // recorded once per location (re-review N5)
	}
	if err := appendStep(ctx, tx, run.id, &id, "late_result", "ok", map[string]string{"result": result,
		"removed_count": strconv.Itoa(removed)}, now); err != nil {
		return err
	}
	if err := s.queueDiscovery(ctx, tx, loc.targetID); err != nil {
		return err
	}
	var server string
	if err := tx.QueryRow(ctx, "SELECT name::text FROM targets WHERE id = $1", loc.targetID).Scan(&server); err != nil {
		return fmt.Errorf("sshkeys: read the server: %w", err)
	}
	// Its own template (once per location): what the server did after the run gave up on it.
	return s.mail(ctx, tx, TemplateLateResult, map[string]string{"key_label": run.oldLabel, "server": server, "os_user": loc.osUser,
		"file_path": loc.filePath, "result": result, "rotation_id": run.id.String()})
}

// queueDiscovery queues a scan of the server (deduped) so the inventory catches up with a file the
// rotation may have left changed.
func (s *Service) queueDiscovery(ctx context.Context, tx pgx.Tx, targetID uuid.UUID) error {
	_, err := s.jobs.EnqueueTx(ctx, tx, inventory.JobRequest{Type: inventory.JobDiscover, TargetID: targetID,
		Payload: map[string]string{}, Kind: "system", DedupeKey: "target.discover:" + targetID.String() + ":rotation"})
	return err
}

// undoWait is how long after the add was sent an undo of an add that never had a definite answer
// waits (S3): a helper still working may write until its budget ends.
func (s *Service) undoWait() time.Duration { return s.helperBudget + undoGrace }

// lastAddSend is the latest send of the location's add: add_sent_at or the latest re-send (add_resent_at, G25).
func lastAddSend(l locRow) time.Time {
	t := *l.addSentAt
	if l.lastResend != nil && l.lastResend.After(t) {
		t = *l.lastResend
	}
	return t
}

// undoMustWait reports whether the undo of an add without a definite answer must still wait (S3).
func (s *Service) undoMustWait(l locRow, now time.Time) bool {
	return uncertainAdd(l) && now.Before(lastAddSend(l).Add(s.undoWait()))
}

// undoGrace is the margin after the helper's budget (S3).
const undoGrace = 30 * time.Second

// uncertainAdd reports whether the location's add was sent and may still land: no accepted login was
// recorded (verified_at), and either FinishAdd recorded no definite answer or the add was re-sent: an
// answer to a re-send says nothing about an earlier send of the same operation, which may still be
// running within its helper budget (S3; review I1, re-review N3).
func uncertainAdd(loc locRow) bool {
	return loc.addSentAt != nil && loc.verifiedAt == nil && (!loc.addAnswered || loc.resendCount > 0)
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
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		if run.status != StatusRollingBack || loc.addSentAt == nil || !slices.Contains(undoable, loc.state) {
			return ErrNotYourTurn
		}
		now := s.clock.Now().UTC()
		if s.undoMustWait(loc, now) {
			return ErrNotYourTurn
		}
		if now.Before(lastAddSend(loc)) {
			return ErrNotYourTurn // the clock went back behind the latest send (G14; re-review M1)
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
	err := s.jobTx(ctx, func(tx pgx.Tx) error {
		run, loc, err := lockLocation(ctx, tx, locationID, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if loc.state == LocUndoFailed && loc.errorCode == ReasonRetriesExhausted && r.Reason == "" {
			// A definite answer after the sweep gave up on the row (review M9): the server changed.
			newLocation = loc.newLocation
			return s.lateResult(ctx, tx, run, loc, LocUndone, r.Res.Removed, now)
		}
		if run.status != StatusRollingBack {
			return ErrNotYourTurn
		}
		switch {
		case loc.state == LocUndoing && r.Reason == "":
			newLocation = loc.newLocation
			return s.setLocation(ctx, tx, actor, loc, LocUndone, "", now, "")
		case r.Reason != "" && (loc.state == LocUndoing || (loc.addSentAt != nil && loc.state != LocAdding && slices.Contains(undoable, loc.state))):
			// G2, G17: a pending undo may end without a send, except a row still adding (its add may
			// still land; it gets a real undo attempt).
			reason := closedReason(r.Reason, "")
			if err := s.setLocation(ctx, tx, actor, loc, LocUndoFailed, reason, now, ", error_code = $5", reason); err != nil {
				return err
			}
			return s.queueDiscovery(ctx, tx, loc.targetID) // the new key may be left there (re-review N4)
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
