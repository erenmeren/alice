package sshkeys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/sshkeys/plan"
)

// Run statuses (rotations.status, C8).
const (
	StatusDryRunNotified = "dry_run_notified"
	StatusAddingNew      = "adding_new"
	StatusVerifyingNew   = "verifying_new"
	StatusOverlap        = "overlap"
	StatusRemovingOld    = "removing_old"
	StatusCompleted      = "completed"
	StatusRollingBack    = "rolling_back"
	StatusAborted        = "aborted"
	StatusNeedsAttention = "needs_attention"
	StatusCancelled      = "cancelled"
)

// Location states used by Task 8 (rotation_locations.state; Task 9 adds the rest of C8's).
const (
	LocPlanned   = "planned"
	LocSkipped   = "skipped"
	LocCancelled = "cancelled"
)

// Rotation is one run with its locations and steps (C7).
type Rotation struct {
	ID, PolicyID, OldKeyID                          uuid.UUID
	NewKeyID                                        *uuid.UUID
	OldFingerprint                                  string
	NewFingerprint                                  string
	Trigger, Status                                 string
	PausedLicense                                   bool
	RenotifiedAt                                    *time.Time // the renewal notice of the current pause (S6)
	AwaitingDecision                                bool
	DecisionDueAt                                   *time.Time
	Plan                                            plan.Plan
	Digest                                          string
	NewKeyType                                      string
	OverlapMinutes                                  int
	PlannedFor, NotifiedAt                          time.Time
	StartedAt, VerifiedAt, OverlapUntil, FinishedAt *time.Time
	ResultCode                                      string
	KeptCount                                       int // where the old key stays (skipped, kept_old; S11)
	Locations                                       []RotationLocation
	Steps                                           []Step
	Version                                         int
}

// RotationLocation is one location of a run.
type RotationLocation struct {
	ID, OldLocationID, TargetID                                  uuid.UUID
	N                                                            int
	TargetName, OSUser, FilePath, Options                        string
	State, SkipReason, VerifyNote, ErrorCode, Backup             string
	AddSentAt, VerifiedAt, ReverifiedAt, RemoveSentAt, RemovedAt *time.Time
	NewLocationID                                                *uuid.UUID
	AddOpID, RemoveOpID, UndoOpID                                uuid.UUID // uuid.Nil until the step began
}

// Step is one recorded step of a run (§26.8).
type Step struct {
	N          int
	LocationID *uuid.UUID
	Name       string
	Status     string
	At         time.Time
	Params     map[string]string
}

// finishedList is finishedStatuses as a Go list.
var finishedList = []string{StatusCompleted, StatusAborted, StatusNeedsAttention, StatusCancelled}

// Rotation returns one run with its locations and steps; ErrNotFound.
func (s *Service) Rotation(ctx context.Context, id uuid.UUID) (Rotation, error) {
	var r Rotation
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		r, err = readRotation(ctx, tx, id, true)
		return err
	})
	return r, err
}

// readRotation reads a run; with steps, its steps too.
func readRotation(ctx context.Context, q db.Querier, id uuid.UUID, steps bool) (Rotation, error) {
	var (
		r       Rotation
		rawPlan []byte
	)
	err := q.QueryRow(ctx, `SELECT r.id, r.policy_id, r.old_ssh_key_id, r.new_ssh_key_id, ok.fingerprint_sha256, coalesce(nk.fingerprint_sha256, ''),
    r.trigger, r.status, r.paused_license, r.awaiting_decision, r.decision_due_at, r.plan, r.plan_digest, r.new_key_type, r.overlap_minutes,
    r.planned_for, r.notified_at, r.started_at, r.verified_at, r.overlap_until, r.finished_at, r.result_code, r.version, r.kept_count, r.renotified_at
FROM rotations r JOIN ssh_keys ok ON ok.id = r.old_ssh_key_id LEFT JOIN ssh_keys nk ON nk.id = r.new_ssh_key_id WHERE r.id = $1`, id).Scan(
		&r.ID, &r.PolicyID, &r.OldKeyID, &r.NewKeyID, &r.OldFingerprint, &r.NewFingerprint, &r.Trigger, &r.Status, &r.PausedLicense,
		&r.AwaitingDecision, &r.DecisionDueAt, &rawPlan, &r.Digest, &r.NewKeyType, &r.OverlapMinutes, &r.PlannedFor, &r.NotifiedAt,
		&r.StartedAt, &r.VerifiedAt, &r.OverlapUntil, &r.FinishedAt, &r.ResultCode, &r.Version, &r.KeptCount, &r.RenotifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrNotFound
	}
	if err != nil {
		return Rotation{}, fmt.Errorf("sshkeys: read the rotation: %w", err)
	}
	if err := json.Unmarshal(rawPlan, &r.Plan); err != nil {
		return Rotation{}, fmt.Errorf("sshkeys: decode the rotation's plan: %w", err)
	}
	r.PlannedFor, r.NotifiedAt = r.PlannedFor.UTC(), r.NotifiedAt.UTC()
	r.DecisionDueAt, r.StartedAt, r.VerifiedAt = utcPtr(r.DecisionDueAt), utcPtr(r.StartedAt), utcPtr(r.VerifiedAt)
	r.OverlapUntil, r.FinishedAt, r.RenotifiedAt = utcPtr(r.OverlapUntil), utcPtr(r.FinishedAt), utcPtr(r.RenotifiedAt)
	if r.Locations, err = readRotationLocations(ctx, q, id); err != nil {
		return Rotation{}, err
	}
	if steps {
		if r.Steps, err = readSteps(ctx, q, id); err != nil {
			return Rotation{}, err
		}
	}
	return r, nil
}

func readRotationLocations(ctx context.Context, q db.Querier, runID uuid.UUID) ([]RotationLocation, error) {
	rows, err := q.Query(ctx, `SELECT l.id, l.old_location_id, l.target_id, l.n, t.name::text, l.os_user, l.file_path, l.options, l.state,
    l.skip_reason, l.verify_note, l.error_code, l.backup, l.add_sent_at, l.verified_at, l.reverified_at, l.remove_sent_at, l.removed_at,
    l.new_location_id, l.add_op_id, l.remove_op_id, l.undo_op_id
FROM rotation_locations l JOIN targets t ON t.id = l.target_id WHERE l.rotation_id = $1 ORDER BY l.n`, runID)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: read the rotation's locations: %w", err)
	}
	defer rows.Close()
	out := []RotationLocation{}
	for rows.Next() {
		var (
			l                   RotationLocation
			addOp, remOp, undOp *uuid.UUID
		)
		if err := rows.Scan(&l.ID, &l.OldLocationID, &l.TargetID, &l.N, &l.TargetName, &l.OSUser, &l.FilePath, &l.Options, &l.State,
			&l.SkipReason, &l.VerifyNote, &l.ErrorCode, &l.Backup, &l.AddSentAt, &l.VerifiedAt, &l.ReverifiedAt, &l.RemoveSentAt,
			&l.RemovedAt, &l.NewLocationID, &addOp, &remOp, &undOp); err != nil {
			return nil, fmt.Errorf("sshkeys: read a rotation location: %w", err)
		}
		l.AddOpID, l.RemoveOpID, l.UndoOpID = orNil(addOp), orNil(remOp), orNil(undOp)
		l.AddSentAt, l.VerifiedAt, l.ReverifiedAt = utcPtr(l.AddSentAt), utcPtr(l.VerifiedAt), utcPtr(l.ReverifiedAt)
		l.RemoveSentAt, l.RemovedAt = utcPtr(l.RemoveSentAt), utcPtr(l.RemovedAt)
		out = append(out, l)
	}
	return out, rows.Err()
}

func readSteps(ctx context.Context, q db.Querier, runID uuid.UUID) ([]Step, error) {
	rows, err := q.Query(ctx, `SELECT n, location_id, name, status, at, params FROM rotation_steps WHERE rotation_id = $1 ORDER BY n`, runID)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: read the rotation's steps: %w", err)
	}
	defer rows.Close()
	out := []Step{}
	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.N, &st.LocationID, &st.Name, &st.Status, &st.At, &st.Params); err != nil {
			return nil, fmt.Errorf("sshkeys: read a rotation step: %w", err)
		}
		st.At = st.At.UTC()
		out = append(out, st)
	}
	return out, rows.Err()
}

func orNil(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// RotationFilter selects runs for a list.
type RotationFilter struct {
	PolicyID, KeyID uuid.UUID // uuid.Nil = any; KeyID matches the old or the new key
	Cursor          string
	Limit           int // 1..200, default 50
}

// ErrBadCursor: the list cursor is not one this service returned.
var ErrBadCursor = errors.New("sshkeys: the cursor is not valid")

// Rotations lists runs newest first, without their steps; the returned cursor is "" on the last page.
func (s *Service) Rotations(ctx context.Context, f RotationFilter) ([]Rotation, string, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	var afterAt *time.Time
	var afterID *uuid.UUID
	if f.Cursor != "" {
		at, id, err := decodeRotationCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		afterAt, afterID = &at, &id
	}
	var out []Rotation
	next := ""
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, created_at FROM rotations
WHERE ($1::uuid IS NULL OR policy_id = $1) AND ($2::uuid IS NULL OR old_ssh_key_id = $2 OR new_ssh_key_id = $2)
  AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4::uuid))
ORDER BY created_at DESC, id DESC LIMIT $5`, nilUUID(f.PolicyID), nilUUID(f.KeyID), afterAt, afterID, limit+1)
		if err != nil {
			return fmt.Errorf("sshkeys: list rotations: %w", err)
		}
		type ref struct {
			id uuid.UUID
			at time.Time
		}
		refs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ref, error) {
			var x ref
			err := r.Scan(&x.id, &x.at)
			return x, err
		})
		if err != nil {
			return fmt.Errorf("sshkeys: list rotations: %w", err)
		}
		if len(refs) > limit {
			refs = refs[:limit]
			last := refs[limit-1]
			next = encodeRotationCursor(last.at, last.id)
		}
		out = make([]Rotation, 0, len(refs))
		for _, x := range refs {
			r, err := readRotation(ctx, tx, x.id, false)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, next, nil
}

func nilUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func encodeRotationCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMicro(), 10) + "|" + id.String()))
}

func decodeRotationCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	micros, err := strconv.ParseInt(at, 10, 64)
	if err != nil || micros < 0 || micros > 253402300799999999 {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrBadCursor
	}
	return time.UnixMicro(micros).UTC(), u, nil
}
