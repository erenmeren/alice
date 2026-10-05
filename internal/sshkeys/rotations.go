package sshkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	AwaitingDecision                                bool
	DecisionDueAt                                   *time.Time
	Plan                                            plan.Plan
	Digest                                          string
	NewKeyType                                      string
	OverlapMinutes                                  int
	PlannedFor, NotifiedAt                          time.Time
	StartedAt, VerifiedAt, OverlapUntil, FinishedAt *time.Time
	ResultCode                                      string
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
    r.planned_for, r.notified_at, r.started_at, r.verified_at, r.overlap_until, r.finished_at, r.result_code, r.version
FROM rotations r JOIN ssh_keys ok ON ok.id = r.old_ssh_key_id LEFT JOIN ssh_keys nk ON nk.id = r.new_ssh_key_id WHERE r.id = $1`, id).Scan(
		&r.ID, &r.PolicyID, &r.OldKeyID, &r.NewKeyID, &r.OldFingerprint, &r.NewFingerprint, &r.Trigger, &r.Status, &r.PausedLicense,
		&r.AwaitingDecision, &r.DecisionDueAt, &rawPlan, &r.Digest, &r.NewKeyType, &r.OverlapMinutes, &r.PlannedFor, &r.NotifiedAt,
		&r.StartedAt, &r.VerifiedAt, &r.OverlapUntil, &r.FinishedAt, &r.ResultCode, &r.Version)
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
	r.OverlapUntil, r.FinishedAt = utcPtr(r.OverlapUntil), utcPtr(r.FinishedAt)
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
