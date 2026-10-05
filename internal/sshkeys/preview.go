package sshkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/sshkeys/keymat"
	"alice/internal/sshkeys/plan"
)

// Preview is a plan as the Administrator sees it before a run (C7).
type Preview struct {
	PolicyID   uuid.UUID
	Plan       plan.Plan
	Digest     string
	PlannedFor time.Time
	Emailed    bool
}

// Warning codes of the provider that the planner reads per user (inventory's names).
const (
	warnKeysManagedElsewhere = "keys_managed_elsewhere"
	warnSSHDUnreadable       = "sshd_unreadable"
)

// loadPlanInput reads what the planner decides from, in tx: the policy's key, its locations, their
// targets and Alice's own fingerprints. With lock, the targets and then the locations are locked
// (inventory.KeyLocationsTx: targets by ascending id, then locations), after the run and the policy
// the caller already holds. A deleted target is left out of the map: the planner skips it.
func (s *Service) loadPlanInput(ctx context.Context, tx pgx.Tx, pol policyRow, plannedFor time.Time, lock bool) (plan.Input, keyRow, error) {
	key, err := readKeyRow(ctx, tx, pol.SSHKeyID)
	if err != nil {
		return plan.Input{}, keyRow{}, err
	}
	locs, err := s.inv.KeyLocationsTx(ctx, tx, key.id, lock)
	if err != nil {
		return plan.Input{}, keyRow{}, err
	}
	targets := map[uuid.UUID]inventory.Target{}
	for _, l := range locs { // ordered by target id
		if _, seen := targets[l.TargetID]; seen {
			continue
		}
		t, err := s.inv.TargetTx(ctx, tx, l.TargetID, lock)
		if errors.Is(err, inventory.ErrNotFound) {
			continue
		}
		if err != nil {
			return plan.Input{}, keyRow{}, err
		}
		targets[l.TargetID] = t
	}
	protected, err := inventory.ProtectedFingerprintsTx(ctx, tx)
	if err != nil {
		return plan.Input{}, keyRow{}, err
	}
	return toPlanInput(key, locs, targets, protected, pol.Policy, plannedFor), key, nil
}

// toPlanInput maps what inventory knows to the planner's input.
func toPlanInput(key keyRow, locs []inventory.KeyLocation, targets map[uuid.UUID]inventory.Target, protected []string, pol Policy,
	plannedFor time.Time) plan.Input {
	in := plan.Input{
		Key: plan.Key{ID: key.id, Fingerprint: key.fingerprint, PublicKey: key.publicKey, Label: key.label, Managed: key.privateKeyID != uuid.Nil,
			IsPlatform: key.isPlatform, Retired: key.retired || key.destroyed, KeyType: string(keymat.TypeOf(key.algorithm, key.bits))},
		Targets:        make(map[uuid.UUID]plan.Target, len(targets)),
		Protected:      protected,
		NewKeyType:     pol.NewKeyType,
		OverlapMinutes: pol.OverlapMinutes,
		NewComment:     keymat.Comment(key.label, plannedFor),
	}
	for id, t := range targets {
		pt := plan.Target{ID: id, Name: t.Name, Status: t.Status, ConnectionUser: connectionUser(t), KeysManagedElsewhere: t.KeysManagedElsewhere,
			UID0Users: t.Facts.UID0Users}
		if t.Facts.SSHD != nil {
			pt.SSHDRead = t.Facts.SSHD.Read
			pt.PermitRootLogin = t.Facts.SSHD.PermitRootLogin
			pt.PubkeyAuthentication = t.Facts.SSHD.PubkeyAuthentication
		}
		for _, w := range t.Facts.Warnings {
			switch w.Code {
			case warnKeysManagedElsewhere:
				if u := w.Params["user"]; u != "" {
					pt.ManagedElsewhereUsers = append(pt.ManagedElsewhereUsers, u)
				}
			case warnSSHDUnreadable:
				if u := w.Params["user"]; u != "" {
					pt.SSHDUnreadUsers = append(pt.SSHDUnreadUsers, u)
				} else {
					pt.SSHDRead = false
				}
			}
		}
		in.Targets[id] = pt
	}
	for _, l := range locs {
		in.Locations = append(in.Locations, plan.Location{ID: l.ID, TargetID: l.TargetID, OSUser: l.OSUser, FilePath: l.FilePath,
			Options: l.Options, Comment: l.Comment, Flags: l.Flags, Missing: l.MissingSince != nil, IsAliceConnectionKey: l.IsAliceConnectionKey})
	}
	return in
}

// planError maps the planner's refusals to the module's errors.
func planError(err error) error {
	switch {
	case errors.Is(err, plan.ErrOwnKey):
		return ErrOwnKeyProtected
	case errors.Is(err, plan.ErrNotManaged):
		return ErrNotManaged
	case errors.Is(err, plan.ErrRetired):
		return ErrRetired
	case errors.Is(err, plan.ErrNothingToRotate):
		return ErrNothingToRotate
	}
	return err
}

// Preview plans the policy's next run as it would be now (spec §13.6 item 1) and mails it to every
// Administrator, at most once per policy in PreviewMailEvery (row 16). A plan in which nothing can
// change is shown with its skips (no error). In lock nothing is planned or sent (L-88). A preview
// creates no run; Run now must carry its digest.
func (s *Service) Preview(ctx context.Context, a inventory.Actor, policyID uuid.UUID) (Preview, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Preview{}, err
	}
	var out Preview
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		pol, err := getPolicy(ctx, tx, policyID, true)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		plannedFor := now
		if pol.Enabled && pol.NextRunAt != nil {
			plannedFor = *pol.NextRunAt
		}
		in, key, err := s.loadPlanInput(ctx, tx, pol, plannedFor, false)
		if err != nil {
			return err
		}
		p, err := plan.Build(in)
		if err != nil && !errors.Is(err, plan.ErrNothingToRotate) {
			return planError(err)
		}
		out = Preview{PolicyID: policyID, Plan: p, Digest: p.Digest(), PlannedFor: plannedFor}
		if s.notifier != nil && (pol.previewMailedAt == nil || !now.Before(pol.previewMailedAt.Add(PreviewMailEvery))) {
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplatePreview, previewParams(key, p, plannedFor, uuid.Nil)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE rotation_policies SET preview_mailed_at = $2 WHERE id = $1", policyID, now); err != nil {
				return fmt.Errorf("sshkeys: record the preview email: %w", err)
			}
			out.Emailed = true
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.previewed", ObjectType: "rotation_policy",
			ObjectID: policyID.String(), Result: audit.Success, Details: map[string]string{"policy_id": policyID.String(),
				"plan_digest": out.Digest, "change_count": strconv.Itoa(p.Changes), "skip_count": strconv.Itoa(p.Skips),
				"emailed": strconv.FormatBool(out.Emailed)}})
		return err
	})
	if err != nil {
		return Preview{}, err
	}
	return out, nil
}

// insertRun creates a previewed run (C8 "(new) → dry_run_notified") in tx, which holds the policy's
// row lock: the run row, one location per action (planned, or skipped with the planner's reason),
// the rotation.preview notice to every Administrator (the notification before each run; S1 counts
// it delivered by its rotation_id), the audit row and the first step. The plan is stored as it was
// previewed (public data only); a plan with nothing to change is ErrNothingToRotate.
func (s *Service) insertRun(ctx context.Context, tx pgx.Tx, pol policyRow, key keyRow, p plan.Plan, digest, trigger string,
	plannedFor time.Time, a inventory.Actor) (uuid.UUID, error) {
	if p.Changes == 0 {
		return uuid.Nil, ErrNothingToRotate
	}
	if len(p.Actions) > maxPlanActions {
		return uuid.Nil, ErrPlanTooLarge
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return uuid.Nil, fmt.Errorf("sshkeys: encode the plan: %w", err)
	}
	if len(raw) > maxPlanBytes {
		return uuid.Nil, ErrPlanTooLarge // before the database's CHECK refuses it
	}
	id, now := uuid.Must(uuid.NewV7()), s.clock.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type,
    overlap_minutes, planned_for, notified_at, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $11, $11)`, id, pol.ID, p.KeyID, trigger, StatusDryRunNotified, raw, digest,
		p.NewKeyType, p.Overlap, plannedFor.UTC(), now, nullableUser(a.UserID)); err != nil {
		return uuid.Nil, fmt.Errorf("sshkeys: store the rotation: %w", err)
	}
	for _, act := range p.Actions {
		state := LocPlanned
		if act.Skip != "" {
			state = LocSkipped
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, options,
    verify_note, state, skip_reason, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			uuid.Must(uuid.NewV7()), id, act.N, act.LocationID, act.TargetID, act.OSUser, act.FilePath, act.Options, act.VerifyNote, state,
			act.Skip, now); err != nil {
			return uuid.Nil, fmt.Errorf("sshkeys: store a rotation location: %w", err)
		}
	}
	if s.notifier != nil {
		if err := s.notifier.NotifyAdmins(ctx, tx, TemplatePreview, previewParams(key, p, plannedFor, id)); err != nil {
			return uuid.Nil, err
		}
	}
	if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.created", ObjectType: "rotation", ObjectID: id.String(),
		Result: audit.Success, Details: map[string]string{"rotation_id": id.String(), "policy_id": pol.ID.String(), "trigger": trigger,
			"plan_digest": digest, "planned_for": plannedFor.UTC().Format(time.RFC3339)}}); err != nil {
		return uuid.Nil, err
	}
	return id, appendStep(ctx, tx, id, nil, StatusDryRunNotified, "ok", map[string]string{"trigger": trigger, "plan_digest": digest}, now)
}
