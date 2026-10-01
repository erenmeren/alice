package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// reasonRE accepts stable reasons ("ssh.auth_failed"); anything else is stored as
// internal.unexpected so no provider text ever reaches the database or the UI.
var reasonRE = regexp.MustCompile(`^[a-z][a-z_]{0,40}(\.[a-z][a-z_]{0,40}){1,3}$`)

const reasonUnconfirmed = "target.host_key_unconfirmed"

// TargetRef returns what a provider needs to open a session to a live target.
func (s *Service) TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, Target, error) {
	t, err := s.GetTarget(ctx, id)
	if err != nil {
		return providers.TargetRef{}, Target{}, err
	}
	k, ok := providers.KindForTargetType(t.Type)
	if !ok {
		return providers.TargetRef{}, Target{}, fmt.Errorf("inventory: target type %q has no provider", t.Type)
	}
	return providers.TargetRef{ID: t.ID, Name: t.Name, Kind: k,
		Config: providers.TargetConfig{"host": t.Host, "port": t.Port, "username": t.Username}}, t, nil
}

// hasPinnedKey reports whether the target has a confirmed host key.
func hasPinnedKey(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM host_keys WHERE target_id = $1 AND status = $2)", id, keyPinned).Scan(&ok); err != nil {
		return false, fmt.Errorf("inventory: read pinned host key: %w", err)
	}
	return ok, nil
}

// RecordConnectionOK stores a successful connection test: status ok, operating system and helper
// facts, last success time. Only a re-pin leaves host_key_changed and only a confirmation leaves
// pending_host_key, so neither a late report nor one for a target without a pinned key changes
// those statuses.
func (s *Service) RecordConnectionOK(ctx context.Context, id uuid.UUID, r providers.ConnectionReport) error {
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		pinned, err := hasPinnedKey(ctx, tx, id)
		if err != nil {
			return err
		}
		to := StatusOK
		switch {
		case t.Status == StatusHostKeyChanged:
			to = t.Status
		case !pinned:
			to = StatusPendingHostKey
		}
		f := t.Facts
		f.OS, f.HelperVersion, f.HelperProtocol = r.OS, r.HelperVersion, r.HelperProtocol
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = $2, facts = $3, last_success_at = $4, last_error_code = '', updated_at = $4
WHERE id = $1`, id, to, raw, now); err != nil {
			return fmt.Errorf("inventory: record connection: %w", err)
		}
		return s.auditStatus(ctx, tx, t, to, "connection_ok")
	})
}

// statusFor maps a failure reason to the target status (contract "Reason strings"; a permanent
// failure such as ssh.auth_failed marks the target, §8.4, R37 item 13). Only a re-pin leaves
// host_key_changed, which only HostKeyStore.Observed enters (with its alert); a report that the
// key is unconfirmed is stale once a key is pinned. Other reasons keep the status.
func statusFor(reason, current string, pinned bool) string {
	if current == StatusHostKeyChanged {
		return current
	}
	switch reason {
	case "ssh.auth_failed":
		return StatusAuthFailed
	case "ssh.unreachable", "ssh.timeout":
		return StatusUnreachable
	case reasonUnconfirmed:
		if pinned {
			return current
		}
		return StatusPendingHostKey
	default:
		return current
	}
}

// RecordConnectionFailure stores why a connection failed. Entering auth_failed mails every
// Administrator once per transition (F-34, R37 item 14): the email is queued in the transaction
// that changes the status, under the target's row lock, so repeated failures and retries of the
// same state send nothing.
func (s *Service) RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error {
	if !reasonRE.MatchString(reason) {
		reason = "internal.unexpected"
	}
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		pinned := false
		if reason == reasonUnconfirmed {
			if pinned, err = hasPinnedKey(ctx, tx, id); err != nil {
				return err
			}
		}
		to := statusFor(reason, t.Status, pinned)
		if _, err := tx.Exec(ctx, "UPDATE targets SET status = $2, last_error_code = $3, updated_at = $4 WHERE id = $1",
			id, to, reason, now); err != nil {
			return fmt.Errorf("inventory: record connection failure: %w", err)
		}
		if to == StatusAuthFailed && t.Status != StatusAuthFailed && s.notifier != nil {
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplateAuthFailed, map[string]string{"target_name": t.Name}); err != nil {
				return fmt.Errorf("inventory: queue the authentication email: %w", err)
			}
		}
		return s.auditStatus(ctx, tx, t, to, reason)
	})
}

// auditStatus records a status transition (system actor); no row when the status is unchanged.
// It runs last in its transaction (audit.Append takes the chain lock).
func (s *Service) auditStatus(ctx context.Context, tx pgx.Tx, t Target, to, reason string) error {
	if t.Status == to {
		return nil
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("jobs"), Action: "target.status_changed",
		ObjectType: "target", ObjectID: t.ID.String(), Result: audit.Success,
		Details: map[string]string{"from_status": t.Status, "to_status": to, "reason": reason}})
	return err
}
