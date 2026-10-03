package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// reasonRE accepts stable reasons ("ssh.auth_failed"); anything else is stored as
// internal.unexpected so no provider text ever reaches the database or the UI.
var reasonRE = regexp.MustCompile(`^[a-z][a-z_]{0,40}(\.[a-z][a-z_]{0,40}){1,3}$`)

const (
	reasonUnconfirmed = "target.host_key_unconfirmed"
	reasonChanged     = "target.host_key_changed"
)

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

// pinnedFingerprint returns the fingerprint of the target's confirmed host key ("" = none).
func pinnedFingerprint(ctx context.Context, tx pgx.Tx, id uuid.UUID) (string, error) {
	var fp string
	err := tx.QueryRow(ctx, "SELECT fingerprint_sha256 FROM host_keys WHERE target_id = $1 AND status = $2", id, keyPinned).Scan(&fp)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("inventory: read pinned host key: %w", err)
	}
	return fp, nil
}

// statusAfterSuccess is the status of a target after an operation reached the server over SSH
// (pinned reports that a key is pinned). Only a re-pin leaves host_key_changed, only a
// confirmation leaves pending_host_key, and disabled stays disabled, so neither a late report nor
// one for a target without a pinned key changes those statuses. An explicit connection test (test)
// connects every other status. A discovery or a removal connects only an unreachable or checking
// target with a pinned key: it never clears what a person must look at (auth_failed).
func statusAfterSuccess(current string, pinned, test bool) string {
	switch {
	case current == StatusHostKeyChanged || current == StatusDisabled:
		return current
	case test && !pinned:
		return StatusPendingHostKey
	case test, pinned && (current == StatusUnreachable || current == StatusChecking):
		return StatusOK
	}
	return current
}

// markConnected stores a successful operation on the locked target t (see statusAfterSuccess):
// the status, the last success time and, unless the status still names a problem, an empty last
// error. reason names the operation in the status-change audit row; it runs last in its
// transaction's status updates.
func (s *Service) markConnected(ctx context.Context, tx pgx.Tx, t Target, now time.Time, test bool, reason string, facts []byte) error {
	pinned, err := pinnedFingerprint(ctx, tx, t.ID)
	if err != nil {
		return err
	}
	to := statusAfterSuccess(t.Status, pinned != "", test)
	errorCode := ""
	if to == StatusHostKeyChanged || to == StatusAuthFailed {
		errorCode = t.LastErrorCode // the block reason stays until a person acts
	}
	if _, err := tx.Exec(ctx, `UPDATE targets SET status = $2, last_error_code = $3, last_success_at = $4, updated_at = $4,
    facts = coalesce($5, facts) WHERE id = $1`, t.ID, to, errorCode, now, facts); err != nil {
		return fmt.Errorf("inventory: record a successful connection: %w", err)
	}
	return s.auditStatus(ctx, tx, t, to, reason)
}

// RecordConnectionOK stores a successful connection test: status (statusAfterSuccess), operating
// system and helper facts, last success time. A blocked target whose server presented the pinned
// key again has its outstanding candidates rejected: the server stopped presenting them, so they
// can never be accepted; the Administrator dismisses the change by re-pinning the pinned key
// (RepinHostKey).
func (s *Service) RecordConnectionOK(ctx context.Context, id uuid.UUID, r providers.ConnectionReport) error {
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if t.Status == StatusHostKeyChanged && r.HostKey.Fingerprint != "" {
			pinned, err := pinnedFingerprint(ctx, tx, id)
			if err != nil {
				return err
			}
			if r.HostKey.Fingerprint == pinned {
				if err := rejectCandidates(ctx, tx, id); err != nil {
					return err
				}
			}
		}
		f := t.Facts
		f.OS, f.HelperVersion, f.HelperProtocol = r.OS, r.HelperVersion, r.HelperProtocol
		if r.Nginx != nil {
			f.Nginx = mergeNginxFacts(f.Nginx, *r.Nginx)
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return s.markConnected(ctx, tx, t, now, true, "connection_ok", raw)
	})
}

// mergeNginxFacts is the stored Nginx facts after a report: the report replaces them, except that
// a connection test (nginx-test) knows neither the version nor the configuration path, so those of
// the last certificate scan stay while Nginx is still found. Remote text is made storable (jsonb
// refuses NUL).
func mergeNginxFacts(old *providers.NginxFacts, n providers.NginxFacts) *providers.NginxFacts {
	if old != nil && n.Found && old.Found {
		if n.Version == "" {
			n.Version = old.Version
		}
		if n.ConfPath == "" {
			n.ConfPath = old.ConfPath
		}
	}
	n.Version, n.ConfPath, n.ConfigError = clean(n.Version), clean(n.ConfPath), clean(n.ConfigError)
	n.ConfigErrorReason, n.ConfigErrorFile = clean(n.ConfigErrorReason), clean(n.ConfigErrorFile)
	return &n
}

// statusFor maps a failure reason to the target status (contract "Reason strings"; a permanent
// failure such as ssh.auth_failed marks the target, §8.4, R37 item 13). Only a re-pin leaves
// host_key_changed, which only HostKeyStore.Observed enters (with its alert), and disabled stays
// disabled. A target waiting for its first confirmation (pending_host_key, nothing pinned) stays
// there when the server cannot be reached, so its recorded candidate can still be confirmed. Host-key reasons are owned by the store and the confirmation: a report that the key is
// unconfirmed is stale once a key is pinned. Any other failure of a target in checking makes it
// unreachable (it never stays checking); in other statuses it keeps the status.
func statusFor(reason, current string, pinned bool) string {
	if current == StatusHostKeyChanged || current == StatusDisabled {
		return current
	}
	switch reason {
	case "ssh.auth_failed":
		return StatusAuthFailed
	case "ssh.unreachable", "ssh.timeout":
		if current == StatusPendingHostKey && !pinned {
			return current // the recorded candidate stays confirmable (ConfirmHostKey needs pending_host_key)
		}
		return StatusUnreachable
	case reasonUnconfirmed:
		if pinned {
			return current
		}
		return StatusPendingHostKey
	case reasonChanged:
		return current
	default:
		if current == StatusChecking {
			return StatusUnreachable
		}
		return current
	}
}

// RecordConnectionFailure stores why a connection failed. Entering auth_failed mails every
// Administrator once per transition (F-34, R37 item 14): the email is queued in the transaction
// that changes the status, under the target's row lock, so repeated failures and retries of the
// same state send nothing. A blocked target keeps its block reason.
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
		pinned, err := pinnedFingerprint(ctx, tx, id)
		if err != nil {
			return err
		}
		to := statusFor(reason, t.Status, pinned != "")
		errorCode := reason
		if to == StatusHostKeyChanged {
			errorCode = t.LastErrorCode // the block reason stays until the re-pin
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET status = $2, last_error_code = $3, updated_at = $4 WHERE id = $1",
			id, to, errorCode, now); err != nil {
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
