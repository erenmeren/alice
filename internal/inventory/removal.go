package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// denial is a refusal that is audited (sshkey.remove.denied) after the request's transaction
// has been rolled back.
type denial struct {
	reason string
	err    error
	loc    KeyLocation
}

func (d *denial) Error() string { return d.err.Error() }
func (d *denial) Unwrap() error { return d.err }

// warnKeysManagedElsewhere is the provider's warning for a user whose keys sshd also asks
// AuthorizedKeysCommand for (F-35, per user through a Match block; param user).
const warnKeysManagedElsewhere = "keys_managed_elsewhere"

// warnSSHDUnreadable is the provider's warning that sshd's settings could not be read: without
// param user for the whole server (defaults were assumed), with it for one user's Match block.
const warnSSHDUnreadable = "sshd_unreadable"

// warnedFor reports whether the last discovery gave the warning code for user.
func warnedFor(f Facts, code, user string) bool {
	return slices.ContainsFunc(f.Warnings, func(w providers.Warning) bool {
		return w.Code == code && w.Params["user"] == user
	})
}

// managedElsewhereFor reports whether the last discovery found that sshd asks a program for
// user's keys (the target-wide case is Target.KeysManagedElsewhere).
func managedElsewhereFor(f Facts, user string) bool {
	return warnedFor(f, warnKeysManagedElsewhere, user)
}

// sshdUnreadFor reports whether the last discovery could not read sshd's settings for the server
// or for user: the files Alice sees may then not be the ones sshd uses for that user.
func sshdUnreadFor(f Facts, user string) bool {
	return f.SSHD == nil || !f.SSHD.Read || warnedFor(f, warnSSHDUnreadable, user)
}

// RequestKeyRemoval validates and queues the removal of one key location (§13.4, R37 item 9).
// Alice's own key, unconfirmed or changed servers, AuthorizedKeysCommand servers and users
// (F-35), servers and users whose sshd settings the last scan could not read, cert-authority
// lines, keys no longer present and root's last key without an Administrator's confirmation are
// refused before anything is queued; refusals that protect access are audited. The job's user
// and file are those of the location row. The same removal already queued with another root
// confirmation answers ErrJobConflict.
func (s *Service) RequestKeyRemoval(ctx context.Context, a Actor, locationID uuid.UUID, confirmLastRootKey bool) (uuid.UUID, error) {
	allowLastRoot := confirmLastRootKey && a.Role == rbac.Admin
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The target row is locked before the location (Reconcile's order).
		var targetID uuid.UUID
		err := tx.QueryRow(ctx, "SELECT target_id FROM ssh_key_locations WHERE id = $1", locationID).Scan(&targetID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: read key location: %w", err)
		}
		t, err := getTarget(ctx, tx, targetID, true)
		if err != nil {
			return err
		}
		var isPlatform bool
		loc, err := scanLocation(tx.QueryRow(ctx, `SELECT l.id, l.ssh_key_id, k.fingerprint_sha256, k.key_type, l.target_id,
t.name::text, l.os_user, l.file_path, l.line_no, l.options, l.comment, l.flags, l.first_seen_at, l.last_seen_at, l.missing_since,
l.removed_by_alice_at, l.is_alice_connection_key, k.is_platform_key
FROM ssh_key_locations l JOIN ssh_keys k ON k.id = l.ssh_key_id JOIN targets t ON t.id = l.target_id
WHERE l.id = $1 AND l.target_id = $2 FOR UPDATE OF l`, locationID, targetID), &isPlatform)
		if err != nil {
			return err
		}
		protected, err := protectedFingerprints(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case loc.RemovedAt != nil || loc.MissingSince != nil, slices.Contains(loc.Flags, providers.FlagCertAuthority):
			return ErrNotRemovable
		case loc.IsAliceConnectionKey || isPlatform || slices.Contains(protected, loc.Fingerprint):
			return &denial{reason: "own_key", err: ErrOwnKeyProtected, loc: loc}
		}
		if err := KeyChangeRefusal(t, loc.OSUser); err != nil {
			switch {
			case errors.Is(err, ErrKeysManagedElsewhere):
				return &denial{reason: "keys_managed_elsewhere", err: err, loc: loc}
			case errors.Is(err, ErrSSHDUnreadable):
				return &denial{reason: "sshd_unreadable", err: err, loc: loc}
			default:
				return err
			}
		}
		if (loc.OSUser == "root" || slices.Contains(t.Facts.UID0Users, loc.OSUser)) && !allowLastRoot {
			var others int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssh_key_locations
WHERE target_id = $1 AND os_user = $4 AND file_path = $2 AND id <> $3 AND missing_since IS NULL AND removed_by_alice_at IS NULL`,
				loc.TargetID, loc.FilePath, loc.ID, loc.OSUser).Scan(&others); err != nil {
				return fmt.Errorf("inventory: count root keys: %w", err)
			}
			if others == 0 {
				return &denial{reason: "last_root_key", err: ErrLastRootKey, loc: loc}
			}
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobSSHKeyRemove, TargetID: loc.TargetID, Kind: a.jobKind(),
			CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "sshkey.remove:" + loc.ID.String(),
			Payload: map[string]string{"location_id": loc.ID.String(), "fingerprint": loc.Fingerprint, "os_user": loc.OSUser,
				"file_path": loc.FilePath, "confirm_last_root_key": strconv.FormatBool(allowLastRoot)}})
		if err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "sshkey.remove_requested", ObjectType: "ssh_key_location",
			ObjectID: loc.ID.String(), Result: audit.Success, Details: map[string]string{
				"fingerprint": loc.Fingerprint, "os_user": loc.OSUser, "file_path": loc.FilePath, "job_id": jobID.String()}})
		return err
	})
	var d *denial
	if errors.As(err, &d) {
		s.auditDenial(ctx, a, d)
	}
	return jobID, err
}

// auditDenial records a refused removal in its own transaction (the request's was rolled back).
// The record does not depend on the request: a client that disconnects does not erase it (it is
// bounded by detachedTimeout).
func (s *Service) auditDenial(ctx context.Context, a Actor, d *denial) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "sshkey.remove.denied", ObjectType: "ssh_key_location",
			ObjectID: d.loc.ID.String(), Result: audit.Denied, Details: map[string]string{
				"reason": d.reason, "fingerprint": d.loc.Fingerprint, "os_user": d.loc.OSUser, "file_path": d.loc.FilePath}})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused key removal", "error_type", fmt.Sprintf("%T", err))
	}
}

// ProtectedFingerprints returns every fingerprint of Alice's own keys: the platform key in the
// credentials and every key recorded as a platform key that is not retired (during a rotation
// overlap both the old and the new key sign in). A removal never touches any of them (F-36).
func (s *Service) ProtectedFingerprints(ctx context.Context) ([]string, error) {
	return protectedFingerprints(ctx, s.pool)
}

func protectedFingerprints(ctx context.Context, q db.Querier) ([]string, error) {
	out := []string{}
	pk, err := loadPlatformKey(ctx, q)
	switch {
	case err == nil:
		out = append(out, pk.Fingerprint)
	case !errors.Is(err, ErrNoPlatformKey):
		return nil, err
	}
	rows, err := q.Query(ctx, "SELECT fingerprint_sha256 FROM ssh_keys WHERE is_platform_key AND retired_at IS NULL ORDER BY fingerprint_sha256")
	if err != nil {
		return nil, fmt.Errorf("inventory: read platform keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("inventory: read platform key: %w", err)
		}
		if !slices.Contains(out, fp) {
			out = append(out, fp)
		}
	}
	return out, rows.Err()
}

// MarkKeyRemoved records a removal the provider applied. actor is the job's system actor; its
// RequestID is the job id, which links this row to sshkey.remove_requested. Alice's own key is
// refused here, and the database trigger refuses it even if this check had a bug. The removal
// reached the server, so the target's connection is recorded too (markConnected). The target row
// is locked before the location (Reconcile's and RequestKeyRemoval's order). A target deleted
// while the removal ran does not hide it: the location is read whatever its target's state, so
// the change made on the server is recorded and audited.
func (s *Service) MarkKeyRemoved(ctx context.Context, locationID uuid.UUID, actor audit.Actor, res providers.AuthKeyResult) error {
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var targetID uuid.UUID
		err := tx.QueryRow(ctx, "SELECT target_id FROM ssh_key_locations WHERE id = $1", locationID).Scan(&targetID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: read key location: %w", err)
		}
		// A target deleted while the removal ran keeps its record: the server did change.
		var deleted bool
		if err := tx.QueryRow(ctx, "SELECT deleted_at IS NOT NULL FROM targets WHERE id = $1 FOR UPDATE", targetID).Scan(&deleted); err != nil {
			return fmt.Errorf("inventory: lock target: %w", err)
		}
		loc, err := scanLocation(tx.QueryRow(ctx, locationSelectAny+" WHERE l.id = $1 FOR UPDATE OF l", locationID))
		if err != nil {
			return err
		}
		protected, err := protectedFingerprints(ctx, tx)
		if err != nil {
			return err
		}
		if loc.IsAliceConnectionKey || slices.Contains(protected, loc.Fingerprint) {
			return ErrOwnKeyProtected
		}
		if _, err := tx.Exec(ctx, `UPDATE ssh_key_locations SET removed_by_alice_at = $2, missing_since = coalesce(missing_since, $2)
WHERE id = $1`, locationID, now); err != nil {
			return fmt.Errorf("inventory: mark key removed: %w", err)
		}
		if !deleted {
			t, err := getTarget(ctx, tx, targetID, false) // locked above
			if err != nil {
				return err
			}
			if err := s.markConnected(ctx, tx, t, now, false, "removal_ok", nil); err != nil {
				return err
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.removed", ObjectType: "ssh_key_location",
			ObjectID: locationID.String(), Result: audit.Success, Details: map[string]string{
				"fingerprint": loc.Fingerprint, "os_user": loc.OSUser, "file_path": loc.FilePath, "job_id": actor.RequestID,
				"removed_count": strconv.Itoa(res.Removed), "verified": strconv.FormatBool(res.Verified)}})
		return err
	})
}

// RecordRemovalFailure audits a removal that failed (reason is a stable reason; anything else is
// stored as internal.unexpected).
func (s *Service) RecordRemovalFailure(ctx context.Context, locationID uuid.UUID, actor audit.Actor, reason string) error {
	if !reasonRE.MatchString(reason) {
		reason = "internal.unexpected"
	}
	// Also on a target deleted meanwhile: the attempt on the server is still audited.
	loc, err := scanLocation(s.pool.QueryRow(ctx, locationSelectAny+" WHERE l.id = $1", locationID))
	if err != nil {
		return err
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.remove_failed", ObjectType: "ssh_key_location",
			ObjectID: locationID.String(), Result: audit.Failure, Details: map[string]string{
				"fingerprint": loc.Fingerprint, "os_user": loc.OSUser, "file_path": loc.FilePath, "job_id": actor.RequestID, "reason": reason}})
		return err
	})
}
