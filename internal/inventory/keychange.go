package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
)

// KeyChangeRefusal is the readiness rule every authorized_keys change shares (RequestKeyRemoval,
// deploys, rotations; C6). Connection problems (unreachable, checking, auth_failed) are not refused
// here: the job finds them and records them on the target.
func KeyChangeRefusal(t Target, osUser string) error {
	switch {
	case t.Status == StatusPendingHostKey:
		return ErrHostKeyUnconfirmed
	case t.Status == StatusHostKeyChanged:
		return ErrHostKeyChanged
	case t.Status == StatusDisabled:
		return ErrTargetDisabled
	case t.KeysManagedElsewhere || managedElsewhereFor(t.Facts, osUser):
		return ErrKeysManagedElsewhere
	case sshdUnreadFor(t.Facts, osUser):
		return ErrSSHDUnreadable
	}
	return nil
}

// TargetTx reads a live target in tx (FOR UPDATE with lock); ErrNotFound when deleted or unknown.
func (s *Service) TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (Target, error) {
	return getTarget(ctx, tx, id, lock)
}

// CheckClaimTx is ErrClaimLost when the job run on ctx no longer holds its job (no claim: nil).
func CheckClaimTx(ctx context.Context, tx pgx.Tx) error { return checkClaim(ctx, tx) }

// ProtectedFingerprintsTx is the fingerprints of Alice's own keys, read in tx.
func ProtectedFingerprintsTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	return protectedFingerprints(ctx, tx)
}

// KeyLocationsTx returns the key's locations that Alice did not remove (missing ones included), of
// live targets, ordered by target id, file path and OS user. With lock the rows are locked, and the lock order
// is the one Reconcile uses, so it cannot deadlock against a scan: the targets first (ascending id, FOR UPDATE),
// then the location rows (ordered by target id, which is the same order). A rotation's transaction takes its run
// row before this call (the run, then the targets, then the locations: see migration 00010).
func (s *Service) KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]KeyLocation, error) {
	if lock {
		if _, err := tx.Exec(ctx, `SELECT t.id FROM targets t WHERE t.deleted_at IS NULL AND t.id IN
    (SELECT l.target_id FROM ssh_key_locations l WHERE l.ssh_key_id = $1 AND l.removed_by_alice_at IS NULL)
ORDER BY t.id FOR UPDATE OF t`, keyID); err != nil {
			return nil, fmt.Errorf("inventory: lock the key's targets: %w", err)
		}
	}
	q := locationSelect + ` WHERE l.ssh_key_id = $1 AND l.removed_by_alice_at IS NULL ORDER BY l.target_id, l.file_path, l.os_user`
	if lock {
		q += " FOR UPDATE OF l"
	}
	rows, err := tx.Query(ctx, q, keyID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read key locations: %w", err)
	}
	return collectLocations(rows)
}

// KeyAdded records a key line Alice added (a deploy or a rotation).
type KeyAdded struct {
	SSHKeyID, TargetID uuid.UUID
	OSUser, FilePath   string
	Options, Comment   string
	LineNo             int
	Actor              audit.Actor // its RequestID is the job id
	Verified           bool
}

// RecordKeyAddedTx upserts the location of an added line, records the connection and audits
// sshkey.added. Alice's own key is refused (the database trigger holds too).
func (s *Service) RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in KeyAdded) (uuid.UUID, error) {
	if err := checkClaim(ctx, tx); err != nil {
		return uuid.Nil, err
	}
	now := s.clock.Now().UTC()
	t, err := getTarget(ctx, tx, in.TargetID, true)
	if err != nil {
		return uuid.Nil, err
	}
	var fp string
	if err := tx.QueryRow(ctx, "SELECT fingerprint_sha256 FROM ssh_keys WHERE id = $1", in.SSHKeyID).Scan(&fp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("inventory: read the added key: %w", err)
	}
	protected, err := protectedFingerprints(ctx, tx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, p := range protected {
		if p == fp {
			return uuid.Nil, ErrOwnKeyProtected
		}
	}
	lineNo := max(in.LineNo, 1)
	user, file := clean(in.OSUser), clean(in.FilePath) // the audit row says what the location row stores
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, options, comment, flags,
    first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}', $9, $9)
ON CONFLICT (ssh_key_id, target_id, os_user, file_path) DO UPDATE SET line_no = EXCLUDED.line_no, options = EXCLUDED.options,
    comment = EXCLUDED.comment, last_seen_at = EXCLUDED.last_seen_at, missing_since = NULL, removed_by_alice_at = NULL
RETURNING id`, uuid.Must(uuid.NewV7()), in.SSHKeyID, in.TargetID, user, file, lineNo, clean(in.Options),
		clean(in.Comment), now).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: record the added key: %w", err)
	}
	if err := s.markConnected(ctx, tx, t, now, false, "key_added", nil); err != nil {
		return uuid.Nil, err
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: in.Actor, Action: "sshkey.added", ObjectType: "ssh_key_location",
		ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": in.SSHKeyID.String(), "fingerprint": fp,
			"target_id": in.TargetID.String(), "os_user": user, "file_path": file, "job_id": in.Actor.RequestID,
			"verified": strconv.FormatBool(in.Verified)}})
	return id, err
}
