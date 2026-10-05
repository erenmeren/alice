package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// maxDestroyBatch bounds the keys one DestroyRetiredKeys call looks at (it runs every hour; the
// rest waits for the next run).
const maxDestroyBatch = 500

// destroyActor is the audit actor of the periodic task.
var destroyActor = audit.SystemActor("jobs")

// DestroyRetiredKeys destroys the private key of every generated key that was retired at least
// RetiredKeyRetention ago (R41 row 23): in one transaction per key, its envelope columns become
// NULL with destroyed_at, audited sshkey.private_key_destroyed. A retired key that is live again on
// a server (a server restored from a backup, a home that was not mounted during a scan) is never
// destroyed: it is un-retired instead, audited sshkey.reactivated (S5). Live means a location that
// is neither missing nor removed by Alice, on a server that is not deleted. A key an unfinished
// rotation references (old or new key) is left alone. A key whose private key is already destroyed
// and that is live again stays retired (the database refuses to un-retire it, Z1014); it is audited
// sshkey.live_after_destruction once. One key's failure does not stop the others: the errors are
// joined. It returns the number of keys destroyed.
func (s *Service) DestroyRetiredKeys(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT k.id FROM ssh_keys k JOIN managed_private_keys p ON p.id = k.private_key_id
WHERE k.retired_at IS NOT NULL AND p.destroyed_at IS NULL ORDER BY k.retired_at, k.id LIMIT $1`, maxDestroyBatch)
	if err != nil {
		return 0, fmt.Errorf("sshkeys: list retired keys: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("sshkeys: list retired keys: %w", err)
	}
	n := 0
	var errs []error
	for _, id := range ids {
		destroyed, err := s.destroyRetired(ctx, id)
		if err != nil {
			s.log.Error("could not destroy a retired key", "ssh_key_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			errs = append(errs, err)
			continue
		}
		if destroyed {
			n++
		}
	}
	if err := s.auditLiveAfterDestruction(ctx); err != nil {
		errs = append(errs, err)
	}
	return n, errors.Join(errs...)
}

// liveLocations counts a key's live locations (S5's rule).
const liveLocations = `SELECT count(*) FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id
WHERE l.ssh_key_id = k.id AND l.missing_since IS NULL AND l.removed_by_alice_at IS NULL AND t.deleted_at IS NULL`

// onLiveFound runs between the read of the destroyed keys found live and their audit rows (tests
// only; nil in production).
var onLiveFound func()

// auditLiveAfterDestruction records, once per key, a retired key whose private key was destroyed
// and that has a live location again: nothing can bring the private key back, an Administrator
// should remove those lines or replace the key.
func (s *Service) auditLiveAfterDestruction(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT k.id, k.fingerprint_sha256, (`+liveLocations+`) FROM ssh_keys k
JOIN managed_private_keys p ON p.id = k.private_key_id
WHERE k.retired_at IS NOT NULL AND p.destroyed_at IS NOT NULL AND (`+liveLocations+`) > 0
  AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = 'sshkey.live_after_destruction' AND a.object_id = k.id::text)
ORDER BY k.id LIMIT $1`, maxDestroyBatch)
	if err != nil {
		return fmt.Errorf("sshkeys: list destroyed keys found live: %w", err)
	}
	type found struct {
		id    uuid.UUID
		fp    string
		count int
	}
	keys, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (found, error) {
		var f found
		err := r.Scan(&f.id, &f.fp, &f.count)
		return f, err
	})
	if err != nil {
		return fmt.Errorf("sshkeys: list destroyed keys found live: %w", err)
	}
	if onLiveFound != nil {
		onLiveFound()
	}
	var errs []error
	for _, k := range keys {
		// Once per key, atomically: the key's row is locked, then the audit log read again, so two
		// instances of the task write one row (review N3). One failure does not stop the others.
		if err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			var done bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = 'sshkey.live_after_destruction'
AND a.object_id = $1::uuid::text) FROM ssh_keys WHERE id = $1::uuid FOR UPDATE`, k.id).Scan(&done); err != nil {
				return fmt.Errorf("sshkeys: lock the destroyed key: %w", err)
			}
			if done {
				return nil
			}
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: destroyActor, Action: "sshkey.live_after_destruction", ObjectType: "ssh_key",
				ObjectID: k.id.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": k.id.String(), "fingerprint": k.fp,
					"location_count": strconv.Itoa(k.count)}})
			return err
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// destroyRetired decides one retired key under its row lock: reactivated when live, destroyed when
// its retention has passed, otherwise left alone.
func (s *Service) destroyRetired(ctx context.Context, id uuid.UUID) (bool, error) {
	destroyed := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock.Now().UTC()
		var (
			pkID        uuid.UUID
			fingerprint string
			retiredAt   *time.Time
			gone        bool
		)
		// The key row is locked first: a scan that records a location of it upserts this row too,
		// so the live count below sees every location committed before the lock.
		err := tx.QueryRow(ctx, `SELECT k.private_key_id, k.fingerprint_sha256, k.retired_at, p.destroyed_at IS NOT NULL
FROM ssh_keys k JOIN managed_private_keys p ON p.id = k.private_key_id WHERE k.id = $1 FOR UPDATE OF k`, id).
			Scan(&pkID, &fingerprint, &retiredAt, &gone)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sshkeys: read the retired key: %w", err)
		}
		if retiredAt == nil || gone {
			return nil
		}
		var live int
		var inRun bool
		if err := tx.QueryRow(ctx, `SELECT (`+liveLocations+`), EXISTS (SELECT 1 FROM rotations r WHERE (r.old_ssh_key_id = k.id OR r.new_ssh_key_id = k.id)
    AND r.status NOT IN `+finishedStatuses+`) FROM ssh_keys k WHERE k.id = $1`, id).Scan(&live, &inRun); err != nil {
			return fmt.Errorf("sshkeys: count the retired key's locations: %w", err)
		}
		if live > 0 {
			if _, err := tx.Exec(ctx, "UPDATE ssh_keys SET retired_at = NULL WHERE id = $1", id); err != nil {
				return fmt.Errorf("sshkeys: reactivate the key: %w", err)
			}
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: destroyActor, Action: "sshkey.reactivated", ObjectType: "ssh_key",
				ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": id.String(),
					"fingerprint": fingerprint, "location_count": strconv.Itoa(live)}})
			return err
		}
		if inRun || retiredAt.After(now.Add(-RetiredKeyRetention)) {
			return nil // an unfinished rotation still needs the key (defence in depth: Task 9 never retires one)
		}
		tag, err := tx.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL,
    key_version = NULL WHERE id = $1 AND destroyed_at IS NULL`, pkID, now)
		if err != nil {
			return fmt.Errorf("sshkeys: destroy the private key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: destroyActor, Action: "sshkey.private_key_destroyed", ObjectType: "ssh_key",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": id.String(), "fingerprint": fingerprint}})
		destroyed = err == nil
		return err
	})
	return destroyed && err == nil, err
}
