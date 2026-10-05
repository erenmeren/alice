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
// is neither missing nor removed by Alice, on a server that is not deleted. It returns the number of
// keys destroyed.
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
	for _, id := range ids {
		destroyed, err := s.destroyRetired(ctx, id)
		if err != nil {
			return n, err
		}
		if destroyed {
			n++
		}
	}
	return n, nil
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
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssh_key_locations l JOIN targets t ON t.id = l.target_id
WHERE l.ssh_key_id = $1 AND l.missing_since IS NULL AND l.removed_by_alice_at IS NULL AND t.deleted_at IS NULL`, id).Scan(&live); err != nil {
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
		if retiredAt.After(now.Add(-RetiredKeyRetention)) {
			return nil
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
