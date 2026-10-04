package inventory

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// ScheduleKVPolls queues a poll (kv.poll, kind scheduled, dedupe key kv.poll:<id>) for every live,
// enabled vault that is due (job kv.schedule, ClassReadOnly: nothing is queued in lock). A vault is
// due when it was never scheduled or when its last scheduled poll is older than
// min(interval * 2^min(poll_failures, 2), max(interval, 1 h)): the interval while healthy, twice
// that after one failed poll, four times after two or more, never more than an hour for an
// interval below an hour (R40 row 13). The delay depends only on last_scheduled_at and
// poll_failures: a vault degraded from birth has no last_success_at, and that changes nothing here.
// last_scheduled_at is stamped in the transaction that queues the job, so a refused enqueue
// leaves the vault due. Vaults another transaction holds are skipped until the next tick. At most
// two polls run at a time (MaxConcurrentKVPolls, enforced by the poll job's slot), so many due
// vaults queue up rather than load Azure and the database together.
func (s *Service) ScheduleKVPolls(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM targets
WHERE deleted_at IS NULL AND type = 'azure_key_vault' AND status <> 'disabled'
  AND (last_scheduled_at IS NULL OR last_scheduled_at + make_interval(secs => LEAST(
        discovery_interval_seconds * (1 << LEAST(poll_failures, 2)), GREATEST(discovery_interval_seconds, 3600))) <= $1)
ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED`, now, maxScheduledPerRun)
		if err != nil {
			return fmt.Errorf("inventory: find due vaults: %w", err)
		}
		var due []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("inventory: read a due vault: %w", err)
			}
			due = append(due, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range due {
			if _, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobKVPoll, TargetID: id, Payload: map[string]string{}, Kind: "scheduled",
				DedupeKey: "kv.poll:" + id.String()}); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", id, now); err != nil {
				return fmt.Errorf("inventory: record the scheduled poll: %w", err)
			}
			n++
		}
		return nil
	})
	return n, err
}
