package inventory

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

const maxScheduledPerRun = 500

// ScheduleDiscovery queues a discovery for every connected target whose interval has passed
// (job discovery.schedule, gated as ClassReadOnly by the scheduler, so nothing is queued in lock,
// L-27), and a connection test for every unreachable target on the same rhythm: a server that was
// down comes back without a person (its successful test starts a discovery). A target in checking
// with a pinned key and no job left (its post-pin test was cut off by a restart or cancelled in
// lock) is tested the same way, so it does not wait for a person either. Targets that need a
// person (pending_host_key, host_key_changed, auth_failed) and disabled ones are never scheduled,
// so a refused key is never retried automatically (F-34).
//
// A target is due when neither its last successful discovery nor the scheduler's last job for it
// (last_scheduled_at, stamped in the transaction that queues the job) is younger than its
// interval: whatever that job's outcome (an outdated helper, a dead job, a scan cancelled in
// lock), the next one waits a full interval (R37 item 13). A checking target's last discovery
// does not count (a re-pinned server was scanned before its key changed): it is tested at once
// when the scheduler never queued anything for it. The dedupe key names the interval slot, so
// concurrent ticks within one slot are harmless. Targets another transaction holds are skipped
// until the next tick.
func (s *Service) ScheduleDiscovery(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, status, discovery_interval_seconds FROM targets
WHERE deleted_at IS NULL
  AND (last_scheduled_at IS NULL OR last_scheduled_at + make_interval(secs => discovery_interval_seconds) <= $1)
  AND ((status = ANY($3)
        AND (last_discovery_at IS NULL OR last_discovery_at + make_interval(secs => discovery_interval_seconds) <= $1))
    OR (status = $4
        AND EXISTS (SELECT 1 FROM host_keys h WHERE h.target_id = targets.id AND h.status = $5)
        AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.target_id = targets.id AND j.status = ANY($6))))
ORDER BY id LIMIT $2 FOR UPDATE OF targets SKIP LOCKED`, now, maxScheduledPerRun, []string{StatusOK, StatusUnreachable},
			StatusChecking, keyPinned, []string{"queued", "running"})
		if err != nil {
			return fmt.Errorf("inventory: find due targets: %w", err)
		}
		type due struct {
			id       uuid.UUID
			status   string
			interval int64
		}
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.id, &d.status, &d.interval); err != nil {
				rows.Close()
				return fmt.Errorf("inventory: read due target: %w", err)
			}
			list = append(list, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, d := range list {
			req := JobRequest{Type: JobDiscover, TargetID: d.id, Payload: map[string]string{}, Kind: "scheduled",
				DedupeKey: fmt.Sprintf("target.discover:%s:%d", d.id, now.Unix()/d.interval)}
			if d.status != StatusOK {
				req.Type, req.DedupeKey = JobTestConnection, "target.test_connection:"+d.id.String()
			}
			if _, err := s.jobs.EnqueueTx(ctx, tx, req); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE targets SET last_scheduled_at = $2 WHERE id = $1", d.id, now); err != nil {
				return fmt.Errorf("inventory: record the scheduled job: %w", err)
			}
			n++
		}
		return nil
	})
	return n, err
}
