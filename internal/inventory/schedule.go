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
// L-27). The dedupe key names the interval slot, so repeated ticks within one slot are harmless.
func (s *Service) ScheduleDiscovery(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	n := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, discovery_interval_seconds FROM targets
WHERE deleted_at IS NULL AND status = 'ok'
  AND (last_discovery_at IS NULL OR last_discovery_at + make_interval(secs => discovery_interval_seconds) <= $1)
ORDER BY id LIMIT $2`, now, maxScheduledPerRun)
		if err != nil {
			return fmt.Errorf("inventory: find due targets: %w", err)
		}
		type due struct {
			id       uuid.UUID
			interval int64
		}
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.id, &d.interval); err != nil {
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
			slot := now.Unix() / d.interval
			if _, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobDiscover, TargetID: d.id, Payload: map[string]string{},
				Kind: "scheduled", DedupeKey: fmt.Sprintf("target.discover:%s:%d", d.id, slot)}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
