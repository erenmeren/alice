package license

import (
	"context"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Tick observes the clock, re-verifies the stored files, recomputes the state and saves the
// time record. It runs at start, hourly (job license.evaluate), after every upload, and after
// the demo clock moves (e2e build). It holds the license row lock, so a Tick never overwrites
// the snapshot of a later one.
func (s *Service) Tick(ctx context.Context) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := loadInstallation(ctx, tx, true); err != nil {
			return err
		}
		reading, _ := s.observe()
		c, err := s.compute(ctx, tx, reading, false)
		if err != nil {
			return err
		}
		s.setSnapshot(c.snap)
		return s.persistHWM(ctx, tx)
	})
}
