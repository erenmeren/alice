package auth

import (
	"context"
	"fmt"
	"time"
)

// revokedKeep is how long a revoked session row is kept (it can explain a "signed out
// everywhere" in support cases); after that it is pruned like an expired one.
const revokedKeep = 24 * time.Hour

// PruneExpired deletes sessions that can never authenticate again (absolute or idle lifetime
// over, or revoked more than a day ago) and expired setup-wizard sessions (maintenance.cleanup,
// spec §8.2). It returns the number of rows deleted, also when the second statement fails.
//
// Only sessions.expires_at is indexed (sessions_expires); idle_expires_at, revoked_at and
// setup_sessions.idle_expires_at are not, so these deletes scan their tables. That is fine at
// the hourly cadence and the expected sizes (sessions are pruned every hour); add indexes if
// the tables grow large.
func (s *Service) PruneExpired(ctx context.Context) (int64, error) {
	now := s.clock.Now().UTC()
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions
WHERE expires_at < $1 OR idle_expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)`, now, now.Add(-revokedKeep))
	if err != nil {
		return 0, fmt.Errorf("auth: prune sessions: %w", err)
	}
	setupTag, err := s.pool.Exec(ctx, `DELETE FROM setup_sessions WHERE idle_expires_at < $1`, now)
	if err != nil {
		return tag.RowsAffected(), fmt.Errorf("auth: prune setup sessions: %w", err)
	}
	return tag.RowsAffected() + setupTag.RowsAffected(), nil
}
