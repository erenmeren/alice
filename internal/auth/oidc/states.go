package oidc

import (
	"context"
	"fmt"
)

// PruneStates deletes the sign-in states that expired (maintenance.cleanup) and returns how many.
func (s *Service) PruneStates(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM oidc_login_states WHERE expires_at <= $1", s.clock.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("oidc: prune sign-in states: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
