package inventory

import (
	"context"
	"fmt"

	"alice/internal/platform/db"
)

// Counter counts managed targets for the license module (license.TargetCounter, spec §7.3):
// live targets that count toward the license. Certificates and keys never count (L-72).
type Counter struct{}

// CountTargets implements license.TargetCounter.
func (Counter) CountTargets(ctx context.Context, q db.Querier) (int, error) {
	var n int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM targets WHERE deleted_at IS NULL AND counts_toward_license").Scan(&n); err != nil {
		return 0, fmt.Errorf("inventory: count targets: %w", err)
	}
	return n, nil
}
