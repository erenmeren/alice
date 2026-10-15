package store

import (
	"context"
	"fmt"

	"alice/internal/vconsole/audit"
)

// Setting is one row of vendor_settings.
type Setting struct{ Key, Value, UpdatedBy string }

// SetSetting writes a setting (owner only; the database checks the key and an owner address, stamps
// who changed it and audits the change). Callers validate the value first, so a refusal here is a
// permission problem or a race, not a typo.
func SetSetting(ctx context.Context, q audit.Q, key, value string) error {
	if _, err := q.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value); err != nil {
		return fmt.Errorf("store: set %s: %w", key, err)
	}
	return nil
}

// Settings returns every stored setting, sorted by key.
func Settings(ctx context.Context, q audit.Q) ([]Setting, error) {
	rows, err := q.Query(ctx, `SELECT key, value, coalesce(updated_by, '') FROM vendor_settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("store: read settings: %w", err)
	}
	defer rows.Close()
	var out []Setting
	for rows.Next() {
		var s Setting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedBy); err != nil {
			return nil, fmt.Errorf("store: read settings: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
