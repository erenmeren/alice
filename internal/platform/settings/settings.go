// Package settings reads and writes application settings stored as JSON in the
// settings table. Values here are never secret; secret settings use envelope
// encryption in their own columns.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Get decodes the value of key into dst. It reports false (and no error) when
// the key does not exist.
func Get(ctx context.Context, q db.Querier, key string, dst any) (bool, error) {
	var raw []byte
	err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1", key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read setting %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("decode setting %s: %w", key, err)
	}
	return true, nil
}

// Set stores v (encoded as JSON) under key, replacing any previous value.
func Set(ctx context.Context, q db.Querier, key string, v any, now time.Time) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode setting %s: %w", key, err)
	}
	_, err = q.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, $3)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
		key, string(raw), now.UTC())
	if err != nil {
		return fmt.Errorf("write setting %s: %w", key, err)
	}
	return nil
}

// Delete removes key. Deleting a missing key is not an error.
func Delete(ctx context.Context, q db.Querier, key string) error {
	if _, err := q.Exec(ctx, "DELETE FROM settings WHERE key = $1", key); err != nil {
		return fmt.Errorf("delete setting %s: %w", key, err)
	}
	return nil
}
