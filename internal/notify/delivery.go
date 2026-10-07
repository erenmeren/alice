package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/settings"
)

const deliveryKey = "notify.delivery"

// Delivery is the state behind the "E-mails could not be sent" banner (F-60, R42 row 8).
type Delivery struct {
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastFailureAt       *time.Time `json:"last_failure_at"`
	LastFailureCode     string     `json:"last_failure_code"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	Pending             int        `json:"-"` // pending outbox rows now
	Failed24h           int        `json:"-"` // rows that gave up in the last 24 hours
}

// Failing reports whether the last FailingAfter or more send attempts all failed.
func (d Delivery) Failing() bool { return d.ConsecutiveFailures >= FailingAfter }

// recordDelivery counts one send attempt in the same transaction as the outbox update. It is one INSERT … ON
// CONFLICT DO UPDATE whose new value is computed from the stored one by the database, so parallel drains neither lose
// an increment nor overwrite a newer state (S-9).
func recordDelivery(ctx context.Context, tx pgx.Tx, ok bool, code string, now time.Time) error {
	now = now.UTC()
	at := now.Format(time.RFC3339Nano)
	var err error
	if ok {
		first := Delivery{LastSuccessAt: &now}
		_, err = tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, $3)
ON CONFLICT (key) DO UPDATE SET
value = settings.value || jsonb_build_object('consecutive_failures', 0, 'last_success_at', $4::text),
updated_at = EXCLUDED.updated_at`, deliveryKey, mustJSON(first), now, at)
	} else {
		first := Delivery{ConsecutiveFailures: 1, LastFailureAt: &now, LastFailureCode: code}
		_, err = tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, $3)
ON CONFLICT (key) DO UPDATE SET
value = settings.value || jsonb_build_object('consecutive_failures',
  coalesce((settings.value->>'consecutive_failures')::int, 0) + 1, 'last_failure_at', $4::text, 'last_failure_code', $5::text),
updated_at = EXCLUDED.updated_at`, deliveryKey, mustJSON(first), now, at, code)
	}
	if err != nil {
		return fmt.Errorf("notify: record the delivery state: %w", err)
	}
	return nil
}

// Delivery reads the state and the outbox counts: pending rows now, and failed rows queued within the last 48 hours
// (they gave up at most 24 hours ago).
func (s *Settings) Delivery(ctx context.Context) (Delivery, error) {
	var d Delivery
	if _, err := settings.Get(ctx, s.pool, deliveryKey, &d); err != nil {
		return Delivery{}, err
	}
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'pending'),
count(*) FILTER (WHERE status = 'failed' AND created_at >= $1) FROM notifications_outbox`,
		s.clock.Now().UTC().Add(-2*GiveUpAfter)).Scan(&d.Pending, &d.Failed24h)
	if err != nil {
		return Delivery{}, fmt.Errorf("notify: count the outbox: %w", err)
	}
	return d, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // a struct of plain fields cannot fail to encode
	}
	return string(b)
}
