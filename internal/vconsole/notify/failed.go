package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alice/internal/vconsole/audit"
)

// ErrNotFailed means the message does not exist or is not marked failed (pending or sent), so a
// retry would change nothing or would send a message twice.
var ErrNotFailed = errors.New("notify: no failed message with that id")

// FailedRow is one message that SendPending gave up on.
type FailedRow struct {
	ID        int64
	Kind      string
	CreatedAt time.Time
	FailedAt  time.Time
	Attempts  int
	Subject   string
	LastError string
}

// ListFailed returns up to limit failed, unsent messages, oldest first. The owner and notifier
// logins may read the outbox; others get a permission error (42501) through err.
func ListFailed(ctx context.Context, q audit.Q, limit int) ([]FailedRow, error) {
	if limit < 1 {
		return nil, errors.New("notify: list failed: limit must be positive")
	}
	rows, err := q.Query(ctx, `SELECT id, kind, created_at, failed_at, attempts, subject, last_error FROM mail_outbox
		WHERE failed_at IS NOT NULL AND sent_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("notify: list failed: %w", err)
	}
	defer rows.Close()
	var out []FailedRow
	for rows.Next() {
		var r FailedRow
		if err := rows.Scan(&r.ID, &r.Kind, &r.CreatedAt, &r.FailedAt, &r.Attempts, &r.Subject, &r.LastError); err != nil {
			return nil, fmt.Errorf("notify: list failed: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: list failed: %w", err)
	}
	return out, nil
}

// RetryFailed makes one failed message due again at now, with a fresh attempt count, so the next
// SendPending sends it. Only a row that is failed and unsent is touched (ErrNotFailed otherwise):
// a pending row keeps its backoff and a sent row is never sent again. The database audits the
// change (mail.retry). Only the notifier login may change the outbox; others get 42501.
func RetryFailed(ctx context.Context, q audit.Q, id int64, now time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE mail_outbox SET failed_at = NULL, attempts = 0, last_error = '', next_attempt_at = $2
		WHERE id = $1 AND failed_at IS NOT NULL AND sent_at IS NULL`, id, now)
	if err != nil {
		return fmt.Errorf("notify: retry message %d: %w", id, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: %d", ErrNotFailed, id)
	}
	return nil
}
