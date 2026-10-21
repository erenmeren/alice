// Package notify queues and sends Alice's emails. An email is queued in
// notifications_outbox inside the transaction of the change that causes it and is sent
// later by Sender (job notify.send), so mail trouble never blocks or undoes work
// (spec §7.6, §8.2).
package notify

import (
	"context"
	"regexp"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/clock"
)

var templatePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// AdminNotifier queues emails to Administrators. It implements license.Notifier.
type AdminNotifier struct{ Clock clock.Clock }

// NotifyAdmins queues template for every enabled Administrator with an email address, and the extra addresses of the
// recipients setting (R42 row 6), each in its own language, inside tx. The signature is unchanged.
func (a AdminNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	raw, err := encodeParams(template, params)
	if err != nil {
		return err
	}
	rcpts, err := recipientsFor(ctx, tx)
	if err != nil {
		return err
	}
	return insertRows(ctx, tx, a.Clock, rcpts, template, raw)
}
