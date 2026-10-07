// Package notify queues and sends Alice's emails. An email is queued in
// notifications_outbox inside the transaction of the change that causes it and is sent
// later by Sender (job notify.send), so mail trouble never blocks or undoes work
// (spec §7.6, §8.2).
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/clock"
)

var templatePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// AdminNotifier queues emails to Administrators. It implements license.Notifier.
type AdminNotifier struct{ Clock clock.Clock }

// NotifyAdmins queues template for every enabled Administrator with an email address, and the extra addresses of the
// recipients setting (R42 row 6), each in its own language, inside tx. The signature is unchanged.
func (a AdminNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if !templatePattern.MatchString(template) {
		return fmt.Errorf("notify: %q is not a template name", template)
	}
	if params == nil {
		params = map[string]string{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	rcpts, err := recipientsFor(ctx, tx)
	if err != nil {
		return err
	}
	now := a.Clock.Now().UTC()
	for _, r := range rcpts {
		if _, err := tx.Exec(ctx, `INSERT INTO notifications_outbox
(id, kind, to_address, template_key, params, locale, status, attempts, next_attempt_at, created_at)
VALUES ($1, 'email', $2, $3, $4, $5, 'pending', 0, $6, $6)`, uuid.Must(uuid.NewV7()), r.email, template, raw, r.locale, now); err != nil {
			return fmt.Errorf("notify: queue email: %w", err)
		}
	}
	return nil
}
