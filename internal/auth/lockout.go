package auth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// TemplateLockout is the e-mail to Administrators when an account is blocked (SEC-020, R42 row 25).
// Its parameters are username, minutes and failed_logins.
const TemplateLockout = "auth.lockout"

// Templates lists every e-mail template of the auth module.
func Templates() []string { return []string{TemplateLockout} }

// Notifier queues e-mails to the recipients of the notify settings inside the caller's
// transaction; notify.AdminNotifier implements it.
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}
