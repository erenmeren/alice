package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/webuser"
)

// shownSettings are the settings "settings show" always lists, in this order; settableSettings
// are the ones "settings set" accepts (last_summary_at is the notifier's mark, not an owner choice).
var (
	shownSettings    = []string{"timezone", "last_summary_at"}
	settableSettings = "timezone"
)

// noOwnerWarning is printed by notify run when no web user could see the owner notifications.
const noOwnerWarning = "warning: no enabled owner web user exists; owner notifications will wait until one is created"

// isPermissionDenied reports a database refusal for lack of privilege.
func isPermissionDenied(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501" // insufficient_privilege
}

func (c *cli) usageErr(format string, a ...any) int {
	_, _ = fmt.Fprintf(c.err, "vendor-console: "+format+"\n", a...)
	return 2
}

// settings handles "settings set KEY VALUE" and "settings show" (owner login only).
func (c *cli) settings(args []string) int {
	switch {
	case len(args) >= 1 && args[0] == "set":
		if len(args) != 3 {
			return c.usageErr("settings set needs a KEY and a VALUE")
		}
		key, value := args[1], args[2]
		if key != "timezone" {
			return c.usageErr("unknown setting %q (allowed keys: %s)", key, settableSettings)
		}
		// "Local" would mean the zone of whichever host runs the notifier, not a configured one.
		if value == "" || value == "Local" {
			return c.usageErr("timezone: give an IANA zone name such as Europe/Istanbul")
		}
		if _, err := time.LoadLocation(value); err != nil {
			return c.usageErr("timezone: unknown zone %q (use an IANA name such as Europe/Istanbul)", value)
		}
		ctx := context.Background()
		pool, err := c.connect(ctx)
		if err != nil {
			return c.fail(err)
		}
		defer pool.Close()
		if err := store.SetSetting(ctx, pool, key, value); err != nil {
			return c.settingsErr(err)
		}
		_, _ = fmt.Fprintf(c.out, "%s set\n", key)
		return 0
	case len(args) >= 1 && args[0] == "show":
		if len(args) != 1 {
			return c.usageErr("settings show takes no arguments")
		}
		ctx := context.Background()
		pool, err := c.connect(ctx)
		if err != nil {
			return c.fail(err)
		}
		defer pool.Close()
		list, err := store.Settings(ctx, pool)
		if err != nil {
			return c.settingsErr(err)
		}
		stored := map[string]string{}
		for _, s := range list {
			stored[s.Key] = s.Value
		}
		for _, k := range shownSettings {
			v, ok := stored[k]
			if !ok {
				v = "(not set)"
			}
			_, _ = fmt.Fprintf(c.out, "%-16s %s\n", k, termSafe(v))
		}
		return 0
	}
	return c.unknown(append([]string{"settings"}, args...))
}

func (c *cli) settingsErr(err error) int {
	if isPermissionDenied(err) {
		return c.fail(errors.New("permission denied: the settings commands need the owner login"))
	}
	return c.fail(err)
}

// requireNotifier refuses a login that is not in vendor_notifier before anything is done, so an
// owner or sales login does not get halfway through a run.
func requireNotifier(ctx context.Context, pool *pgxpool.Pool) error {
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT pg_has_role('vendor_notifier', 'MEMBER')`).Scan(&ok); err != nil {
		return fmt.Errorf("check the login's role: %w", err)
	}
	if !ok {
		return errors.New("permission denied: notify run needs a login that is a member of vendor_notifier")
	}
	return nil
}

// hasEnabledOwner reports whether an enabled web user with the role owner exists. It reads only
// the web_users columns the notifier is granted (name, disabled_at, role).
func hasEnabledOwner(ctx context.Context, q audit.Q) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM web_users WHERE role = $1 AND disabled_at IS NULL)`,
		webuser.RoleOwner).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check for an owner web user: %w", err)
	}
	return ok, nil
}

// warnIfNoOwner tells the operator that owner notifications have no reader yet. It is advice
// only: a failure to check is reported as a warning and never fails the run.
func (c *cli) warnIfNoOwner(ctx context.Context, q audit.Q) {
	ok, err := hasEnabledOwner(ctx, q)
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(c.err, "warning: could not %v\n", err)
	case !ok:
		_, _ = fmt.Fprintln(c.err, noOwnerWarning)
	}
}

// notifyRun is "notify run [--dry-run]", meant for cron or a systemd timer. It creates the due
// expiry reminders and the weekly summary as in-app notifications and prunes old read ones;
// nothing is sent anywhere.
func (c *cli) notifyRun(args []string) int {
	fs := c.flags("notify run")
	dry := fs.Bool("dry-run", false, "print what would be created; change nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("notify run takes no arguments besides its flags")
	}
	// A SIGTERM from the timer stops the run between licenses; what was committed stays.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	if err := requireNotifier(ctx, pool); err != nil {
		return c.fail(err)
	}
	c.warnIfNoOwner(ctx, pool)
	now := c.clk.Now()
	if *dry {
		return c.notifyPreview(ctx, pool, now)
	}

	// Every step runs even when an earlier one failed: a broken reminder must not keep the weekly
	// summary from being written. The errors are reported at the end and make the exit code 1.
	var errs []error
	reminders, err := notify.CreateReminders(ctx, pool, now)
	errs = append(errs, err)
	_, _ = fmt.Fprintf(c.out, "reminders: %d created\n", reminders)
	summary, err := notify.WeeklySummary(ctx, pool, now)
	errs = append(errs, err)
	if summary {
		_, _ = fmt.Fprintln(c.out, "weekly summary: created")
	} else {
		_, _ = fmt.Fprintln(c.out, "weekly summary: not due")
	}
	pruned, err := notify.Prune(ctx, pool, now)
	errs = append(errs, err)
	_, _ = fmt.Fprintf(c.out, "pruned: %d\n", pruned)

	if err := errors.Join(errs...); err != nil {
		return c.fail(err)
	}
	return 0
}

// notifyPreview is the dry run: the same selection as a real run, in a read-only transaction.
func (c *cli) notifyPreview(ctx context.Context, pool *pgxpool.Pool, now time.Time) int {
	p, err := notify.PreviewRun(ctx, pool, now)
	if err != nil {
		return c.fail(err)
	}
	summary := "not due"
	if p.Summary {
		summary = "due"
	}
	_, _ = fmt.Fprintf(c.out, "dry run, nothing changed\nreminders: %d to create\nweekly summary: %s\npruned: not run (dry run)\n",
		p.Reminders, summary)
	return 0
}
