package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/mail"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/webuser"
)

// The SMTP server is configured by environment, like the database (ruling 1).
const (
	smtpAddrEnv     = "VENDOR_SMTP_ADDR"
	smtpUserEnv     = "VENDOR_SMTP_USER"
	smtpPasswordEnv = "VENDOR_SMTP_PASSWORD" //nolint:gosec // G101: the name of a variable, not a secret
	smtpFromEnv     = "VENDOR_SMTP_FROM"
)

// smtpRootCAs is nil (the system pool) in production; tests point it at the throw-away certificate
// of their in-process SMTP server.
var smtpRootCAs *x509.CertPool

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
		switch key {
		case "owner_email":
			// The sender's own rule: an address stored here is one that can be mailed.
			if err := mail.ValidateAddress(value); err != nil {
				return c.usageErr("owner_email: %v", err)
			}
		case "timezone":
			// "Local" would mean the zone of whichever host runs the notifier, not a configured one.
			if value == "" || value == "Local" {
				return c.usageErr("timezone: give an IANA zone name such as Europe/Istanbul")
			}
			if _, err := time.LoadLocation(value); err != nil {
				return c.usageErr("timezone: unknown zone %q (use an IANA name such as Europe/Istanbul)", value)
			}
		default:
			return c.usageErr("unknown setting %q (owner_email, timezone)", key)
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
		for _, s := range list {
			_, _ = fmt.Fprintf(c.out, "%-16s %s\n", s.Key, s.Value)
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

// webUserSetEmail handles "web-user set-email NAME EMAIL"; an empty EMAIL removes the address.
func (c *cli) webUserSetEmail(args []string) int {
	if len(args) != 2 || strings.TrimSpace(args[0]) == "" {
		return c.usageErr("web-user set-email needs a NAME and an EMAIL (\"\" removes the address)")
	}
	name, email := args[0], args[1]
	if email != "" {
		if err := mail.ValidateAddress(email); err != nil {
			return c.usageErr("email: %v", err)
		}
	}
	ctx := context.Background()
	pool, err := c.connect(ctx)
	if err != nil {
		return c.fail(err)
	}
	defer pool.Close()
	if err := webuser.SetEmail(ctx, pool, name, email); err != nil {
		return c.webUserErr(err)
	}
	if email == "" {
		_, _ = fmt.Fprintf(c.out, "%s: e-mail address removed\n", name)
	} else {
		_, _ = fmt.Fprintf(c.out, "%s: e-mail address set\n", name)
	}
	return 0
}

// smtpSender builds the sender from the environment. It never connects, and its errors never
// contain the password (mail.NewSMTP only names what is wrong).
func (c *cli) smtpSender() (mail.Sender, error) {
	addr, from := c.getenv(smtpAddrEnv), c.getenv(smtpFromEnv)
	if addr == "" || from == "" {
		return nil, fmt.Errorf("set %s (host:port) and %s (the sender address); %s and %s if the server needs a login",
			smtpAddrEnv, smtpFromEnv, smtpUserEnv, smtpPasswordEnv)
	}
	s, err := mail.NewSMTP(mail.SMTPConfig{Addr: addr, User: c.getenv(smtpUserEnv), Password: c.getenv(smtpPasswordEnv),
		From: from, RootCAs: smtpRootCAs})
	if err != nil {
		return nil, fmt.Errorf("check %s, %s, %s and %s: %w", smtpAddrEnv, smtpFromEnv, smtpUserEnv, smtpPasswordEnv, err)
	}
	return s, nil
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

// notifyRun is "notify run [--base-url URL] [--dry-run]", meant for cron or a systemd timer.
func (c *cli) notifyRun(args []string) int {
	fs := c.flags("notify run")
	baseURL := fs.String("base-url", "", "address of the sales web page, for the Renew link in reminders")
	dry := fs.Bool("dry-run", false, "print what would be created and sent; change nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return c.usageErr("notify run takes no arguments besides its flags")
	}
	if err := notify.ValidateBaseURL(*baseURL); err != nil {
		return c.usageErr("--base-url: %v", err)
	}
	var sender mail.Sender
	if !*dry {
		var err error
		if sender, err = c.smtpSender(); err != nil {
			return c.usageErr("%v", err)
		}
	}
	// A SIGTERM from the timer stops the run between messages; a message the server already accepted
	// is still recorded as sent (notify.SendPending).
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
	now := c.clk.Now()
	if *dry {
		return c.notifyPreview(ctx, pool, now)
	}

	// Every step runs even when an earlier one failed: a broken reminder must not keep the issuance
	// mails from going out. The errors are reported at the end.
	var errs []error
	resolved, err := notify.ResolveEmptyRecipients(ctx, pool)
	errs = append(errs, err)
	_, _ = fmt.Fprintf(c.out, "recipients filled: %d\n", resolved)
	reminders, err := notify.CreateReminders(ctx, pool, now, *baseURL)
	errs = append(errs, err)
	_, _ = fmt.Fprintf(c.out, "reminders created: %d\n", reminders)
	summary, err := notify.WeeklySummary(ctx, pool, now)
	errs = append(errs, err)
	if summary {
		_, _ = fmt.Fprintln(c.out, "weekly summary: created")
	} else {
		_, _ = fmt.Fprintln(c.out, "weekly summary: not due")
	}
	res, err := notify.SendPending(ctx, pool, sender, "", now)
	errs = append(errs, err)
	_, _ = fmt.Fprintf(c.out, "mail: sent %d, to retry %d, failed %d, waiting for the owner address %d\n",
		res.Sent, res.Retry, res.Failed, res.Waiting)

	code := 0
	if err := errors.Join(errs...); err != nil {
		code = c.fail(err)
	}
	if res.Failed > 0 {
		_, _ = fmt.Fprintf(c.err, "vendor-console: %d message(s) could not be sent and were marked failed\n", res.Failed)
		code = 1
	}
	return code
}

func (c *cli) notifyPreview(ctx context.Context, pool *pgxpool.Pool, now time.Time) int {
	p, err := notify.PreviewRun(ctx, pool, now)
	if err != nil {
		return c.fail(err)
	}
	summary := "not due"
	if p.Summary {
		summary = "due"
	}
	_, _ = fmt.Fprintf(c.out, "dry run, nothing changed\nrecipients to fill: %d\nreminders to create: %d\nweekly summary: %s\n"+
		"mail to send: %d already queued, plus the new ones above; waiting for the owner address %d\n",
		p.Resolved, p.Reminders, summary, p.Due, p.Waiting)
	return 0
}
