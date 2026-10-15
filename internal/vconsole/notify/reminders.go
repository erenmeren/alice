package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/audit"
)

// ownerRole is the web_users.role whose holders see owner notifications.
const ownerRole = "owner"

// thresholds are the reminder points in days before the end, most urgent first.
var thresholds = []int{30, 60, 90}

// liveLicense is the one rule for "this license still needs reminding", shared by the reminder
// candidates, the re-check inside the reminder transaction and the summary's ending-soon section.
// It applies to the alias l: not revoked, not named in a later license's replaces, and not renewed
// (a later license, not revoked, for the same customer and installation that ends after it; a
// renewal requested from scratch does not fill replaces).
const liveLicense = `l.revoked_at IS NULL
	AND NOT EXISTS (SELECT 1 FROM licenses n WHERE n.replaces = l.license_id)
	AND NOT EXISTS (SELECT 1 FROM licenses n WHERE n.customer_id = l.customer_id AND n.installation = l.installation
	    AND n.revoked_at IS NULL AND n.valid_until > l.valid_until)`

// candidate is a license inside the 90-day window whose current threshold has no reminder row yet.
// requester is the requesting web user's name as stored, empty when the request was not made by an
// enabled web user; requesterRole is that user's role.
type candidate struct {
	licenseID, customer, requestedBy string
	requester, requesterRole         string
	validUntil                       time.Time
	targets                          int
}

// CreateReminders creates the expiry reminders due at now and returns how many reminders it
// created (one per license and threshold, however many notifications that took).
//
// A license qualifies when it is live (see liveLicense: not revoked, not replaced, not renewed) and
// ends within (now, now+90 days]. Its threshold T is the smallest of 30, 60, 90 with valid_until <=
// now+T days. If (license, T) has no reminders row, rows for T and every larger threshold are
// inserted (a threshold that was skipped never fires late) and the notices for T are created.
//
// The notices: one for the owner audience (dedupe key ending:<license>:<T>), always; and one for
// the requester (audience user, ending:<license>:<T>:<name>) when the request was made by an
// enabled web user (requested_by "web:<name>", matched case-insensitively like the unique index).
// A requester with the role owner gets no user notice: the owner notice already reaches them.
// Severity is warning at 30 days and info before.
//
// Each license is handled in its own transaction holding both the reminder rows and the notices,
// so a crash cannot leave a reminder recorded without its notice or a notice without its record.
// Two concurrent runs create each once: the reminder rows are inserted with ON CONFLICT DO NOTHING
// RETURNING and the notices are created only when this transaction inserted the row for T; a
// second run that races on the same row waits on the primary key until the first commits, then
// sees the conflict and inserts nothing (or inserts it itself if the first rolled back). The
// notices' dedupe keys are a second guard.
//
// A license whose transaction fails is skipped and retried on the next run; the errors are joined
// and returned together with the number of reminders that were created.
//
// The body carries the path /requests/new?renew=<license id> of the web application (relative:
// the notice is shown inside it). It never contains the installation ID.
func CreateReminders(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	cands, err := reminderCandidates(ctx, pool, now)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("notify: create reminders: %w", err))
			break
		}
		created, err := remindOne(ctx, pool, c, now)
		if err != nil {
			// One bad license must not keep the others from being reminded; its transaction
			// rolled back, so the next run retries it.
			errs = append(errs, fmt.Errorf("notify: reminder for %s: %w", oneLine(c.licenseID), err))
			continue
		}
		if created {
			n++
		}
	}
	return n, errors.Join(errs...)
}

func reminderCandidates(ctx context.Context, q audit.Q, now time.Time) ([]candidate, error) {
	// The threshold CASE must agree with threshold() below; both use the same instants.
	rows, err := q.Query(ctx, `SELECT l.license_id, c.name, l.valid_until, l.targets, r.requested_by,
		       coalesce(w.name, ''), coalesce(w.role, '')
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN license_requests r ON r.id = l.request_id
		LEFT JOIN web_users w ON r.requested_by LIKE 'web:%' AND lower(w.name) = lower(substr(r.requested_by, 5))
		     AND w.disabled_at IS NULL
		WHERE `+liveLicense+` AND l.valid_until > $1 AND l.valid_until <= $4
		  AND NOT EXISTS (SELECT 1 FROM reminders m WHERE m.license_id = l.license_id
		      AND m.days_before = CASE WHEN l.valid_until <= $2 THEN 30 WHEN l.valid_until <= $3 THEN 60 ELSE 90 END)
		ORDER BY l.valid_until, l.license_id`,
		now, now.Add(30*day), now.Add(60*day), now.Add(90*day))
	if err != nil {
		return nil, fmt.Errorf("notify: find expiring licenses: %w", err)
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.licenseID, &c.customer, &c.validUntil, &c.targets, &c.requestedBy,
			&c.requester, &c.requesterRole); err != nil {
			return nil, fmt.Errorf("notify: read expiring license: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: find expiring licenses: %w", err)
	}
	return out, nil
}

// threshold returns the smallest threshold T with validUntil <= now+T days.
func threshold(validUntil, now time.Time) int {
	for _, t := range thresholds {
		if !validUntil.After(now.Add(time.Duration(t) * day)) {
			return t
		}
	}
	return thresholds[len(thresholds)-1] // not reached: candidates end within 90 days
}

// remindOne records the reminder rows for c and creates its notices in one transaction. It reports
// whether this run created the reminder (false when another run recorded threshold T first).
func remindOne(ctx context.Context, pool *pgxpool.Pool, c candidate, now time.Time) (bool, error) {
	t := threshold(c.validUntil, now)
	var record []int
	for _, th := range thresholds {
		if th >= t {
			record = append(record, th)
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("notify: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// The license is checked again here: it may have been revoked, replaced or renewed since the
	// candidate query, and then nothing is recorded.
	rows, err := tx.Query(ctx, `INSERT INTO reminders (license_id, days_before)
		SELECT $1, th FROM unnest($2::int[]) th
		WHERE EXISTS (SELECT 1 FROM licenses l WHERE l.license_id = $1 AND `+liveLicense+`)
		ON CONFLICT DO NOTHING RETURNING days_before`, c.licenseID, record)
	if err != nil {
		return false, fmt.Errorf("notify: record reminder: %w", err)
	}
	inserted, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return false, fmt.Errorf("notify: record reminder: %w", err)
	}
	if !slices.Contains(inserted, t) {
		// Another run already recorded (and notified) T. Rows for larger thresholds that this
		// transaction may have added are still correct, so commit them.
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("notify: commit reminder: %w", err)
		}
		return false, nil
	}

	for _, n := range reminderNotices(c, t, now) {
		if _, err := Notify(ctx, tx, n); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("notify: commit reminder: %w", err)
	}
	return true, nil
}

// reminderNotices returns the notices of one reminder: the owner's, then the requester's if any.
func reminderNotices(c candidate, t int, now time.Time) []Notice {
	title, body := reminderMessage(c, t, now)
	severity := SeverityInfo
	if t == thresholds[0] {
		severity = SeverityWarning
	}
	days := fmt.Sprint(t)
	owner := Notice{Kind: "license.ending", Severity: severity, Title: title, Body: body,
		Audience: AudienceOwner, Subject: c.licenseID, DedupeKey: licenseKey("ending", c.licenseID, days)}
	out := []Notice{owner}
	if c.requester != "" && c.requesterRole != ownerRole {
		user := owner
		user.Audience, user.Target = AudienceUser, c.requester
		user.DedupeKey = licenseKey("ending", c.licenseID, days, c.requester)
		out = append(out, user)
	}
	return out
}

func reminderMessage(c candidate, t int, now time.Time) (title, body string) {
	customer := oneLine(c.customer)
	title = oneLine(fmt.Sprintf("License ending in %d days: %s", t, customer))
	daysLeft := int((c.validUntil.Sub(now) + day - 1) / day) // rounded up: half a day left is "1"
	var b strings.Builder
	fmt.Fprintf(&b, "A license ends in %d days or less.\n\n", t)
	fmt.Fprintf(&b, "Customer: %s\n", customer)
	fmt.Fprintf(&b, "License: %s\n", oneLine(c.licenseID))
	fmt.Fprintf(&b, "Valid until: %s\n", c.validUntil.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "Days left: %d\n", daysLeft)
	fmt.Fprintf(&b, "Targets: %d\n", c.targets)
	fmt.Fprintf(&b, "Requested by: %s\n", oneLine(c.requestedBy))
	fmt.Fprintf(&b, "Renew: /requests/new?renew=%s\n", url.QueryEscape(c.licenseID))
	return title, b.String()
}
