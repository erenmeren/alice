package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/audit"
)

const (
	day = 24 * time.Hour
	// maxLineRunes matches the migration's left(..., 200) for names in the issuance mail and the
	// mail_outbox subject CHECK (length(subject) <= 200, counted in characters).
	maxLineRunes = 200
)

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
type candidate struct {
	licenseID, customer, requestedBy, requesterEmail string
	validUntil                                       time.Time
	targets                                          int
}

// CreateReminders enqueues expiry reminders due at now and returns how many reminders it created
// (one per license and threshold, however many outbox rows that took).
//
// A license qualifies when it is live (see liveLicense: not revoked, not replaced, not renewed) and ends within
// (now, now+90 days]. Its threshold T is the smallest of 30, 60, 90 with valid_until <= now+T days.
// If (license, T) has no reminders row, rows for T and every larger threshold are inserted (ruling
// 6: a threshold that was skipped never fires late) and one e-mail for T is enqueued.
//
// Each license is handled in its own transaction holding both the reminder rows and the outbox
// row, so a crash cannot leave a reminder recorded without its mail or a mail without its record.
// Two concurrent runs enqueue once: the reminder rows are inserted with ON CONFLICT DO NOTHING
// RETURNING, and the mail is enqueued only when this transaction inserted the row for T. A second
// run that races on the same row waits on the primary key until the first commits, then sees the
// conflict and inserts nothing (or inserts it itself if the first rolled back).
//
// Every recipient gets an outbox row of their own, so one mailbox that refuses the mail fails only
// its own row. The owner's row goes to the owner_email setting; while that is not set its
// recipient list is empty and ResolveEmptyRecipients fills it once the address exists. The
// requester's row goes to their web_users.email (requested_by "web:<name>", name matched
// case-insensitively like the unique index, user not disabled, address not empty) and is written
// only when they have one that differs from the owner's (compared case-insensitively). The count
// is of reminders, not outbox rows.
//
// A license whose transaction fails is skipped and retried on the next run; the errors are joined
// and returned together with the number of reminders that did go out.
//
// baseURL, when not empty, must be an absolute http(s) URL with a host and without user info,
// query or fragment; the body then links to <baseURL>/requests/new?renew=<license-id>. An invalid
// baseURL is refused before anything is written. The body never contains the installation ID.
func CreateReminders(ctx context.Context, pool *pgxpool.Pool, now time.Time, baseURL string) (int, error) {
	base, err := renewBase(baseURL)
	if err != nil {
		return 0, err
	}
	var owner string
	err = pool.QueryRow(ctx, `SELECT value FROM vendor_settings WHERE key = 'owner_email'`).Scan(&owner)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("notify: read owner address: %w", err)
	}

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
		sent, err := remindOne(ctx, pool, c, now, owner, base)
		if err != nil {
			// One bad license must not keep the others from being reminded; its transaction
			// rolled back, so the next run retries it.
			errs = append(errs, fmt.Errorf("notify: reminder for %s: %w", oneLine(c.licenseID), err))
			continue
		}
		if sent {
			n++
		}
	}
	return n, errors.Join(errs...)
}

// ValidateBaseURL checks a --base-url value the way CreateReminders will, so a command can refuse
// it before doing anything else.
func ValidateBaseURL(baseURL string) error {
	_, err := renewBase(baseURL)
	return err
}

// renewBase validates baseURL and returns it without a trailing slash ("" for no link).
func renewBase(baseURL string) (string, error) {
	if baseURL == "" {
		return "", nil
	}
	// url.Parse accepts spaces and some other characters that would make the link break or wrap
	// in a plain-text mail; refuse them instead of guessing an encoding.
	if strings.ContainsFunc(baseURL, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", errors.New("notify: base url: contains whitespace or control characters")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.New("notify: base url: not a valid url") // the parse error repeats the input
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("notify: base url: must be http(s)://host[/path] without user info, query or fragment")
	}
	return strings.TrimRight(baseURL, "/"), nil
}

func reminderCandidates(ctx context.Context, q audit.Q, now time.Time) ([]candidate, error) {
	// The threshold CASE must agree with threshold() below; both use the same instants.
	rows, err := q.Query(ctx, `SELECT l.license_id, c.name, l.valid_until, l.targets, r.requested_by, coalesce(w.email, '')
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN license_requests r ON r.id = l.request_id
		LEFT JOIN web_users w ON r.requested_by LIKE 'web:%' AND lower(w.name) = lower(substr(r.requested_by, 5))
		     AND w.email <> '' AND w.disabled_at IS NULL
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
		if err := rows.Scan(&c.licenseID, &c.customer, &c.validUntil, &c.targets, &c.requestedBy, &c.requesterEmail); err != nil {
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

// remindOne records the reminder rows for c and enqueues its mail in one transaction. It reports
// whether a mail was enqueued (false when another run recorded threshold T first).
func remindOne(ctx context.Context, pool *pgxpool.Pool, c candidate, now time.Time, owner, base string) (bool, error) {
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
		// Another run already recorded (and enqueued) T. Rows for larger thresholds that this
		// transaction may have added are still correct, so commit them.
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("notify: commit reminder: %w", err)
		}
		return false, nil
	}

	subject, body := reminderMessage(c, t, now, base)
	var ownerTo []string // empty: the row waits for the owner address
	if owner != "" {
		ownerTo = []string{owner}
	}
	if _, err := Enqueue(ctx, tx, "reminder", ownerTo, subject, body); err != nil {
		return false, err
	}
	if c.requesterEmail != "" && !strings.EqualFold(c.requesterEmail, owner) {
		if _, err := Enqueue(ctx, tx, "reminder", []string{c.requesterEmail}, subject, body); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("notify: commit reminder: %w", err)
	}
	return true, nil
}

func reminderMessage(c candidate, t int, now time.Time, base string) (subject, body string) {
	customer := oneLine(c.customer)
	subject = oneLine(fmt.Sprintf("License ending in %d days: %s", t, customer))
	daysLeft := int((c.validUntil.Sub(now) + day - 1) / day) // rounded up: half a day left is "1"
	var b strings.Builder
	fmt.Fprintf(&b, "A license ends in %d days or less.\n\n", t)
	fmt.Fprintf(&b, "Customer: %s\n", customer)
	fmt.Fprintf(&b, "License: %s\n", oneLine(c.licenseID))
	fmt.Fprintf(&b, "Valid until: %s\n", c.validUntil.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "Days left: %d\n", daysLeft)
	fmt.Fprintf(&b, "Targets: %d\n", c.targets)
	fmt.Fprintf(&b, "Requested by: %s\n", oneLine(c.requestedBy))
	if base != "" {
		fmt.Fprintf(&b, "Renew: %s/requests/new?renew=%s\n", base, url.QueryEscape(c.licenseID))
	}
	return subject, b.String()
}

// oneLine turns every run of control and format characters (line breaks, escape sequences, bidi
// overrides) and invalid UTF-8 into one space and keeps the first 200 runes, like the issuance
// trigger does, so a value from the database can never start a new header or body line or make a
// line read differently than it is.
func oneLine(s string) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToValidUTF8(s, string(utf8.RuneError)) {
		if dropRune(r) {
			if !gap {
				b.WriteByte(' ')
			}
			gap = true
			continue
		}
		gap = false
		b.WriteRune(r)
	}
	s = b.String()
	if utf8.RuneCountInString(s) > maxLineRunes {
		s = string([]rune(s)[:maxLineRunes])
	}
	return s
}
