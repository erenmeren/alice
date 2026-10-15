package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	day = 24 * time.Hour
	// maxLineRunes matches the migration's left(..., 200) for names in the issuance mail and the
	// mail_outbox subject CHECK (length(subject) <= 200, counted in characters).
	maxLineRunes = 200
)

// thresholds are the reminder points in days before the end, most urgent first.
var thresholds = []int{30, 60, 90}

var lineBreaks = regexp.MustCompile(`[\r\n]+`)

// candidate is a license inside the 90-day window whose current threshold has no reminder row yet.
type candidate struct {
	licenseID, customer, requestedBy, requesterEmail string
	validUntil                                       time.Time
	targets                                          int
}

// CreateReminders enqueues expiry reminders due at now and returns how many e-mails it enqueued.
//
// A license qualifies when it is not revoked, not replaced by a later license, and ends within
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
// Recipients are the owner_email setting and the requester's web_users.email (requested_by
// "web:<name>", name matched case-insensitively like the unique index, user not disabled, address
// not empty), each address once. A mail with at least one recipient is enqueued as it is, so a
// requester is told even before the owner address is configured (ResolveEmptyRecipients only
// fills fully empty rows, so the owner is not added to that mail later). With no address at all
// the row is enqueued with an empty list and waits for the owner address.
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
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			return n, fmt.Errorf("notify: create reminders: %w", err)
		}
		sent, err := remindOne(ctx, pool, c, now, owner, base)
		if err != nil {
			return n, err
		}
		if sent {
			n++
		}
	}
	return n, nil
}

// renewBase validates baseURL and returns it without a trailing slash ("" for no link).
func renewBase(baseURL string) (string, error) {
	if baseURL == "" {
		return "", nil
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

func reminderCandidates(ctx context.Context, q *pgxpool.Pool, now time.Time) ([]candidate, error) {
	// The threshold CASE must agree with threshold() below; both use the same instants.
	rows, err := q.Query(ctx, `SELECT l.license_id, c.name, l.valid_until, l.targets, r.requested_by, coalesce(w.email, '')
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN license_requests r ON r.id = l.request_id
		LEFT JOIN web_users w ON r.requested_by LIKE 'web:%' AND lower(w.name) = lower(substr(r.requested_by, 5))
		     AND w.email <> '' AND w.disabled_at IS NULL
		WHERE l.revoked_at IS NULL AND l.valid_until > $1 AND l.valid_until <= $4
		  AND NOT EXISTS (SELECT 1 FROM licenses n WHERE n.replaces = l.license_id)
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

	// The license is checked again here: it may have been revoked or replaced since the candidate
	// query, and then nothing is recorded.
	rows, err := tx.Query(ctx, `INSERT INTO reminders (license_id, days_before)
		SELECT $1, th FROM unnest($2::int[]) th
		WHERE EXISTS (SELECT 1 FROM licenses l WHERE l.license_id = $1 AND l.revoked_at IS NULL
		      AND NOT EXISTS (SELECT 1 FROM licenses n WHERE n.replaces = $1))
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
	if _, err := Enqueue(ctx, tx, "reminder", recipients(owner, c.requesterEmail), subject, body); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("notify: commit reminder: %w", err)
	}
	return true, nil
}

// recipients lists the owner and the requester, each non-empty address once (addresses compared
// case-insensitively, as mail servers treat them in practice).
func recipients(owner, requester string) []string {
	to := []string{}
	if owner != "" {
		to = append(to, owner)
	}
	if requester != "" && !strings.EqualFold(requester, owner) {
		to = append(to, requester)
	}
	return to
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

// oneLine replaces line breaks with a space and keeps the first 200 runes, like the issuance
// trigger does, so a value from the database can never start a new header or body line.
func oneLine(s string) string {
	s = lineBreaks.ReplaceAllString(s, " ")
	if utf8.RuneCountInString(s) > maxLineRunes {
		s = string([]rune(s)[:maxLineRunes])
	}
	return s
}
