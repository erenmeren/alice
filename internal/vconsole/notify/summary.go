package notify

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // embedded zone database: Europe/Istanbul must load on a host without one
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// summaryEvery is the minimum gap between two summaries and the period of the first one.
	summaryEvery = 7 * day
	// defaultTimezone is used when the timezone setting is missing or empty (the company's zone).
	defaultTimezone = "Europe/Istanbul"
	// maxSectionLines keeps the mail readable; the rest of a section is counted, not listed.
	maxSectionLines = 20
	// maxNameRunes bounds customer and user names in a line, so one odd name cannot fill the mail.
	maxNameRunes = 60
	// maxIDRunes bounds a license ID; IDs are short, this only guards against a strange row.
	maxIDRunes = 64
	// maxFailedRunes bounds the subject and error of a failed mail in its line.
	maxFailedRunes = 80
	// endingWithin is the look-ahead of the "Ending in the next 90 days" section.
	endingWithin = 90 * day

	// Ruling 4, unusual activity: issuing between nightStartHour:00 and nightEndHour:00 local time
	// (06:00 itself is day), or more than maxPerSignerDay licenses by one signer in one local day.
	nightStartHour  = 22
	nightEndHour    = 6
	maxPerSignerDay = 5

	localTimeLayout = "2006-01-02 15:04 MST"

	// summaryLockKey is the pg_advisory_xact_lock key that serialises concurrent summary runs
	// ("vcsumary" in ASCII; any constant no other code uses would do).
	summaryLockKey int64 = 0x7663_7375_6d61_7279
)

// issuedRow is one license issued in the covered period.
type issuedRow struct {
	licenseID, customer, signer string
	targets                     int
	issuedAt                    time.Time
}

// section is one block of the summary body. count may exceed len(lines) when the query listed
// only the first maxSectionLines rows.
type section struct {
	title string
	count int
	note  string // printed first, not counted (the time-zone fallback)
	empty string // printed when count is zero
	lines []string
}

// WeeklySummary enqueues the owner's weekly summary when none went out in the last 7 days, and
// reports whether it did.
//
// It runs when the last_summary_at setting is missing (or unreadable) or at most now-7 days. The
// first summary covers the 7 days before now, later ones cover [last_summary_at, now). The mail goes
// to owner_email (an empty recipient list waits for that address, see ResolveEmptyRecipients).
//
// Everything happens in one transaction: an advisory lock is taken first and the condition is
// checked after it, so two concurrent runs send one summary; notify_mark_summary(now) and the
// outbox insert share the transaction, so a failed insert leaves last_summary_at unchanged and a
// failed mark leaves no mail behind. notify_mark_summary stores whole seconds, so the period ends
// at now truncated to the second: the next period starts exactly where this one ended.
//
// The body lists names and IDs only. It never contains installation IDs, license files, customer
// contacts or other customer data beyond the name.
func WeeklySummary(ctx context.Context, pool *pgxpool.Pool, now time.Time) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("notify: summary: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, summaryLockKey); err != nil {
		return false, fmt.Errorf("notify: summary: lock: %w", err)
	}
	// Read after the lock: in READ COMMITTED this statement sees a summary another run committed
	// while this one waited.
	settings, err := readSettings(ctx, tx)
	if err != nil {
		return false, err
	}
	last, haveLast := parseLastSummary(settings["last_summary_at"])
	if haveLast && last.After(now.Add(-summaryEvery)) {
		return false, nil
	}
	end := now.UTC().Truncate(time.Second)
	start := end.Add(-summaryEvery)
	if haveLast {
		start = last
	}
	loc, zoneNote := summaryZone(settings["timezone"])

	issued, err := issuedIn(ctx, tx, start, end)
	if err != nil {
		return false, err
	}
	open, err := openRequests(ctx, tx, now)
	if err != nil {
		return false, err
	}
	ending, err := endingSoon(ctx, tx, now, loc)
	if err != nil {
		return false, err
	}
	failed, err := failedMails(ctx, tx, start, end, loc)
	if err != nil {
		return false, err
	}
	unusual := unusualLines(issued, loc)

	issuedSec := section{title: "Issued since " + start.In(loc).Format(localTimeLayout), count: len(issued), empty: "Nothing issued."}
	for _, r := range issued {
		issuedSec.lines = append(issuedSec.lines, fmt.Sprintf("%s | %s | %d targets | signed by %s | %s",
			clean(r.licenseID, maxIDRunes), clean(r.customer, maxNameRunes), r.targets,
			clean(r.signer, maxNameRunes), r.issuedAt.In(loc).Format(localTimeLayout)))
	}
	unusualSec := section{title: "Unusual", count: len(unusual), note: zoneNote, empty: "None.", lines: unusual}

	var b strings.Builder
	b.WriteString("Weekly summary of the vendor console.\n\n")
	fmt.Fprintf(&b, "Period: %s to %s\n", start.In(loc).Format(localTimeLayout), end.In(loc).Format(localTimeLayout))
	fmt.Fprintf(&b, "Time zone: %s\n\n", loc.String())
	for _, s := range []section{issuedSec, open, ending, failed, unusualSec} {
		writeSection(&b, s)
	}
	subject := fmt.Sprintf("Weekly summary: %d issued, %d open requests, %d unusual", len(issued), open.count, len(unusual))

	var to []string
	if owner := settings["owner_email"]; owner != "" {
		to = []string{owner}
	}
	// The mark comes before the insert on purpose: if the insert then fails, the rollback is what
	// keeps last_summary_at unchanged, which is the property the transaction exists for.
	if _, err := tx.Exec(ctx, `SELECT notify_mark_summary($1)`, now); err != nil {
		return false, fmt.Errorf("notify: summary: mark: %w", err)
	}
	if _, err := Enqueue(ctx, tx, "summary", to, subject, b.String()); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("notify: summary: commit: %w", err)
	}
	return true, nil
}

func readSettings(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT key, value FROM vendor_settings
		WHERE key IN ('owner_email', 'timezone', 'last_summary_at')`)
	if err != nil {
		return nil, fmt.Errorf("notify: summary: read settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("notify: summary: read settings: %w", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: summary: read settings: %w", err)
	}
	return out, nil
}

// parseLastSummary reads the value notify_mark_summary writes. An unreadable value (the owner can
// write the setting by hand) counts as "never": a broken setting must not stop the summaries.
func parseLastSummary(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// summaryZone loads the configured zone. An unknown name falls back to UTC with a note for the
// Unusual section, because the night rule silently shifting by hours would be worse than a
// visible warning. "Local" is refused: it means the host's zone, not a configured one.
func summaryZone(name string) (*time.Location, string) {
	if name == "" {
		name = defaultTimezone
	}
	if name != "Local" {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc, ""
		}
	}
	return time.UTC, fmt.Sprintf("Time zone \"%s\" is unknown; times are shown in UTC.", clean(name, maxNameRunes))
}

func issuedIn(ctx context.Context, tx pgx.Tx, start, end time.Time) ([]issuedRow, error) {
	// All rows, not the first 20: the unusual rules look at every license of the period.
	rows, err := tx.Query(ctx, `SELECT l.license_id, c.name, l.signed_by, l.targets, l.issued_at
		FROM licenses l JOIN customers c ON c.id = l.customer_id
		WHERE l.issued_at >= $1 AND l.issued_at < $2
		ORDER BY l.issued_at, l.license_id`, start, end)
	if err != nil {
		return nil, fmt.Errorf("notify: summary: issued licenses: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (issuedRow, error) {
		var x issuedRow
		err := r.Scan(&x.licenseID, &x.customer, &x.signer, &x.targets, &x.issuedAt)
		return x, err
	})
	if err != nil {
		return nil, fmt.Errorf("notify: summary: issued licenses: %w", err)
	}
	return out, nil
}

func openRequests(ctx context.Context, tx pgx.Tx, now time.Time) (section, error) {
	s := section{title: "Open requests", empty: "None."}
	rows, err := tx.Query(ctx, `SELECT r.id, c.name, r.requested_at, r.requested_by, count(*) OVER ()
		FROM license_requests r JOIN customers c ON c.id = r.customer_id
		WHERE r.status = 'open'
		ORDER BY r.requested_at, r.id LIMIT $1`, maxSectionLines)
	if err != nil {
		return s, fmt.Errorf("notify: summary: open requests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id        int64
			cust, by  string
			requested time.Time
		)
		if err := rows.Scan(&id, &cust, &requested, &by, &s.count); err != nil {
			return s, fmt.Errorf("notify: summary: open requests: %w", err)
		}
		age := max(int(now.Sub(requested)/day), 0)
		s.lines = append(s.lines, fmt.Sprintf("#%d | %s | %d days old | requested by %s",
			id, clean(cust, maxNameRunes), age, clean(by, maxNameRunes)))
	}
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("notify: summary: open requests: %w", err)
	}
	return s, nil
}

// endingSoon uses the same rule as the reminders: not revoked, not replaced, ends in (now, now+90d].
func endingSoon(ctx context.Context, tx pgx.Tx, now time.Time, loc *time.Location) (section, error) {
	s := section{title: "Ending in the next 90 days", empty: "None."}
	rows, err := tx.Query(ctx, `SELECT l.license_id, c.name, l.valid_until, count(*) OVER ()
		FROM licenses l JOIN customers c ON c.id = l.customer_id
		WHERE l.revoked_at IS NULL AND l.valid_until > $1 AND l.valid_until <= $2
		  AND NOT EXISTS (SELECT 1 FROM licenses n WHERE n.replaces = l.license_id)
		ORDER BY l.valid_until, l.license_id LIMIT $3`, now, now.Add(endingWithin), maxSectionLines)
	if err != nil {
		return s, fmt.Errorf("notify: summary: ending licenses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, cust string
			until    time.Time
		)
		if err := rows.Scan(&id, &cust, &until, &s.count); err != nil {
			return s, fmt.Errorf("notify: summary: ending licenses: %w", err)
		}
		daysLeft := int((until.Sub(now) + day - 1) / day) // rounded up, as in the reminders
		s.lines = append(s.lines, fmt.Sprintf("%s | %s | ends %s | %d days left",
			clean(id, maxIDRunes), clean(cust, maxNameRunes), until.In(loc).Format(localTimeLayout), daysLeft))
	}
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("notify: summary: ending licenses: %w", err)
	}
	return s, nil
}

// failedMails lists messages that gave up in the covered period. Failed rows are never retried, so
// listing every failed row ever would repeat the same lines each week; each failure is reported
// once, in the summary whose period contains its failed_at.
func failedMails(ctx context.Context, tx pgx.Tx, start, end time.Time, loc *time.Location) (section, error) {
	s := section{title: "Failed e-mails", empty: "None."}
	rows, err := tx.Query(ctx, `SELECT kind, created_at, subject, last_error, count(*) OVER ()
		FROM mail_outbox
		WHERE failed_at IS NOT NULL AND failed_at >= $1 AND failed_at < $2
		ORDER BY failed_at, id LIMIT $3`, start, end, maxSectionLines)
	if err != nil {
		return s, fmt.Errorf("notify: summary: failed mails: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			kind, subject, lastErr string
			created                time.Time
		)
		if err := rows.Scan(&kind, &created, &subject, &lastErr, &s.count); err != nil {
			return s, fmt.Errorf("notify: summary: failed mails: %w", err)
		}
		s.lines = append(s.lines, fmt.Sprintf("%s | %s | %s | %s", clean(kind, maxNameRunes),
			created.In(loc).Format(localTimeLayout), clean(subject, maxFailedRunes), clean(lastErr, maxFailedRunes)))
	}
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("notify: summary: failed mails: %w", err)
	}
	return s, nil
}

// unusualLines applies ruling 4 to the licenses of the period: night issuance first (in issue
// order), then signers above the daily limit (by day, then signer).
func unusualLines(issued []issuedRow, loc *time.Location) []string {
	var out []string
	type signerDay struct{ signer, day string }
	perDay := map[signerDay]int{}
	for _, r := range issued {
		local := r.issuedAt.In(loc)
		if h := local.Hour(); h >= nightStartHour || h < nightEndHour {
			out = append(out, fmt.Sprintf("Issued at night: %s | %s | signed by %s | %s",
				clean(r.licenseID, maxIDRunes), clean(r.customer, maxNameRunes),
				clean(r.signer, maxNameRunes), local.Format(localTimeLayout)))
		}
		perDay[signerDay{r.signer, local.Format("2006-01-02")}]++
	}
	var busy []signerDay
	for k, n := range perDay {
		if n > maxPerSignerDay {
			busy = append(busy, k)
		}
	}
	slices.SortFunc(busy, func(a, b signerDay) int {
		if c := strings.Compare(a.day, b.day); c != 0 {
			return c
		}
		return strings.Compare(a.signer, b.signer)
	})
	for _, k := range busy {
		out = append(out, fmt.Sprintf("%s issued %d licenses on %s (more than %d in one day)",
			clean(k.signer, maxNameRunes), perDay[k], k.day, maxPerSignerDay))
	}
	return out
}

func writeSection(b *strings.Builder, s section) {
	fmt.Fprintf(b, "== %s (%d) ==\n", s.title, s.count)
	if s.note != "" {
		b.WriteString(s.note + "\n")
	}
	if s.count == 0 {
		b.WriteString(s.empty + "\n")
	}
	shown := s.lines[:min(len(s.lines), maxSectionLines)]
	for _, l := range shown {
		b.WriteString(l + "\n")
	}
	if more := s.count - len(shown); more > 0 {
		fmt.Fprintf(b, "... and %d more\n", more)
	}
	b.WriteString("\n")
}

// clean drops control and format characters (line breaks, escape sequences, bidi overrides that
// could make a line read differently than it is) and keeps the first n runes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return s
}
