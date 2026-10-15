package notify

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // embedded zone database: Europe/Istanbul must load on a host without one
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/vconsole/audit"
)

const (
	// summaryEvery is the minimum gap between two summaries and the period of the first one.
	summaryEvery = 7 * day
	// defaultTimezone is used when the timezone setting is missing or empty (the company's zone).
	defaultTimezone = "Europe/Istanbul"
	// maxSectionLines keeps the notice readable; the rest of a section is counted, not listed.
	// When the body would not fit the 4000-character column, sections list fewer lines.
	maxSectionLines = 20
	// maxNameRunes bounds customer and user names in a line, so one odd name cannot fill the notice.
	maxNameRunes = 60
	// maxIDRunes bounds a license ID; IDs are short, this only guards against a strange row.
	maxIDRunes = 64
	// endingWithin is the look-ahead of the "Ending in the next 90 days" section.
	endingWithin = 90 * day
	// futureSkew is how far last_summary_at may lie after now and still count: concurrent runs
	// whose clocks differ by seconds must not each create a summary. A mark further in the future
	// (a hand-written or clock-jumped value) counts as never, so it cannot stop the summaries.
	futureSkew = time.Hour

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

// issuedRow is one license issued in the covered period; signer and issuedAt are the actor and
// time of its audit row.
type issuedRow struct {
	licenseID, customer, signer string
	targets                     int
	issuedAt                    time.Time
}

// section is one block of the summary body. count may exceed len(keep)+len(lines) when the query
// listed only the first maxSectionLines rows.
type section struct {
	title string
	count int
	note  string   // printed first, not counted (the time-zone fallback)
	empty string   // printed when count is zero
	keep  []string // the most important lines: printed first and trimmed only as a last resort
	lines []string
}

// WeeklySummary creates the owner's weekly summary notice when none was made in the last 7 days,
// and reports whether it did.
//
// It runs when the last_summary_at setting is missing, unreadable, more than an hour after now
// (see futureSkew) or at most now-7 days. The first summary covers the 7 days before now, later
// ones cover [last_summary_at, now). The notice (kind summary.weekly, audience owner, dedupe key
// summary:<period end date in UTC>) lists what was issued, the open requests, the licenses ending
// in the next 90 days and unusual activity, and ends with the audit head. When the Unusual section
// is not empty, a second notice (kind activity.unusual, severity alert, unusual:<date>) repeats it,
// so it stands out in the list instead of hiding inside a routine summary.
//
// Everything happens in one transaction: an advisory lock is taken first and the condition is
// checked after it, so two concurrent runs create one summary; notify_mark_summary(now) and the
// notices share the transaction, so a failed insert leaves last_summary_at unchanged and a failed
// mark leaves no notice behind. notify_mark_summary stores whole seconds, so the period ends at now
// truncated to the second: the next period starts exactly where this one ended. The result is
// false when a summary was due but its dedupe key already existed (a mark moved back by hand
// within the same day); the mark is still written.
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
	due, ns, err := composeSummary(ctx, tx, settings, now)
	if err != nil || !due {
		return false, err
	}
	// The mark comes before the inserts on purpose: if an insert then fails, the rollback is what
	// keeps last_summary_at unchanged, which is the property the transaction exists for.
	if _, err := tx.Exec(ctx, `SELECT notify_mark_summary($1)`, now); err != nil {
		return false, fmt.Errorf("notify: summary: mark: %w", err)
	}
	created := false
	for i, n := range ns {
		c, err := Notify(ctx, tx, n)
		if err != nil {
			return false, err
		}
		if i == 0 { // the summary itself; the alert follows it
			created = c
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("notify: summary: commit: %w", err)
	}
	return created, nil
}

// composeSummary decides whether a summary is due at now and, if so, builds its notices: the
// summary first, then the unusual-activity alert when there is any. It only reads, so the dry run
// uses it too and shows exactly what the real run would create.
func composeSummary(ctx context.Context, tx pgx.Tx, settings map[string]string, now time.Time) (bool, []Notice, error) {
	due, last, haveLast := summaryDue(settings["last_summary_at"], now)
	if !due {
		return false, nil, nil
	}
	end := now.UTC().Truncate(time.Second)
	start := end.Add(-summaryEvery)
	if haveLast {
		start = last
	}
	loc, zoneNote := summaryZone(settings["timezone"])

	issued, err := issuedIn(ctx, tx, start, end)
	if err != nil {
		return false, nil, err
	}
	open, err := openRequests(ctx, tx, now)
	if err != nil {
		return false, nil, err
	}
	ending, err := endingSoon(ctx, tx, now, loc)
	if err != nil {
		return false, nil, err
	}
	busy, night := unusualLines(issued, loc)
	unaudited, err := licensesWithoutIssueAudit(ctx, tx)
	if err != nil {
		return false, nil, err
	}
	// The order is by weight: possible tampering first, then signers above the daily limit, then
	// night issuance, which is the most frequent and the first to be trimmed.
	var keep []string
	if unaudited > 0 {
		keep = append(keep, fmt.Sprintf("%d license(s) have no issue audit row (possible tampering or disabled triggers)", unaudited))
	}
	keep = append(keep, busy...)
	unusual := len(keep) + len(night)

	issuedSec := section{title: "Issued since " + start.In(loc).Format(localTimeLayout), count: len(issued), empty: "Nothing issued."}
	for _, r := range issued {
		issuedSec.lines = append(issuedSec.lines, fmt.Sprintf("%s | %s | %d targets | signed by %s | %s",
			clean(r.licenseID, maxIDRunes), clean(r.customer, maxNameRunes), r.targets,
			clean(r.signer, maxNameRunes), r.issuedAt.In(loc).Format(localTimeLayout)))
	}
	unusualSec := section{title: "Unusual", count: unusual, note: zoneNote, empty: "None.", keep: keep, lines: night}

	// The head is read in this transaction, before the mark (which itself adds an audit row): the
	// owner copies it into the paper log, and `vendor-console audit-verify --head` compares
	// against it.
	head, haveHead, err := audit.CurrentHead(ctx, tx)
	if err != nil {
		return false, nil, fmt.Errorf("notify: summary: %w", err)
	}

	var top strings.Builder
	period := fmt.Sprintf("Period: %s to %s\n", start.In(loc).Format(localTimeLayout), end.In(loc).Format(localTimeLayout))
	zone := fmt.Sprintf("Time zone: %s\n\n", loc.String())
	top.WriteString("Weekly summary of the vendor console.\n\n")
	top.WriteString(period)
	top.WriteString(zone)
	tail := ""
	if haveHead {
		tail = fmt.Sprintf("Audit head: %s\n", head)
	}
	body := fitSections(top.String(), []section{issuedSec, open, ending, unusualSec}, tail)
	date := end.Format("2006-01-02")
	out := []Notice{{
		Kind:      "summary.weekly",
		Severity:  SeverityInfo,
		Title:     fmt.Sprintf("Weekly summary: %d issued, %d open requests, %d unusual", len(issued), open.count, unusual),
		Body:      body,
		Audience:  AudienceOwner,
		DedupeKey: "summary:" + date,
	}}
	if unusual > 0 {
		alertSec := unusualSec
		alertSec.title = "Unusual activity"
		alertTop := "Unusual activity was found for the weekly summary.\n\n" + period + zone
		out = append(out, Notice{
			Kind:      "activity.unusual",
			Severity:  SeverityAlert,
			Title:     fmt.Sprintf("Unusual activity: %s in the weekly summary", plural(unusual, "item")),
			Body:      fitSections(alertTop, []section{alertSec}, "The weekly summary covers the whole period.\n"),
			Audience:  AudienceOwner,
			DedupeKey: "unusual:" + date,
		})
	}
	return true, out, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// fitSections renders top, the sections and tail, listing at most maxSectionLines lines per
// section and fewer when the body would not fit the notifications body limit. The sections before
// the last one (the long lists) give up lines first, the largest first; the last one (Unusual)
// then gives up its ordinary lines (night issuance), and only then, as a last resort, its keep
// lines from the end, so the first of them (possible tampering) is the last to go. Headers, counts,
// the "... and N more" lines and the tail (the audit head) are always kept.
func fitSections(top string, secs []section, tail string) string {
	caps := make([]int, len(secs))
	keepCaps := make([]int, len(secs))
	for i, s := range secs {
		keepCaps[i] = len(s.keep)
		caps[i] = max(maxSectionLines-len(s.keep), 0)
	}
	render := func() string {
		var b strings.Builder
		b.WriteString(top)
		for i, s := range secs {
			writeSection(&b, s, keepCaps[i], caps[i])
		}
		b.WriteString(tail)
		return b.String()
	}
	last := len(secs) - 1
	for {
		body := render()
		if utf8.RuneCountInString(body) <= maxBodyRunes {
			return body
		}
		pick := -1
		for i := range last {
			if caps[i] > 0 && (pick < 0 || caps[i] > caps[pick]) {
				pick = i
			}
		}
		switch {
		case pick >= 0:
			caps[pick]--
		case caps[last] > 0:
			caps[last]--
		case keepCaps[last] > 1:
			keepCaps[last]--
		default:
			return body // cannot shrink further; Notify cuts it (not reached with bounded lines)
		}
	}
}

func readSettings(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT key, value FROM vendor_settings
		WHERE key IN ('timezone', 'last_summary_at')`)
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

// summaryDue decides from the raw last_summary_at value whether a summary is due at now. It is
// the one place for that rule, shared by WeeklySummary and PreviewRun so a dry run can never
// disagree with a real run. haveLast reports a usable mark (last is then the start of the next
// period): a missing or unreadable mark, or one more than futureSkew after now, counts as never.
func summaryDue(raw string, now time.Time) (due bool, last time.Time, haveLast bool) {
	last, haveLast = parseLastSummary(raw)
	if haveLast && last.After(now.Add(futureSkew)) {
		haveLast = false
	}
	if haveLast && last.After(now.Add(-summaryEvery)) {
		return false, last, true
	}
	return true, last, haveLast
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

// issuedIn lists the licenses whose license.issue audit row falls in [start, end). The time and
// the signer come from that audit row (written by the database at insert time with the acting
// login), not from issued_at and signed_by, which the inserting client can set to anything: a
// back-dated or mis-attributed license is still listed, at the time and under the login that
// really issued it.
func issuedIn(ctx context.Context, tx pgx.Tx, start, end time.Time) ([]issuedRow, error) {
	// All rows, not the first 20: the unusual rules look at every license of the period.
	rows, err := tx.Query(ctx, `SELECT l.license_id, c.name, a.actor, l.targets, a.at
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN audit a ON a.action = 'license.issue' AND a.subject = l.license_id
		WHERE a.at >= $1 AND a.at < $2
		ORDER BY a.at, l.license_id`, start, end)
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

// licensesWithoutIssueAudit counts licenses that have no license.issue audit row: the trigger that
// writes it always fires on insert, so a missing row means the triggers were off or the row is gone.
// It looks at every license, not the period: issued_at is set by the inserting client and could put
// such a license outside any period. Only license_id, action and subject are read (the notifier's
// column grants).
func licensesWithoutIssueAudit(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM licenses l
		WHERE NOT EXISTS (SELECT 1 FROM audit a WHERE a.action = 'license.issue' AND a.subject = l.license_id)`).Scan(&n); err != nil {
		return 0, fmt.Errorf("notify: summary: licenses without audit: %w", err)
	}
	return n, nil
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

// endingSoon uses the same rule as the reminders: live (liveLicense), ends in (now, now+90d].
func endingSoon(ctx context.Context, tx pgx.Tx, now time.Time, loc *time.Location) (section, error) {
	s := section{title: "Ending in the next 90 days", empty: "None."}
	rows, err := tx.Query(ctx, `SELECT l.license_id, c.name, l.valid_until, count(*) OVER ()
		FROM licenses l JOIN customers c ON c.id = l.customer_id
		WHERE `+liveLicense+` AND l.valid_until > $1 AND l.valid_until <= $2
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

// unusualLines applies ruling 4 to the licenses of the period. busy lists the signers above the
// daily limit (by day, then signer), night the licenses issued at night (in issue order).
func unusualLines(issued []issuedRow, loc *time.Location) (busy, night []string) {
	type signerDay struct{ signer, day string }
	perDay := map[signerDay]int{}
	for _, r := range issued {
		local := r.issuedAt.In(loc)
		if h := local.Hour(); h >= nightStartHour || h < nightEndHour {
			night = append(night, fmt.Sprintf("Issued at night: %s | %s | signed by %s | %s",
				clean(r.licenseID, maxIDRunes), clean(r.customer, maxNameRunes),
				clean(r.signer, maxNameRunes), local.Format(localTimeLayout)))
		}
		perDay[signerDay{r.signer, local.Format("2006-01-02")}]++
	}
	var days []signerDay
	for k, n := range perDay {
		if n > maxPerSignerDay {
			days = append(days, k)
		}
	}
	slices.SortFunc(days, func(a, b signerDay) int {
		if c := strings.Compare(a.day, b.day); c != 0 {
			return c
		}
		return strings.Compare(a.signer, b.signer)
	})
	for _, k := range days {
		busy = append(busy, fmt.Sprintf("%s issued %d licenses on %s (more than %d in one day)",
			clean(k.signer, maxNameRunes), perDay[k], k.day, maxPerSignerDay))
	}
	return busy, night
}

// writeSection writes the section header, its note, at most keepLimit of its keep lines and at
// most limit of its other lines; the rest is counted in a "... and N more" line.
func writeSection(b *strings.Builder, s section, keepLimit, limit int) {
	fmt.Fprintf(b, "== %s (%d) ==\n", s.title, s.count)
	if s.note != "" {
		b.WriteString(s.note + "\n")
	}
	if s.count == 0 {
		b.WriteString(s.empty + "\n")
	}
	shown := 0
	for _, l := range s.keep[:min(len(s.keep), keepLimit)] {
		b.WriteString(l + "\n")
		shown++
	}
	for _, l := range s.lines[:min(len(s.lines), limit)] {
		b.WriteString(l + "\n")
		shown++
	}
	if more := s.count - shown; more > 0 {
		fmt.Fprintf(b, "... and %d more\n", more)
	}
	b.WriteString("\n")
}
