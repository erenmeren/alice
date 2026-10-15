//go:build integration

package notify_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

// summaryNow is 12:00 in Istanbul (UTC+3 all year), a Thursday.
var summaryNow = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

// ist returns the instant of a wall-clock time in Istanbul.
func ist(t *testing.T, y int, m time.Month, d, hh, mm, ss int) time.Time {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Istanbul")
	require.NoError(t, err)
	return time.Date(y, m, d, hh, mm, ss, 0, loc)
}

// seedIssued inserts a license issued at issuedAt by signer (seedLicense cannot set either, and
// licenses cannot be updated afterwards). It ends a year later, outside the 90-day section.
func seedIssued(t *testing.T, d *vpgtest.DB, id, customer, signer string, issuedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	var cid, rid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO customers (name, contact) VALUES ($1, 'buyer@customer.example')
		ON CONFLICT ((lower(name))) DO UPDATE SET contact = customers.contact RETURNING id`, customer).Scan(&cid))
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, status, requested_by)
		VALUES ($1, $2, 7, 'signed', 'web:ayse') RETURNING id`, cid, installation).Scan(&rid))
	_, err := d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256, signed_by)
		VALUES ($1, $2, $3, $4, 'vk-1', $5, $5, $6, 7, '\xdeadbeef', 'x', $7)`,
		id, rid, cid, installation, issuedAt, issuedAt.Add(365*day), signer)
	require.NoError(t, err)
}

// seedOpenRequest inserts an open request made at requestedAt.
func seedOpenRequest(t *testing.T, d *vpgtest.DB, customer, requestedBy string, requestedAt time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	var cid, rid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO customers (name) VALUES ($1)
		ON CONFLICT ((lower(name))) DO UPDATE SET contact = customers.contact RETURNING id`, customer).Scan(&cid))
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, requested_by, requested_at)
		VALUES ($1, $2, 3, $3, $4) RETURNING id`, cid, installation, requestedBy, requestedAt).Scan(&rid))
	return rid
}

func setSetting(t *testing.T, d *vpgtest.DB, key, value string) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO vendor_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	require.NoError(t, err)
}

func lastSummaryAt(t *testing.T, d *vpgtest.DB) string {
	t.Helper()
	var v string
	err := d.Owner.QueryRow(context.Background(), `SELECT coalesce((SELECT value FROM vendor_settings WHERE key = 'last_summary_at'), '')`).Scan(&v)
	require.NoError(t, err)
	return v
}

func summaryMails(t *testing.T, d *vpgtest.DB) []reminderMail {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(),
		`SELECT id, to_addrs, subject, body FROM mail_outbox WHERE kind = 'summary' ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []reminderMail
	for rows.Next() {
		var m reminderMail
		require.NoError(t, rows.Scan(&m.ID, &m.To, &m.Subject, &m.Body))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

// onlySummary runs WeeklySummary expecting it to enqueue, and returns the body of the one summary.
func onlySummary(t *testing.T, d *vpgtest.DB, p *pgxpool.Pool, now time.Time) string {
	t.Helper()
	ok, err := notify.WeeklySummary(context.Background(), p, now)
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryMails(t, d)
	require.Len(t, ms, 1)
	return ms[0].Body
}

// section returns the header and lines of the section whose title starts with title.
func section(t *testing.T, body, title string) (string, []string) {
	t.Helper()
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "== "+title) {
			var out []string
			for _, x := range lines[i+1:] {
				if x == "" {
					break
				}
				out = append(out, x)
			}
			return l, out
		}
	}
	require.Failf(t, "section missing", "%q not in body:\n%s", title, body)
	return "", nil
}

func TestFirstSummaryCoversTheLastSevenDays(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s1_notifier")
	setOwner(t, d, "boss@example.com")
	seedIssued(t, d, "LIC-IN", "Acme Corp", "web:ayse", summaryNow.Add(-7*day))             // first instant of the period
	seedIssued(t, d, "LIC-OUT", "Beta Ltd", "web:ayse", summaryNow.Add(-7*day-time.Second)) // just before it
	seedIssued(t, d, "LIC-LATE", "Gamma", "web:ayse", summaryNow.Add(time.Second))          // after now

	ok, err := notify.WeeklySummary(context.Background(), p, summaryNow)
	require.NoError(t, err)
	assert.True(t, ok)
	ms := summaryMails(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, []string{"boss@example.com"}, ms[0].To)
	assert.Equal(t, "Weekly summary: 1 issued, 0 open requests, 0 unusual", ms[0].Subject)
	head, lines := section(t, ms[0].Body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (1) ==", head)
	require.Len(t, lines, 1)
	assert.Equal(t, "LIC-IN | Acme Corp | 7 targets | signed by web:ayse | 2026-10-08 12:00 +03", lines[0])
	assert.Contains(t, ms[0].Body, "Period: 2026-10-08 12:00 +03 to 2026-10-15 12:00 +03\n")
	assert.Equal(t, "2026-10-15T09:00:00Z", lastSummaryAt(t, d))
}

func TestSecondRunWithinSevenDaysSendsNothing(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s2_notifier")
	// now with a fraction of a second: the period must still end where the stored mark says.
	first := summaryNow.Add(500 * time.Millisecond)
	seedIssued(t, d, "LIC-BEFORE", "Acme Corp", "web:ayse", summaryNow.Add(-time.Hour))
	seedIssued(t, d, "LIC-EDGE", "Acme Corp", "web:ayse", summaryNow.Add(200*time.Millisecond))
	seedIssued(t, d, "LIC-AFTER", "Beta Ltd", "web:ayse", summaryNow.Add(day))

	ok, err := notify.WeeklySummary(ctx, p, first)
	require.NoError(t, err)
	require.True(t, ok)
	for _, at := range []time.Time{first, first.Add(time.Hour), summaryNow.Add(7*day - time.Second)} {
		ok, err = notify.WeeklySummary(ctx, p, at)
		require.NoError(t, err)
		assert.False(t, ok, "at %v", at)
	}
	require.Len(t, summaryMails(t, d), 1)

	ok, err = notify.WeeklySummary(ctx, p, summaryNow.Add(7*day))
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryMails(t, d)
	require.Len(t, ms, 2)
	_, firstLines := section(t, ms[0].Body, "Issued since")
	head, lines := section(t, ms[1].Body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-15 12:00 +03 (2) ==", head, "covers from the last summary")
	require.Len(t, firstLines, 1)
	assert.True(t, strings.HasPrefix(firstLines[0], "LIC-BEFORE |"))
	require.Len(t, lines, 2)
	assert.True(t, strings.HasPrefix(lines[0], "LIC-EDGE |"), "a license in the cut-off second is in exactly one summary")
	assert.True(t, strings.HasPrefix(lines[1], "LIC-AFTER |"))
	assert.Equal(t, "2026-10-22T09:00:00Z", lastSummaryAt(t, d))
}

func TestSummaryListsSectionsInOrderAndCapsLines(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s3_notifier")
	for i := range 30 {
		seedOpenRequest(t, d, fmt.Sprintf("Cust %02d", i), "web:ayse", summaryNow.Add(-time.Duration(40-i)*day))
	}
	seedLicense(t, d, lic{id: "LIC-END", customer: "Ender", validUntil: summaryNow.Add(40*day + time.Hour)})
	seedLicense(t, d, lic{id: "LIC-FAR", customer: "Farther", validUntil: summaryNow.Add(91 * day)})
	seedLicense(t, d, lic{id: "LIC-REV", customer: "Revoked", validUntil: summaryNow.Add(20 * day), revoked: true})

	body := onlySummary(t, d, p, summaryNow)
	var at []int
	for _, h := range []string{"== Issued since ", "== Open requests (", "== Ending in the next 90 days (", "== Failed e-mails (", "== Unusual ("} {
		i := strings.Index(body, h)
		require.GreaterOrEqual(t, i, 0, h)
		at = append(at, i)
	}
	assert.IsIncreasing(t, at, "sections in the order of the brief")

	head, lines := section(t, body, "Open requests")
	assert.Equal(t, "== Open requests (30) ==", head)
	require.Len(t, lines, 21)
	assert.Equal(t, "... and 10 more", lines[20])
	assert.Regexp(t, `^#\d+ \| Cust 00 \| 40 days old \| requested by web:ayse$`, lines[0], "oldest first")
	assert.Regexp(t, `^#\d+ \| Cust 19 \| 21 days old \| requested by web:ayse$`, lines[19])

	head, lines = section(t, body, "Ending in the next 90 days")
	assert.Equal(t, "== Ending in the next 90 days (1) ==", head)
	assert.Equal(t, []string{"LIC-END | Ender | ends 2026-11-24 13:00 +03 | 41 days left"}, lines)

	_, lines = section(t, body, "Issued since")
	assert.Equal(t, []string{"Nothing issued."}, lines)
}

func TestNightIssuanceIsUnusual(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s4_notifier")
	seedIssued(t, d, "LIC-2330", "A", "sig_a", ist(t, 2026, 10, 12, 23, 30, 0))
	seedIssued(t, d, "LIC-0559", "B", "sig_b", ist(t, 2026, 10, 13, 5, 59, 59))
	seedIssued(t, d, "LIC-2200", "C", "sig_c", ist(t, 2026, 10, 13, 22, 0, 0))
	seedIssued(t, d, "LIC-0600", "D", "sig_d", ist(t, 2026, 10, 14, 6, 0, 0))
	seedIssued(t, d, "LIC-2159", "E", "sig_e", ist(t, 2026, 10, 14, 21, 59, 59))

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (3) ==", head)
	assert.Equal(t, []string{
		"Issued at night: LIC-2330 | A | signed by sig_a | 2026-10-12 23:30 +03",
		"Issued at night: LIC-0559 | B | signed by sig_b | 2026-10-13 05:59 +03",
		"Issued at night: LIC-2200 | C | signed by sig_c | 2026-10-13 22:00 +03",
	}, lines)
}

func TestSixthLicenseInADayBySameSignerIsUnusual(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s5_notifier")
	for i := range 6 {
		seedIssued(t, d, fmt.Sprintf("LIC-A%d", i), "Acme", "web:ayse", ist(t, 2026, 10, 13, 9+i, 0, 0))
	}
	for i := range 5 {
		seedIssued(t, d, fmt.Sprintf("LIC-M%d", i), "Beta", "web:mehmet", ist(t, 2026, 10, 13, 9+i, 30, 0))
	}
	// Three on each of two days: per day, not per period.
	for i := range 3 {
		seedIssued(t, d, fmt.Sprintf("LIC-Z%d", i), "Gamma", "web:zeynep", ist(t, 2026, 10, 10, 10+i, 0, 0))
		seedIssued(t, d, fmt.Sprintf("LIC-Y%d", i), "Gamma", "web:zeynep", ist(t, 2026, 10, 11, 10+i, 0, 0))
	}

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (1) ==", head)
	assert.Equal(t, []string{"web:ayse issued 6 licenses on 2026-10-13 (more than 5 in one day)"}, lines)
	head, _ = section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (17) ==", head)
}

func TestQuietWeekStillSends(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s6_notifier")

	ok, err := notify.WeeklySummary(context.Background(), p, summaryNow)
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryMails(t, d)
	require.Len(t, ms, 1)
	assert.Empty(t, ms[0].To, "no owner address yet: the row waits for it")
	assert.Equal(t, "Weekly summary: 0 issued, 0 open requests, 0 unusual", ms[0].Subject)
	want := "Weekly summary of the vendor console.\n\n" +
		"Period: 2026-10-08 12:00 +03 to 2026-10-15 12:00 +03\n" +
		"Time zone: Europe/Istanbul\n\n" +
		"== Issued since 2026-10-08 12:00 +03 (0) ==\nNothing issued.\n\n" +
		"== Open requests (0) ==\nNone.\n\n" +
		"== Ending in the next 90 days (0) ==\nNone.\n\n" +
		"== Failed e-mails (0) ==\nFailures stay listed for 28 days.\nNone.\n\n" +
		"== Unusual (0) ==\nNone.\n\n"
	assert.Equal(t, want, ms[0].Body)
	for _, r := range ms[0].Body {
		require.Less(t, r, rune(128), "a quiet summary is plain ASCII")
	}
}

func TestUnknownTimezoneFallsBackToUTCAndSaysSo(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s7_notifier")
	setSetting(t, d, "timezone", "Mars/Olympus_Mons")
	// 23:30 UTC is night in UTC (and 02:30 in Istanbul, so night there too); 20:00 UTC is 23:00
	// in Istanbul but day in UTC: the rule follows the zone actually used.
	seedIssued(t, d, "LIC-U1", "A", "sig_a", time.Date(2026, 10, 12, 23, 30, 0, 0, time.UTC))
	seedIssued(t, d, "LIC-U2", "B", "sig_b", time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC))

	body := onlySummary(t, d, p, summaryNow)
	assert.Contains(t, body, "Time zone: UTC\n")
	assert.Contains(t, body, "Period: 2026-10-08 09:00 UTC to 2026-10-15 09:00 UTC\n")
	head, lines := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (1) ==", head)
	assert.Equal(t, []string{
		`Time zone "Mars/Olympus_Mons" is unknown; times are shown in UTC.`,
		"Issued at night: LIC-U1 | A | signed by sig_a | 2026-10-12 23:30 UTC",
	}, lines)
}

func TestKnownTimezoneSettingIsUsed(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s7b_notifier")
	setSetting(t, d, "timezone", "UTC")
	seedIssued(t, d, "LIC-K1", "A", "sig_a", time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)) // 23:00 Istanbul, day in UTC

	body := onlySummary(t, d, p, summaryNow)
	assert.Contains(t, body, "Time zone: UTC\n")
	head, lines := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (0) ==", head)
	assert.Equal(t, []string{"None."}, lines, "no fallback note for a valid zone")
}

// insertOutbox inserts an outbox row that gave up at failed (or, with sent set, one that went out).
func insertOutbox(t *testing.T, d *vpgtest.DB, kind, subject, lastErr string, created time.Time, failed, sent *time.Time) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO mail_outbox (kind, to_addrs, subject, body, created_at, attempts, last_error, failed_at, sent_at)
		VALUES ($1, '{boss@example.com}', $2, 'b', $3, 10, $4, $5, $6)`, kind, subject, created, lastErr, failed, sent)
	require.NoError(t, err)
}

func TestFailedMailsAreListed(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s8_notifier")
	longSubject := "License issued: " + strings.Repeat("x", 150)
	longErr := "smtp: 550 mailbox unavailable\r\n" + strings.Repeat("y", 300)
	f1 := summaryNow.Add(-2 * day)
	f20 := summaryNow.Add(-20 * day)
	old := summaryNow.Add(-28*day - time.Second)
	insertOutbox(t, d, "issued", longSubject, longErr, ist(t, 2026, 10, 12, 10, 15, 0), &f1, nil)
	insertOutbox(t, d, "reminder", "Twenty days ago", "smtp: 554", f20, &f20, nil)
	insertOutbox(t, d, "reminder", "License ending in 30 days: Old", "smtp: old", old, &old, nil) // older than 28 days
	insertOutbox(t, d, "reminder", "Sent fine", "", f1, nil, &f1)
	insertOutbox(t, d, "reminder", "Still retrying", "smtp: 451", f1, nil, nil)

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Failed e-mails")
	assert.Equal(t, "== Failed e-mails (2) ==", head)
	wantErr := ("smtp: 550 mailbox unavailable" + strings.Repeat("y", 300))[:80]
	assert.Equal(t, []string{
		"Failures stay listed for 28 days.",
		"issued | 2026-10-12 10:15 +03 | " + longSubject[:80] + " | " + wantErr, // most recent first
		"reminder | 2026-09-25 12:00 +03 | Twenty days ago | smtp: 554",
	}, lines)
}

func TestFailureStaysListedInLaterSummaries(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s8b_notifier")
	f := summaryNow.Add(-6 * day)
	insertOutbox(t, d, "issued", "Failed once", "smtp: 550", f, &f, nil)

	for i, at := range []time.Time{summaryNow, summaryNow.Add(7 * day), summaryNow.Add(14 * day), summaryNow.Add(21 * day)} {
		ok, err := notify.WeeklySummary(ctx, p, at)
		require.NoError(t, err)
		require.True(t, ok)
		ms := summaryMails(t, d)
		require.Len(t, ms, i+1)
		head, _ := section(t, ms[i].Body, "Failed e-mails")
		assert.Equal(t, "== Failed e-mails (1) ==", head, "summary %d (failure %v old)", i, at.Sub(f))
	}
	ok, err := notify.WeeklySummary(ctx, p, summaryNow.Add(28*day))
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryMails(t, d)
	head, _ := section(t, ms[len(ms)-1].Body, "Failed e-mails")
	assert.Equal(t, "== Failed e-mails (0) ==", head, "34 days old: no longer listed")
}

// SendPending stamps failed_at with its own now while holding the row, so a failure can carry a
// time after the summary's now; it must be listed, not fall between two summary periods.
func TestFailureStampedAfterNowIsListed(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s8c_notifier")
	late := summaryNow.Add(30 * time.Second)
	insertOutbox(t, d, "reminder", "Failed during the summary", "smtp: 421", summaryNow.Add(-time.Hour), &late, nil)

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Failed e-mails")
	assert.Equal(t, "== Failed e-mails (1) ==", head)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[1], "Failed during the summary")
}

func TestFailedMailsAreCappedAtTwentyLines(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s8d_notifier")
	for i := range 25 {
		f := summaryNow.Add(-time.Duration(i+1) * time.Hour)
		insertOutbox(t, d, "reminder", fmt.Sprintf("Failed %02d", i), "smtp: 550", f, &f, nil)
	}

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Failed e-mails")
	assert.Equal(t, "== Failed e-mails (25) ==", head)
	require.Len(t, lines, 22) // note + 20 lines + "and 5 more"
	assert.Contains(t, lines[1], "Failed 00")
	assert.Equal(t, "... and 5 more", lines[21])
}

func TestWaitingSummaryGetsTheOwnerOnceSet(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s13_notifier")
	ok, err := notify.WeeklySummary(ctx, p, summaryNow)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, summaryMails(t, d)[0].To)

	setOwner(t, d, "boss@example.com")
	_, err = notify.ResolveEmptyRecipients(ctx, p)
	require.NoError(t, err)
	ms := summaryMails(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, []string{"boss@example.com"}, ms[0].To)
}

func TestFutureLastSummaryCountsAsNever(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s14_notifier")
	setSetting(t, d, "last_summary_at", "2027-01-01T00:00:00Z")

	body := onlySummary(t, d, p, summaryNow)
	head, _ := section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (0) ==", head, "a fresh 7-day summary")
	assert.Equal(t, "2026-10-15T09:00:00Z", lastSummaryAt(t, d))

	// A mark a few seconds ahead is clock skew between two concurrent runs, not a broken value:
	// the second run must not send another summary.
	ok, err := notify.WeeklySummary(ctx, p, summaryNow.Add(-5*time.Second))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Len(t, summaryMails(t, d), 1)
}

// Europe/London changes between BST (UTC+1) and GMT (UTC+0); the night rule follows local time.
func TestNightRuleFollowsDaylightSavingTime(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s15_notifier")
	setSetting(t, d, "timezone", "Europe/London")
	setSetting(t, d, "last_summary_at", "2026-07-01T00:00:00Z")
	seedIssued(t, d, "LIC-BST-2330", "A", "sig_a", time.Date(2026, 7, 10, 22, 30, 0, 0, time.UTC))
	seedIssued(t, d, "LIC-BST-2130", "B", "sig_b", time.Date(2026, 7, 11, 20, 30, 0, 0, time.UTC))
	seedIssued(t, d, "LIC-GMT-2330", "C", "sig_c", time.Date(2026, 11, 2, 23, 30, 0, 0, time.UTC))

	body := onlySummary(t, d, p, time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC))
	assert.Contains(t, body, "Time zone: Europe/London\n")
	head, lines := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (2) ==", head)
	assert.Equal(t, []string{
		"Issued at night: LIC-BST-2330 | A | signed by sig_a | 2026-07-10 23:30 BST",
		"Issued at night: LIC-GMT-2330 | C | signed by sig_c | 2026-11-02 23:30 GMT",
	}, lines)
}

func TestSummaryLinesAreCleanAndLeakNothing(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s9_notifier")
	long := strings.Repeat("ş", 100)
	seedIssued(t, d, "LIC-EVIL", "Evil\r\nBcc: x@example.com\x1b[2J\u202e", "web:"+long, summaryNow.Add(-day))
	seedOpenRequest(t, d, long, "web:a\nb", summaryNow.Add(-3*day))

	body := onlySummary(t, d, p, summaryNow)
	_, lines := section(t, body, "Issued since")
	require.Len(t, lines, 1)
	assert.Equal(t, "LIC-EVIL | EvilBcc: x@example.com[2J | 7 targets | signed by web:"+strings.Repeat("ş", 56)+" | 2026-10-14 12:00 +03", lines[0])
	_, lines = section(t, body, "Open requests")
	require.Len(t, lines, 1)
	assert.Regexp(t, `^#\d+ \| `+strings.Repeat("ş", 60)+` \| 3 days old \| requested by web:ab$`, lines[0])

	assert.NotContains(t, body, installation[:9])
	assert.NotContains(t, body, "buyer@customer.example")
	assert.NotContains(t, body, "deadbeef")
	assert.NotContains(t, body, "\r")
	assert.NotContains(t, body, "\x1b")
}

// A failing outbox insert must leave last_summary_at unchanged, and a failing mark must leave no
// summary row. Both failures are injected through the owner pool with schema objects that only
// this test's database has, so the production code needs no test hook: a CHECK that refuses
// summary rows (NOT VALID so it ignores existing rows), and a trigger that refuses the mark.
func TestSummaryAndMarkAreOneTransaction(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s10_notifier")
	setSetting(t, d, "last_summary_at", "2026-10-01T09:00:00Z")

	_, err := d.Owner.Exec(ctx, `ALTER TABLE mail_outbox ADD CONSTRAINT test_no_summary CHECK (kind <> 'summary') NOT VALID`)
	require.NoError(t, err)
	ok, err := notify.WeeklySummary(ctx, p, summaryNow)
	require.Error(t, err)
	assert.False(t, ok)
	assert.Equal(t, "2026-10-01T09:00:00Z", lastSummaryAt(t, d), "insert failed: the mark was rolled back")
	assert.Empty(t, summaryMails(t, d))

	_, err = d.Owner.Exec(ctx, `ALTER TABLE mail_outbox DROP CONSTRAINT test_no_summary`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `CREATE FUNCTION test_refuse_mark() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'mark refused'; END $$`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `CREATE TRIGGER test_refuse_mark BEFORE UPDATE ON vendor_settings
		FOR EACH ROW WHEN (NEW.key = 'last_summary_at') EXECUTE FUNCTION test_refuse_mark()`)
	require.NoError(t, err)
	ok, err = notify.WeeklySummary(ctx, p, summaryNow)
	require.Error(t, err)
	assert.False(t, ok)
	assert.Empty(t, summaryMails(t, d), "mark failed: no summary row")
	assert.Equal(t, "2026-10-01T09:00:00Z", lastSummaryAt(t, d))

	_, err = d.Owner.Exec(ctx, `DROP TRIGGER test_refuse_mark ON vendor_settings`)
	require.NoError(t, err)
	body := onlySummary(t, d, p, summaryNow)
	head, _ := section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-01 12:00 +03 (0) ==", head, "covers from the unchanged mark")
	assert.Equal(t, "2026-10-15T09:00:00Z", lastSummaryAt(t, d))
}

func TestUnreadableLastSummaryCountsAsNever(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s11_notifier")
	setSetting(t, d, "last_summary_at", "yesterday")

	body := onlySummary(t, d, p, summaryNow)
	head, _ := section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (0) ==", head)
}

func TestTwoConcurrentSummariesSendOne(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := notifier(t, d, "t_s12_notifier_a")
	p2 := notifier(t, d, "t_s12_notifier_b")

	const rounds = 5
	for round := range rounds {
		at := summaryNow.Add(time.Duration(round) * 7 * day)
		var wg sync.WaitGroup
		oks := make([]bool, 4)
		errs := make([]error, 4)
		for i := range 4 {
			p := p1
			if i%2 == 1 {
				p = p2
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				oks[i], errs[i] = notify.WeeklySummary(ctx, p, at)
			}()
		}
		wg.Wait()
		sent := 0
		for i := range 4 {
			require.NoError(t, errs[i])
			if oks[i] {
				sent++
			}
		}
		assert.Equal(t, 1, sent, "round %d", round)
	}
	assert.Len(t, summaryMails(t, d), rounds)
}
