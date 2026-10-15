//go:build integration

package notify_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/audit"
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

// seedIssued inserts a license issued at issuedAt by signer: the license columns and its audit
// row agree. It ends a year later, outside the 90-day section.
func seedIssued(t *testing.T, d *vpgtest.DB, id, customer, signer string, issuedAt time.Time) {
	t.Helper()
	seedIssuedRecorded(t, d, id, customer, signer, issuedAt, signer, issuedAt)
}

// seedIssuedRecorded inserts a license whose audit row says actor issued it at at, while the
// client-writable columns say signed_by and issued_at. The audit row is written by the trigger at
// the real clock time; the test rewrites it with triggers off (the owner pool is a superuser), so
// the hash chain of this test database no longer verifies.
func seedIssuedRecorded(t *testing.T, d *vpgtest.DB, id, customer, actor string, at time.Time, signedBy string, issuedAt time.Time) {
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
		id, rid, cid, installation, issuedAt, issuedAt.Add(365*day), signedBy)
	require.NoError(t, err)
	tx, err := d.Owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET LOCAL session_replication_role = replica`)
	require.NoError(t, err)
	tag, err := tx.Exec(ctx, `UPDATE audit SET at = $2, actor = $3 WHERE action = 'license.issue' AND subject = $1`, id, at, actor)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
	require.NoError(t, tx.Commit(ctx))
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

// summaryNotices returns the weekly summary notifications, oldest first.
func summaryNotices(t *testing.T, d *vpgtest.DB) []notice {
	t.Helper()
	return notices(t, d, "summary.weekly")
}

// alertNotices returns the unusual-activity notifications, oldest first.
func alertNotices(t *testing.T, d *vpgtest.DB) []notice {
	t.Helper()
	return notices(t, d, "activity.unusual")
}

// onlySummary runs WeeklySummary expecting it to create a notice, and returns the body of the one summary.
func onlySummary(t *testing.T, d *vpgtest.DB, p *pgxpool.Pool, now time.Time) string {
	t.Helper()
	ok, err := notify.WeeklySummary(context.Background(), p, now)
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryNotices(t, d)
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
	seedIssued(t, d, "LIC-IN", "Acme Corp", "web:ayse", summaryNow.Add(-7*day))             // first instant of the period
	seedIssued(t, d, "LIC-OUT", "Beta Ltd", "web:ayse", summaryNow.Add(-7*day-time.Second)) // just before it
	seedIssued(t, d, "LIC-LATE", "Gamma", "web:ayse", summaryNow.Add(time.Second))          // after now

	ok, err := notify.WeeklySummary(context.Background(), p, summaryNow)
	require.NoError(t, err)
	assert.True(t, ok)
	ms := summaryNotices(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, "owner", ms[0].Audience)
	assert.Nil(t, ms[0].Target)
	assert.Equal(t, "info", ms[0].Severity)
	assert.Equal(t, "summary:2026-10-15", ms[0].DedupeKey, "the period end date in UTC")
	assert.Equal(t, "Weekly summary: 1 issued, 0 open requests, 0 unusual", ms[0].Title)
	head, lines := section(t, ms[0].Body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (1) ==", head)
	require.Len(t, lines, 1)
	assert.Equal(t, "LIC-IN | Acme Corp | 7 targets | signed by web:ayse | 2026-10-08 12:00 +03", lines[0])
	assert.Contains(t, ms[0].Body, "Period: 2026-10-08 12:00 +03 to 2026-10-15 12:00 +03\n")
	assert.Equal(t, "2026-10-15T09:00:00Z", lastSummaryAt(t, d))
}

func TestSecondRunWithinSevenDaysCreatesNothing(t *testing.T) {
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
	require.Len(t, summaryNotices(t, d), 1)

	ok, err = notify.WeeklySummary(ctx, p, summaryNow.Add(7*day))
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryNotices(t, d)
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
	for _, h := range []string{"== Issued since ", "== Open requests (", "== Ending in the next 90 days (", "== Unusual ("} {
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

func TestQuietWeekStillCreatesASummary(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s6_notifier")

	ok, err := notify.WeeklySummary(context.Background(), p, summaryNow)
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryNotices(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, "Weekly summary: 0 issued, 0 open requests, 0 unusual", ms[0].Title)
	want := "Weekly summary of the vendor console.\n\n" +
		"Period: 2026-10-08 12:00 +03 to 2026-10-15 12:00 +03\n" +
		"Time zone: Europe/Istanbul\n\n" +
		"== Issued since 2026-10-08 12:00 +03 (0) ==\nNothing issued.\n\n" +
		"== Open requests (0) ==\nNone.\n\n" +
		"== Ending in the next 90 days (0) ==\nNone.\n\n" +
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
	assert.Len(t, summaryNotices(t, d), 1)
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

// A failing notice insert must leave last_summary_at unchanged, and a failing mark must leave no
// summary row. Both failures are injected through the owner pool with schema objects that only
// this test's database has, so the production code needs no test hook: a CHECK that refuses
// summary rows (NOT VALID so it ignores existing rows), and a trigger that refuses the mark.
func TestSummaryAndMarkAreOneTransaction(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s10_notifier")
	setSetting(t, d, "last_summary_at", "2026-10-01T09:00:00Z")

	_, err := d.Owner.Exec(ctx, `ALTER TABLE notifications ADD CONSTRAINT test_no_summary CHECK (kind <> 'summary.weekly') NOT VALID`)
	require.NoError(t, err)
	ok, err := notify.WeeklySummary(ctx, p, summaryNow)
	require.Error(t, err)
	assert.False(t, ok)
	assert.Equal(t, "2026-10-01T09:00:00Z", lastSummaryAt(t, d), "insert failed: the mark was rolled back")
	assert.Empty(t, summaryNotices(t, d))

	_, err = d.Owner.Exec(ctx, `ALTER TABLE notifications DROP CONSTRAINT test_no_summary`)
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
	assert.Empty(t, summaryNotices(t, d), "mark failed: no summary row")
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

func TestTwoConcurrentSummariesCreateOne(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := notifier(t, d, "t_s12_notifier_a")
	p2 := notifier(t, d, "t_s12_notifier_b")

	const rounds = 5
	for round := range rounds {
		at := summaryNow.Add(time.Duration(round) * 7 * day)
		// 02:00 in Istanbul three days before: every week has unusual activity, so its alert
		// notice must be created once too.
		seedIssued(t, d, fmt.Sprintf("LIC-NIGHT%d", round), "Night", "sig_n", at.Add(-3*day+14*time.Hour))
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
	assert.Len(t, summaryNotices(t, d), rounds)
	assert.Len(t, alertNotices(t, d), rounds)
}

// The period, the order, the unusual rules and the signer come from the audit row, which no
// client can write; issued_at and signed_by are client-supplied columns.
func TestIssuedAndUnusualUseTheAuditTimeAndActor(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s20_notifier")
	// Back-dated a month and with a forged signer, but really issued at 23:30 this week by t_real.
	seedIssuedRecorded(t, d, "LIC-BACK", "Backdate", "t_real", ist(t, 2026, 10, 13, 23, 30, 0),
		"web:boss", summaryNow.Add(-30*day))
	// Claims to be from this week, really issued before the period.
	seedIssuedRecorded(t, d, "LIC-OLDREAL", "Old Real", "t_real", summaryNow.Add(-8*day),
		"t_real", summaryNow.Add(-day))
	// Six in one day by one real login, spread over six recorded signers and back-dated.
	for i := range 6 {
		seedIssuedRecorded(t, d, fmt.Sprintf("LIC-B%d", i), "Busy", "t_busy", ist(t, 2026, 10, 14, 9+i, 0, 0),
			fmt.Sprintf("web:alias%d", i), summaryNow.Add(-time.Duration(20+i)*day))
	}

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (7) ==", head)
	require.Len(t, lines, 7)
	assert.Equal(t, "LIC-BACK | Backdate | 7 targets | signed by t_real | 2026-10-13 23:30 +03", lines[0])
	assert.Equal(t, "LIC-B0 | Busy | 7 targets | signed by t_busy | 2026-10-14 09:00 +03", lines[1])
	assert.NotContains(t, body, "LIC-OLDREAL")
	assert.NotContains(t, body, "web:boss")
	assert.NotContains(t, body, "web:alias")

	head, lines = section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (2) ==", head)
	assert.Equal(t, []string{
		"Issued at night: LIC-BACK | Backdate | signed by t_real | 2026-10-13 23:30 +03",
		"t_busy issued 6 licenses on 2026-10-14 (more than 5 in one day)",
	}, lines)
}

// A renewal (a later license for the same customer and installation) ends the old license's place
// in the ending-soon list, even when it does not name the old one in replaces.
func TestRenewedLicenseIsNotListedAsEnding(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s21_notifier")
	seedLicense(t, d, lic{id: "LIC-OLD", customer: "Renew Co", validUntil: summaryNow.Add(20 * day)})
	seedLicense(t, d, lic{id: "LIC-NEW", customer: "Renew Co", validUntil: summaryNow.Add(80 * day)})
	seedLicense(t, d, lic{id: "LIC-SOLO", customer: "Solo", validUntil: summaryNow.Add(30 * day)})

	body := onlySummary(t, d, p, summaryNow)
	head, lines := section(t, body, "Ending in the next 90 days")
	assert.Equal(t, "== Ending in the next 90 days (2) ==", head)
	require.Len(t, lines, 2)
	assert.True(t, strings.HasPrefix(lines[0], "LIC-SOLO |"), lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "LIC-NEW |"), lines[1])
}

// A license without its license.issue audit row was inserted with the triggers off (or the row was
// removed); that is reported whatever its client-set issued_at says.
func TestLicenseWithoutIssueAuditRowIsUnusual(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_s22_notifier")
	seedIssued(t, d, "LIC-NORMAL", "Normal", "web:ayse", summaryNow.Add(-2*day))
	var cid, rid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO customers (name) VALUES ('Hidden') RETURNING id`).Scan(&cid))
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, status, requested_by)
		VALUES ($1, $2, 7, 'signed', 'web:ayse') RETURNING id`, cid, installation).Scan(&rid))
	tx, err := d.Owner.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET LOCAL session_replication_role = replica`)
	require.NoError(t, err)
	// Back-dated years before any period: the check must not filter by issued_at.
	_, err = tx.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-HIDDEN', $1, $2, $3, 'vk-1',
		'2020-01-01', '2020-01-01', '2030-01-01', 7, '\xdeadbeef', 'x')`, rid, cid, installation)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	ok, err := notify.WeeklySummary(ctx, p, summaryNow)
	require.NoError(t, err)
	require.True(t, ok)
	ms := summaryNotices(t, d)
	require.Len(t, ms, 1)
	head, lines := section(t, ms[0].Body, "Unusual")
	assert.Equal(t, "== Unusual (1) ==", head)
	assert.Equal(t, []string{"1 license(s) have no issue audit row (possible tampering or disabled triggers)"}, lines)
	assert.Equal(t, "Weekly summary: 1 issued, 0 open requests, 1 unusual", ms[0].Title)
	assert.NotContains(t, ms[0].Body, "LIC-HIDDEN", "only the count, from the notifier's column grants")
}

func TestSummaryEndsWithTheAuditHead(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_head_notifier")
	seedIssued(t, d, "LIC-HEAD", "Head Co", "alice", summaryNow.Add(-48*time.Hour))
	var seq int64
	var hash string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash))

	body := onlySummary(t, d, p, summaryNow)
	assert.True(t, strings.HasSuffix(body, fmt.Sprintf("\nAudit head: %d:%s\n", seq, hash)), body)
	assert.Equal(t, 1, strings.Count(body, "Audit head:"))
}

func TestSummaryHeadLineVerifiesAfterLaterRows(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_compose_notifier")
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_compose_sales")
	_, err := sales.Exec(ctx, `INSERT INTO customers (name) VALUES ('Compose Co')`)
	require.NoError(t, err)

	body := onlySummary(t, d, p, summaryNow)
	var line string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "Audit head:") {
			line = l
		}
	}
	require.NotEmpty(t, line, body)

	_, err = audit.Append(ctx, d.Owner, "test.later", "x", nil)
	require.NoError(t, err)

	h, err := audit.ParseHead(strings.TrimSpace(strings.TrimPrefix(line, "Audit head:")))
	require.NoError(t, err, line)
	require.NoError(t, audit.VerifyHead(ctx, d.Owner, h))
}

func TestSummaryHasNoHeadLineOnAnEmptyChain(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_nohead_notifier")
	body := onlySummary(t, d, p, summaryNow)
	assert.NotContains(t, body, "Audit head")
}

func TestUnusualActivityGetsAnAlertNotice(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s30_notifier")
	seedIssued(t, d, "LIC-2330", "Night Co", "sig_a", ist(t, 2026, 10, 12, 23, 30, 0))
	seedIssued(t, d, "LIC-DAY", "Day Co", "sig_b", ist(t, 2026, 10, 12, 12, 0, 0))

	body := onlySummary(t, d, p, summaryNow)
	_, lines := section(t, body, "Unusual")
	want := "Issued at night: LIC-2330 | Night Co | signed by sig_a | 2026-10-12 23:30 +03"
	assert.Equal(t, []string{want}, lines, "the summary still lists it")

	as := alertNotices(t, d)
	require.Len(t, as, 1)
	a := as[0]
	assert.Equal(t, "alert", a.Severity)
	assert.Equal(t, "owner", a.Audience)
	assert.Nil(t, a.Target)
	assert.Equal(t, "unusual:2026-10-15", a.DedupeKey)
	assert.Equal(t, "Unusual activity: 1 item in the weekly summary", a.Title)
	assert.Contains(t, a.Body, "\n"+want+"\n")
	assert.Contains(t, a.Body, "Period: 2026-10-08 12:00 +03 to 2026-10-15 12:00 +03\n")
	assert.NotContains(t, a.Body, "LIC-DAY")
	assert.NotContains(t, a.Body, installation[:9])
}

func TestQuietWeekHasNoAlertNotice(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s31_notifier")
	seedIssued(t, d, "LIC-DAY", "Day Co", "sig_b", ist(t, 2026, 10, 12, 12, 0, 0))
	// The time-zone fallback note is printed in the Unusual section but is not unusual activity.
	setSetting(t, d, "timezone", "Mars/Olympus_Mons")

	body := onlySummary(t, d, p, summaryNow)
	head, _ := section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (0) ==", head)
	assert.Empty(t, alertNotices(t, d))
}

func TestSummaryBodyFitsTheLimitWithManyRows(t *testing.T) {
	d := vpgtest.New(t)
	p := notifier(t, d, "t_s32_notifier")
	long := strings.Repeat("ş", 80)
	// 200 licenses, all at night by one signer (unusual on both rules), with long names.
	for i := range 200 {
		seedIssued(t, d, fmt.Sprintf("LIC-MANY-%03d-%s", i, strings.Repeat("x", 50)), fmt.Sprintf("%s %03d", long, i),
			"web:"+long, ist(t, 2026, 10, 13, 0, 0, 0).Add(time.Duration(i)*time.Minute))
	}
	for i := range 100 {
		seedOpenRequest(t, d, fmt.Sprintf("%s R%03d", long, i), "web:"+long, summaryNow.Add(-time.Duration(i+1)*time.Hour))
	}

	// The head is read before the run: the mark itself appends an audit row after it.
	var seq int64
	var hash string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash))

	body := onlySummary(t, d, p, summaryNow)
	assert.LessOrEqual(t, utf8.RuneCountInString(body), 4000)
	assert.NotContains(t, body, "(truncated)", "budgeted, not cut")
	head, lines := section(t, body, "Issued since")
	assert.Equal(t, "== Issued since 2026-10-08 12:00 +03 (200) ==", head)
	require.NotEmpty(t, lines)
	assert.Regexp(t, `^\.\.\. and \d+ more$`, lines[len(lines)-1])
	head, lines = section(t, body, "Open requests")
	assert.Equal(t, "== Open requests (100) ==", head)
	assert.Regexp(t, `^\.\.\. and \d+ more$`, lines[len(lines)-1])
	head, lines = section(t, body, "Unusual")
	assert.Equal(t, "== Unusual (201) ==", head)
	assert.Regexp(t, `^\.\.\. and \d+ more$`, lines[len(lines)-1])
	assert.True(t, strings.HasSuffix(body, fmt.Sprintf("\nAudit head: %d:%s\n", seq, hash)), "ends with the head line")

	as := alertNotices(t, d)
	require.Len(t, as, 1)
	assert.LessOrEqual(t, utf8.RuneCountInString(as[0].Body), 4000)
	assert.Equal(t, "Unusual activity: 201 items in the weekly summary", as[0].Title)
}
