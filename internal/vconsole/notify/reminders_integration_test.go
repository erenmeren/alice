//go:build integration

package notify_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

const (
	day          = 24 * time.Hour
	installation = "inst-0123456789abcdef0123"
)

// lic describes one license seeded through the owner pool (a superuser, so requested_by can be
// set to anything and the request's row-level security does not apply).
type lic struct {
	id, customer, requestedBy string
	validUntil                time.Time
	replaces                  string
	revoked                   bool
}

func seedLicense(t *testing.T, d *vpgtest.DB, l lic) {
	t.Helper()
	ctx := context.Background()
	if l.requestedBy == "" {
		l.requestedBy = "t_sales_login"
	}
	var cid, rid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO customers (name) VALUES ($1)
		ON CONFLICT ((lower(name))) DO UPDATE SET contact = customers.contact RETURNING id`, l.customer).Scan(&cid))
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, status, requested_by)
		VALUES ($1, $2, 7, 'signed', $3) RETURNING id`, cid, installation, l.requestedBy).Scan(&rid))
	var revoked *time.Time
	if l.revoked {
		r := l.validUntil.Add(-200 * day)
		revoked = &r
	}
	_, err := d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, replaces, file, file_sha256, revoked_at)
		VALUES ($1, $2, $3, $4, 'vk-1', $5, $5, $6, 7, $7, '\xdeadbeef', 'x', $8)`,
		l.id, rid, cid, installation, l.validUntil.Add(-365*day), l.validUntil, l.replaces, revoked)
	require.NoError(t, err)
}

// addWebUser creates a web user with the role sales or owner.
func addWebUser(t *testing.T, d *vpgtest.DB, name, role string) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO web_users (name, role) VALUES ($1, $2)`, name, role)
	require.NoError(t, err)
}

// reminderNotices returns the reminder notifications, oldest first.
func reminderNotices(t *testing.T, d *vpgtest.DB) []notice {
	t.Helper()
	return notices(t, d, "license.ending")
}

// ownerReminders returns the reminder notifications for the owner audience only.
func ownerReminders(t *testing.T, d *vpgtest.DB) []notice {
	t.Helper()
	var out []notice
	for _, n := range reminderNotices(t, d) {
		if n.Audience == "owner" {
			out = append(out, n)
		}
	}
	return out
}

func reminderRows(t *testing.T, d *vpgtest.DB, licenseID string) []int {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(),
		`SELECT days_before FROM reminders WHERE license_id = $1 ORDER BY days_before`, licenseID)
	require.NoError(t, err)
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		require.NoError(t, rows.Scan(&n))
		out = append(out, n)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestReminderAt90ThenNotAgain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r1_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-R1", customer: "Acme Corp", validUntil: now.Add(89 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Zero(t, n)
	n, err = notify.CreateReminders(ctx, p, now.Add(10*day))
	require.NoError(t, err)
	assert.Zero(t, n, "still inside the 90-day threshold")

	ns := reminderNotices(t, d)
	require.Len(t, ns, 1)
	assert.Equal(t, "License ending in 90 days: Acme Corp", ns[0].Title)
	assert.Equal(t, "owner", ns[0].Audience)
	assert.Nil(t, ns[0].Target)
	assert.Equal(t, "info", ns[0].Severity)
	assert.Equal(t, "LIC-R1", ns[0].Subject)
	assert.Equal(t, "ending:LIC-R1:90", ns[0].DedupeKey)
	assert.Equal(t, []int{90}, reminderRows(t, d, "LIC-R1"))
}

func TestEachThresholdSendsOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r2_notifier")
	now := testNow()
	end := now.Add(89 * day)
	seedLicense(t, d, lic{id: "LIC-R2", customer: "Acme Corp", validUntil: end})

	for _, before := range []int{89, 59, 29} {
		at := end.Add(-time.Duration(before) * day)
		for range 2 {
			_, err := notify.CreateReminders(ctx, p, at)
			require.NoError(t, err)
		}
	}
	ns := reminderNotices(t, d)
	require.Len(t, ns, 3)
	for i, want := range []struct{ days, severity string }{{"90", "info"}, {"60", "info"}, {"30", "warning"}} {
		assert.Equal(t, "License ending in "+want.days+" days: Acme Corp", ns[i].Title)
		assert.Equal(t, want.severity, ns[i].Severity)
		assert.Equal(t, "ending:LIC-R2:"+want.days, ns[i].DedupeKey)
	}
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-R2"))
}

func TestBoundariesOfTheThresholds(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r2b_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-EXACT90", customer: "A", validUntil: now.Add(90 * day)})
	seedLicense(t, d, lic{id: "LIC-OVER90", customer: "B", validUntil: now.Add(90*day + time.Second)})
	seedLicense(t, d, lic{id: "LIC-EXACT60", customer: "C", validUntil: now.Add(60 * day)})
	seedLicense(t, d, lic{id: "LIC-EXACT30", customer: "D", validUntil: now.Add(30 * day)})
	seedLicense(t, d, lic{id: "LIC-OVER30", customer: "E", validUntil: now.Add(30*day + time.Second)})
	seedLicense(t, d, lic{id: "LIC-UNDER30", customer: "F", validUntil: now.Add(29*day + 23*time.Hour)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, []int{90}, reminderRows(t, d, "LIC-EXACT90"))
	assert.Empty(t, reminderRows(t, d, "LIC-OVER90"))
	assert.Equal(t, []int{60, 90}, reminderRows(t, d, "LIC-EXACT60"))
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-EXACT30"))
	assert.Equal(t, []int{60, 90}, reminderRows(t, d, "LIC-OVER30"))
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-UNDER30"))
	titles := map[string]bool{}
	for _, m := range reminderNotices(t, d) {
		titles[m.Title] = true
	}
	assert.Len(t, titles, 5)
	assert.True(t, titles["License ending in 30 days: D"])
	assert.True(t, titles["License ending in 60 days: E"])
	assert.True(t, titles["License ending in 30 days: F"])
}

func TestLateDiscoveryFiresOnlyTheMostUrgentThreshold(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r3_notifier")
	now := testNow()
	end := now.Add(20 * day)
	seedLicense(t, d, lic{id: "LIC-R3", customer: "Acme Corp", validUntil: end})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-R3"))
	for _, at := range []time.Time{now, now.Add(5 * day), end.Add(-time.Minute)} {
		n, err = notify.CreateReminders(ctx, p, at)
		require.NoError(t, err)
		assert.Zero(t, n)
	}
	ns := reminderNotices(t, d)
	require.Len(t, ns, 1)
	assert.Equal(t, "License ending in 30 days: Acme Corp", ns[0].Title)
	assert.Contains(t, ns[0].Body, "Days left: 20\n")
}

func TestRevokedAndReplacedLicensesGetNoReminder(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r4_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-REVOKED", customer: "A", validUntil: now.Add(25 * day), revoked: true})
	seedLicense(t, d, lic{id: "LIC-OLD", customer: "B", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-NEW", customer: "B", validUntil: now.Add(365 * day), replaces: "LIC-OLD"})
	seedLicense(t, d, lic{id: "LIC-LIVE", customer: "C", validUntil: now.Add(25 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 1)
	assert.Contains(t, ns[0].Body, "LIC-LIVE")
	assert.Empty(t, reminderRows(t, d, "LIC-REVOKED"))
	assert.Empty(t, reminderRows(t, d, "LIC-OLD"))
	assert.Empty(t, reminderRows(t, d, "LIC-NEW"))
}

func TestEndedLicensesGetNoReminder(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r5_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-ENDED", customer: "A", validUntil: now.Add(-time.Hour)})
	seedLicense(t, d, lic{id: "LIC-ENDS-NOW", customer: "B", validUntil: now})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Empty(t, reminderNotices(t, d))
	assert.Empty(t, reminderRows(t, d, "LIC-ENDED"))
	assert.Empty(t, reminderRows(t, d, "LIC-ENDS-NOW"))
}

// The owner is told about every reminder; the requester only when they are an enabled web user,
// matched case-insensitively and named as stored.
func TestRequesterNoticeOnlyForEnabledWebUsers(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r6_notifier")
	now := testNow()
	addWebUser(t, d, "Ayse", "sales")
	addWebUser(t, d, "mehmet", "sales")
	_, err := d.Owner.Exec(ctx, `UPDATE web_users SET disabled_at = now() WHERE name = 'mehmet'`)
	require.NoError(t, err)
	seedLicense(t, d, lic{id: "LIC-WEB", customer: "A", requestedBy: "web:ayse", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-DB", customer: "B", requestedBy: "t_sales_login", validUntil: now.Add(26 * day)})
	seedLicense(t, d, lic{id: "LIC-GONE", customer: "C", requestedBy: "web:nobody", validUntil: now.Add(27 * day)})
	seedLicense(t, d, lic{id: "LIC-DISABLED", customer: "D", requestedBy: "web:mehmet", validUntil: now.Add(28 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 4, n, "reminders, not notifications")
	owner := ownerReminders(t, d)
	require.Len(t, owner, 4, "the owner is told even when the requester has no web account")
	assert.Contains(t, owner[0].Body, "Requested by: web:ayse\n")
	assert.Contains(t, owner[1].Body, "Requested by: t_sales_login\n")

	ns := reminderNotices(t, d)
	require.Len(t, ns, 5)
	var user []notice
	for _, x := range ns {
		if x.Audience == "user" {
			user = append(user, x)
		}
	}
	require.Len(t, user, 1)
	require.NotNil(t, user[0].Target)
	assert.Equal(t, "Ayse", *user[0].Target, "the name as stored")
	assert.Equal(t, "ending:LIC-WEB:30:Ayse", user[0].DedupeKey)
	assert.Equal(t, owner[0].Title, user[0].Title)
	assert.Equal(t, owner[0].Body, user[0].Body)
	assert.Equal(t, "warning", user[0].Severity)
}

// An owner-role web user already sees the owner notice; a user notice would be a duplicate.
func TestReminderForAnOwnerRoleRequesterIsNotDuplicated(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r7_notifier")
	now := testNow()
	addWebUser(t, d, "Boss", "owner")
	addWebUser(t, d, "ayse", "sales")
	seedLicense(t, d, lic{id: "LIC-B", customer: "B", requestedBy: "web:boss", validUntil: now.Add(26 * day)})
	seedLicense(t, d, lic{id: "LIC-A", customer: "A", requestedBy: "web:ayse", validUntil: now.Add(27 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 3)
	var keys []string
	for _, x := range ns {
		keys = append(keys, x.DedupeKey)
	}
	assert.ElementsMatch(t, []string{"ending:LIC-B:30", "ending:LIC-A:30", "ending:LIC-A:30:ayse"}, keys)
}

// A renewal is a later license for the same customer and installation; it need not name the old
// one in replaces (a renewal requested from scratch does not). The old one then gets no reminder.
func TestRenewedLicenseGetsNoReminderButTheNewOneDoes(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r16_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-OLD", customer: "Renew Co", validUntil: now.Add(20 * day)})
	seedLicense(t, d, lic{id: "LIC-NEW", customer: "Renew Co", validUntil: now.Add(80 * day)})
	// A later license for the same customer that is revoked does not count as a renewal.
	seedLicense(t, d, lic{id: "LIC-KEEP", customer: "Other Co", validUntil: now.Add(21 * day)})
	seedLicense(t, d, lic{id: "LIC-KEEP-REV", customer: "Other Co", validUntil: now.Add(300 * day), revoked: true})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Empty(t, reminderRows(t, d, "LIC-OLD"))
	assert.Equal(t, []int{90}, reminderRows(t, d, "LIC-NEW"))
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-KEEP"))
	for _, m := range reminderNotices(t, d) {
		assert.NotContains(t, m.Body, "License: LIC-OLD\n")
	}
}

func TestOneFailingLicenseDoesNotStopTheRun(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r15_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-A1", customer: "A", validUntil: now.Add(20 * day)})
	seedLicense(t, d, lic{id: "LIC-BAD", customer: "B", validUntil: now.Add(21 * day)})
	seedLicense(t, d, lic{id: "LIC-C1", customer: "C", validUntil: now.Add(22 * day)})
	// A test-only trigger makes the notice of one license fail deterministically, after its
	// reminder rows were inserted in the same transaction.
	_, err := d.Owner.Exec(ctx, `CREATE FUNCTION t_fail_notice() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.kind = 'license.ending' AND NEW.subject = 'LIC-BAD' THEN RAISE EXCEPTION 'injected failure'; END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER t_fail_notice BEFORE INSERT ON notifications FOR EACH ROW EXECUTE FUNCTION t_fail_notice()`)
	require.NoError(t, err)

	n, err := notify.CreateReminders(ctx, p, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injected failure")
	assert.Equal(t, 2, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 2)
	assert.Contains(t, ns[0].Body, "License: LIC-A1\n")
	assert.Contains(t, ns[1].Body, "License: LIC-C1\n", "the license after the failing one still gets its reminder")
	assert.Empty(t, reminderRows(t, d, "LIC-BAD"), "the failed transaction left no reminder row behind")

	_, err = d.Owner.Exec(ctx, `DROP TRIGGER t_fail_notice ON notifications`)
	require.NoError(t, err)
	n, err = notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the failed license is retried on the next run")
	assert.Len(t, reminderNotices(t, d), 3)
}

func TestReminderBodyHasTheRenewPathAndNoInstallationID(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r9_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC 1/a&b=c", customer: "A", validUntil: now.Add(25 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 1)
	assert.Contains(t, ns[0].Body, "\nRenew: /requests/new?renew=LIC+1%2Fa%26b%3Dc\n", "a path, the id escaped")
	assert.NotContains(t, ns[0].Body, "http")
	assert.NotContains(t, ns[0].Body, installation)
	assert.NotContains(t, ns[0].Body, installation[:9], "not even a prefix longer than 8 characters")
	assert.NotContains(t, ns[0].Title, installation[:9])
}

func TestReminderBodyHasTheFacts(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r12_notifier")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	addWebUser(t, d, "ayse", "sales")
	// 23:30 in Istanbul is still the 25th in UTC: the date is printed in UTC.
	end := time.Date(2026, 11, 25, 23, 30, 0, 0, time.UTC)
	seedLicense(t, d, lic{id: "LIC-R12", customer: "Acme Corp", requestedBy: "web:ayse", validUntil: end})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 2, "one for the owner, one for the requester")
	assert.Equal(t, ns[0].Body, ns[1].Body)
	b := ns[0].Body
	for _, want := range []string{
		"Customer: Acme Corp\n", "License: LIC-R12\n", "Valid until: 2026-11-25\n", "Days left: 42\n",
		"Targets: 7\n", "Requested by: web:ayse\n", "Renew: /requests/new?renew=LIC-R12\n",
	} {
		assert.Contains(t, b, want)
	}
	assert.NotContains(t, b, installation[:9])
	assert.NotContains(t, b, "deadbeef")
}

func TestCustomerNameIsOneLineInTheTitle(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r13_notifier")
	now := testNow()
	// The customers CHECK only trims spaces, so a name can carry a line break.
	seedLicense(t, d, lic{id: "LIC-CRLF", customer: "Evil\r\nSecond line\u2028third", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-LONG", customer: strings.Repeat("ş", 200), validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 2)
	assert.Equal(t, "License ending in 30 days: Evil Second line third", ns[0].Title)
	assert.Contains(t, ns[0].Body, "Customer: Evil Second line third\n")
	assert.True(t, utf8.ValidString(ns[1].Title))
	assert.Equal(t, 200, utf8.RuneCountInString(ns[1].Title))
	assert.True(t, strings.HasPrefix(ns[1].Title, "License ending in 30 days: şş"))
}

func TestReminderDropsControlAndFormatCharacters(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r17_notifier")
	now := testNow()
	seedLicense(t, d, lic{id: "LIC-BIDI", customer: "Acme\u202e\u2066moc.live\u2069\x1b[31m\u200bX",
		requestedBy: "t_sales\x07login", validUntil: now.Add(25 * day)})

	_, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	ns := reminderNotices(t, d)
	require.Len(t, ns, 1)
	for _, s := range []string{ns[0].Title, ns[0].Body} {
		for _, bad := range []string{"\u202e", "\u2066", "\u2069", "\x1b", "\u200b", "\x07"} {
			assert.NotContains(t, s, bad)
		}
	}
	assert.Equal(t, "License ending in 30 days: Acme moc.live [31m X", ns[0].Title)
	assert.Contains(t, ns[0].Body, "Requested by: t_sales login\n")
}

// The dedupe key column holds 200 characters. A license id over 180 characters is keyed by its
// SHA-256 under a prefix of its own, the rule of the issuance trigger; so is one whose key would
// overflow only with the requester's name appended.
func TestLongLicenseIDsGetASafeDedupeKey(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r18_notifier")
	now := testNow()
	user := strings.Repeat("u", 64)
	addWebUser(t, d, user, "sales")
	long := "L-" + strings.Repeat("ş", 298)
	edge := strings.Repeat("e", 180)
	seedLicense(t, d, lic{id: long, customer: "A", requestedBy: "web:" + user, validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: edge, customer: "B", requestedBy: "web:" + user, validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	var keys []string
	for _, x := range reminderNotices(t, d) {
		assert.LessOrEqual(t, utf8.RuneCountInString(x.DedupeKey), 200)
		assert.LessOrEqual(t, utf8.RuneCountInString(x.Subject), 64)
		keys = append(keys, x.DedupeKey)
	}
	assert.ElementsMatch(t, []string{
		"ending-sha256:" + hash(long) + ":30",
		"ending-sha256:" + hash(long) + ":30:" + user,
		"ending:" + edge + ":30", // 190 characters: verbatim, like the issuance trigger
		"ending-sha256:" + hash(edge) + ":30:" + user,
	}, keys)

	// The issuance trigger keys by length alone (its own rule; it has no suffix to confuse).
	var issued []string
	rows, err := d.Owner.Query(ctx, `SELECT dedupe_key FROM notifications WHERE kind = 'license.issued' ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		issued = append(issued, k)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"issued-sha256:" + hash(long), "issued:" + edge}, issued)
}

func TestTwoConcurrentReminderRunsCreateEachOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := notifier(t, d, "t_r14_notifier_a")
	p2 := notifier(t, d, "t_r14_notifier_b")
	now := testNow()
	addWebUser(t, d, "ayse", "sales")
	const licenses = 30
	for i := range licenses {
		by := "t_sales_login"
		if i%2 == 0 {
			by = "web:ayse"
		}
		seedLicense(t, d, lic{id: fmt.Sprintf("LIC-C%02d", i), customer: fmt.Sprintf("Cust %02d", i),
			requestedBy: by, validUntil: now.Add(time.Duration(10+i*2) * day)})
	}

	for round := range 3 {
		var wg sync.WaitGroup
		counts := make([]int, 2)
		errs := make([]error, 2)
		for i, p := range []*pgxpool.Pool{p1, p2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				counts[i], errs[i] = notify.CreateReminders(ctx, p, now)
			}()
		}
		wg.Wait()
		require.NoError(t, errs[0])
		require.NoError(t, errs[1])
		if round == 0 {
			assert.Equal(t, licenses, counts[0]+counts[1])
		} else {
			assert.Zero(t, counts[0]+counts[1], "round %d", round)
		}
	}

	assert.Len(t, ownerReminders(t, d), licenses)
	assert.Len(t, reminderNotices(t, d), licenses+licenses/2, "one owner notice each, one user notice for half")
	var orphans int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM licenses l
		WHERE EXISTS (SELECT 1 FROM reminders r WHERE r.license_id = l.license_id)
		  AND NOT EXISTS (SELECT 1 FROM notifications n WHERE n.kind = 'license.ending' AND n.audience = 'owner'
		      AND n.subject = l.license_id)`).Scan(&orphans))
	assert.Zero(t, orphans, "every reminded license has its notice")
}

// A verbatim id never contains ':', so license "X:30" cannot take the key of license "X"'s
// reminder for a web user named "30".
func TestDedupeKeysOfDifferentLicensesNeverCollide(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r19_notifier")
	now := testNow()
	addWebUser(t, d, "30", "sales")
	seedLicense(t, d, lic{id: "X", customer: "A", requestedBy: "web:30", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "X:30", customer: "B", validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	sum := sha256.Sum256([]byte("X:30"))
	var keys []string
	for _, x := range reminderNotices(t, d) {
		keys = append(keys, x.DedupeKey)
	}
	assert.ElementsMatch(t, []string{"ending:X:30", "ending:X:30:30", "ending-sha256:" + hex.EncodeToString(sum[:]) + ":30"}, keys)
}
