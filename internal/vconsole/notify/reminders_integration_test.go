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

	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

const (
	day          = 24 * time.Hour
	installation = "inst-0123456789abcdef0123"
	baseURL      = "https://console.example.com"
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

func setOwner(t *testing.T, d *vpgtest.DB, addr string) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, addr)
	require.NoError(t, err)
}

func addWebUser(t *testing.T, d *vpgtest.DB, name, email string) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO web_users (name, email) VALUES ($1, $2)`, name, email)
	require.NoError(t, err)
}

type reminderMail struct {
	ID      int64
	To      []string
	Subject string
	Body    string
}

// reminderMails returns the reminder rows of the outbox (the issuance trigger writes 'issued' rows too).
func reminderMails(t *testing.T, d *vpgtest.DB) []reminderMail {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(),
		`SELECT id, to_addrs, subject, body FROM mail_outbox WHERE kind = 'reminder' ORDER BY id`)
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

func notifier(t *testing.T, d *vpgtest.DB, login string) *pgxpool.Pool {
	t.Helper()
	return d.As(t, "vendor_notifier", login)
}

func TestReminderAt90ThenNotAgain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r1_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-R1", customer: "Acme Corp", validUntil: now.Add(89 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Zero(t, n)
	n, err = notify.CreateReminders(ctx, p, now.Add(10*day), baseURL)
	require.NoError(t, err)
	assert.Zero(t, n, "still inside the 90-day threshold")

	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, "License ending in 90 days: Acme Corp", ms[0].Subject)
	assert.Equal(t, []string{"boss@example.com"}, ms[0].To)
	assert.Equal(t, []int{90}, reminderRows(t, d, "LIC-R1"))
}

func TestEachThresholdSendsOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r2_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	end := now.Add(89 * day)
	seedLicense(t, d, lic{id: "LIC-R2", customer: "Acme Corp", validUntil: end})

	for _, before := range []int{89, 59, 29} {
		at := end.Add(-time.Duration(before) * day)
		for range 2 {
			_, err := notify.CreateReminders(ctx, p, at, baseURL)
			require.NoError(t, err)
		}
	}
	ms := reminderMails(t, d)
	require.Len(t, ms, 3)
	for i, want := range []string{"90", "60", "30"} {
		assert.Equal(t, "License ending in "+want+" days: Acme Corp", ms[i].Subject)
	}
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-R2"))
}

func TestBoundariesOfTheThresholds(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r2b_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-EXACT90", customer: "A", validUntil: now.Add(90 * day)})
	seedLicense(t, d, lic{id: "LIC-OVER90", customer: "B", validUntil: now.Add(90*day + time.Second)})
	seedLicense(t, d, lic{id: "LIC-EXACT60", customer: "C", validUntil: now.Add(60 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []int{90}, reminderRows(t, d, "LIC-EXACT90"))
	assert.Empty(t, reminderRows(t, d, "LIC-OVER90"))
	assert.Equal(t, []int{60, 90}, reminderRows(t, d, "LIC-EXACT60"))
}

func TestLateDiscoveryFiresOnlyTheMostUrgentThreshold(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r3_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	end := now.Add(20 * day)
	seedLicense(t, d, lic{id: "LIC-R3", customer: "Acme Corp", validUntil: end})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []int{30, 60, 90}, reminderRows(t, d, "LIC-R3"))
	for _, at := range []time.Time{now, now.Add(5 * day), end.Add(-time.Minute)} {
		n, err = notify.CreateReminders(ctx, p, at, baseURL)
		require.NoError(t, err)
		assert.Zero(t, n)
	}
	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	assert.Equal(t, "License ending in 30 days: Acme Corp", ms[0].Subject)
	assert.Contains(t, ms[0].Body, "Days left: 20\n")
}

func TestRevokedAndReplacedLicensesGetNoReminder(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r4_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-REVOKED", customer: "A", validUntil: now.Add(25 * day), revoked: true})
	seedLicense(t, d, lic{id: "LIC-OLD", customer: "B", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-NEW", customer: "B", validUntil: now.Add(365 * day), replaces: "LIC-OLD"})
	seedLicense(t, d, lic{id: "LIC-LIVE", customer: "C", validUntil: now.Add(25 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	assert.Contains(t, ms[0].Body, "LIC-LIVE")
	assert.Empty(t, reminderRows(t, d, "LIC-REVOKED"))
	assert.Empty(t, reminderRows(t, d, "LIC-OLD"))
	assert.Empty(t, reminderRows(t, d, "LIC-NEW"))
}

func TestEndedLicensesGetNoReminder(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r5_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-ENDED", customer: "A", validUntil: now.Add(-time.Hour)})
	seedLicense(t, d, lic{id: "LIC-ENDS-NOW", customer: "B", validUntil: now})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Empty(t, reminderMails(t, d))
	assert.Empty(t, reminderRows(t, d, "LIC-ENDED"))
	assert.Empty(t, reminderRows(t, d, "LIC-ENDS-NOW"))
}

func TestRequesterWithoutEmailOnlyOwnerIsTold(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r6_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	addWebUser(t, d, "ayse", "")
	addWebUser(t, d, "mehmet", "mehmet@example.com")
	_, err := d.Owner.Exec(ctx, `UPDATE web_users SET disabled_at = now() WHERE name = 'mehmet'`)
	require.NoError(t, err)
	seedLicense(t, d, lic{id: "LIC-WEB", customer: "A", requestedBy: "web:ayse", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-DB", customer: "B", requestedBy: "t_sales_login", validUntil: now.Add(26 * day)})
	seedLicense(t, d, lic{id: "LIC-GONE", customer: "C", requestedBy: "web:nobody", validUntil: now.Add(27 * day)})
	seedLicense(t, d, lic{id: "LIC-DISABLED", customer: "D", requestedBy: "web:mehmet", validUntil: now.Add(28 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 4)
	for _, m := range ms {
		assert.Equal(t, []string{"boss@example.com"}, m.To, m.Subject)
	}
	assert.Contains(t, ms[0].Body, "Requested by: web:ayse\n")
	assert.Contains(t, ms[1].Body, "Requested by: t_sales_login\n")
}

func TestRequesterWithEmailIsAddedOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r7_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	addWebUser(t, d, "Ayse", "ayse@example.com")
	addWebUser(t, d, "boss", "Boss@Example.com")
	seedLicense(t, d, lic{id: "LIC-A", customer: "A", requestedBy: "web:ayse", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-B", customer: "B", requestedBy: "web:boss", validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 2)
	assert.Equal(t, []string{"boss@example.com", "ayse@example.com"}, ms[0].To, "name matched case-insensitively")
	assert.Equal(t, []string{"boss@example.com"}, ms[1].To, "the same address is not listed twice")
}

func TestOwnerAddressMissingLeavesWaitingRow(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r8_notifier")
	now := testNow()
	addWebUser(t, d, "ayse", "ayse@example.com")
	seedLicense(t, d, lic{id: "LIC-NOBODY", customer: "A", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-REQ", customer: "B", requestedBy: "web:ayse", validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 2)
	assert.Empty(t, ms[0].To, "no address at all: the row waits for the owner address")
	assert.Equal(t, []string{"ayse@example.com"}, ms[1].To, "a mail with a recipient is not held back")

	setOwner(t, d, "boss@example.com")
	_, err = notify.ResolveEmptyRecipients(ctx, p)
	require.NoError(t, err)
	ms = reminderMails(t, d)
	assert.Equal(t, []string{"boss@example.com"}, ms[0].To)
	assert.Equal(t, []string{"ayse@example.com"}, ms[1].To)
}

func TestRenewLinkUsesTheBaseURLAndEscapesTheID(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r9_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC 1/a&b=c", customer: "A", validUntil: now.Add(25 * day)})

	n, err := notify.CreateReminders(ctx, p, now, "https://console.example.com/vc/")
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	assert.Contains(t, ms[0].Body, "\nRenew: https://console.example.com/vc/requests/new?renew=LIC+1%2Fa%26b%3Dc\n")
}

func TestNoRenewLineWithoutBaseURL(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r10_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-R10", customer: "A", validUntil: now.Add(25 * day)})

	n, err := notify.CreateReminders(ctx, p, now, "")
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	assert.NotContains(t, ms[0].Body, "Renew")
	assert.NotContains(t, ms[0].Body, "requests/new")
}

func TestInvalidBaseURLIsRefusedBeforeAnything(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r11_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	seedLicense(t, d, lic{id: "LIC-R11", customer: "A", validUntil: now.Add(25 * day)})

	for _, u := range []string{
		"console.example.com", "ftp://console.example.com", "https://", "javascript:alert(1)",
		"https://console.example.com/?x=1", "https://console.example.com/#top", "https://user:pw@console.example.com",
		"https://console.example.com/\r\nx", "/requests",
	} {
		n, err := notify.CreateReminders(ctx, p, now, u)
		require.Error(t, err, u)
		assert.Zero(t, n, u)
	}
	assert.Empty(t, reminderMails(t, d))
	assert.Empty(t, reminderRows(t, d, "LIC-R11"))
}

func TestReminderBodyHasTheFactsAndNoInstallation(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r12_notifier")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	setOwner(t, d, "boss@example.com")
	addWebUser(t, d, "ayse", "ayse@example.com")
	// 23:30 in Istanbul is still the 25th in UTC: the date is printed in UTC.
	end := time.Date(2026, 11, 25, 23, 30, 0, 0, time.UTC)
	seedLicense(t, d, lic{id: "LIC-R12", customer: "Acme Corp", requestedBy: "web:ayse", validUntil: end})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 1)
	b := ms[0].Body
	for _, want := range []string{
		"Customer: Acme Corp\n", "License: LIC-R12\n", "Valid until: 2026-11-25\n", "Days left: 42\n",
		"Targets: 7\n", "Requested by: web:ayse\n", "Renew: " + baseURL + "/requests/new?renew=LIC-R12\n",
	} {
		assert.Contains(t, b, want)
	}
	assert.NotContains(t, b, installation)
	assert.NotContains(t, b, installation[:9], "not even a prefix longer than 8 characters")
	assert.NotContains(t, b, "deadbeef")
}

func TestCustomerNameIsOneLineInTheSubject(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_r13_notifier")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	// The customers CHECK only trims spaces, so a name can carry a line break.
	seedLicense(t, d, lic{id: "LIC-CRLF", customer: "Evil\r\nBcc: x@example.com", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-LONG", customer: strings.Repeat("ş", 200), validUntil: now.Add(26 * day)})

	n, err := notify.CreateReminders(ctx, p, now, baseURL)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ms := reminderMails(t, d)
	require.Len(t, ms, 2)
	assert.Equal(t, "License ending in 30 days: Evil Bcc: x@example.com", ms[0].Subject)
	assert.Contains(t, ms[0].Body, "Customer: Evil Bcc: x@example.com\n")
	assert.True(t, utf8.ValidString(ms[1].Subject))
	assert.Equal(t, 200, utf8.RuneCountInString(ms[1].Subject))
	assert.True(t, strings.HasPrefix(ms[1].Subject, "License ending in 30 days: şş"))
}

func TestTwoConcurrentReminderRunsEnqueueEachOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := notifier(t, d, "t_r14_notifier_a")
	p2 := notifier(t, d, "t_r14_notifier_b")
	now := testNow()
	setOwner(t, d, "boss@example.com")
	const licenses = 30
	for i := range licenses {
		seedLicense(t, d, lic{id: fmt.Sprintf("LIC-C%02d", i), customer: fmt.Sprintf("Cust %02d", i),
			validUntil: now.Add(time.Duration(10+i*2) * day)})
	}

	for round := range 3 {
		var wg sync.WaitGroup
		counts := make([]int, 2)
		errs := make([]error, 2)
		for i, p := range []*pgxpool.Pool{p1, p2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				counts[i], errs[i] = notify.CreateReminders(ctx, p, now, baseURL)
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

	ms := reminderMails(t, d)
	require.Len(t, ms, licenses)
	seen := map[string]int{}
	for _, m := range ms {
		seen[m.Body]++
	}
	for b, n := range seen {
		assert.Equal(t, 1, n, "mail sent %d times: %s", n, b)
	}
	var orphans int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM reminders r WHERE NOT EXISTS (
		SELECT 1 FROM mail_outbox m WHERE m.kind = 'reminder' AND m.body LIKE '%License: ' || r.license_id || E'\n%')`).Scan(&orphans))
	assert.Zero(t, orphans, "every reminder row has its mail")
}
