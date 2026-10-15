//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/mail"
	"alice/internal/vconsole/vpgtest"
)

func pgCode(t *testing.T, err error) string {
	t.Helper()
	var pe *pgconn.PgError
	require.True(t, errors.As(err, &pe), "want a PgError, got %v", err)
	return pe.Code
}

// issue inserts a license by raw SQL as p (the path a client could take without vendor-console).
func issue(t *testing.T, p *pgxpool.Pool, id, customer string) {
	t.Helper()
	c := addCustomer(t, p, customer)
	rid, err := addRequest(t, p, c)
	require.NoError(t, err)
	_, err = p.Exec(context.Background(), `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ($1, $2, $3, 'x', 'vk-77', now(), now(), now() + interval '1 year', 3, '\xdeadbeef', 'x')`, id, rid, c)
	require.NoError(t, err)
}

func TestIssuingALicenseEnqueuesTheOwnerMail(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n1_owner")
	signer := d.As(t, "vendor_signer", "t_n1_signer")
	_, err := owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'boss@example.com')`)
	require.NoError(t, err)
	issue(t, signer, "LIC-N1", "Acme Corp")

	var n int
	var kind, subject, body string
	var to []string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM mail_outbox`).Scan(&n))
	assert.Equal(t, 1, n)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT kind, to_addrs, subject, body FROM mail_outbox`).Scan(&kind, &to, &subject, &body))
	assert.Equal(t, "issued", kind)
	assert.Equal(t, []string{"boss@example.com"}, to)
	assert.Contains(t, subject, "Acme Corp")
	assert.Contains(t, subject, "LIC-N1")
	assert.Contains(t, body, "t_n1_signer")
	assert.Contains(t, body, "vk-77")
	assert.NotContains(t, body, "deadbeef")
}

func TestIssuedMailWaitsWhenNoOwnerAddressIsSet(t *testing.T) {
	d := vpgtest.New(t)
	signer := d.As(t, "vendor_signer", "t_n2_signer")
	issue(t, signer, "LIC-N2", "Beta Ltd")
	var to []string
	var sent *string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT to_addrs, sent_at::text FROM mail_outbox`).Scan(&to, &sent))
	assert.Empty(t, to)
	assert.Nil(t, sent)
}

func TestSalesAndWebCannotTouchTheOutbox(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, g := range []string{"vendor_sales", "vendor_web"} {
		p := d.As(t, g, "t_n3_"+g)
		for _, q := range []string{
			`SELECT * FROM mail_outbox`,
			`INSERT INTO mail_outbox (to_addrs, subject, body) VALUES ('{}', 's', 'b')`,
			`UPDATE mail_outbox SET attempts = 1`,
			`DELETE FROM mail_outbox`,
			`SELECT * FROM reminders`,
			`INSERT INTO reminders (license_id, days_before) VALUES ('x', 90)`,
			`UPDATE reminders SET days_before = 60`,
			`DELETE FROM reminders`,
			`INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`,
		} {
			_, err := p.Exec(ctx, q)
			require.Error(t, err, "%s: %s", g, q)
			assert.Equal(t, "42501", pgCode(t, err), "%s: %s", g, q)
		}
	}
}

func TestOnlyTheOwnerChangesSettingsAndWebUserEmail(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n4_owner")
	signer := d.As(t, "vendor_signer", "t_n4_signer")

	_, err := signer.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `UPDATE vendor_settings SET value = 'x@y.co'`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `UPDATE vendor_settings SET value = 'c@d.co' WHERE key = 'owner_email'`)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `UPDATE vendor_settings SET value = 'bad' WHERE key = 'owner_email'`)
	require.Error(t, err, "a malformed owner address would block issuing")

	_, err = owner.Exec(ctx, `INSERT INTO web_users (name) VALUES ('ayse')`)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `UPDATE web_users SET email = 'ayse@example.com' WHERE name = 'ayse'`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `UPDATE web_users SET email = 'ayse@example.com' WHERE name = 'ayse'`)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `UPDATE web_users SET email = 'no at sign' WHERE name = 'ayse'`)
	require.Error(t, err)

	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'settings.set' AND subject = 'owner_email'
		AND actor = 't_n4_owner' AND details ? 'value'`).Scan(&n))
	assert.Equal(t, 2, n)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'webuser.email' AND subject = 'ayse'
		AND details->>'email' = 'ayse@example.com'`).Scan(&n))
	assert.Equal(t, 1, n)
	var v int64
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT audit_verify()`).Scan(&v))
	assert.Zero(t, v)
}

func TestNotifierCannotReadLicenseFilesOrWrite(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n5_signer")
	nt := d.As(t, "vendor_notifier", "t_n5_notifier")
	issue(t, signer, "LIC-N5", "Gamma")

	for _, q := range []string{
		`SELECT file FROM licenses`,
		`SELECT * FROM licenses`,
		`INSERT INTO licenses (license_id) VALUES ('z')`,
		`UPDATE customers SET notes = 'x'`,
		`DELETE FROM mail_outbox`,
		`INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`,
		`UPDATE vendor_settings SET value = 'a@b.co'`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
	var id string
	require.NoError(t, nt.QueryRow(ctx, `SELECT license_id FROM licenses`).Scan(&id))
	assert.Equal(t, "LIC-N5", id)
	_, err := nt.Exec(ctx, `UPDATE mail_outbox SET attempts = attempts + 1`)
	require.NoError(t, err)
	_, err = nt.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N5', 90)`)
	require.NoError(t, err)
	_, err = nt.Exec(ctx, `SELECT notify_mark_summary(now())`)
	require.NoError(t, err)
	var v string
	require.NoError(t, nt.QueryRow(ctx, `SELECT value FROM vendor_settings WHERE key = 'last_summary_at'`).Scan(&v))
	assert.NotEmpty(t, v)
}

func TestOutboxRejectsHeaderInjection(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, c := range []struct{ to, subject string }{
		{"a@b.co", "hi\nBcc: x@y.co"},
		{"a@b.co", "hi\rthere"},
		{"a@b.co\nBcc: x@y.co", "ok"},
		{"a@b.co\r", "ok"},
	} {
		_, err := d.Owner.Exec(ctx, `INSERT INTO mail_outbox (to_addrs, subject, body) VALUES (ARRAY[$1::text], $2, 'b')`, c.to, c.subject)
		require.Error(t, err, "%q %q", c.to, c.subject)
		assert.Equal(t, "23514", pgCode(t, err))
	}
}

func TestReminderRowsAreUniquePerThreshold(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n7_signer")
	issue(t, signer, "LIC-N7", "Eta")
	_, err := d.Owner.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N7', 90)`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N7', 90)`)
	require.Error(t, err)
	assert.Equal(t, "23505", pgCode(t, err))
	_, err = d.Owner.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N7', 45)`)
	require.Error(t, err)
	assert.Equal(t, "23514", pgCode(t, err))
}

func TestNotifierSeesRequestsDespiteRowLevelSecurity(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n8_signer")
	nt := d.As(t, "vendor_notifier", "t_n8_notifier")
	c := addCustomer(t, signer, "Theta")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)

	var id int64
	require.NoError(t, nt.QueryRow(ctx, `SELECT id FROM license_requests`).Scan(&id))
	assert.Equal(t, rid, id)
	for _, q := range []string{
		`UPDATE license_requests SET targets = 9`,
		`INSERT INTO license_requests (customer_id, installation, targets) VALUES (1, 'ALICE-TESTX-AAAAA', 1)`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
}

func TestIssuanceMailSurvivesHostileValues(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n9_signer")
	name := "Line1\nBcc: x@y.co\r\n" + strings.Repeat("n", 180)
	c := addCustomer(t, signer, name)
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	// license_id is the primary key, so the btree limit (~2700 bytes) caps it; key_id is unindexed and can be huge.
	huge := strings.Repeat("a", 2000)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ($1, $2, $3, 'ALICE-SECRET-INSTALL', $4, now(), now(), now(), 1, '\x00', 'x')`,
		huge, rid, c, strings.Repeat("k", 300000))
	require.NoError(t, err, "issuing must never fail because of the mail")

	var subject, body string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT subject, body FROM mail_outbox`).Scan(&subject, &body))
	assert.NotContains(t, subject, "\n")
	assert.NotContains(t, subject, "\r")
	assert.LessOrEqual(t, len(subject), 200)
	assert.Contains(t, subject, "Line1 Bcc: x@y.co")
	assert.LessOrEqual(t, len(body), 200000)
	assert.NotContains(t, body, "ALICE-SECRET-INSTALL")
	assert.NotContains(t, body, "ALICE-SECR")
}

func TestMarkSummarySetsOnlyLastSummaryAndOnlyForTheNotifier(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n10_owner")
	nt := d.As(t, "vendor_notifier", "t_n10_notifier")
	_, err := owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`)
	require.NoError(t, err)

	_, err = nt.Exec(ctx, `SELECT notify_mark_summary('2026-10-01T00:00:00Z')`)
	require.NoError(t, err)
	_, err = nt.Exec(ctx, `SELECT notify_mark_summary('2026-10-08T00:00:00Z')`)
	require.NoError(t, err)
	rows, err := d.Owner.Query(ctx, `SELECT key, value FROM vendor_settings ORDER BY key`)
	require.NoError(t, err)
	got := map[string]string{}
	for rows.Next() {
		var k, v string
		require.NoError(t, rows.Scan(&k, &v))
		got[k] = v
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, map[string]string{"owner_email": "a@b.co", "last_summary_at": "2026-10-08T00:00:00Z"}, got)
	var marks int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'settings.set'
		AND subject = 'last_summary_at' AND actor = 't_n10_notifier'`).Scan(&marks))
	assert.Equal(t, 2, marks, "each mark is audited under the notifier login")

	for name, p := range map[string]*pgxpool.Pool{
		"sales":  d.As(t, "vendor_sales", "t_n10_sales"),
		"web":    d.As(t, "vendor_web", "t_n10_web"),
		"signer": d.As(t, "vendor_signer", "t_n10_signer"),
		"owner":  owner,
	} {
		_, err := p.Exec(ctx, `SELECT notify_mark_summary(now())`)
		require.Error(t, err, name)
		assert.Equal(t, "42501", pgCode(t, err), name)
	}
}

// The database must never store an owner or web-user address that the sender would refuse to
// send to: such an address would only show up as a failed mail, long after it was typed.
func TestAddressChecksAgreeWithTheSender(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO web_users (name) VALUES ('ayse')`)
	require.NoError(t, err)
	for _, addr := range []string{
		"a@b.co", "e.altan+x@sub.example.com", "o'brien@example.com", "x_y@a-b.example", "!#$%&'*+/=?^_`{|}~-@example.com",
		"a@b", "a@localhost", "@b.co", "a@", "a@@b.co", "a b@c.co", ".a@b.co", "a.@b.co", "a..b@c.co", "a@-b.co",
		"a@b-.co", "a@b..co", "a@.b.co", "a@b.co.", "a@b_c.co", "ayşe@example.com", "a@exämple.com", `"a"@b.co`,
		"Boss <boss@example.com>", "a@b.co,c@d.co", "a\\b@c.co", "a@b.co\t", "a@b.co\n", "a\n@b.co", strings.Repeat("a", 250) + "@b.co",
	} {
		want := mail.ValidateAddress(addr) == nil
		_, err := d.Owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', $1)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, addr)
		assert.Equal(t, want, err == nil, "owner_email %q: sender ok=%v, database err=%v", addr, want, err)
		_, err = d.Owner.Exec(ctx, `UPDATE web_users SET email = $1 WHERE name = 'ayse'`, addr)
		assert.Equal(t, want, err == nil, "web_users.email %q: sender ok=%v, database err=%v", addr, want, err)
	}
}

// issuedMail returns the subject and body of the one issuance mail.
func issuedMail(t *testing.T, d *vpgtest.DB) (string, string) {
	t.Helper()
	var subject, body string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT subject, body FROM mail_outbox WHERE kind = 'issued'`).Scan(&subject, &body))
	return subject, body
}

func linesWithPrefix(body, prefix string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func TestIssuanceMailCleansControlAndBidiCharacters(t *testing.T) {
	d := vpgtest.New(t)
	signer := d.As(t, "vendor_signer", "t_n11_signer")
	issue(t, signer, "LIC-N11", "Acme\nSigned by: mallory\u202e\u2066gro.live\u2069\x1b[31m")

	subject, body := issuedMail(t, d)
	assert.Equal(t, []string{"Signed by: t_n11_signer"}, linesWithPrefix(body, "Signed by:"),
		"a name with line breaks must not add a line")
	for _, s := range []string{subject, body} {
		assert.NotContains(t, s, "\u202e")
		assert.NotContains(t, s, "\u2066")
		assert.NotContains(t, s, "\u2069")
		assert.NotContains(t, s, "\x1b")
	}
	assert.Contains(t, body, "Customer: Acme Signed by: mallory gro.live [31m\n")
	assert.Contains(t, subject, "Acme Signed by: mallory gro.live [31m (LIC-N11)")
}

func TestIssuanceMailNamesTheLoginNotAForgedSigner(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n12_signer")
	c := addCustomer(t, signer, "Forge Inc")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256, signed_by) VALUES ('LIC-N12', $1, $2, 'x', 'vk-1', now(), now(),
		now() + interval '1 year', 1, '\x00', 'x', E'web:boss\nSigned by: x')`, rid, c)
	require.NoError(t, err)

	_, body := issuedMail(t, d)
	assert.Equal(t, []string{"Signed by: t_n12_signer"}, linesWithPrefix(body, "Signed by:"))
	assert.Equal(t, []string{"Recorded signer: web:boss Signed by: x (differs from the login)"},
		linesWithPrefix(body, "Recorded signer:"))

	// The default signed_by is the login: no Recorded signer line then.
	issue(t, signer, "LIC-N12B", "Plain Ltd")
	var body2 string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT body FROM mail_outbox WHERE subject LIKE '%LIC-N12B%'`).Scan(&body2))
	assert.Empty(t, linesWithPrefix(body2, "Recorded signer:"))
}

func TestOwnerReadsTheOutboxAndReminders(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n13_owner")
	signer := d.As(t, "vendor_signer", "t_n13_signer")
	issue(t, signer, "LIC-N13", "Iota")
	_, err := d.Owner.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N13', 90)`)
	require.NoError(t, err)

	var n int
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM mail_outbox WHERE failed_at IS NULL`).Scan(&n))
	assert.Equal(t, 1, n)
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM reminders`).Scan(&n))
	assert.Equal(t, 1, n)
	for _, q := range []string{
		`UPDATE mail_outbox SET failed_at = NULL`,
		`DELETE FROM mail_outbox`,
		`INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N13', 60)`,
	} {
		_, err := owner.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
}

func TestNotifierReadsOnlyTheColumnsItNeeds(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_n14_signer")
	nt := d.As(t, "vendor_notifier", "t_n14_notifier")
	issue(t, signer, "LIC-N14", "Kappa")

	for _, q := range []string{
		`SELECT contact FROM customers`,
		`SELECT notes FROM customers`,
		`SELECT details FROM audit`,
		`SELECT * FROM audit`,
		`SELECT installation FROM license_requests`,
		`SELECT created_by FROM web_users`,
		`UPDATE mail_outbox SET body = 'x'`,
		`UPDATE mail_outbox SET subject = 'x'`,
		`UPDATE mail_outbox SET kind = 'x'`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
	for _, q := range []string{
		`SELECT id, name FROM customers`,
		`SELECT at, actor, action, subject FROM audit`,
		`SELECT id, customer_id, status, requested_by, requested_at FROM license_requests`,
		`SELECT name, email, disabled_at FROM web_users`,
		`UPDATE mail_outbox SET failed_at = NULL, attempts = 0, last_error = '', next_attempt_at = now() WHERE id = 1`,
	} {
		_, err := nt.Exec(ctx, q)
		require.NoError(t, err, q)
	}
}
