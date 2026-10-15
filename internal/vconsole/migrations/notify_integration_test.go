//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestSalesAndWebCannotTouchRemindersOrSettings(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, g := range []string{"vendor_sales", "vendor_web"} {
		p := d.As(t, g, "t_n3_"+g)
		for _, q := range []string{
			`SELECT * FROM reminders`,
			`INSERT INTO reminders (license_id, days_before) VALUES ('x', 90)`,
			`UPDATE reminders SET days_before = 60`,
			`DELETE FROM reminders`,
			`SELECT * FROM vendor_settings`,
			`INSERT INTO vendor_settings (key, value) VALUES ('timezone', 'UTC')`,
		} {
			_, err := p.Exec(ctx, q)
			require.Error(t, err, "%s: %s", g, q)
			assert.Equal(t, "42501", pgCode(t, err), "%s: %s", g, q)
		}
	}
}

func TestOnlyTheOwnerChangesSettings(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n4_owner")
	signer := d.As(t, "vendor_signer", "t_n4_signer")

	_, err := signer.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('timezone', 'UTC')`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('timezone', 'UTC')`)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `UPDATE vendor_settings SET value = 'Europe/Istanbul'`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `UPDATE vendor_settings SET value = 'Europe/Istanbul' WHERE key = 'timezone'`)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('unknown_key', 'x')`)
	require.Error(t, err)
	assert.Equal(t, "23514", pgCode(t, err))

	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'settings.set' AND subject = 'timezone'
		AND actor = 't_n4_owner' AND details ? 'value'`).Scan(&n))
	assert.Equal(t, 2, n)
	var by string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT updated_by FROM vendor_settings WHERE key = 'timezone'`).Scan(&by))
	assert.Equal(t, "t_n4_owner", by)
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
		`INSERT INTO vendor_settings (key, value) VALUES ('timezone', 'UTC')`,
		`UPDATE vendor_settings SET value = 'UTC'`,
		`DELETE FROM reminders`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
	var id string
	require.NoError(t, nt.QueryRow(ctx, `SELECT license_id FROM licenses`).Scan(&id))
	assert.Equal(t, "LIC-N5", id)
	_, err := nt.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N5', 90)`)
	require.NoError(t, err)
	_, err = nt.Exec(ctx, `SELECT notify_mark_summary(now())`)
	require.NoError(t, err)
	var v string
	require.NoError(t, nt.QueryRow(ctx, `SELECT value FROM vendor_settings WHERE key = 'last_summary_at'`).Scan(&v))
	assert.NotEmpty(t, v)
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

func TestMarkSummarySetsOnlyLastSummaryAndOnlyForTheNotifier(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n10_owner")
	nt := d.As(t, "vendor_notifier", "t_n10_notifier")
	_, err := owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('timezone', 'Europe/Istanbul')`)
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
	assert.Equal(t, map[string]string{"timezone": "Europe/Istanbul", "last_summary_at": "2026-10-08T00:00:00Z"}, got)
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

func TestOwnerReadsNotificationsAndRemindersButChangesNeither(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_n13_owner")
	signer := d.As(t, "vendor_signer", "t_n13_signer")
	issue(t, signer, "LIC-N13", "Iota")
	_, err := d.Owner.Exec(ctx, `INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N13', 90)`)
	require.NoError(t, err)

	var n int
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM notifications`).Scan(&n))
	assert.Equal(t, 1, n)
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM notification_reads`).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM reminders`).Scan(&n))
	assert.Equal(t, 1, n)
	for _, q := range []string{
		`UPDATE notifications SET title = 'x'`,
		`DELETE FROM notifications`,
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'owner', 'own:1')`,
		`INSERT INTO notification_reads (notification_id, user_id) VALUES (1, 1)`,
		`INSERT INTO reminders (license_id, days_before) VALUES ('LIC-N13', 60)`,
		`SELECT notify_prune(now())`,
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
		`SELECT id FROM web_users`,
		`SELECT * FROM notification_reads`,
		`UPDATE notifications SET body = 'x'`,
		`UPDATE notifications SET title = 'x'`,
		`DELETE FROM notifications`,
		`INSERT INTO notifications (kind, title, audience, dedupe_key, created_at) VALUES ('k', 't', 'owner', 'n14:old', now() - interval '1 year')`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
	for _, q := range []string{
		`SELECT id, name FROM customers`,
		`SELECT at, actor, action, subject FROM audit`,
		`SELECT id, customer_id, status, requested_by, requested_at FROM license_requests`,
		`SELECT name, disabled_at FROM web_users`,
		`SELECT * FROM notifications`,
	} {
		_, err := nt.Exec(ctx, q)
		require.NoError(t, err, q)
	}
}
