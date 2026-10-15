//go:build integration

package migrations_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/migrations"
	"alice/internal/vconsole/vpgtest"
)

// issuedNotice returns the title and body of the issuance notification for license id.
func issuedNotice(t *testing.T, d *vpgtest.DB, id string) (string, string) {
	t.Helper()
	var title, body string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT title, body FROM notifications WHERE kind = 'license.issued' AND subject = $1`, id).Scan(&title, &body))
	return title, body
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

// webUser creates a web user through the migration login and returns its id.
func webUser(t *testing.T, d *vpgtest.DB, name, role string, disabled bool) int64 {
	t.Helper()
	var id int64
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`INSERT INTO web_users (name, role, disabled_at) VALUES ($1, $2, CASE WHEN $3 THEN now() END) RETURNING id`,
		name, role, disabled).Scan(&id))
	return id
}

// notice inserts a notification through the migration login and returns its id.
func notice(t *testing.T, d *vpgtest.DB, audience, target, key string) int64 {
	t.Helper()
	var id int64
	var tgt *string
	if target != "" {
		tgt = &target
	}
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`INSERT INTO notifications (kind, title, body, audience, target_user, dedupe_key) VALUES ('test', $1, 'b', $2, $3, $1) RETURNING id`,
		key, audience, tgt).Scan(&id))
	return id
}

// visible returns the ids web_notifications gives the user, newest first.
func visible(t *testing.T, web *pgxpool.Pool, uid int64, unreadOnly bool) []int64 {
	t.Helper()
	rows, err := web.Query(context.Background(), `SELECT id FROM web_notifications($1, 100, $2)`, uid, unreadOnly)
	require.NoError(t, err)
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}

func unread(t *testing.T, web *pgxpool.Pool, uid int64) int64 {
	t.Helper()
	var n int64
	require.NoError(t, web.QueryRow(context.Background(), `SELECT web_unread_count($1)`, uid).Scan(&n))
	return n
}

func TestIssuingALicenseCreatesAnOwnerNotification(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_nt1_signer")
	c := addCustomer(t, signer, "Acme Corp")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-NT1', $1, $2, 'ALICE-SECRET-INSTALL', 'vk-77', now(),
		'2026-01-02T03:04:05Z', '2027-01-02T03:04:05Z', 3, '\xdeadbeef', 'x')`, rid, c)
	require.NoError(t, err)

	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM notifications`).Scan(&n))
	assert.Equal(t, 1, n)
	var kind, severity, audience, subject, key, title, body string
	var target *string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT kind, severity, audience, target_user, subject, dedupe_key, title, body
		FROM notifications`).Scan(&kind, &severity, &audience, &target, &subject, &key, &title, &body))
	assert.Equal(t, "license.issued", kind)
	assert.Equal(t, "info", severity)
	assert.Equal(t, "owner", audience)
	assert.Nil(t, target)
	assert.Equal(t, "LIC-NT1", subject)
	assert.Equal(t, "issued:LIC-NT1", key)
	assert.Contains(t, title, "Acme Corp")
	assert.Contains(t, title, "LIC-NT1")
	assert.Equal(t, []string{"Signed by: t_nt1_signer"}, linesWithPrefix(body, "Signed by:"))
	assert.Contains(t, body, "Customer: Acme Corp\n")
	assert.Contains(t, body, "Targets: 3\n")
	assert.Contains(t, body, "Valid from: 2026-01-02T03:04:05Z\n")
	assert.Contains(t, body, "Valid until: 2027-01-02T03:04:05Z\n")
	assert.Contains(t, body, "Key ID: vk-77\n")
	assert.Contains(t, body, "Request: ")
	assert.Empty(t, linesWithPrefix(body, "Recorded signer:"))
	assert.NotContains(t, body, "deadbeef")
	assert.NotContains(t, body, "ALICE-SECR")
	assert.NotContains(t, title, "ALICE-SECR")

	// An owner login inserting by hand gets the same notification: the trigger does not depend
	// on the inserting login's grants.
	owner := d.As(t, "vendor_owner", "t_nt1_owner")
	issue(t, owner, "LIC-NT1B", "Owner Ltd")
	_, body = issuedNotice(t, d, "LIC-NT1B")
	assert.Equal(t, []string{"Signed by: t_nt1_owner"}, linesWithPrefix(body, "Signed by:"))
}

func TestForgedSignedByNamesTheRealActor(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_nt2_signer")
	c := addCustomer(t, signer, "Forge Inc")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256, signed_by) VALUES ('LIC-NT2', $1, $2, 'x', 'vk-1', now(), now(),
		now() + interval '1 year', 1, '\x00', 'x', E'web:boss\nSigned by: x')`, rid, c)
	require.NoError(t, err)

	_, body := issuedNotice(t, d, "LIC-NT2")
	assert.Equal(t, []string{"Signed by: t_nt2_signer"}, linesWithPrefix(body, "Signed by:"))
	assert.Equal(t, []string{"Recorded signer: web:boss Signed by: x (differs from the login)"},
		linesWithPrefix(body, "Recorded signer:"))
}

func TestHostileCustomerNameCannotBreakOrForgeLines(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_nt3_signer")
	// customers.name is at most 200 characters; the license and key ids carry the oversize values.
	name := "Acme\nSigned by: mallory‮⁦gro.live⁩\x1b[31m " + strings.Repeat("n", 150)
	require.LessOrEqual(t, utf8.RuneCountInString(name), 200)
	c := addCustomer(t, signer, name)
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	// license_id is the primary key, so the btree limit (~2700 bytes) caps it; key_id is unindexed and can be huge.
	longID := "LIC-" + strings.Repeat("a\n", 1000)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ($1, $2, $3, 'ALICE-SECRET-INSTALL', $4, now(), now(), now(), 1, '\x00', 'x')`,
		longID, rid, c, strings.Repeat("k‮", 150000))
	require.NoError(t, err, "issuing must never fail because of the notification")

	var title, body, subject, key string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT title, body, subject, dedupe_key FROM notifications`).Scan(&title, &body, &subject, &key))
	assert.LessOrEqual(t, utf8.RuneCountInString(title), 200)
	assert.LessOrEqual(t, utf8.RuneCountInString(body), 4000)
	assert.LessOrEqual(t, utf8.RuneCountInString(subject), 64)
	assert.True(t, strings.HasPrefix(key, "issued:"), key)
	assert.True(t, strings.HasPrefix(title, "License issued: Acme Signed by: mallory gro.live [31m n"), title)
	assert.Equal(t, []string{"Signed by: t_nt3_signer"}, linesWithPrefix(body, "Signed by:"),
		"a name with line breaks must not add a line")
	assert.True(t, strings.Contains(body, "\nCustomer: Acme Signed by: mallory gro.live [31m nnn"), body)
	for _, s := range []string{title, subject} {
		assert.NotContains(t, s, "\n")
		assert.NotContains(t, s, "\r")
	}
	for _, s := range []string{title, body, subject} {
		for _, bad := range []string{"‮", "⁦", "⁩", " ", "\x1b"} {
			assert.NotContains(t, s, bad)
		}
		assert.NotContains(t, s, "ALICE-SECR")
	}
}

func TestWebSeesOnlyItsOwnAudience(t *testing.T) {
	d := vpgtest.New(t)
	web := d.As(t, "vendor_web", "t_nt4_web")
	boss := webUser(t, d, "boss", "owner", false)
	ayse := webUser(t, d, "ayse", "sales", false)
	mehmet := webUser(t, d, "mehmet", "sales", false)
	gone := webUser(t, d, "gone", "owner", true)

	nOwner := notice(t, d, "owner", "", "k:owner")
	nSales := notice(t, d, "sales", "", "k:sales")
	nAyse := notice(t, d, "user", "Ayse", "k:ayse") // names match case-insensitively, as web_users.name is unique
	nMehmet := notice(t, d, "user", "mehmet", "k:mehmet")
	nBoss := notice(t, d, "user", "boss", "k:boss")

	assert.ElementsMatch(t, []int64{nOwner, nSales, nBoss}, visible(t, web, boss, false))
	assert.ElementsMatch(t, []int64{nSales, nAyse}, visible(t, web, ayse, false))
	assert.ElementsMatch(t, []int64{nSales, nMehmet}, visible(t, web, mehmet, false))
	assert.Empty(t, visible(t, web, gone, false), "a disabled user sees nothing")
	assert.Empty(t, visible(t, web, 999999, false), "an unknown id sees nothing")
	assert.EqualValues(t, 3, unread(t, web, boss))
	assert.EqualValues(t, 2, unread(t, web, ayse))
	assert.EqualValues(t, 0, unread(t, web, gone))
	assert.EqualValues(t, 0, unread(t, web, 999999))

	// Newest first, the limit is applied, and the columns the page needs are there.
	rows, err := web.Query(context.Background(),
		`SELECT id, kind, severity, title, body, audience, subject, created_at, read_at FROM web_notifications($1, 1, false)`, boss)
	require.NoError(t, err)
	var got []int64
	for rows.Next() {
		var id int64
		var kind, severity, title, body, audience, subject string
		var created, read any
		require.NoError(t, rows.Scan(&id, &kind, &severity, &title, &body, &audience, &subject, &created, &read))
		assert.Nil(t, read)
		got = append(got, id)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []int64{nBoss}, got)
}

func TestUnreadCountAndMarkRead(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_nt5_web")
	boss := webUser(t, d, "boss", "owner", false)
	ayse := webUser(t, d, "ayse", "sales", false)
	mehmet := webUser(t, d, "mehmet", "sales", false)
	gone := webUser(t, d, "gone", "sales", true)
	nOwner := notice(t, d, "owner", "", "k:owner")
	nSales := notice(t, d, "sales", "", "k:sales")
	nAyse := notice(t, d, "user", "ayse", "k:ayse")
	nMehmet := notice(t, d, "user", "mehmet", "k:mehmet")

	mark := func(uid, nid int64) bool {
		t.Helper()
		var ok bool
		require.NoError(t, web.QueryRow(ctx, `SELECT web_mark_read($1, $2)`, uid, nid).Scan(&ok))
		return ok
	}
	readsOf := func(uid int64) []int64 {
		t.Helper()
		rows, err := d.Owner.Query(ctx, `SELECT notification_id FROM notification_reads WHERE user_id = $1`, uid)
		require.NoError(t, err)
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		return ids
	}

	assert.True(t, mark(ayse, nAyse))
	assert.True(t, mark(ayse, nAyse), "marking twice is not an error")
	assert.EqualValues(t, 1, unread(t, web, ayse))
	assert.EqualValues(t, 2, unread(t, web, mehmet), "another user's count is unchanged")
	assert.Equal(t, []int64{nSales}, visible(t, web, ayse, true))

	// An invisible notification answers exactly like an unknown one and records nothing.
	assert.False(t, mark(ayse, nOwner))
	assert.False(t, mark(ayse, nMehmet))
	assert.False(t, mark(ayse, 999999))
	assert.False(t, mark(gone, nSales), "a disabled user marks nothing")
	assert.ElementsMatch(t, []int64{nAyse}, readsOf(ayse))
	assert.Empty(t, readsOf(gone))

	var n int64
	require.NoError(t, web.QueryRow(ctx, `SELECT web_mark_all_read($1)`, ayse).Scan(&n))
	assert.EqualValues(t, 1, n)
	assert.EqualValues(t, 0, unread(t, web, ayse))
	assert.ElementsMatch(t, []int64{nAyse, nSales}, readsOf(ayse), "mark-all-read touches only visible ones")
	assert.EqualValues(t, 2, unread(t, web, boss))
	assert.EqualValues(t, 2, unread(t, web, mehmet))
	require.NoError(t, web.QueryRow(ctx, `SELECT web_mark_all_read($1)`, gone).Scan(&n))
	assert.Zero(t, n)

	require.NoError(t, web.QueryRow(ctx, `SELECT web_mark_all_read($1)`, boss).Scan(&n))
	assert.EqualValues(t, 2, n)
	assert.ElementsMatch(t, []int64{nOwner, nSales}, readsOf(boss))
	var readAt any
	require.NoError(t, web.QueryRow(ctx, `SELECT read_at FROM web_notifications($1, 100, false) WHERE id = $2`, boss, nOwner).Scan(&readAt))
	assert.NotNil(t, readAt)
}

func TestWebServiceCannotWriteNotifications(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_nt6_web")
	uid := webUser(t, d, "ayse", "sales", false)
	nid := notice(t, d, "sales", "", "k:sales")
	for _, q := range []string{
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'sales', 'web:1')`,
		`UPDATE notifications SET title = 'x'`,
		`DELETE FROM notifications`,
		`SELECT * FROM notifications`,
		`SELECT * FROM notification_reads`,
		`INSERT INTO notification_reads (notification_id, user_id) VALUES (` + strconv.FormatInt(nid, 10) + `, ` + strconv.FormatInt(uid, 10) + `)`,
		`UPDATE notification_reads SET read_at = now()`,
		`DELETE FROM notification_reads`,
		`SELECT notify_prune(now())`,
	} {
		_, err := web.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
}

func TestSalesAndSignerCannotCallTheWebFunctions(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, g := range []string{"vendor_sales", "vendor_signer", "vendor_owner", "vendor_notifier"} {
		p := d.As(t, g, "t_nt7_"+g)
		for _, q := range []string{
			`SELECT * FROM web_notifications(1, 10, false)`,
			`SELECT web_unread_count(1)`,
			`SELECT web_mark_read(1, 1)`,
			`SELECT web_mark_all_read(1)`,
		} {
			_, err := p.Exec(ctx, q)
			require.Error(t, err, "%s: %s", g, q)
			assert.Equal(t, "42501", pgCode(t, err), "%s: %s", g, q)
		}
	}
}

func TestNotifierWritesNotificationsAndPrunes(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	nt := d.As(t, "vendor_notifier", "t_nt8_notifier")
	uid := webUser(t, d, "boss", "owner", false)

	var oldRead, oldUnread, newRead int64
	for _, c := range []struct {
		key string
		id  *int64
	}{{"k:old-read", &oldRead}, {"k:old-unread", &oldUnread}, {"k:new-read", &newRead}} {
		require.NoError(t, nt.QueryRow(ctx, `INSERT INTO notifications (kind, severity, title, body, audience, subject, dedupe_key)
			VALUES ('summary.weekly', 'info', 't', 'b', 'owner', '', $1) ON CONFLICT (dedupe_key) DO NOTHING RETURNING id`, c.key).Scan(c.id))
	}
	_, err := nt.Exec(ctx, `INSERT INTO notifications (kind, title, audience, target_user, dedupe_key) VALUES ('license.ending', 't', 'user', 'boss', 'k:user')`)
	require.NoError(t, err)
	for _, q := range []string{
		`UPDATE notifications SET title = 'x'`,
		`DELETE FROM notifications`,
		`TRUNCATE notifications`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}

	_, err = d.Owner.Exec(ctx, `UPDATE notifications SET created_at = now() - interval '200 days' WHERE id IN ($1, $2)`, oldRead, oldUnread)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO notification_reads (notification_id, user_id) VALUES ($1, $3), ($2, $3)`, oldRead, newRead, uid)
	require.NoError(t, err)

	var n int64
	require.NoError(t, nt.QueryRow(ctx, `SELECT notify_prune(now() - interval '180 days')`).Scan(&n))
	assert.EqualValues(t, 1, n)
	var left []int64
	rows, err := d.Owner.Query(ctx, `SELECT id FROM notifications WHERE dedupe_key LIKE 'k:%-%' ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		left = append(left, id)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []int64{oldUnread, newRead}, left)
	var reads int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM notification_reads WHERE notification_id = $1`, oldRead).Scan(&reads))
	assert.Zero(t, reads, "the read rows go with the notification")
	require.NoError(t, nt.QueryRow(ctx, `SELECT notify_prune(now() - interval '180 days')`).Scan(&n))
	assert.Zero(t, n)
}

func TestDedupeKeyIsUnique(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	nt := d.As(t, "vendor_notifier", "t_nt9_notifier")
	const ins = `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'owner', 'ending:LIC-1:90')`
	_, err := nt.Exec(ctx, ins)
	require.NoError(t, err)
	_, err = nt.Exec(ctx, ins)
	require.Error(t, err)
	assert.Equal(t, "23505", pgCode(t, err))
	ct, err := nt.Exec(ctx, ins+` ON CONFLICT (dedupe_key) DO NOTHING`)
	require.NoError(t, err)
	assert.Zero(t, ct.RowsAffected())

	for name, q := range map[string]string{
		"user without target": `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'user', 'c:1')`,
		"target without user": `INSERT INTO notifications (kind, title, audience, target_user, dedupe_key) VALUES ('k', 't', 'owner', 'ayse', 'c:2')`,
		"two-line title":      `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', E't\nx', 'owner', 'c:3')`,
		"empty title":         `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', '', 'owner', 'c:4')`,
		"long title":          `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', repeat('t', 201), 'owner', 'c:5')`,
		"long body":           `INSERT INTO notifications (kind, title, body, audience, dedupe_key) VALUES ('k', 't', repeat('b', 4001), 'owner', 'c:6')`,
		"bad severity":        `INSERT INTO notifications (kind, severity, title, audience, dedupe_key) VALUES ('k', 'panic', 't', 'owner', 'c:7')`,
		"bad audience":        `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'everyone', 'c:8')`,
		"long subject":        `INSERT INTO notifications (kind, title, audience, subject, dedupe_key) VALUES ('k', 't', 'owner', repeat('s', 65), 'c:9')`,
		"empty dedupe key":    `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'owner', '')`,
		"malformed user name": `INSERT INTO notifications (kind, title, audience, target_user, dedupe_key) VALUES ('k', 't', 'user', 'a b', 'c:10')`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, name)
		assert.Equal(t, "23514", pgCode(t, err), name)
	}
}

func TestOwnerRoleOnlyThroughTheDatabase(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	owner := d.As(t, "vendor_owner", "t_nt10_owner")
	web := d.As(t, "vendor_web", "t_nt10_web")

	_, err := owner.Exec(ctx, `INSERT INTO web_users (name) VALUES ('ayse')`)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `INSERT INTO web_users (name, role) VALUES ('boss', 'owner')`)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `INSERT INTO web_users (name, role) VALUES ('eve', 'admin')`)
	require.Error(t, err)
	assert.Equal(t, "23514", pgCode(t, err))
	var role string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT role FROM web_users WHERE name = 'ayse'`).Scan(&role))
	assert.Equal(t, "sales", role)

	for _, who := range []struct{ name, role string }{{"ayse", "sales"}, {"boss", "owner"}} {
		var got string
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details->>'role' FROM audit WHERE action = 'webuser.add' AND subject = $1`,
			who.name).Scan(&got))
		assert.Equal(t, who.role, got, who.name)
	}

	for name, p := range map[string]*pgxpool.Pool{"web": web, "owner": owner} {
		_, err := p.Exec(ctx, `UPDATE web_users SET role = 'owner' WHERE name = 'ayse'`)
		require.Error(t, err, name)
		assert.Equal(t, "42501", pgCode(t, err), name)
	}
	_, err = web.Exec(ctx, `INSERT INTO web_users (name, role) VALUES ('mallory', 'owner')`)
	require.Error(t, err)
	assert.Equal(t, "42501", pgCode(t, err))
	_, err = owner.Exec(ctx, `UPDATE web_users SET disabled_at = now() WHERE name = 'ayse'`)
	require.NoError(t, err)

	// Only the migration login can change a role, and even that is audited.
	_, err = d.Owner.Exec(ctx, `UPDATE web_users SET role = 'owner' WHERE name = 'ayse'`)
	require.NoError(t, err)
	var from, to string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details->>'from', details->>'to' FROM audit WHERE action = 'webuser.role' AND subject = 'ayse'`).Scan(&from, &to))
	assert.Equal(t, "sales", from)
	assert.Equal(t, "owner", to)
	var v int64
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT audit_verify()`).Scan(&v))
	assert.Zero(t, v)
}

func TestNoMailObjectsRemain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	var gone bool
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT to_regclass('public.mail_outbox') IS NULL`).Scan(&gone))
	assert.True(t, gone, "mail_outbox")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace
		WHERE s.nspname = 'public' AND (p.proname ILIKE '%mail%' OR p.prosrc ILIKE '%mail%')`).Scan(&n))
	assert.Zero(t, n, "functions named after or writing mail")
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname ILIKE '%mail%'`).Scan(&n))
	assert.Zero(t, n, "mail triggers")
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND (column_name ILIKE '%mail%' OR column_name = 'to_addrs')`).Scan(&n))
	assert.Zero(t, n, "mail columns (web_users.email)")
	_, err := d.Owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'a@b.co')`)
	require.Error(t, err)
	assert.Equal(t, "23514", pgCode(t, err))
}

// The two edited migrations must still go down cleanly and come back up: Down drops exactly what
// Up created and restores what Up replaced.
func TestNotifyAndOpsMigrationsGoDownAndUpAgain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)

	_, err = p.DownTo(ctx, 2)
	require.NoError(t, err)
	for _, rel := range []string{"notifications", "notification_reads", "reminders", "vendor_settings"} {
		var gone bool
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT to_regclass($1) IS NULL`, "public."+rel).Scan(&gone))
		assert.True(t, gone, rel)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace
		WHERE s.nspname = 'public' AND p.proname IN ('web_notifications', 'web_unread_count', 'web_mark_read', 'web_mark_all_read',
		'notify_prune', 'notify_mark_summary', 'audit_head', 'vendor_clean_line', 'vendor_notify_license', 'vendor_notifications_for')`).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'web_users' AND column_name = 'role'`).Scan(&n))
	assert.Zero(t, n)
	// The 00002 audit trigger is back: webuser.add without details.
	_, err = d.Owner.Exec(ctx, `INSERT INTO web_users (name) VALUES ('down')`)
	require.NoError(t, err)
	var details string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details::text FROM audit WHERE action = 'webuser.add' AND subject = 'down'`).Scan(&details))
	assert.Equal(t, "{}", details)
	var src string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE proname = 'vendor_audit_licenses'`).Scan(&src))
	assert.NotContains(t, src, "vendor.reason")

	_, err = p.Up(ctx)
	require.NoError(t, err)
	signer := d.As(t, "vendor_signer", "t_nt11_signer")
	issue(t, signer, "LIC-NT11", "Updown")
	_, body := issuedNotice(t, d, "LIC-NT11")
	assert.Contains(t, body, "Signed by: t_nt11_signer")
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT role FROM web_users WHERE name = 'down'`).Scan(&details))
	assert.Equal(t, "sales", details)
}
