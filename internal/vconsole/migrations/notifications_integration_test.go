//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
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

// actorTx runs fn in a transaction of the web service in which vendor.actor is actor ("" sets
// none), the way the web service calls the notification functions (inside its actor transaction).
func actorTx(t *testing.T, web *pgxpool.Pool, actor string, fn func(pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := web.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	if actor != "" {
		_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', $1, true)`, actor)
		require.NoError(t, err)
	}
	fn(tx)
	require.NoError(t, tx.Commit(ctx))
}

// visible returns the ids web_notifications gives user uid when called acting as actor.
func visible(t *testing.T, web *pgxpool.Pool, actor string, uid int64, unreadOnly bool) []int64 {
	t.Helper()
	var ids []int64
	actorTx(t, web, actor, func(tx pgx.Tx) {
		rows, err := tx.Query(context.Background(), `SELECT id FROM web_notifications($1, 100, $2)`, uid, unreadOnly)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var id int64
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
	})
	return ids
}

// webScalar returns the single value of query, run by the web service acting as actor.
func webScalar[T any](t *testing.T, web *pgxpool.Pool, actor, query string, args ...any) T {
	t.Helper()
	var v T
	actorTx(t, web, actor, func(tx pgx.Tx) {
		require.NoError(t, tx.QueryRow(context.Background(), query, args...).Scan(&v))
	})
	return v
}

func unread(t *testing.T, web *pgxpool.Pool, actor string, uid int64) int64 {
	t.Helper()
	return webScalar[int64](t, web, actor, `SELECT web_unread_count($1)`, uid)
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
	name := "Acme\nSigned by: mallory\u202e\u2066gro.live\u2069\x1b[31m\u2028" + strings.Repeat("n", 150)
	require.LessOrEqual(t, utf8.RuneCountInString(name), 200)
	c := addCustomer(t, signer, name)
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	// license_id is the primary key, so the btree limit (~2700 bytes) caps it; key_id is unindexed and can be huge.
	longID := "LIC-" + strings.Repeat("a\n", 1000)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ($1, $2, $3, 'ALICE-SECRET-INSTALL', $4, now(), now(), now(), 1, '\x00', 'x')`,
		longID, rid, c, strings.Repeat("k\u202e", 150000))
	require.NoError(t, err, "issuing must never fail because of the notification")

	var title, body, subject, key string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT title, body, subject, dedupe_key FROM notifications`).Scan(&title, &body, &subject, &key))
	assert.LessOrEqual(t, utf8.RuneCountInString(title), 200)
	assert.LessOrEqual(t, utf8.RuneCountInString(body), 4000)
	assert.LessOrEqual(t, utf8.RuneCountInString(subject), 64)
	assert.True(t, strings.HasPrefix(key, "issued-sha256:"), key)
	assert.True(t, strings.HasPrefix(title, "License issued: Acme Signed by: mallory gro.live [31m n"), title)
	assert.Equal(t, []string{"Signed by: t_nt3_signer"}, linesWithPrefix(body, "Signed by:"),
		"a name with line breaks must not add a line")
	assert.True(t, strings.Contains(body, "\nCustomer: Acme Signed by: mallory gro.live [31m nnn"), body)
	for _, s := range []string{title, subject} {
		assert.NotContains(t, s, "\n")
		assert.NotContains(t, s, "\r")
	}
	for _, s := range []string{title, body, subject} {
		for _, bad := range []string{"\u202e", "\u2066", "\u2069", "\u2028", "\x1b"} {
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

	assert.ElementsMatch(t, []int64{nOwner, nSales, nBoss}, visible(t, web, "boss", boss, false))
	assert.ElementsMatch(t, []int64{nSales, nAyse}, visible(t, web, "ayse", ayse, false))
	assert.ElementsMatch(t, []int64{nSales, nMehmet}, visible(t, web, "mehmet", mehmet, false))
	assert.Empty(t, visible(t, web, "gone", gone, false), "a disabled user sees nothing")
	assert.Empty(t, visible(t, web, "ayse", 999999, false), "an unknown id sees nothing")
	assert.EqualValues(t, 3, unread(t, web, "boss", boss))
	assert.EqualValues(t, 2, unread(t, web, "ayse", ayse))
	assert.EqualValues(t, 0, unread(t, web, "gone", gone))
	assert.EqualValues(t, 0, unread(t, web, "ayse", 999999))

	// Newest first, the limit is applied, and the columns the page needs are there.
	var got []int64
	actorTx(t, web, "boss", func(tx pgx.Tx) {
		rows, err := tx.Query(context.Background(),
			`SELECT id, kind, severity, title, body, audience, subject, created_at, read_at FROM web_notifications($1, 1, false)`, boss)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var id int64
			var kind, severity, title, body, audience, subject string
			var created, read any
			require.NoError(t, rows.Scan(&id, &kind, &severity, &title, &body, &audience, &subject, &created, &read))
			assert.Nil(t, read)
			got = append(got, id)
		}
		require.NoError(t, rows.Err())
	})
	assert.Equal(t, []int64{nBoss}, got)

	// The database refuses another user's id: the acting person must be the user asked about.
	assert.Empty(t, visible(t, web, "ayse", boss, false), "ayse asking for boss's notifications")
	assert.EqualValues(t, 0, unread(t, web, "ayse", boss))
	assert.Empty(t, visible(t, web, "", ayse, false), "no vendor.actor")
	assert.EqualValues(t, 0, unread(t, web, "", ayse))
	assert.Empty(t, visible(t, web, "AYSE", ayse, false), "the actor names the stored user exactly")
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

	mark := func(actor string, uid, nid int64) bool {
		t.Helper()
		return webScalar[bool](t, web, actor, `SELECT web_mark_read($1, $2)`, uid, nid)
	}
	markAll := func(actor string, uid int64) int64 {
		t.Helper()
		return webScalar[int64](t, web, actor, `SELECT web_mark_all_read($1)`, uid)
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

	assert.True(t, mark("ayse", ayse, nAyse))
	assert.True(t, mark("ayse", ayse, nAyse), "marking twice is not an error")
	assert.EqualValues(t, 1, unread(t, web, "ayse", ayse))
	assert.EqualValues(t, 2, unread(t, web, "mehmet", mehmet), "another user's count is unchanged")
	assert.Equal(t, []int64{nSales}, visible(t, web, "ayse", ayse, true))

	// An invisible notification answers exactly like an unknown one and records nothing.
	assert.False(t, mark("ayse", ayse, nOwner))
	assert.False(t, mark("ayse", ayse, nMehmet))
	assert.False(t, mark("ayse", ayse, 999999))
	assert.False(t, mark("gone", gone, nSales), "a disabled user marks nothing")
	assert.ElementsMatch(t, []int64{nAyse}, readsOf(ayse))
	assert.Empty(t, readsOf(gone))

	// Acting as someone else, or as nobody, marks nothing.
	assert.False(t, mark("mehmet", ayse, nSales))
	assert.False(t, mark("", ayse, nSales))
	assert.Zero(t, markAll("mehmet", ayse))
	assert.Zero(t, markAll("", ayse))
	assert.ElementsMatch(t, []int64{nAyse}, readsOf(ayse))

	assert.EqualValues(t, 1, markAll("ayse", ayse))
	assert.EqualValues(t, 0, unread(t, web, "ayse", ayse))
	assert.ElementsMatch(t, []int64{nAyse, nSales}, readsOf(ayse), "mark-all-read touches only visible ones")
	assert.EqualValues(t, 2, unread(t, web, "boss", boss))
	assert.EqualValues(t, 2, unread(t, web, "mehmet", mehmet))
	assert.Zero(t, markAll("gone", gone))

	assert.EqualValues(t, 2, markAll("boss", boss))
	assert.ElementsMatch(t, []int64{nOwner, nSales}, readsOf(boss))
	readAt := webScalar[any](t, web, "boss", `SELECT read_at FROM web_notifications($1, 100, false) WHERE id = $2`, boss, nOwner)
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

// The notifier reads a web user's role (reminders skip a duplicate user notice for owners) and
// nothing else beyond name and disabled_at; it has no access to credentials or sessions.
func TestNotifierReadsWebUserRoleButNoOtherWebColumns(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	nt := d.As(t, "vendor_notifier", "t_nt12_notifier")
	webUser(t, d, "boss", "owner", false)

	var name, role string
	require.NoError(t, nt.QueryRow(ctx, `SELECT name, role FROM web_users WHERE disabled_at IS NULL`).Scan(&name, &role))
	assert.Equal(t, "boss", name)
	assert.Equal(t, "owner", role)
	for _, q := range []string{
		`SELECT id FROM web_users`,
		`SELECT created_by FROM web_users`,
		`SELECT created_at FROM web_users`,
		`SELECT * FROM web_users`,
		`SELECT * FROM web_credentials`,
		`SELECT * FROM web_sessions`,
		`UPDATE web_users SET role = 'sales'`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
}

// A long license id is keyed by its hash under a prefix of its own, so a license whose id is
// literally "sha256:<hash of the long id>" cannot take the long id's key and silence it.
func TestLongLicenseIDKeyCannotBeSilencedByAShortOne(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_nt13_signer")
	long := "LIC-" + strings.Repeat("L", 300)
	sum := sha256.Sum256([]byte(long))
	h := hex.EncodeToString(sum[:])
	issue(t, signer, "sha256:"+h, "Forger Ltd")
	issue(t, signer, long, "Victim Ltd")

	rows, err := d.Owner.Query(ctx, `SELECT dedupe_key FROM notifications WHERE kind = 'license.issued' ORDER BY id`)
	require.NoError(t, err)
	var keys []string
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		keys = append(keys, k)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"issued:sha256:" + h, "issued-sha256:" + h}, keys)
}

// The notifier cannot insert an issuance notification (or take an issued* key) ahead of the
// trigger, which would make the real one disappear through ON CONFLICT DO NOTHING.
func TestNotifierCannotPreemptIssuanceNotifications(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	nt := d.As(t, "vendor_notifier", "t_nt14_notifier")
	owner := d.As(t, "vendor_owner", "t_nt14_owner")
	signer := d.As(t, "vendor_signer", "t_nt14_signer")
	for _, q := range []string{
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('license.issued', 't', 'owner', 'x:1')`,
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('license.ending', 't', 'owner', 'issued:LIC-1')`,
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('license.ending', 't', 'owner', 'issued-sha256:ab')`,
		`INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('license.ending', 't', 'owner', 'issued:LIC-1') ON CONFLICT (dedupe_key) DO NOTHING`,
	} {
		_, err := nt.Exec(ctx, q)
		require.Error(t, err, q)
		assert.Equal(t, "42501", pgCode(t, err), q)
	}
	for _, key := range []string{"ending:LIC-1:90", "summary:2026-10-12", "unusual:2026-10-12"} {
		_, err := nt.Exec(ctx, `INSERT INTO notifications (kind, title, audience, dedupe_key) VALUES ('k', 't', 'owner', $1)
			ON CONFLICT (dedupe_key) DO NOTHING`, key)
		require.NoError(t, err, key)
	}
	issue(t, signer, "LIC-1", "Real Ltd")
	var n int
	require.NoError(t, nt.QueryRow(ctx, `SELECT count(*) FROM notifications`).Scan(&n))
	assert.Equal(t, 4, n, "the notifier still reads every row")
	require.NoError(t, owner.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE dedupe_key = 'issued:LIC-1' AND kind = 'license.issued'`).Scan(&n))
	assert.Equal(t, 1, n, "the trigger still writes, and the owner reads it")
}

func TestPruneNeverGoesBelowTheFloor(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	nt := d.As(t, "vendor_notifier", "t_nt15_notifier")
	uid := webUser(t, d, "boss", "owner", false)
	ages := map[string]string{"k:200": "200 days", "k:100": "100 days", "k:1": "1 day"}
	for key, age := range ages {
		id := notice(t, d, "owner", "", key)
		_, err := d.Owner.Exec(ctx, `UPDATE notifications SET created_at = now() - $2::interval WHERE id = $1`, id, age)
		require.NoError(t, err)
		_, err = d.Owner.Exec(ctx, `INSERT INTO notification_reads (notification_id, user_id) VALUES ($1, $2)`, id, uid)
		require.NoError(t, err)
	}
	var n int64
	require.NoError(t, nt.QueryRow(ctx, `SELECT notify_prune(NULL)`).Scan(&n))
	assert.Zero(t, n, "a NULL cutoff removes nothing")
	require.NoError(t, nt.QueryRow(ctx, `SELECT notify_prune('infinity')`).Scan(&n))
	assert.EqualValues(t, 1, n)
	var left []string
	rows, err := d.Owner.Query(ctx, `SELECT dedupe_key FROM notifications ORDER BY dedupe_key`)
	require.NoError(t, err)
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		left = append(left, k)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"k:1", "k:100"}, left)
}

// Invisible characters must not sit literally in the migrations, where a reader cannot see them:
// the SQL spells them as escapes. Comments are skipped; no exceptions exist today.
func TestMigrationSQLIsASCIIOutsideComments(t *testing.T) {
	allowed := map[string]bool{} // "file:line" of a deliberate exception
	files, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		b, err := fs.ReadFile(migrations.FS, f)
		require.NoError(t, err)
		for i, line := range strings.Split(string(b), "\n") {
			if c := strings.Index(line, "--"); c >= 0 {
				line = line[:c]
			}
			for _, r := range line {
				if r > 0x7f {
					where := f + ":" + strconv.Itoa(i+1)
					assert.True(t, allowed[where], "non-ASCII %U at %s", r, where)
				}
			}
		}
	}
}

// A notification pruned while web_mark_read or web_mark_all_read runs is skipped: no foreign key
// error reaches the web service, and the answer is the one for an unknown notification.
func TestMarkReadSurvivesAConcurrentPrune(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_nt16_web")
	uid := webUser(t, d, "ayse", "sales", false)

	gone := notice(t, d, "sales", "", "k:gone")
	_, err := d.Owner.Exec(ctx, `DELETE FROM notifications WHERE id = $1`, gone)
	require.NoError(t, err)
	assert.False(t, webScalar[bool](t, web, "ayse", `SELECT web_mark_read($1, $2)`, uid, gone))

	for i, q := range []string{`SELECT web_mark_read($1, $2)::int`, `SELECT web_mark_all_read($1)::int + 0 * $2`} {
		nid := notice(t, d, "sales", "", "k:race:"+strconv.Itoa(i))
		del, err := d.Owner.Begin(ctx)
		require.NoError(t, err)
		_, err = del.Exec(ctx, `DELETE FROM notifications WHERE id = $1`, nid)
		require.NoError(t, err)

		type result struct {
			v   int
			err error
		}
		done := make(chan result, 1)
		go func() {
			tx, err := web.Begin(ctx)
			if err != nil {
				done <- result{err: err}
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			var v int
			if _, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`); err == nil {
				err = tx.QueryRow(ctx, q, uid, nid).Scan(&v)
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			done <- result{v, err}
		}()
		require.Eventually(t, func() bool {
			var waiting int
			err := d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
			return err == nil && waiting > 0
		}, 10*time.Second, 10*time.Millisecond, "the mark call waits for the delete")
		require.NoError(t, del.Commit(ctx))
		r := <-done
		require.NoError(t, r.err, q)
		assert.Zero(t, r.v, q)
	}
}
