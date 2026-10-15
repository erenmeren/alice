//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
)

func TestActorSettingIsHonoredOnlyForTheWebServiceLogin(t *testing.T) {
	d := vpgtest.New(t)
	web := d.As(t, "vendor_web", "t_web_svc")
	sales := d.As(t, "vendor_sales", "t_sales_impostor")

	actor := func(p *pgxpool.Pool, setting string) string { return actorWith(t, p, setting) }
	assert.Equal(t, "web:ayse", actor(web, "ayse"))
	assert.Equal(t, "t_sales_impostor", actor(sales, "ayse"))
}

// actorWith returns vendor_actor() in a transaction of p in which vendor.actor is setting.
func actorWith(t *testing.T, p *pgxpool.Pool, setting string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', $1, true)`, setting)
	require.NoError(t, err)
	var a string
	require.NoError(t, tx.QueryRow(ctx, `SELECT vendor_actor()`).Scan(&a))
	return a
}

// Only logins that inherit vendor_web may act for a person. A superuser, a login that holds
// vendor_web without INHERIT (such as the PostgreSQL 16 CREATEROLE login that ran the migration,
// which gets an ADMIN-only grant), the owner and the signer all stay themselves.
func TestActorSettingIsIgnoredForEveryOtherLogin(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()

	var super string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT session_user`).Scan(&super))
	assert.Equal(t, super, actorWith(t, d.Owner, "ayse"), "superuser")

	for _, c := range []struct{ login, grant string }{
		{"t_actor_noinherit", "WITH INHERIT FALSE, SET FALSE"},
		{"t_actor_adminonly", "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"},
	} {
		_, err := d.Owner.Exec(ctx, `CREATE ROLE `+c.login+` LOGIN PASSWORD '`+vpgtest.AsPassword+`'`)
		require.NoError(t, err)
		_, err = d.Owner.Exec(ctx, `GRANT vendor_web TO `+c.login+` `+c.grant)
		require.NoError(t, err)
		// Such a login does not inherit vendor_sales' EXECUTE; the migration login can call the
		// function because it owns it. Grant it directly so the function's own check is what is tested.
		_, err = d.Owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION vendor_actor() TO `+c.login)
		require.NoError(t, err)
		p := d.Connect(t, c.login)
		assert.Equal(t, c.login, actorWith(t, p, "ayse"), c.grant)
	}

	assert.Equal(t, "t_actor_owner", actorWith(t, d.As(t, "vendor_owner", "t_actor_owner"), "ayse"), "owner")
	assert.Equal(t, "t_actor_signer", actorWith(t, d.As(t, "vendor_signer", "t_actor_signer"), "ayse"), "signer")
}

func TestMalformedActorFallsBackToTheLogin(t *testing.T) {
	d := vpgtest.New(t)
	web := d.As(t, "vendor_web", "t_web_badactor")
	assert.Equal(t, "web:"+strings.Repeat("a", 64), actorWith(t, web, strings.Repeat("a", 64)))
	for _, bad := range []string{strings.Repeat("a", 65), "a:b", "", "web:ayse", "a b", "ayse\n"} {
		assert.Equal(t, "t_web_badactor", actorWith(t, web, bad), "%q", bad)
	}
}

func TestWebServiceActsAsThePersonInRowsAndAudit(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc2")

	var cid int64
	tx, err := web.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctx, `INSERT INTO customers (name) VALUES ('Acme') RETURNING id`).Scan(&cid))
	var by string
	require.NoError(t, tx.QueryRow(ctx, `SELECT created_by FROM customers WHERE id = $1`, cid).Scan(&by))
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, "web:ayse", by)

	var actor string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor FROM audit WHERE action = 'customer.add'`).Scan(&actor))
	assert.Equal(t, "web:ayse", actor)
}

// asPerson runs fn in a transaction of the web service acting as person.
func asPerson(t *testing.T, p *pgxpool.Pool, person string, fn func(pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', $1, true)`, person)
	require.NoError(t, err)
	fn(tx)
	require.NoError(t, tx.Commit(ctx))
}

func TestWebUserCannotCancelAnotherWebUsersRequest(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc3")

	var reqID int64
	asPerson(t, web, "ayse", func(tx pgx.Tx) {
		var cid int64
		require.NoError(t, tx.QueryRow(ctx, `INSERT INTO customers (name) VALUES ('Acme') RETURNING id`).Scan(&cid))
		require.NoError(t, tx.QueryRow(ctx,
			`INSERT INTO license_requests (customer_id, installation, targets) VALUES ($1, $2, 5) RETURNING id`,
			cid, goodInstallation).Scan(&reqID))
	})

	asPerson(t, web, "mehmet", func(tx pgx.Tx) {
		ct, err := tx.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, reqID)
		require.NoError(t, err)
		assert.EqualValues(t, 0, ct.RowsAffected())
	})
	asPerson(t, web, "ayse", func(tx pgx.Tx) {
		ct, err := tx.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, reqID)
		require.NoError(t, err)
		assert.EqualValues(t, 1, ct.RowsAffected())
	})
}

func TestWebServiceHasNoSigningOrAuditPrivileges(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc4")

	denied := func(name string, err error) {
		t.Helper()
		var pe *pgconn.PgError
		require.Error(t, err, name)
		require.True(t, errors.As(err, &pe), name)
		assert.Equal(t, "42501", pe.Code, name)
	}
	_, err := web.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at, valid_from, valid_until, targets, file, file_sha256)
		VALUES ('x', 1, 1, 'x', 'k', now(), now(), now(), 1, 'x', 'x')`)
	denied("licenses insert", err)
	_, err = web.Exec(ctx, `SELECT * FROM audit`)
	denied("audit select", err)
	_, err = web.Exec(ctx, `SELECT audit_append('x', 'y', '{}'::jsonb)`)
	denied("audit_append", err)
	_, err = web.Exec(ctx, `SELECT audit_verify()`)
	denied("audit_verify", err)
}

func TestWebLoginAuditRowNamesThePerson(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc5")

	_, err := d.Owner.Exec(ctx, `INSERT INTO web_users (name) VALUES ('ayse')`)
	require.NoError(t, err)
	_, err = web.Exec(ctx, `SELECT web_audit_login('ayse')`)
	require.NoError(t, err)

	var actor, subject string
	require.NoError(t, d.Owner.QueryRow(ctx,
		`SELECT actor, subject FROM audit WHERE action = 'web.login'`).Scan(&actor, &subject))
	assert.Equal(t, "t_web_svc5", actor)
	assert.Equal(t, "ayse", subject)
}

func TestWebServiceCannotRewriteCredentialsOrCodes(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc6")
	var uid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO web_users (name) VALUES ('ayse') RETURNING id`).Scan(&uid))
	_, err := d.Owner.Exec(ctx, `INSERT INTO web_credentials (credential_id, user_id, credential) VALUES ('\x01', $1, '{}')`, uid)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO web_enrollments (token_hash, user_id, expires_at) VALUES ('h', $1, now())`, uid)
	require.NoError(t, err)

	for name, q := range map[string]string{
		"credential owner":  `UPDATE web_credentials SET user_id = user_id`,
		"enrollment expiry": `UPDATE web_enrollments SET expires_at = now() + interval '1 year'`,
		"enrollment user":   `UPDATE web_enrollments SET user_id = user_id`,
		"session expiry":    `UPDATE web_sessions SET expires_at = now()`,
		"web user":          `UPDATE web_users SET disabled_at = NULL`,
		"credential delete": `DELETE FROM web_credentials`,
		"enrollment insert": `INSERT INTO web_enrollments (token_hash, user_id, expires_at) VALUES ('x', 1, now())`,
	} {
		_, err := web.Exec(ctx, q)
		var pe *pgconn.PgError
		require.True(t, errors.As(err, &pe), "%s: %v", name, err)
		assert.Equal(t, "42501", pe.Code, name)
	}
	// The columns the service does update stay writable.
	_, err = web.Exec(ctx, `UPDATE web_credentials SET credential = '{"a":1}', last_used_at = now()`)
	require.NoError(t, err)
	_, err = web.Exec(ctx, `UPDATE web_enrollments SET used_at = now()`)
	require.NoError(t, err)
}

func TestWebLoginAuditNeedsAnEnabledUser(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc7")
	_, err := d.Owner.Exec(ctx, `INSERT INTO web_users (name, disabled_at) VALUES ('gone', now())`)
	require.NoError(t, err)
	for _, who := range []string{"nobody", "gone"} {
		_, err := web.Exec(ctx, `SELECT web_audit_login($1)`, who)
		require.NoError(t, err, who)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'web.login'`).Scan(&n))
	assert.Zero(t, n)
}

func TestWebUserAuditRowsNameTheUser(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	var uid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO web_users (name) VALUES ('ayse') RETURNING id`).Scan(&uid))
	_, err := d.Owner.Exec(ctx, `INSERT INTO web_enrollments (token_hash, user_id, expires_at) VALUES ('h', $1, now())`, uid)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO web_credentials (credential_id, user_id, credential) VALUES ('\x01', $1, '{}')`, uid)
	require.NoError(t, err)
	for _, action := range []string{"webuser.invite", "webuser.passkey_add"} {
		var subject string
		var gotID int64
		require.NoError(t, d.Owner.QueryRow(ctx,
			`SELECT subject, (details->>'user_id')::bigint FROM audit WHERE action = $1`, action).Scan(&subject, &gotID), action)
		assert.Equal(t, "ayse", subject, action)
		assert.Equal(t, uid, gotID, action)
	}
}
