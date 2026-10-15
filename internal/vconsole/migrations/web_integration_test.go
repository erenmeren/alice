//go:build integration

package migrations_test

import (
	"context"
	"errors"
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
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc")
	sales := d.As(t, "vendor_sales", "t_sales_impostor")

	actor := func(p *pgxpool.Pool) string {
		tx, err := p.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`)
		require.NoError(t, err)
		var a string
		require.NoError(t, tx.QueryRow(ctx, `SELECT vendor_actor()`).Scan(&a))
		return a
	}
	assert.Equal(t, "web:ayse", actor(web))
	assert.Equal(t, "t_sales_impostor", actor(sales))
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
