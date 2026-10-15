//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
)

const goodInstallation = "ALICE-TESTX-AAAAA" // only length matters at this layer

func addCustomer(t *testing.T, p *pgxpool.Pool, name string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, p.QueryRow(context.Background(),
		`INSERT INTO customers (name) VALUES ($1) RETURNING id`, name).Scan(&id))
	return id
}

func addRequest(t *testing.T, p *pgxpool.Pool, customer int64) (int64, error) {
	t.Helper()
	var id int64
	err := p.QueryRow(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets) VALUES ($1, $2, 5) RETURNING id`,
		customer, goodInstallation).Scan(&id)
	return id, err
}

func TestSalesCanCreateCustomersAndRequests(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_a")
	c := addCustomer(t, sales, "Acme Ltd")
	id, err := addRequest(t, sales, c)
	require.NoError(t, err)

	var by, status string
	require.NoError(t, sales.QueryRow(context.Background(),
		`SELECT requested_by, status FROM license_requests WHERE id = $1`, id).Scan(&by, &status))
	assert.Equal(t, "t_sales_a", by)
	assert.Equal(t, "open", status)
}

func TestSalesCannotForgeTheRequester(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_b")
	c := addCustomer(t, sales, "Beta Ltd")
	_, err := sales.Exec(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets, requested_by) VALUES ($1, $2, 5, 'someone_else')`,
		c, goodInstallation)
	assert.Error(t, err)
	_, err = sales.Exec(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets, status) VALUES ($1, $2, 5, 'signed')`,
		c, goodInstallation)
	assert.Error(t, err)
}

func TestSalesChangeOnlyTheirOwnOpenRequestsAndOnlyCancel(t *testing.T) {
	d := vpgtest.New(t)
	a := d.As(t, "vendor_sales", "t_sales_c1")
	b := d.As(t, "vendor_sales", "t_sales_c2")
	c := addCustomer(t, a, "Gamma Ltd")
	id, err := addRequest(t, a, c)
	require.NoError(t, err)
	ctx := context.Background()

	// Someone else's request: zero rows affected.
	tag, err := b.Exec(ctx, `UPDATE license_requests SET targets = 99 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 0, tag.RowsAffected())

	// Own request may be edited while open.
	tag, err = a.Exec(ctx, `UPDATE license_requests SET targets = 7 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, tag.RowsAffected())

	// ... but may not be marked signed.
	_, err = a.Exec(ctx, `UPDATE license_requests SET status = 'signed' WHERE id = $1`, id)
	assert.Error(t, err)

	// ... and may be cancelled; after that it is no longer editable.
	_, err = a.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, id)
	require.NoError(t, err)
	tag, err = a.Exec(ctx, `UPDATE license_requests SET targets = 8 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 0, tag.RowsAffected())
}

func TestSalesCannotWriteLicensesOrReadAudit(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_d")
	ctx := context.Background()
	_, err := sales.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-1', 1, 1, 'x', 'vk-1', now(), now(), now(), 1, '\x00', 'x')`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `SELECT * FROM audit`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `SELECT audit_verify()`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `INSERT INTO audit (seq, at, actor, action, subject, details, prev_hash, hash)
		VALUES (1, now(), 'x', 'x', 'x', '{}', 'x', 'x')`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `UPDATE customers SET name = 'x'`)
	assert.Error(t, err, "only signers may change a customer")
}

func TestSalesMaySeeLicensesButOnlyOwnersVerifyAudit(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_e")
	owner := d.As(t, "vendor_owner", "t_owner_e")
	ctx := context.Background()
	_, err := sales.Exec(ctx, `SELECT count(*) FROM licenses`)
	assert.NoError(t, err)
	var bad int64
	require.NoError(t, owner.QueryRow(ctx, `SELECT audit_verify()`).Scan(&bad))
	assert.EqualValues(t, 0, bad)
}

func TestOnlyOwnersRevokeAndNothingElseChanges(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_signer_f")
	owner := d.As(t, "vendor_owner", "t_owner_f")
	c := addCustomer(t, signer, "Delta Ltd")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-F', $1, $2, 'x', 'vk-1', now(), now(), now(), 1, '\x00', 'x')`, rid, c)
	require.NoError(t, err)

	_, err = signer.Exec(ctx, `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "a signer may not revoke")
	_, err = owner.Exec(ctx, `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-F'`)
	assert.NoError(t, err)
	_, err = owner.Exec(ctx, `UPDATE licenses SET targets = 1000 WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "not even an owner changes the content of a license")
	_, err = d.Owner.Exec(ctx, `UPDATE licenses SET targets = 1000 WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "the guard trigger also stops the migration role")
	_, err = d.Owner.Exec(ctx, `DELETE FROM licenses WHERE license_id = 'LIC-F'`)
	assert.Error(t, err)
}

// A person cannot hide behind a group role: SET ROLE to the group they belong to changes
// current_user, but the record names the login.
func TestTheLoginIsRecordedEvenAfterSetRoleToTheGroup(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	pool := d.As(t, "vendor_signer", "t_signer_h")
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `SET ROLE vendor_signer`)
	require.NoError(t, err)

	var by string
	require.NoError(t, conn.QueryRow(ctx, `INSERT INTO customers (name) VALUES ('Hidden Ltd') RETURNING created_by`).Scan(&by))
	assert.Equal(t, "t_signer_h", by)
	var actor string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor FROM audit WHERE action = 'customer.add'`).Scan(&actor))
	assert.Equal(t, "t_signer_h", actor)
}

// Every change to customers, requests and licenses leaves an audit row in the same statement, whatever
// client made it; no client has to remember to write one.
func TestEveryWriteIsAudited(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_sales_i")
	signer := d.As(t, "vendor_signer", "t_signer_i")
	owner := d.As(t, "vendor_owner", "t_owner_i")

	c := addCustomer(t, sales, "Audited Ltd")
	rid, err := addRequest(t, sales, c)
	require.NoError(t, err)
	_, err = sales.Exec(ctx, `UPDATE license_requests SET targets = 9 WHERE id = $1`, rid)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-I', $1, $2, 'x', 'vk-1', now(), now(), now(), 1, '\x00', 'x')`, rid, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `UPDATE license_requests SET status = 'signed' WHERE id = $1`, rid)
	require.NoError(t, err)
	_, err = owner.Exec(ctx, `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-I'`)
	require.NoError(t, err)

	rows, err := d.Owner.Query(ctx, `SELECT action, actor FROM audit ORDER BY seq`)
	require.NoError(t, err)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, actor string
		require.NoError(t, rows.Scan(&action, &actor))
		got = append(got, action+":"+actor)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{
		"customer.add:t_sales_i", "request.add:t_sales_i", "request.edit:t_sales_i",
		"license.issue:t_signer_i", "request.signed:t_signer_i", "license.revoke:t_owner_i",
	}, got)
	var bad int64
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT audit_verify()`).Scan(&bad))
	assert.EqualValues(t, 0, bad)
}

func TestNoLoginCanWriteAuditRowsByHand(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for i, group := range []string{"vendor_sales", "vendor_signer", "vendor_owner"} {
		p := d.As(t, group, "t_hand_"+group)
		_, err := p.Exec(ctx, `SELECT audit_append('license.issue', 'LIC-FAKE', '{}')`)
		assert.Error(t, err, "%d %s", i, group)
	}
}
