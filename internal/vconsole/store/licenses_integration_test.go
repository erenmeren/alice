//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

// seedLicense inserts a request and an issued license row as the database owner (the signer is not
// needed to test listing).
func seedLicense(t *testing.T, d *vpgtest.DB, customerID int64, id string, until time.Time, revoked bool) {
	t.Helper()
	ctx := context.Background()
	var reqID int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets)
		VALUES ($1, $2, 5) RETURNING id`, customerID, license.NewInstallationID()).Scan(&reqID))
	_, err := d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256, revoked_at)
		VALUES ($1, $2, $3, 'inst', 'key1', $4, $4, $5, 5, 'bytes', 'sha', CASE WHEN $6 THEN $4::timestamptz END)`,
		id, reqID, customerID, now.Add(-24*time.Hour), until, revoked)
	require.NoError(t, err)
}

func TestListLicensesOrdersByEndDateAndFilters(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_lic")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Lic Ltd"})
	require.NoError(t, err)
	day := 24 * time.Hour
	seedLicense(t, d, cid, "L-200", now.Add(200*day), false)
	seedLicense(t, d, cid, "L-10", now.Add(10*day), false)
	seedLicense(t, d, cid, "L-50", now.Add(50*day), false)
	seedLicense(t, d, cid, "L-REVOKED", now.Add(20*day), true)
	seedLicense(t, d, cid, "L-ENDED", now.Add(-5*day), false)

	ids := func(rows []store.LicenseRow) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r.LicenseID)
		}
		return out
	}
	soon, err := store.ListLicenses(ctx, sales, now, 90, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"L-10", "L-50"}, ids(soon))

	withEnded, err := store.ListLicenses(ctx, sales, now, 90, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"L-ENDED", "L-10", "L-50"}, ids(withEnded))

	all, err := store.ListLicenses(ctx, sales, now, 0, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"L-ENDED", "L-10", "L-REVOKED", "L-50", "L-200"}, ids(all))
	for _, r := range all {
		assert.Equal(t, "Lic Ltd", r.Customer)
		assert.Equal(t, 5, r.Targets)
		assert.Equal(t, "key1", r.KeyID)
		if r.LicenseID == "L-REVOKED" {
			assert.NotNil(t, r.RevokedAt)
		} else {
			assert.Nil(t, r.RevokedAt)
		}
	}
}

func TestListCustomersSorted(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_cust")
	for _, n := range []string{"beta", "Alpha", "Gamma"} {
		_, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: n, Contact: "c-" + n})
		require.NoError(t, err)
	}
	got, err := store.ListCustomers(ctx, sales)
	require.NoError(t, err)
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	assert.Equal(t, []string{"Alpha", "beta", "Gamma"}, names)
	assert.Equal(t, "c-Alpha", got[0].Contact)
}
