//go:build integration

package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func TestCustomerNamesAreNormalizedAndUnique(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_a")
	_, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Çelik A.Ş."})
	require.NoError(t, err)
	// Same name: decomposed Unicode, extra spaces, other case.
	_, err = store.AddCustomer(ctx, sales, store.NewCustomer{Name: "  Çelik a.ş. "})
	assert.ErrorIs(t, err, store.ErrDuplicateCustomer)
}

func TestAddRequestStoresCanonicalInstallationAndAudits(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_b")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Acme Ltd"})
	require.NoError(t, err)
	inst := license.NewInstallationID()
	id, err := store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: " " + inst + " ",
		Targets: 5, Features: []string{" ssh ", ""}}, now)
	require.NoError(t, err)

	got, err := store.GetRequest(ctx, sales, id)
	require.NoError(t, err)
	assert.Equal(t, inst, got.Installation)
	assert.Equal(t, "Acme Ltd", got.Customer)
	assert.Equal(t, 12, got.Months)
	assert.Equal(t, []string{"ssh"}, got.Features)
	assert.Equal(t, "open", got.Status)
	assert.Equal(t, "t_store_b", got.RequestedBy)
	require.NoError(t, audit.Check(ctx, d.Owner))
}

func TestAddRequestRefusesWhatCouldNeverBeSigned(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_c")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Beta Ltd"})
	require.NoError(t, err)
	valid := license.NewInstallationID()

	for name, r := range map[string]store.NewRequest{
		"bad installation id": {CustomerID: cid, Installation: "ALICE-AAAAA-AAAAA", Targets: 5},
		"zero targets":        {CustomerID: cid, Installation: valid, Targets: 0},
		"too many months":     {CustomerID: cid, Installation: valid, Targets: 5, Months: 61},
		"start long ago":      {CustomerID: cid, Installation: valid, Targets: 5, From: "2020-01-01"},
		"unknown customer":    {CustomerID: 9999, Installation: valid, Targets: 5},
	} {
		_, err := store.AddRequest(ctx, sales, r, now)
		assert.Error(t, err, name)
	}
	list, err := store.ListRequests(ctx, sales, "")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestListRequestsFiltersByStatus(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_d")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Gamma Ltd"})
	require.NoError(t, err)
	a, err := store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: license.NewInstallationID(), Targets: 1}, now)
	require.NoError(t, err)
	_, err = store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: license.NewInstallationID(), Targets: 2}, now)
	require.NoError(t, err)
	_, err = sales.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, a)
	require.NoError(t, err)

	open, err := store.ListRequests(ctx, sales, "open")
	require.NoError(t, err)
	assert.Len(t, open, 1)
	all, err := store.ListRequests(ctx, sales, "")
	require.NoError(t, err)
	assert.Len(t, all, 2)
}
