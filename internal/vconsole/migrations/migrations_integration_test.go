//go:build integration

package migrations_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

func TestSchemaHasTablesAndRoles(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, table := range []string{"customers", "license_requests", "licenses", "audit"} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&ok))
		assert.True(t, ok, table)
	}
	for _, role := range []string{"vendor_sales", "vendor_signer", "vendor_owner"} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1 AND NOT rolcanlogin)`, role).Scan(&ok))
		assert.True(t, ok, role)
	}
	// vendor_signer inherits vendor_sales, vendor_owner inherits vendor_signer.
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members m
		JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member
		WHERE (g.rolname, r.rolname) IN (('vendor_sales','vendor_signer'), ('vendor_signer','vendor_owner'))`).Scan(&n))
	assert.Equal(t, 2, n)
}
