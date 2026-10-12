//go:build integration

package oidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/testutil/pgtest"
)

// Review L-14: the unique constraints that callers name exist under those names in the migrated schema, so a
// duplicate is still recognised (and nothing else is).
func TestNamedUniqueConstraintsExist(t *testing.T) {
	d := pgtest.New(t)
	for table, name := range map[string]string{"users": auth.UsernameConstraint, "oidc_group_mappings": groupMappingConstraint} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_constraint
WHERE conrelid = $1::regclass AND conname = $2 AND contype = 'u')`, table, name).Scan(&ok))
		require.True(t, ok, "%s.%s", table, name)
	}
}
