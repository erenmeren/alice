//go:build integration

package migrations_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// P1-01, R43 row 7: in production the schema owner alice_owner is not a superuser. Every migration
// applies as such an owner (citext is a trusted extension; alice_app already exists cluster-wide),
// the owner may switch off triggers for a restore (session_replication_role) and create the staging
// database, and the grant guard holds for the result.
func TestMigrationsRunAsNonSuperuserOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	super := pgtest.New(t) // its Owner pool is the container's superuser
	for _, stmt := range []string{
		"CREATE ROLE t_owner LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD '0wner-pw'",
		"GRANT SET ON PARAMETER session_replication_role TO t_owner",
		"CREATE DATABASE t_nonsuper OWNER t_owner",
	} {
		_, err := super.Owner.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, stmt := range []string{
			"DROP DATABASE IF EXISTS t_nonsuper WITH (FORCE)",
			"DROP DATABASE IF EXISTS t_nonsuper_copy WITH (FORCE)",
			"REVOKE SET ON PARAMETER session_replication_role FROM t_owner",
			"DROP ROLE IF EXISTS t_owner",
		} {
			_, _ = super.Owner.Exec(c, stmt)
		}
	})

	u, err := url.Parse(super.OwnerURL)
	require.NoError(t, err)
	u.User = url.UserPassword("t_owner", "0wner-pw")
	u.Path = "/t_nonsuper"
	owner, err := db.Open(ctx, u.String())
	require.NoError(t, err)
	defer owner.Close()

	var isSuper bool
	require.NoError(t, owner.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&isSuper))
	require.False(t, isSuper, "the test owner is not a superuser")

	require.NoError(t, db.Migrate(ctx, owner, migrations.FS))
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	v, err := db.SchemaVersion(ctx, owner)
	require.NoError(t, err)
	assert.Equal(t, latest, v)

	// A restore loads rows with the triggers off.
	conn, err := owner.Acquire(ctx)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET session_replication_role = replica")
	require.NoError(t, err, "the owner may switch off triggers for a restore")
	_, err = conn.Exec(ctx, "RESET session_replication_role")
	require.NoError(t, err)
	conn.Release()

	// A restore builds its staging database as the owner.
	_, err = owner.Exec(ctx, "CREATE DATABASE t_nonsuper_copy")
	require.NoError(t, err)
	_, err = owner.Exec(ctx, "DROP DATABASE t_nonsuper_copy")
	require.NoError(t, err)

	assert.Empty(t, grantProblems(t, &pgtest.DB{Owner: owner}), "the grant guard holds for a non-superuser owner")
}
