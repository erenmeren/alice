//go:build integration

package dump_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup/dump"
	"alice/internal/testutil/pgtest"
)

// A restore empties a table the migrations seeded before it copies the backup's rows (R49). When the target table
// cannot be read or emptied, Load names the table and fails instead of copying next to the seeded rows. Another
// session holds a lock on the seeded environments table, and the load's lock_timeout turns the wait into an error.
func TestLoadReportsASeededTableItCannotEmpty(t *testing.T) {
	a := pgtest.New(t)
	payload, _ := dumpDB(t, a.App)

	cases := []struct {
		name, lock, want string
	}{
		// ACCESS EXCLUSIVE blocks even the read of whether the table holds rows.
		{"the table cannot be read", "ACCESS EXCLUSIVE", "dump: read table environments"},
		// SHARE lets the read through and blocks the DELETE.
		{"the table cannot be emptied", "SHARE", "dump: empty table environments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := pgtest.New(t)
			holder, err := b.Owner.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = holder.Rollback(ctx) }()
			_, err = holder.Exec(ctx, "LOCK TABLE public.environments IN "+c.lock+" MODE")
			require.NoError(t, err)

			conn, err := b.Owner.Acquire(ctx)
			require.NoError(t, err)
			defer conn.Release()
			tx, err := conn.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, "SET LOCAL session_replication_role = replica; SET LOCAL lock_timeout = '200ms'")
			require.NoError(t, err)
			dec := dump.NewDecoder(bytes.NewReader(payload))
			_, err = dec.Next() // M
			require.NoError(t, err)
			first, err := dec.Next()
			require.NoError(t, err)

			_, err = dump.Load(ctx, tx.Conn(), dec, first)
			require.Error(t, err)
			assert.ErrorContains(t, err, c.want)
			require.NoError(t, tx.Rollback(ctx))
			require.NoError(t, holder.Rollback(ctx))

			var n int64
			require.NoError(t, b.Owner.QueryRow(ctx, "SELECT count(*) FROM public.environments").Scan(&n))
			assert.Equal(t, migrationSeeds["environments"], n, "the failed load changed nothing")
		})
	}
}
