//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00028 (R49 Phase 2, R53): the break-glass account always keeps a global role (another person may lose theirs and hold
// role bindings only), and the bindings are indexed by service and environment. The Down drops both.
func TestMigration00028ScopedBindings(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	glass, person := uuid.New(), uuid.New()
	for _, u := range []struct {
		id    uuid.UUID
		name  string
		glass bool
	}{{glass, "glass", true}, {person, "person", false}} {
		require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role,
    is_break_glass, created_at, updated_at) VALUES ($1, $2::text, $2::text || '@example.test', $2::text, 'local', 'x', 'admin', $3, now(), now())`,
			u.id, u.name, u.glass))
	}
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = 'operator' WHERE id = $1", glass), "demoting the break-glass account stays possible")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE users SET role = NULL WHERE id = $1", glass)),
		"the break-glass account never loses its global role")
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = NULL WHERE id = $1", person), "any other person may hold bindings only")
	require.NoError(t, exec(t, d.App, `INSERT INTO role_bindings (id, user_id, role, environment_id, created_at)
SELECT gen_random_uuid(), $1, 'operator', id, now() FROM environments WHERE key = 'production'`, person))

	var indexes int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'role_bindings'
AND indexname IN ('role_bindings_service', 'role_bindings_environment')`).Scan(&indexes))
	assert.Equal(t, 2, indexes)

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 27)
	require.NoError(t, err)
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'role_bindings'
AND indexname IN ('role_bindings_service', 'role_bindings_environment')`).Scan(&indexes))
	assert.Zero(t, indexes)
	_, err = p.Up(ctx)
	require.NoError(t, err)
}
