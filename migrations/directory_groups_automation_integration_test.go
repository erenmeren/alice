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

// 00029 (R49 Phase 3, R54): an automation account never gets a session, an authenticator or recovery codes (Z1029),
// while a person still does; the values seen at sign-in are indexed by value. The Down drops both.
func TestMigration00029DirectoryGroupsAutomation(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	robot, person := uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, description, created_at, updated_at)
VALUES ($1, 'ci-bot', 'CI', 'automation', 'operator', 'the pipeline', now(), now())`, robot))
	require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, created_at, updated_at)
VALUES ($1, 'person', 'Person', 'local', 'x', 'operator', now(), now())`, person))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'ci-admin', 'CI', 'automation', 'admin', now(), now())`)), "an automation account is never a global Administrator")

	session := `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at, idle_expires_at)
VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'full', now(), now(), now() + interval '1 hour', now() + interval '1 hour')`
	mfa := `INSERT INTO user_mfa (user_id, totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version, created_at)
VALUES ($1, 'x', 'x', 'x', 1, now())`
	codes := `INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (gen_random_uuid(), $1, 'x', now())`
	for name, sql := range map[string]string{"session": session, "authenticator": mfa, "recovery code": codes} {
		assert.Equal(t, "Z1029", sqlState(exec(t, d.App, sql, robot)), "no %s for an automation account", name)
		require.NoError(t, exec(t, d.App, sql, person), "a person's %s", name)
	}
	assert.Equal(t, "Z1029", sqlState(exec(t, d.App, "UPDATE sessions SET user_id = $1 WHERE user_id = $2", robot, person)),
		"a session is not handed over to an automation account")

	indexed := func() int {
		var n int
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'user_directory_groups'
AND indexname = 'user_directory_groups_value'`).Scan(&n))
		return n
	}
	assert.Equal(t, 1, indexed())

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 28)
	require.NoError(t, err)
	assert.Zero(t, indexed())
	require.NoError(t, exec(t, d.Owner, session, robot), "without 00029 only the application keeps automation accounts out")
	_, err = d.Owner.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", robot)
	require.NoError(t, err)
	_, err = p.Up(ctx)
	require.NoError(t, err)
}
