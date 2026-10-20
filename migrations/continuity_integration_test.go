//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00019 adds the license class continuity to jobs.class (owner decision 2026-10-20). Up re-classes a live kv.poll;
// the Down refuses while a live acme.renew or certificate.deploy_auto job exists and otherwise maps the class back to
// change (renewal orders and automatic deployments) and read_only (polls and the planners).
func TestMigration00019AddsTheContinuityClass(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 18)
	require.NoError(t, err)

	add := func(typ, class, status string) uuid.UUID {
		id := uuid.New()
		require.NoError(t, exec(t, d.Owner, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, $2, $3, 'scheduled', decode(repeat('00', 32), 'hex'), $4, now(), 1, now())`, id, typ, class, status))
		return id
	}
	poll := add("kv.poll", "read_only", "queued")
	donePoll := add("kv.poll", "read_only", "succeeded")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.Owner, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, 'kv.poll', 'continuity', 'scheduled', decode(repeat('00', 32), 'hex'), 'queued', now(), 1, now())`, uuid.New())),
		"18 does not know the class")

	_, err = p.UpTo(ctx, 19)
	require.NoError(t, err)
	assert.Equal(t, "continuity", classOf(t, d.Owner, poll), "a live poll takes the class kv.poll has now")
	assert.Equal(t, "read_only", classOf(t, d.Owner, donePoll), "history keeps its class")
	renew := add("acme.renew", "continuity", "blocked_license")
	add("kv.schedule", "continuity", "succeeded")

	_, err = p.DownTo(ctx, 18)
	require.Error(t, err)
	assert.Equal(t, "Z1008", sqlState(err), "the Down refuses while a renewal order is held")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(19), version, "nothing changed")

	require.NoError(t, exec(t, d.Owner, "UPDATE jobs SET status = 'cancelled' WHERE id = $1", renew))
	_, err = p.DownTo(ctx, 18)
	require.NoError(t, err)
	assert.Equal(t, "change", classOf(t, d.Owner, renew), "a finished renewal order is a change again")
	assert.Equal(t, "read_only", classOf(t, d.Owner, poll))

	_, err = p.Up(ctx)
	require.NoError(t, err)
}

func classOf(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var c string
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT class FROM jobs WHERE id = $1", id).Scan(&c))
	return c
}
