//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// canaryDownRefused is the SQLSTATE of 00035's Down while canary history exists.
const canaryDownRefused = "Z1033"

// insertRollout stores a minimal manual rollout of the world's certificate and answers its id.
func insertRollout(t *testing.T, d *pgtest.DB, w world) uuid.UUID {
	t.Helper()
	id := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings, origin, state,
wave1_location_ids, wave2_location_ids, created_at) VALUES ($1, $2, 1, '{}', 'manual', 'wave1', $3, $4, now())`,
		id, w.cert, []uuid.UUID{w.loc}, []uuid.UUID{uuid.New()}))
	return id
}

// CAN-05 (R65, design §16): 00035 adds the rollouts, the observations, the holding state and four deployment columns;
// existing rows are unchanged; the new constraints hold; the Down refuses while canary history exists (Z1033) and
// restores the old state check otherwise.
func TestMigration00035Canary(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 34)
	require.NoError(t, err)

	// A populated fixture before 00035: an unfinished and a finished deployment.
	w := seedWorld(t, d)
	open := deploymentRow(w)
	require.NoError(t, insertRow(t, d.App, "deployments", open))
	done := with(deploymentRow(w), map[string]any{"state": "done", "status": "succeeded", "finished_at": time.Now(), "verified": "remote"})
	require.NoError(t, insertRow(t, d.App, "deployments", done))
	snapshot := func() map[string]string {
		rows, err := d.Owner.Query(ctx, `SELECT id::text, (to_jsonb(d) - 'rollout_id' - 'wave' - 'held_cert_file_sha256' - 'revert_reason')::text
FROM deployments d ORDER BY id`)
		require.NoError(t, err)
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var id, body string
			require.NoError(t, rows.Scan(&id, &body))
			out[id] = body
		}
		require.NoError(t, rows.Err())
		return out
	}
	before := snapshot()

	_, err = p.UpTo(ctx, 35)
	require.NoError(t, err)
	assert.Equal(t, before, snapshot(), "every existing deployment row is unchanged")
	var rollout *uuid.UUID
	var wave *int
	var held, revert string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT rollout_id, wave, held_cert_file_sha256, revert_reason FROM deployments WHERE id = $1",
		open["id"]).Scan(&rollout, &wave, &held, &revert))
	assert.Nil(t, rollout)
	assert.Nil(t, wave)
	assert.Empty(t, held)
	assert.Empty(t, revert)

	// The new constraints.
	r := insertRollout(t, d, w)
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE deployments SET state = 'holding', status = 'running' WHERE id = $1", open["id"])),
		"deployments_holding_wave1: holding only for a wave-1 deployment")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"rollout_id": r}))),
		"deployments_wave_rollout: a rollout id goes with a wave")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"wave": 1}))),
		"deployments_wave_rollout: a wave goes with a rollout id")
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET state = 'done', status = 'failed', finished_at = now() WHERE id = $1", open["id"]))
	hold := with(deploymentRow(w), map[string]any{"rollout_id": r, "wave": 1, "state": "deploying", "status": "running"})
	require.NoError(t, insertRow(t, d.App, "deployments", hold))
	require.NoError(t, exec(t, d.App, `UPDATE deployments SET state = 'holding', held_cert_file_sha256 = $2 WHERE id = $1`, hold["id"], hex64("e")))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE deployments SET held_cert_file_sha256 = 'x' WHERE id = $1", hold["id"])))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE deployments SET revert_reason = 'a b' WHERE id = $1", hold["id"])))
	require.NoError(t, exec(t, d.App, `INSERT INTO canary_checks (deployment_id, rollout_id, next_check_at) VALUES ($1, $2, now())`, hold["id"], r))
	require.NoError(t, exec(t, d.App, `UPDATE canary_checks SET rounds = 1, passes = 1, last_result = 'pass', last_tls = 'skipped',
last_http_status = 200, last_latency_ms = 12, last_at = now(), last_pass_at = now(), next_check_at = now() WHERE deployment_id = $1`, hold["id"]))
	for _, bad := range []string{
		"UPDATE canary_checks SET last_result = 'maybe' WHERE deployment_id = $1",
		"UPDATE canary_checks SET last_tls = 'maybe' WHERE deployment_id = $1",
		"UPDATE canary_checks SET last_http_status = 600 WHERE deployment_id = $1",
		"UPDATE canary_checks SET rounds = -1 WHERE deployment_id = $1",
	} {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, bad, hold["id"])), bad)
	}
	for name, sql := range map[string]string{
		"a finished rollout has finished_at": `UPDATE deployment_rollouts SET state = 'completed' WHERE id = $1`,
		"unknown state":                      `UPDATE deployment_rollouts SET state = 'paused' WHERE id = $1`,
		"bad reason":                         `UPDATE deployment_rollouts SET reason = 'a b' WHERE id = $1`,
	} {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, sql, r)), name)
	}
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings,
origin, state, wave1_location_ids, wave2_location_ids, created_at) VALUES ($1, $2, 1, '{}', 'acme', 'wave1', $3, $3, now())`,
		uuid.New(), w.cert, []uuid.UUID{w.loc})), "an acme rollout names its ACME certificate")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO deployment_rollouts (id, certificate_id, policy_version, settings,
origin, state, wave1_location_ids, wave2_location_ids, created_at) VALUES ($1, $2, 1, '{}', 'manual', 'wave1', '{}', $3, now())`,
		uuid.New(), w.cert, []uuid.UUID{w.loc})), "wave 1 is never empty")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "DELETE FROM deployment_rollouts WHERE id = $1", r)), "no delete grant")

	// The Down refuses while canary history exists.
	_, err = p.DownTo(ctx, 34)
	assert.Equal(t, canaryDownRefused, sqlState(err), "%v", err)

	// Without it, the Down works and the old state check is back.
	d2 := pgtest.New(t)
	p2, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d2.Owner), migrations.FS)
	require.NoError(t, err)
	w2 := seedWorld(t, d2)
	queued := deploymentRow(w2)
	require.NoError(t, insertRow(t, d2.App, "deployments", queued))
	_, err = p2.DownTo(ctx, 34)
	require.NoError(t, err)
	assert.False(t, hasColumn(t, d2, "deployments", "rollout_id"))
	assert.Equal(t, checkViolation, sqlState(exec(t, d2.App, "UPDATE deployments SET state = 'holding', status = 'running' WHERE id = $1",
		queued["id"])), "the old state check is back")
	_, err = p2.Up(ctx)
	require.NoError(t, err)
	assert.True(t, hasColumn(t, d2, "deployments", "rollout_id"))
}
