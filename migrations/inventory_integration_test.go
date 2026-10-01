//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) error {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	return err
}

// seedTarget inserts the platform credential and one target through the application role and
// returns the target ID.
func seedTarget(t *testing.T, d *pgtest.DB, name, host string) string {
	t.Helper()
	ctx := context.Background()
	var cred string
	err := d.App.QueryRow(ctx, "SELECT id::text FROM credentials WHERE purpose = 'platform_ssh'").Scan(&cred)
	if err != nil {
		require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES (gen_random_uuid(), 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())
RETURNING id::text`).Scan(&cred))
	}
	var id string
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES (gen_random_uuid(), $1, 'linux', jsonb_build_object('host', $2::text, 'port', 22, 'username', 'alice-svc'), $3, 'pending_host_key', now(), now())
RETURNING id::text`, name, host, cred).Scan(&id))
	return id
}

func seedJob(t *testing.T, d *pgtest.DB, dedupe *string, status string) (string, error) {
	t.Helper()
	var id string
	err := d.App.QueryRow(context.Background(), `INSERT INTO jobs (id, type, class, kind, payload_mac, dedupe_key, status, run_at, max_attempts, created_at)
VALUES (gen_random_uuid(), 'target.discover', 'read_only', 'scheduled', decode(repeat('00', 32), 'hex'), $1, $2, now(), 5, now())
RETURNING id::text`, dedupe, status).Scan(&id)
	return id, err
}

func TestInventoryTablesGrantOnlyWhatTheAppNeeds(t *testing.T) {
	d := pgtest.New(t)
	target := seedTarget(t, d, "web-01", "web-01.example.com")

	for _, stmt := range []string{
		"DELETE FROM targets",
		"DELETE FROM credentials",
		"UPDATE credentials SET rotated_at = now()",
		"DELETE FROM host_keys",
		"DELETE FROM ssh_keys",
		"DELETE FROM ssh_key_locations",
		"UPDATE host_keys SET public_key = '\\x01'",
		"UPDATE host_keys SET target_id = target_id",
		"UPDATE targets SET config = '{}'",
		"UPDATE targets SET credential_id = credential_id",
		"UPDATE ssh_keys SET public_key = 'x'",
		"UPDATE ssh_keys SET fingerprint_sha256 = 'x'",
		"UPDATE ssh_key_locations SET file_path = 'x'",
		"UPDATE ssh_key_locations SET target_id = target_id",
	} {
		assert.Equal(t, "42501", sqlState(exec(t, d.App, stmt)), "%s must be refused for alice_app", stmt)
	}
	require.NoError(t, exec(t, d.App, "UPDATE targets SET deleted_at = now() WHERE id = $1", target), "soft delete")
	jobID, err := seedJob(t, d, nil, "succeeded")
	require.NoError(t, err)
	require.NoError(t, exec(t, d.App, "DELETE FROM jobs WHERE id = $1", jobID), "finished jobs are pruned")
}

func TestTargetNamesAndEndpointsAreUniqueAmongLiveTargets(t *testing.T) {
	d := pgtest.New(t)
	first := seedTarget(t, d, "web-01", "web-01.example.com")

	_, err := d.App.Exec(context.Background(), `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'WEB-01', 'linux', jsonb_build_object('host', 'other.example.com', 'port', 22, 'username', 'alice-svc'), credential_id, 'pending_host_key', now(), now() FROM targets WHERE id = $1`, first)
	assert.Equal(t, "23505", sqlState(err), "names are case-insensitive (citext)")
	_, err = d.App.Exec(context.Background(), `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'web-02', 'linux', config, credential_id, 'pending_host_key', now(), now() FROM targets WHERE id = $1`, first)
	assert.Equal(t, "23505", sqlState(err), "one live target per type, host and port")

	require.NoError(t, exec(t, d.App, "UPDATE targets SET deleted_at = now() WHERE id = $1", first))
	seedTarget(t, d, "web-01", "web-01.example.com") // a deleted target frees its name and address
}

// SEC-081: the location of Alice's own connection key can neither be marked removed nor deleted,
// whatever role asks; other locations can be marked removed.
func TestAliceKeyLocationIsProtectedByTrigger(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	var key string
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, is_platform_key, first_seen_at, created_at)
VALUES (gen_random_uuid(), 'SHA256:alice', 'ssh-ed25519', 'ssh-ed25519 AAAA', true, now(), now()) RETURNING id::text`).Scan(&key))
	var own, other string
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at, is_alice_connection_key)
VALUES (gen_random_uuid(), $1, $2, 'alice-svc', '/var/lib/alice-svc/.ssh/authorized_keys', 1, now(), now(), true) RETURNING id::text`, key, target).Scan(&own))
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, 'deploy', '/home/deploy/.ssh/authorized_keys', 1, now(), now()) RETURNING id::text`, key, target).Scan(&other))

	assert.Equal(t, "P0001", sqlState(exec(t, d.App, "UPDATE ssh_key_locations SET removed_by_alice_at = now() WHERE id = $1", own)))
	assert.Equal(t, "P0001", sqlState(exec(t, d.Owner, "UPDATE ssh_key_locations SET removed_by_alice_at = now() WHERE id = $1", own)), "the owner role too")
	assert.Equal(t, "P0001", sqlState(exec(t, d.Owner, "DELETE FROM ssh_key_locations WHERE id = $1", own)))
	require.NoError(t, exec(t, d.App, "UPDATE ssh_key_locations SET last_seen_at = now() WHERE id = $1", own), "discovery still updates it")
	require.NoError(t, exec(t, d.App, "UPDATE ssh_key_locations SET removed_by_alice_at = now() WHERE id = $1", other))
	require.NoError(t, exec(t, d.Owner, "DELETE FROM ssh_key_locations WHERE id = $1", other))
}

func TestOneHostKeyIsPinnedPerTarget(t *testing.T) {
	d := pgtest.New(t)
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	insert := func(fp, status string) error {
		return exec(t, d.App, `INSERT INTO host_keys (id, target_id, key_type, public_key, fingerprint_sha256, status, observed_at)
VALUES (gen_random_uuid(), $1, 'ssh-ed25519', '\x00', $2, $3, now())`, target, fp, status)
	}
	require.NoError(t, insert("SHA256:a", "pinned"))
	require.NoError(t, insert("SHA256:b", "observed"))
	assert.Equal(t, "23505", sqlState(insert("SHA256:c", "pinned")), "a second pinned key")
	assert.Equal(t, "23505", sqlState(insert("SHA256:a", "superseded")), "one row per fingerprint and target")
	assert.Equal(t, "23514", sqlState(insert("SHA256:d", "trusted")), "status is a closed set")
}

func TestJobDedupeKeysAreUniqueAmongLiveJobsOnly(t *testing.T) {
	d := pgtest.New(t)
	key := "target.discover:x:1"
	first, err := seedJob(t, d, &key, "queued")
	require.NoError(t, err)
	_, err = seedJob(t, d, &key, "queued")
	assert.Equal(t, "23505", sqlState(err))
	require.NoError(t, exec(t, d.App, "UPDATE jobs SET status = 'blocked_license' WHERE id = $1", first))
	_, err = seedJob(t, d, &key, "queued")
	assert.Equal(t, "23505", sqlState(err), "a job waiting for the license is still live")
	require.NoError(t, exec(t, d.App, "UPDATE jobs SET status = 'succeeded' WHERE id = $1", first))
	_, err = seedJob(t, d, &key, "queued")
	require.NoError(t, err, "a finished job frees its dedupe key")
	_, err = seedJob(t, d, nil, "waiting")
	assert.Equal(t, "23514", sqlState(err))
}

func TestJobChildrenFollowTheirJob(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	job, err := seedJob(t, d, nil, "running")
	require.NoError(t, err)
	require.NoError(t, exec(t, d.App, `INSERT INTO job_attempts (id, job_id, attempt, worker_id, started_at) VALUES (gen_random_uuid(), $1, 1, 'w', now())`, job))
	require.NoError(t, exec(t, d.App, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'target.discover', 'w', now(), now() + interval '45 seconds')`, target, job))
	require.NoError(t, exec(t, d.App, "DELETE FROM jobs WHERE id = $1", job))
	var attempts, locks int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT (SELECT count(*) FROM job_attempts), (SELECT count(*) FROM target_locks)").Scan(&attempts, &locks))
	assert.Zero(t, attempts)
	assert.Zero(t, locks)
}

func TestAliceKeyLocationCannotBeUnprotectedByEditingIt(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	other := seedTarget(t, d, "web-02", "web-02.example.com")
	require.NoError(t, exec(t, d.Owner, `UPDATE credentials SET public_info = '{"fingerprint": "SHA256:alice"}'`))
	var key, otherKey string
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES (gen_random_uuid(), 'SHA256:alice', 'ssh-ed25519', 'ssh-ed25519 AAAA', now(), now()) RETURNING id::text`).Scan(&key))
	require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES (gen_random_uuid(), 'SHA256:bob', 'ssh-ed25519', 'ssh-ed25519 BBBB', now(), now()) RETURNING id::text`).Scan(&otherKey))
	insert := func(flag bool, user string) string {
		var id string
		require.NoError(t, d.App.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at, is_alice_connection_key)
VALUES (gen_random_uuid(), $1, $2, $3, '/home/x/.ssh/authorized_keys', 1, now(), now(), $4) RETURNING id::text`, key, target, user, flag).Scan(&id))
		return id
	}
	own := insert(true, "alice-svc")
	for _, set := range []string{
		"is_alice_connection_key = false",
		"ssh_key_id = '" + otherKey + "'",
		"target_id = '" + other + "'",
		"os_user = 'someone'",
		"file_path = '/elsewhere'",
	} {
		// The owner role is not limited by column grants; the trigger still refuses it.
		assert.Equal(t, "P0001", sqlState(exec(t, d.Owner, "UPDATE ssh_key_locations SET "+set+" WHERE id = $1", own)), set)
	}

	// An unflagged location of the platform key's fingerprint is protected too.
	unflagged := insert(false, "deploy")
	assert.Equal(t, "P0001", sqlState(exec(t, d.App, "UPDATE ssh_key_locations SET removed_by_alice_at = now() WHERE id = $1", unflagged)))
	assert.Equal(t, "P0001", sqlState(exec(t, d.Owner, "DELETE FROM ssh_key_locations WHERE id = $1", unflagged)))
	assert.Equal(t, "P0001", sqlState(exec(t, d.Owner, "UPDATE ssh_key_locations SET ssh_key_id = $2, removed_by_alice_at = now() WHERE id = $1", unflagged, otherKey)),
		"repointing in the same statement does not help")
	// Setting the flag is allowed; after that the row is the platform key's location.
	require.NoError(t, exec(t, d.App, "UPDATE ssh_key_locations SET is_alice_connection_key = true WHERE id = $1", unflagged))
	assert.Equal(t, "P0001", sqlState(exec(t, d.App, "UPDATE ssh_key_locations SET is_alice_connection_key = false WHERE id = $1", unflagged)))
}

func TestInventoryConstraints(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	target := seedTarget(t, d, "web-01", "web-01.example.com")
	job, err := seedJob(t, d, nil, "running")
	require.NoError(t, err)
	lock := func(target string) error {
		return exec(t, d.App, `INSERT INTO target_locks (target_id, job_id, operation, locked_by, heartbeat_at, lease_until)
VALUES ($1, $2, 'target.discover', 'w', now(), now())`, target, job)
	}
	require.NoError(t, lock(target))
	assert.Equal(t, "23505", sqlState(lock(target)), "one lock per target")

	var cred string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT id::text FROM credentials").Scan(&cred))
	cols := `(id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)`
	assert.Equal(t, "23505", sqlState(exec(t, d.App, `INSERT INTO credentials `+cols+`
VALUES (gen_random_uuid(), 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`)), "one platform key")
	assert.Equal(t, "23514", sqlState(exec(t, d.Owner, `INSERT INTO credentials `+cols+`
VALUES (gen_random_uuid(), 'platform_ssh', 'ssh_private_key', '\x01', '\x00', '\x02', 1, now())`)), "nonce length")

	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, created_at)
VALUES (gen_random_uuid(), 't', 'always', 'system', '\x00', 'queued', now(), 5, now())`)), "payload_mac length")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE jobs SET attempts = -1 WHERE id = $1", job)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE jobs SET priority = 0 WHERE id = $1", job)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, "UPDATE jobs SET priority = 10 WHERE id = $1", job)))

	// A running job holds its dedupe key.
	key := "k"
	require.NoError(t, exec(t, d.App, "UPDATE jobs SET dedupe_key = $2 WHERE id = $1", job, key))
	_, err = seedJob(t, d, &key, "queued")
	assert.Equal(t, "23505", sqlState(err), "a running job is live")

	// Targets: host and port are required except for Key Vault, and the address is case-insensitive.
	ins := func(typ, cfg string) error {
		return exec(t, d.App, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES (gen_random_uuid(), gen_random_uuid()::text, $1, $2::jsonb, $3, 'ok', now(), now())`, typ, cfg, cred)
	}
	assert.Equal(t, "23514", sqlState(ins("linux", `{"host": "a"}`)))
	assert.Equal(t, "23514", sqlState(ins("nginx", `{"port": 22}`)))
	assert.Equal(t, "23505", sqlState(ins("linux", `{"host": "WEB-01.example.com", "port": 22}`)), "host compares case-insensitively")
	require.NoError(t, ins("linux", `{"host": "web-01.example.com", "port": 2222}`))
	require.NoError(t, ins("azure_key_vault", `{"vault": "v"}`))
}
