//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

// rotFixture is a rotation of one location seeded through the legal path of the schema (as the migration
// tests do), as the application role: a target, a generated old key with one location on it (deploy's
// authorized_keys), its policy, and, after createRun, a run created with the policy's overlap. No key
// material: the private key rows hold placeholder bytes.
type rotFixture struct {
	t                   *testing.T
	d                   *pgtest.DB
	target, policy, run uuid.UUID
	oldKey, newKey, loc uuid.UUID
	oldLoc              uuid.UUID
	t0                  time.Time
}

// connectedFacts are what a scan of a reachable server leaves: sshd read, public keys allowed, and the
// connection account's key files known completely, so the planner changes the deploy location.
const connectedFacts = `{"sshd": {"Read": true, "PubkeyAuthentication": "yes", "PermitRootLogin": "prohibit-password"},
 "key_files": [{"os_user": "alice-svc", "files": ["/home/alice-svc/.ssh/authorized_keys"], "complete": true},
               {"os_user": "deploy", "files": ["/home/deploy/.ssh/authorized_keys"], "complete": true}]}`

// newRotFixture needs the platform key's credential (EnsurePlatformKey). connected makes the target a
// scanned server in status ok (otherwise it waits for its host key and the planner skips it).
func newRotFixture(t *testing.T, d *pgtest.DB, t0 time.Time, connected bool) *rotFixture {
	t.Helper()
	f := &rotFixture{t: t, d: d, t0: t0}
	status, facts := "pending_host_key", "{}"
	if connected {
		status, facts = "ok", connectedFacts
	}
	require.NoError(t, d.App.QueryRow(context.Background(), `INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
SELECT gen_random_uuid(), 'web-01', 'linux', jsonb_build_object('host', 'web-01.example.test', 'port', 22, 'username', 'alice-svc'), id,
       $1, $2::jsonb, now(), now() FROM credentials WHERE purpose = 'platform_ssh' RETURNING id`, status, facts).Scan(&f.target))
	f.oldKey = f.seedKey("SHA256:"+strings.Repeat("O", 43), nil)
	f.oldLoc = f.keyLocation(f.oldKey)
	f.policy = uuid.New()
	f.must(`INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at) VALUES ($1, $2, 'p', 90, $3, $3)`,
		f.policy, f.oldKey, f.t0)
	return f
}

func (f *rotFixture) exec(sql string, args ...any) error {
	_, err := f.d.App.Exec(context.Background(), sql, args...)
	return err
}

func (f *rotFixture) must(sql string, args ...any) {
	f.t.Helper()
	require.NoError(f.t, f.exec(sql, args...))
}

// seedKey inserts a generated key (managed, with a private key row holding no real key material).
func (f *rotFixture) seedKey(fp string, from *uuid.UUID) uuid.UUID {
	f.t.Helper()
	pk, key := uuid.New(), uuid.New()
	f.must(`INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, pk, f.t0)
	f.must(`INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, rotated_from, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $5, $5)`, key, fp, pk, from, f.t0)
	return key
}

func (f *rotFixture) keyLocation(key uuid.UUID) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.must(`INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'deploy', '/home/deploy/.ssh/authorized_keys', 1, $4, $4)`, id, key, f.target, f.t0)
	return id
}

// createRun inserts a manual run as the planner does (its overlap is the policy's at that moment) with
// one planned location.
func (f *rotFixture) createRun() {
	f.t.Helper()
	f.run = uuid.New()
	f.must(`INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes, planned_for,
    notified_at, created_at, updated_at)
SELECT $1, p.id, p.ssh_key_id, 'manual', 'dry_run_notified', '{}', repeat('0', 64), 'ed25519', p.overlap_minutes, $3, $3, $3, $3
FROM rotation_policies p WHERE p.id = $2`, f.run, f.policy, f.t0)
	f.loc = uuid.New()
	f.must(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES ($1, $2, 1, $3, $4, 'deploy', '/home/deploy/.ssh/authorized_keys', 'planned', $5)`, f.loc, f.run, f.oldLoc, f.target, f.t0)
}

// start generates the new key (a placeholder row) and moves the run to adding_new; its location is still
// planned, so nothing has been sent.
func (f *rotFixture) start() {
	f.t.Helper()
	f.newKey = f.seedKey("SHA256:"+strings.Repeat("N", 43), &f.oldKey)
	f.must("UPDATE rotations SET status = 'adding_new', new_ssh_key_id = $2, started_at = $3 WHERE id = $1", f.run, f.newKey, f.t0)
}
