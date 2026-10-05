//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

var rotNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// repeat43 is the 43 base64 characters of a SHA-256 fingerprint.
func repeat43(s string) string { return strings.Repeat(s, 43) }

// constraintOf is the name of the constraint a failed statement violated ("" when none).
func constraintOf(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.ConstraintName
	}
	return ""
}

// seedSSHKey inserts a generated key (managed, with its private key row) and returns the key id and
// the private key id.
func seedSSHKey(t *testing.T, db *pgtest.DB, fp string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	pk, key := uuid.New(), uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		pk, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, first_seen_at,
    created_at) VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $4)`, key, fp, pk, rotNow)
	require.NoError(t, err)
	return key, pk
}

func insertPolicy(db *pgtest.DB, key uuid.UUID) error {
	_, err := db.App.Exec(context.Background(), `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at)
VALUES ($1, $2, 'p', 90, $3, $3)`, uuid.New(), key, rotNow)
	return err
}

// runOpts are the knobs of insertRun; the zero value is a valid run in adding_new.
type runOpts struct {
	status         string
	newKey         *uuid.UUID
	removalAllowed bool
	verifiedAt     *time.Time
	finishedAt     *time.Time
	pausedAt       *time.Time
	paused         bool
	awaiting       bool
	dueAt          *time.Time
	digest         string
	newKeyType     string
	overlap        int
	resultCode     string
	keptCount      int
}

func insertRun(db *pgtest.DB, policy, oldKey uuid.UUID, o runOpts) (uuid.UUID, error) {
	if o.status == "" {
		o.status = "adding_new"
	}
	if o.digest == "" {
		o.digest = strings.Repeat("0", 64)
	}
	if o.newKeyType == "" {
		o.newKeyType = "ed25519"
	}
	id := uuid.New()
	_, err := db.App.Exec(context.Background(), `INSERT INTO rotations (id, policy_id, old_ssh_key_id, new_ssh_key_id, trigger, status,
    paused_license, paused_at, awaiting_decision, decision_due_at, plan, plan_digest, new_key_type, overlap_minutes, planned_for, notified_at,
    started_at, verified_at, removal_allowed, kept_count, finished_at, result_code, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, $8, $9, '{}', $10, $11, $12, $13, $13, $13, $14, $15, $16, $17, $18, $13, $13)`,
		id, policy, oldKey, o.newKey, o.status, o.paused, o.pausedAt, o.awaiting, o.dueAt, o.digest, o.newKeyType, o.overlap, rotNow,
		o.verifiedAt, o.removalAllowed, o.keptCount, o.finishedAt, o.resultCode)
	return id, err
}

// insertOldLocation records one location of the old key on the target.
func insertOldLocation(t *testing.T, db *pgtest.DB, key uuid.UUID, target, file string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.App.Exec(context.Background(), `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'deploy', $4, 1, $5, $5)`, id, key, target, file, rotNow)
	require.NoError(t, err)
	return id
}

type rotationFixture struct {
	target           string
	oldKey, newKey   uuid.UUID
	oldFP            string
	policy, rotation uuid.UUID
	oldLoc, location uuid.UUID
	locationFile     string
}

// seedRotation seeds a target, a generated old key with a location, a generated new key, a policy of the
// old key, a run in adding_new and one rotation location in state verified.
func seedRotation(t *testing.T, db *pgtest.DB) rotationFixture {
	t.Helper()
	ctx := context.Background()
	f := rotationFixture{oldFP: "SHA256:" + repeat43("O"), locationFile: "/home/deploy/.ssh/authorized_keys"}
	f.target = seedTarget(t, db, "web-01", "web-01.example.com")
	f.oldKey, _ = seedSSHKey(t, db, f.oldFP)
	f.newKey, _ = seedSSHKey(t, db, "SHA256:"+repeat43("N"))
	f.oldLoc = insertOldLocation(t, db, f.oldKey, f.target, f.locationFile)
	require.NoError(t, insertPolicy(db, f.oldKey))
	require.NoError(t, db.App.QueryRow(ctx, "SELECT id FROM rotation_policies WHERE ssh_key_id = $1", f.oldKey).Scan(&f.policy))
	var err error
	f.rotation, err = insertRun(db, f.policy, f.oldKey, runOpts{newKey: &f.newKey, overlap: 1})
	require.NoError(t, err)
	f.location = uuid.New()
	_, err = db.App.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state,
    add_sent_at, verified_at, updated_at) VALUES ($1, $2, 1, $3, $4, 'deploy', $5, 'verified', $6, $6, $6)`,
		f.location, f.rotation, f.oldLoc, f.target, f.locationFile, rotNow)
	require.NoError(t, err)
	return f
}

func TestManagedPrivateKeyGuard(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	_, pk := seedSSHKey(t, db, "SHA256:"+repeat43("A"))

	_, err := db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = download_count + 1, last_downloaded_at = $2 WHERE id = $1", pk, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = download_count + 2 WHERE id = $1", pk)
	assert.Equal(t, "Z1009", sqlState(err), "a download counts one")
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = 0 WHERE id = $1", pk)
	assert.Equal(t, "Z1009", sqlState(err))
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET ciphertext = '\x09' WHERE id = $1`, pk)
	assert.Equal(t, "Z1009", sqlState(err), "an envelope cannot be replaced")
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET ciphertext = NULL WHERE id = $1", pk)
	assert.Error(t, err, "half a destruction is refused (CHECK)")
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, download_count = download_count + 1, ciphertext = NULL,
    nonce = NULL, wrapped_dek = NULL, key_version = NULL WHERE id = $1`, pk, rotNow)
	assert.Equal(t, "Z1009", sqlState(err), "a destruction changes nothing but the envelope")
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL,
    key_version = NULL WHERE id = $1`, pk, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET last_downloaded_at = $2 WHERE id = $1", pk, rotNow)
	assert.Equal(t, "Z1009", sqlState(err), "a destroyed key never changes")
	_, err = db.App.Exec(ctx, "DELETE FROM managed_private_keys WHERE id = $1", pk)
	assert.Error(t, err, "no DELETE grant")

	// A certificate key cannot be destroyed, and Ed25519 is only for SSH keys.
	cert := uuid.New()
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'certificate', 'rsa', 2048, repeat('c', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		cert, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL,
    key_version = NULL WHERE id = $1`, cert, rotNow)
	assert.Equal(t, "managed_private_keys_destroyed", constraintOf(err), "a certificate key cannot be destroyed")
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET bits = 4096 WHERE id = $1`, cert)
	assert.Error(t, err, "bits has no UPDATE grant")
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'certificate', 'ed25519', 256, repeat('b', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		uuid.New(), rotNow)
	assert.Equal(t, "managed_private_keys_ed25519_is_ssh", constraintOf(err))
	for _, c := range []struct {
		algo string
		bits int
		name string
	}{{"rsa", 2048, "RSA SSH keys are 3072 or 4096 bits"}, {"ecdsa", 384, "ECDSA SSH keys are P-256"}, {"ed25519", 512, "Ed25519 is 256 bits"}} {
		_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', $2, $3, repeat('b', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $4)`,
			uuid.New(), c.algo, c.bits, rotNow)
		assert.Error(t, err, c.name)
	}
	for _, bits := range []int{3072, 4096} {
		_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'rsa', $2, repeat('b', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $3)`,
			uuid.New(), bits, rotNow)
		assert.NoError(t, err, "RSA %d is allowed", bits)
	}
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ecdsa', 256, repeat('b', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		uuid.New(), rotNow)
	assert.NoError(t, err, "ECDSA P-256 is allowed")
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('b', 64), decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		uuid.New(), rotNow)
	assert.Equal(t, "managed_private_keys_destroyed", constraintOf(err), "a live key has its whole envelope")
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = -1")
	assert.Error(t, err)
}

func TestSSHKeyManagedConstraints(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	_, err := db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', true, $3, $3)`, uuid.New(), "SHA256:"+repeat43("B"), rotNow)
	assert.Equal(t, "ssh_keys_managed_has_private_key", constraintOf(err), "a managed key needs its private key")
	key, pk := seedSSHKey(t, db, "SHA256:"+repeat43("C"))
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', true, $3, $4, $4)`, uuid.New(), "SHA256:"+repeat43("D"), pk, rotNow)
	assert.Error(t, err, "a private key belongs to one key (UNIQUE)")
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', false, $3, $4, $4)`, uuid.New(), "SHA256:"+repeat43("E"), uuid.New(), rotNow)
	assert.Error(t, err, "a discovered key has no private key")
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, is_platform_key, managed, private_key_id, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', true, true, $3, $4, $4)`, uuid.New(), "SHA256:"+repeat43("F"), uuid.New(), rotNow)
	assert.Error(t, err)
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET is_platform_key = true WHERE id = $1", key)
	assert.Equal(t, "ssh_keys_managed_is_not_platform", constraintOf(err), "a generated key is never the platform key")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET managed = false WHERE id = $1", key)
	assert.Equal(t, "42501", sqlState(err), "no grant on managed")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET private_key_id = NULL WHERE id = $1", key)
	assert.Equal(t, "42501", sqlState(err), "no grant on private_key_id")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET rotated_from = $2 WHERE id = $1", key, key)
	assert.Equal(t, "42501", sqlState(err), "no grant on rotated_from")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET key_comment = 'x' WHERE id = $1", key)
	assert.Equal(t, "42501", sqlState(err), "no grant on key_comment")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET label = 'x' WHERE id = $1", key)
	assert.Equal(t, "42501", sqlState(err), "label has no grant")
	_, err = db.Owner.Exec(ctx, "UPDATE ssh_keys SET label = $2 WHERE id = $1", key, strings.Repeat("l", 101))
	assert.Equal(t, "ssh_keys_label_length", constraintOf(err))
	_, err = db.Owner.Exec(ctx, "UPDATE ssh_keys SET key_comment = 'with space' WHERE id = $1", key)
	assert.Error(t, err, "a comment is printable ASCII without spaces")
	_, err = db.Owner.Exec(ctx, "UPDATE ssh_keys SET key_comment = $2 WHERE id = $1", key, strings.Repeat("c", 101))
	assert.Error(t, err, "a comment is at most 100 characters")
	_, err = db.Owner.Exec(ctx, "UPDATE ssh_keys SET key_comment = 'ci-deploy@alice' WHERE id = $1", key)
	assert.NoError(t, err)

	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, rotNow)
	require.NoError(t, err)
	// S5: a retired key found live again is un-retired.
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = NULL WHERE id = $1", key)
	assert.NoError(t, err, "sshkey.reactivated")

	// rotated_from links the new key to the old one; the application can write it at INSERT only.
	child, pk2 := uuid.New(), uuid.New()
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('d', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, pk2, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, rotated_from, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', true, $3, $4, $5, $5)`, child, "SHA256:"+repeat43("H"), pk2, key, rotNow)
	assert.NoError(t, err)
}

func TestRotationPolicyKeyCheck(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	insert := func(key uuid.UUID) error { return insertPolicy(db, key) }
	key, _ := seedSSHKey(t, db, "SHA256:"+repeat43("D"))
	require.NoError(t, insert(key))
	var overlap, notify int
	var enabled bool
	var typ string
	require.NoError(t, db.App.QueryRow(ctx, "SELECT overlap_minutes, notify_before_hours, enabled, new_key_type FROM rotation_policies WHERE ssh_key_id = $1",
		key).Scan(&overlap, &notify, &enabled, &typ))
	assert.Equal(t, 10080, overlap, "7 days by default")
	assert.Equal(t, 24, notify)
	assert.False(t, enabled, "off by default")
	assert.Equal(t, "same", typ)
	assert.Error(t, insert(key), "one live policy per key")

	discovered := uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', $3, $3)`, discovered, "SHA256:"+repeat43("E"), rotNow)
	require.NoError(t, err)
	assert.Equal(t, "Z1010", sqlState(insert(discovered)), "only keys Alice generated")

	platform := "SHA256:" + repeat43("F")
	_, err = db.Owner.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', jsonb_build_object('fingerprint', $2::text), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $3)`,
		uuid.New(), platform, rotNow)
	require.NoError(t, err)
	own, _ := seedSSHKey(t, db, platform) // impossible through the service; the trigger holds anyway
	assert.Equal(t, "Z1010", sqlState(insert(own)), "never Alice's own key (F-36)")

	retired, _ := seedSSHKey(t, db, "SHA256:"+repeat43("G"))
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", retired, rotNow)
	require.NoError(t, err)
	assert.Equal(t, "Z1010", sqlState(insert(retired)))

	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = true WHERE ssh_key_id = $1", key)
	assert.Equal(t, "rotation_policies_check", constraintOf(err), "enabled needs a next run")
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = true, next_run_at = $2 WHERE ssh_key_id = $1", key, rotNow.Add(time.Hour))
	assert.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET next_run_at = NULL WHERE ssh_key_id = $1", key)
	assert.Error(t, err, "a next run without enabled is refused the other way round too")

	// Moving a policy to another key goes through the trigger; a completed rotation moves it to the new key.
	next, _ := seedSSHKey(t, db, "SHA256:"+repeat43("I"))
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET ssh_key_id = $2 WHERE ssh_key_id = $1", key, discovered)
	assert.Equal(t, "Z1010", sqlState(err), "a policy cannot move to a discovered key")
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET ssh_key_id = $2 WHERE ssh_key_id = $1", key, next)
	assert.NoError(t, err)
	// A soft-deleted policy is not checked and frees the key.
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = false, next_run_at = NULL, deleted_at = $2 WHERE ssh_key_id = $1", next, rotNow)
	assert.NoError(t, err)
	assert.NoError(t, insert(next), "one live policy per key: the deleted one does not count")

	for _, c := range []struct{ set, name string }{
		{"interval_days = 0", "interval"}, {"interval_days = 3651", "interval"}, {"overlap_minutes = -1", "overlap"},
		{"overlap_minutes = 129601", "overlap"}, {"notify_before_hours = 0", "notice"}, {"notify_before_hours = 169", "notice"},
		{"new_key_type = 'dsa'", "type"}, {"name = ''", "name"}, {"version = 0", "version"},
	} {
		_, err = db.Owner.Exec(ctx, "UPDATE rotation_policies SET "+c.set+" WHERE ssh_key_id = $1 AND deleted_at IS NULL", next)
		assert.Equal(t, "23514", sqlState(err), c.name+": "+c.set)
	}
	_, err = db.App.Exec(ctx, "DELETE FROM rotation_policies")
	assert.Equal(t, "42501", sqlState(err), "policies are soft-deleted")
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET created_by = NULL")
	assert.Equal(t, "42501", sqlState(err), "created_by is fixed at insert")
}

// The old-key rule in the schema (C2): removing needs removal_allowed and a fresh verification.
func TestRotationRemovalGuards(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	rot, loc := f.rotation, f.location

	_, err := db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old' WHERE id = $1", rot)
	assert.Error(t, err, "removing_old needs removal_allowed")
	_, err = db.App.Exec(ctx, "UPDATE rotations SET removal_allowed = true WHERE id = $1", rot)
	assert.Error(t, err, "removal_allowed needs verified_at")
	_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $3 WHERE id = $1",
		loc, uuid.New(), rotNow)
	assert.Equal(t, "Z1011", sqlState(err), "the run is not removing")

	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old', removal_allowed = true, verified_at = $2 WHERE id = $1", rot, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4
WHERE id = $1`, loc, uuid.New(), rotNow, rotNow.Add(16*time.Minute))
	assert.Error(t, err, "a verification older than 15 minutes is not fresh")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4
WHERE id = $1`, loc, uuid.New(), rotNow.Add(time.Minute), rotNow)
	assert.Error(t, err, "a verification after the send is not a verification before it")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_sent_at = $3 WHERE id = $1`,
		loc, uuid.New(), rotNow)
	assert.Error(t, err, "a removal needs the verification it relied on")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_verified_at = $2, remove_sent_at = $2 WHERE id = $1`,
		loc, rotNow)
	assert.Error(t, err, "a removal needs its operation id")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4
WHERE id = $1`, loc, uuid.New(), rotNow, rotNow.Add(15*time.Minute))
	assert.NoError(t, err, "exactly 15 minutes is still fresh")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removed', removed_at = $2 WHERE id = $1`, loc, rotNow)
	assert.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET removed_at = NULL, state = 'remove_failed' WHERE id = $1`, loc)
	assert.NoError(t, err, "a failed removal is recorded without a new send")

	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'completed' WHERE id = $1", rot)
	assert.Error(t, err, "a finished run has finished_at")
	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'completed', finished_at = $2 WHERE id = $1", rot, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET backup = 'x' WHERE id = $1", loc)
	assert.Equal(t, "Z1011", sqlState(err), "a finished run's rows are frozen")
}

// A location row cannot be created already removing, and the run's own states gate the update.
func TestRotationLocationInsertCannotStartRemoving(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	second := insertOldLocation(t, db, f.oldKey, f.target, "/home/other/.ssh/authorized_keys")
	insert := func() error {
		_, err := db.App.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state,
    add_sent_at, verified_at, remove_op_id, remove_verified_at, remove_sent_at, updated_at)
VALUES ($1, $2, 2, $3, $4, 'other', '/home/other/.ssh/authorized_keys', 'removing', $5, $5, $6, $5, $5, $5)`,
			uuid.New(), f.rotation, second, f.target, rotNow, uuid.New())
		return err
	}
	assert.Equal(t, "Z1011", sqlState(insert()), "adding_new does not remove")
	_, err := db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old', removal_allowed = true, verified_at = $2 WHERE id = $1", f.rotation, rotNow)
	require.NoError(t, err)
	assert.NoError(t, insert(), "the same insert is fine while the run is removing_old")
}

func TestRotationPlatformFingerprintNeverRemoving(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	tag, err := db.Owner.Exec(ctx, `UPDATE credentials SET public_info = jsonb_build_object('fingerprint', $1::text) WHERE purpose = 'platform_ssh'`, f.oldFP)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old', removal_allowed = true, verified_at = $2 WHERE id = $1", f.rotation, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $3 WHERE id = $1`,
		f.location, uuid.New(), rotNow)
	assert.Equal(t, "Z1011", sqlState(err), "Alice's own key is never removed, whatever the run says")

	// Another fingerprint on the platform credential: the same statement goes through.
	_, err = db.Owner.Exec(ctx, `UPDATE credentials SET public_info = jsonb_build_object('fingerprint', $1::text) WHERE purpose = 'platform_ssh'`,
		"SHA256:"+repeat43("Z"))
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $3 WHERE id = $1`,
		f.location, uuid.New(), rotNow)
	assert.NoError(t, err)
}

// The CHECKs of rotations and the unique indexes that keep one live run per key and per policy.
func TestRotationRunConstraints(t *testing.T) {
	db := pgtest.New(t)
	f := seedRotation(t, db)
	done := rotNow.Add(time.Hour)
	other, _ := seedSSHKey(t, db, "SHA256:"+repeat43("P"))
	newKey := f.newKey
	paused := rotNow

	for _, c := range []struct {
		name string
		o    runOpts
	}{
		{"removing_old needs removal_allowed", runOpts{status: "removing_old", newKey: &newKey}},
		{"removal_allowed needs verified_at", runOpts{removalAllowed: true, newKey: &newKey}},
		{"removal_allowed needs the new key", runOpts{removalAllowed: true, verifiedAt: &done}},
		{"the new key is not the old one", runOpts{newKey: &other}},
		{"a running run has its new key", runOpts{status: "verifying_new"}},
		{"paused flag and time agree", runOpts{newKey: &newKey, paused: true}},
		{"paused time needs the flag", runOpts{newKey: &newKey, pausedAt: &paused}},
		{"awaiting needs a due time", runOpts{newKey: &newKey, awaiting: true}},
		{"a due time needs awaiting", runOpts{newKey: &newKey, dueAt: &done}},
		{"completed has finished_at", runOpts{status: "completed", newKey: &newKey}},
		{"a live run has no finished_at", runOpts{newKey: &newKey, finishedAt: &done}},
		{"digest is a sha256", runOpts{newKey: &newKey, digest: "xyz"}},
		{"new key type is a closed list", runOpts{newKey: &newKey, newKeyType: "same"}},
		{"overlap is bounded", runOpts{newKey: &newKey, overlap: 129601}},
		{"status is a closed list", runOpts{status: "weird", newKey: &newKey}},
		{"result code has the code form", runOpts{status: "cancelled", finishedAt: &done, resultCode: "Not A Code"}},
		{"kept_count is not negative", runOpts{newKey: &newKey, keptCount: -1}},
	} {
		// Finished and cancelled runs do not hold the unique indexes; the live ones would collide with the
		// seeded run, so every case is first checked against a fresh policy and key where it needs one.
		_, err := insertRun(db, f.policy, other, c.o)
		assert.Equal(t, "23514", sqlState(err), c.name)
	}

	// A run that is dry_run_notified or cancelled has no new key (the plan's preview); S1: cancelled with a
	// result code of the new reason; S11: kept_count; S6: verifying_new paused with its deadline waiting.
	id, err := insertRun(db, f.policy, other, runOpts{status: "cancelled", finishedAt: &done, resultCode: "rotation.notice_undelivered"})
	assert.NoError(t, err, "S1: a scheduled run whose notice was never delivered ends cancelled with a result code")
	assert.NotEqual(t, uuid.Nil, id)
	_, err = insertRun(db, f.policy, other, runOpts{status: "aborted", finishedAt: &done, newKey: &newKey, keptCount: 3, resultCode: "rotation.partial"})
	assert.NoError(t, err, "S11: a finished run holds kept_count")
	_, err = insertRun(db, f.policy, other, runOpts{status: "cancelled", finishedAt: &done, resultCode: "rotation.policy_off"})
	assert.NoError(t, err)

	// One live run per policy and per key.
	_, err = insertRun(db, f.policy, other, runOpts{status: "dry_run_notified"})
	assert.Equal(t, "rotations_one_live_per_policy", constraintOf(err))
	_, err = db.App.Exec(context.Background(), "UPDATE rotation_policies SET deleted_at = $2 WHERE id = $1", f.policy, rotNow)
	require.NoError(t, err)
	var second uuid.UUID
	require.NoError(t, db.App.QueryRow(context.Background(), `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at)
VALUES (gen_random_uuid(), $1, 'again', 30, $2, $2) RETURNING id`, f.oldKey, rotNow).Scan(&second))
	_, err = insertRun(db, second, f.oldKey, runOpts{status: "dry_run_notified"})
	assert.Equal(t, "rotations_one_live_per_key", constraintOf(err), "a new policy of the same key does not allow a second live run")
	_, err = db.App.Exec(context.Background(), "UPDATE rotations SET status = 'aborted', finished_at = $2 WHERE id = $1", f.rotation, rotNow)
	require.NoError(t, err)
	_, err = insertRun(db, second, f.oldKey, runOpts{status: "dry_run_notified"})
	assert.NoError(t, err, "a finished run frees the key")
}

// What the rulings S3, S4, S6, S11 and S12 need the schema to hold.
func TestRotationRulingStatesAreHeld(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	due := rotNow.Add(14 * 24 * time.Hour)

	// S6: verifying_new paused in lock, its deadline kept; the notice after the renewal is renotified_at.
	_, err := db.App.Exec(ctx, `UPDATE rotations SET status = 'verifying_new', paused_license = true, paused_at = $2, awaiting_decision = true,
    decision_due_at = $3, renotified_at = $2, continued_at = $2, kept_count = 2, version = version + 1 WHERE id = $1`, f.rotation, rotNow, due)
	assert.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotations SET paused_license = false, paused_at = NULL, decision_due_at = $2 WHERE id = $1`, f.rotation, due.Add(time.Hour))
	assert.NoError(t, err, "Continue moves the deadline by the time spent paused")

	// S3, S4, S12: a location whose add was sent can be undoing, undone and undo_failed (reason old_key_gone).
	for _, st := range []string{"adding", "added", "undoing", "undone", "unverifiable", "kept_old", "verify_failed", "add_failed"} {
		_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET state = $2, add_sent_at = $3, add_op_id = gen_random_uuid() WHERE id = $1", f.location, st, rotNow)
		assert.NoError(t, err, st)
	}
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'undo_failed', error_code = 'rotation.old_key_gone', undo_sent_at = NULL WHERE id = $1`, f.location)
	assert.NoError(t, err, "S12: an undo that finds the old key gone sends nothing and ends undo_failed")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET error_code = 'Rotation Old' WHERE id = $1`, f.location)
	assert.Error(t, err, "an error code keeps the code form")

	// A location that never had an add sent cannot be undone or verified.
	other := insertOldLocation(t, db, f.oldKey, f.target, "/home/x/.ssh/authorized_keys")
	insert := func(state string, sent, verified *time.Time) error {
		_, err := db.App.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state,
    add_sent_at, verified_at, skip_reason, updated_at) VALUES (gen_random_uuid(), $1, 2, $2, $3, 'x', '/home/x/.ssh/authorized_keys', $4, $5, $6, '', $7)`,
			f.rotation, other, f.target, state, sent, verified, rotNow)
		return err
	}
	assert.Error(t, insert("undone", nil, nil), "undone needs add_sent_at")
	assert.Error(t, insert("undo_failed", nil, nil), "undo_failed needs add_sent_at")
	assert.Error(t, insert("verified", nil, &rotNow), "verified_at needs add_sent_at")
	assert.Error(t, insert("skipped", nil, nil), "skipped needs a reason")
	assert.NoError(t, insert("planned", nil, nil))
}

func TestRotationLocationConstraints(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	for _, c := range []struct{ set, name string }{
		{"state = 'weird'", "state is a closed list"},
		{"verify_note = 'other'", "verify_note is a closed list"},
		{"skip_reason = 'Not Valid'", "skip_reason form"},
		{"added_line_no = 0", "line numbers start at 1"},
		{"job_count = 1001", "job_count is bounded"},
		{"state = 'skipped', skip_reason = ''", "skipped has a reason"},
		{"removed_at = $2", "removed_at only in removed"},
		{"backup = repeat('b', 201)", "backup is bounded"},
		{"verified_at = NULL, reverified_at = $2, remove_verified_at = $2", "remove_verified_at needs verified_at"},
	} {
		sql := "UPDATE rotation_locations SET " + c.set + " WHERE id = $1"
		var err error
		if strings.Contains(c.set, "$2") {
			_, err = db.Owner.Exec(ctx, sql, f.location, rotNow)
		} else {
			_, err = db.Owner.Exec(ctx, sql, f.location)
		}
		assert.Equal(t, "23514", sqlState(err), c.name)
	}
	_, err := db.Owner.Exec(ctx, `UPDATE rotation_locations SET n = 0 WHERE id = $1`, f.location)
	assert.Equal(t, "23514", sqlState(err), "n starts at 1")
	_, err = db.App.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES (gen_random_uuid(), $1, 1, $2, $3, 'x', '/p', 'planned', $4)`, f.rotation, f.oldLoc, f.target, rotNow)
	assert.Equal(t, "23505", sqlState(err), "one row per location number and per old location")

	// Fixed at insert: the application cannot update these columns.
	for _, col := range []string{"rotation_id", "n", "old_location_id", "target_id", "os_user", "file_path", "options"} {
		_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET "+col+" = "+col+" WHERE id = $1", f.location)
		assert.Equal(t, "42501", sqlState(err), col)
	}
	for _, col := range []string{"plan", "plan_digest", "new_key_type", "overlap_minutes", "planned_for", "notified_at", "policy_id", "old_ssh_key_id", "trigger", "created_at"} {
		_, err = db.App.Exec(ctx, "UPDATE rotations SET "+col+" = "+col+" WHERE id = $1", f.rotation)
		assert.Equal(t, "42501", sqlState(err), col+" is fixed at insert")
	}
	_, err = db.App.Exec(ctx, "DELETE FROM rotations")
	assert.Equal(t, "42501", sqlState(err))
	_, err = db.App.Exec(ctx, "DELETE FROM rotation_locations")
	assert.Equal(t, "42501", sqlState(err))
}

func TestRotationStepsAreAppendOnly(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	insert := func(n int, name, status, params string) error {
		_, err := db.App.Exec(ctx, `INSERT INTO rotation_steps (id, rotation_id, n, location_id, name, status, at, params)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7::jsonb)`, f.rotation, n, f.location, name, status, rotNow, params)
		return err
	}
	require.NoError(t, insert(1, "add_started", "started", `{"target_id": "x"}`))
	assert.Equal(t, "23505", sqlState(insert(1, "add_ok", "ok", `{}`)), "step numbers are unique per run")
	assert.Equal(t, "23514", sqlState(insert(2, "Add", "ok", `{}`)), "step names have the code form")
	assert.Equal(t, "23514", sqlState(insert(2, "add", "done", `{}`)), "status is a closed list")
	assert.Equal(t, "23514", sqlState(insert(2, "add", "ok", `[]`)), "params is an object")
	assert.Equal(t, "23514", sqlState(insert(0, "add", "ok", `{}`)))
	assert.Equal(t, "23514", sqlState(insert(2, "add", "ok", `{"x": "`+strings.Repeat("y", 4100)+`"}`)), "params are bounded")
	_, err := db.App.Exec(ctx, "UPDATE rotation_steps SET status = 'failed'")
	assert.Equal(t, "42501", sqlState(err))
	_, err = db.App.Exec(ctx, "DELETE FROM rotation_steps")
	assert.Equal(t, "42501", sqlState(err))
}

func TestRotationTablesRefuseOddRows(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := seedRotation(t, db)
	_, err := db.App.Exec(ctx, `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes,
    planned_for, notified_at, created_at, updated_at) VALUES (gen_random_uuid(), $1, $2, 'cron', 'cancelled', '{}', repeat('0', 64), 'ed25519', 1, $3, $3, $3, $3)`,
		f.policy, f.oldKey, rotNow)
	assert.Equal(t, "23514", sqlState(err), "trigger is closed to scheduled and manual")
	_, err = db.Owner.Exec(ctx, `UPDATE rotations SET plan = '[]' WHERE id = $1`, f.rotation)
	assert.Equal(t, "23514", sqlState(err), "a plan is an object")
	_, err = db.Owner.Exec(ctx, `UPDATE rotations SET plan = jsonb_build_object('x', repeat('y', 2097152)) WHERE id = $1`, f.rotation)
	assert.Equal(t, "23514", sqlState(err), "a plan is at most 2 MiB")
}

// Migration 00010 goes up over a database that holds Phase 3 to 5 data, goes down to 00009 with that data
// intact, refuses the Down when Phase 6 data exists (changing nothing) and goes up again.
func TestMigration00010UpAndDownKeepEarlierData(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)

	_, err = p.DownTo(ctx, 9)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(9), version)
	for _, tbl := range []string{"rotation_policies", "rotations", "rotation_locations", "rotation_steps"} {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	var cols int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND
((table_name = 'managed_private_keys' AND column_name IN ('download_count', 'last_downloaded_at', 'destroyed_at'))
 OR (table_name = 'ssh_keys' AND column_name IN ('private_key_id', 'key_comment', 'rotated_from', 'created_by')))`).Scan(&cols))
	assert.Equal(t, 0, cols)
	assert.ElementsMatch(t, []string{"public.ssh_keys", "public.managed_private_keys"}, grantProblems(t, d),
		"no Phase 6 grant is left behind: the guard lists the two tables whose column grants it expects")
	var fn int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname IN ('managed_private_keys_guard', 'rotation_policies_check_key', 'rotation_locations_guard')`).Scan(&fn))
	assert.Equal(t, 0, fn, "the Down drops the trigger functions")
	// The 00009 shapes are back.
	assert.Equal(t, "23514", sqlState(exec(t, d.Owner, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES (gen_random_uuid(), 'ssh_key', 'ed25519', 256, repeat('b', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`)))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, "UPDATE ssh_keys SET retired_at = now()")), "retired_at has no grant below 00010")

	// Phase 3 to 5 data that must survive both directions.
	server := seedTarget(t, d, "web-01", "web-01.example.com")
	require.NoError(t, exec(t, d.App, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES (gen_random_uuid(), $1, 'ssh-ed25519', 'k', now(), now())`, "SHA256:"+repeat43("Q")))
	discovered := scanID(t, d, "SELECT id::text FROM ssh_keys")
	require.NoError(t, exec(t, d.App, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, $2, 'deploy', '/home/deploy/.ssh/authorized_keys', 1, now(), now())`, discovered, server))
	leaf := insertCertificate(t, d)
	loc := insertLocation(t, d, server)
	addVault(t, d, "kv1")
	require.NoError(t, exec(t, d.App, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, 'manual', 'queued', 'pending', repeat('e', 64), '/etc/ssl/a.pem', '/etc/ssl/a.key', now())`, leaf, loc, server))
	count := func() (n [6]int) {
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM targets), (SELECT count(*) FROM credentials), (SELECT count(*) FROM ssh_keys),
(SELECT count(*) FROM ssh_key_locations), (SELECT count(*) FROM managed_private_keys), (SELECT count(*) FROM deployments)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]))
		return
	}
	want := count()

	_, err = p.Up(ctx)
	require.NoError(t, err, "00010 applies over Phase 3 to 5 data")
	assert.Empty(t, grantProblems(t, d))
	assert.Equal(t, want, count(), "earlier data survives the Up")
	var managed int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM ssh_keys WHERE managed OR private_key_id IS NOT NULL OR key_comment <> ''").Scan(&managed))
	assert.Equal(t, 0, managed, "a discovered key stays discovered")
	var dl int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT coalesce(sum(download_count), 0) FROM managed_private_keys").Scan(&dl))
	assert.Equal(t, 0, dl)

	_, err = p.DownTo(ctx, 9)
	require.NoError(t, err, "no Phase 6 data: the Down goes through")
	assert.Equal(t, want, count(), "earlier data survives the Down")
	_, err = p.Up(ctx)
	require.NoError(t, err)

	// Each kind of Phase 6 data refuses the Down whole.
	refused := func(what string) {
		t.Helper()
		_, err := p.DownTo(ctx, 9)
		require.Error(t, err, what)
		assert.Equal(t, "Z1012", sqlState(err), what)
		assert.ErrorContains(t, err, "rotation data exists")
		version, err := p.GetDBVersion(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(10), version, what)
		assert.True(t, tableExists(t, d, "rotations"), what)
	}
	key, pk := seedSSHKey(t, d, "SHA256:"+repeat43("R"))
	refused("a generated key")
	require.NoError(t, exec(t, d.Owner, "UPDATE ssh_keys SET managed = false, private_key_id = NULL WHERE id = $1", key))
	refused("an SSH-owned or Ed25519 private key")
	require.NoError(t, exec(t, d.Owner, "UPDATE managed_private_keys SET destroyed_at = now(), ciphertext = NULL, nonce = NULL, wrapped_dek = NULL, key_version = NULL WHERE id = $1", pk))
	refused("a destroyed key")
	require.NoError(t, exec(t, d.Owner, "DELETE FROM managed_private_keys WHERE id = $1", pk))
	require.NoError(t, exec(t, d.Owner, "DELETE FROM ssh_keys WHERE id = $1", key))
	_, err = p.DownTo(ctx, 9)
	require.NoError(t, err, "without Phase 6 data the Down goes through")
	assert.False(t, tableExists(t, d, "rotations"))
	_, err = p.Up(ctx)
	require.NoError(t, err)

	// A policy or a run alone refuses too.
	k2, _ := seedSSHKey(t, d, "SHA256:"+repeat43("S"))
	require.NoError(t, insertPolicy(d, k2))
	require.NoError(t, exec(t, d.Owner, "UPDATE ssh_keys SET managed = false, private_key_id = NULL WHERE id = $1", k2)) // only the policy row is left to refuse
	require.NoError(t, exec(t, d.Owner, "DELETE FROM managed_private_keys WHERE owner_type = 'ssh_key'"))
	refused("a rotation policy")
}
