//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"slices"
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

func TestManagedPrivateKeyGuard(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	key, pk := seedSSHKey(t, db, "SHA256:"+repeat43("A"))

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
	destroy := `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL, key_version = NULL WHERE id = $1`
	_, err = db.App.Exec(ctx, destroy, pk, rotNow)
	assert.Equal(t, "Z1009", sqlState(err), "a live key's private key is never destroyed")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, rotNow)
	require.NoError(t, err)
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
	_, err = db.App.Exec(ctx, destroy, cert, rotNow)
	assert.Equal(t, "Z1009", sqlState(err), "a certificate key is not destroyed (no retired SSH key owns it)")
	guardOff(t, db, "managed_private_keys", "managed_private_keys_guard", func() {
		_, err := db.Owner.Exec(ctx, destroy, cert, rotNow)
		assert.Equal(t, "managed_private_keys_destroyed", constraintOf(err), "nor by the CHECK, whoever asks")
	})
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

// SEC-041/042: the master-key re-wrap changes the wrapped key and the version together, upwards, and never the
// payload; M-3: the download time moves only with the count, forwards.
func TestPrivateKeyRewrapAndDownloadTime(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	_, pk := seedSSHKey(t, db, "SHA256:"+repeat43("A"))
	exec := func(set string, args ...any) error {
		_, err := db.App.Exec(ctx, "UPDATE managed_private_keys SET "+set+" WHERE id = $1", append([]any{pk}, args...)...)
		return err
	}
	assert.NoError(t, exec(`wrapped_dek = '\x07', key_version = 2`), "a re-wrap: the wrapped key and the version together")
	assert.NoError(t, exec(`wrapped_dek = '\x08', key_version = 5`))
	assert.Equal(t, "Z1009", sqlState(exec(`wrapped_dek = '\x09'`)), "a new wrapped key without a new version")
	assert.Equal(t, "Z1009", sqlState(exec(`key_version = 6`)), "a new version without a new wrapped key")
	assert.Equal(t, "Z1009", sqlState(exec(`wrapped_dek = '\x0a', key_version = 4`)), "the version does not go back")
	assert.Equal(t, "Z1009", sqlState(exec(`wrapped_dek = '\x0a', key_version = 6, ciphertext = '\x09'`)), "never the payload")
	assert.Equal(t, "Z1009", sqlState(exec(`wrapped_dek = '\x0a', key_version = 6, nonce = decode(repeat('01', 12), 'hex')`)), "nor its nonce")

	assert.Equal(t, "Z1009", sqlState(exec(`last_downloaded_at = $2`, rotNow)), "a time without a count")
	assert.Equal(t, "Z1009", sqlState(exec(`download_count = download_count + 1`)), "a count without a time")
	assert.NoError(t, exec(`download_count = download_count + 1, last_downloaded_at = $2`, rotNow))
	assert.Equal(t, "Z1009", sqlState(exec(`download_count = download_count + 1, last_downloaded_at = $2`, rotNow.Add(-time.Hour))), "not backwards")
	assert.Equal(t, "Z1009", sqlState(exec(`last_downloaded_at = $2`, rotNow.Add(time.Hour))), "not forwards on its own either")
	assert.Equal(t, "Z1009", sqlState(exec(`download_count = download_count + 1, last_downloaded_at = NULL`)), "a count needs its time")
	assert.NoError(t, exec(`download_count = download_count + 1, last_downloaded_at = $2`, rotNow.Add(time.Hour)))
}

// A generated key's private key is a live SSH private key, and a key whose private key was destroyed stays retired.
func TestSSHKeyPrivateKeyOwnerAndReactivation(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	cert := uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek,
    key_version, created_at) VALUES ($1, 'certificate', 'rsa', 2048, repeat('c', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, cert, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES (gen_random_uuid(), $1, 'ssh-rsa', 'k', true, $2, $3, $3)`, "SHA256:"+repeat43("C"), cert, rotNow)
	assert.Equal(t, "Z1014", sqlState(err), "a certificate's private key cannot back an SSH key (it would be served as a download)")

	key, pk := seedSSHKey(t, db, "SHA256:"+repeat43("D"))
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = NULL WHERE id = $1", key)
	assert.NoError(t, err, "S5: a retired key whose private key still exists is un-retired")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL, key_version = NULL WHERE id = $1`, pk, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = NULL WHERE id = $1", key)
	assert.Equal(t, "Z1014", sqlState(err), "a key whose private key was destroyed is not un-retired")
	// A new key cannot be given a destroyed private key.
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES (gen_random_uuid(), $1, 'ssh-ed25519', 'k', true, $2, $3, $3)`, "SHA256:"+repeat43("E"), pk, rotNow)
	assert.Error(t, err)
}

// M-6: switching a policy on re-checks its key; switching it off never needs the key.
func TestRotationPolicyEnableRechecksTheKey(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	key, _ := seedSSHKey(t, db, "SHA256:"+repeat43("A"))
	require.NoError(t, insertPolicy(db, key))
	_, err := db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = true, next_run_at = $2 WHERE ssh_key_id = $1", key, rotNow.Add(time.Hour))
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = false, next_run_at = NULL WHERE ssh_key_id = $1", key)
	assert.NoError(t, err, "an off policy of a retired key can be switched off")
	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = true, next_run_at = $2 WHERE ssh_key_id = $1", key, rotNow.Add(time.Hour))
	assert.Equal(t, "Z1010", sqlState(err), "switching on re-checks the key (it was retired meanwhile)")
}

// seedReplacementKey inserts a generated key that replaces `from` (rotated_from), as a rotation's start does.
func seedReplacementKey(t *testing.T, db *pgtest.DB, fp string, from uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	pk, key := uuid.New(), uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('c', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, pk, rotNow)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, rotated_from, first_seen_at,
    created_at) VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $5, $5)`, key, fp, pk, from, rotNow)
	require.NoError(t, err)
	return key
}

// insertKeyLocation records one place of a key on the target (the inventory's row).
func insertKeyLocation(t *testing.T, db *pgtest.DB, key uuid.UUID, target, user, file string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.App.Exec(context.Background(), `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, 1, $6, $6)`, id, key, target, user, file, rotNow)
	require.NoError(t, err)
	return id
}

// rotFx is a rotation seeded through the legal path: a target, a generated old key with n locations, a policy,
// a run in dry_run_notified and n planned rotation locations. The methods move it along C8.
type rotFx struct {
	t              *testing.T
	db             *pgtest.DB
	target         string
	oldKey, newKey uuid.UUID
	oldFP, newFP   string
	policy, run    uuid.UUID
	locs           []uuid.UUID // rotation_locations
	oldLocs        []uuid.UUID
	newLocs        []uuid.UUID
	files          []string
}

func newRotFx(t *testing.T, db *pgtest.DB, n int) *rotFx {
	t.Helper()
	f := &rotFx{t: t, db: db, oldFP: "SHA256:" + repeat43("O"), newFP: "SHA256:" + repeat43("N")}
	ctx := context.Background()
	f.target = seedTarget(t, db, "web-01", "web-01.example.com")
	f.oldKey, _ = seedSSHKey(t, db, f.oldFP)
	require.NoError(t, insertPolicy(db, f.oldKey))
	require.NoError(t, db.App.QueryRow(ctx, "SELECT id FROM rotation_policies WHERE ssh_key_id = $1", f.oldKey).Scan(&f.policy))
	f.run = uuid.New()
	f.must(`INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes, planned_for,
    notified_at, created_at, updated_at) VALUES ($1, $2, $3, 'manual', 'dry_run_notified', '{}', repeat('0', 64), 'ed25519', 1, $4, $4, $4, $4)`,
		f.run, f.policy, f.oldKey, rotNow)
	for i := 0; i < n; i++ {
		file := "/home/u" + string(rune('a'+i)) + "/.ssh/authorized_keys"
		user := "u" + string(rune('a'+i))
		f.files = append(f.files, file)
		old := insertKeyLocation(t, db, f.oldKey, f.target, user, file)
		f.oldLocs = append(f.oldLocs, old)
		id := uuid.New()
		f.must(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'planned', $8)`, id, f.run, i+1, old, f.target, user, file, rotNow)
		f.locs = append(f.locs, id)
	}
	return f
}

func (f *rotFx) x(sql string, args ...any) error {
	f.t.Helper()
	_, err := f.db.App.Exec(context.Background(), sql, args...)
	return err
}

func (f *rotFx) must(sql string, args ...any) {
	f.t.Helper()
	require.NoError(f.t, f.x(sql, args...))
}

// runSet runs UPDATE rotations SET <set> for the run; the arguments are $2, $3, ...
func (f *rotFx) runSet(set string, args ...any) error {
	return f.x("UPDATE rotations SET "+set+" WHERE id = $1", append([]any{f.run}, args...)...)
}

// locSet runs UPDATE rotation_locations SET <set> for location i; the arguments are $2, $3, ...
func (f *rotFx) locSet(i int, set string, args ...any) error {
	return f.x("UPDATE rotation_locations SET "+set+" WHERE id = $1", append([]any{f.locs[i]}, args...)...)
}

func (f *rotFx) mustLoc(i int, set string, args ...any) {
	f.t.Helper()
	require.NoError(f.t, f.locSet(i, set, args...))
}

func (f *rotFx) state(i int) string {
	var s string
	require.NoError(f.t, f.db.Owner.QueryRow(context.Background(), "SELECT state FROM rotation_locations WHERE id = $1", f.locs[i]).Scan(&s))
	return s
}

// start generates the new key and moves the run to adding_new.
func (f *rotFx) start() {
	f.t.Helper()
	f.newKey = seedReplacementKey(f.t, f.db, f.newFP, f.oldKey)
	f.must("UPDATE rotations SET status = 'adding_new', new_ssh_key_id = $2, started_at = $3 WHERE id = $1", f.run, f.newKey, rotNow)
}

// added moves location i planned -> adding -> added (records the new key's place).
func (f *rotFx) added(i int) {
	f.t.Helper()
	f.mustLoc(i, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	var user, file string
	require.NoError(f.t, f.db.Owner.QueryRow(context.Background(), "SELECT os_user, file_path FROM rotation_locations WHERE id = $1", f.locs[i]).Scan(&user, &file))
	nl := insertKeyLocation(f.t, f.db, f.newKey, f.target, user, file)
	f.newLocs = append(f.newLocs, nl)
	f.mustLoc(i, "state = 'added', added_line_no = 2, new_location_id = $2", nl)
}

// verified moves location i to verified through adding and added.
func (f *rotFx) verified(i int) {
	f.t.Helper()
	f.added(i)
	f.mustLoc(i, "state = 'verified', verified_at = $2", rotNow)
}

func (f *rotFx) overlap() {
	f.t.Helper()
	f.must("UPDATE rotations SET status = 'overlap', verified_at = $2, overlap_until = $3 WHERE id = $1", f.run, rotNow, rotNow.Add(time.Hour))
}

func (f *rotFx) removingOld() {
	f.t.Helper()
	f.must("UPDATE rotations SET status = 'removing_old', removal_allowed = true WHERE id = $1", f.run)
}

// recheck records a fresh login with the new key on location i.
func (f *rotFx) recheck(i int, at time.Time) {
	f.t.Helper()
	f.mustLoc(i, "reverified_at = $2", at)
}

// startRemoving sends the removal on location i (verified, re-checked at `checked`, sent at `sent`).
func (f *rotFx) startRemoving(i int, checked, sent time.Time) error {
	return f.locSet(i, "state = 'removing', remove_op_id = gen_random_uuid(), remove_verified_at = reverified_at, remove_sent_at = $2", sent)
}

// readyToRemove: location 0 verified, run in removing_old, location 0 re-checked at rotNow+1m.
func readyToRemove(t *testing.T, db *pgtest.DB, n int) *rotFx {
	t.Helper()
	f := newRotFx(t, db, n)
	f.start()
	f.verified(0)
	f.overlap()
	f.removingOld()
	f.recheck(0, rotNow.Add(time.Minute))
	return f
}

// guardOff switches a trigger off (as the owner) for one fixture statement and back on: the CHECK constraints
// are tested on rows the guards would refuse earlier.
func guardOff(t *testing.T, db *pgtest.DB, table, trigger string, fn func()) {
	t.Helper()
	ctx := context.Background()
	_, err := db.Owner.Exec(ctx, "ALTER TABLE "+table+" DISABLE TRIGGER "+trigger)
	require.NoError(t, err)
	defer func() {
		_, err := db.Owner.Exec(ctx, "ALTER TABLE "+table+" ENABLE TRIGGER "+trigger)
		require.NoError(t, err)
	}()
	fn()
}

// insertRun inserts a preview run (the only kind the guard accepts) for the policy and old key.
func insertRun(db *pgtest.DB, policy, oldKey uuid.UUID, status string, newKey *uuid.UUID) error {
	_, err := db.App.Exec(context.Background(), `INSERT INTO rotations (id, policy_id, old_ssh_key_id, new_ssh_key_id, trigger, status, plan, plan_digest,
    new_key_type, overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, 'manual', $4, '{}', repeat('0', 64), 'ed25519', 1, $5, $5, $5, $5)`, policy, oldKey, newKey, status, rotNow)
	return err
}

func TestRotationInsertGuards(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	other, _ := seedSSHKey(t, db, "SHA256:"+repeat43("X"))
	// Control: a valid preview passes the guard and meets the unique index of the live run.
	assert.Contains(t, []string{"rotations_one_live_per_policy", "rotations_one_live_per_key"}, constraintOf(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)))
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "adding_new", &other)), "a rotation starts as a preview")
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "dry_run_notified", &other)), "no key chosen at insert")
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "cancelled", nil)), "no finished run is inserted")
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, other, "dry_run_notified", nil)), "the old key is the policy's key")

	// Alice's own fingerprint on the policy's key (the credential was set after the policy: impossible through the service).
	_, err := db.Owner.Exec(context.Background(), `UPDATE credentials SET public_info = jsonb_build_object('fingerprint', $1::text) WHERE purpose = 'platform_ssh'`, f.oldFP)
	require.NoError(t, err)
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)), "never Alice's own key")
	_, err = db.Owner.Exec(context.Background(), `UPDATE credentials SET public_info = '{}' WHERE purpose = 'platform_ssh'`)
	require.NoError(t, err)
	assert.Contains(t, []string{"rotations_one_live_per_policy", "rotations_one_live_per_key"}, constraintOf(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)))

	// A retired key and a deleted policy.
	require.NoError(t, f.x("UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", f.oldKey, rotNow))
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)), "a retired key is not rotated")
	require.NoError(t, f.x("UPDATE ssh_keys SET retired_at = NULL WHERE id = $1", f.oldKey))
	require.NoError(t, f.x("UPDATE rotation_policies SET deleted_at = $2 WHERE id = $1", f.policy, rotNow))
	assert.Equal(t, "Z1013", sqlState(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)), "a deleted policy starts nothing")
}

func TestRotationRunCannotBeRewrittenOnceFinished(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	f.start()
	f.verified(0)
	f.overlap()
	f.removingOld()
	f.recheck(0, rotNow)
	require.NoError(t, f.startRemoving(0, rotNow, rotNow))
	f.mustLoc(0, "state = 'removed', removed_at = $2", rotNow)
	require.NoError(t, f.runSet("status = 'completed', finished_at = $2, result_code = 'rotation.done'", rotNow))

	for _, c := range []struct{ set, why string }{
		{"status = 'removing_old', finished_at = NULL", "un-finishing"},
		{"finished_at = NULL", "finished_at back to NULL"},
		{"result_code = 'rotation.other'", "result_code"},
		{"kept_count = 5", "kept_count"},
		{"removal_allowed = false", "removal_allowed"},
		{"verified_at = $2", "verified_at"},
		{"status = 'aborted'", "another end"},
	} {
		var args []any
		if strings.Contains(c.set, "$2") {
			args = append(args, rotNow.Add(time.Hour))
		}
		assert.Equal(t, "Z1013", sqlState(f.runSet(c.set, args...)), c.why)
	}
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'remove_failed', removed_at = NULL")), "a finished run's removed location is not rewritten")
}

func TestRotationKeysAreFixed(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	require.NoError(t, f.runSet("version = version + 1"), "an ordinary change of a preview")
	// The new key: never Alice's own, never an unrelated key, never a discovered one.
	unrelated, _ := seedSSHKey(t, db, "SHA256:"+repeat43("U"))
	discovered := uuid.New()
	f.must(`INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at) VALUES ($1, $2, 'ssh-ed25519', 'k', $3, $3)`,
		discovered, "SHA256:"+repeat43("V"), rotNow)
	own := seedReplacementKey(t, db, "SHA256:"+repeat43("W"), f.oldKey)
	_, err := db.Owner.Exec(context.Background(), `UPDATE credentials SET public_info = jsonb_build_object('fingerprint', $1::text) WHERE purpose = 'platform_ssh'`, "SHA256:"+repeat43("W"))
	require.NoError(t, err)
	start := func(key uuid.UUID) error {
		return f.runSet("status = 'adding_new', new_ssh_key_id = $2, started_at = $3", key, rotNow)
	}
	assert.Equal(t, "Z1013", sqlState(start(own)), "Alice's own fingerprint is not a new key")
	assert.Equal(t, "Z1013", sqlState(start(unrelated)), "the new key replaces the old one (rotated_from)")
	assert.Equal(t, "Z1013", sqlState(start(discovered)), "a discovered key is not a new key")
	assert.Equal(t, "Z1013", sqlState(start(f.oldKey)), "not the old key itself")
	_, err = db.Owner.Exec(context.Background(), `UPDATE credentials SET public_info = '{}' WHERE purpose = 'platform_ssh'`)
	require.NoError(t, err)
	assert.Equal(t, "rotations_new_key_set", constraintOf(f.runSet("status = 'adding_new'")), "a started run has its new key")
	f.start()

	// Chosen once; the policy and the old key never change.
	assert.Equal(t, "Z1013", sqlState(f.runSet("new_ssh_key_id = $2", unrelated)), "the new key is not retargeted")
	assert.Equal(t, "Z1013", sqlState(f.runSet("new_ssh_key_id = NULL")), "nor cleared")
	assert.Equal(t, "42501", sqlState(f.runSet("old_ssh_key_id = $2", unrelated)), "no grant on the old key")
	assert.Equal(t, "42501", sqlState(f.runSet("policy_id = gen_random_uuid()")), "no grant on the policy")
	_, err = db.Owner.Exec(context.Background(), "UPDATE rotations SET old_ssh_key_id = $1 WHERE id = $2", unrelated, f.run)
	assert.Equal(t, "Z1013", sqlState(err), "the guard holds for every role")
	assert.NoError(t, f.runSet("new_ssh_key_id = $2", f.newKey), "the same value is not a change")
}

func TestRotationRunEdges(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	// Illegal edges of a preview.
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'overlap', verified_at = $2", rotNow)), "dry_run_notified -> overlap")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'rolling_back'")), "dry_run_notified -> rolling_back")
	f.start()
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'completed', finished_at = $2", rotNow)), "adding_new -> completed")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'dry_run_notified'")), "never back to the preview")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'removing_old', removal_allowed = true, verified_at = $2", rotNow)), "adding_new -> removing_old")
	assert.Equal(t, "Z1013", sqlState(f.runSet("removal_allowed = true, verified_at = $2", rotNow)), "removal is allowed only on the edge into removing_old")
	// A pause and a decision are changes in place (S6: verifying_new is paused too).
	require.NoError(t, f.runSet("paused_license = true, paused_at = $2", rotNow))
	require.NoError(t, f.runSet("paused_license = false, paused_at = NULL, status = 'verifying_new', awaiting_decision = true, decision_due_at = $2", rotNow.Add(time.Hour)))
	require.NoError(t, f.runSet("paused_license = true, paused_at = $2", rotNow))
	require.NoError(t, f.runSet("paused_license = false, paused_at = NULL, status = 'overlap', verified_at = $2, awaiting_decision = false, decision_due_at = NULL, overlap_until = $2", rotNow))
	assert.Equal(t, "Z1013", sqlState(f.runSet("verified_at = $2", rotNow.Add(time.Minute))), "the verification time is set once")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'completed', finished_at = $2", rotNow)), "overlap -> completed")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'verifying_new'")), "overlap -> verifying_new")
	require.NoError(t, f.runSet("status = 'removing_old', removal_allowed = true"))
	assert.Equal(t, "Z1013", sqlState(f.runSet("removal_allowed = false")), "removal stays allowed")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'rolling_back'")), "removing_old -> rolling_back (no abort once removing)")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'aborted', finished_at = $2", rotNow)), "removing_old -> aborted")
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'overlap'")), "removing_old -> overlap")

	// A run ends only when no location has a send in flight, and completes only without a location still to remove.
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'completed', finished_at = $2", rotNow)), "location 0 is planned: completed with a location still to change")
	f.mustLoc(0, "state = 'cancelled'")
	require.NoError(t, f.runSet("status = 'completed', finished_at = $2", rotNow))
}

func TestRotationRunEndsOnlyWithoutSendsInFlight(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 2)
	f.start()
	f.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	f.mustLoc(1, "state = 'cancelled'")
	require.NoError(t, f.runSet("status = 'rolling_back'"))
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'aborted', finished_at = $2", rotNow)), "an add is in flight")
	f.mustLoc(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", rotNow)
	assert.Equal(t, "Z1013", sqlState(f.runSet("status = 'needs_attention', finished_at = $2", rotNow)), "an undo is in flight")
	f.mustLoc(0, "state = 'undo_failed', error_code = 'rotation.old_key_gone'")
	assert.NoError(t, f.runSet("status = 'needs_attention', finished_at = $2", rotNow), "S12: undo_failed ends the run in needs_attention")
}

// The CHECKs of rotations, by name. The guard would refuse most of these rows earlier, so it is off here.
func TestRotationRunConstraints(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	f.start()
	other, _ := seedSSHKey(t, db, "SHA256:"+repeat43("P"))
	guardOff(t, db, "rotations", "rotations_guard", func() {
		newKey := f.newKey
		insert := func(cols, vals string, status string, nk *uuid.UUID, extra ...any) error {
			args := append([]any{uuid.New(), f.policy, other, nk, status, rotNow}, extra...)
			_, err := db.Owner.Exec(context.Background(), `INSERT INTO rotations (id, policy_id, old_ssh_key_id, new_ssh_key_id, trigger, status, plan,
    plan_digest, new_key_type, overlap_minutes, planned_for, notified_at, created_at, updated_at`+cols+`)
VALUES ($1, $2, $3, $4, 'manual', $5, '{}', repeat('0', 64), 'ed25519', 1, $6, $6, $6, $6`+vals+`)`, args...)
			return err
		}
		for _, c := range []struct {
			name, want string
			err        error
		}{
			{"removing_old needs removal_allowed", "rotations_removing_needs_allowed", insert("", "", "removing_old", &newKey)},
			{"removal_allowed needs verified_at", "rotations_allowed_needs_verified", insert(", removal_allowed", ", true", "overlap", &newKey)},
			{"removal_allowed needs the new key", "rotations_allowed_needs_verified", insert(", removal_allowed, verified_at", ", true, $6", "cancelled", nil)},
			{"the new key is not the old one", "rotations_new_differs", insert("", "", "adding_new", &other)},
			{"a started run has its new key", "rotations_new_key_set", insert("", "", "verifying_new", nil)},
			{"paused flag needs a time", "rotations_paused_pair", insert(", paused_license", ", true", "adding_new", &newKey)},
			{"paused time needs the flag", "rotations_paused_pair", insert(", paused_at", ", $6", "adding_new", &newKey)},
			{"awaiting needs a due time", "rotations_decision_pair", insert(", awaiting_decision", ", true", "adding_new", &newKey)},
			{"a due time needs awaiting", "rotations_decision_pair", insert(", decision_due_at", ", $6", "adding_new", &newKey)},
			{"completed has finished_at", "rotations_finished_pair", insert("", "", "completed", &newKey)},
			{"a live run has no finished_at", "rotations_finished_pair", insert(", finished_at", ", $6", "adding_new", &newKey)},
		} {
			assert.Equal(t, c.want, constraintOf(c.err), c.name)
		}
		for _, c := range []struct{ name, set string }{
			{"digest is a sha256", "plan_digest = 'xyz'"}, {"new key type is a closed list", "new_key_type = 'same'"},
			{"overlap is bounded", "overlap_minutes = 129601"}, {"status is a closed list", "status = 'weird'"},
			{"result code has the code form", "result_code = 'Not A Code'"}, {"kept_count is not negative", "kept_count = -1"},
			{"trigger is closed", "trigger = 'cron'"}, {"a plan is an object", "plan = '[]'"},
			{"a plan is at most 2 MiB", "plan = jsonb_build_object('x', repeat('y', 2097152))"},
		} {
			_, err := db.Owner.Exec(context.Background(), "UPDATE rotations SET "+c.set+" WHERE id = $1", f.run)
			assert.Equal(t, "23514", sqlState(err), c.name)
		}
		// S1, S11: the states the rulings need.
		assert.NoError(t, insert(", finished_at, result_code", ", $6, 'rotation.notice_undelivered'", "cancelled", nil), "S1: cancelled with a result code")
		assert.NoError(t, insert(", finished_at, kept_count", ", $6, 3", "aborted", &newKey), "S11: kept_count on a finished run")
	})
	// One live run per policy and per key.
	assert.Contains(t, []string{"rotations_one_live_per_policy", "rotations_one_live_per_key"}, constraintOf(insertRun(db, f.policy, f.oldKey, "dry_run_notified", nil)))
	require.NoError(t, f.x("UPDATE rotation_policies SET deleted_at = $2 WHERE id = $1", f.policy, rotNow))
	var second uuid.UUID
	require.NoError(t, db.App.QueryRow(context.Background(), `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at)
VALUES (gen_random_uuid(), $1, 'again', 30, $2, $2) RETURNING id`, f.oldKey, rotNow).Scan(&second))
	assert.Equal(t, "rotations_one_live_per_key", constraintOf(insertRun(db, second, f.oldKey, "dry_run_notified", nil)),
		"a new policy of the same key does not allow a second live run")
	f.mustLoc(0, "state = 'cancelled'")
	require.NoError(t, f.runSet("status = 'rolling_back'"))
	require.NoError(t, f.runSet("status = 'aborted', finished_at = $2", rotNow))
	assert.NoError(t, insertRun(db, second, f.oldKey, "dry_run_notified", nil), "a finished run frees the key")
}

func (f *rotFx) insertLoc(run uuid.UUID, n int, old uuid.UUID, user, file, state string, addSent *time.Time) error {
	f.t.Helper()
	return f.x(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at, add_sent_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)`, run, n, old, f.target, user, file, state, rotNow, addSent)
}

func TestRotationLocationInsertRules(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	const user, file = "extra", "/home/extra/.ssh/authorized_keys"
	oldLoc := insertKeyLocation(t, db, f.oldKey, f.target, user, file)
	foreign, _ := seedSSHKey(t, db, "SHA256:"+repeat43("F"))
	foreignLoc := insertKeyLocation(t, db, foreign, f.target, user, file)
	for _, st := range []string{"adding", "added", "verified", "removing", "removed", "undoing", "undone"} {
		assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, oldLoc, user, file, st, nil)), "born "+st)
	}
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, oldLoc, user, file, "planned", &rotNow)), "an add column set at insert")
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, foreignLoc, user, file, "planned", nil)), "a place of another key")
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, oldLoc, "other", file, "planned", nil)), "another user than the old location's")
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, oldLoc, user, "/elsewhere", "planned", nil)), "another path than the old location's")
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 2, uuid.New(), user, file, "planned", nil)), "an unknown old location")
	require.NoError(t, f.insertLoc(f.run, 2, oldLoc, user, file, "cancelled", nil), "cancelled is a state a row may be born in")

	// Only a previewed run takes locations: not a started one, not a finished one.
	later := insertKeyLocation(t, db, f.oldKey, f.target, "later", "/home/later/.ssh/authorized_keys")
	f.start()
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 3, later, "later", "/home/later/.ssh/authorized_keys", "planned", nil)), "a started run takes no new location")
	f.overlap()
	f.removingOld()
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 3, later, "later", "/home/later/.ssh/authorized_keys", "removing", nil)), "born removing in a removing run")
	f.mustLoc(0, "state = 'cancelled'")
	require.NoError(t, f.runSet("status = 'completed', finished_at = $2", rotNow))
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 3, later, "later", "/home/later/.ssh/authorized_keys", "removed", nil)), "born removed in a finished run")
	assert.Equal(t, "Z1011", sqlState(f.insertLoc(f.run, 3, later, "later", "/home/later/.ssh/authorized_keys", "planned", nil)), "a finished run takes no location")
}

// The location table of C8 as built: every pair of states that is not an edge is refused (SQLSTATE Z1011).
func TestRotationLocationEdgeTable(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 16)
	idx := map[string]int{"planned": 0, "skipped": 1, "cancelled": 2, "adding": 3, "added": 4, "add_failed": 5, "verified": 6, "unverifiable": 7,
		"verify_failed": 8, "kept_old": 9, "removing": 10, "removed": 11, "remove_failed": 12, "undoing": 13, "undone": 14, "undo_failed": 15}
	guardOff(t, db, "rotation_locations", "rotation_locations_guard", func() {
		_, err := db.Owner.Exec(context.Background(), "UPDATE rotation_locations SET state = 'skipped', skip_reason = 'unreachable' WHERE id = $1", f.locs[idx["skipped"]])
		require.NoError(t, err) // a skipped row is born skipped; the fixture inserts every row planned
	})
	f.start()
	f.mustLoc(idx["cancelled"], "state = 'cancelled'")
	f.mustLoc(idx["adding"], "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	f.added(idx["added"])
	f.mustLoc(idx["add_failed"], "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	f.mustLoc(idx["add_failed"], "state = 'add_failed', error_code = 'ssh.timeout'")
	f.verified(idx["verified"])
	f.added(idx["unverifiable"])
	f.mustLoc(idx["unverifiable"], "state = 'unverifiable', verify_note = 'from_option'")
	f.mustLoc(idx["verify_failed"], "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	f.mustLoc(idx["verify_failed"], "state = 'verify_failed', error_code = 'sshkey.login_failed'") // F2: adding -> verify_failed
	f.verified(idx["kept_old"])
	f.mustLoc(idx["kept_old"], "state = 'kept_old'")
	f.verified(idx["removing"])
	f.verified(idx["removed"])
	f.verified(idx["remove_failed"])
	f.verified(idx["undoing"])
	f.mustLoc(idx["undoing"], "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", rotNow)
	f.verified(idx["undone"])
	f.mustLoc(idx["undone"], "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", rotNow)
	f.mustLoc(idx["undone"], "state = 'undone'")
	f.verified(idx["undo_failed"])
	f.mustLoc(idx["undo_failed"], "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", rotNow)
	f.mustLoc(idx["undo_failed"], "state = 'undo_failed', error_code = 'rotation.old_key_gone'") // S12
	f.overlap()
	f.removingOld()
	for _, n := range []string{"removing", "removed", "remove_failed"} {
		f.recheck(idx[n], rotNow.Add(time.Minute))
	}
	require.NoError(t, f.startRemoving(idx["removing"], rotNow, rotNow.Add(2*time.Minute)))
	require.NoError(t, f.startRemoving(idx["removed"], rotNow, rotNow.Add(2*time.Minute)))
	f.mustLoc(idx["removed"], "state = 'removed', removed_at = $2", rotNow.Add(3*time.Minute))
	f.mustLoc(idx["remove_failed"], "state = 'remove_failed', error_code = 'rotation.new_key_failed'") // F3: verified -> remove_failed
	for st, i := range idx {
		require.Equal(t, st, f.state(i), "fixture row "+st)
	}

	allowed := map[string][]string{
		"planned": {"adding", "cancelled", "add_failed"}, "adding": {"added", "add_failed", "verified", "unverifiable", "verify_failed", "undoing"},
		"added": {"verified", "unverifiable", "verify_failed", "undoing"}, "verified": {"removing", "remove_failed", "kept_old", "undoing"},
		"unverifiable": {"kept_old", "undoing"}, "verify_failed": {"undoing"}, "add_failed": {"undoing"}, "kept_old": {"undoing"},
		"removing": {"removed", "remove_failed"}, "undoing": {"undone", "undo_failed"},
	}
	terminal := []string{"skipped", "cancelled", "removed", "remove_failed", "undone", "undo_failed"}
	for from, i := range idx {
		for to := range idx {
			if to == from || slices.Contains(allowed[from], to) {
				continue
			}
			assert.Equal(t, "Z1011", sqlState(f.locSet(i, "state = $2", to)), from+" -> "+to+" is not an edge")
		}
	}
	for _, from := range terminal {
		assert.Equal(t, "Z1011", sqlState(f.locSet(idx[from], "job_count = job_count + 1")), from+" never changes again")
	}
	// A live row changes in place (a job counter, a note).
	assert.NoError(t, f.locSet(idx["verified"], "job_count = job_count + 1"))
	assert.NoError(t, f.locSet(idx["adding"], "job_count = job_count + 1"))
}

func TestRotationLocationTies(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	f.start()
	f.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	file, user := f.files[0], "ua"
	onOld := f.oldLocs[0]
	elsewhere := insertKeyLocation(t, db, f.newKey, f.target, "other", "/home/other/.ssh/authorized_keys")
	foreign, _ := seedSSHKey(t, db, "SHA256:"+repeat43("F"))
	foreignLoc := insertKeyLocation(t, db, foreign, f.target, user, file)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'added', new_location_id = $2", onOld)), "a new location is a place of the new key")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'added', new_location_id = $2", foreignLoc)), "not another key's place")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'added', new_location_id = $2", elsewhere)), "the same user and path as the row")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'added', new_location_id = gen_random_uuid()")), "an unknown place")
	right := insertKeyLocation(t, db, f.newKey, f.target, user, file)
	require.NoError(t, f.locSet(0, "state = 'added', new_location_id = $2", right))
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "new_location_id = $2", elsewhere)), "recorded once")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "new_location_id = NULL")), "and not cleared")
	for _, col := range []string{"rotation_id", "n", "old_location_id", "target_id", "os_user", "file_path"} {
		_, err := db.Owner.Exec(context.Background(), "UPDATE rotation_locations SET "+col+" = (SELECT "+map[string]string{
			"rotation_id": "gen_random_uuid()", "n": "99", "old_location_id": "gen_random_uuid()", "target_id": "gen_random_uuid()",
			"os_user": "'zz'", "file_path": "'/zz'"}[col]+") WHERE id = $1", f.locs[0])
		assert.Equal(t, "Z1011", sqlState(err), "the identity column "+col+" never changes, for any role")
	}
}

// The old-key gate on every path into removing and removed (the review's bypasses), each by its statement.
func TestRotationRemovalGate(t *testing.T) {
	db := pgtest.New(t)
	f := readyToRemove(t, db, 2)
	sent := rotNow.Add(5 * time.Minute)
	op := uuid.New()
	// 1. Straight to removed, with the send columns written in the same statement.
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removed', removed_at = $2, remove_op_id = $3, remove_verified_at = reverified_at, remove_sent_at = $2`, sent, op)),
		"verified -> removed")
	// 4. The verification written in the same statement as the removal.
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', verified_at = $2, remove_op_id = $3, remove_verified_at = reverified_at, remove_sent_at = $4`,
		rotNow.Add(time.Minute), op, sent)), "the verification is the one the row had")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', add_sent_at = $2, remove_op_id = $3, remove_verified_at = reverified_at, remove_sent_at = $4`,
		rotNow.Add(-time.Hour), op, sent)), "nor the add time")
	// A row that was never verified cannot jump to removing, whatever the statement says.
	assert.Equal(t, "Z1011", sqlState(f.locSet(1, `state = 'removing', verified_at = $2, reverified_at = $2, add_sent_at = $2, remove_op_id = $3, remove_verified_at = $2, remove_sent_at = $2`,
		rotNow, op)), "planned -> removing with self-attested columns")
	// 8. The re-check is the login the removal relied on.
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4`, op, rotNow, sent)),
		"remove_verified_at is the re-check (reverified_at), not the old verification")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', reverified_at = NULL, remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $3`, op, sent)),
		"a removal needs a re-check")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at`, op)),
		"the send time comes with the removal")
	assert.Equal(t, "rotation_locations_removal_fresh", constraintOf(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op, rotNow.Add(time.Minute+16*time.Minute))), "a re-check older than 15 minutes is not fresh")
	assert.Equal(t, "rotation_locations_removal_fresh", constraintOf(f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op, rotNow)), "a re-check after the send is not a re-check before it")
	assert.Equal(t, "rotation_locations_times", constraintOf(f.locSet(0, "reverified_at = $2", rotNow.Add(-time.Minute))), "a re-check is not older than the verification")
	require.NoError(t, f.locSet(0, `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`, op, rotNow.Add(time.Minute+15*time.Minute)),
		"exactly 15 minutes is still fresh")

	// 5. A re-send re-checks everything.
	later := rotNow.Add(time.Hour)
	f.recheck(0, later)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `remove_verified_at = reverified_at, remove_sent_at = $2, remove_op_id = $3`, later, uuid.New())), "a re-send keeps the op id")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `remove_verified_at = reverified_at, remove_sent_at = $2`, rotNow)), "a re-send does not go back in time")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `remove_sent_at = $2`, later)), "the send columns change together")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `reverified_at = $2`, rotNow)), "a re-check does not go back in time")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'verified'`)), "removing never goes back")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `verified_at = $2`, later)), "the verification of a removing row does not move")
	require.NoError(t, f.locSet(0, `remove_verified_at = reverified_at, remove_sent_at = $2`, later.Add(time.Minute)), "a re-send on the new re-check")
	assert.Equal(t, "rotation_locations_times", constraintOf(f.locSet(0, `state = 'removed', removed_at = $2`, rotNow)), "removed before it was sent")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'removed', removed_at = $2, remove_sent_at = $3`, later.Add(2*time.Minute), later.Add(2*time.Minute))), "finishing keeps the send")
	require.NoError(t, f.locSet(0, `state = 'removed', removed_at = $2`, later.Add(2*time.Minute)))
	// 7. The record of a removal is not rewritten.
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, `state = 'remove_failed', removed_at = NULL`)), "removed -> remove_failed")
}

func TestRotationRemovalNeedsTheRunToBeRemoving(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	f.start()
	f.verified(0)
	f.recheck(0, rotNow)
	op := uuid.New()
	remove := `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, remove, op, rotNow)), "adding_new")
	f.overlap()
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, remove, op, rotNow)), "overlap")
	f.removingOld()
	assert.NoError(t, f.locSet(0, remove, op, rotNow), "removing_old with removal_allowed")
}

func TestRotationPlatformFingerprintNeverRemoving(t *testing.T) {
	db := pgtest.New(t)
	f := readyToRemove(t, db, 1)
	op := uuid.New()
	remove := `state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`
	set := func(fp string) {
		_, err := db.Owner.Exec(context.Background(), `UPDATE credentials SET public_info = jsonb_build_object('fingerprint', $1::text) WHERE purpose = 'platform_ssh'`, fp)
		require.NoError(t, err)
	}
	set(f.oldFP)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, remove, op, rotNow.Add(time.Minute))), "Alice's own key is never removed, whatever the run says")
	set(f.newFP)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, remove, op, rotNow.Add(time.Minute))), "nor replaced by Alice's own key")
	set("SHA256:" + repeat43("Z"))
	assert.NoError(t, f.locSet(0, remove, op, rotNow.Add(time.Minute)), "the same statement goes through for a key that is not Alice's")
	// The connection key's flag (it is never cleared: one fixture each) on the old or on the new key's place.
	for name, pick := range map[string]func(*rotFx) uuid.UUID{"old": func(f *rotFx) uuid.UUID { return f.oldLocs[0] }, "new": func(f *rotFx) uuid.UUID { return f.newLocs[0] }} {
		g := readyToRemove(t, pgtest.New(t), 1)
		_, err := g.db.Owner.Exec(context.Background(), "UPDATE ssh_key_locations SET is_alice_connection_key = true WHERE id = $1", pick(g))
		require.NoError(t, err)
		assert.Equal(t, "Z1011", sqlState(g.locSet(0, remove, op, rotNow.Add(time.Minute))), "the "+name+" location is Alice's connection key")
	}
	// A re-send is gated again: the platform key changed to the old key meanwhile.
	f.recheck(0, rotNow.Add(2*time.Minute))
	set(f.oldFP)
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "job_count = job_count + 1")), "every change of a removing row passes the gate")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "remove_verified_at = reverified_at, remove_sent_at = $2", rotNow.Add(3*time.Minute))), "re-sends re-check the platform condition")
	assert.Equal(t, "Z1011", sqlState(f.locSet(0, "state = 'removed', removed_at = $2", rotNow.Add(4*time.Minute))), "so does finishing")
}

// I-2: the location guard reads the run FOR SHARE, so finishing the run and changing a location serialize.
func TestRotationLocationWaitsForARunThatIsBeingFinished(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	ctx := context.Background()
	tx, err := db.App.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "UPDATE rotations SET status = 'cancelled', finished_at = $2 WHERE id = $1", f.run, rotNow)
	require.NoError(t, err)

	result := make(chan error, 1)
	go func() {
		_, err := db.App.Exec(ctx, "UPDATE rotation_locations SET state = 'cancelled' WHERE id = $1", f.locs[0])
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("the location change did not wait for the run (without the lock it would read the old status): %v", err)
	case <-time.After(700 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(ctx))
	select {
	case err := <-result:
		assert.Equal(t, "Z1011", sqlState(err), "after the run finished the change is refused")
	case <-time.After(10 * time.Second):
		t.Fatal("the location change stayed blocked after the run committed")
	}
	assert.Equal(t, "planned", f.state(0))
}

// What the rulings S3, S4, S6, S11 and S12 need the schema to hold (through the legal path).
func TestRotationRulingStatesAreHeld(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	f.start()
	due := rotNow.Add(14 * 24 * time.Hour)
	// S6: verifying_new paused in lock with its deadline kept; the notice after the renewal is renotified_at.
	require.NoError(t, f.runSet(`status = 'verifying_new', paused_license = true, paused_at = $2, awaiting_decision = true, decision_due_at = $3,
    renotified_at = $2, continued_at = $2, kept_count = 2, version = version + 1`, rotNow, due))
	require.NoError(t, f.runSet(`paused_license = false, paused_at = NULL, decision_due_at = $2`, due.Add(time.Hour)), "Continue moves the deadline by the time spent paused")
	// S4: an add confirmed only by the login (adding -> verified), the new place recorded with it (F-67).
	f.mustLoc(0, "state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", rotNow)
	nl := insertKeyLocation(t, db, f.newKey, f.target, "ua", f.files[0])
	f.mustLoc(0, "state = 'verified', verified_at = $2, new_location_id = $3", rotNow, nl)
	// S3, S12: an undo after an uncertain add, and an undo that finds the old key gone.
	f.mustLoc(0, "state = 'undoing', undo_op_id = gen_random_uuid(), undo_sent_at = $2", rotNow)
	assert.Equal(t, "23514", sqlState(f.locSet(0, "error_code = 'Rotation Old'")), "an error code keeps the code form")
	f.mustLoc(0, "state = 'undo_failed', error_code = 'rotation.old_key_gone'")
	require.NoError(t, f.runSet("status = 'rolling_back'"))
	require.NoError(t, f.runSet("status = 'needs_attention', finished_at = $2, result_code = 'rotation.undo_failed'", rotNow))
}

// The CHECKs of rotation_locations, by name (the guard is off: it would refuse most of these rows earlier), and the
// columns the application cannot write.
func TestRotationLocationConstraints(t *testing.T) {
	db := pgtest.New(t)
	f := newRotFx(t, db, 1)
	ctx := context.Background()
	t0 := rotNow
	guardOff(t, db, "rotation_locations", "rotation_locations_guard", func() {
		for _, c := range []struct{ set, want string }{
			{"state = 'weird'", "rotation_locations_state_check"},
			{"verify_note = 'other'", "rotation_locations_verify_note_check"},
			{"skip_reason = 'Not Valid'", "rotation_locations_skip_reason_check"},
			{"error_code = 'Bad'", "rotation_locations_error_code_check"},
			{"added_line_no = 0", "rotation_locations_added_line_no_check"},
			{"job_count = 1001", "rotation_locations_job_count_check"},
			{"backup = repeat('b', 201)", "rotation_locations_backup_check"},
			{"n = 0", "rotation_locations_n_check"},
			{"state = 'skipped'", "rotation_locations_skipped_reason"},
			{"state = 'removing'", "rotation_locations_removing_columns"},
			{"remove_op_id = gen_random_uuid()", "rotation_locations_remove_together"},
			{"state = 'removed'", "rotation_locations_removed_pair"},
			{"removed_at = $2", "rotation_locations_removed_pair"},
			{"reverified_at = $2", "rotation_locations_recheck_needs_verified"},
			{"state = 'undoing'", "rotation_locations_undo_needs_add"},
			{"verified_at = $2", "rotation_locations_verified_needs_add"},
			{"add_sent_at = $2, verified_at = $3", "rotation_locations_times"},
			{"add_sent_at = $2, verified_at = $2, reverified_at = $3", "rotation_locations_times"},
			{"add_sent_at = $2, undo_sent_at = $3", "rotation_locations_times"},
			// a removal whose re-check is stale, after the send, or before the verification
			{"add_sent_at = $2, verified_at = $2, reverified_at = $2, remove_op_id = gen_random_uuid(), remove_verified_at = $2, remove_sent_at = $4", "rotation_locations_removal_fresh"},
			{"add_sent_at = $2, verified_at = $2, reverified_at = $2, remove_op_id = gen_random_uuid(), remove_verified_at = $2, remove_sent_at = $3", "rotation_locations_removal_fresh"},
			{"add_sent_at = $4, verified_at = $4, reverified_at = $2", "rotation_locations_times"},
			{"state = 'removed', add_sent_at = $2, verified_at = $2, reverified_at = $2, remove_op_id = gen_random_uuid(), remove_verified_at = $2, remove_sent_at = $2, removed_at = $3", "rotation_locations_times"},
		} {
			_, err := db.Owner.Exec(ctx, "UPDATE rotation_locations SET "+c.set+` WHERE id = $1 AND $2::timestamptz IS NOT NULL
 AND $3::timestamptz IS NOT NULL AND $4::timestamptz IS NOT NULL`, f.locs[0], t0, t0.Add(-time.Hour), t0.Add(time.Hour))
			assert.Equal(t, c.want, constraintOf(err), c.set)
		}
	})
	// Fixed at insert: the application cannot update these columns, and the plan cannot be rewritten.
	for _, col := range []string{"rotation_id", "n", "old_location_id", "target_id", "os_user", "file_path", "options"} {
		_, err := db.App.Exec(ctx, "UPDATE rotation_locations SET "+col+" = "+col+" WHERE id = $1", f.locs[0])
		assert.Equal(t, "42501", sqlState(err), col)
	}
	for _, col := range []string{"plan", "plan_digest", "new_key_type", "overlap_minutes", "planned_for", "notified_at", "policy_id", "old_ssh_key_id", "trigger", "created_at"} {
		_, err := db.App.Exec(ctx, "UPDATE rotations SET "+col+" = "+col+" WHERE id = $1", f.run)
		assert.Equal(t, "42501", sqlState(err), col+" is fixed at insert")
	}
	_, err := db.App.Exec(ctx, "DELETE FROM rotations")
	assert.Equal(t, "42501", sqlState(err))
	_, err = db.App.Exec(ctx, "DELETE FROM rotation_locations")
	assert.Equal(t, "42501", sqlState(err))
	_, err = db.App.Exec(ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES (gen_random_uuid(), $1, 1, $2, $3, 'x', '/p', 'planned', $4)`, f.run, f.oldLocs[0], f.target, rotNow)
	assert.Equal(t, "Z1011", sqlState(err), "the guard answers before the unique index")
}

func TestRotationStepsAreAppendOnly(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	f := newRotFx(t, db, 1)
	insert := func(n int, name, status, params string) error {
		_, err := db.App.Exec(ctx, `INSERT INTO rotation_steps (id, rotation_id, n, location_id, name, status, at, params)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7::jsonb)`, f.run, n, f.locs[0], name, status, rotNow, params)
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
	guardOff(t, d, "managed_private_keys", "managed_private_keys_guard", func() { // the key is unlinked above: no retired key owns it
		require.NoError(t, exec(t, d.Owner, "UPDATE managed_private_keys SET destroyed_at = now(), ciphertext = NULL, nonce = NULL, wrapped_dek = NULL, key_version = NULL WHERE id = $1", pk))
	})
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
