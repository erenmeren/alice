//go:build integration

package sshkeys_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/keymat"
)

func TestGenerateStoresAnEnvelope(t *testing.T) {
	e := newEnv(t)
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "CI deploy"})
	require.NoError(t, err)
	assert.Equal(t, "ed25519", k.KeyType)
	assert.Equal(t, 256, k.Bits)
	assert.Equal(t, "alice:ci-deploy:2026-10-05", k.Comment)
	assert.Equal(t, "CI deploy", k.Label)
	assert.Equal(t, e.admin.UserID, k.CreatedBy)
	assert.True(t, k.CreatedAt.Equal(start))
	var ct, nonce []byte
	var owner, algorithm string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT ciphertext, nonce, owner_type, algorithm FROM managed_private_keys WHERE id = $1`,
		k.PrivateKeyID).Scan(&ct, &nonce, &owner, &algorithm))
	assert.Equal(t, "ssh_key", owner)
	assert.Equal(t, "ed25519", algorithm)
	assert.NotContains(t, string(ct), "PRIVATE KEY")
	assert.False(t, bytes.HasPrefix(ct, []byte{0x30}), "not DER in clear")
	pt, err := e.keyring.Open(secrets.Location{Table: "managed_private_keys", RowID: k.PrivateKeyID.String(), Column: "ciphertext"},
		e.envelope(k.PrivateKeyID))
	require.NoError(t, err)
	defer pt.Zero()
	pub, fp, err := keymat.PublicOf(pt)
	require.NoError(t, err)
	assert.Equal(t, k.PublicKey, pub)
	assert.Equal(t, k.Fingerprint, fp)
	assert.Equal(t, 1, e.audits("sshkey.generated"))
	assert.Equal(t, k.ID.String(), e.lastAuditDetail("sshkey.generated", "ssh_key_id"))
	assert.Equal(t, "ed25519", e.lastAuditDetail("sshkey.generated", "algorithm"))
	// The inventory row: managed, its private key, the SSH type of the public key, the comment.
	var managed bool
	var keyType, comment string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT managed, key_type, key_comment FROM ssh_keys WHERE id = $1 AND private_key_id = $2`,
		k.ID, k.PrivateKeyID).Scan(&managed, &keyType, &comment))
	assert.True(t, managed)
	assert.Equal(t, "ssh-ed25519", keyType)
	assert.Equal(t, k.Comment, comment)
	// S-04: two keys, two DEKs, two different ciphertexts
	k2, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "CI deploy"})
	require.NoError(t, err)
	assert.NotEqual(t, e.wrappedDEK(k.PrivateKeyID), e.wrappedDEK(k2.PrivateKeyID))
	assert.NotEqual(t, e.envelope(k.PrivateKeyID).Ciphertext, e.envelope(k2.PrivateKeyID).Ciphertext)
}

func TestGenerateEveryType(t *testing.T) {
	e := newEnv(t)
	sshTypes := map[string]string{"ed25519": "ssh-ed25519", "rsa-3072": "ssh-rsa", "rsa-4096": "ssh-rsa", "ecdsa-p256": "ecdsa-sha2-nistp256"}
	for _, kt := range []string{"ed25519", "rsa-3072", "rsa-4096", "ecdsa-p256"} {
		k, err := e.svc.Generate(e.ctx, e.operator, sshkeys.GenerateInput{Label: "k " + kt, KeyType: kt})
		require.NoError(t, err, kt)
		assert.Equal(t, kt, k.KeyType)
		var keyType string
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT key_type FROM ssh_keys WHERE id = $1", k.ID).Scan(&keyType))
		assert.Equal(t, sshTypes[kt], keyType, kt)
		assert.True(t, strings.HasPrefix(k.PublicKey, sshTypes[kt]+" "), kt)
	}
	var verr validate.Errors
	_, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x", KeyType: "dsa"})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "key_type", verr[0].Field)
	assert.Equal(t, validate.OneOf, verr[0].Code)
	for _, c := range []struct{ label, code string }{
		{"a\u202eb", validate.Pattern}, // bidi override
		{"a\u200bb", validate.Pattern}, // zero-width space (format)
		{"a\x07b", validate.Pattern},   // control
		{"   ", validate.Required},
		{"", validate.Required},
		{strings.Repeat("é", 101), validate.TooLong},
		{"a\xffb", validate.Pattern}, // not UTF-8
	} {
		_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: c.label})
		require.ErrorAs(t, err, &verr, "%q", c.label)
		assert.Equal(t, "label", verr[0].Field, "%q", c.label)
		assert.Equal(t, c.code, verr[0].Code, "%q", c.label)
	}
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "  " + strings.Repeat("é", 100) + " "})
	require.NoError(t, err, "100 runes after trimming")
	assert.Equal(t, strings.Repeat("é", 100), k.Label)
	assert.Equal(t, 5, e.audits("sshkey.generated"))
}

func TestGenerateRefusedInLockAndWhenBusy(t *testing.T) {
	e := newEnv(t)
	e.gate.lock()
	_, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x"})
	assert.ErrorIs(t, err, license.ErrLocked)
	e.gate.unlock()
	release := sshkeys.HoldGenerationSlots(t) // export_test.go: takes every slot until release
	_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x"})
	assert.ErrorIs(t, err, sshkeys.ErrGenerateBusy)
	release()
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_keys"))
	assert.Zero(t, e.count("SELECT count(*) FROM managed_private_keys"))
	// A caller that has gone generates nothing.
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	_, err = e.svc.Generate(ctx, e.admin, sshkeys.GenerateInput{Label: "x"})
	assert.Error(t, err)
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_keys"))
}

// The generated PKCS #8 exists in clear only until it is sealed: Generate zeroes it on return
// (a removed zeroing turns this red).
func TestGenerateZeroesTheClearKey(t *testing.T) {
	e := newEnv(t)
	var held [][]byte
	sshkeys.OnHold(t, func(kind string, b []byte) {
		if kind == "generated" {
			held = append(held, b)
		}
	})
	for _, kt := range []string{"ed25519", "rsa-3072", "ecdsa-p256"} {
		_, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "z", KeyType: kt})
		require.NoError(t, err)
	}
	// A failure after generation zeroes it too: a database error in the insert transaction.
	_, err := e.db.Owner.Exec(e.ctx, "REVOKE INSERT ON ssh_keys FROM alice_app")
	require.NoError(t, err)
	_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "z"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "PRIVATE")
	_, err = e.db.Owner.Exec(e.ctx, "GRANT INSERT ON ssh_keys TO alice_app")
	require.NoError(t, err)
	require.Len(t, held, 4)
	for i, b := range held {
		assert.NotEmpty(t, b, i)
		assert.Equal(t, make([]byte, len(b)), b, "generated key %d is zeroed", i)
	}
	assert.Equal(t, 3, e.count("SELECT count(*) FROM managed_private_keys"), "the failed insert left no key")
}

func TestManagedKeyReads(t *testing.T) {
	e := newEnv(t)
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "ci"})
	require.NoError(t, err)
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, k, got)
	assert.Equal(t, k.Fingerprint, got.Fingerprint)
	assert.Zero(t, got.DownloadCount)
	assert.Nil(t, got.RetiredAt)
	assert.Nil(t, got.DestroyedAt)
	assert.Nil(t, got.PolicyID)
	assert.Nil(t, got.OpenRotationID)
	discovered := e.discoveredKey() // a key found on a server: no private key
	_, err = e.svc.ManagedKey(e.ctx, discovered)
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	_, err = e.svc.ManagedKey(e.ctx, e.platformKeyRow())
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	_, err = e.svc.ManagedKey(e.ctx, uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)

	// The live policy and the open rotation of the key (rows written as Tasks 8-9 write them).
	policy := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_by, created_at, updated_at)
VALUES ($1, $2, 'p', 30, $3, $4, $4)`, policy, k.ID, e.admin.UserID, e.clock.Now())
	require.NoError(t, err)
	rotation := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type,
    overlap_minutes, planned_for, notified_at, created_at, updated_at)
VALUES ($1, $2, $3, 'manual', 'dry_run_notified', '{}', repeat('a', 64), 'ed25519', 0, $4, $4, $4, $4)`, rotation, policy, k.ID, e.clock.Now())
	require.NoError(t, err)
	got, err = e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.PolicyID)
	assert.Equal(t, policy, *got.PolicyID)
	require.NotNil(t, got.OpenRotationID)
	assert.Equal(t, rotation, *got.OpenRotationID)
	e.retire(k.ID)
	got, err = e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RetiredAt)
	assert.True(t, got.RetiredAt.Equal(start))
}

// A test may fix the Ed25519 seed (Config.Rand): the same seed is the same key. Production leaves
// Rand nil, which is crypto/rand.
func TestGenerateWithAGivenReader(t *testing.T) {
	e := newEnv(t)
	seed := bytes.Repeat([]byte{7}, 64)
	svc := sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget, Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.tick, License: e.gate, Inventory: e.inv,
		Jobs: e.queue, Rand: bytes.NewReader(seed)})
	k, err := svc.Generate(e.ctx, inventorySystem(), sshkeys.GenerateInput{Label: "seeded"})
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, k.CreatedBy, "generated by Alice itself")
	other, err := keymat.Generate(bytes.NewReader(seed), keymat.Ed25519)
	require.NoError(t, err)
	defer other.PKCS8.Zero()
	assert.Equal(t, other.Fingerprint, k.Fingerprint)
	_, err = svc.Generate(e.ctx, inventorySystem(), sshkeys.GenerateInput{Label: "seeded"})
	assert.Error(t, err, "the reader is exhausted")
}

func inventorySystem() inventory.Actor { return inventory.Actor{Audit: audit.SystemActor("jobs")} }
