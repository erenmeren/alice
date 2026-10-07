//go:build integration

package sshkeys_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
)

// S-09 at the service: Administrator only is the route's job; here: a reason, the audit row is
// committed before the file is handed out, every download is counted and audited.
func TestDownloadAuditsBeforeTheFile(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "Hand-over to the CI team"})
	require.NoError(t, err)
	defer dl.Body.Zero()
	// The row is visible to another connection: it was committed before the call returned.
	var count int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM audit_log WHERE action = 'sshkey.private_key_downloaded'
  AND details->>'ssh_key_id' = $1 AND details->>'reason' = 'Hand-over to the CI team' AND details->>'download_count' = '1'
  AND details->>'protected' = 'false' AND details->>'fingerprint' = $2 AND result = 'success'`, k.ID.String(), k.Fingerprint).Scan(&count))
	assert.Equal(t, 1, count)
	assert.True(t, bytes.HasPrefix(dl.Body.Bytes(), []byte("-----BEGIN "+"OPENSSH PRIVATE KEY-----")))
	assert.Regexp(t, `^alice-ci-[0-9a-f]{8}\.key$`, dl.FileName)
	priv, err := ssh.ParseRawPrivateKey(dl.Body.Bytes())
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	assert.Equal(t, k.Fingerprint, ssh.FingerprintSHA256(signer.PublicKey()), "the file is the key")

	pass := []byte("a passphrase of length")
	dl2, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "Second copy for the backup host",
		Passphrase: pass})
	require.NoError(t, err)
	defer dl2.Body.Zero()
	assert.Equal(t, make([]byte, len(pass)), pass, "the passphrase is cleared once used")
	_, err = ssh.ParseRawPrivateKeyWithPassphrase(dl2.Body.Bytes(), []byte("a passphrase of length"))
	require.NoError(t, err)
	_, err = ssh.ParseRawPrivateKey(dl2.Body.Bytes())
	var missing *ssh.PassphraseMissingError
	assert.ErrorAs(t, err, &missing, "the second file is encrypted")
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.DownloadCount, "the second download is counted and audited too")
	require.NotNil(t, got.LastDownloadedAt)
	assert.True(t, got.LastDownloadedAt.Equal(start))
	assert.Equal(t, 2, e.audits("sshkey.private_key_downloaded"))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.private_key_downloaded", "protected"))
	assert.Equal(t, "2", e.lastAuditDetail("sshkey.private_key_downloaded", "download_count"))
}

func TestDownloadRefusals(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	_, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "short"})
	var verr validate.Errors
	assert.ErrorAs(t, err, &verr)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "-----BEGIN " + "RSA PRIVATE KEY----- x"})
	assert.ErrorAs(t, err, &verr, "S-05: a reason holding a PEM block is refused")
	pass := []byte("short")
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "long enough reason", Passphrase: pass})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, "passphrase", verr[0].Field)
	assert.Equal(t, validate.TooShort, verr[0].Code)
	assert.Equal(t, make([]byte, len(pass)), pass, "a refused passphrase is cleared too")
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "long enough reason",
		Passphrase: bytes.Repeat([]byte("p"), 1025)})
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, validate.TooLong, verr[0].Code)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "long enough reason", Passphrase: []byte{}})
	assert.ErrorAs(t, err, &verr, "an empty passphrase is not none")
	assert.Zero(t, e.audits("sshkey.private_key_download.denied"), "invalid input is not a refusal")
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: e.platformKeyRow(), Reason: "long enough reason"})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	assert.Equal(t, "own_key", e.lastAuditDetail("sshkey.private_key_download.denied", "reason"))
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: e.discoveredKey(), Reason: "long enough reason"})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	assert.Equal(t, "not_managed", e.lastAuditDetail("sshkey.private_key_download.denied", "reason"))
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: uuid.New(), Reason: "long enough reason"})
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
	e.retire(k.ID)
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "emergency after a rotation"})
	require.NoError(t, err, "a retired key can be downloaded until it is destroyed")
	dl.Body.Zero()
	e.destroy(k.ID)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "too late for this one"})
	assert.ErrorIs(t, err, sshkeys.ErrDestroyed)
	assert.Equal(t, "destroyed", e.lastAuditDetail("sshkey.private_key_download.denied", "reason"))
	assert.Equal(t, 3, e.audits("sshkey.private_key_download.denied"))
	assert.Equal(t, 1, e.audits("sshkey.private_key_downloaded"))
}

// No file leaves without its committed audit row: a key destroyed between the build and the
// counter's transaction answers ErrDestroyed, nothing is counted, and the built file is zeroed.
// The clear PKCS #8 is zeroed before that transaction starts.
func TestDownloadWithoutItsAuditRowZeroesTheFile(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	var opened, built []byte
	var openedAtBuild []byte
	sshkeys.OnHold(t, func(kind string, b []byte) {
		switch kind {
		case "opened":
			opened = b
		case "file":
			built = b
			openedAtBuild = bytes.Clone(opened)
			// The key goes before the counter's transaction (another process destroys it).
			e.destroy(k.ID)
		}
	})
	_, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "the race with destruction"})
	assert.ErrorIs(t, err, sshkeys.ErrDestroyed)
	require.NotEmpty(t, built)
	assert.NotEqual(t, make([]byte, len(openedAtBuild)), openedAtBuild, "the key was open while the file was built")
	assert.Equal(t, make([]byte, len(built)), built, "the file is zeroed")
	assert.Equal(t, make([]byte, len(opened)), opened, "the opened key is zeroed")
	assert.Zero(t, e.audits("sshkey.private_key_downloaded"))
	assert.Zero(t, e.count("SELECT download_count FROM managed_private_keys WHERE id = $1", k.PrivateKeyID))
}

// A successful download zeroes the opened PKCS #8 before the transaction; the file is the
// caller's (zeroed by the handler after writing).
func TestDownloadZeroesTheOpenedKey(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	var opened []byte
	var zeroAtTx bool
	sshkeys.OnHold(t, func(kind string, b []byte) {
		switch kind {
		case "opened":
			opened = b
		case "tx":
			zeroAtTx = bytes.Equal(opened, make([]byte, len(opened)))
		}
	})
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "zeroing before the transaction"})
	require.NoError(t, err)
	defer dl.Body.Zero()
	require.NotEmpty(t, opened)
	assert.True(t, zeroAtTx, "the opened key is zeroed before the counter's transaction")
	assert.NotEqual(t, make([]byte, len(dl.Body.Bytes())), dl.Body.Bytes())
}

// A key Alice cannot open (another master key) answers an error that carries no key material,
// counts nothing and audits nothing.
func TestDownloadWithAnotherMasterKey(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	key := make([]byte, secrets.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	other, err := secrets.NewKeyring(e.keyring.Version(), key)
	require.NoError(t, err)
	svc := e.newService(other)
	_, err = svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "with the wrong master key"})
	require.Error(t, err)
	assert.Equal(t, "sshkeys: the private key cannot be decrypted with this master key", err.Error())
	_, _, err = svc.KeySigner(k.ID).SSHSigner(e.ctx)
	require.Error(t, err)
	assert.Equal(t, "sshkeys: the private key cannot be decrypted with this master key", err.Error())
	assert.Zero(t, e.audits("sshkey.private_key_downloaded"))
}

// Canaries: the private key (its file lines, and slices of its PKCS #8 as hex, standard and raw
// base64), the passphrase and the seed never reach a table or a log line; for an Ed25519 and an
// RSA key.
func TestStoredKeyIsAnEnvelope(t *testing.T) {
	e := newEnv(t)
	var secretParts []string
	sshkeys.OnHold(t, func(kind string, b []byte) {
		if kind == "generated" || kind == "opened" {
			for _, part := range [][]byte{b[len(b)-32:], b[len(b)/2 : len(b)/2+24]} { // the Ed25519 seed; a slice from the middle
				secretParts = append(secretParts, hexOf(part), base64.StdEncoding.EncodeToString(part), base64.RawStdEncoding.EncodeToString(part),
					base64.RawURLEncoding.EncodeToString(part))
			}
		}
	})
	srv := e.server("web-01")
	pass := "canary-passphrase-" + uuid.NewString()
	var canaries []string
	for _, kt := range []string{"ed25519", "rsa-3072"} {
		k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "ci " + kt, KeyType: kt})
		require.NoError(t, err)
		_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
			FilePath: "/home/deploy/.ssh/authorized_keys"})
		require.NoError(t, err)
		_, release, err := e.svc.KeySigner(k.ID).SSHSigner(e.ctx)
		require.NoError(t, err)
		release()
		dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "canary extraction"})
		require.NoError(t, err)
		body := string(dl.Body.Bytes())
		dl.Body.Zero()
		dl2, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "canary extraction",
			Passphrase: []byte(pass)})
		require.NoError(t, err)
		body2 := string(dl2.Body.Bytes())
		dl2.Body.Zero()
		// The base64 lines between the PEM markers; the unencrypted file embeds the public key, so a
		// line that is part of the public key's own text is not a canary.
		pubBlob := strings.Fields(k.PublicKey)[1]
		for _, l := range append(keyBodyLines(body), keyBodyLines(body2)...) {
			if !strings.Contains(pubBlob, l) {
				canaries = append(canaries, l)
			}
		}
		canaries = append(canaries, base64.StdEncoding.EncodeToString([]byte(body))[8:48]) // the file itself in base64
	}
	// A refused download with a passphrase.
	_, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: e.discoveredKey(), Reason: "canary extraction",
		Passphrase: []byte(pass)})
	require.ErrorIs(t, err, sshkeys.ErrNotManaged)
	canaries = append(canaries, pass, base64.StdEncoding.EncodeToString([]byte(pass)))
	require.NotEmpty(t, secretParts)
	canaries = append(canaries, secretParts...)
	for _, table := range leakTables {
		dump := e.dumpTable(table) // every column of every row as text (owner pool)
		for _, c := range canaries {
			assert.NotContains(t, dump, c, table)
		}
		assert.NotContains(t, dump, "PRIVATE KEY", table)
	}
	logs := e.logs.String()
	for _, c := range canaries {
		assert.NotContains(t, logs, c)
	}
	assert.NotContains(t, logs, "PRIVATE KEY")
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var s strings.Builder
	for _, c := range b {
		s.WriteByte(digits[c>>4])
		s.WriteByte(digits[c&15])
	}
	return s.String()
}

func TestDestroyRetiredKeys(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	live := e.generate("live")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(30*24*time.Hour - time.Second)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "kept for 30 days")
	e.clock.Advance(time.Second)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NOT NULL AND ciphertext IS NULL AND nonce IS NULL AND wrapped_dek IS NULL AND key_version IS NULL"))
	assert.Equal(t, 1, e.audits("sshkey.private_key_destroyed"))
	assert.Equal(t, k.ID.String(), e.lastAuditDetail("sshkey.private_key_destroyed", "ssh_key_id"))
	assert.Equal(t, k.Fingerprint, e.lastAuditDetail("sshkey.private_key_destroyed", "fingerprint"))
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.DestroyedAt)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "destroyed once")
	got, err = e.svc.ManagedKey(e.ctx, live.ID)
	require.NoError(t, err)
	assert.Nil(t, got.DestroyedAt, "a key that is not retired is kept")
}

// S5: a retired key found live again (a server restored from a backup, a home mounted again) is
// never destroyed: it is un-retired, audited sshkey.reactivated, and its private key is kept.
func TestDestroySkipsAndReactivatesAKeyThatIsLiveAgain(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	k2 := e.generate("ci2")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(31 * 24 * time.Hour)
	e.liveLocation(k) // the restored server: discovery finds the old key again
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Nil(t, got.RetiredAt, "un-retired")
	assert.Nil(t, got.DestroyedAt, "the private key is kept")
	assert.Equal(t, 1, e.audits("sshkey.reactivated"))
	assert.Equal(t, k.ID.String(), e.lastAuditDetail("sshkey.reactivated", "ssh_key_id"))
	assert.Equal(t, k.Fingerprint, e.lastAuditDetail("sshkey.reactivated", "fingerprint"))
	assert.Equal(t, "1", e.lastAuditDetail("sshkey.reactivated", "location_count"))
	assert.Zero(t, e.audits("sshkey.private_key_destroyed"))
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "still usable after all"})
	require.NoError(t, err)
	dl.Body.Zero()

	// Retired again later; the location is now missing (or its server deleted): it is not live, so
	// the key is destroyed after the retention.
	e.retireAt(k.ID, e.clock.Now())
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE ssh_key_locations SET missing_since = $2 WHERE ssh_key_id = $1", k.ID, e.clock.Now())
	require.NoError(t, err)
	e.clock.Advance(30 * 24 * time.Hour)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, e.audits("sshkey.reactivated"))

	// A location on a deleted server is not live either.
	t2 := e.liveLocation(k2)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET deleted_at = $2 WHERE id = $1", t2, e.clock.Now())
	require.NoError(t, err)
	e.retireAt(k2.ID, e.clock.Now())
	e.clock.Advance(30 * 24 * time.Hour)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// Carry 3: the retention of a retired key's private key is the general setting (default 30 days).
func TestDestroyFollowsTheRetentionSetting(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	require.NoError(t, settings.Set(e.ctx, e.db.App, settings.GeneralKey,
		settings.General{RetiredKeyRetentionDays: 7, Version: 1}, e.clock.Now()))
	e.clock.Advance(7*24*time.Hour - time.Second)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	e.clock.Advance(time.Second)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "destroyed after 7 days, not 30")
}

// A stored retention far beyond the 3650-day limit is clamped on read; it must never overflow into "destroy now".
func TestDestroyClampsAnAbsurdRetention(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	require.NoError(t, settings.Set(e.ctx, e.db.App, settings.GeneralKey,
		settings.General{RetiredKeyRetentionDays: 200000, Version: 1}, e.clock.Now()))
	e.clock.Advance(365 * 24 * time.Hour)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a year after retirement the key is kept")
	e.clock.Advance(3650 * 24 * time.Hour)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "clamped to 3650 days")
}
