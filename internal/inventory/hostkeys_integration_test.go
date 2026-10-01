//go:build integration

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

func ed25519HostKey(t *testing.T) providers.HostKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return providers.HostKey{Type: k.Type(), PublicKey: k.Marshal(), Fingerprint: ssh.FingerprintSHA256(k)}
}

func ecdsaHostKey(t *testing.T) providers.HostKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return providers.HostKey{Type: k.Type(), PublicKey: k.Marshal(), Fingerprint: ssh.FingerprintSHA256(k)}
}

// keyID returns the id of the host_keys row with the fingerprint.
func keyID(t *testing.T, h *harness, target uuid.UUID, fp string) uuid.UUID {
	t.Helper()
	recs, err := h.svc.ListHostKeys(h.ctx, target)
	require.NoError(t, err)
	for _, r := range recs {
		if r.Fingerprint == fp {
			return r.ID
		}
	}
	t.Fatalf("no host key %s", fp)
	return uuid.Nil
}

func statusOf(t *testing.T, h *harness, id uuid.UUID) string {
	t.Helper()
	tg, err := h.svc.GetTarget(h.ctx, id)
	require.NoError(t, err)
	return tg.Status
}

// pinned brings a new target to "ok" with k pinned.
func pinned(t *testing.T, h *harness, admin inventory.Actor, k providers.HostKey) inventory.Target {
	t.Helper()
	tg := h.add(admin, "web-01", "web-01.example.com")
	store := h.svc.HostKeyStore()
	require.NoError(t, store.Observed(h.ctx, tg.ID, k, false))
	_, err := h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k.Fingerprint), k.Fingerprint)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: k}))
	require.Equal(t, inventory.StatusOK, statusOf(t, h, tg.ID))
	return tg
}

// F-30: a first contact pins nothing; only the Administrator's confirmation of the presented
// fingerprint does, and it is audited with the confirming user.
func TestF30FirstContactNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	tg := h.add(admin, "web-01", "web-01.example.com")
	store := h.svc.HostKeyStore()
	_, err := store.Pinned(h.ctx, tg.ID)
	require.ErrorIs(t, err, providers.ErrNoPinnedKey)

	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	require.NoError(t, store.Observed(h.ctx, tg.ID, k1, false))
	require.NoError(t, store.Observed(h.ctx, tg.ID, k1, false), "observing the same key twice is harmless")
	recs, err := h.svc.ListHostKeys(h.ctx, tg.ID)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "observed", recs[0].Status)
	assert.Equal(t, inventory.StatusPendingHostKey, statusOf(t, h, tg.ID))
	_, err = store.Pinned(h.ctx, tg.ID)
	require.ErrorIs(t, err, providers.ErrNoPinnedKey, "observing never pins")

	// The server now presents another key: the first candidate can no longer be confirmed.
	require.NoError(t, store.Observed(h.ctx, tg.ID, k2, false))
	id1, id2 := keyID(t, h, tg.ID, k1.Fingerprint), keyID(t, h, tg.ID, k2.Fingerprint)
	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, id1, k1.Fingerprint)
	require.ErrorIs(t, err, inventory.ErrHostKeyStale)
	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, id2, k1.Fingerprint)
	require.ErrorIs(t, err, inventory.ErrHostKeyStale, "the fingerprint must be the one shown")
	assert.Equal(t, 0, h.audits("hostkey.pinned"))

	before := len(h.jobs.requests())
	jobID, err := h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, id2, " "+k2.Fingerprint+" ")
	require.NoError(t, err)
	assert.NotZero(t, jobID)
	got, err := store.Pinned(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, k2, got)
	assert.Equal(t, inventory.StatusChecking, statusOf(t, h, tg.ID))
	assert.Equal(t, []map[string]string{{"fingerprint": k2.Fingerprint, "algorithm": "ssh-ed25519", "target_id": tg.ID.String()}},
		h.auditDetails("hostkey.pinned"))
	reqs := h.jobs.requests()
	require.Len(t, reqs, before+1)
	assert.Equal(t, inventory.JobTestConnection, reqs[before].Type)
	assert.Equal(t, admin.UserID, reqs[before].CreatedBy)

	recs, err = h.svc.ListHostKeys(h.ctx, tg.ID)
	require.NoError(t, err)
	byFP := map[string]inventory.HostKeyRecord{}
	for _, r := range recs {
		byFP[r.Fingerprint] = r
	}
	assert.Equal(t, "rejected", byFP[k1.Fingerprint].Status)
	assert.Equal(t, "pinned", byFP[k2.Fingerprint].Status)
	assert.Equal(t, "ada Yılmaz", byFP[k2.Fingerprint].ConfirmedByName)
	require.NotNil(t, byFP[k2.Fingerprint].ConfirmedAt)

	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, id2, k2.Fingerprint)
	require.ErrorIs(t, err, inventory.ErrHostKeyState, "a pinned target is never confirmed again")
	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, uuid.New(), k2.Fingerprint)
	require.ErrorIs(t, err, inventory.ErrHostKeyState)
}

func TestConfirmIsExclusive(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	k := ed25519HostKey(t)
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k, false))
	id := keyID(t, h, tg.ID, k.Fingerprint)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, id, k.Fingerprint)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else {
			require.ErrorIs(t, err, inventory.ErrHostKeyState)
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, 1, h.audits("hostkey.pinned"))
}

// Review Focus 5 / F-31: a changed key blocks the target, is audited once and mails every
// Administrator with an address exactly once, however often it is seen.
func TestChangedKeyNotifiesOnceAndBlocks(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	h.user("bora", rbac.Admin, "bora@example.com")
	h.user("cem", rbac.Admin, "") // no address: no email
	h.user("oya", rbac.Operator, "oya@example.com")
	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	tg := pinned(t, h, admin, k1)
	store := h.svc.HostKeyStore()

	require.NoError(t, store.Observed(h.ctx, tg.ID, k2, true))
	require.NoError(t, store.Observed(h.ctx, tg.ID, k2, true))
	require.NoError(t, store.Observed(h.ctx, tg.ID, ecdsaHostKey(t), true))

	assert.Equal(t, inventory.StatusHostKeyChanged, statusOf(t, h, tg.ID))
	got, err := store.Pinned(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, k1, got, "a change never replaces the pinned key")
	assert.Equal(t, []map[string]string{{"old_fingerprint": k1.Fingerprint, "new_fingerprint": k2.Fingerprint, "target_name": "web-01"}},
		h.auditDetails("hostkey.changed"))
	assert.Equal(t, 2, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'"))
	assert.Equal(t, 1, h.count(`SELECT count(*) FROM notifications_outbox WHERE to_address = 'bora@example.com'
AND params->>'old_fingerprint' = $1 AND params->>'new_fingerprint' = $2 AND params->>'target_name' = 'web-01'`, k1.Fingerprint, k2.Fingerprint))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM notifications_outbox WHERE to_address = 'oya@example.com'"))

	_, err = h.svc.RequestDiscovery(h.ctx, admin, tg.ID)
	require.ErrorIs(t, err, inventory.ErrHostKeyChanged)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{}))
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.unreachable"))
	assert.Equal(t, inventory.StatusHostKeyChanged, statusOf(t, h, tg.ID), "only a re-pin leaves host_key_changed")
	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k2.Fingerprint), k2.Fingerprint)
	require.ErrorIs(t, err, inventory.ErrHostKeyState, "a changed key needs the re-pin with a reason")
}

// Seeing the pinned key again with changed=true (a caller mistake) is not a change.
func TestObservedPinnedKeyIsNoChange(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	k1 := ed25519HostKey(t)
	tg := pinned(t, h, admin, k1)
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k1, true))
	assert.Equal(t, inventory.StatusOK, statusOf(t, h, tg.ID))
	assert.Equal(t, 0, h.audits("hostkey.changed"))
}

// F-32 / Review Focus 5: the re-pin needs a reason, keeps the old fingerprint in the history
// and resumes work through a new connection test.
func TestRepinKeepsHistory(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	tg := pinned(t, h, admin, k1)
	id2 := func() uuid.UUID { return keyID(t, h, tg.ID, k2.Fingerprint) }

	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k2, false))
	_, err := h.svc.RepinHostKey(h.ctx, admin, tg.ID, id2(), k2.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.ErrorIs(t, err, inventory.ErrHostKeyState, "no re-pin unless the identity changed")

	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k2, true))
	for _, tc := range []struct{ reason, code string }{
		{"short", validate.TooShort},
		{strings.Repeat("ü", 501), validate.TooLong},
		{"see -----BEGIN OPENSSH PRIVATE KEY----- below", validate.Pattern},
	} {
		_, err := h.svc.RepinHostKey(h.ctx, admin, tg.ID, id2(), k2.Fingerprint, tc.reason)
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs, tc.reason)
		assert.Equal(t, "reason", verrs[0].Field)
		assert.Equal(t, tc.code, verrs[0].Code)
	}
	_, err = h.svc.RepinHostKey(h.ctx, admin, tg.ID, id2(), k1.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.ErrorIs(t, err, inventory.ErrHostKeyStale)

	jobID, err := h.svc.RepinHostKey(h.ctx, admin, tg.ID, id2(), k2.Fingerprint, "Sunucu yeniden kuruldu, kayıt CHG-1042")
	require.NoError(t, err)
	assert.NotZero(t, jobID)
	got, err := h.svc.HostKeyStore().Pinned(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, k2, got)
	assert.Equal(t, inventory.StatusChecking, statusOf(t, h, tg.ID))
	recs, err := h.svc.ListHostKeys(h.ctx, tg.ID)
	require.NoError(t, err)
	statuses := map[string]string{}
	for _, r := range recs {
		statuses[r.Fingerprint] = r.Status
		if r.Fingerprint == k1.Fingerprint {
			require.NotNil(t, r.SupersededAt, "the old key keeps the time it was replaced")
		}
	}
	assert.Equal(t, map[string]string{k1.Fingerprint: "superseded", k2.Fingerprint: "pinned"}, statuses)
	assert.Equal(t, []map[string]string{{"old_fingerprint": k1.Fingerprint, "new_fingerprint": k2.Fingerprint,
		"reason": "Sunucu yeniden kuruldu, kayıt CHG-1042", "target_id": tg.ID.String()}}, h.auditDetails("hostkey.repinned"))
	_, err = h.svc.RepinHostKey(h.ctx, admin, tg.ID, id2(), k2.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.ErrorIs(t, err, inventory.ErrHostKeyState)
}

func TestVerifyCommand(t *testing.T) {
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", inventory.VerifyCommand("ssh-ed25519"))
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub", inventory.VerifyCommand("ecdsa-sha2-nistp256"))
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub", inventory.VerifyCommand("ssh-rsa"))
	assert.Equal(t, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", inventory.VerifyCommand("unknown"))
}

// Concurrent and late sightings of the same changed key (the dialer's store call may land after
// Dial returned) block the target, audit and mail once, and keep one row per key.
func TestChangedKeySeenConcurrentlyNotifiesOnce(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	h.user("bora", rbac.Admin, "bora@example.com")
	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	tg := pinned(t, h, admin, k1)
	store := h.svc.HostKeyStore()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = store.Observed(h.ctx, tg.ID, k2, true)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, inventory.StatusHostKeyChanged, statusOf(t, h, tg.ID))
	assert.Equal(t, 1, h.audits("hostkey.changed"))
	assert.Equal(t, 2, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM host_keys WHERE target_id = $1 AND fingerprint_sha256 = $2", tg.ID, k2.Fingerprint))

	// The administrator accepts k2; a late report of the same sighting changes nothing.
	_, err := h.svc.RepinHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k2.Fingerprint), k2.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.NoError(t, err)
	require.NoError(t, store.Observed(h.ctx, tg.ID, k2, true))
	assert.Equal(t, inventory.StatusChecking, statusOf(t, h, tg.ID))
	assert.Equal(t, 1, h.audits("hostkey.changed"))
	assert.Equal(t, 2, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.host_key_changed'"))
	got, err := store.Pinned(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, k2, got)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM host_keys WHERE target_id = $1", tg.ID))
}

// Observed honours its context: a cancelled call stores nothing.
func TestObservedHonoursContext(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	ctx, cancel := context.WithCancel(h.ctx)
	cancel()
	require.ErrorIs(t, h.svc.HostKeyStore().Observed(ctx, tg.ID, ed25519HostKey(t), false), context.Canceled)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM host_keys"))
}

// A sighting whose fingerprint is not the one of its public key is refused: the administrator
// confirms a fingerprint, so it must name exactly the key that gets pinned.
func TestObservedRefusesInconsistentKey(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	store := h.svc.HostKeyStore()
	for name, k := range map[string]providers.HostKey{
		"other fingerprint": {Type: k1.Type, PublicKey: k1.PublicKey, Fingerprint: k2.Fingerprint},
		"other type":        {Type: "ssh-rsa", PublicKey: k1.PublicKey, Fingerprint: k1.Fingerprint},
		"not a key":         {Type: k1.Type, PublicKey: []byte("junk"), Fingerprint: k1.Fingerprint},
		"empty":             {},
	} {
		require.Error(t, store.Observed(h.ctx, tg.ID, k, false), name)
	}
	assert.Equal(t, 0, h.count("SELECT count(*) FROM host_keys"))
	require.ErrorIs(t, store.Observed(h.ctx, uuid.New(), k1, false), inventory.ErrNotFound)
}

// A changed=true sighting on a target with nothing pinned is only a candidate: Observed never
// pins and never blocks a target that has no confirmed identity.
func TestObservedWithoutPinNeverPinsOrBlocks(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	tg := h.add(admin, "web-01", "web-01.example.com")
	k := ed25519HostKey(t)
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k, true))
	_, err := h.svc.HostKeyStore().Pinned(h.ctx, tg.ID)
	require.ErrorIs(t, err, providers.ErrNoPinnedKey)
	assert.Equal(t, inventory.StatusPendingHostKey, statusOf(t, h, tg.ID))
	assert.Equal(t, 0, h.audits("hostkey.changed"))
	// A connection report never trusts a target whose key is unconfirmed.
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{}))
	assert.Equal(t, inventory.StatusPendingHostKey, statusOf(t, h, tg.ID))
}

// A key the server presents again after it was replaced becomes a candidate again and can be
// re-pinned; the pinned row then no longer carries the time it was superseded.
func TestRepinBackToSupersededKey(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	k1, k2 := ed25519HostKey(t), ed25519HostKey(t)
	tg := pinned(t, h, admin, k1)
	store := h.svc.HostKeyStore()
	require.NoError(t, store.Observed(h.ctx, tg.ID, k2, true))
	_, err := h.svc.RepinHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k2.Fingerprint), k2.Fingerprint, "Server reinstalled, ticket CHG-1042")
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{}))

	require.NoError(t, store.Observed(h.ctx, tg.ID, k1, true))
	assert.Equal(t, inventory.StatusHostKeyChanged, statusOf(t, h, tg.ID))
	assert.Equal(t, 2, h.audits("hostkey.changed"), "a new change after a re-pin is a new transition")
	_, err = h.svc.RepinHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k1.Fingerprint), k1.Fingerprint, "Restored from backup, ticket CHG-1043")
	require.NoError(t, err)
	recs, err := h.svc.ListHostKeys(h.ctx, tg.ID)
	require.NoError(t, err)
	for _, r := range recs {
		if r.Fingerprint == k1.Fingerprint {
			assert.Equal(t, "pinned", r.Status)
			assert.Nil(t, r.SupersededAt)
		} else {
			assert.Equal(t, "superseded", r.Status)
			assert.NotNil(t, r.SupersededAt)
		}
	}
}
