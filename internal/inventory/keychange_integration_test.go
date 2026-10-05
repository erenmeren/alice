//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// seedGeneratedKey inserts a key Alice generated, as Phase 6's generation does: its private key row and a
// managed ssh_keys row (owner pool: the tests' stand-in for the generation service).
func seedGeneratedKey(t *testing.T, h *harness, fp, comment string) uuid.UUID {
	t.Helper()
	pk, key := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`,
		pk, h.clock.Now())
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, key_comment,
    first_seen_at, created_at) VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $5, $5)`, key, fp, pk, comment, h.clock.Now())
	require.NoError(t, err)
	return key
}

const (
	genFP  = "SHA256:Gen0000000000000000000000000000000000000000"
	genFP2 = "SHA256:Gen2000000000000000000000000000000000000000"
)

func insertLoc(t *testing.T, h *harness, key, target uuid.UUID, user, file string, line int, missing, removed *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at,
    missing_since, removed_by_alice_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`, id, key, target, user, file, line, h.clock.Now(), missing, removed)
	require.NoError(t, err)
	return id
}

func TestKeyLocationsTxListsLiveAndMissing(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	other := okTarget(t, h, admin, "web-02")
	key := seedGeneratedKey(t, h, genFP, "")
	now := h.clock.Now()
	present := insertLoc(t, h, key, tg.ID, "deploy", "/home/deploy/.ssh/authorized_keys", 1, nil, nil)
	missing := insertLoc(t, h, key, tg.ID, "bob", "/home/bob/.ssh/authorized_keys", 1, &now, nil)
	insertLoc(t, h, key, tg.ID, "carol", "/home/carol/.ssh/authorized_keys", 1, nil, &now)
	onOther := insertLoc(t, h, key, other.ID, "deploy", "/home/deploy/.ssh/authorized_keys", 1, nil, nil)
	deleted := okTarget(t, h, admin, "web-03")
	insertLoc(t, h, key, deleted.ID, "deploy", "/home/deploy/.ssh/authorized_keys", 1, nil, nil)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", deleted.ID)
	require.NoError(t, err)

	var got []inventory.KeyLocation
	require.NoError(t, db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error {
		var err error
		got, err = h.svc.KeyLocationsTx(h.ctx, tx, key, false)
		return err
	}))
	require.Len(t, got, 3, "the present and the missing one of live targets; not the one Alice removed, not a deleted target's")
	byID := map[uuid.UUID]inventory.KeyLocation{}
	for _, l := range got {
		byID[l.ID] = l
	}
	require.Contains(t, byID, present)
	require.Contains(t, byID, missing)
	require.Contains(t, byID, onOther)
	assert.NotNil(t, byID[missing].MissingSince)
	assert.Nil(t, byID[present].MissingSince)
	for i := 1; i < len(got); i++ {
		a, b := got[i-1], got[i]
		assert.LessOrEqual(t, a.TargetID.String()+"\x00"+a.FilePath+"\x00"+a.OSUser, b.TargetID.String()+"\x00"+b.FilePath+"\x00"+b.OSUser, "ordered by target, file, user")
	}

	// With lock the rows are locked until the transaction ends.
	tx, err := h.db.App.Begin(h.ctx)
	require.NoError(t, err)
	locked, err := h.svc.KeyLocationsTx(h.ctx, tx, key, true)
	require.NoError(t, err)
	require.Len(t, locked, 3)
	tx2, err := h.db.App.Begin(h.ctx)
	require.NoError(t, err)
	var one int
	err = tx2.QueryRow(h.ctx, "SELECT 1 FROM ssh_key_locations WHERE id = $1 FOR UPDATE NOWAIT", present).Scan(&one)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "55P03", pgErr.Code, "the row is locked")
	require.NoError(t, tx2.Rollback(h.ctx))
	require.NoError(t, tx.Rollback(h.ctx))

	// Without lock a query error is reported (the transaction is finished).
	_, err = h.svc.KeyLocationsTx(h.ctx, tx, key, false)
	assert.Error(t, err)
}

func recordAdded(h *harness, in inventory.KeyAdded) (id uuid.UUID, err error) {
	err = db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error {
		id, err = h.svc.RecordKeyAddedTx(h.ctx, tx, in)
		return err
	})
	return id, err
}

func TestRecordKeyAddedTx(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	h.pinnedKey(tg.ID)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'unreachable' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	key := seedGeneratedKey(t, h, genFP, "ci@alice")
	job := uuid.Must(uuid.NewV7())
	actor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: job.String()}
	in := inventory.KeyAdded{SSHKeyID: key, TargetID: tg.ID, OSUser: "deploy", FilePath: deployFile, Options: `from="10.0.0.1"`,
		Comment: "ci@alice", LineNo: 4, Actor: actor, Verified: true}

	id, err := recordAdded(h, in)
	require.NoError(t, err)
	var line int
	var options, comment string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT line_no, options, comment FROM ssh_key_locations WHERE id = $1", id).Scan(&line, &options, &comment))
	assert.Equal(t, 4, line)
	assert.Equal(t, `from="10.0.0.1"`, options)
	assert.Equal(t, "ci@alice", comment)
	d := h.auditDetails("sshkey.added")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"ssh_key_id": key.String(), "fingerprint": genFP, "target_id": tg.ID.String(), "os_user": "deploy",
		"file_path": deployFile, "job_id": job.String(), "verified": "true"}, d[0])
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status, "the connection that wrote the line proves the server reachable")
	changed := h.auditDetails("target.status_changed")
	require.NotEmpty(t, changed)
	assert.Equal(t, "key_added", changed[len(changed)-1]["reason"])

	// Again for the same place, after the line was found missing and then removed: one row, revived.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE ssh_key_locations SET missing_since = now(), removed_by_alice_at = now() WHERE id = $1", id)
	require.NoError(t, err)
	in.LineNo, in.Verified, in.Options = 0, false, ""
	again, err := recordAdded(h, in)
	require.NoError(t, err)
	assert.Equal(t, id, again)
	var missing, removed *time.Time
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT line_no, missing_since, removed_by_alice_at, options FROM ssh_key_locations WHERE id = $1", id).Scan(&line, &missing, &removed, &options))
	assert.Equal(t, 1, line, "an unknown line number is stored as 1")
	assert.Nil(t, missing)
	assert.Nil(t, removed)
	assert.Empty(t, options)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", key))
	assert.Equal(t, "false", h.auditDetails("sshkey.added")[1]["verified"])

	// Alice's own key is refused and nothing is written.
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	var own uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES (gen_random_uuid(), $1, 'ssh-ed25519', 'k', now(), now()) ON CONFLICT (fingerprint_sha256) DO UPDATE SET weak = ssh_keys.weak RETURNING id`, pk.Fingerprint).Scan(&own))
	before := h.audits("sshkey.added")
	_, err = recordAdded(h, inventory.KeyAdded{SSHKeyID: own, TargetID: tg.ID, OSUser: "deploy", FilePath: deployFile, Actor: actor})
	require.ErrorIs(t, err, inventory.ErrOwnKeyProtected)
	assert.Equal(t, before, h.audits("sshkey.added"))
	assert.Zero(t, h.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", own))

	// Unknown key, deleted or unknown target.
	_, err = recordAdded(h, inventory.KeyAdded{SSHKeyID: uuid.New(), TargetID: tg.ID, OSUser: "deploy", FilePath: deployFile, Actor: actor})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = recordAdded(h, inventory.KeyAdded{SSHKeyID: key, TargetID: uuid.New(), OSUser: "deploy", FilePath: deployFile, Actor: actor})
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestCheckClaimTxRefusesALostClaim(t *testing.T) {
	h := newHarness(t)
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	job, err := h.svc.RequestDiscovery(h.ctx, admin, tg.ID)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET status = 'running', attempts = 2 WHERE id = $1", job)
	require.NoError(t, err)
	key := seedGeneratedKey(t, h, genFP, "")
	check := func(ctx_ inventory.Claim) error {
		return db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error {
			return inventory.CheckClaimTx(inventory.WithClaim(h.ctx, ctx_), tx)
		})
	}
	assert.ErrorIs(t, check(inventory.Claim{JobID: job, Attempt: 1}), inventory.ErrClaimLost, "an older run")
	assert.NoError(t, check(inventory.Claim{JobID: job, Attempt: 2}))
	assert.NoError(t, db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error { return inventory.CheckClaimTx(h.ctx, tx) }), "no claim: not a job")

	// RecordKeyAddedTx is fenced the same way: nothing is written for a lost run.
	lost := inventory.WithClaim(h.ctx, inventory.Claim{JobID: job, Attempt: 1})
	err = db.InTx(lost, h.db.App, func(tx pgx.Tx) error {
		_, err := h.svc.RecordKeyAddedTx(lost, tx, inventory.KeyAdded{SSHKeyID: key, TargetID: tg.ID, OSUser: "deploy", FilePath: deployFile})
		return err
	})
	require.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Zero(t, h.count("SELECT count(*) FROM ssh_key_locations"))
}

func TestProtectedFingerprintsTxAndTargetTx(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	require.NoError(t, db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error {
		fps, err := inventory.ProtectedFingerprintsTx(h.ctx, tx)
		require.NoError(t, err)
		assert.Contains(t, fps, pk.Fingerprint)
		got, err := h.svc.TargetTx(h.ctx, tx, tg.ID, true)
		require.NoError(t, err)
		assert.Equal(t, tg.ID, got.ID)
		_, err = h.svc.TargetTx(h.ctx, tx, uuid.New(), false)
		assert.ErrorIs(t, err, inventory.ErrNotFound)
		return nil
	}))
}

func TestReconcileStoresKeyFiles(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	files := []providers.UserKeyFiles{{OSUser: "alice-svc", Files: []string{aliceFile}}, {OSUser: "deploy", Files: []string{deployFile, "/home/deploy/.ssh/authorized_keys2"}}}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{SSHD: sshdRead, KeyFiles: files, ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	got, err := h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, files, got.Facts.KeyFiles)

	// A certificates-only result knows nothing about SSH: the earlier files stay.
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK})
	require.NoError(t, err)
	got, err = h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, files, got.Facts.KeyFiles, "a certificates-only result keeps them")

	// The next SSH scan replaces them.
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{SSHD: sshdRead, KeyFiles: files[:1], ReadFiles: []string{aliceFile}})
	require.NoError(t, err)
	got, err = h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, files[:1], got.Facts.KeyFiles)
}

// The removal's refusals answer as before (the removal tests are the regression check); a disabled server
// is the one new refusal, and it is not audited as a denial.
func TestRemovalStillRefusesAsBefore(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", f.target.ID)
	require.NoError(t, err)
	before := len(h.jobs.requests())
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrTargetDisabled)
	assert.Len(t, h.jobs.requests(), before, "nothing was queued")
	assert.Zero(t, h.audits("sshkey.remove.denied"))
}

func TestListSSHKeysShowsGeneratedKeysWithoutLocations(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	key := seedGeneratedKey(t, h, genFP, "ci-deploy@alice")
	list := func(f inventory.KeyFilter) []inventory.SSHKey {
		t.Helper()
		p, err := h.svc.ListSSHKeys(h.ctx, f)
		require.NoError(t, err)
		return p.Items
	}
	items := list(inventory.KeyFilter{})
	require.Len(t, items, 1)
	k := items[0]
	assert.Equal(t, key, k.ID)
	assert.True(t, k.Managed)
	assert.Zero(t, k.LocationCount)
	assert.Zero(t, k.TargetCount)
	assert.False(t, k.Missing)
	assert.Equal(t, "ci-deploy@alice", k.Comment)
	assert.Len(t, list(inventory.KeyFilter{Query: "CI-DEPLOY"}), 1, "found by its comment")
	assert.Empty(t, list(inventory.KeyFilter{Query: "nothing-like-this"}))
	assert.Empty(t, list(inventory.KeyFilter{TargetID: tg.ID}), "a target filter shows keys that are on it")
	assert.Empty(t, list(inventory.KeyFilter{OSUser: "deploy"}))
	assert.Empty(t, list(inventory.KeyFilter{Flag: providers.FlagWeak}))

	got, err := h.svc.GetSSHKey(h.ctx, key)
	require.NoError(t, err)
	assert.Empty(t, got.Locations)
	assert.Equal(t, "ci-deploy@alice", got.Comment)
	assert.False(t, got.Missing)
	assert.Zero(t, got.LocationCount)

	// With a location the comment of the location wins (as before) and the count follows.
	insertLoc(t, h, key, tg.ID, "deploy", deployFile, 1, nil, nil)
	items = list(inventory.KeyFilter{})
	require.Len(t, items, 1)
	assert.Equal(t, 1, items[0].LocationCount)
	assert.Equal(t, 1, items[0].TargetCount)
	assert.Len(t, list(inventory.KeyFilter{TargetID: tg.ID}), 1)

	// A discovered key whose every location is missing stays hidden without IncludeMissing.
	now := h.clock.Now()
	disc := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', $3, $3)`, disc, genFP2, now.Add(time.Second))
	require.NoError(t, err)
	insertLoc(t, h, disc, tg.ID, "bob", "/home/bob/.ssh/authorized_keys", 1, &now, nil)
	assert.Len(t, list(inventory.KeyFilter{}), 1, "the missing discovered key is hidden")
	assert.Len(t, list(inventory.KeyFilter{IncludeMissing: true}), 2)
	// A discovered key with no live location at all is not listed (only generated keys are).
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", tg.ID)
	require.NoError(t, err)
	items = list(inventory.KeyFilter{IncludeMissing: true})
	require.Len(t, items, 1, "the generated key stays; the discovered one lost its only (deleted) target")
	assert.Equal(t, key, items[0].ID)
}
