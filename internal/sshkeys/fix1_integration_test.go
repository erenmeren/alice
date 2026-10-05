//go:build integration

package sshkeys_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// S7 fails closed (Task 7 review I1): when the last scan has no key-file entry for the connection
// account on that server, or its list is not known to be complete, Alice cannot know which files
// that account's sshd reads, so every deploy there is refused — at the request and in the job.
func TestDeployRefusedWhenTheConnectionAccountsFilesAreUnknown(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	deploy := providers.UserKeyFiles{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}
	in := func(srv uuid.UUID) sshkeys.DeployInput {
		return sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"}
	}
	for name, files := range map[string][]providers.UserKeyFiles{
		"no entry":   {deploy},
		"incomplete": {deploy, {OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys"}}},
	} {
		srv := e.serverWith("web-"+name[:2], files)
		_, err := e.svc.RequestDeploy(e.ctx, e.operator, in(srv))
		assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount, name)
		assert.Equal(t, "connection_account_files_unknown", e.lastAuditDetail("sshkey.deploy.denied", "reason"), name)
	}
	srv := e.server("web-ok")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, in(srv))
	require.NoError(t, err)
	payload := e.job(id).Payload
	setFiles := func(files []providers.UserKeyFiles) {
		raw, err := json.Marshal(files)
		require.NoError(t, err)
		_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{key_files}', $2) WHERE id = $1", srv, raw)
		require.NoError(t, err)
	}
	setFiles([]providers.UserKeyFiles{deploy})
	_, err = e.svc.DeployJob(e.ctx, id, srv, payload)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount, "the job reads the scan again")
	setFiles([]providers.UserKeyFiles{deploy, {OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys"}}})
	_, err = e.svc.DeployJob(e.ctx, id, srv, payload)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
	setFiles(keyFiles)
	_, err = e.svc.DeployJob(e.ctx, id, srv, payload)
	assert.NoError(t, err)
}

// notAServer is the inventory with every target read as a Key Vault (review M2: the allow-list of
// target types, tested without a vault row).
type notAServer struct{ sshkeys.Inventory }

func (n notAServer) TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (inventory.Target, error) {
	t, err := n.Inventory.TargetTx(ctx, tx, id, lock)
	t.Type = inventory.TypeAzureKeyVault
	return t, err
}

func TestDeployRefusesATargetThatIsNotAServer(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	srv := e.server("web-01")
	svc := sshkeys.New(sshkeys.Config{HelperBudget: helperproto.HelperBudget, Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, License: e.gate,
		Inventory: notAServer{e.inv}, Jobs: e.queue})
	_, err := svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrNotAServer)
}

// Review M1: a key whose destruction fails does not stop the others, every hour.
func TestDestroyContinuesAfterAFailingKey(t *testing.T) {
	e := newEnv(t)
	bad, good := e.generate("bad"), e.generate("good")
	e.retireAt(bad.ID, e.clock.Now()) // the oldest: tried first
	e.retireAt(good.ID, e.clock.Now().Add(time.Second))
	_, err := e.db.Owner.Exec(e.ctx, `CREATE FUNCTION test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'refused for the test'; END $$`)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `CREATE TRIGGER test_refuse BEFORE UPDATE ON managed_private_keys FOR EACH ROW
WHEN (OLD.id = '`+bad.PrivateKeyID.String()+`') EXECUTE FUNCTION test_refuse()`)
	require.NoError(t, err)
	e.clock.Advance(31 * 24 * time.Hour)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	assert.Error(t, err)
	assert.Equal(t, 1, n, "the other key is destroyed")
	got, err := e.svc.ManagedKey(e.ctx, good.ID)
	require.NoError(t, err)
	assert.NotNil(t, got.DestroyedAt)
}

// Review M3: a key an unfinished run references (as old or new key) is never destroyed.
func TestDestroySkipsKeysOfAnUnfinishedRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	require.Equal(t, "adding_new", r.Status)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_key_locations SET missing_since = $2 WHERE ssh_key_id = $1", k.ID, e.clock.Now())
	require.NoError(t, err)
	e.retireAt(k.ID, e.clock.Now())
	e.retireAt(*r.NewKeyID, e.clock.Now())
	e.clock.Advance(31 * 24 * time.Hour)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Zero(t, e.count("SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NOT NULL"))
}

// S5 with the ssh_keys guard (Z1014): a key whose private key was destroyed and that is found live
// again stays retired; it is audited sshkey.live_after_destruction, once.
func TestDestroyedKeyFoundLiveAgainStaysRetired(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(30 * 24 * time.Hour)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	e.liveLocation(k)
	for range 2 {
		n, err = e.svc.DestroyRetiredKeys(e.ctx)
		require.NoError(t, err)
		assert.Zero(t, n)
	}
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.NotNil(t, got.RetiredAt, "stays retired")
	assert.Zero(t, e.audits("sshkey.reactivated"))
	assert.Equal(t, 1, e.audits("sshkey.live_after_destruction"), "once")
	assert.Equal(t, k.ID.String(), e.lastAuditDetail("sshkey.live_after_destruction", "ssh_key_id"))
	assert.Equal(t, "1", e.lastAuditDetail("sshkey.live_after_destruction", "location_count"))
}
