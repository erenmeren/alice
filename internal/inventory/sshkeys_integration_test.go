//go:build integration

package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// okTarget adds a target and marks it connected (as a confirmed host key and a successful test would).
func okTarget(t *testing.T, h *harness, a inventory.Actor, name string) inventory.Target {
	t.Helper()
	tg := h.add(a, name, name+".example.com")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	tg.Status = inventory.StatusOK
	return tg
}

func dk(user, path string, line int, fp, comment string, flags ...string) providers.DiscoveredSSHKey {
	return providers.DiscoveredSSHKey{OSUser: user, FilePath: path, LineNo: line, PublicKey: "ssh-ed25519 AAAAC3" + fp,
		Fingerprint: fp, KeyType: "ssh-ed25519", Bits: 256, Comment: comment, Flags: flags}
}

const (
	deployFile = "/home/deploy/.ssh/authorized_keys"
	aliceFile  = "/var/lib/alice-svc/.ssh/authorized_keys"
	rootFile   = "/root/.ssh/authorized_keys"
)

func locations(t *testing.T, h *harness, target uuid.UUID, missing bool) map[string]inventory.KeyLocation {
	t.Helper()
	locs, err := h.svc.ListTargetKeys(h.ctx, target, missing)
	require.NoError(t, err)
	out := map[string]inventory.KeyLocation{}
	for _, l := range locs {
		out[l.OSUser+" "+l.Fingerprint] = l
	}
	return out
}

func TestReconcileTracksNewMissingAndOwnKey(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	tg := okTarget(t, h, admin, "web-01")

	first := providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{
			dk("deploy", deployFile, 1, "SHA256:aaa", "deploy@laptop"),
			dk("deploy", deployFile, 2, "SHA256:bbb", "ci@build", providers.FlagWeak),
			dk("deploy", deployFile, 3, "SHA256:aaa", "deploy@laptop", providers.FlagDuplicate),
			dk("alice-svc", aliceFile, 1, pk.Fingerprint, "alice-platform"),
			dk("root", rootFile, 1, "SHA256:aaa", "root copy", providers.FlagRootWithoutFrom),
		},
		HostKeys:  []providers.DiscoveredHostKey{{KeyType: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:host"}},
		SSHD:      providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none", AuthorizedKeysFile: []string{".ssh/authorized_keys"}},
		Warnings:  []providers.Warning{{Code: "strict_modes", Params: map[string]string{"file_path": rootFile}}},
		ReadFiles: []string{deployFile, aliceFile, rootFile},
	}
	sum, err := h.svc.Reconcile(h.ctx, tg.ID, first)
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Keys: 4, New: 4, Missing: 0}, sum, "the duplicate line is one location")
	assert.Equal(t, 3, h.count("SELECT count(*) FROM ssh_keys"), "one row per fingerprint")
	locs := locations(t, h, tg.ID, false)
	require.Len(t, locs, 4)
	assert.Equal(t, 1, locs["deploy SHA256:aaa"].LineNo, "the first line of a duplicate is kept")
	assert.True(t, locs["alice-svc "+pk.Fingerprint].IsAliceConnectionKey)
	assert.False(t, locs["deploy SHA256:aaa"].IsAliceConnectionKey)
	assert.Equal(t, []string{providers.FlagWeak}, locs["deploy SHA256:bbb"].Flags)
	assert.Equal(t, "web-01", locs["deploy SHA256:aaa"].TargetName)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM ssh_keys WHERE is_platform_key AND fingerprint_sha256 = $1", pk.Fingerprint))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM ssh_keys WHERE weak AND fingerprint_sha256 = 'SHA256:bbb'"))
	assert.Equal(t, []map[string]string{{"key_count": "4", "new_count": "4", "missing_count": "0", "partial": "false"}},
		h.auditDetails("target.discovered"))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastDiscoveryAt)
	require.NotNil(t, got.Facts.SSHD)
	assert.Equal(t, first.HostKeys, got.Facts.HostKeys)
	assert.Equal(t, first.Warnings, got.Facts.Warnings)
	assert.False(t, got.KeysManagedElsewhere)

	// Second scan: the Alice file could not be read (partial). bbb and the root copy are gone from
	// files that were read; the platform key is not marked missing because its file was not read.
	h.clock.Advance(time.Hour)
	second := providers.DiscoveryResult{
		SSHKeys:   []providers.DiscoveredSSHKey{dk("deploy", deployFile, 1, "SHA256:aaa", "deploy@laptop")},
		SSHD:      providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "/usr/bin/sss_ssh_authorizedkeys", KeysManagedElsewhere: true},
		Partial:   true,
		ReadFiles: []string{deployFile, rootFile},
	}
	sum, err = h.svc.Reconcile(h.ctx, tg.ID, second)
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Keys: 1, New: 0, Missing: 2}, sum)
	live := locations(t, h, tg.ID, false)
	assert.Len(t, live, 2, "aaa in deploy's file and the platform key stay")
	assert.Contains(t, live, "alice-svc "+pk.Fingerprint)
	all := locations(t, h, tg.ID, true)
	require.NotNil(t, all["deploy SHA256:bbb"].MissingSince)
	require.NotNil(t, all["root SHA256:aaa"].MissingSince)
	assert.Equal(t, 4, h.count("SELECT count(*) FROM ssh_key_locations"), "nothing is ever deleted")
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.True(t, got.KeysManagedElsewhere, "F-35")

	// Third scan: bbb is back; its missing mark is cleared.
	h.clock.Advance(time.Hour)
	first.ReadFiles = []string{deployFile}
	sum, err = h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{SSHKeys: first.SSHKeys[:2], ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	assert.Equal(t, 0, sum.New)
	assert.Nil(t, locations(t, h, tg.ID, true)["deploy SHA256:bbb"].MissingSince)
}

// SEC-081: even the owner role cannot mark Alice's own key location removed or delete it.
func TestTriggerProtectsTheOwnKeyLocation(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	tg := okTarget(t, h, admin, "web-01")
	_, err = h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{dk("alice-svc", aliceFile, 1, pk.Fingerprint, "alice-platform")}, ReadFiles: []string{aliceFile}})
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE ssh_key_locations SET removed_by_alice_at = now() WHERE is_alice_connection_key")
	require.ErrorContains(t, err, "own connection key cannot be removed")
	_, err = h.db.Owner.Exec(h.ctx, "DELETE FROM ssh_key_locations WHERE is_alice_connection_key")
	require.ErrorContains(t, err, "cannot be deleted")
}

// L-72 with discovery: 200 keys found on existing targets at 10 of 10 are accepted and the limit
// is unchanged.
func TestL72DiscoveryAtTheLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.installLicense("LIC-L72", 10, 365)
	var first inventory.Target
	for i := range 10 {
		tg := okTarget(t, h, admin, fmt.Sprintf("web-%02d", i))
		if i == 0 {
			first = tg
		}
	}
	keys := make([]providers.DiscoveredSSHKey, 200)
	for i := range keys {
		keys[i] = dk("deploy", deployFile, i+1, fmt.Sprintf("SHA256:k%03d", i), "")
	}
	sum, err := h.svc.Reconcile(h.ctx, first.ID, providers.DiscoveryResult{SSHKeys: keys, ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	assert.Equal(t, 200, sum.New)
	n, err := inventory.Counter{}.CountTargets(h.ctx, h.db.App)
	require.NoError(t, err)
	assert.Equal(t, 10, n)
	require.NoError(t, h.lic.Tick(h.ctx))
	assert.Equal(t, 10, h.lic.Snapshot().Targets)
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-11", Type: "linux", Host: "web-11.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit)
}

func TestReconcileOfDeletedTargetIsNotFound(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{})
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func seedInventory(t *testing.T, h *harness) (inventory.Target, inventory.Target) {
	t.Helper()
	admin := h.user("ada", rbac.Admin, "")
	a := okTarget(t, h, admin, "web-01")
	b := okTarget(t, h, admin, "web-02")
	_, err := h.svc.Reconcile(h.ctx, a.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:Izm1", "deploy@İzmir"),
		dk("deploy", deployFile, 2, "SHA256:Igd2", "ops@ığdır", providers.FlagWeak),
		dk("root", rootFile, 1, "SHA256:Ci3", "100%_done"),
	}, ReadFiles: []string{deployFile, rootFile}})
	require.NoError(t, err)
	h.clock.Advance(time.Minute)
	_, err = h.svc.Reconcile(h.ctx, b.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:Izm1", "deploy@izmir-new"),
	}, ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	return a, b
}

func fingerprints(p inventory.KeyPage) []string {
	out := []string{}
	for _, k := range p.Items {
		out = append(out, k.Fingerprint)
	}
	return out
}

func TestListSSHKeysFiltersSearchAndCursor(t *testing.T) {
	h := newHarness(t)
	a, b := seedInventory(t, h)
	list := func(f inventory.KeyFilter) inventory.KeyPage {
		t.Helper()
		p, err := h.svc.ListSSHKeys(h.ctx, f)
		require.NoError(t, err)
		return p
	}
	all := list(inventory.KeyFilter{})
	assert.Equal(t, []string{"SHA256:Izm1", "SHA256:Igd2", "SHA256:Ci3"}, fingerprints(all))
	assert.Equal(t, 2, all.Items[0].LocationCount)
	assert.Equal(t, 2, all.Items[0].TargetCount)
	assert.Equal(t, "deploy@izmir-new", all.Items[0].Comment, "the comment of the most recently seen location")
	assert.True(t, all.Items[1].Weak)

	assert.Equal(t, []string{"SHA256:Izm1"}, fingerprints(list(inventory.KeyFilter{Query: "İZMİR"})))
	assert.Equal(t, []string{"SHA256:Izm1"}, fingerprints(list(inventory.KeyFilter{Query: "izmir"})))
	assert.Equal(t, []string{"SHA256:Igd2"}, fingerprints(list(inventory.KeyFilter{Query: "Iğdır"})))
	assert.Equal(t, []string{"SHA256:Ci3"}, fingerprints(list(inventory.KeyFilter{Query: "100%_"})))
	assert.Equal(t, []string{"SHA256:Ci3"}, fingerprints(list(inventory.KeyFilter{Query: "%"})), "a literal % matches only the comment that has one")
	assert.Equal(t, []string{"SHA256:Igd2"}, fingerprints(list(inventory.KeyFilter{Query: "sha256:igd"})), "fingerprints too")
	assert.Equal(t, []string{"SHA256:Izm1"}, fingerprints(list(inventory.KeyFilter{TargetID: b.ID})))
	assert.Equal(t, []string{"SHA256:Ci3"}, fingerprints(list(inventory.KeyFilter{TargetID: a.ID, OSUser: "root"})))
	assert.Equal(t, []string{"SHA256:Igd2"}, fingerprints(list(inventory.KeyFilter{Flag: providers.FlagWeak})))

	p1 := list(inventory.KeyFilter{Limit: 2})
	assert.Equal(t, []string{"SHA256:Izm1", "SHA256:Igd2"}, fingerprints(p1))
	require.NotEmpty(t, p1.NextCursor)
	p2 := list(inventory.KeyFilter{Limit: 2, Cursor: p1.NextCursor})
	assert.Equal(t, []string{"SHA256:Ci3"}, fingerprints(p2))
	assert.Empty(t, p2.NextCursor)

	// A key that is only missing is hidden unless asked for.
	_, err := h.svc.Reconcile(h.ctx, a.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:Izm1", "deploy@İzmir"),
		dk("deploy", deployFile, 2, "SHA256:Igd2", "ops@ığdır", providers.FlagWeak),
	}, ReadFiles: []string{deployFile, rootFile}})
	require.NoError(t, err)
	assert.NotContains(t, fingerprints(list(inventory.KeyFilter{})), "SHA256:Ci3")
	assert.Contains(t, fingerprints(list(inventory.KeyFilter{IncludeMissing: true})), "SHA256:Ci3")

	for _, bad := range []inventory.KeyFilter{{Limit: 201}, {Limit: -1}, {Cursor: "not-a-cursor"}, {Flag: "evil"}, {Query: string(make([]byte, 201))}} {
		_, err := h.svc.ListSSHKeys(h.ctx, bad)
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs, "%+v", bad)
	}
}

func TestGetSSHKeyListsWhereItIsUsed(t *testing.T) {
	h := newHarness(t)
	seedInventory(t, h)
	page, err := h.svc.ListSSHKeys(h.ctx, inventory.KeyFilter{Query: "izmir"})
	require.NoError(t, err)
	k, err := h.svc.GetSSHKey(h.ctx, page.Items[0].ID)
	require.NoError(t, err)
	require.Len(t, k.Locations, 2)
	assert.Equal(t, []string{"web-01", "web-02"}, []string{k.Locations[0].TargetName, k.Locations[1].TargetName})
	assert.Equal(t, "deploy", k.Locations[0].OSUser)
	assert.Equal(t, deployFile, k.Locations[0].FilePath)
	_, err = h.svc.GetSSHKey(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.KeyLocation(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// Carry (Task 9): a listed file that no longer exists counts as read, so its keys become missing.
func TestReconcileMarksTheKeysOfADeletedFileMissing(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:aaa", ""), dk("root", rootFile, 1, "SHA256:rrr", ""),
	}, ReadFiles: []string{deployFile, rootFile}})
	require.NoError(t, err)
	h.clock.Advance(time.Hour)
	// deploy's file was deleted (listed, absent: read with no keys); root's file was not readable.
	sum, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{Partial: true, ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Keys: 0, New: 0, Missing: 1}, sum)
	all := locations(t, h, tg.ID, true)
	require.NotNil(t, all["deploy SHA256:aaa"].MissingSince)
	assert.True(t, all["deploy SHA256:aaa"].MissingSince.Equal(h.clock.Now()))
	assert.Nil(t, all["root SHA256:rrr"].MissingSince, "a file that was not read never makes its keys missing")
}

// SEC-081: the connection-key mark is never written back to false by a later scan (the trigger
// would refuse it), even for a location whose key is no longer the current platform key.
func TestReconcileNeverClearsTheConnectionKeyMark(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	tg := okTarget(t, h, admin, "web-01")
	scan := providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("alice-svc", aliceFile, 1, pk.Fingerprint, "alice-platform"),
		dk("alice-svc", aliceFile, 2, "SHA256:previous", "alice-platform-old"),
	}, ReadFiles: []string{aliceFile}}
	_, err = h.svc.Reconcile(h.ctx, tg.ID, scan)
	require.NoError(t, err)
	// An earlier platform key's location (an owner procedure marks it during a rotation).
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE ssh_key_locations SET is_alice_connection_key = true
WHERE ssh_key_id = (SELECT id FROM ssh_keys WHERE fingerprint_sha256 = 'SHA256:previous')`)
	require.NoError(t, err)
	h.clock.Advance(time.Hour)
	_, err = h.svc.Reconcile(h.ctx, tg.ID, scan)
	require.NoError(t, err, "the scan must not try to clear the mark")
	locs := locations(t, h, tg.ID, false)
	assert.True(t, locs["alice-svc "+pk.Fingerprint].IsAliceConnectionKey)
	assert.True(t, locs["alice-svc SHA256:previous"].IsAliceConnectionKey)
}

// Remote text is stored as text: invalid UTF-8 and NUL never reach the database as bytes.
func TestReconcileCleansRemoteText(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	k := dk("deploy", deployFile, 1, "SHA256:aaa", "bad\xff\x00comment")
	k.Options = `from="10.0.0.1"`
	_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		k, dk("deploy", deployFile, 0, "SHA256:noline", ""), dk("deploy", deployFile, 2, "", ""),
	}, ReadFiles: []string{deployFile}})
	require.NoError(t, err)
	locs := locations(t, h, tg.ID, false)
	require.Len(t, locs, 1, "entries without a fingerprint or a line number are skipped")
	assert.Equal(t, "bad��comment", locs["deploy SHA256:aaa"].Comment)
	assert.Equal(t, `from="10.0.0.1"`, locs["deploy SHA256:aaa"].Options)
}

func TestListTargetKeysOfDeletedTargetIsNotFound(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "web-01")
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	_, err := h.svc.ListTargetKeys(h.ctx, tg.ID, true)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
