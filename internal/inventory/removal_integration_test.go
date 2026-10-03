//go:build integration

package inventory_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// sshdRead is a scan that read sshd's settings (removals need one, R37 item 9).
var sshdRead = providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none", AuthorizedKeysFile: []string{".ssh/authorized_keys"}}

type removalFixture struct {
	h        *harness
	admin    inventory.Actor
	operator inventory.Actor
	target   inventory.Target
	own      uuid.UUID // Alice's key location
	deploy   uuid.UUID // a normal key
	root     uuid.UUID // root's only key
	ca       uuid.UUID // a cert-authority line
}

func newRemovalFixture(t *testing.T) removalFixture {
	t.Helper()
	h := newHarness(t)
	f := removalFixture{h: h, admin: h.user("ada", rbac.Admin, ""), operator: h.user("oya", rbac.Operator, "")}
	pk, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	f.target = okTarget(t, h, f.admin, "web-01")
	_, err = h.svc.Reconcile(h.ctx, f.target.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("alice-svc", aliceFile, 1, pk.Fingerprint, "alice-platform"),
		dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "deploy@laptop"),
		dk("deploy", deployFile, 2, "SHA256:ca00000000000000000000000000000000000000000", "", providers.FlagCertAuthority),
		dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
	}, SSHD: sshdRead, ReadFiles: []string{aliceFile, deployFile, rootFile}})
	require.NoError(t, err)
	locs := locations(t, h, f.target.ID, false)
	f.own, f.deploy = locs["alice-svc "+pk.Fingerprint].ID, locs["deploy SHA256:dep0000000000000000000000000000000000000000"].ID
	f.root, f.ca = locs["root SHA256:root000000000000000000000000000000000000000"].ID, locs["deploy SHA256:ca00000000000000000000000000000000000000000"].ID
	return f
}

func TestRequestKeyRemovalQueuesTheJob(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	before := len(h.jobs.requests())
	jobID, err := h.svc.RequestKeyRemoval(h.ctx, f.operator, f.deploy, false)
	require.NoError(t, err)
	assert.NotZero(t, jobID)
	reqs := h.jobs.requests()
	require.Len(t, reqs, before+1)
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobSSHKeyRemove, TargetID: f.target.ID, Kind: "user",
		CreatedBy: f.operator.UserID, CreatedByRole: "operator", DedupeKey: "sshkey.remove:" + f.deploy.String(),
		Payload: map[string]string{"location_id": f.deploy.String(), "fingerprint": "SHA256:dep0000000000000000000000000000000000000000", "os_user": "deploy",
			"file_path": deployFile, "confirm_last_root_key": "false"}}, reqs[before])
	d := h.auditDetails("sshkey.remove_requested")
	require.Len(t, d, 1)
	assert.Equal(t, "SHA256:dep0000000000000000000000000000000000000000", d[0]["fingerprint"])
	assert.Equal(t, "deploy", d[0]["os_user"])
	assert.Equal(t, deployFile, d[0]["file_path"])
}

// F-36 at the service: Alice's own key is refused and the refusal is audited; nothing is queued.
func TestRequestKeyRemovalRefusals(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	before := len(h.jobs.requests())

	_, err := h.svc.RequestKeyRemoval(h.ctx, f.admin, f.own, true)
	require.ErrorIs(t, err, inventory.ErrOwnKeyProtected)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.ca, false)
	require.ErrorIs(t, err, inventory.ErrNotRemovable, "cert-authority lines are never managed")
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, uuid.New(), false)
	require.ErrorIs(t, err, inventory.ErrNotFound)

	// Root's last key: an Operator's confirmation does not count; an Administrator's does.
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.operator, f.root, true)
	require.ErrorIs(t, err, inventory.ErrLastRootKey)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.root, false)
	require.ErrorIs(t, err, inventory.ErrLastRootKey)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.root, true)
	require.NoError(t, err)
	assert.Equal(t, "true", h.jobs.requests()[len(h.jobs.requests())-1].Payload["confirm_last_root_key"])

	for _, tc := range []struct {
		status string
		want   error
	}{{"pending_host_key", inventory.ErrHostKeyUnconfirmed}, {"host_key_changed", inventory.ErrHostKeyChanged}} {
		_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = $2 WHERE id = $1", f.target.ID, tc.status)
		require.NoError(t, err)
		_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
		require.ErrorIs(t, err, tc.want, tc.status)
	}
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok', keys_managed_elsewhere = true WHERE id = $1", f.target.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrKeysManagedElsewhere, "F-35")

	assert.Len(t, h.jobs.requests(), before+1, "only the confirmed root removal was queued")
	reasons := []string{}
	for _, d := range h.auditDetails("sshkey.remove.denied") {
		reasons = append(reasons, d["reason"])
	}
	assert.Equal(t, []string{"own_key", "last_root_key", "last_root_key", "keys_managed_elsewhere"}, reasons)
	assert.Equal(t, 4, h.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.remove.denied' AND result = 'denied'"))
}

func TestMarkKeyRemovedAndFailures(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	jobActor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: "0192aaaa-0000-7000-8000-000000000001"}
	require.NoError(t, h.svc.RecordRemovalFailure(h.ctx, f.deploy, jobActor, "ssh.file_changed"))
	require.NoError(t, h.svc.MarkKeyRemoved(h.ctx, f.deploy, jobActor, providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}))
	loc, err := h.svc.KeyLocation(h.ctx, f.deploy)
	require.NoError(t, err)
	require.NotNil(t, loc.RemovedAt)
	require.NotNil(t, loc.MissingSince)
	assert.Equal(t, []map[string]string{{"fingerprint": "SHA256:dep0000000000000000000000000000000000000000", "os_user": "deploy", "file_path": deployFile,
		"job_id": jobActor.RequestID, "removed_count": "1", "verified": "true"}}, h.auditDetails("sshkey.removed"))
	assert.Equal(t, []map[string]string{{"fingerprint": "SHA256:dep0000000000000000000000000000000000000000", "os_user": "deploy", "file_path": deployFile,
		"job_id": jobActor.RequestID, "reason": "ssh.file_changed"}}, h.auditDetails("sshkey.remove_failed"))
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrNotRemovable, "a removed key cannot be removed again")

	require.Error(t, h.svc.MarkKeyRemoved(h.ctx, f.own, jobActor, providers.AuthKeyResult{}), "the trigger refuses the own key")
	own, err := h.svc.KeyLocation(h.ctx, f.own)
	require.NoError(t, err)
	assert.Nil(t, own.RemovedAt)
}

// F-35 per user: sshd asks a program for one user's keys (a Match block); that user's keys are
// refused while other users' keys stay removable.
func TestRequestKeyRemovalRefusesAUserWhoseKeysAreManagedElsewhere(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	_, err := h.svc.Reconcile(h.ctx, f.target.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "deploy@laptop"),
		dk("deploy", deployFile, 2, "SHA256:ca00000000000000000000000000000000000000000", "", providers.FlagCertAuthority),
		dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
		dk("root", rootFile, 2, "SHA256:root200000000000000000000000000000000000000", "root@backup"),
	}, Warnings: []providers.Warning{{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "deploy"}}},
		SSHD: sshdRead, ReadFiles: []string{deployFile, rootFile}})
	require.NoError(t, err)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrKeysManagedElsewhere)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.operator, f.root, false)
	require.NoError(t, err, "root has another key in the file, and its keys are not managed elsewhere")
	d := h.auditDetails("sshkey.remove.denied")
	require.Len(t, d, 1)
	assert.Equal(t, "keys_managed_elsewhere", d[0]["reason"])
}

// F-36 during a rotation overlap: a key recorded as a platform key is protected like the current one.
func TestProtectedFingerprintsIncludeEveryPlatformKey(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	pk, err := h.svc.PlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE ssh_keys SET is_platform_key = true WHERE fingerprint_sha256 = 'SHA256:dep0000000000000000000000000000000000000000'")
	require.NoError(t, err)
	fps, err := h.svc.ProtectedFingerprints(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{pk.Fingerprint, "SHA256:dep0000000000000000000000000000000000000000"}, fps)

	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrOwnKeyProtected)
	jobActor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: uuid.NewString()}
	require.ErrorIs(t, h.svc.MarkKeyRemoved(h.ctx, f.deploy, jobActor, providers.AuthKeyResult{}), inventory.ErrOwnKeyProtected)
	require.ErrorIs(t, h.svc.MarkKeyRemoved(h.ctx, f.own, jobActor, providers.AuthKeyResult{}), inventory.ErrOwnKeyProtected)

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE ssh_keys SET retired_at = now() WHERE fingerprint_sha256 = 'SHA256:dep0000000000000000000000000000000000000000'")
	require.NoError(t, err)
	fps, err = h.svc.ProtectedFingerprints(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{pk.Fingerprint}, fps, "a retired key is no longer protected")
	assert.Zero(t, h.audits("sshkey.removed"))
}

func TestRemovalBookkeepingOfUnknownLocations(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	jobActor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: uuid.NewString()}
	require.ErrorIs(t, h.svc.MarkKeyRemoved(h.ctx, uuid.New(), jobActor, providers.AuthKeyResult{}), inventory.ErrNotFound)
	require.ErrorIs(t, h.svc.RecordRemovalFailure(h.ctx, uuid.New(), jobActor, "ssh.file_changed"), inventory.ErrNotFound)
	require.NoError(t, h.svc.RecordRemovalFailure(h.ctx, f.deploy, jobActor, "Free text from a server"))
	d := h.auditDetails("sshkey.remove_failed")
	require.Len(t, d, 1)
	assert.Equal(t, "internal.unexpected", d[0]["reason"], "only stable reasons are stored")
}

// When the last scan could not read sshd's settings, globally or for the user (a Match block),
// the files Alice sees may not be the ones sshd uses: removals are refused and audited.
func TestRequestKeyRemovalRefusesWhenSSHDWasNotRead(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	scan := func(sshd providers.SSHDSummary, warnings ...providers.Warning) {
		t.Helper()
		_, err := h.svc.Reconcile(h.ctx, f.target.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
			dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "deploy@laptop"),
			dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
			dk("root", rootFile, 2, "SHA256:root200000000000000000000000000000000000000", "root@backup"),
		}, SSHD: sshd, Warnings: warnings, ReadFiles: []string{deployFile, rootFile}})
		require.NoError(t, err)
	}
	scan(providers.SSHDSummary{AuthorizedKeysCommand: "none"}, providers.Warning{Code: "sshd_unreadable", Params: map[string]string{}})
	_, err := h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrSSHDUnreadable)

	scan(providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none"},
		providers.Warning{Code: "sshd_unreadable", Params: map[string]string{"user": "deploy"}})
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.deploy, false)
	require.ErrorIs(t, err, inventory.ErrSSHDUnreadable)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, f.root, false)
	require.NoError(t, err, "another user's settings were read")

	reasons := []string{}
	for _, d := range h.auditDetails("sshkey.remove.denied") {
		reasons = append(reasons, d["reason"])
	}
	assert.Equal(t, []string{"sshd_unreadable", "sshd_unreadable"}, reasons)
}
