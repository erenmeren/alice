//go:build integration

package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
)

func TestConnectionStatusTransitions(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	tg := pinned(t, h, admin, ed25519HostKey(t))
	assert.Equal(t, 1, h.audits("target.status_changed"), "checking -> ok")

	// F-34: an authentication failure marks the target and mails the Administrators once.
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.auth_failed"))
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.auth_failed"))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusAuthFailed, got.Status)
	assert.Equal(t, "ssh.auth_failed", got.LastErrorCode)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.auth_failed'"))
	assert.Equal(t, 2, h.audits("target.status_changed"))

	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.timeout"))
	assert.Equal(t, inventory.StatusUnreachable, statusOf(t, h, tg.ID))
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.helper_missing"))
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusUnreachable, got.Status, "other reasons keep the status")
	assert.Equal(t, "ssh.helper_missing", got.LastErrorCode)
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "not a reason\n"))
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, "internal.unexpected", got.LastErrorCode, "only well-formed reasons are stored")

	report := providers.ConnectionReport{HelperVersion: "1.0.0", HelperProtocol: 1,
		OS: providers.OSRelease{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.4 LTS"}}
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, report))
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	assert.Empty(t, got.LastErrorCode)
	assert.Equal(t, report.OS, got.Facts.OS)
	assert.Equal(t, "1.0.0", got.Facts.HelperVersion)
	assert.Equal(t, 1, got.Facts.HelperProtocol)
	require.NotNil(t, got.LastSuccessAt)
	assert.Equal(t, tg.Version, got.Version, "status updates never make an If-Match stale")

	assert.Equal(t, 1, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.auth_failed'"),
		"leaving auth_failed sends nothing")
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.auth_failed"))
	assert.Equal(t, 2, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.auth_failed'"),
		"a new transition sends a new email")
}

func TestUnconfirmedReasonReturnsToPending(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'unreachable' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "target.host_key_unconfirmed"))
	assert.Equal(t, inventory.StatusPendingHostKey, statusOf(t, h, tg.ID))
}

func TestTargetRef(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com", Port: 2222, Username: "deploy"})
	require.NoError(t, err)
	ref, got, err := h.svc.TargetRef(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, tg, got)
	assert.Equal(t, providers.TargetRef{ID: tg.ID, Name: "web-01", Kind: providers.KindLinuxSSH,
		Config: providers.TargetConfig{"host": "web-01.example.com", "port": 2222, "username": "deploy"}}, ref)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	_, _, err = h.svc.TargetRef(h.ctx, tg.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// A connection test that started before the confirmation reports the key as unconfirmed after
// it was pinned: the stale report does not send the target back to pending_host_key (where no
// confirmation could ever leave it again).
func TestStaleUnconfirmedReportAfterPinKeepsStatus(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	k := ed25519HostKey(t)
	tg := h.add(admin, "web-01", "web-01.example.com")
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k, false))
	_, err := h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k.Fingerprint), k.Fingerprint)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "target.host_key_unconfirmed"))
	assert.Equal(t, inventory.StatusChecking, statusOf(t, h, tg.ID))
}

// Review fixes: a failure that has no status of its own does not leave a target in checking; a
// disabled target stays disabled.
func TestCheckingAndDisabledStatuses(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	k := ed25519HostKey(t)
	tg := h.add(admin, "web-01", "web-01.example.com")
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, k, false))
	_, err := h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, k.Fingerprint), k.Fingerprint)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, "ssh.helper_missing"))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusUnreachable, got.Status)
	assert.Equal(t, "ssh.helper_missing", got.LastErrorCode)

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'disabled' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	for _, reason := range []string{"ssh.auth_failed", "ssh.timeout", "target.host_key_unconfirmed"} {
		require.NoError(t, h.svc.RecordConnectionFailure(h.ctx, tg.ID, reason))
		assert.Equal(t, inventory.StatusDisabled, statusOf(t, h, tg.ID), reason)
	}
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: k}))
	assert.Equal(t, inventory.StatusDisabled, statusOf(t, h, tg.ID))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'target.auth_failed'"))

	// A key change still blocks a disabled target (the safe side).
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, ed25519HostKey(t), true))
	assert.Equal(t, inventory.StatusHostKeyChanged, statusOf(t, h, tg.ID))
}
