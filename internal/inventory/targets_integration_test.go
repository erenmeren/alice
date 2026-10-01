//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

func TestCreateTargetStoresNormalizedTargetAndQueuesTest(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "ada@example.com")
	tg, jobID, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: " web-01 ", Type: "linux", Host: "WEB-01.Example.com."})
	require.NoError(t, err)
	assert.NotZero(t, jobID)
	assert.Equal(t, "web-01", tg.Name)
	assert.Equal(t, "web-01.example.com", tg.Host)
	assert.Equal(t, 22, tg.Port)
	assert.Equal(t, "alice-svc", tg.Username)
	assert.Equal(t, inventory.StatusPendingHostKey, tg.Status)
	assert.Equal(t, 24*time.Hour, tg.DiscoveryInterval)
	assert.Equal(t, []string{"authorized_keys", "discover_ssh_keys", "test_connection"}, tg.Capabilities)
	assert.Equal(t, 1, tg.Version)

	reqs := h.jobs.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobTestConnection, TargetID: tg.ID, Payload: map[string]string{},
		Kind: "user", CreatedBy: admin.UserID, CreatedByRole: "admin", DedupeKey: "target.test_connection:" + tg.ID.String()}, reqs[0])
	assert.Equal(t, []map[string]string{{"name": "web-01", "host": "web-01.example.com", "port": "22", "username": "alice-svc", "type": "linux"}},
		h.auditDetails("target.created"))

	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, tg, got)
	list, err := h.svc.ListTargets(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, []inventory.Target{tg}, list)
}

func TestCreateTargetRejectsInvalidInputWithoutAnyRow(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web", Type: "linux", Host: "169.254.169.254"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, inventory.CodeHostNotAllowed, verrs[0].Code)
	assert.Equal(t, 0, h.count("SELECT count(*) FROM targets"))
	assert.Empty(t, h.jobs.requests())
}

// Review Focus 2: WEB-01 and web-01 are the same server.
func TestDuplicateTargetIsCaseInsensitive(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.add(admin, "Web-01", "web-01.example.com")
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "WEB-01", Type: "linux", Host: "other.example.com"})
	require.ErrorIs(t, err, inventory.ErrDuplicateTarget, "names are unique without regard to case")
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "second", Type: "linux", Host: "WEB-01.EXAMPLE.COM"})
	require.ErrorIs(t, err, inventory.ErrDuplicateTarget, "the same host and port is the same server")
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "second", Type: "linux", Host: "web-01.example.com", Port: 2222})
	require.NoError(t, err, "another port is another server")
	assert.Equal(t, 2, h.count("SELECT count(*) FROM targets"))
}

func TestUpdateTargetNeedsTheCurrentVersion(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	name, hours := "web-01 (Ankara)", 6
	updated, err := h.svc.UpdateTarget(h.ctx, admin, tg.ID, tg.Version, inventory.TargetPatch{Name: &name, DiscoveryIntervalHours: &hours})
	require.NoError(t, err)
	assert.Equal(t, name, updated.Name)
	assert.Equal(t, 6*time.Hour, updated.DiscoveryInterval)
	assert.Equal(t, tg.Version+1, updated.Version)
	assert.Equal(t, []map[string]string{{"fields": "name,discovery_interval", "name": name}}, h.auditDetails("target.updated"))

	_, err = h.svc.UpdateTarget(h.ctx, admin, tg.ID, tg.Version, inventory.TargetPatch{Name: &name})
	require.ErrorIs(t, err, inventory.ErrVersionMismatch, "a stale version is refused")
	bad := 721
	_, err = h.svc.UpdateTarget(h.ctx, admin, tg.ID, updated.Version, inventory.TargetPatch{DiscoveryIntervalHours: &bad})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "discovery_interval_hours", verrs[0].Field)
}

func TestEmptyPatchIsRefusedWithoutAChange(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	_, err := h.svc.UpdateTarget(h.ctx, admin, tg.ID, tg.Version, inventory.TargetPatch{})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, validate.Required, verrs[0].Code)
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, tg.Version, got.Version, "nothing changed")
	assert.Equal(t, 0, h.audits("target.updated"))
}

func TestDeleteTargetIsSoftAndHidesIt(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	_, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.ErrorIs(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID), inventory.ErrNotFound)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NOT NULL"), "the row stays for history")
	assert.Equal(t, 1, h.audits("target.deleted"))
	_, err = h.svc.RequestTest(h.ctx, admin, tg.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestRequestDiscoveryNeedsAConfirmedKey(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	_, err := h.svc.RequestDiscovery(h.ctx, admin, tg.ID)
	require.ErrorIs(t, err, inventory.ErrHostKeyUnconfirmed)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'host_key_changed' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	_, err = h.svc.RequestDiscovery(h.ctx, admin, tg.ID)
	require.ErrorIs(t, err, inventory.ErrHostKeyChanged)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	id, err := h.svc.RequestDiscovery(h.ctx, admin, tg.ID)
	require.NoError(t, err)
	assert.NotZero(t, id)
	last := h.jobs.requests()[len(h.jobs.requests())-1]
	assert.Equal(t, inventory.JobDiscover, last.Type)
	assert.Equal(t, "target.discover:"+tg.ID.String()+":manual", last.DedupeKey)

	testID, err := h.svc.RequestTest(h.ctx, admin, tg.ID)
	require.NoError(t, err)
	assert.NotZero(t, testID)
	assert.Equal(t, inventory.JobTestConnection, h.jobs.requests()[len(h.jobs.requests())-1].Type)
}
