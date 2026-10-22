//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
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

// forgettingProvider records the targets whose connections inventory asks it to forget.
type forgettingProvider struct {
	*fake.Provider
	forgotten []uuid.UUID
}

func (p *forgettingProvider) ForgetTarget(id uuid.UUID) { p.forgotten = append(p.forgotten, id) }

// A-16: deleting a target makes its provider forget the target's pooled connections, so the
// documented removal procedure does not trip over a live session.
func TestDeleteTargetForgetsItsConnections(t *testing.T) {
	p := &forgettingProvider{Provider: fake.New(providers.KindLinuxSSH)}
	h := newHarness(t, func(c *inventory.Config) {
		reg := providers.NewRegistry()
		reg.Register(p)
		reg.Freeze()
		c.Registry = reg
	})
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	assert.Empty(t, p.forgotten)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	assert.Equal(t, []uuid.UUID{tg.ID}, p.forgotten)
	require.ErrorIs(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID), inventory.ErrNotFound)
	assert.Len(t, p.forgotten, 1, "nothing to forget for a target that was not deleted")
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

// An Nginx server is a target like a Linux server: same validation, license slot, host-key flow;
// its capabilities are the nginx provider's, and a connection test keeps what it learned of Nginx.
func TestNginxTargets(t *testing.T) {
	h := newHarness(t, withNginxProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg, jobID, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-nginx", Type: inventory.TypeNginx, Host: "10.0.0.9"})
	require.NoError(t, err)
	assert.NotZero(t, jobID)
	assert.Equal(t, "nginx", tg.Type)
	assert.Equal(t, inventory.StatusPendingHostKey, tg.Status)
	assert.Contains(t, tg.Capabilities, "discover_certificates")
	assert.Equal(t, []map[string]string{{"name": "web-nginx", "host": "10.0.0.9", "port": "22", "username": "alice-svc", "type": "nginx"}},
		h.auditDetails("target.created"))

	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "x", Type: "windows", Host: "10.0.0.10"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "type", verrs[0].Field)
	assert.Equal(t, map[string]string{"values": "linux, nginx, apache, haproxy, windows"}, verrs[0].Params)
	// The address rules are the same (SEC-065), and so is the endpoint uniqueness within the type.
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "meta", Type: inventory.TypeNginx, Host: "169.254.169.254"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, inventory.CodeHostNotAllowed, verrs[0].Code)
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "again", Type: inventory.TypeNginx, Host: "10.0.0.9"})
	require.ErrorIs(t, err, inventory.ErrDuplicateTarget)
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "same-host-linux", Type: inventory.TypeLinux, Host: "10.0.0.9"})
	require.NoError(t, err, "a Linux target on the same address is another target type")

	// Host-key flow: a confirmation, then the connection test stores what it found of Nginx.
	k := h.pinnedKey(tg.ID)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: k,
		WebServer: &providers.WebServerFacts{Found: true, ConfigValid: true}}))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.StatusOK, got.Status)
	require.NotNil(t, got.Facts.WebServer)
	assert.True(t, got.Facts.WebServer.ConfigValid)

	// A discovery learns the version; a later test (which knows no version) keeps it, a report
	// without Nginx facts keeps them all.
	_, err = h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: &providers.WebServerFacts{Found: true, ConfigValid: true,
		Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf"}})
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: k,
		WebServer: &providers.WebServerFacts{Found: true, ConfigValid: false, ConfigError: providers.ConfigErrSyntax}}))
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, &providers.WebServerFacts{Found: true, ConfigValid: false, ConfigError: providers.ConfigErrSyntax, Version: "1.22.1",
		ConfPath: "/etc/nginx/nginx.conf"}, got.Facts.WebServer)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: k}))
	got, err = h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Facts.WebServer)
	assert.Equal(t, providers.ConfigErrSyntax, got.Facts.WebServer.ConfigError)

	// A target of the nginx type without a registered nginx provider is refused like an unknown type.
	plain := newHarness(t)
	_, _, err = plain.svc.CreateTarget(plain.ctx, plain.user("bo", rbac.Admin, ""), inventory.NewTarget{Name: "n", Type: inventory.TypeNginx, Host: "10.0.0.11"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, map[string]string{"values": "linux, nginx, apache, haproxy, windows"}, verrs[0].Params)
}

// Nginx targets count toward the license limit like every other target (L-74).
func TestNginxTargetsCountTowardTheLicense(t *testing.T) {
	h := newHarness(t, withNginxProvider())
	admin := h.user("ada", rbac.Admin, "")
	for i := range 5 {
		_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "n" + string(rune('a'+i)), Type: inventory.TypeNginx,
			Host: "10.0.1." + string(rune('1'+i))})
		require.NoError(t, err)
	}
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "sixth", Type: inventory.TypeNginx, Host: "10.0.1.9"})
	require.Error(t, err)
	assert.Equal(t, 1, h.audits("target.add.denied_license"))
	assert.Equal(t, 5, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NULL"))
}

// Apache targets count toward the license limit like Nginx ones, and a deleted one does not.
func TestApacheTargetsCountTowardTheLicense(t *testing.T) {
	h := newHarness(t, withApacheProvider())
	admin := h.user("ada", rbac.Admin, "")
	var first uuid.UUID
	for i := range 5 {
		tg, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "a" + string(rune('a'+i)), Type: inventory.TypeApache,
			Host: "10.0.2." + string(rune('1'+i))})
		require.NoError(t, err)
		if i == 0 {
			first = tg.ID
		}
	}
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "sixth", Type: inventory.TypeApache, Host: "10.0.2.9"})
	require.Error(t, err)
	assert.Equal(t, 1, h.audits("target.add.denied_license"))

	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, first))
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "sixth", Type: inventory.TypeApache, Host: "10.0.2.9"})
	require.NoError(t, err, "a deleted target does not count")
	assert.Equal(t, 5, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NULL"))
}

// HAProxy targets count toward the license limit like the others, and a deleted one does not.
func TestHAProxyTargetsCountTowardTheLicense(t *testing.T) {
	h := newHarness(t, withHAProxyProvider())
	admin := h.user("ada", rbac.Admin, "")
	var first uuid.UUID
	for i := range 5 {
		tg, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "h" + string(rune('a'+i)), Type: inventory.TypeHAProxy,
			Host: "10.0.3." + string(rune('1'+i))})
		require.NoError(t, err)
		if i == 0 {
			first = tg.ID
		}
	}
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "sixth", Type: inventory.TypeHAProxy, Host: "10.0.3.9"})
	require.Error(t, err)
	assert.Equal(t, 1, h.audits("target.add.denied_license"))

	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, first))
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "sixth", Type: inventory.TypeHAProxy, Host: "10.0.3.9"})
	require.NoError(t, err, "a deleted target does not count")
	assert.Equal(t, 5, h.count("SELECT count(*) FROM targets WHERE deleted_at IS NULL"))
}
