//go:build integration

package inventory_test

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/testutil/pki"
)

// bindFixture is the deploy fixture (two connected Nginx servers; web-01 holds loc1 and loc5, web-02
// holds loc2, loc3 (api.crt), loc4 (spare.crt, an RSA location) and the unsupported locU) plus a vault
// "prod" holding four reconciled certificates with their details: web-cert and second-cert (ECDSA,
// exportable), monitor-only (not exportable) and rsa-cert (RSA).
type bindFixture struct {
	*deployFixture
	vault                         uuid.UUID
	web, second, monitor, rsaCert uuid.UUID // kv_certificates ids
	webLeaf                       pki.Leaf
	loc3, locRSA, locU            uuid.UUID
}

func newBindFixture(t *testing.T) *bindFixture {
	t.Helper()
	f := newDeployFixture(t)
	h := f.h
	b := &bindFixture{deployFixture: f, loc3: f.loc3onTarget2, locRSA: f.loc4, locU: f.unsupported}
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET key_type = 'rsa' WHERE id = $1", b.locRSA)
	require.NoError(t, err)
	b.vault = h.vault("prod")
	now := h.clock.Now()
	b.webLeaf = b.issue("web.example.test", pki.ECDSA256)
	web := h.kvc("web-cert", b.webLeaf, ver(1), now, true)
	second := h.kvc("second-cert", b.issue("second.example.test", pki.ECDSA256), ver(2), now, true)
	monitor := h.kvc("monitor-only", b.issue("monitor.example.test", pki.ECDSA256), ver(3), now, true)
	monitor.Details.Exportable = ptr(false)
	rsa := h.kvc("rsa-cert", b.issue("rsa.example.test", pki.RSA2048), ver(4), now, true)
	rsa.Details.KeyType, rsa.Details.KeySize = "rsa", 2048
	h.reconcile(b.vault, kvResult(web, second, monitor, rsa))
	b.web, b.second = h.certRow(b.vault, "web-cert").ID, h.certRow(b.vault, "second-cert").ID
	b.monitor, b.rsaCert = h.certRow(b.vault, "monitor-only").ID, h.certRow(b.vault, "rsa-cert").ID
	return b
}

func (b *bindFixture) issue(cn string, kt pki.KeyType) pki.Leaf {
	return b.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}, KeyType: kt}, b.h.clock.Now())
}

func (b *bindFixture) create(a inventory.Actor, cert uuid.UUID, locs ...uuid.UUID) inventory.Binding {
	b.h.t.Helper()
	got, err := b.h.svc.CreateBinding(b.h.ctx, a, inventory.BindingInput{KVCertificateID: cert, LocationIDs: locs})
	require.NoError(b.h.t, err)
	return got
}

// versionID is the stored id of a version of a vault certificate.
func (b *bindFixture) versionID(cert uuid.UUID, version string) uuid.UUID {
	b.h.t.Helper()
	var id uuid.UUID
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT id FROM kv_certificate_versions WHERE kv_certificate_id = $1 AND version = $2",
		cert, version).Scan(&id))
	return id
}

func (b *bindFixture) bindingOf(loc uuid.UUID) *uuid.UUID {
	b.h.t.Helper()
	var id *uuid.UUID
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT binding_id FROM certificate_locations WHERE id = $1", loc).Scan(&id))
	return id
}

func (b *bindFixture) liveBindings() int {
	return b.h.count("SELECT count(*) FROM bindings WHERE deleted_at IS NULL")
}

func locIDs(b inventory.Binding) []uuid.UUID {
	out := []uuid.UUID{}
	for _, l := range b.Locations {
		out = append(out, l.LocationID)
	}
	slices.SortFunc(out, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	return out
}

func sortedIDs(ids ...uuid.UUID) []uuid.UUID {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	return out
}

func TestCreateBindingRules(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	svc := h.svc
	try := func(cert uuid.UUID, locs ...uuid.UUID) error {
		_, err := svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: cert, LocationIDs: locs})
		return err
	}
	denied := func() int { return h.audits("binding.denied") }
	reason := func() string { d := h.auditDetails("binding.denied"); return d[len(d)-1]["reason"] }
	unchanged := func(what string) {
		t.Helper()
		assert.Zero(t, b.liveBindings(), what)
		assert.Zero(t, h.count("SELECT count(*) FROM certificate_locations WHERE binding_id IS NOT NULL"), what)
	}

	// Refusals, each audited binding.denied with its reason, nothing changed.
	err := try(b.monitor, b.loc1)
	assert.ErrorIs(t, err, inventory.ErrNotExportable, "F-45")
	assert.Equal(t, 1, denied())
	assert.Equal(t, "not_exportable", reason())
	unchanged("not exportable")

	err = try(b.rsaCert, b.loc1)
	var km *inventory.KeyTypeMismatchError
	require.ErrorAs(t, err, &km)
	assert.Equal(t, "ecdsa", km.Expected)
	assert.Equal(t, "rsa", km.Actual)
	assert.Equal(t, "key_type_mismatch", reason())
	unchanged("key type")

	err = try(b.web, b.loc1, b.locU)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrLocationUnsupported)
	assert.Equal(t, b.locU, lr.LocationID)
	assert.Equal(t, "location_unsupported", reason())
	unchanged("unsupported location")

	assert.ErrorIs(t, try(uuid.New(), b.loc1), inventory.ErrKVCertificateMissing, "unknown certificate")
	assert.Equal(t, "certificate_missing", reason())
	_, err = h.db.Owner.Exec(ctx, "UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", b.second, h.clock.Now())
	require.NoError(t, err)
	assert.ErrorIs(t, try(b.second, b.loc1), inventory.ErrKVCertificateMissing, "no longer listed by the vault")
	_, err = h.db.Owner.Exec(ctx, "UPDATE kv_certificates SET missing_since = NULL WHERE id = $1", b.second)
	require.NoError(t, err)

	err = try(b.web, uuid.New())
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrNotFound, "an unknown location")
	unchanged("unknown location")

	before := denied()
	var ve validate.Errors
	assert.ErrorAs(t, try(b.web), &ve, "no location")
	many := make([]uuid.UUID, inventory.MaxBindingLocations+1)
	for i := range many {
		many[i] = uuid.New()
	}
	ve = nil
	assert.ErrorAs(t, try(b.web, many...), &ve, "201 locations")
	ve = nil
	assert.ErrorAs(t, try(b.web, b.loc1, b.loc1), &ve, "a duplicate id")
	ve = nil
	assert.ErrorAs(t, try(b.web, uuid.Nil), &ve, "a nil id")
	assert.Equal(t, before, denied(), "a malformed request is not an audited denial")
	unchanged("validation")

	// The success: both locations get the binding.
	got := b.create(b.admin, b.web, b.loc1, b.loc2)
	assert.Equal(t, b.web, got.KVCertificateID)
	assert.Equal(t, b.vault, got.VaultID)
	assert.Equal(t, "web-cert", got.CertificateName)
	assert.Equal(t, "prod", got.VaultName)
	assert.Equal(t, 2, got.LocationCount)
	assert.Equal(t, 1, got.Version)
	assert.False(t, got.AutoDeploy)
	assert.Equal(t, sortedIDs(b.loc1, b.loc2), locIDs(got))
	for _, l := range got.Locations {
		assert.Equal(t, inventory.BindingLocationNotDeployed, l.State)
		assert.NotEmpty(t, l.TargetName)
		assert.NotEmpty(t, l.CertPath)
	}
	require.NotNil(t, b.bindingOf(b.loc1))
	assert.Equal(t, got.ID, *b.bindingOf(b.loc1))
	assert.Equal(t, got.ID, *b.bindingOf(b.loc2))
	assert.Nil(t, b.bindingOf(b.loc5))
	var target uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT kv_target_id FROM bindings WHERE id = $1", got.ID).Scan(&target))
	assert.Equal(t, b.vault, target, "kv_target_id comes from the certificate's own row")
	ev := h.auditDetails("binding.created")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"binding_id": got.ID.String(), "kv_certificate_id": b.web.String(), "certificate_name": "web-cert",
		"vault_url": "https://prod.vault.azure.net", "location_count": "2"}, ev[0])

	// A second binding of the certificate; a website of another binding.
	err = try(b.web, b.loc5)
	assert.ErrorIs(t, err, inventory.ErrBindingExists)
	assert.Equal(t, "binding_exists", reason())
	err = try(b.second, b.loc5, b.loc1)
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrLocationBound)
	assert.Equal(t, b.loc1, lr.LocationID, "names the connected website")
	assert.Equal(t, "location_bound", reason())
	assert.Nil(t, b.bindingOf(b.loc5), "nothing of the refused request stays")
	assert.Equal(t, 1, b.liveBindings())

	// A deleted server's website; a server that is unreachable can still be connected (readiness is
	// checked by every deployment).
	b.setTargetStatus(b.target1, "unreachable")
	other := b.create(b.admin, b.second, b.loc5)
	assert.Equal(t, 1, other.LocationCount)
	require.NoError(t, svc.DeleteTarget(ctx, b.admin, b.target2))
	_, err = svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: b.rsaCert, LocationIDs: []uuid.UUID{b.locRSA}})
	assert.ErrorIs(t, err, inventory.ErrNotFound, "a deleted server")

	// Lock: refused with the license error and audited.
	h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(ctx))
	require.ErrorIs(t, h.lic.Allow(license.ClassChange), license.ErrLocked)
	assert.ErrorIs(t, try(b.monitor, b.loc3), license.ErrLocked, "R40 row 22")
	assert.Equal(t, "locked", reason())
}

// A certificate Alice has listed but not read yet cannot be bound (the baseline rule), and a version
// is judged from its own row, never from the certificate's current-version pointer.
func TestBindingNeedsDetailsAndJudgesTheVersionRow(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	h.reconcile(b.vault, kvResult(h.kvc("listed-only", b.issue("l.example.test", pki.ECDSA256), "", h.clock.Now(), false)))
	b.exec("UPDATE kv_certificates SET missing_since = NULL") // the listing above named one certificate only
	_, err := h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: h.certRow(b.vault, "listed-only").ID, LocationIDs: []uuid.UUID{b.loc1}})
	assert.ErrorIs(t, err, inventory.ErrVersionNotDeployable)
	d := h.auditDetails("binding.denied")
	assert.Equal(t, "no_current_version", d[len(d)-1]["reason"])

	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	h.clock.Advance(time.Minute)
	h.reconcile(b.vault, kvResult(h.kvc("web-cert", b.issue("web.example.test", pki.ECDSA256), ver(11), h.clock.Now(), true, ver(1))))
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE kv_certificate_id = $1 AND version = $2", b.web, ver(11))
	// The pointer is at the held ver(11); ver(1) is a history row that is fine.
	reqs, err := h.svc.RequestKVDeployment(ctx, b.operator, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1})
	require.NoError(t, err)
	b.finishQueued(reqs...)
	_, err = h.svc.RequestKVDeployment(ctx, b.operator, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(b.web, ver(11))})
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin)
	// Move the pointer to a history row: the held row is still held.
	b.exec("UPDATE kv_certificates SET current_version = $2 WHERE id = $1", b.web, ver(1))
	_, err = h.svc.RequestKVDeployment(ctx, b.operator, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(b.web, ver(11))})
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin)
}

func TestCreateBindingNeedsAKnownVault(t *testing.T) {
	b := newBindFixture(t)
	require.NoError(t, b.h.svc.DeleteVault(b.h.ctx, b.admin, b.vault, false))
	_, err := b.h.svc.CreateBinding(b.h.ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc1}})
	assert.ErrorIs(t, err, inventory.ErrKVCertificateMissing, "a deleted vault's certificate")
}

func TestUpdateDeleteAndAutoDeploy(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	svc := h.svc
	bind := b.create(b.admin, b.web, b.loc1, b.loc2)
	other := b.create(b.admin, b.second, b.loc5)

	// UpdateBindingLocations with If-Match.
	got, err := svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 1, []uuid.UUID{b.loc2, b.loc3})
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, sortedIDs(b.loc2, b.loc3), locIDs(got))
	assert.Nil(t, b.bindingOf(b.loc1), "released")
	assert.Equal(t, bind.ID, *b.bindingOf(b.loc3))
	ev := h.auditDetails("binding.locations_changed")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"binding_id": bind.ID.String(), "kv_certificate_id": b.web.String(), "certificate_name": "web-cert",
		"added_count": "1", "removed_count": "1", "location_count": "2"}, ev[0])
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 1, []uuid.UUID{b.loc2})
	assert.ErrorIs(t, err, inventory.ErrVersionMismatch, "a stale version")
	assert.Equal(t, 2, mustBinding(t, b, bind.ID).Version)
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 2, []uuid.UUID{b.loc2, b.loc5})
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrLocationBound, "another binding's website")
	assert.Equal(t, b.loc5, lr.LocationID)
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 2, []uuid.UUID{b.loc2, b.locU})
	assert.ErrorIs(t, err, inventory.ErrLocationUnsupported)
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 2, []uuid.UUID{b.loc2, b.locRSA})
	var km *inventory.KeyTypeMismatchError
	assert.ErrorAs(t, err, &km)
	var ve validate.Errors
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 2, nil)
	assert.ErrorAs(t, err, &ve, "a binding keeps at least one website; DeleteBinding removes it")
	same, err := svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 2, []uuid.UUID{b.loc3, b.loc2})
	require.NoError(t, err)
	assert.Equal(t, 2, same.Version, "the same set changes nothing")
	assert.Equal(t, 1, h.audits("binding.locations_changed"))
	_, err = svc.UpdateBindingLocations(ctx, b.admin, uuid.New(), 1, []uuid.UUID{b.loc1})
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// Automatic deployment: Administrator only; the switch is audited, its time recorded, a stopped
	// wave forgotten.
	_, err = h.db.Owner.Exec(ctx, "UPDATE bindings SET stopped_version = $2 WHERE id = $1", bind.ID, ver(9))
	require.NoError(t, err)
	_, err = svc.SetAutoDeploy(ctx, b.operator, bind.ID, 2, true)
	assert.ErrorIs(t, err, inventory.ErrAdminRequired, "no weaker path (S6)")
	assert.False(t, mustBinding(t, b, bind.ID).AutoDeploy)
	d := h.auditDetails("binding.denied")
	assert.Equal(t, "admin_required", d[len(d)-1]["reason"])
	_, err = svc.SetAutoDeploy(ctx, b.admin, bind.ID, 1, true)
	assert.ErrorIs(t, err, inventory.ErrVersionMismatch)
	h.clock.Advance(time.Minute)
	on, err := svc.SetAutoDeploy(ctx, b.admin, bind.ID, 2, true)
	require.NoError(t, err)
	assert.True(t, on.AutoDeploy)
	require.NotNil(t, on.AutoSince)
	assert.True(t, on.AutoSince.Equal(h.clock.Now()))
	assert.Empty(t, on.StoppedVersion, "stopped_version cleared")
	assert.Equal(t, 3, on.Version)
	ev = h.auditDetails("binding.auto_deploy_changed")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"binding_id": bind.ID.String(), "kv_certificate_id": b.web.String(), "certificate_name": "web-cert",
		"enabled": "true"}, ev[0])
	again, err := svc.SetAutoDeploy(ctx, b.admin, bind.ID, 3, true)
	require.NoError(t, err)
	assert.Equal(t, 3, again.Version, "no change, no audit row")
	assert.Equal(t, 1, h.audits("binding.auto_deploy_changed"))

	// An Operator may not add websites to a binding that deploys automatically, but may release some.
	_, err = svc.UpdateBindingLocations(ctx, b.operator, bind.ID, 3, []uuid.UUID{b.loc2, b.loc3, b.loc1})
	assert.ErrorIs(t, err, inventory.ErrAdminRequired)
	assert.Nil(t, b.bindingOf(b.loc1))
	shrunk, err := svc.UpdateBindingLocations(ctx, b.operator, bind.ID, 3, []uuid.UUID{b.loc2})
	require.NoError(t, err)
	assert.Equal(t, 1, shrunk.LocationCount)
	grown, err := svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 4, []uuid.UUID{b.loc2, b.loc3})
	require.NoError(t, err)
	assert.Equal(t, 2, grown.LocationCount)

	off, err := svc.SetAutoDeploy(ctx, b.admin, bind.ID, 5, false)
	require.NoError(t, err)
	assert.False(t, off.AutoDeploy)
	assert.Nil(t, off.AutoSince)
	assert.Equal(t, "false", h.auditDetails("binding.auto_deploy_changed")[1]["enabled"])
	assert.Zero(t, h.count("SELECT count(*) FROM bindings WHERE id = $1 AND (auto_deploy <> (auto_since IS NOT NULL))", bind.ID))

	// Turning it on while the current version is held does not release the version.
	_, err = h.db.Owner.Exec(ctx, "UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE kv_certificate_id = $1", b.web)
	require.NoError(t, err)
	_, err = svc.SetAutoDeploy(ctx, b.admin, bind.ID, 6, true)
	require.NoError(t, err)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions WHERE kv_certificate_id = $1 AND held AND held_reason = 'license'", b.web))

	// A certificate whose key can no longer be read from the vault cannot start deploying.
	_, err = h.db.Owner.Exec(ctx, "UPDATE kv_certificates SET exportable = false WHERE id = $1", b.second)
	require.NoError(t, err)
	_, err = svc.SetAutoDeploy(ctx, b.admin, other.ID, 1, true)
	assert.ErrorIs(t, err, inventory.ErrNotExportable)

	// In lock automatic deployment cannot start, but can be stopped, and a binding can be removed.
	h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(ctx))
	require.ErrorIs(t, h.lic.Allow(license.ClassChange), license.ErrLocked)
	_, err = svc.SetAutoDeploy(ctx, b.admin, other.ID, 1, true)
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 7, []uuid.UUID{b.loc2})
	assert.ErrorIs(t, err, license.ErrLocked)
	_, err = svc.SetAutoDeploy(ctx, b.admin, bind.ID, 7, false)
	require.NoError(t, err, "switching off is a safety action, allowed in lock")
	require.NoError(t, svc.DeleteBinding(ctx, b.admin, other.ID), "so is removing a binding")
	assert.Nil(t, b.bindingOf(b.loc5))
}

func mustBinding(t *testing.T, b *bindFixture, id uuid.UUID) inventory.Binding {
	t.Helper()
	got, err := b.h.svc.Binding(b.h.ctx, id)
	require.NoError(t, err)
	return got
}

func TestDeleteBindingKeepsWhatIsInFlight(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2)
	reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(b.web, ver(1))})
	require.NoError(t, err)
	require.Len(t, reqs, 2)

	require.NoError(t, h.svc.DeleteBinding(ctx, b.admin, bind.ID))
	var deleted *time.Time
	var version int
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT deleted_at, version FROM bindings WHERE id = $1", bind.ID).Scan(&deleted, &version))
	require.NotNil(t, deleted)
	assert.True(t, deleted.Equal(h.clock.Now()))
	assert.Equal(t, 2, version)
	assert.Nil(t, b.bindingOf(b.loc1))
	assert.Nil(t, b.bindingOf(b.loc2))
	for _, r := range reqs {
		d := b.get(r.ID)
		assert.Equal(t, inventory.DeployStateQueued, d.State, "an unfinished deployment of the binding is untouched")
		require.NotNil(t, d.BindingID)
		assert.Equal(t, bind.ID, *d.BindingID, "it still names its (deleted) binding")
	}
	ev := h.auditDetails("binding.deleted")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"binding_id": bind.ID.String(), "kv_certificate_id": b.web.String(), "certificate_name": "web-cert",
		"vault_url": "https://prod.vault.azure.net", "reason": "removed", "location_count": "2"}, ev[0])
	assert.ErrorIs(t, h.svc.DeleteBinding(ctx, b.admin, bind.ID), inventory.ErrNotFound)
	_, err = h.svc.Binding(ctx, bind.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// The deployment engine's view of the in-flight deployment: its material is still readable.
	m, err := h.svc.DeploymentMaterial(ctx, reqs[0].ID, false)
	require.NoError(t, err)
	require.NotNil(t, m.KV)
	assert.Equal(t, "web-cert", m.KV.Name)

	// The certificate and the websites can be connected again; the unfinished deployment of loc1 still
	// blocks a new one there (F-15).
	again := b.create(b.admin, b.web, b.loc1, b.loc2)
	assert.NotEqual(t, bind.ID, again.ID)
	_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: again.ID, VersionID: b.versionID(b.web, ver(1))})
	assert.ErrorIs(t, err, inventory.ErrDeploymentInProgress)
}

func TestBindingStatePerLocation(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2, b.loc3, b.loc5)
	state := func() map[uuid.UUID]inventory.BindingLocation {
		t.Helper()
		out := map[uuid.UUID]inventory.BindingLocation{}
		for _, l := range mustBinding(t, b, bind.ID).Locations {
			out[l.LocationID] = l
		}
		return out
	}
	for _, l := range state() {
		assert.Equal(t, inventory.BindingLocationNotDeployed, l.State)
		assert.Empty(t, l.Version)
		assert.Nil(t, l.DeploymentID)
	}
	v1 := b.versionID(b.web, ver(1))

	// pending: an unfinished Key Vault deployment.
	reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
		LocationIDs: []uuid.UUID{b.loc1, b.loc2, b.loc3, b.loc5}})
	require.NoError(t, err)
	dep := map[uuid.UUID]uuid.UUID{}
	for _, r := range reqs {
		dep[r.LocationID] = r.ID
	}
	for id, l := range state() {
		assert.Equal(t, inventory.BindingLocationPending, l.State)
		require.NotNil(t, l.DeploymentID)
		assert.Equal(t, dep[id], *l.DeploymentID)
	}

	// deployed <version>: a succeeded one; failed: the last one failed; the rest stay pending.
	finish := func(loc uuid.UUID, fin inventory.DeploymentFinish) {
		t.Helper()
		id := dep[loc]
		_, err := h.svc.BeginDeployment(ctx, id)
		require.NoError(t, err)
		m, err := h.svc.DeploymentMaterial(ctx, id, false)
		require.NoError(t, err)
		require.NoError(t, h.svc.StartDeployment(ctx, id, m.SendValues("", 0)))
		require.NoError(t, h.svc.FinishDeployment(ctx, id, fin))
	}
	finish(b.loc1, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote"})
	finish(b.loc2, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.interrupted", NothingWritten: true})
	st := state()
	assert.Equal(t, inventory.BindingLocationDeployed, st[b.loc1].State)
	assert.Equal(t, ver(1), st[b.loc1].Version)
	assert.Equal(t, inventory.BindingLocationFailed, st[b.loc2].State)
	assert.Equal(t, inventory.BindingLocationPending, st[b.loc3].State)

	// deployed also when the location's served leaf equals a version's leaf (discovered, not deployed
	// by Alice): the version's certificate row is the one the location holds.
	_, err = h.db.Owner.Exec(ctx, `UPDATE certificate_locations SET certificate_id = (SELECT certificate_id FROM kv_certificate_versions WHERE id = $2)
WHERE id = $1`, b.loc5, v1)
	require.NoError(t, err)
	finish(b.loc3, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.interrupted", NothingWritten: true})
	st = state()
	assert.Equal(t, inventory.BindingLocationFailed, st[b.loc3].State)
	// loc5 is still pending (its deployment is unfinished); finish it as failed: the served leaf wins.
	finish(b.loc5, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.interrupted", NothingWritten: true})
	st = state()
	assert.Equal(t, inventory.BindingLocationDeployed, st[b.loc5].State, "the website serves the version's leaf")
	assert.Equal(t, ver(1), st[b.loc5].Version)

	// stopped: the wave of the current version stopped and the website does not serve it.
	_, err = h.db.Owner.Exec(ctx, "UPDATE bindings SET stopped_version = $2 WHERE id = $1", bind.ID, ver(1))
	require.NoError(t, err)
	st = state()
	assert.Equal(t, inventory.BindingLocationStopped, st[b.loc2].State)
	assert.Equal(t, inventory.BindingLocationStopped, st[b.loc3].State)
	assert.Equal(t, inventory.BindingLocationDeployed, st[b.loc1].State, "deployed wins over stopped")

	// A newer current version: loc1 now serves an older one (still "deployed", with its version).
	l2 := b.issue("web.example.test", pki.ECDSA256)
	h.clock.Advance(time.Hour)
	h.reconcile(b.vault, kvResult(h.kvc("web-cert", l2, ver(11), h.clock.Now(), true, ver(1))))
	st = state()
	assert.Equal(t, inventory.BindingLocationDeployed, st[b.loc1].State)
	assert.Equal(t, ver(1), st[b.loc1].Version)
	assert.Equal(t, inventory.BindingLocationFailed, st[b.loc2].State, "the stop named the old version only")
}

func TestListBindings(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	one := b.create(b.admin, b.web, b.loc1)
	h.clock.Advance(time.Minute)
	two := b.create(b.admin, b.second, b.loc2, b.loc3)
	other := h.vault("other")
	h.reconcile(other, kvResult(h.kvc("o-cert", b.issue("o.example.test", pki.ECDSA256), ver(21), h.clock.Now(), true)))
	three := b.create(b.admin, h.certRow(other, "o-cert").ID, b.loc5)

	page, err := h.svc.ListBindings(ctx, inventory.BindingFilter{})
	require.NoError(t, err)
	ids := []uuid.UUID{}
	for _, it := range page.Items {
		ids = append(ids, it.ID)
		assert.NotEmpty(t, it.CertificateName)
		assert.NotEmpty(t, it.VaultName)
		assert.Empty(t, it.Locations, "a list carries counts, Binding carries the websites")
	}
	assert.Equal(t, []uuid.UUID{three.ID, two.ID, one.ID}, ids, "newest first")
	assert.Equal(t, 2, page.Items[1].LocationCount)

	page, err = h.svc.ListBindings(ctx, inventory.BindingFilter{VaultID: b.vault})
	require.NoError(t, err)
	require.Len(t, page.Items, 2)
	page, err = h.svc.ListBindings(ctx, inventory.BindingFilter{KVCertificateID: b.second})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, two.ID, page.Items[0].ID)

	first, err := h.svc.ListBindings(ctx, inventory.BindingFilter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, first.Items, 2)
	require.NotEmpty(t, first.NextCursor)
	rest, err := h.svc.ListBindings(ctx, inventory.BindingFilter{Limit: 2, Cursor: first.NextCursor})
	require.NoError(t, err)
	require.Len(t, rest.Items, 1)
	assert.Equal(t, one.ID, rest.Items[0].ID)
	assert.Empty(t, rest.NextCursor)

	var ve validate.Errors
	_, err = h.svc.ListBindings(ctx, inventory.BindingFilter{Limit: 201})
	assert.ErrorAs(t, err, &ve)
	ve = nil
	_, err = h.svc.ListBindings(ctx, inventory.BindingFilter{Cursor: "!"})
	assert.ErrorAs(t, err, &ve)

	require.NoError(t, h.svc.DeleteBinding(ctx, b.admin, two.ID))
	page, err = h.svc.ListBindings(ctx, inventory.BindingFilter{})
	require.NoError(t, err)
	assert.Len(t, page.Items, 2, "a removed binding is not listed")
}

func TestListDeployableLocations(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	list := func(f inventory.LocationFilter) []inventory.DeployableLocation {
		t.Helper()
		page, err := h.svc.ListDeployableLocations(ctx, f)
		require.NoError(t, err)
		return page.Items
	}
	idsOf := func(items []inventory.DeployableLocation) []uuid.UUID {
		out := []uuid.UUID{}
		for _, it := range items {
			out = append(out, it.ID)
		}
		return sortedIDs(out...)
	}
	all := sortedIDs(b.loc1, b.loc5, b.loc2, b.loc3, b.locRSA)

	// Across both servers: supported, present, deployable paths only (locU is excluded).
	got := list(inventory.LocationFilter{})
	assert.Equal(t, all, idsOf(got))
	for i, it := range got {
		assert.NotEmpty(t, it.TargetName)
		assert.NotEmpty(t, it.CertPath)
		assert.NotEmpty(t, it.KeyPath)
		assert.Nil(t, it.BindingID)
		if i > 0 {
			prev := got[i-1]
			assert.LessOrEqual(t, prev.TargetName+"\x00"+prev.CertPath, it.TargetName+"\x00"+it.CertPath, "ordered by server, then path")
		}
	}
	_, err := h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET missing_since = $2 WHERE id = $1", b.loc5, h.clock.Now())
	require.NoError(t, err)
	assert.NotContains(t, idsOf(list(inventory.LocationFilter{})), b.loc5, "missing at the last scan")
	_, err = h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET missing_since = NULL WHERE id = $1", b.loc5)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET key_path = '/etc/nginx/ssl/sp ace.key' WHERE id = $1", b.loc3)
	require.NoError(t, err)
	assert.NotContains(t, idsOf(list(inventory.LocationFilter{})), b.loc3, "a path the helper cannot take")
	_, err = h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET key_path = '/etc/nginx/ssl/api.key' WHERE id = $1", b.loc3)
	require.NoError(t, err)

	// key_type filter, unbound.
	assert.Equal(t, []uuid.UUID{b.locRSA}, idsOf(list(inventory.LocationFilter{KeyType: "rsa"})))
	assert.Equal(t, sortedIDs(b.loc1, b.loc5, b.loc2, b.loc3), idsOf(list(inventory.LocationFilter{KeyType: "ecdsa"})))
	var ve validate.Errors
	_, err = h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{KeyType: "dsa"})
	assert.ErrorAs(t, err, &ve)
	bound := b.create(b.admin, b.web, b.loc1, b.loc2)
	assert.Equal(t, sortedIDs(b.loc5, b.loc3, b.locRSA), idsOf(list(inventory.LocationFilter{Unbound: true})))
	for _, it := range list(inventory.LocationFilter{}) {
		if it.ID == b.loc1 || it.ID == b.loc2 {
			require.NotNil(t, it.BindingID)
			assert.Equal(t, bound.ID, *it.BindingID)
		}
	}

	// q: a server name of the target, the path, a server name of the location; case-insensitive; "%"
	// and "_" match literally.
	assert.Equal(t, sortedIDs(b.loc1, b.loc5), idsOf(list(inventory.LocationFilter{Query: "WEB-01"})))
	assert.Equal(t, []uuid.UUID{b.loc3}, idsOf(list(inventory.LocationFilter{Query: "/api.crt"})))
	_, err = h.db.Owner.Exec(ctx, `UPDATE certificate_locations SET servers = '[{"names":["Shop_%.example.test"],"listens":[],"file":"","line":0}]'
WHERE id = $1`, b.loc5)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{b.loc5}, idsOf(list(inventory.LocationFilter{Query: "shop_%"})))
	assert.Equal(t, []uuid.UUID{b.loc5}, idsOf(list(inventory.LocationFilter{Query: "%"})), "a percent sign is not a wildcard")
	assert.Equal(t, []uuid.UUID{b.loc5}, idsOf(list(inventory.LocationFilter{Query: "_"})), "nor an underscore")
	assert.Empty(t, list(inventory.LocationFilter{Query: "no-such-site"}))
	ve = nil
	_, err = h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{Query: string(make([]byte, 1))})
	assert.ErrorAs(t, err, &ve, "a NUL byte")

	// Paging and limits.
	var seen []uuid.UUID
	cursor := ""
	for range 10 {
		page, err := h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{Limit: 2, Cursor: cursor})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(page.Items), 2)
		for _, it := range page.Items {
			seen = append(seen, it.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	assert.Equal(t, all, sortedIDs(seen...), "every location once")
	assert.Len(t, seen, len(all))
	for _, bad := range []int{-1, 201} {
		ve = nil
		_, err = h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{Limit: bad})
		assert.ErrorAs(t, err, &ve, fmt.Sprint(bad))
	}
	ve = nil
	_, err = h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{Cursor: "garbage!"})
	assert.ErrorAs(t, err, &ve)

	// A deleted server's locations are not offered.
	require.NoError(t, h.svc.DeleteTarget(ctx, b.admin, b.target2))
	assert.Equal(t, sortedIDs(b.loc1, b.loc5), idsOf(list(inventory.LocationFilter{})))
}

func TestBindingRacesAreSerialised(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx

	// Two requests to connect one certificate: one wins.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc1}})
		}()
	}
	// Two certificates asking for one website: one wins.
	for i := 2; i < 4; i++ {
		cert := []uuid.UUID{b.second, b.rsaCert}[i-2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: cert, LocationIDs: []uuid.UUID{b.loc2}})
		}()
	}
	wg.Wait()
	ok := func(a, c int) int {
		n := 0
		for _, err := range errs[a:c] {
			if err == nil {
				n++
			}
		}
		return n
	}
	assert.Equal(t, 1, ok(0, 2), "one binding per certificate: %v", errs[:2])
	for _, err := range errs[:2] {
		if err != nil {
			assert.ErrorIs(t, err, inventory.ErrBindingExists)
		}
	}
	// second-cert (ECDSA) can take loc2; rsa-cert is refused for the key type anyway, so it never wins.
	assert.Equal(t, 1, ok(2, 4), "%v", errs[2:])
	for _, err := range errs[2:] {
		if err != nil {
			assert.True(t, errors.Is(err, inventory.ErrLocationBound) || errors.Is(err, inventory.ErrKeyTypeMismatch), "%v", err)
		}
	}
	assert.Equal(t, 2, b.liveBindings())

	// Deleting a vault with bindings while websites are connected to it: either the binding is created
	// and removed with the vault, or the creation is refused; never a live binding of a deleted vault.
	for i := range 4 {
		vault := h.vault(fmt.Sprintf("race-%d", i))
		h.reconcile(vault, kvResult(h.kvc("r-cert", b.issue("r.example.test", pki.ECDSA256), ver(30+i), h.clock.Now(), true)))
		cert := h.certRow(vault, "r-cert").ID
		loc := []uuid.UUID{b.loc3, b.loc5, b.locRSA, b.loc1}[i]
		if loc == b.locRSA {
			_, err := h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET key_type = 'ecdsa' WHERE id = $1", loc)
			require.NoError(t, err)
		}
		if loc == b.loc1 { // already bound above: free it by removing that binding
			require.NoError(t, h.svc.DeleteBinding(ctx, b.admin, mustBindingOfLocation(t, b, loc)))
		}
		var createErr, deleteErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: cert, LocationIDs: []uuid.UUID{loc}})
		}()
		go func() {
			defer wg.Done()
			deleteErr = h.svc.DeleteVault(ctx, b.admin, vault, true)
		}()
		wg.Wait()
		require.NoError(t, deleteErr)
		if createErr != nil {
			assert.ErrorIs(t, createErr, inventory.ErrKVCertificateMissing)
		}
		assert.Zero(t, h.count("SELECT count(*) FROM bindings WHERE kv_target_id = $1 AND deleted_at IS NULL", vault), "round %d", i)
		assert.Nil(t, b.bindingOf(loc), "round %d: the website is free", i)
	}

	// A binding removed while a deployment of it is being requested: the request succeeds (and the
	// deployments stay, tolerated) or is refused as not found; nothing deadlocks.
	bind := b.create(b.admin, b.web, b.loc5)
	_, err := h.db.Owner.Exec(ctx, "UPDATE certificate_locations SET key_type = 'ecdsa' WHERE id = $1", b.loc5)
	require.NoError(t, err)
	var reqErr, delErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, reqErr = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(b.web, ver(1))})
	}()
	go func() {
		defer wg.Done()
		delErr = h.svc.DeleteBinding(ctx, b.admin, bind.ID)
	}()
	wg.Wait()
	require.NoError(t, delErr)
	if reqErr != nil {
		assert.ErrorIs(t, reqErr, inventory.ErrNotFound)
	}

	// A poll's final transaction and a binding: both complete.
	var pollErr, bindErr error
	h.clock.Advance(time.Minute)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, pollErr = h.svc.ReconcileKV(ctx, b.vault, kvResult(h.kvc("web-cert", b.issue("web.example.test", pki.ECDSA256), ver(12), h.clock.Now(), true, ver(1))))
	}()
	go func() {
		defer wg.Done()
		_, bindErr = h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc5}})
	}()
	wg.Wait()
	require.NoError(t, pollErr)
	require.NoError(t, bindErr)
}

func mustBindingOfLocation(t *testing.T, b *bindFixture, loc uuid.UUID) uuid.UUID {
	t.Helper()
	id := b.bindingOf(loc)
	require.NotNil(t, id)
	return *id
}

func TestReleaseHeldVersion(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	hold := func(reason string) {
		t.Helper()
		_, err := h.db.Owner.Exec(ctx, "UPDATE kv_certificate_versions SET held = $2 <> '', held_reason = $2 WHERE id = $1", v1, reason)
		require.NoError(t, err)
	}
	deploymentsBefore := h.count("SELECT count(*) FROM deployments")

	// Not held: nothing to release.
	_, err := h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrVersionNotHeld)
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: uuid.New()})
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// A held version is released by an Administrator only (S8); the Operator is refused and audited.
	hold("license")
	_, err = h.svc.ReleaseVersion(ctx, b.operator, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions WHERE id = $1 AND held", v1))
	d := h.auditDetails("kv.version.release_denied")
	assert.Equal(t, "held_needs_admin", d[len(d)-1]["reason"])

	// In lock the gate is closed: nothing is released (a version held for the license is not released
	// while the license still refuses changes).
	h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(ctx))
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, license.ErrLocked)
	h.installLicense("LIC-REL", 5, 365)
	require.NoError(t, h.lic.Allow(license.ClassChange))

	got, err := h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	require.NoError(t, err)
	assert.False(t, got.Held)
	assert.Empty(t, got.HeldReason)
	assert.Equal(t, ver(1), got.Version)
	var held bool
	var reason string
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT held, held_reason FROM kv_certificate_versions WHERE id = $1", v1).Scan(&held, &reason))
	assert.False(t, held)
	assert.Empty(t, reason, "held and held_reason are cleared together")
	ev := h.auditDetails("kv.version.released")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"kv_certificate_id": b.web.String(), "certificate_name": "web-cert", "version": ver(1), "reason": "license",
		"held": "false"}, ev[0])
	assert.Equal(t, deploymentsBefore, h.count("SELECT count(*) FROM deployments"), "releasing does not deploy")
	assert.Zero(t, h.count("SELECT count(*) FROM jobs WHERE type = 'certificate.deploy'"))
	_ = bind

	// An incomplete chain: the Administrator's confirmation (F-17) is not relaxed.
	hold("incomplete_chain")
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions WHERE id = $1 AND held_reason = 'incomplete_chain'", v1))
	_, err = h.svc.ReleaseVersion(ctx, b.operator, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1, ConfirmIncompleteChain: true})
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin, "an Operator's confirmation counts for nothing")
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	ev = h.auditDetails("kv.version.released")
	require.Len(t, ev, 2)
	assert.Equal(t, "incomplete_chain", ev[1]["reason"])
	assert.Equal(t, "true", ev[1]["chain_incomplete_acknowledged"], "an acknowledgement, not an approval of a deployment")
	assert.NotContains(t, ev[1], "confirm_incomplete_chain")

	// A deleted vault's version.
	hold("license")
	require.NoError(t, h.svc.DeleteVault(ctx, b.admin, b.vault, true))
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestBindingEdgeCases(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2)

	// Adding a website to the binding of a certificate whose key the vault cannot export is refused.
	b.exec("UPDATE kv_certificates SET exportable = false WHERE id = $1", b.web)
	_, err := h.svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 1, []uuid.UUID{b.loc1, b.loc2, b.loc3})
	assert.ErrorIs(t, err, inventory.ErrNotExportable)
	assert.Nil(t, b.bindingOf(b.loc3))
	d := h.auditDetails("binding.denied")
	assert.Equal(t, "not_exportable", d[len(d)-1]["reason"])
	assert.Equal(t, bind.ID.String(), d[len(d)-1]["binding_id"])
	b.exec("UPDATE kv_certificates SET exportable = true WHERE id = $1", b.web)

	// A deleted server's websites are neither counted nor listed; the next change releases them.
	require.NoError(t, h.svc.DeleteTarget(ctx, b.admin, b.target2))
	got := mustBinding(t, b, bind.ID)
	assert.Equal(t, 1, got.LocationCount)
	assert.Equal(t, []uuid.UUID{b.loc1}, locIDs(got))
	assert.NotNil(t, b.bindingOf(b.loc2), "the mark stays until the binding changes")
	updated, err := h.svc.UpdateBindingLocations(ctx, b.admin, bind.ID, 1, []uuid.UUID{b.loc1, b.loc5})
	require.NoError(t, err)
	assert.Equal(t, 2, updated.LocationCount)
	assert.Nil(t, b.bindingOf(b.loc2), "released with the change")

	// Unknown binding ids.
	_, err = h.svc.SetAutoDeploy(ctx, b.admin, uuid.New(), 1, true)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.ErrorIs(t, h.svc.DeleteBinding(ctx, b.admin, uuid.New()), inventory.ErrNotFound)

	// A binding without a website (not reachable through the API) cannot be deployed to.
	b.exec("UPDATE certificate_locations SET binding_id = NULL WHERE binding_id = $1", bind.ID)
	_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(b.web, ver(1))})
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	d = h.auditDetails("deployment.denied")
	assert.Equal(t, "no_websites", d[len(d)-1]["reason"])
}

// An automatic deployment whose chain turns out incomplete: a lost job claim writes nothing (the
// version is not held by a run that lost its job); a vault deleted meanwhile has nothing to hold.
func TestHeldVersionIsFencedAndTolerantOfADeletedVault(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	leafOnly := string(b.webLeaf.KeyPEM) + string(b.webLeaf.CertPEM)
	auto := func() uuid.UUID {
		t.Helper()
		reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1})
		require.NoError(t, err)
		b.exec("UPDATE deployments SET trigger = 'kv_renewal' WHERE id = $1", reqs[0].ID)
		_, err = h.svc.BeginDeployment(ctx, reqs[0].ID)
		require.NoError(t, err)
		return reqs[0].ID
	}
	held := func() int { return h.count("SELECT count(*) FROM kv_certificate_versions WHERE id = $1 AND held", v1) }
	_, err := h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, bind.Version, true)
	require.NoError(t, err)

	id := auto()
	_, secret := pemSecret(leafOnly)
	claimed := inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	_, err = h.svc.KVDeployMaterial(claimed, id, secret)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Zero(t, held(), "a run that lost its job holds nothing")

	// The vault is deleted while the secret is being judged (after the pre-read check passed).
	restore := inventory.SetKVMaterialHook(func(stage string, _ []byte) {
		if stage == "der" {
			b.exec("UPDATE targets SET deleted_at = now() WHERE id = $1", b.vault)
		}
	})
	defer restore()
	_, secret = pemSecret(leafOnly)
	_, err = h.svc.KVDeployMaterial(ctx, id, secret)
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed, "the deployment still ends with the closed refusal")
	assert.Zero(t, held(), "nothing is held in a deleted vault")
	assert.Zero(t, h.audits("kv.version.held"))
}
