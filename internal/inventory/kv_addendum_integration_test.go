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
)

// B1: the import reads check the vault like every vault-scoped read.
func TestImportReadsCheckTheVault(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	im := f.mustRequest("read-name", false)
	_, err := h.svc.ListImports(ctx, f.target1, 10)
	assert.ErrorIs(t, err, inventory.ErrNotAVault, "a server")
	_, err = h.svc.ListImports(ctx, uuid.New(), 10)
	assert.ErrorIs(t, err, inventory.ErrNotFound, "a random id")
	_, err = h.svc.ListImportsPage(ctx, uuid.New(), inventory.ImportFilter{})
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.Import(ctx, f.target1, im.ID)
	assert.ErrorIs(t, err, inventory.ErrNotAVault)
	require.NoError(t, h.svc.DeleteVault(ctx, f.admin, f.vault, true))
	_, err = h.svc.ListImports(ctx, f.vault, 10)
	assert.ErrorIs(t, err, inventory.ErrNotFound, "a deleted vault's history")
	_, err = h.svc.Import(ctx, f.vault, im.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	// The job that owns the import still reads it, to end it (a context with a claim is a job run).
	_, err = h.svc.Import(inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1}), f.vault, im.ID)
	assert.NoError(t, err)
}

// B2: a held version is deployed only by an Administrator with a strict session, checked inside the
// transaction; a not-held version ignores the flag.
func TestHeldVersionNeedsAStrictSession(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	deploy := func(a inventory.Actor, strict bool) ([]inventory.RequestedDeployment, error) {
		return h.svc.RequestKVDeployment(ctx, a, inventory.KVDeployInput{BindingID: bind.ID, VersionID: v1, StrictSession: strict})
	}
	// Not held: the flag changes nothing.
	got, err := deploy(b.operator, false)
	require.NoError(t, err)
	b.finishQueued(got...)
	// The hold appears between the caller's read and the call.
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
	n := h.count("SELECT count(*) FROM deployments")
	_, err = deploy(b.admin, false)
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsStepUp, "an Administrator without a fresh step-up, or with a token")
	assert.Equal(t, n, h.count("SELECT count(*) FROM deployments"), "nothing was created")
	d := h.auditDetails("deployment.denied")
	assert.Equal(t, "held_needs_step_up", d[len(d)-1]["reason"])
	_, err = deploy(b.operator, true)
	assert.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin, "an Operator is refused whatever the flag says")
	got, err = deploy(b.admin, true)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestAddingToAnAutomaticBindingNeedsAStrictSession(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	on, err := h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, bind.Version, true)
	require.NoError(t, err)
	want := []uuid.UUID{b.loc1, b.loc2}
	_, err = h.svc.UpdateBindingLocationsStrict(ctx, b.admin, bind.ID, on.Version, want, false)
	assert.ErrorIs(t, err, inventory.ErrAutoDeployNeedsStepUp)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificate_locations WHERE binding_id = $1", bind.ID))
	// Removing needs no step-up; a binding that is not automatic needs none either.
	_, err = h.svc.UpdateBindingLocationsStrict(ctx, b.admin, bind.ID, on.Version, []uuid.UUID{}, false)
	assert.Error(t, err, "an empty set is a validation error, not a step-up question")
	got, err := h.svc.UpdateBindingLocationsStrict(ctx, b.admin, bind.ID, on.Version, want, true)
	require.NoError(t, err)
	off, err := h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, got.Version, false)
	require.NoError(t, err)
	_, err = h.svc.UpdateBindingLocationsStrict(ctx, b.admin, bind.ID, off.Version, []uuid.UUID{b.loc1, b.loc2, b.loc3}, false)
	assert.NoError(t, err)
}

// B3: the filter and the cursor are applied in SQL; a cursor is bound to its vault.
func TestListImportsPageFiltersAndPages(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	mk := func(name string, cert uuid.UUID) inventory.KVImport {
		h.clock.Advance(time.Second)
		im, err := h.svc.RequestImport(ctx, f.admin, inventory.ImportInput{VaultID: f.vault, CertificateID: cert, Name: name})
		require.NoError(t, err)
		_, err = h.svc.FailQueuedImport(ctx, im.ID, "target.disabled")
		require.NoError(t, err)
		return im
	}
	rsa := f.deployFixture.rsaCert.ID
	var ecdsa, other []uuid.UUID
	for i := range 5 {
		ecdsa = append(ecdsa, mk("p-name", f.cert.ID).ID)
		_ = i
		other = append(other, mk("p-other", rsa).ID)
	}
	page, err := h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{CertificateID: f.cert.ID, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page.Items, 2)
	assert.Equal(t, []uuid.UUID{ecdsa[4], ecdsa[3]}, []uuid.UUID{page.Items[0].ID, page.Items[1].ID})
	require.NotEmpty(t, page.NextCursor)
	var all []uuid.UUID
	for _, it := range page.Items {
		all = append(all, it.ID)
	}
	for page.NextCursor != "" {
		page, err = h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{CertificateID: f.cert.ID, Limit: 2, Cursor: page.NextCursor})
		require.NoError(t, err)
		for _, it := range page.Items {
			all = append(all, it.ID)
		}
	}
	assert.Equal(t, []uuid.UUID{ecdsa[4], ecdsa[3], ecdsa[2], ecdsa[1], ecdsa[0]}, all, "every row of the filter, none of the others")
	byName, err := h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{CertificateName: "P-OTHER", Limit: 50})
	require.NoError(t, err)
	assert.Len(t, byName.Items, 5, "the name is folded")
	assert.Empty(t, byName.NextCursor)
	_ = other
	// A cursor of one vault is nothing in another.
	first, err := h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{Limit: 2})
	require.NoError(t, err)
	require.NotEmpty(t, first.NextCursor)
	elsewhere := h.vault("elsewhere")
	got, err := h.svc.ListImportsPage(ctx, elsewhere, inventory.ImportFilter{Limit: 2, Cursor: first.NextCursor})
	var errs validate.Errors
	assert.ErrorAs(t, err, &errs)
	assert.Empty(t, got.Items)
	_, err = h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{CertificateName: "bad name!"})
	assert.ErrorAs(t, err, &errs)
	_, err = h.svc.ListImportsPage(ctx, f.vault, inventory.ImportFilter{Limit: 500})
	assert.ErrorAs(t, err, &errs)
}
