package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// Every new route answers 404 for an id that is not a UUID (the inventory is never asked) and the closed
// code of an inventory refusal for a real one.
func TestKeyVaultRoutesAnswerForUnknownAndFailingIDs(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	inv.ListKVKeysFn = func(context.Context, uuid.UUID, inventory.KVFilter) ([]inventory.KVKey, string, error) {
		return nil, "", inventory.ErrNotFound
	}
	inv.ListKVSecretsFn = func(context.Context, uuid.UUID, inventory.KVFilter) ([]inventory.KVSecret, string, error) {
		return nil, "", inventory.ErrNotFound
	}
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{}, inventory.ErrNotFound
	}
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	inv.ListImportsFn = func(context.Context, uuid.UUID, int) ([]inventory.KVImport, error) { return nil, inventory.ErrNotFound }
	inv.ImportFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVImport, error) {
		return inventory.KVImport{}, inventory.ErrNotFound
	}
	inv.ListDeployableLocationsFn = func(context.Context, inventory.LocationFilter) (inventory.DeployableLocationPage, error) {
		return inventory.DeployableLocationPage{}, inventory.ErrNotFound
	}
	inv.SetAutoDeployFn = func(context.Context, inventory.Actor, uuid.UUID, int, bool) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	inv.DeleteBindingFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrNotFound }
	inv.ReleaseVersionFn = func(context.Context, inventory.Actor, inventory.ReleaseInput) (inventory.KVVersion, error) {
		return inventory.KVVersion{}, inventory.ErrNotFound
	}
	inv.RequestImportFn = func(context.Context, inventory.Actor, inventory.ImportInput) (inventory.KVImport, error) {
		return inventory.KVImport{}, inventory.ErrNotFound
	}
	inv.DeleteVaultFn = func(context.Context, inventory.Actor, uuid.UUID, bool) error { return inventory.ErrNotFound }
	inv.DeleteTargetFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrNotAServer }
	inv.UpdateBindingLocationsFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	inv.RequestKVDeploymentFn = func(context.Context, inventory.Actor, inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		return nil, inventory.ErrNotFound
	}
	inv.ReplaceVaultCredentialsFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, inventory.ErrNotFound
	}
	good, bad := uuid.NewString(), "not-a-uuid"
	hdr := map[string]string{"If-Match": `"1"`}
	type req struct {
		method, path, body string
		id                 string
	}
	reqs := []req{
		{http.MethodGet, "/api/v1/targets/%s/kv/certificates/%s", "", "auditor"},
		{http.MethodGet, "/api/v1/targets/%s/kv/keys", "", "auditor"},
		{http.MethodGet, "/api/v1/targets/%s/kv/secrets", "", "auditor"},
		{http.MethodGet, "/api/v1/targets/%s/kv/imports", "", "auditor"},
		{http.MethodGet, "/api/v1/targets/%s/kv/imports/%s", "", "auditor"},
		{http.MethodGet, "/api/v1/bindings/%s", "", "auditor"},
		{http.MethodDelete, "/api/v1/bindings/%s", "", "operator"},
		{http.MethodPut, "/api/v1/bindings/%s/auto-deploy", `{"enabled":true}`, "admin-stepup"},
		{http.MethodPatch, "/api/v1/bindings/%s", `{"location_ids":["` + uuid.NewString() + `"]}`, "operator"},
		{http.MethodPost, "/api/v1/bindings/%s/actions/deploy", `{"version_id":"` + uuid.NewString() + `"}`, "operator"},
		{http.MethodPost, "/api/v1/certificates/%s/actions/import-to-key-vault", `{"target_id":"` + uuid.NewString() + `","name":"a"}`, "admin-stepup"},
		{http.MethodPost, "/api/v1/targets/%s/kv/certificates/%s/versions/%s/actions/release", "", "admin-stepup"},
		{http.MethodPut, "/api/v1/targets/%s/vault-credentials", `{"auth":"managed_identity"}`, "admin-stepup"},
		{http.MethodDelete, "/api/v1/targets/%s?remove_bindings=true", "", "admin-stepup"},
	}
	fill := func(path, id string) string {
		return strings.ReplaceAll(path, "%s", id)
	}
	for _, r := range reqs {
		// One bad id anywhere: 404 before the inventory.
		rec := callWith(h, r.method, fill(r.path, bad), r.id, r.body, hdr)
		assert.Equal(t, http.StatusNotFound, rec.Code, "bad id: %s %s", r.method, r.path)
		// Real ids: the inventory's ErrNotFound is the answer (a refusal that needs ids to exist).
		rec = callWith(h, r.method, fill(r.path, good), r.id, r.body, hdr)
		assert.Equal(t, http.StatusNotFound, rec.Code, "unknown: %s %s: %s", r.method, r.path, rec.Body.String())
	}
	// The remaining branches: a binding that cannot be read, a certificate that cannot be read for the held check.
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{}, inventory.ErrNotFound
	}
	rec := call(h, http.MethodPost, "/api/v1/bindings/"+good+"/actions/deploy", "admin-stepup", `{"version_id":"`+uuid.NewString()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	rec = call(h, http.MethodPost, "/api/v1/bindings/"+good+"/actions/deploy", "admin-stepup", `{"version_id":"`+uuid.NewString()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = callWith(h, http.MethodPatch, "/api/v1/bindings/"+good, "admin-stepup", `{"location_ids":["`+uuid.NewString()+`"]}`, hdr)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// A version that the certificate does not have is not held: the inventory decides.
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{}, nil
	}
	inv.RequestKVDeploymentFn = func(context.Context, inventory.Actor, inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		return nil, inventory.ErrNotFound
	}
	rec = call(h, http.MethodPost, "/api/v1/bindings/"+good+"/actions/deploy", "admin", `{"version_id":"`+uuid.NewString()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Locations that cannot be listed, listing bounds.
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/certificate-locations", "auditor", "").Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/certificate-locations?key_type=dsa", "auditor", "").Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/targets/"+good+"/kv/imports?certificate_id=x", "auditor", "").Code)
	// Odd values of the DTO helpers.
	assert.Empty(t, oneOfOrBlank("x", []string{"a"}))
	assert.Nil(t, accessJSON(nil))
	odd := accessJSON(&providers.AzureFacts{PermissionModel: "weird", Checks: []providers.AzureCheck{{Name: "bogus", Result: "ok"}, {Name: "sign_in", Result: "bogus"}}})
	require.NotNil(t, odd)
	assert.Empty(t, odd.Checks)
	assert.Empty(t, odd.PermissionModel)
	// Unescaping: a trailing backslash and a broken \u sequence stay as they are.
	assert.Equal(t, "a\\", string(unescapeJSONString([]byte(`a\\`))))
	assert.Equal(t, "uZZ", string(unescapeJSONString([]byte(`\uZZ`))))
	r, n := readHex4([]byte("12"))
	assert.Zero(t, r)
	assert.Zero(t, n)
}
