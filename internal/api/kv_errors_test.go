package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.yaml.in/yaml/v3"

	apispec "alice/api"
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
	inv.ListImportsPageFn = func(context.Context, uuid.UUID, inventory.ImportFilter) (inventory.ImportPage, error) {
		return inventory.ImportPage{}, inventory.ErrNotFound
	}
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
	inv.UpdateBindingLocationsStrictFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID, bool) (inventory.Binding, error) {
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

// Optional bodies are read with the exact decoder as well: keys in lower case, each once; an empty body stays allowed.
func TestOptionalBodiesAreExact(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	inv.ReleaseVersionFn = func(context.Context, inventory.Actor, inventory.ReleaseInput) (inventory.KVVersion, error) {
		return inventory.KVVersion{ID: versionA}, nil
	}
	inv.RequestAccessCheckFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID) (uuid.UUID, error) { return jobID, nil }
	inv.RequestTestFn = func(context.Context, inventory.Actor, uuid.UUID) (uuid.UUID, error) { return jobID, nil }
	release := "/api/v1/targets/" + vaultID.String() + "/kv/certificates/" + kvCertID.String() + "/versions/" + versionA.String() + "/actions/release"
	test := "/api/v1/targets/" + vaultID.String() + "/actions/test"
	read := `"read_secret_of":"` + kvCertID.String() + `"`
	for _, tc := range []struct {
		path, id, body string
		want           int
	}{
		{release, "admin-stepup", "", http.StatusOK},
		{release, "admin-stepup", "{}", http.StatusOK},
		{release, "admin-stepup", `{"confirm_incomplete_chain":true}`, http.StatusOK},
		{release, "admin-stepup", `{"Confirm_Incomplete_Chain":true}`, http.StatusBadRequest},
		{release, "admin-stepup", `{"confirm_incomplete_chain":false,"confirm_incomplete_chain":true}`, http.StatusBadRequest},
		{release, "admin-stepup", `{"extra":1}`, http.StatusBadRequest},
		{test, "operator", "", http.StatusAccepted},
		{test, "operator", `{` + read + `}`, http.StatusAccepted},
		{test, "operator", `{"READ_SECRET_OF":"` + kvCertID.String() + `"}`, http.StatusBadRequest},
		{test, "operator", `{` + read + `,` + read + `}`, http.StatusBadRequest},
	} {
		assert.Equal(t, tc.want, call(h, http.MethodPost, tc.path, tc.id, tc.body).Code, tc.path+" "+tc.body)
	}
}

// The second-line filters of the access check and of a vault's last error: a role or model that is not one of the
// closed values never reaches a client, whatever a stored row holds.
func TestAccessCheckFiltersAreSecondLines(t *testing.T) {
	at := sampleVault().Vault.Access.CheckedAt
	got := accessJSON(&providers.AzureFacts{PermissionModel: "rbac", CheckedAt: at, Checks: []providers.AzureCheck{
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: "Key Vault Owner {{x}}"},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: "Key Vault Secrets User"},
	}})
	require.Len(t, got.Checks, 2)
	assert.Empty(t, got.Checks[0].Role, "a role outside the three is dropped")
	require.NotNil(t, got.Checks[0].Error)
	assert.Equal(t, map[string]string{"role": "Key Vault Reader"}, got.Checks[0].Error.Params, "the error text gets the floor role, never the stored text")
	assert.Equal(t, "Key Vault Secrets User", got.Checks[1].Role)
	assert.Equal(t, map[string]string{"role": "Key Vault Secrets User"}, got.Checks[1].Error.Params)

	v := sampleVault()
	v.LastErrorCode = "azure.forbidden"
	v.Vault.Access.PermissionModel = "rbac"
	v.Vault.Access.Checks = []providers.AzureCheck{{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Role: "Key Vault Secrets User"}}
	assert.Equal(t, map[string]string{"role": "Key Vault Secrets User", "model": "rbac"}, vaultLastError(v).Params)
	v.Vault.Access.PermissionModel = "<b>"
	assert.Equal(t, map[string]string{"role": "Key Vault Secrets User"}, vaultLastError(v).Params, "a model outside the three is dropped")
	v.Vault.Access.Checks[0].Role = "Owner"
	assert.Equal(t, map[string]string{"role": "Key Vault Reader"}, vaultLastError(v).Params, "a stored role outside the three is replaced by the floor role")
	v.Vault.Access.Checks[0].Role = "Key Vault Secrets User"
	v.Vault.Access.Checks[0].Result = providers.AzureResultFailed
	assert.Equal(t, map[string]string{"role": "Key Vault Reader"}, vaultLastError(v).Params, "only a forbidden row names its role")
}

// A poll-time failure's params come from facts.kv_poll: the firewall's client address (an IP address literal) and
// the permission model (one of three), from the failure that is the vault's last error; anything else stored there
// never reaches a client.
func TestVaultLastErrorCarriesThePollTimeParams(t *testing.T) {
	at := sampleVault().Vault.Access.CheckedAt
	fw := sampleVault()
	fw.LastErrorCode = "azure.firewall"
	fw.Facts.KVPoll = &inventory.KVPollFacts{At: at, Failures: []inventory.KVPollFailure{
		{Object: "vault", Reason: "azure.firewall", ClientAddress: "203.0.113.7", AzureCode: "ForbiddenByFirewall"}}}
	got := vaultLastError(fw)
	require.NotNil(t, got)
	assert.Equal(t, "ALC-AKV-0004", got.Code)
	assert.Equal(t, map[string]string{"client_address": "203.0.113.7"}, got.Params)
	fw.Facts.KVPoll.Failures[0].ClientAddress = "2001:db8::7"
	assert.Equal(t, map[string]string{"client_address": "2001:db8::7"}, vaultLastError(fw).Params)

	// A list's failure counts as well; one that is not the last error does not.
	fw.Facts.KVPoll.Failures = []inventory.KVPollFailure{{Object: "keys", Reason: "azure.unreachable", ClientAddress: "198.51.100.1"},
		{Object: "certificates", Reason: "azure.firewall", ClientAddress: "198.51.100.2"}}
	assert.Equal(t, map[string]string{"client_address": "198.51.100.2"}, vaultLastError(fw).Params)

	// Hostile stored values are dropped, never echoed.
	for _, bad := range []string{"<script>alert(1)</script>", "203.0.113.7 or any", "fe80::1%eth0", "999.1.1.1", "", "::ffff:1.2.3.4.5"} {
		fw.Facts.KVPoll.Failures = []inventory.KVPollFailure{{Object: "vault", Reason: "azure.firewall", ClientAddress: bad, Model: "<b>"}}
		assert.Nil(t, vaultLastError(fw).Params, bad)
	}

	// azure.forbidden at poll time: the poll's model wins over the access check's, the access check's role stays.
	fb := sampleVault()
	fb.Vault.Access.PermissionModel = "rbac"
	fb.Facts.KVPoll = &inventory.KVPollFacts{At: at, Failures: []inventory.KVPollFailure{
		{Object: "vault", Reason: "azure.forbidden", Role: "Key Vault Reader", Model: "access_policy"}}}
	assert.Equal(t, map[string]string{"role": "Key Vault Reader", "model": "access_policy"}, vaultLastError(fb).Params)
	// Without an access check row, the poll's role names what is missing.
	fb.Vault.Access = nil
	fb.Facts.KVPoll.Failures[0].Role = "Key Vault Secrets User"
	assert.Equal(t, map[string]string{"role": "Key Vault Secrets User", "model": "access_policy"}, vaultLastError(fb).Params)
	fb.Facts.KVPoll.Failures[0].Role, fb.Facts.KVPoll.Failures[0].Model = "Owner", "other"
	assert.Equal(t, map[string]string{"role": "Key Vault Reader"}, vaultLastError(fb).Params, "outside the closed sets: the floor role only")
}

// An Operator's confirm_incomplete_chain counts for nothing: the handler passes false whatever it sent.
func TestOperatorChainConfirmationIsDropped(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{KVCertificate: sampleKVCertificate(), Versions: []inventory.KVVersion{{ID: versionA}}}, nil
	}
	var got []bool
	inv.RequestKVDeploymentFn = func(_ context.Context, _ inventory.Actor, in inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		got = append(got, in.ConfirmIncompleteChain)
		return []inventory.RequestedDeployment{{ID: importA, JobID: jobID, LocationID: locationA}}, nil
	}
	body := `{"version_id":"` + versionA.String() + `","confirm_incomplete_chain":true}`
	path := "/api/v1/bindings/" + bindingA.String() + "/actions/deploy"
	for _, id := range []string{"operator", "alice_operate_operator", "admin", "alice_operate_admin"} {
		require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, path, id, body).Code, id)
	}
	assert.Equal(t, []bool{false, false, true, true}, got)
}

// A version that is not one of the binding's certificate's versions is not found, for every role (the
// inventory's answer for another certificate's version would be a 409 that tells a prober the id exists).
func TestForeignVersionIsNotFound(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{KVCertificate: sampleKVCertificate(), Versions: []inventory.KVVersion{{ID: versionA}}}, nil
	}
	calls := 0
	inv.RequestKVDeploymentFn = func(context.Context, inventory.Actor, inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		calls++
		return nil, inventory.ErrVersionNotDeployable
	}
	path := "/api/v1/bindings/" + bindingA.String() + "/actions/deploy"
	for _, id := range []string{"operator", "admin", "admin-stepup"} {
		rec := call(h, http.MethodPost, path, id, `{"version_id":"`+uuid.NewString()+`"}`)
		assert.Equal(t, http.StatusNotFound, rec.Code, id)
	}
	assert.Zero(t, calls, "the inventory is not asked for a version the certificate does not have")
}

// A stored value outside a field's closed set never becomes an empty string where the spec's enum has none: fields
// with a safe meaning fall back to it (deploy access: not checked; a website: not deployed), the others are "" and
// their enum says so.
func TestDTOFallbacksMatchTheSpecEnums(t *testing.T) {
	d := kvCertificateDetailJSON(inventory.KVCertificateDetail{DeployAccess: "bogus"})
	assert.Equal(t, inventory.DeployAccessNotChecked, d.DeployAccess)
	b := bindingJSON(inventory.Binding{Locations: []inventory.BindingLocation{{State: "bogus"}}})
	assert.Equal(t, inventory.BindingLocationNotDeployed, b.Locations[0].State)
	v := sampleVault()
	v.Vault.Auth = "bogus"
	assert.Empty(t, vaultJSON(v).Auth)
	assert.Empty(t, importJSON(inventory.KVImport{State: "bogus"}).State)

	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(apispec.YAML, &doc))
	comps := doc["components"].(map[string]any)["schemas"].(map[string]any)
	enum := func(schema, prop string) []any {
		sc := comps[schema].(map[string]any)
		if all, ok := sc["allOf"].([]any); ok {
			sc = all[len(all)-1].(map[string]any)
		}
		return sc["properties"].(map[string]any)[prop].(map[string]any)["enum"].([]any)
	}
	assert.ElementsMatch(t, []any{"ok", "forbidden", "not_checked"}, enum("KVCertificateDetail", "deploy_access"))
	assert.ElementsMatch(t, []any{"not_deployed", "pending", "deployed", "failed", "stopped"}, enum("BindingLocation", "state"))
	assert.Contains(t, enum("Vault", "auth"), "")
	assert.Contains(t, enum("KVImport", "state"), "")
	// HoldRule is a string schema with an enum of its own: the values the inventory stores.
	assert.ElementsMatch(t, []any{"gate_closed", "created_before_reopening", "unconfirmed_since_reopening", inventory.HoldRuleDetectedBeforeReopening},
		comps["HoldRule"].(map[string]any)["enum"].([]any))
}

// An import that ended because its requester stopped being an Administrator says so (the job stores auth.forbidden,
// which is only ever that for an import), and an uncertain import has no error at all.
func TestImportErrorForALostAdministrator(t *testing.T) {
	im := importJSON(inventory.KVImport{State: inventory.ImportFailed, ErrorCode: "auth.forbidden"})
	require.NotNil(t, im.Error)
	assert.Equal(t, "ALC-AKV-0040", im.Error.Code)
	assert.Equal(t, "kv.import_admin_required", im.Error.Reason)
	assert.Nil(t, importJSON(inventory.KVImport{State: inventory.ImportUncertain}).Error)
}
