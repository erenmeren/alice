package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
)

var (
	vaultID     = uuid.MustParse("0192d000-0000-7000-8000-0000000000a1")
	kvCertID    = uuid.MustParse("0192d000-0000-7000-8000-0000000000a2")
	versionA    = uuid.MustParse("0192d000-0000-7000-8000-0000000000a3")
	bindingA    = uuid.MustParse("0192d000-0000-7000-8000-0000000000a4")
	locationA   = uuid.MustParse("0192d000-0000-7000-8000-0000000000a5")
	locationB   = uuid.MustParse("0192d000-0000-7000-8000-0000000000a6")
	importA     = uuid.MustParse("0192d000-0000-7000-8000-0000000000a7")
	vaultTenant = "11111111-2222-4333-8444-555555555555"
	vaultClient = "66666666-7777-4888-8999-aaaaaaaaaaaa"
)

func sampleVault() inventory.Target {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	exp := at.Add(90 * 24 * time.Hour)
	return inventory.Target{
		ID: vaultID, Name: "prod-vault", Type: inventory.TypeAzureKeyVault, Host: "contoso.vault.azure.net", Port: 443, Status: "degraded",
		LastErrorCode: "azure.forbidden", LastSuccessAt: &at, Capabilities: []string{"discover_certificates"}, Version: 3, CreatedAt: at, UpdatedAt: at,
		Vault: &inventory.VaultInfo{URL: "https://contoso.vault.azure.net", Host: "contoso.vault.azure.net", Auth: providers.AzureAuthClientSecret,
			TenantID: vaultTenant, ClientID: vaultClient, SecretExpiresOn: &exp, PollInterval: 15 * time.Minute,
			Access: &providers.AzureFacts{ObjectID: "99999999-7777-4888-8999-aaaaaaaaaaaa", TenantID: vaultTenant, PermissionModel: "rbac", CheckedAt: at,
				Checks: []providers.AzureCheck{
					{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
					{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: "Key Vault Reader"},
					{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
				}}},
	}
}

func sampleKVCertificate() inventory.KVCertificate {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	yes := true
	return inventory.KVCertificate{ID: kvCertID, TargetID: vaultID, Name: "web-cert", CurrentVersion: strings.Repeat("a", 32),
		CurrentThumbprint: strings.Repeat("b", 40), Enabled: true, Expires: &at, Exportable: &yes, KeyType: "rsa", KeySize: 2048,
		ContentType: "application/x-pkcs12", FirstSeenAt: at, LastSeenAt: at, Bound: true}
}

func vaultDeps(t *testing.T) (http.Handler, *fakeInventory, Deps) {
	t.Helper()
	d, inv := inventoryDeps(t)
	return NewHandler(d), inv, d
}

// jsonObj decodes a response body.
func jsonObj(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())
	return m
}

func createVaultBody(extra string) string {
	return `{"name":"prod-vault","vault_url":"https://Contoso.vault.azure.net/","auth":"client_secret","tenant_id":"` + "ABCDEFAB-2222-4333-8444-555555555555" +
		`","client_id":"` + vaultClient + `","client_secret":"fake-0123456789abcdef"` + extra + `}`
}

func TestCreateVaultHandler(t *testing.T) {
	h, inv, d := vaultDeps(t)
	var got inventory.NewVault
	var secret []byte
	inv.CreateVaultFn = func(_ context.Context, a inventory.Actor, in inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		got, secret = in, in.ClientSecret.Bytes()
		assert.Equal(t, "fake-0123456789abcdef", string(secret))
		return sampleVault(), providers.ConnectionReport{Azure: sampleVault().Vault.Access}, jobID, nil
	}
	rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", createVaultBody(""))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	// Inventory got the vault address in its normal form and the GUIDs in lower case.
	assert.Equal(t, "https://contoso.vault.azure.net", got.VaultURL)
	assert.Equal(t, "abcdefab-2222-4333-8444-555555555555", got.TenantID)
	assert.Equal(t, "prod-vault", got.Name)
	// The handler zeroed the secret it owned when it was done (the fake inventory did not).
	assert.Equal(t, make([]byte, len("fake-0123456789abcdef")), secret)
	body := jsonObj(t, rec)
	target := body["target"].(map[string]any)
	assert.Equal(t, "azure_key_vault", target["type"])
	vault := target["vault"].(map[string]any)
	assert.Equal(t, "contoso", vault["name"])
	assert.Equal(t, "client_secret", vault["auth"])
	assert.EqualValues(t, 15, vault["poll_interval_minutes"])
	assert.Contains(t, vault, "secret_expires_on")
	assert.Contains(t, vault, "access")
	access := body["access"].(map[string]any)
	assert.Equal(t, "rbac", access["permission_model"])
	assert.Len(t, access["checks"], 3)
	assert.Equal(t, jobID.String(), body["job_id"])
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	for _, word := range []string{`"client_secret":`, `"private_key_pem":`, `"pfx_base64":`, `"pfx_password":`, "fake-0123456789abcdef"} {
		assert.NotContains(t, rec.Body.String(), word)
	}
	// The vault's last error is the closed code with the role the access check names.
	lastErr := target["last_error"].(map[string]any)
	assert.Equal(t, "ALC-AKV-0003", lastErr["code"])
	assert.Equal(t, map[string]any{"role": "Key Vault Reader", "model": "rbac"}, lastErr["params"])

	// Body rules: a key twice, an upper-case key, an unknown key, an oversized body.
	for _, b := range []string{
		createVaultBody(`,"name":"x"`), createVaultBody(`,"Auth":"client_secret"`), createVaultBody(`,"extra":1`),
	} {
		assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b).Code, b)
	}
	big := `{"name":"v","pfx_base64":"` + strings.Repeat("A", 769<<10) + `"}`
	assert.Equal(t, http.StatusRequestEntityTooLarge, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", big).Code)

	// Refusals: the provider's closed code, the license, a duplicate (worded for vaults).
	for _, tc := range []struct {
		err  error
		want ErrorCode
	}{
		{providers.NewError("azure.vault_not_found", false, assert.AnError, nil), ErrAzureVaultNotFound},
		{providers.NewError("azure.forbidden", false, assert.AnError, map[string]string{"role": "Key Vault Reader", "model": "rbac"}), ErrAzureForbidden},
		{&license.TargetLimitError{Max: 5, Used: 5}, ErrLicenseTargetLimit},
		{inventory.ErrDuplicateTarget, ErrKVVaultDuplicate},
		{inventory.ErrClientCertificateInvalid, ErrKVClientCertInvalid},
	} {
		inv.CreateVaultFn = func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
			return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, tc.err
		}
		rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", createVaultBody(""))
		assert.Equal(t, tc.want.Status, rec.Code)
		e := decodeErr(t, rec)
		assert.Equal(t, tc.want.Code, e.Error.Code)
		assert.Equal(t, "errors."+tc.want.Reason, e.Error.MessageKey)
	}

	// Who may: Administrator with step-up only, never a token.
	called := 0
	inv.CreateVaultFn = func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		called++
		return sampleVault(), providers.ConnectionReport{}, jobID, nil
	}
	for id, want := range map[string]int{"operator": 403, "operator-stepup": 403, "auditor": 403, "admin": 403, "alice_operate_admin": 403, "": 401} {
		assert.Equal(t, want, call(h, http.MethodPost, "/api/v1/key-vaults", id, createVaultBody("")).Code, id)
	}
	assert.Equal(t, "auth.stepup_required", decodeErr(t, call(h, http.MethodPost, "/api/v1/key-vaults", "admin", createVaultBody(""))).Error.Reason)
	assert.Zero(t, called)
	d.License.(*fakeLicense).set(license.ErrLocked)
	assert.Equal(t, "license.locked", decodeErr(t, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", createVaultBody(""))).Error.Reason)
	assert.Zero(t, called)
}

// A vault address that is not a public-cloud vault is refused when typed (Review Focus 1) before inventory is called.
func TestCreateVaultRefusesAddressesThatAreNotVaults(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	called := 0
	inv.CreateVaultFn = func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		called++
		return sampleVault(), providers.ConnectionReport{}, jobID, nil
	}
	for _, u := range []string{"http://contoso.vault.azure.net", "https://contoso.vault.azure.net:8443", "https://contoso.vault.azure.net.evil.test",
		"https://contoso.vault.azure.net/secrets", "contoso.vault.usgovcloudapi.net", "", "https://169.254.169.254"} {
		b := `{"name":"v","vault_url":` + mustJSON(u) + `,"auth":"client_secret","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `","client_secret":"x"}`
		rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, u)
		details := errorDetails(t, rec)
		require.Len(t, details, 1, u)
		assert.Equal(t, "vault_url", details[0].Field)
		assert.Equal(t, "validation.pattern", details[0].Code)
	}
	b := `{"name":"v","vault_url":"contoso","auth":"client_secret","tenant_id":"not-a-guid","client_id":"` + vaultClient + `","client_secret":"x"}`
	details := errorDetails(t, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b))
	require.Len(t, details, 1)
	assert.Equal(t, "tenant_id", details[0].Field)
	assert.Zero(t, called)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A certificate sign-in arrives as PEM fields or as a PFX in base64; inventory gets bytes and the handler zeroes its own.
func TestCreateVaultCertificateSignIn(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	var keyView, pfxView []byte
	inv.CreateVaultFn = func(_ context.Context, _ inventory.Actor, in inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		keyView, pfxView = in.Certificate.PrivateKeyPEM, in.Certificate.PFX
		if len(in.Certificate.PFX) > 0 {
			assert.Equal(t, "pfx-bytes", string(in.Certificate.PFX))
			assert.Equal(t, "pw-1", in.Certificate.PFXPassword)
		} else {
			assert.Equal(t, "line1\nline2\n", string(in.Certificate.PrivateKeyPEM))
		}
		return sampleVault(), providers.ConnectionReport{}, jobID, nil
	}
	b := `{"name":"v","vault_url":"contoso","auth":"certificate","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient +
		`","certificate_pem":"cert\n","private_key_pem":"line1\nline2\n"}`
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b).Code)
	assert.Equal(t, make([]byte, len("line1\nline2\n")), keyView)
	b = `{"name":"v","vault_url":"contoso","auth":"certificate","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient +
		`","pfx_base64":"` + base64.StdEncoding.EncodeToString([]byte("pfx-bytes")) + `","pfx_password":"pw-1"}`
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b).Code)
	assert.Equal(t, make([]byte, len("pfx-bytes")), pfxView)
	// Not base64: a field error, nothing sent on.
	b = strings.Replace(b, base64.StdEncoding.EncodeToString([]byte("pfx-bytes")), "***", 1)
	rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "pfx_base64", errorDetails(t, rec)[0].Field)
}

func TestReplaceVaultCredentialsHandler(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	path := "/api/v1/targets/" + vaultID.String() + "/vault-credentials"
	body := `{"auth":"client_secret","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `","client_secret":"fake-new-secret"}`
	var in inventory.VaultCredentialInput
	var ver int
	var secret []byte
	inv.ReplaceVaultCredentialsFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, v int, c inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		in, ver, secret = c, v, c.ClientSecret.Bytes()
		return sampleVault(), providers.ConnectionReport{Azure: sampleVault().Vault.Access}, jobID, nil
	}
	rec := callWith(h, http.MethodPut, path, "admin-stepup", body, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 3, ver)
	assert.Equal(t, providers.AzureAuthClientSecret, in.Auth)
	assert.Equal(t, make([]byte, len("fake-new-secret")), secret)
	assert.Equal(t, jobID.String(), jsonObj(t, rec)["job_id"])
	assert.NotContains(t, rec.Body.String(), "fake-new-secret")
	// Without If-Match: 412. Stale version: 412. A vault_url or a name is not accepted here.
	assert.Equal(t, http.StatusPreconditionFailed, call(h, http.MethodPut, path, "admin-stepup", body).Code)
	inv.ReplaceVaultCredentialsFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, inventory.ErrVersionMismatch
	}
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, path, "admin-stepup", body, map[string]string{"If-Match": `"2"`}).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, path, "admin-stepup", strings.Replace(body, `{`, `{"vault_url":"x",`, 1), map[string]string{"If-Match": `"3"`}).Code)
	// A disabled vault: no job.
	inv.ReplaceVaultCredentialsFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		return sampleVault(), providers.ConnectionReport{}, uuid.Nil, nil
	}
	rec = callWith(h, http.MethodPut, path, "admin-stepup", body, map[string]string{"If-Match": `"3"`})
	assert.Nil(t, jsonObj(t, rec)["job_id"])
	for id, want := range map[string]int{"operator": 403, "admin": 403, "alice_operate_admin": 403} {
		assert.Equal(t, want, callWith(h, http.MethodPut, path, id, body, map[string]string{"If-Match": `"3"`}).Code, id)
	}
}

func TestVaultReadRoutes(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	vault, server := sampleVault(), sampleTarget()
	inv.ListTargetsFn = func(context.Context) ([]inventory.Target, error) { return []inventory.Target{vault, server}, nil }
	names := func(rec *httptest.ResponseRecorder) []string {
		var out []string
		for _, it := range jsonObj(t, rec)["items"].([]any) {
			out = append(out, it.(map[string]any)["type"].(string))
		}
		return out
	}
	assert.Equal(t, []string{"azure_key_vault"}, names(call(h, http.MethodGet, "/api/v1/targets?type=azure_key_vault", "auditor", "")))
	assert.Equal(t, []string{"linux"}, names(call(h, http.MethodGet, "/api/v1/targets?type=linux", "auditor", "")))
	assert.Len(t, names(call(h, http.MethodGet, "/api/v1/targets", "auditor", "")), 2)
	rec := call(h, http.MethodGet, "/api/v1/targets?type=bogus", "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "type", errorDetails(t, rec)[0].Field)
	// A server carries no "vault"; a vault does.
	items := jsonObj(t, call(h, http.MethodGet, "/api/v1/targets", "auditor", ""))["items"].([]any)
	assert.Contains(t, items[0], "vault")
	assert.NotContains(t, items[1], "vault")

	var filter inventory.KVFilter
	inv.ListKVCertificatesFn = func(_ context.Context, v uuid.UUID, f inventory.KVFilter) (inventory.KVCertificatePage, error) {
		assert.Equal(t, vaultID, v)
		filter = f
		return inventory.KVCertificatePage{Items: []inventory.KVCertificate{sampleKVCertificate()}, NextCursor: "next"}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/targets/"+vaultID.String()+"/kv/certificates?q=web&expires_before=2027-01-01T00:00:00Z&missing=include&cursor=abc&limit=7", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "web", filter.Query)
	assert.Equal(t, "abc", filter.Cursor)
	assert.Equal(t, 7, filter.Limit)
	assert.Equal(t, inventory.KVMissingInclude, filter.Missing)
	require.NotNil(t, filter.ExpiresBefore)
	assert.Equal(t, "next", jsonObj(t, rec)["next_cursor"])
	for _, bad := range []string{"limit=0", "limit=201", "expires_before=yesterday", "missing=maybe"} {
		assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/targets/"+vaultID.String()+"/kv/certificates?"+bad, "auditor", "").Code, bad)
	}
	inv.ListKVKeysFn = func(context.Context, uuid.UUID, inventory.KVFilter) ([]inventory.KVKey, string, error) {
		return []inventory.KVKey{{ID: kvCertID, TargetID: vaultID, Name: "k1", KeyType: "rsa"}}, "", nil
	}
	inv.ListKVSecretsFn = func(context.Context, uuid.UUID, inventory.KVFilter) ([]inventory.KVSecret, string, error) {
		return []inventory.KVSecret{{ID: kvCertID, TargetID: vaultID, Name: "s1"}}, "", nil
	}
	for _, kind := range []string{"keys", "secrets"} {
		rec = call(h, http.MethodGet, "/api/v1/targets/"+vaultID.String()+"/kv/"+kind, "auditor", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, jsonObj(t, rec)["items"], 1)
		assert.Nil(t, jsonObj(t, rec)["next_cursor"])
		assert.NotContains(t, rec.Body.String(), "value")
	}
	// Detail with versions and the binding.
	inv.KVCertificateFn = func(_ context.Context, v, id uuid.UUID) (inventory.KVCertificateDetail, error) {
		assert.Equal(t, vaultID, v)
		assert.Equal(t, kvCertID, id)
		return inventory.KVCertificateDetail{KVCertificate: sampleKVCertificate(), DeployAccess: inventory.DeployAccessOK,
			Versions: []inventory.KVVersion{{ID: versionA, Version: strings.Repeat("a", 32), Thumbprint: strings.Repeat("b", 40), Enabled: true, Held: true, HeldReason: "license"}},
			Binding:  &inventory.BindingSummary{ID: bindingA, AutoDeploy: true, LocationCount: 2, Version: 4}}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/targets/"+vaultID.String()+"/kv/certificates/"+kvCertID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	detail := jsonObj(t, rec)
	assert.Equal(t, "ok", detail["deploy_access"])
	assert.Equal(t, "license", detail["versions"].([]any)[0].(map[string]any)["held_reason"])
	assert.Equal(t, bindingA.String(), detail["binding"].(map[string]any)["id"])
	// A server's id on a kv route: the inventory says ErrNotAVault, the API answers 404.
	inv.ListKVCertificatesFn = func(context.Context, uuid.UUID, inventory.KVFilter) (inventory.KVCertificatePage, error) {
		return inventory.KVCertificatePage{}, inventory.ErrNotAVault
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/"+targetID.String()+"/kv/certificates", "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/nope/kv/certificates", "auditor", "").Code)
}

func TestVaultPatchTestDiscoverDelete(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	base := "/api/v1/targets/" + vaultID.String()
	// PATCH: poll_interval_minutes.
	var patch inventory.TargetPatch
	inv.UpdateTargetFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, _ int, p inventory.TargetPatch) (inventory.Target, error) {
		patch = p
		return sampleVault(), nil
	}
	rec := callWith(h, http.MethodPatch, base, "admin", `{"poll_interval_minutes":30}`, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, patch.PollIntervalMinutes)
	assert.Equal(t, 30, *patch.PollIntervalMinutes)
	// A vault renamed to a name that exists: worded for vaults.
	inv.UpdateTargetFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.TargetPatch) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrDuplicateTarget
	}
	inv.GetTargetFn = func(context.Context, uuid.UUID) (inventory.Target, error) { return sampleVault(), nil }
	rec = callWith(h, http.MethodPatch, base, "admin", `{"name":"x"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, "ALC-AKV-0028", decodeErr(t, rec).Error.Code)
	inv.GetTargetFn = func(context.Context, uuid.UUID) (inventory.Target, error) { return sampleTarget(), nil }
	rec = callWith(h, http.MethodPatch, base, "admin", `{"name":"x"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, ErrTargetDuplicate.Code, decodeErr(t, rec).Error.Code)

	// Test: with and without read_secret_of; the discover action is the vault's Check now.
	var readOf uuid.UUID
	inv.RequestAccessCheckFn = func(_ context.Context, _ inventory.Actor, v, r uuid.UUID) (uuid.UUID, error) {
		assert.Equal(t, vaultID, v)
		readOf = r
		return jobID, nil
	}
	inv.RequestTestFn = func(context.Context, inventory.Actor, uuid.UUID) (uuid.UUID, error) { return jobID, nil }
	inv.RequestDiscoveryFn = func(context.Context, inventory.Actor, uuid.UUID) (uuid.UUID, error) { return jobID, nil }
	rec = call(h, http.MethodPost, base+"/actions/test", "operator", `{"read_secret_of":"`+kvCertID.String()+`"}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, kvCertID, readOf)
	assert.Equal(t, http.StatusAccepted, call(h, http.MethodPost, base+"/actions/test", "operator", "").Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, base+"/actions/test", "operator", `{"read_secret_of":"nope"}`).Code)
	assert.Equal(t, http.StatusAccepted, call(h, http.MethodPost, base+"/actions/discover", "operator", "").Code)
	inv.RequestAccessCheckFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID) (uuid.UUID, error) {
		return uuid.Nil, inventory.ErrNotExportable
	}
	assert.Equal(t, "ALC-AKV-0013", decodeErr(t, call(h, http.MethodPost, base+"/actions/test", "operator", `{"read_secret_of":"`+kvCertID.String()+`"}`)).Error.Code)

	// DELETE of a vault: DeleteVault; remove_bindings needs an Administrator with step-up and no token.
	inv.DeleteTargetFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrNotAServer }
	var removed []bool
	inv.DeleteVaultFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, r bool) error {
		removed = append(removed, r)
		return nil
	}
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, base, "admin", "").Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, base+"?remove_bindings=true", "admin-stepup", "").Code)
	assert.Equal(t, []bool{false, true}, removed)
	rec = call(h, http.MethodDelete, base+"?remove_bindings=true", "admin", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "auth.stepup_required", decodeErr(t, rec).Error.Reason)
	rec = call(h, http.MethodDelete, base+"?remove_bindings=true", "alice_operate_admin", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "auth.forbidden", decodeErr(t, rec).Error.Reason)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodDelete, base+"?remove_bindings=perhaps", "admin-stepup", "").Code)
	assert.Len(t, removed, 2)
	inv.DeleteVaultFn = func(context.Context, inventory.Actor, uuid.UUID, bool) error { return inventory.ErrVaultHasBindings }
	assert.Equal(t, "ALC-AKV-0020", decodeErr(t, call(h, http.MethodDelete, base, "admin", "")).Error.Code)
	// A server keeps the Phase 3 path.
	deleted := false
	inv.DeleteTargetFn = func(context.Context, inventory.Actor, uuid.UUID) error { deleted = true; return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/targets/"+targetID.String(), "admin", "").Code)
	assert.True(t, deleted)
}
