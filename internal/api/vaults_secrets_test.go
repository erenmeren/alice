package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/logging"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// The client secret, the private key PEM, the PFX and its password of a vault request, in every form a leak could take.
// (The full leak suite with the real provider and Azure canaries is Task 18's.)
func TestSecretLeakCanaryOverTheKeyVaultRoutes(t *testing.T) {
	raw := make([]byte, 40)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	secret := "fake-" + hex.EncodeToString(raw)
	pw := "pw-" + hex.EncodeToString(raw[:8])
	keyBody := base64.StdEncoding.EncodeToString(raw)
	keyPEM := "-----BEGIN " + "PRIVATE KEY-----\n" + keyBody + "\n-----END " + "PRIVATE KEY-----\n"
	pfx := base64.StdEncoding.EncodeToString(raw)
	markers := []string{secret, hex.EncodeToString([]byte(secret)), base64.StdEncoding.EncodeToString([]byte(secret)), keyBody, keyBody[:24],
		hex.EncodeToString(raw), pfx, pw, hex.EncodeToString([]byte(pw))}

	var logs bytes.Buffer
	d, inv := inventoryDeps(t)
	d.Log = logging.New(&logs, slog.LevelDebug)
	// What the (fake) inventory may answer: success, the closed refusals, a validation error and an error whose
	// text quotes every secret as a careless service might: fail prints no error text.
	leaky := fmt.Errorf("sign in with %s and %s and %s: %w", secret, keyPEM, pw, providers.NewError("azure.auth_failed", false, fmt.Errorf("%s", secret), map[string]string{"aadsts": "7000215"}))
	unknown := fmt.Errorf("db failed on %s / %s", secret, pw)
	answers := []error{nil, leaky, unknown, validate.Errors{{Field: "client_secret", Code: validate.Required}}, inventory.ErrDuplicateTarget,
		inventory.ErrClientCertificateInvalid, inventory.ErrVersionMismatch, license.ErrLocked,
		providers.NewError("azure.forbidden", false, fmt.Errorf("%s", pw), map[string]string{"role": "Key Vault Reader", "model": "rbac", "azure_code": secret}),
		providers.NewError("internal.unexpected", false, fmt.Errorf("%s", secret), nil)}
	var answer error
	inv.CreateVaultFn = func(context.Context, inventory.Actor, inventory.NewVault) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		if answer != nil {
			return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, answer
		}
		return sampleVault(), providers.ConnectionReport{Azure: sampleVault().Vault.Access}, jobID, nil
	}
	inv.ReplaceVaultCredentialsFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.VaultCredentialInput) (inventory.Target, providers.ConnectionReport, uuid.UUID, error) {
		if answer != nil {
			return inventory.Target{}, providers.ConnectionReport{}, uuid.Nil, answer
		}
		return sampleVault(), providers.ConnectionReport{}, jobID, nil
	}
	inv.RequestImportFn = func(context.Context, inventory.Actor, inventory.ImportInput) (inventory.KVImport, error) {
		if answer != nil {
			return inventory.KVImport{}, answer
		}
		return sampleImport(inventory.ImportQueued, ""), nil
	}
	inv.SetAutoDeployFn = func(context.Context, inventory.Actor, uuid.UUID, int, bool) (inventory.Binding, error) {
		if answer != nil {
			return inventory.Binding{}, answer
		}
		return sampleBinding(true), nil
	}
	inv.RequestKVDeploymentFn = func(context.Context, inventory.Actor, inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		return nil, answer
	}
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	h := NewHandler(d)

	cert := `"certificate_pem":"` + jsonString("cert\n") + `","private_key_pem":"` + jsonString(keyPEM) + `"`
	bodies := []string{
		`{"name":"v","vault_url":"contoso","auth":"client_secret","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `","client_secret":"` + secret + `"}`,
		`{"name":"v","vault_url":"contoso","auth":"certificate","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `",` + cert + `}`,
		`{"name":"v","vault_url":"contoso","auth":"certificate","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `","pfx_base64":"` + pfx + `","pfx_password":"` + pw + `"}`,
		// Malformed and misspelled: the secret travels in a field that is not allowed, in broken JSON, in a duplicate key.
		`{"name":"v","extra":"` + secret + `","client_secret":"` + secret + `"}`,
		`{"name":"v","client_secret":"` + secret + `","client_secret":"` + secret + `"}`,
		`{"name":"v","client_secret":"` + secret,
		`{"name":"v","vault_url":"http://` + secret + `.vault.azure.net","auth":"client_secret","client_secret":"` + secret + `"}`,
		`{"name":"v","vault_url":"contoso","auth":"certificate","pfx_base64":"` + pw + `***","pfx_password":"` + pw + `"}`,
		`{"name":"v","vault_url":"contoso","auth":"client_secret","tenant_id":"` + secret + `","client_secret":"` + secret + `"}`,
	}
	credBody := `{"auth":"client_secret","tenant_id":"` + vaultTenant + `","client_id":"` + vaultClient + `","client_secret":"` + secret + `"}`
	check := func(name string, rec interface{ Header() http.Header }, body string) {
		t.Helper()
		var hdr strings.Builder
		for k, vs := range rec.Header() {
			hdr.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
		}
		for _, m := range markers {
			assert.NotContains(t, body, m, "%s: answer", name)
			assert.NotContains(t, hdr.String(), m, "%s: headers", name)
		}
	}
	creds := "/api/v1/targets/" + vaultID.String() + "/vault-credentials"
	for _, a := range answers {
		answer = a
		for i, b := range bodies {
			rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", b)
			check(fmt.Sprintf("create %d answer %v", i, a), rec, rec.Body.String())
		}
		for i, b := range []string{credBody, bodies[1], bodies[2]} {
			rec := callWith(h, http.MethodPut, creds, "admin-stepup", b, map[string]string{"If-Match": `"3"`})
			check(fmt.Sprintf("replace %d answer %v", i, a), rec, rec.Body.String())
		}
		rec := call(h, http.MethodPost, "/api/v1/certificates/"+csrID.String()+"/actions/import-to-key-vault", "admin-stepup",
			`{"target_id":"`+vaultID.String()+`","name":"web-cert"}`)
		check(fmt.Sprintf("import answer %v", a), rec, rec.Body.String())
		rec = callWith(h, http.MethodPut, "/api/v1/bindings/"+bindingA.String()+"/auto-deploy", "admin-stepup", `{"enabled":true}`, map[string]string{"If-Match": `"4"`})
		check(fmt.Sprintf("auto-deploy answer %v", a), rec, rec.Body.String())
		rec = call(h, http.MethodPost, "/api/v1/bindings/"+bindingA.String()+"/actions/deploy", "operator", `{"version_id":"`+versionA.String()+`"}`)
		check(fmt.Sprintf("deploy answer %v", a), rec, rec.Body.String())
	}
	answer = nil
	// Refused before the handler: wrong role, no step-up, a token, the license lock, an oversized body.
	for _, id := range []string{"operator", "auditor", "", "admin", "alice_operate_admin"} {
		rec := call(h, http.MethodPost, "/api/v1/key-vaults", id, bodies[0])
		check("create as "+id, rec, rec.Body.String())
		rec = callWith(h, http.MethodPut, creds, id, credBody, map[string]string{"If-Match": `"3"`})
		check("replace as "+id, rec, rec.Body.String())
	}
	rec := call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", `{"pfx_base64":"`+strings.Repeat("A", maxVaultBody)+`","client_secret":"`+secret+`"}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	check("oversized", rec, rec.Body.String())
	d.License.(*fakeLicense).set(license.ErrLocked)
	rec = call(h, http.MethodPost, "/api/v1/key-vaults", "admin-stepup", bodies[0])
	check("in lock", rec, rec.Body.String())
	// The log and the audit rows the API wrote.
	for _, m := range markers {
		assert.NotContains(t, logs.String(), m, "log")
	}
	for _, e := range d.Audit.(*fakeAudit).Events() {
		for k, v := range e.Details {
			for _, m := range markers {
				assert.NotContains(t, k+"="+v, m, "audit %s", e.Action)
			}
		}
	}
}

// A step's reason param is shown only when it is a registered reason: the engine's "state_changed" (a Key
// Vault deployment that follows a re-read state) never reaches a client as a raw key.
func TestKVSecretStepSkippedParamIsNotShown(t *testing.T) {
	assert.Empty(t, stepParams(map[string]string{"reason": "state_changed"}))
	assert.Equal(t, map[string]string{"reason": "azure.forbidden"}, stepParams(map[string]string{"reason": "azure.forbidden"}))
}

// A secret field is unescaped into the handler's own bytes exactly as encoding/json would have done.
func TestSecretTextUnescapesLikeJSON(t *testing.T) {
	for _, in := range []string{"plain", "line1\nline2\r\n\t", `quote " back \ slash / ok`, "café 世界", "emoji \U0001F600", "<>&"} {
		var got secretText
		require.NoError(t, got.UnmarshalJSON([]byte(mustJSON(in))), in)
		assert.Equal(t, in, string(got))
	}
	var got secretText
	require.NoError(t, got.UnmarshalJSON([]byte(`"é😀\/\b\f"`)))
	assert.Equal(t, "é\U0001F600/\b\f", string(got))
	require.NoError(t, got.UnmarshalJSON([]byte("null")))
	assert.Error(t, got.UnmarshalJSON([]byte("12")))
}
