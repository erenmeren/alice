package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
)

func licenseLocked() error { return license.ErrLocked }

func sampleImport(state, code string) inventory.KVImport {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	return inventory.KVImport{ID: importA, CertificateID: csrID, VaultID: vaultID, Name: "web-cert", State: state, ErrorCode: code,
		JobID: &jobID, CreatedAt: at, SentAt: &at}
}

func TestImportRoutes(t *testing.T) {
	h, inv, d := vaultDeps(t)
	path := "/api/v1/certificates/" + csrID.String() + "/actions/import-to-key-vault"
	var in inventory.ImportInput
	inv.RequestImportFn = func(_ context.Context, _ inventory.Actor, i inventory.ImportInput) (inventory.KVImport, error) {
		in = i
		return sampleImport(inventory.ImportQueued, ""), nil
	}
	body := `{"target_id":"` + vaultID.String() + `","name":"web-cert","confirm_new_version":true}`
	rec := call(h, http.MethodPost, path, "admin-stepup", body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.ImportInput{VaultID: vaultID, CertificateID: csrID, Name: "web-cert", ConfirmExisting: true}, in)
	out := jsonObj(t, rec)
	assert.Equal(t, jobID.String(), out["job_id"])
	assert.Equal(t, "/api/v1/jobs/"+jobID.String(), out["status_url"])
	assert.Equal(t, "queued", out["import"].(map[string]any)["state"])
	// Body rules and the name grammar (checked before inventory).
	for _, bad := range []string{`{"target_id":"x","name":"a"}`, `{"target_id":"` + vaultID.String() + `","name":"has space"}`,
		`{"target_id":"` + vaultID.String() + `","name":""}`, `{"target_id":"` + vaultID.String() + `","name":"` + strings.Repeat("a", 128) + `"}`} {
		assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, path, "admin-stepup", bad).Code, bad)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, path, "admin-stepup", strings.Replace(body, "{", `{"extra":1,`, 1)).Code)
	assert.Equal(t, http.StatusRequestEntityTooLarge, call(h, http.MethodPost, path, "admin-stepup", `{"name":"`+strings.Repeat("a", 5<<10)+`"}`).Code)
	// Refusals.
	for _, tc := range []struct {
		err  error
		want string
		code int
	}{{&inventory.ImportConfirmError{CertificateName: "web-cert", AutoDeploy: true, Bound: true}, "ALC-AKV-0023", 409}, {inventory.ErrImportInProgress, "ALC-AKV-0024", 409},
		{inventory.ErrNoPrivateKey, "ALC-CRT-0009", 409}, {inventory.ErrCertificateExpired, "ALC-CRT-0003", 422},
		{inventory.ErrVaultUnavailable, "ALC-AKV-0033", 409}, {inventory.ErrAdminRequired, "ALC-AUTH-0002", 403}} {
		inv.RequestImportFn = func(context.Context, inventory.Actor, inventory.ImportInput) (inventory.KVImport, error) {
			return inventory.KVImport{}, tc.err
		}
		rec := call(h, http.MethodPost, path, "admin-stepup", body)
		assert.Equal(t, tc.code, rec.Code, tc.want)
		assert.Equal(t, tc.want, decodeErr(t, rec).Error.Code)
		if tc.want == "ALC-AKV-0023" {
			assert.Contains(t, rec.Body.String(), `"certificate_name":"web-cert"`)
			assert.Contains(t, rec.Body.String(), `"auto_deploy_follows":"true"`)
		}
	}
	// Who may: Administrator with step-up, never a token (a private key leaves Alice).
	calls := 0
	inv.RequestImportFn = func(context.Context, inventory.Actor, inventory.ImportInput) (inventory.KVImport, error) {
		calls++
		return sampleImport(inventory.ImportQueued, ""), nil
	}
	for id, want := range map[string]int{"operator": 403, "operator-stepup": 403, "auditor": 403, "admin": 403, "alice_operate_admin": 403} {
		assert.Equal(t, want, call(h, http.MethodPost, path, id, body).Code, id)
	}
	assert.Zero(t, calls)
	d.License.(*fakeLicense).set(license.ErrLocked)
	assert.Equal(t, "license.locked", decodeErr(t, call(h, http.MethodPost, path, "admin-stepup", body)).Error.Reason)
}

func TestImportReadRoutes(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	base := "/api/v1/targets/" + vaultID.String() + "/kv/imports"
	var limit int
	inv.ListImportsFn = func(_ context.Context, v uuid.UUID, l int) ([]inventory.KVImport, error) {
		assert.Equal(t, vaultID, v)
		limit = l
		return []inventory.KVImport{sampleImport(inventory.ImportUncertain, ""), sampleImport(inventory.ImportFailed, "kv.import_confirm_needed")}, nil
	}
	rec := call(h, http.MethodGet, base+"?limit=10", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 10, limit)
	items := jsonObj(t, rec)["items"].([]any)
	require.Len(t, items, 2)
	assert.Equal(t, "uncertain", items[0].(map[string]any)["state"])
	e := items[1].(map[string]any)["error"].(map[string]any)
	assert.Equal(t, "ALC-AKV-0023", e["code"])
	assert.Equal(t, map[string]any{"certificate_name": "web-cert"}, e["params"])
	assert.Nil(t, jsonObj(t, rec)["next_cursor"])
	// certificate_id narrows the list.
	rec = call(h, http.MethodGet, base+"?certificate_id="+uuid.NewString(), "auditor", "")
	assert.Empty(t, jsonObj(t, rec)["items"])
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, base+"?limit=0", "auditor", "").Code)
	inv.ImportFn = func(_ context.Context, v, id uuid.UUID) (inventory.KVImport, error) {
		assert.Equal(t, vaultID, v)
		assert.Equal(t, importA, id)
		return sampleImport(inventory.ImportSucceeded, ""), nil
	}
	rec = call(h, http.MethodGet, base+"/"+importA.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "succeeded", jsonObj(t, rec)["state"])
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, base+"/nope", "auditor", "").Code)
}
