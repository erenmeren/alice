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
)

func sampleBinding(auto bool) inventory.Binding {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	dep := uuid.MustParse("0192d000-0000-7000-8000-0000000000b1")
	return inventory.Binding{
		BindingSummary:  inventory.BindingSummary{ID: bindingA, AutoDeploy: auto, LocationCount: 1, Version: 4, CreatedAt: at},
		KVCertificateID: kvCertID, VaultID: vaultID, CertificateName: "web-cert", VaultName: "prod-vault",
		Locations: []inventory.BindingLocation{{LocationID: locationA, TargetID: targetID, TargetName: "web-01", CertPath: "/etc/ssl/a.pem",
			State: inventory.BindingLocationDeployed, Version: strings.Repeat("a", 32), DeploymentID: &dep}},
	}
}

func TestCreateBindingHandler(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	var in inventory.BindingInput
	inv.CreateBindingFn = func(_ context.Context, _ inventory.Actor, i inventory.BindingInput) (inventory.Binding, error) {
		in = i
		return sampleBinding(false), nil
	}
	body := `{"kv_certificate_id":"` + kvCertID.String() + `","location_ids":["` + locationA.String() + `","` + locationB.String() + `"]}`
	rec := call(h, http.MethodPost, "/api/v1/bindings", "operator", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, kvCertID, in.KVCertificateID)
	assert.Equal(t, []uuid.UUID{locationA, locationB}, in.LocationIDs)
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	assert.Equal(t, "/api/v1/bindings/"+bindingA.String(), rec.Header().Get("Location"))
	b := jsonObj(t, rec)
	assert.Equal(t, false, b["auto_deploy"])
	assert.Equal(t, "deployed", b["locations"].([]any)[0].(map[string]any)["state"])
	// Body rules.
	for _, bad := range []string{`{"kv_certificate_id":"x","location_ids":[]}`, `{"kv_certificate_id":"` + kvCertID.String() + `","location_ids":["x"]}`,
		`{"kv_certificate_id":"` + kvCertID.String() + `","location_ids":["` + locationA.String() + `","` + locationA.String() + `"]}`} {
		assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, "/api/v1/bindings", "operator", bad).Code, bad)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/bindings", "operator", strings.Replace(body, "{", `{"extra":1,`, 1)).Code)
	// Refusals.
	for _, tc := range []struct {
		err  error
		want string
	}{
		{inventory.ErrBindingExists, "ALC-AKV-0019"}, {&inventory.LocationRefusalError{LocationID: locationB, Err: inventory.ErrLocationBound}, "ALC-AKV-0018"},
		{inventory.ErrNotExportable, "ALC-AKV-0013"}, {inventory.ErrKVCertificateMissing, "ALC-AKV-0015"},
		{&inventory.LocationRefusalError{LocationID: locationB, Err: &inventory.KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"}}, "ALC-CRT-0010"},
	} {
		inv.CreateBindingFn = func(context.Context, inventory.Actor, inventory.BindingInput) (inventory.Binding, error) {
			return inventory.Binding{}, tc.err
		}
		rec := call(h, http.MethodPost, "/api/v1/bindings", "operator", body)
		assert.Equal(t, tc.want, decodeErr(t, rec).Error.Code)
		if tc.want == "ALC-AKV-0018" || tc.want == "ALC-CRT-0010" {
			assert.Contains(t, rec.Body.String(), `"location_id":"`+locationB.String()+`"`)
		}
	}
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/bindings", "auditor", body).Code)
}

func TestBindingReadPatchDelete(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	path := "/api/v1/bindings/" + bindingA.String()
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	rec := call(h, http.MethodGet, path, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/bindings/nope", "auditor", "").Code)

	var ver int
	var locs []uuid.UUID
	inv.UpdateBindingLocationsFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, l []uuid.UUID) (inventory.Binding, error) {
		ver, locs = v, l
		return sampleBinding(false), nil
	}
	body := `{"location_ids":["` + locationA.String() + `"]}`
	require.Equal(t, http.StatusOK, callWith(h, http.MethodPatch, path, "operator", body, map[string]string{"If-Match": `"4"`}).Code)
	assert.Equal(t, 4, ver)
	assert.Equal(t, []uuid.UUID{locationA}, locs)
	assert.Equal(t, http.StatusPreconditionFailed, call(h, http.MethodPatch, path, "operator", body).Code)
	inv.UpdateBindingLocationsFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrVersionMismatch
	}
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPatch, path, "operator", body, map[string]string{"If-Match": `"3"`}).Code)

	inv.DeleteBindingFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, path, "operator", "").Code)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodDelete, path, "auditor", "").Code)
}

// Adding websites to a binding that deploys automatically puts them under automatic deployment: an
// Administrator with a fresh step-up, never a token (S6). Releasing websites, or a binding that does not
// deploy automatically, stays an ordinary operation.
func TestPatchBindingAddingToAnAutoDeployingBindingIsStrict(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	path := "/api/v1/bindings/" + bindingA.String()
	calls := 0
	inv.UpdateBindingLocationsFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID) (inventory.Binding, error) {
		calls++
		return sampleBinding(true), nil
	}
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(true), nil }
	add := `{"location_ids":["` + locationA.String() + `","` + locationB.String() + `"]}`
	same := `{"location_ids":["` + locationA.String() + `"]}`
	hdr := map[string]string{"If-Match": `"4"`}
	for _, tc := range []struct {
		id, body string
		code     int
		reason   string
	}{
		{"admin", add, 403, "auth.stepup_required"},
		{"alice_operate_admin", add, 403, "auth.forbidden"},
		{"admin-stepup", add, 200, ""},
		{"admin", same, 200, ""}, // nothing added
		{"alice_operate_operator", same, 200, ""},
	} {
		calls = 0
		rec := callWith(h, http.MethodPatch, path, tc.id, tc.body, hdr)
		require.Equal(t, tc.code, rec.Code, "%s %s", tc.id, rec.Body.String())
		if tc.reason != "" {
			assert.Equal(t, tc.reason, decodeErr(t, rec).Error.Reason)
			assert.Zero(t, calls, "nothing reached inventory")
		}
	}
	// An Operator adding: inventory refuses (and audits) with ErrAdminRequired.
	inv.UpdateBindingLocationsFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrAdminRequired
	}
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPatch, path, "operator", add, hdr).Code)
	// A binding that does not deploy automatically: an Operator adds freely.
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.UpdateBindingLocationsFn = func(context.Context, inventory.Actor, uuid.UUID, int, []uuid.UUID) (inventory.Binding, error) {
		return sampleBinding(false), nil
	}
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodPatch, path, "operator", add, hdr).Code)
}

func TestSetAutoDeployHandler(t *testing.T) {
	h, inv, d := vaultDeps(t)
	path := "/api/v1/bindings/" + bindingA.String() + "/auto-deploy"
	var got []bool
	inv.SetAutoDeployFn = func(_ context.Context, a inventory.Actor, _ uuid.UUID, v int, enabled bool) (inventory.Binding, error) {
		got = append(got, enabled)
		assert.Equal(t, 4, v)
		return sampleBinding(enabled), nil
	}
	hdr := map[string]string{"If-Match": `"4"`}
	rec := callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":true}`, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, true, jsonObj(t, rec)["auto_deploy"])
	require.Equal(t, http.StatusOK, callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":false}`, hdr).Code)
	assert.Equal(t, []bool{true, false}, got)
	// enabled is required and a boolean.
	assert.Equal(t, http.StatusUnprocessableEntity, callWith(h, http.MethodPut, path, "admin-stepup", `{}`, hdr).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":"yes"}`, hdr).Code)
	assert.Equal(t, http.StatusPreconditionFailed, call(h, http.MethodPut, path, "admin-stepup", `{"enabled":true}`).Code)
	// Both directions: Administrator with step-up, no token, no Operator.
	got = nil
	for id, want := range map[string]int{"operator": 403, "operator-stepup": 403, "admin": 403, "alice_operate_admin": 403, "auditor": 403} {
		for _, body := range []string{`{"enabled":true}`, `{"enabled":false}`} {
			assert.Equal(t, want, callWith(h, http.MethodPut, path, id, body, hdr).Code, id+body)
		}
	}
	assert.Empty(t, got)
	// In lock: switching off is a safety action, the route is open and inventory decides (it refuses switching on).
	d.License.(*fakeLicense).set(licenseLocked())
	require.Equal(t, http.StatusOK, callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":false}`, hdr).Code)
	inv.SetAutoDeployFn = func(context.Context, inventory.Actor, uuid.UUID, int, bool) (inventory.Binding, error) {
		return inventory.Binding{}, licenseLocked()
	}
	assert.Equal(t, "license.locked", decodeErr(t, callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":true}`, hdr)).Error.Reason)
	// Removing a binding works in lock too.
	inv.DeleteBindingFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/bindings/"+bindingA.String(), "operator", "").Code)
}

func TestDeployBindingHandler(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	path := "/api/v1/bindings/" + bindingA.String() + "/actions/deploy"
	held := false
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	inv.KVCertificateFn = func(context.Context, uuid.UUID, uuid.UUID) (inventory.KVCertificateDetail, error) {
		return inventory.KVCertificateDetail{KVCertificate: sampleKVCertificate(), Versions: []inventory.KVVersion{{ID: versionA, Held: held, HeldReason: "license"}}}, nil
	}
	var in inventory.KVDeployInput
	var asAdmin bool
	inv.RequestKVDeploymentFn = func(_ context.Context, a inventory.Actor, i inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		in = i
		asAdmin = a.Role == "admin"
		return []inventory.RequestedDeployment{{ID: importA, JobID: jobID, LocationID: locationA, Warnings: []string{"san_mismatch"}}}, nil
	}
	body := `{"version_id":"` + versionA.String() + `","location_ids":["` + locationA.String() + `"]}`
	rec := call(h, http.MethodPost, path, "operator", body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, versionA, in.VersionID)
	assert.Equal(t, bindingA, in.BindingID)
	assert.False(t, in.ConfirmIncompleteChain, "an Operator's confirmation counts for nothing")
	d := jsonObj(t, rec)["deployments"].([]any)[0].(map[string]any)
	assert.Equal(t, jobID.String(), d["job_id"])
	assert.Equal(t, locationA.String(), d["location_id"])
	assert.Equal(t, []any{"san_mismatch"}, d["warnings"])
	// No location_ids: every website of the binding.
	require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, path, "operator", `{"version_id":"`+versionA.String()+`"}`).Code)
	assert.Empty(t, in.LocationIDs)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, path, "operator", `{}`).Code)
	// F-17: an Administrator's confirmation is passed on.
	require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, path, "admin", `{"version_id":"`+versionA.String()+`","confirm_incomplete_chain":true}`).Code)
	assert.True(t, in.ConfirmIncompleteChain)
	assert.True(t, asAdmin)

	// A held version: Administrator with step-up and no token; an Operator is refused by inventory (ALC-AKV-0022).
	held = true
	calls := 0
	inv.RequestKVDeploymentFn = func(_ context.Context, a inventory.Actor, i inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
		calls++
		if a.Role != "admin" {
			return nil, inventory.ErrHeldNeedsAdmin
		}
		return []inventory.RequestedDeployment{{ID: importA, JobID: jobID, LocationID: locationA}}, nil
	}
	rec = call(h, http.MethodPost, path, "admin", body)
	assert.Equal(t, "auth.stepup_required", decodeErr(t, rec).Error.Reason)
	rec = call(h, http.MethodPost, path, "alice_operate_admin", body)
	assert.Equal(t, "auth.forbidden", decodeErr(t, rec).Error.Reason)
	assert.Zero(t, calls)
	assert.Equal(t, http.StatusAccepted, call(h, http.MethodPost, path, "admin-stepup", body).Code)
	rec = call(h, http.MethodPost, path, "operator", body)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AKV-0022", decodeErr(t, rec).Error.Code)
	rec = call(h, http.MethodPost, path, "alice_operate_operator", body)
	assert.Equal(t, "ALC-AKV-0022", decodeErr(t, rec).Error.Code)
	// Other refusals.
	held = false
	for _, tc := range []struct {
		err  error
		want string
	}{{inventory.ErrVersionNotDeployable, "ALC-AKV-0021"}, {inventory.ErrVersionDisabled, "ALC-AKV-0014"}, {inventory.ErrNotExportable, "ALC-AKV-0013"},
		{inventory.ErrDeploymentInProgress, "ALC-DEP-0001"}} {
		inv.RequestKVDeploymentFn = func(context.Context, inventory.Actor, inventory.KVDeployInput) ([]inventory.RequestedDeployment, error) {
			return nil, tc.err
		}
		assert.Equal(t, tc.want, decodeErr(t, call(h, http.MethodPost, path, "operator", body)).Error.Code)
	}
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, path, "auditor", body).Code)
}

func TestReleaseVersionHandler(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	path := "/api/v1/targets/" + vaultID.String() + "/kv/certificates/" + kvCertID.String() + "/versions/" + versionA.String() + "/actions/release"
	var in inventory.ReleaseInput
	inv.ReleaseVersionFn = func(_ context.Context, _ inventory.Actor, i inventory.ReleaseInput) (inventory.KVVersion, error) {
		in = i
		return inventory.KVVersion{ID: versionA, Version: strings.Repeat("a", 32)}, nil
	}
	rec := call(h, http.MethodPost, path, "admin-stepup", `{"confirm_incomplete_chain":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.ReleaseInput{VaultID: vaultID, KVCertificateID: kvCertID, VersionID: versionA, ConfirmIncompleteChain: true}, in)
	assert.Equal(t, versionA.String(), jsonObj(t, rec)["id"])
	require.Equal(t, http.StatusOK, call(h, http.MethodPost, path, "admin-stepup", "").Code, "the body is optional")
	assert.False(t, in.ConfirmIncompleteChain)
	for id, want := range map[string]int{"operator": 403, "admin": 403, "alice_operate_admin": 403, "auditor": 403} {
		assert.Equal(t, want, call(h, http.MethodPost, path, id, "").Code, id)
	}
	inv.ReleaseVersionFn = func(context.Context, inventory.Actor, inventory.ReleaseInput) (inventory.KVVersion, error) {
		return inventory.KVVersion{}, inventory.ErrVersionNotHeld
	}
	assert.Equal(t, "ALC-AKV-0035", decodeErr(t, call(h, http.MethodPost, path, "admin-stepup", "")).Error.Code)
	inv.ReleaseVersionFn = func(context.Context, inventory.Actor, inventory.ReleaseInput) (inventory.KVVersion, error) {
		return inventory.KVVersion{}, inventory.ErrChainUnconfirmed
	}
	assert.Equal(t, "ALC-CRT-0011", decodeErr(t, call(h, http.MethodPost, path, "admin-stepup", "")).Error.Code)
}

func TestListDeployableLocationsHandler(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	var f inventory.LocationFilter
	bound := bindingA
	inv.ListDeployableLocationsFn = func(_ context.Context, fl inventory.LocationFilter) (inventory.DeployableLocationPage, error) {
		f = fl
		return inventory.DeployableLocationPage{Items: []inventory.DeployableLocation{{ID: locationA, TargetID: targetID, TargetName: "web-01",
			CertPath: "/a.pem", KeyPath: "/a.key", KeyType: "rsa", ServerNames: []string{"a.example.com"}, BindingID: &bound}}, NextCursor: "n"}, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/certificate-locations?key_type=rsa&unbound=true&q=web&cursor=c&limit=5", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.LocationFilter{Query: "web", KeyType: "rsa", Unbound: true, Cursor: "c", Limit: 5}, f)
	assert.Equal(t, "n", jsonObj(t, rec)["next_cursor"])
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/certificate-locations?unbound=maybe", "auditor", "").Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/certificate-locations?limit=0", "auditor", "").Code)
}
