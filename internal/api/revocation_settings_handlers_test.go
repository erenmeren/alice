package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
)

// fakeRevocation is the RevocationService of the handler tests: a switch with a version, as the inventory keeps it.
type fakeRevocation struct {
	set   inventory.RevocationSettings
	saved []bool
	actor audit.Actor
}

func (f *fakeRevocation) RevocationSettings(context.Context) (inventory.RevocationSettings, error) {
	return f.set, nil
}

func (f *fakeRevocation) SaveRevocationSettings(_ context.Context, a audit.Actor, version int, enabled bool) (inventory.RevocationSettings, error) {
	if version != f.set.Version {
		return inventory.RevocationSettings{}, inventory.ErrRevocationSettingsVersion
	}
	f.set = inventory.RevocationSettings{Enabled: enabled, Version: version + 1}
	f.saved, f.actor = append(f.saved, enabled), a
	return f.set, nil
}

// The revocation check switch (R64, D5, HB-16/17): Settings, an Administrator with a fresh step-up, If-Match required;
// a stale version is 412; an Operator gets 403.
func TestRevocationSettingsRoutes(t *testing.T) {
	d := testDeps(t, nil)
	fr := &fakeRevocation{set: inventory.RevocationSettings{Enabled: true}}
	d.Revocation = fr
	h := NewHandler(d)
	const path = "/api/v1/settings/revocation-checks"

	rec := call(h, http.MethodGet, path, "admin-stepup", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"enabled":true,"version":0}`, rec.Body.String())
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))

	rec = call(h, http.MethodPut, path, "admin-stepup", `{"enabled":false}`)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "If-Match is required")
	assert.Equal(t, ErrPreconditionFailed.Code, decodeErr(t, rec).Error.Code)

	rec = callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":false}`, map[string]string{"If-Match": `"0"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"enabled":false,"version":1}`, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.Equal(t, []bool{false}, fr.saved)
	assert.Equal(t, adminID, fr.actor.ID)

	rec = callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":true}`, map[string]string{"If-Match": `"0"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a stale version")
	assert.Equal(t, ErrPreconditionFailed.Code, decodeErr(t, rec).Error.Code)

	rec = callWith(h, http.MethodPut, path, "admin-stepup", `{"enabled":true,"x":1}`, map[string]string{"If-Match": `"1"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an unknown member")
	rec = callWith(h, http.MethodPut, path, "admin-stepup", `{}`, map[string]string{"If-Match": `"1"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "enabled is required")

	rec = callWith(h, http.MethodPut, path, "admin", `{"enabled":true}`, map[string]string{"If-Match": `"1"`})
	assert.Equal(t, http.StatusForbidden, rec.Code, "a fresh step-up is needed")
	assert.Equal(t, ErrStepUpRequired.Code, decodeErr(t, rec).Error.Code)
	rec = call(h, http.MethodGet, path, "operator-stepup", "")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, []bool{false}, fr.saved, "nothing else was saved")

	d.Revocation = nil
	rec = call(NewHandler(d), http.MethodGet, path, "admin-stepup", "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "not configured")
}
