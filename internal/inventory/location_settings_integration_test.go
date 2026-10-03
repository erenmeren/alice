//go:build integration

package inventory_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

func ptr[T any](v T) *T { return &v }

func TestUpdateLocationVerificationSettings(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Loc", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	found := providers.DiscoveryResult{Nginx: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), l)}}
	_, err := h.svc.Reconcile(h.ctx, web.ID, found)
	require.NoError(t, err)
	loc := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	require.Equal(t, 1, loc.Version)

	got, err := h.svc.UpdateLocation(h.ctx, admin, loc.ID, loc.Version, inventory.LocationPatch{VerifyPort: ptr(8443),
		VerifySNI: ptr(" Check.Example.TEST ")})
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	require.NotNil(t, got.VerifyPort)
	assert.Equal(t, 8443, *got.VerifyPort)
	assert.Equal(t, "check.example.test", got.VerifySNI)
	assert.False(t, got.SkipVerify)
	assert.Equal(t, loc.CertPath, got.CertPath)
	assert.Equal(t, []map[string]string{{"location_id": loc.ID.String(), "verify_port": "8443", "verify_sni": "check.example.test",
		"skip_verify": "false"}}, h.auditDetails("location.updated"))

	_, err = h.svc.UpdateLocation(h.ctx, admin, loc.ID, loc.Version, inventory.LocationPatch{SkipVerify: ptr(true)})
	require.ErrorIs(t, err, inventory.ErrVersionMismatch)

	// An unchanged scan does not stale the version; the fields a scan writes never touch the settings.
	_, err = h.svc.Reconcile(h.ctx, web.ID, found)
	require.NoError(t, err)
	again := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	assert.Equal(t, 2, again.Version)
	assert.Equal(t, "check.example.test", again.VerifySNI)

	for _, tc := range []struct {
		p      inventory.LocationPatch
		fields map[string]string
	}{
		{inventory.LocationPatch{VerifyPort: ptr(70000)}, map[string]string{"verify_port": validate.OutOfRange}},
		{inventory.LocationPatch{VerifyPort: ptr(-1)}, map[string]string{"verify_port": validate.OutOfRange}},
		{inventory.LocationPatch{VerifySNI: ptr("Bad Name")}, map[string]string{"verify_sni": validate.Pattern}},
		{inventory.LocationPatch{VerifySNI: ptr("192.0.2.1")}, map[string]string{"verify_sni": validate.Pattern}},
		{inventory.LocationPatch{VerifySNI: ptr("*.example.test")}, map[string]string{"verify_sni": validate.Pattern}},
		{inventory.LocationPatch{VerifySNI: ptr(strings.Repeat("a.", 127) + "a")}, map[string]string{"verify_sni": validate.Pattern}},
		{inventory.LocationPatch{}, map[string]string{"verify_port": validate.Required, "verify_sni": validate.Required,
			"skip_verify": validate.Required}},
	} {
		_, err := h.svc.UpdateLocation(h.ctx, admin, loc.ID, 2, tc.p)
		assert.Equal(t, tc.fields, fieldsOf(err), "%+v", tc.p)
	}

	// 0 and "" clear (NULL, never 0 or ''); skip_verify is stored and audited.
	got, err = h.svc.UpdateLocation(h.ctx, admin, loc.ID, 2, inventory.LocationPatch{VerifyPort: ptr(0), VerifySNI: ptr(""), SkipVerify: ptr(true)})
	require.NoError(t, err)
	assert.Nil(t, got.VerifyPort)
	assert.Equal(t, "", got.VerifySNI)
	assert.True(t, got.SkipVerify)
	assert.Equal(t, 3, got.Version)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificate_locations WHERE id = $1 AND verify_port IS NULL AND verify_sni IS NULL AND skip_verify",
		loc.ID))
	assert.Equal(t, map[string]string{"location_id": loc.ID.String(), "verify_port": "", "verify_sni": "", "skip_verify": "true"},
		h.auditDetails("location.updated")[1])

	// A field left out keeps its value.
	got, err = h.svc.UpdateLocation(h.ctx, admin, loc.ID, 3, inventory.LocationPatch{VerifyPort: ptr(443)})
	require.NoError(t, err)
	assert.True(t, got.SkipVerify)
	assert.Equal(t, 443, *got.VerifyPort)

	_, err = h.svc.UpdateLocation(h.ctx, admin, uuid.Must(uuid.NewV7()), 1, inventory.LocationPatch{SkipVerify: ptr(false)})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, web.ID))
	_, err = h.svc.UpdateLocation(h.ctx, admin, loc.ID, 4, inventory.LocationPatch{SkipVerify: ptr(false)})
	require.ErrorIs(t, err, inventory.ErrNotFound, "a location of a deleted server")
	assert.Equal(t, 3, h.audits("location.updated"))
}
