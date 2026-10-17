//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R38 item 9: uploads, signing requests and location settings are refused while the license is
// locked (the route's class is ClassChange; the service checks too).
func TestCertificateChangesAreRefusedInLock(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"), l)}})
	require.NoError(t, err)
	loc := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	csr, err := h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "b.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)

	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	fresh := ca.Issue(pki.Opts{CommonName: "new.example.test"}, h.clock.Now())
	_, _, err = h.svc.UploadCertificate(h.ctx, admin, pemUpload(fresh))
	require.ErrorIs(t, err, license.ErrLocked)
	_, _, err = h.svc.UploadCertificate(h.ctx, admin, inventory.UploadInput{PFXBase64: "eA=="})
	require.ErrorIs(t, err, license.ErrLocked)
	_, err = h.svc.CreateCSR(h.ctx, admin, inventory.CSRInput{CommonName: "a.example.test", KeyType: "ecdsa-p256"})
	require.ErrorIs(t, err, license.ErrLocked)
	_, _, err = h.svc.CompleteCSR(h.ctx, admin, csr.ID, string(fresh.FullchainPEM), "")
	require.ErrorIs(t, err, license.ErrLocked)
	_, err = h.svc.CancelCSR(h.ctx, admin, csr.ID)
	require.ErrorIs(t, err, license.ErrLocked)
	port := 8443
	_, err = h.svc.UpdateLocation(h.ctx, admin, loc.ID, loc.Version, inventory.LocationPatch{VerifyPort: &port})
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM managed_private_keys"))
	assert.Equal(t, []string{"locked", "locked"}, rejectReasons(h))
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", got.Status)

	// Reads stay available.
	_, err = h.svc.ListCSRs(h.ctx)
	require.NoError(t, err)
	_, err = h.svc.GetLocation(h.ctx, loc.ID)
	require.NoError(t, err)
}
