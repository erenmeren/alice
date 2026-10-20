//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R52 item 1: the file observation has its own clock. A scan that read the file's content (a certificate, or that the
// file holds none) is an observation of it; a scan that names the location but could not read the file moves
// last_seen_at only, and keeps the certificate and the time of the last observation.
func TestFileObservationTimeIsTheTimeTheFileWasRead(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	loc := cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")
	read := h.clock.Now()
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(loc, leaf)}})
	require.NoError(t, err)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	observed := func() time.Time {
		var at time.Time
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT file_observed_at FROM certificate_locations WHERE id = $1", l.ID).Scan(&at))
		return at.UTC()
	}
	assert.Equal(t, read, observed())

	h.clock.Advance(time.Hour)
	unread := loc
	unread.Problem = providers.CertProblemUnreadable
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{{Location: unread}}})
	require.NoError(t, err)
	got := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	assert.Equal(t, h.clock.Now(), got.LastSeenAt, "the scan named the location")
	assert.Equal(t, read, observed(), "but did not read the file: the observation keeps its time")
	require.NotNil(t, got.Certificate)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), got.Certificate.Fingerprint, "and its certificate")
	assert.Nil(t, got.Observation, "an unbound location has no observation model")

	h.clock.Advance(time.Hour)
	gone := loc
	gone.Problem = providers.CertProblemMissing
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{{Location: gone}}})
	require.NoError(t, err)
	assert.Equal(t, h.clock.Now(), observed(), "a file found missing is an observation too")
}

// A location that follows no binding has nothing desired: the drift actions refuse it (R52).
func TestDriftActionsNeedABinding(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), leaf)}})
	require.NoError(t, err)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	a := admin
	_, err = h.svc.SetDriftMode(h.ctx, a, l.ID, inventory.DriftModeObserve, true)
	assert.ErrorIs(t, err, inventory.ErrDriftNotBound)
	_, err = h.svc.RepairDrift(h.ctx, a, l.ID, true)
	assert.ErrorIs(t, err, inventory.ErrDriftNotBound)
	o, err := h.svc.LocationObservation(h.ctx, l.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.HealthUnmanaged, o.Health)
	n, err := h.svc.ScheduleDriftObservations(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "an unbound location is not observed")
	assert.Zero(t, h.count("SELECT count(*) FROM location_observations"), "and the refused mode left no row")
}
