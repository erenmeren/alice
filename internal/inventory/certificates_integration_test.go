//go:build integration

package inventory_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

var nginxOK = &providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.22.1"}

// cl builds a supported location with one server on port 443 using the names.
func cl(path, key string, names ...string) providers.CertLocation {
	return providers.CertLocation{CertPath: path, KeyPath: key, ResolvedCertPath: path, Supported: true, KeyExists: true,
		KeyMode: "0600", KeyOwner: "root", KeyGroup: "root",
		Servers: []providers.CertServer{{Names: names, Listens: []providers.CertListen{{Port: 443}}, File: "/etc/nginx/sites-enabled/default", Line: 1}}}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// dc is the discovered file at loc holding leaf's full chain.
func dc(loc providers.CertLocation, leaf pki.Leaf) providers.DiscoveredCertificate {
	return providers.DiscoveredCertificate{Location: loc, PEMChain: leaf.FullchainPEM, FileSHA256: sha(leaf.FullchainPEM)}
}

func byPath(t *testing.T, h *harness, target uuid.UUID, missing bool) map[string]inventory.CertificateLocation {
	t.Helper()
	locs, err := h.svc.ListLocations(h.ctx, target, missing)
	require.NoError(t, err)
	out := map[string]inventory.CertificateLocation{}
	for _, l := range locs {
		out[l.CertPath] = l
	}
	return out
}

// locationRows is every stored column of the target's locations (as the owner reads them), less
// the columns named in without.
func locationRows(t *testing.T, h *harness, target uuid.UUID, without ...string) []string {
	t.Helper()
	if without == nil {
		without = []string{}
	}
	rows, err := h.db.Owner.Query(h.ctx, "SELECT (to_jsonb(l) - $2::text[])::text FROM certificate_locations l WHERE target_id = $1 ORDER BY id",
		target, without)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// nginxTarget adds a connected target of the Nginx type (the certificate half is reconciled only
// for those). The harness has no nginx provider, so the type is set as the owner.
func nginxTarget(t *testing.T, h *harness, a inventory.Actor, name string) inventory.Target {
	t.Helper()
	tg := okTarget(t, h, a, name)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET type = 'nginx' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	tg.Type = inventory.TypeNginx
	return tg
}

func withRoots(pool *x509.CertPool) harnessOption {
	return func(c *inventory.Config) { c.Roots = pool }
}

func TestReconcileStoresCertificatesAndLocations(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web1, web2 := nginxTarget(t, h, admin, "web-01"), nginxTarget(t, h, admin, "web-02")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	shared := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	for _, tg := range []inventory.Target{web1, web2} {
		sum, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{Nginx: nginxOK,
			Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), shared)}})
		require.NoError(t, err)
		assert.Equal(t, inventory.ReconcileSummary{Certificates: 1, Locations: 1, NewLocations: 1}, sum)
	}
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1, "the same certificate on two servers is one certificate")
	c := page.Items[0]
	assert.Equal(t, pki.Fingerprint(shared.Cert), c.Fingerprint)
	assert.Equal(t, "discovered", c.Source)
	assert.Equal(t, 2, c.LocationCount)
	assert.False(t, c.HasPrivateKey, "a discovered certificate never brings its key")
	assert.Equal(t, "www.example.test", c.SubjectCN)
	assert.Equal(t, []string{"www.example.test"}, c.SANs)
	assert.Equal(t, "ecdsa", c.KeyAlgorithm)
	assert.Equal(t, 256, c.KeyBits)
	assert.Equal(t, shared.Cert.NotAfter.UTC(), c.NotAfter)
	assert.Empty(t, c.PEMChain, "the list leaves the chain out")
	locs, err := h.svc.ListLocations(h.ctx, web1.ID, false)
	require.NoError(t, err)
	require.Len(t, locs, 1)
	l := locs[0]
	assert.Equal(t, "ecdsa", l.KeyType)
	require.NotNil(t, l.Certificate)
	assert.Equal(t, pki.Fingerprint(shared.Cert), l.Certificate.Fingerprint)
	assert.Equal(t, c.ID, l.Certificate.ID)
	assert.True(t, l.Supported)
	assert.Equal(t, sha(shared.FullchainPEM), l.CertFileSHA256, "the helper's file hash, verbatim")
	assert.Equal(t, "web-01", l.TargetName)
	assert.Equal(t, "/etc/nginx/ssl/www.key", l.KeyPath)
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}},
		File: "/etc/nginx/sites-enabled/default", Line: 1}}, l.Servers)
	assert.Equal(t, []string{}, l.Warnings)
	assert.Equal(t, 1, l.Version)
	assert.Nil(t, l.ActiveDeploymentID)
	full, err := h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, string(shared.FullchainPEM), full.PEMChain)
	assert.Len(t, full.Locations, 2)

	// A second identical run updates, never duplicates (S3 AC4), and changes nothing else.
	before := locationRows(t, h, web1.ID, "last_seen_at")
	h.clock.Advance(time.Hour)
	sum, err := h.svc.Reconcile(h.ctx, web1.ID, providers.DiscoveryResult{Nginx: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), shared)}})
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Certificates: 1, Locations: 1}, sum)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM certificate_locations"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates"))
	got, err := h.svc.GetLocation(h.ctx, l.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version, "an unchanged location keeps its version (an If-Match stays valid)")
	assert.Equal(t, h.clock.Now(), got.LastSeenAt)
	assert.Equal(t, l.FirstSeenAt, got.FirstSeenAt)
	assert.Equal(t, before, locationRows(t, h, web1.ID, "last_seen_at"), "only last_seen_at moved")
	assert.Zero(t, h.audits("location.changed_outside"))
	d := h.auditDetails("target.discovered")
	require.Len(t, d, 3)
	assert.Equal(t, map[string]string{"key_count": "0", "new_count": "0", "missing_count": "0", "partial": "false",
		"certificate_count": "1", "location_count": "1", "new_location_count": "0", "missing_location_count": "0",
		"skipped_location_count": "0"}, d[2])
}

// The discovery order of the certificates changes nothing.
func TestReconcileIsOrderIndependent(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	var found []providers.DiscoveredCertificate
	for i := range 6 {
		name := fmt.Sprintf("s%d.example.test", i)
		found = append(found, dc(cl("/etc/nginx/ssl/"+name+".crt", "/etc/nginx/ssl/"+name+".key", name),
			ca.Issue(pki.Opts{CommonName: name, SANs: []string{name}}, h.clock.Now())))
	}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: found})
	require.NoError(t, err)
	before := locationRows(t, h, web.ID)
	reversed := slices.Clone(found)
	slices.Reverse(reversed)
	sum, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: reversed})
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Certificates: 6, Locations: 6}, sum)
	assert.Equal(t, before, locationRows(t, h, web.ID), "the same clock: nothing changed at all")
}

func TestReconcileMissingChangedOutsideAndInvalidConfiguration(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	a, b, a2 := ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now()), ca.Issue(pki.Opts{CommonName: "b.example.test"}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now())
	locA, locB := cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", "a.example.test"), cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "b.example.test")
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
	require.NoError(t, err)

	// An invalid configuration changes no location (F-20 spirit: no partial data).
	sum, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigValid: false}})
	require.NoError(t, err)
	assert.Zero(t, sum.MissingLocations)
	locs, _ := h.svc.ListLocations(h.ctx, web.ID, false)
	assert.Len(t, locs, 2)

	// b disappears; a's file now holds another certificate Alice did not deploy.
	sum, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a2)}})
	require.NoError(t, err)
	assert.Equal(t, 1, sum.MissingLocations)
	paths := byPath(t, h, web.ID, true)
	assert.NotNil(t, paths["/etc/nginx/ssl/b.crt"].MissingSince)
	assert.Equal(t, 2, paths["/etc/nginx/ssl/b.crt"].Version)
	require.NotNil(t, paths["/etc/nginx/ssl/a.crt"].ChangedOutsideAt)
	assert.Equal(t, pki.Fingerprint(a2.Cert), paths["/etc/nginx/ssl/a.crt"].Certificate.Fingerprint, "the location moves to the new certificate")
	assert.Equal(t, 2, paths["/etc/nginx/ssl/a.crt"].Version)
	assert.Len(t, byPath(t, h, web.ID, false), 1, "missing locations only when asked")
	d := h.auditDetails("location.changed_outside")
	require.Len(t, d, 1)
	assert.Equal(t, pki.Fingerprint(a.Cert), d[0]["previous_fingerprint"])
	assert.Equal(t, pki.Fingerprint(a2.Cert), d[0]["fingerprint"])
	assert.Equal(t, "/etc/nginx/ssl/a.crt", d[0]["cert_path"])
	assert.Equal(t, web.ID.String(), d[0]["target_id"])
	assert.Equal(t, 3, h.count("SELECT count(*) FROM certificates"), "a certificate no longer used stays in the inventory")
	old, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: pki.Fingerprint(a.Cert)})
	require.NoError(t, err)
	require.Len(t, old.Items, 1)
	assert.Zero(t, old.Items[0].LocationCount)

	// b comes back: no longer missing; the same scan again audits nothing new.
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a2), dc(locB, b)}})
	require.NoError(t, err)
	l, err := h.svc.GetLocation(h.ctx, paths["/etc/nginx/ssl/b.crt"].ID)
	require.NoError(t, err)
	assert.Nil(t, l.MissingSince)
	assert.Equal(t, 1, h.audits("location.changed_outside"))

	// A certificate Alice deployed (deployed_fingerprint) is not a change outside Alice.
	a3 := ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now())
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET deployed_fingerprint = $2, changed_outside_at = NULL WHERE id = $1",
		paths["/etc/nginx/ssl/a.crt"].ID, pki.Fingerprint(a3.Cert))
	require.NoError(t, err)
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a3), dc(locB, b)}})
	require.NoError(t, err)
	l, err = h.svc.GetLocation(h.ctx, paths["/etc/nginx/ssl/a.crt"].ID)
	require.NoError(t, err)
	assert.Nil(t, l.ChangedOutsideAt)
	assert.Equal(t, pki.Fingerprint(a3.Cert), l.Certificate.Fingerprint)
	assert.Equal(t, 1, h.audits("location.changed_outside"))

	// A file that is gone is no certificate any more; one Alice cannot read keeps the last one known.
	gone, unreadable := locA, locB
	gone.Supported, gone.Unsupported, gone.Problem = false, providers.UnsupportedFile, providers.CertProblemMissing
	unreadable.Supported, unreadable.Unsupported, unreadable.Problem = false, providers.UnsupportedFile, providers.CertProblemUnreadable
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: gone}, {Location: unreadable}}})
	require.NoError(t, err)
	paths = byPath(t, h, web.ID, false)
	assert.Nil(t, paths["/etc/nginx/ssl/a.crt"].Certificate)
	assert.Empty(t, paths["/etc/nginx/ssl/a.crt"].CertFileSHA256)
	require.NotNil(t, paths["/etc/nginx/ssl/b.crt"].Certificate)
	assert.Equal(t, pki.Fingerprint(b.Cert), paths["/etc/nginx/ssl/b.crt"].Certificate.Fingerprint)
	assert.False(t, paths["/etc/nginx/ssl/b.crt"].Supported)
	assert.Equal(t, providers.CertProblemUnreadable, paths["/etc/nginx/ssl/b.crt"].Problem)
	assert.Equal(t, 1, h.audits("location.changed_outside"))
}

// Requirement: a result without a usable Nginx configuration (SSH only, a configuration error
// class, Nginx not found) leaves every known location exactly as it is; the facts say why.
func TestReconcileNeverDestroysOnABadScan(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	a, b := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "b.example.test", SANs: []string{"b.example.test"}}, h.clock.Now())
	locA, locB := cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", "a.example.test"), cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "b.example.test")
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
	require.NoError(t, err)
	known := locationRows(t, h, web.ID)

	// Every case reports a with another certificate and b gone, plus a new location c.
	a2 := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, h.clock.Now())
	cert := ca.Issue(pki.Opts{CommonName: "c.example.test", SANs: []string{"c.example.test"}}, h.clock.Now())
	locC := cl("/etc/nginx/ssl/c.crt", "/etc/nginx/ssl/c.key", "c.example.test")
	changed := []providers.DiscoveredCertificate{dc(locA, a2), dc(locC, cert)}
	untrusted := &providers.NginxFacts{Found: true, ConfigError: providers.ConfigErrUntrusted, ConfigErrorReason: providers.ConfigReasonNotRootControlled,
		ConfigErrorFile: "/etc/nginx/conf.d/x.conf"}
	cases := []struct {
		name  string
		res   providers.DiscoveryResult
		facts *providers.NginxFacts
	}{
		{name: "ssh only", res: providers.DiscoveryResult{SSHD: sshdRead, Certificates: changed}},
		{name: "syntax error", res: providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigError: providers.ConfigErrSyntax}},
			facts: &providers.NginxFacts{Found: true, ConfigError: providers.ConfigErrSyntax, Version: "1.22.1"}},
		{name: "untrusted", res: providers.DiscoveryResult{Nginx: untrusted}, facts: &providers.NginxFacts{Found: true, ConfigError: providers.ConfigErrUntrusted,
			ConfigErrorReason: providers.ConfigReasonNotRootControlled, ConfigErrorFile: "/etc/nginx/conf.d/x.conf", Version: "1.22.1"}},
		{name: "unsupported with certificates", res: providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigError: providers.ConfigErrUnsupported},
			Certificates: changed}},
		{name: "valid flag with an error class", res: providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigValid: true,
			ConfigError: providers.ConfigErrUnsupported}, Certificates: changed}},
		{name: "nginx not found", res: providers.DiscoveryResult{Nginx: &providers.NginxFacts{ConfigValid: true}, Certificates: changed},
			facts: &providers.NginxFacts{ConfigValid: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.clock.Advance(time.Hour)
			sum, err := h.svc.Reconcile(h.ctx, web.ID, tc.res)
			require.NoError(t, err)
			assert.Zero(t, sum.MissingLocations+sum.NewLocations+sum.Locations)
			assert.Equal(t, known, locationRows(t, h, web.ID), "the known locations are untouched, nothing new is stored")
			assert.Zero(t, h.audits("location.changed_outside"))
			got, err := h.svc.GetTarget(h.ctx, web.ID)
			require.NoError(t, err)
			if tc.facts != nil {
				assert.Equal(t, tc.facts, got.Facts.Nginx, "the facts say why")
			}
		})
	}
}

// Controller ruling (fix round 1): a usable configuration updates every location it reports and
// inserts new ones, whatever else the scan says; only marking a known location missing needs the
// whole list of locations, which only locations_dropped denies. Partial (an SSH file),
// list_truncated (names, listens or servers cut inside a location) and too_many_files (the
// helper's file descriptions cut) never leave a location out.
func TestReconcileIncompleteScansUpdateAndMarkMissingOnlyFromTheWholeList(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	a, b := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "b.example.test", SANs: []string{"b.example.test"}}, h.clock.Now())
	a2 := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, h.clock.Now())
	cert := ca.Issue(pki.Opts{CommonName: "c.example.test", SANs: []string{"c.example.test"}}, h.clock.Now())
	locA, locB := cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", "a.example.test"), cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "b.example.test")
	locC := cl("/etc/nginx/ssl/c.crt", "/etc/nginx/ssl/c.key", "c.example.test")
	warn := func(code string) []providers.Warning {
		return []providers.Warning{{Code: code, Params: map[string]string{}}}
	}
	for i, tc := range []struct {
		name        string
		res         providers.DiscoveryResult
		markMissing bool
	}{
		{name: "partial", res: providers.DiscoveryResult{Partial: true, SSHD: sshdRead}, markMissing: true},
		{name: "list truncated", res: providers.DiscoveryResult{Warnings: warn(providers.WarnListTruncated)}, markMissing: true},
		{name: "too many files", res: providers.DiscoveryResult{SSHD: sshdRead, Warnings: warn(providers.WarnTooManyFiles)}, markMissing: true},
		{name: "locations dropped", res: providers.DiscoveryResult{Warnings: warn(providers.WarnLocationsDropped)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			web := nginxTarget(t, h, admin, fmt.Sprintf("web-%02d", i))
			_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK,
				Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
			require.NoError(t, err)
			before := h.audits("location.changed_outside")
			res := tc.res
			res.Nginx, res.Certificates = nginxOK, []providers.DiscoveredCertificate{dc(locA, a2), dc(locC, cert)}
			sum, err := h.svc.Reconcile(h.ctx, web.ID, res)
			require.NoError(t, err)
			assert.Equal(t, 1, sum.NewLocations)
			paths := byPath(t, h, web.ID, true)
			require.Contains(t, paths, "/etc/nginx/ssl/c.crt")
			assert.Equal(t, pki.Fingerprint(a2.Cert), paths["/etc/nginx/ssl/a.crt"].Certificate.Fingerprint, "the reported location is updated")
			assert.NotNil(t, paths["/etc/nginx/ssl/a.crt"].ChangedOutsideAt)
			assert.Equal(t, before+1, h.audits("location.changed_outside"))
			if tc.markMissing {
				assert.Equal(t, 1, sum.MissingLocations)
				assert.NotNil(t, paths["/etc/nginx/ssl/b.crt"].MissingSince)
			} else {
				assert.Zero(t, sum.MissingLocations)
				assert.Nil(t, paths["/etc/nginx/ssl/b.crt"].MissingSince, "a list with locations left out proves nothing")
			}
		})
	}

	// A missing location that comes back in a partial scan is no longer missing.
	web := nginxTarget(t, h, admin, "web-back")
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
	require.NoError(t, err)
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a)}})
	require.NoError(t, err)
	require.NotNil(t, byPath(t, h, web.ID, true)["/etc/nginx/ssl/b.crt"].MissingSince)
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Partial: true, SSHD: sshdRead,
		Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
	require.NoError(t, err)
	assert.Nil(t, byPath(t, h, web.ID, true)["/etc/nginx/ssl/b.crt"].MissingSince)
}

// A certificates-only result says nothing about SSH: stored sshd, host-key, account and warning
// facts and the key locations stay; the SSH-only scan leaves the Nginx facts and locations.
func TestReconcileHalvesKeepTheOtherHalf(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	hk := providers.DiscoveredHostKey{KeyType: "ssh-ed25519", Bits: 256, Fingerprint: "SHA256:host"}
	ssh := providers.DiscoveryResult{SSHD: sshdRead, HostKeys: []providers.DiscoveredHostKey{hk}, ReadFiles: []string{deployFile},
		SSHKeys:   []providers.DiscoveredSSHKey{dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "x")},
		UID0Users: []string{"root"}, Warnings: []providers.Warning{{Code: "strict_modes", Params: map[string]string{"user": "deploy"}}},
		Accounts: []string{"deploy", "root"}, AccountsComplete: true}
	_, err := h.svc.Reconcile(h.ctx, web.ID, ssh)
	require.NoError(t, err)
	before, err := h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	keysBefore := locations(t, h, web.ID, true)

	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	h.clock.Advance(time.Hour)
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Warnings: []providers.Warning{{Code: "stream_tls"}},
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), leaf)}})
	require.NoError(t, err)
	after, err := h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, before.Facts.SSHD, after.Facts.SSHD)
	assert.Equal(t, before.Facts.HostKeys, after.Facts.HostKeys)
	assert.Equal(t, before.Facts.UID0Users, after.Facts.UID0Users)
	assert.Equal(t, before.Facts.Warnings, after.Facts.Warnings)
	assert.Equal(t, nginxOK, after.Facts.Nginx)
	assert.Equal(t, keysBefore, locations(t, h, web.ID, true))
	assert.Equal(t, before.LastDiscoveryAt, after.LastDiscoveryAt, "only a scan of the SSH half is a discovery for the schedule")

	// The SSH-only scan replaces the SSH facts and keeps Nginx's and the locations.
	ssh.UID0Users = []string{"root", "toor"}
	_, err = h.svc.Reconcile(h.ctx, web.ID, ssh)
	require.NoError(t, err)
	after, err = h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"root", "toor"}, after.Facts.UID0Users)
	assert.Equal(t, nginxOK, after.Facts.Nginx)
	assert.Len(t, byPath(t, h, web.ID, false), 1)
}

func TestReconcileUnsupportedLocationsAndWarnings(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", SANs: []string{"old.example.test"},
		NotBefore: h.clock.Now().AddDate(0, -3, 0), NotAfter: h.clock.Now().Add(-time.Hour)}, h.clock.Now())
	other := ca.Issue(pki.Opts{CommonName: "x.example.test", SANs: []string{"x.example.test"}}, h.clock.Now())
	ed := ca.Issue(pki.Opts{CommonName: "ed.example.test", KeyType: pki.Ed25519}, h.clock.Now())
	rsa := ca.Issue(pki.Opts{CommonName: "rsa.example.test", SANs: []string{"*.example.test"}, KeyType: pki.RSA2048}, h.clock.Now())
	variable := providers.CertLocation{CertPath: "/etc/nginx/ssl/$ssl_server_name.crt", Unsupported: providers.UnsupportedVariable,
		Servers: []providers.CertServer{{Names: []string{"files.example.test"}, Listens: []providers.CertListen{{Port: 443}}}}}
	openKey := cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test")
	openKey.KeyMode, openKey.Warnings = "0644", []string{providers.WarnKeyModeOpen}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: variable},
		dc(cl("/etc/nginx/ssl/old.crt", "/etc/nginx/ssl/old.key", "old.example.test"), expired),
		dc(openKey, other),
		dc(cl("/etc/nginx/ssl/ed.crt", "/etc/nginx/ssl/ed.key", "ed.example.test"), ed),
		dc(cl("/etc/nginx/ssl/rsa.crt", "/etc/nginx/ssl/rsa.key", "_", "", "~^w+\\.example\\.test$", "app.example.test", "APP.Example.Test"), rsa),
	}})
	require.NoError(t, err)
	paths := byPath(t, h, web.ID, false)
	v := paths["/etc/nginx/ssl/$ssl_server_name.crt"]
	assert.False(t, v.Supported)
	assert.Equal(t, providers.UnsupportedVariable, v.UnsupportedReason)
	assert.Nil(t, v.Certificate)
	assert.Equal(t, []string{"certificate_expired"}, paths["/etc/nginx/ssl/old.crt"].Warnings)
	assert.True(t, paths["/etc/nginx/ssl/old.crt"].Supported, "an expired certificate is a warning: deploying a new one fixes it")
	assert.ElementsMatch(t, []string{providers.WarnKeyModeOpen, "san_mismatch"}, paths["/etc/nginx/ssl/x.crt"].Warnings)
	assert.Equal(t, "0644", paths["/etc/nginx/ssl/x.crt"].KeyMode)
	assert.False(t, paths["/etc/nginx/ssl/ed.crt"].Supported)
	assert.Equal(t, providers.UnsupportedKeyType, paths["/etc/nginx/ssl/ed.crt"].UnsupportedReason)
	assert.Empty(t, paths["/etc/nginx/ssl/ed.crt"].KeyType)
	assert.Equal(t, "rsa", paths["/etc/nginx/ssl/rsa.crt"].KeyType)
	assert.Equal(t, []string{}, paths["/etc/nginx/ssl/rsa.crt"].Warnings, "catch-all, empty and regex names are not checked; a wildcard covers")
	assert.True(t, paths["/etc/nginx/ssl/rsa.crt"].Supported)
}

func TestReconcileStoresTheBetterChain(t *testing.T) {
	ca := pki.NewCA("Inv", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withRoots(roots))
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	loc := cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")
	leafOnly := providers.DiscoveredCertificate{Location: loc, PEMChain: leaf.CertPEM, FileSHA256: sha(leaf.CertPEM)}
	run := func(d providers.DiscoveredCertificate) inventory.Certificate {
		t.Helper()
		_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{d}})
		require.NoError(t, err)
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
		require.NoError(t, err)
		require.Len(t, page.Items, 1)
		c, err := h.svc.GetCertificate(h.ctx, page.Items[0].ID)
		require.NoError(t, err)
		return c
	}
	c := run(leafOnly)
	assert.False(t, c.ChainComplete)
	assert.Equal(t, string(leaf.CertPEM), c.PEMChain)
	c = run(dc(loc, leaf))
	assert.True(t, c.ChainComplete, "the intermediate leads to a trusted root")
	assert.Equal(t, string(leaf.FullchainPEM), c.PEMChain)
	c = run(leafOnly)
	assert.True(t, c.ChainComplete, "a complete chain is never replaced by an incomplete one")
	assert.Equal(t, string(leaf.FullchainPEM), c.PEMChain)
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	assert.Equal(t, sha(leaf.CertPEM), l.CertFileSHA256, "the location follows the file")
}

// Two servers that share certificates, scanned at the same time with the certificates in opposite
// orders, never deadlock (rows are locked in fingerprint order).
func TestReconcileConcurrentTargetsSharingCertificates(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	targets := []inventory.Target{nginxTarget(t, h, admin, "web-01"), nginxTarget(t, h, admin, "web-02"), nginxTarget(t, h, admin, "web-03")}
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	var found []providers.DiscoveredCertificate
	for i := range 12 {
		name := fmt.Sprintf("s%d.example.test", i)
		found = append(found, dc(cl("/etc/nginx/ssl/"+name+".crt", "/etc/nginx/ssl/"+name+".key", name),
			ca.Issue(pki.Opts{CommonName: name, SANs: []string{name}}, h.clock.Now())))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3*8)
	for i, tg := range targets {
		list := slices.Clone(found)
		if i%2 == 1 {
			slices.Reverse(list)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: list})
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 12, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, 36, h.count("SELECT count(*) FROM certificate_locations"))
}

// Requirement: what a server reports is data. The worst shapes the provider can emit, and some it
// cannot, are stored bounded (or skipped and counted) without failing the scan, SSH keys included.
func TestReconcileHostileDiscoveryData(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "nul\x00cn.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, h.clock.Now())

	// The provider's bounds: 500 servers per location, 100 names of 253 characters, 100 listens.
	big := cl("/etc/nginx/ssl/big.crt", "/etc/nginx/ssl/big.key")
	big.Servers = nil
	for s := range 500 {
		srv := providers.CertServer{File: "/etc/nginx/" + strings.Repeat("f", 4000), Line: s}
		for n := range 100 {
			srv.Names = append(srv.Names, fmt.Sprintf("%s%03d", strings.Repeat("n", 250), n))
			srv.Listens = append(srv.Listens, providers.CertListen{Addr: strings.Repeat("a", 253), Port: 443 + n})
		}
		big.Servers = append(big.Servers, srv)
	}
	invalid := strings.Repeat("\xff", 4096)
	quoted := strconv.QuoteToASCII(invalid) // the provider's longest shown path: 16386 characters
	require.Len(t, quoted, 16386)
	pathNotAllowed := providers.CertLocation{CertPath: quoted, KeyPath: quoted, Unsupported: providers.UnsupportedPathNotAllowed,
		Servers: []providers.CertServer{{Names: []string{"x"}}}}
	newReason := providers.CertLocation{CertPath: "/etc/nginx/ssl/new.crt", Unsupported: "brand_new_reason"}
	badReason := providers.CertLocation{CertPath: "/etc/nginx/ssl/bad.crt", Unsupported: "Not A Reason!", Problem: "weird-problem",
		KeyProblem: strings.Repeat("k", 41)}
	lying := cl("/etc/nginx/ssl/lying.crt", "/etc/nginx/ssl/lying.key", "www.example.test")
	lying.Unsupported = providers.UnsupportedVariable // Supported is true as well: the reason wins
	lyingProblem := cl("/etc/nginx/ssl/lyingp.crt", "/etc/nginx/ssl/lyingp.key", "www.example.test")
	lyingProblem.KeyProblem = providers.CertProblemNotRootControlled
	reasonless := providers.CertLocation{CertPath: "/etc/nginx/ssl/reasonless.crt"}
	emptyChain := providers.CertLocation{CertPath: "/etc/nginx/ssl/empty.crt", Unsupported: providers.UnsupportedFile, Problem: providers.CertProblemMissing}
	odd := cl("/etc/nginx/ssl/odd\x00.crt", "/etc/nginx/ssl/odd.key\x00", "nul\x00name", "www.example.test")
	odd.KeyMode, odd.KeyOwner, odd.KeyGroup = "rwxr-xr-x", strings.Repeat("ö", 100), "grp\x00"
	odd.ResolvedCertPath = "/" + strings.Repeat("r", 5000)
	odd.Servers[0].File = "/etc/nginx/\x00file"
	odd.Servers[0].Listens = nil
	for i := range 40 {
		odd.Warnings = append(odd.Warnings, fmt.Sprintf("warning_%c", 'a'+rune(i%26))+strings.Repeat("x", i/26))
	}
	odd.Warnings = append(odd.Warnings, "BAD", "", "a,b", strings.Repeat("w", 41))
	longKey := cl("/etc/nginx/ssl/longkey.crt", "/"+strings.Repeat("k", 16400), "www.example.test")
	garbage := providers.DiscoveredCertificate{Location: cl("/etc/nginx/ssl/garbage.crt", "/etc/nginx/ssl/garbage.key", "www.example.test"),
		PEMChain: []byte("not a certificate"), FileSHA256: sha([]byte("x"))}
	badHash := dc(cl("/etc/nginx/ssl/badhash.crt", "/etc/nginx/ssl/badhash.key", "other.example.test"), other)
	badHash.FileSHA256 = "zz"
	upperHash := dc(cl("/etc/nginx/ssl/upper.crt", "/etc/nginx/ssl/upper.key", "www.example.test"), leaf)
	upperHash.FileSHA256 = strings.NewReplacer("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F").Replace(upperHash.FileSHA256)
	tooLong := providers.CertLocation{CertPath: "/" + strings.Repeat("p", 16400)}
	empty := providers.CertLocation{}
	dup1 := dc(cl("/etc/nginx/ssl/dup.crt", "/etc/nginx/ssl/dup.key", "www.example.test"), leaf)
	dup2 := dc(cl("/etc/nginx/ssl/dup.crt", "/etc/nginx/ssl/other.key", "other.example.test"), other)
	noChain := cl("/etc/nginx/ssl/nochain.crt", "/etc/nginx/ssl/nochain.key", "www.example.test") // supported, but no file read
	noHash := dc(cl("/etc/nginx/ssl/nohash.crt", "/etc/nginx/ssl/nohash.key", "www.example.test"), leaf)
	noHash.FileSHA256 = ""
	// A SAN longer than a DNS name (a GIN index entry of over 2.7 KB fails the INSERT) and more SANs
	// than the inventory keeps.
	var noise strings.Builder // incompressible, as a hostile name would be
	for i := 0; noise.Len() < 3000; i++ {
		noise.WriteString(sha([]byte(strconv.Itoa(i))))
	}
	longSAN := ca.Issue(pki.Opts{CommonName: "long.example.test", SANs: []string{"long.example.test", noise.String() + ".example.test"}},
		h.clock.Now())
	var sans []string
	for i := range 1200 {
		sans = append(sans, fmt.Sprintf("s%04d.example.test", i))
	}
	manySAN := ca.Issue(pki.Opts{CommonName: "many.example.test", SANs: sans}, h.clock.Now())

	res := providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.2\x003", ConfPath: "/etc/nginx/nginx.conf"},
		SSHD: sshdRead, ReadFiles: []string{deployFile},
		SSHKeys: []providers.DiscoveredSSHKey{dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "x")},
		Certificates: []providers.DiscoveredCertificate{dc(big, leaf), {Location: pathNotAllowed}, {Location: newReason}, {Location: badReason},
			dc(lying, leaf), dc(lyingProblem, leaf), {Location: reasonless}, {Location: emptyChain}, dc(odd, leaf), dc(longKey, leaf), garbage,
			badHash, upperHash, {Location: tooLong}, {Location: empty}, dup1, dup2,
			dc(cl("/etc/nginx/ssl/longsan.crt", "/etc/nginx/ssl/longsan.key", "long.example.test"), longSAN),
			dc(cl("/etc/nginx/ssl/manysan.crt", "/etc/nginx/ssl/manysan.key", "s0000.example.test"), manySAN),
			{Location: noChain}, noHash}}
	sum, err := h.svc.Reconcile(h.ctx, web.ID, res)
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Keys, "the SSH half is stored too")
	assert.Equal(t, 18, sum.Locations)
	assert.Equal(t, 4, sum.Certificates)
	got, err := h.svc.GetTarget(h.ctx, web.ID)
	require.NoError(t, err)
	assert.Equal(t, "1.2�3", got.Facts.Nginx.Version)
	assert.Equal(t, providers.WarnListTruncated, got.Facts.Warnings[len(got.Facts.Warnings)-1].Code, "skipped locations are reported")
	d := h.auditDetails("target.discovered")
	assert.Equal(t, "2", d[len(d)-1]["skipped_location_count"])

	paths := byPath(t, h, web.ID, false)
	require.Len(t, paths, 18)
	for _, p := range []string{"/etc/nginx/ssl/nochain.crt", "/etc/nginx/ssl/nohash.crt"} {
		l := paths[p]
		assert.False(t, l.Supported, "no compare-and-swap value: %s", p)
		assert.Equal(t, []string{providers.UnsupportedFile, providers.CertProblemUnreadable}, []string{l.UnsupportedReason, l.Problem}, p)
		assert.Empty(t, l.CertFileSHA256)
	}
	assert.Equal(t, []string{providers.WarnListTruncated}, paths["/etc/nginx/ssl/longsan.crt"].Warnings, "SANs left out are flagged")
	assert.Equal(t, []string{providers.WarnListTruncated}, paths["/etc/nginx/ssl/manysan.crt"].Warnings)
	long, err := h.svc.GetCertificate(h.ctx, paths["/etc/nginx/ssl/longsan.crt"].Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"long.example.test"}, long.SANs, "a name longer than 253 characters is dropped, never cut")
	many, err := h.svc.GetCertificate(h.ctx, paths["/etc/nginx/ssl/manysan.crt"].Certificate.ID)
	require.NoError(t, err)
	assert.Len(t, many.SANs, 1000)
	assert.Equal(t, sans[:1000], many.SANs)
	assert.Len(t, paths["/etc/nginx/ssl/big.crt"].Servers, 500)
	assert.Len(t, paths["/etc/nginx/ssl/big.crt"].Servers[499].Names, 100)
	pna := paths[quoted]
	assert.False(t, pna.Supported)
	assert.Equal(t, quoted, pna.KeyPath)
	assert.Equal(t, "brand_new_reason", paths["/etc/nginx/ssl/new.crt"].UnsupportedReason, "a well-formed new reason is kept")
	bad := paths["/etc/nginx/ssl/bad.crt"]
	assert.Equal(t, []string{providers.UnsupportedUnknown, providers.CertProblemUnknown}, []string{bad.UnsupportedReason, bad.Problem})
	assert.Equal(t, providers.CertProblemUnknown, bad.KeyProblem)
	assert.False(t, paths["/etc/nginx/ssl/lying.crt"].Supported)
	assert.Equal(t, providers.UnsupportedVariable, paths["/etc/nginx/ssl/lying.crt"].UnsupportedReason)
	assert.False(t, paths["/etc/nginx/ssl/lyingp.crt"].Supported)
	assert.Equal(t, providers.UnsupportedFile, paths["/etc/nginx/ssl/lyingp.crt"].UnsupportedReason)
	assert.Equal(t, providers.UnsupportedUnknown, paths["/etc/nginx/ssl/reasonless.crt"].UnsupportedReason)
	assert.Nil(t, paths["/etc/nginx/ssl/empty.crt"].Certificate)
	o := paths["/etc/nginx/ssl/odd�.crt"]
	assert.Equal(t, "/etc/nginx/ssl/odd.key�", o.KeyPath)
	assert.Empty(t, o.KeyMode)
	assert.Equal(t, strings.Repeat("ö", 64), o.KeyOwner)
	assert.Equal(t, "grp�", o.KeyGroup)
	assert.Empty(t, o.ResolvedCertPath)
	assert.Equal(t, []string{"nul�name", "www.example.test"}, o.Servers[0].Names)
	assert.Equal(t, []providers.CertListen{}, o.Servers[0].Listens)
	assert.Len(t, o.Warnings, 32)
	assert.Contains(t, o.Warnings, "warning_a")
	assert.NotContains(t, o.Warnings, "BAD")
	lk := paths["/etc/nginx/ssl/longkey.crt"]
	assert.Empty(t, lk.KeyPath)
	assert.Equal(t, providers.UnsupportedPathNotAllowed, lk.UnsupportedReason)
	g := paths["/etc/nginx/ssl/garbage.crt"]
	assert.Nil(t, g.Certificate)
	assert.Equal(t, []string{providers.UnsupportedFile, providers.CertProblemNotACertificate}, []string{g.UnsupportedReason, g.Problem})
	assert.Empty(t, g.CertFileSHA256)
	bh := paths["/etc/nginx/ssl/badhash.crt"]
	assert.False(t, bh.Supported)
	assert.Equal(t, providers.CertProblemUnreadable, bh.Problem)
	assert.Empty(t, bh.CertFileSHA256)
	assert.Equal(t, sha(leaf.FullchainPEM), paths["/etc/nginx/ssl/upper.crt"].CertFileSHA256)
	dup := paths["/etc/nginx/ssl/dup.crt"]
	assert.Equal(t, "/etc/nginx/ssl/dup.key", dup.KeyPath, "the first of duplicate locations wins")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), dup.Certificate.Fingerprint)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "nul"})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "nul�cn.example.test", page.Items[0].SubjectCN)

	// The same hostile scan again changes nothing (idempotent, nothing missing, no audit noise).
	before := locationRows(t, h, web.ID)
	sum, err = h.svc.Reconcile(h.ctx, web.ID, res)
	require.NoError(t, err)
	assert.Zero(t, sum.NewLocations+sum.MissingLocations)
	assert.Equal(t, before, locationRows(t, h, web.ID))
	assert.Zero(t, h.audits("location.changed_outside"))
}

func TestListCertificatesFilters(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web1, web2 := nginxTarget(t, h, admin, "web-01"), nginxTarget(t, h, admin, "web-02")
	now := h.clock.Now()
	ca := pki.NewCA("Inv", pki.ECDSA256, now)
	// The SANs are ASCII (IA5String): the dotted capital I is only in a subject CN.
	issue := func(cn, san string, notAfter time.Time) pki.Leaf {
		return ca.Issue(pki.Opts{CommonName: cn, SANs: []string{san}, NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter}, now)
	}
	expired := issue("expired.example.test", "alt-expired.example.test", now.Add(-time.Hour))
	d10 := issue("İzmir.example.test", "alt-city.example.test", now.AddDate(0, 0, 10))
	d45 := issue("istanbul.example.test", "alt-istanbul.example.test", now.AddDate(0, 0, 45))
	d200 := issue("ankara.example.test", "alt-ankara.example.test", now.AddDate(0, 0, 200))
	var found []providers.DiscoveredCertificate
	for i, l := range []pki.Leaf{d200, expired, d45, d10} {
		found = append(found, dc(cl(fmt.Sprintf("/etc/nginx/ssl/%d.crt", i), fmt.Sprintf("/etc/nginx/ssl/%d.key", i), l.Cert.Subject.CommonName), l))
	}
	_, err := h.svc.Reconcile(h.ctx, web1.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: found})
	require.NoError(t, err)
	uploaded := issue("uploaded.example.test", "uploaded.example.test", now.AddDate(0, 0, 300))
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, label, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, 'uploaded.example.test', $3, $4, 'ecdsa', $5, $6, 'uploaded', 'Shop', $7, $7, $7)`, uuid.Must(uuid.NewV7()),
		pki.Fingerprint(uploaded.Cert), uploaded.Cert.NotBefore, uploaded.Cert.NotAfter, sha([]byte("pub")), string(uploaded.CertPEM), now)
	require.NoError(t, err)

	cns := func(f inventory.CertificateFilter) []string {
		t.Helper()
		page, err := h.svc.ListCertificates(h.ctx, f)
		require.NoError(t, err)
		out := []string{}
		for _, c := range page.Items {
			out = append(out, c.SubjectCN)
		}
		return out
	}
	all := []string{"expired.example.test", "İzmir.example.test", "istanbul.example.test", "ankara.example.test", "uploaded.example.test"}
	for _, tc := range []struct {
		f    inventory.CertificateFilter
		want []string
	}{
		{inventory.CertificateFilter{}, all},
		{inventory.CertificateFilter{Expiry: "expired"}, all[:1]},
		{inventory.CertificateFilter{Expiry: "30"}, all[:2]},
		{inventory.CertificateFilter{Expiry: "60"}, all[:3]},
		{inventory.CertificateFilter{Source: "uploaded"}, all[4:]},
		{inventory.CertificateFilter{Source: "discovered"}, all[:4]},
		{inventory.CertificateFilter{Source: "csr"}, []string{}},
		{inventory.CertificateFilter{TargetID: web1.ID}, all[:4]},
		{inventory.CertificateFilter{TargetID: web2.ID}, []string{}},
		{inventory.CertificateFilter{Query: "ISTANBUL"}, []string{"istanbul.example.test"}},
		{inventory.CertificateFilter{Query: "izmir"}, []string{"İzmir.example.test"}},
		{inventory.CertificateFilter{Query: "İZMİR"}, []string{"İzmir.example.test"}},
		{inventory.CertificateFilter{Query: "alt-ankara"}, []string{"ankara.example.test"}},
		{inventory.CertificateFilter{Query: "shop"}, []string{"uploaded.example.test"}},
		{inventory.CertificateFilter{Query: pki.Fingerprint(d45.Cert)[:16]}, []string{"istanbul.example.test"}},
		{inventory.CertificateFilter{Query: "%"}, []string{}},
		{inventory.CertificateFilter{Query: "  "}, all},
		{inventory.CertificateFilter{Expiry: "60", Source: "discovered", TargetID: web1.ID, Query: "example"}, all[:3]},
	} {
		assert.Equal(t, tc.want, cns(tc.f), "%+v", tc.f)
	}

	// Paging: two at a time through all five.
	var seen []string
	cursor := ""
	for range 3 {
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Limit: 2, Cursor: cursor})
		require.NoError(t, err)
		for _, c := range page.Items {
			seen = append(seen, c.SubjectCN)
		}
		cursor = page.NextCursor
	}
	assert.Equal(t, all, seen)
	assert.Empty(t, cursor)

	// A location on a deleted target or a missing one does not count; the target filter ignores them.
	_, err = h.svc.Reconcile(h.ctx, web2.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: found[:1]})
	require.NoError(t, err)
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "ankara"})
	require.NoError(t, err)
	assert.Equal(t, 2, page.Items[0].LocationCount)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, web2.ID))
	_, err = h.svc.Reconcile(h.ctx, web1.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: found[1:]})
	require.NoError(t, err)
	page, err = h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "ankara"})
	require.NoError(t, err)
	assert.Zero(t, page.Items[0].LocationCount)
	assert.Equal(t, []string{}, cns(inventory.CertificateFilter{Query: "ankara", TargetID: web1.ID}))

	for _, tc := range []struct {
		f     inventory.CertificateFilter
		field string
		code  string
	}{
		{inventory.CertificateFilter{Expiry: "90"}, "expiry", validate.OneOf},
		{inventory.CertificateFilter{Cursor: "!!"}, "cursor", validate.Pattern},
		{inventory.CertificateFilter{Limit: 201}, "limit", validate.OutOfRange},
		{inventory.CertificateFilter{Limit: -1}, "limit", validate.OutOfRange},
		{inventory.CertificateFilter{Source: "azure"}, "source", validate.OneOf},
		{inventory.CertificateFilter{Query: strings.Repeat("q", 201)}, "q", validate.TooLong},
		{inventory.CertificateFilter{Query: "a\x00"}, "q", validate.Pattern},
		{inventory.CertificateFilter{Query: "a\xff"}, "q", validate.Pattern},
	} {
		_, err := h.svc.ListCertificates(h.ctx, tc.f)
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs, "%+v", tc.f)
		assert.Equal(t, tc.field, verrs[0].Field)
		assert.Equal(t, tc.code, verrs[0].Code, "%+v", tc.f)
	}

	// Certificates that expire at the same instant page by id.
	tie := now.AddDate(0, 0, 400)
	for i := range 5 {
		_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, $3, $4, $5, 'ecdsa', $2, '', 'uploaded', $4, $4, $4)`, uuid.Must(uuid.NewV7()), sha([]byte(strconv.Itoa(i))),
			fmt.Sprintf("tie-%d", i), now, tie)
		require.NoError(t, err)
	}
	var ties []string
	cursor = ""
	for {
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "tie-", Limit: 2, Cursor: cursor})
		require.NoError(t, err)
		for _, c := range page.Items {
			ties = append(ties, c.SubjectCN)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	assert.Equal(t, []string{"tie-0", "tie-1", "tie-2", "tie-3", "tie-4"}, ties, "every one once, in id order")
}

func TestGetCertificateAndLocations(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web1, web2 := nginxTarget(t, h, admin, "web-01"), nginxTarget(t, h, admin, "web-02")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	for _, tg := range []inventory.Target{web1, web2} {
		_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
			dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "b.example.test", "www.example.test"), leaf),
			dc(cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", "a.example.test"), leaf),
			dc(cl("/etc/nginx/ssl/0.crt", "/etc/nginx/ssl/0.key", "a.example.test"), leaf),
		}})
		require.NoError(t, err)
		h.clock.Advance(time.Minute)
	}
	locs, err := h.svc.ListLocations(h.ctx, web1.ID, false)
	require.NoError(t, err)
	order := []string{}
	for _, l := range locs {
		order = append(order, l.CertPath)
	}
	assert.Equal(t, []string{"/etc/nginx/ssl/0.crt", "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/www.crt"}, order, "by first server name, then path")

	// An active deployment is shown on its location.
	depID := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'queued', 'pending', $5, $6, $7, $8)`,
		depID, locs[0].Certificate.ID, locs[0].ID, web1.ID, pki.Fingerprint(leaf.Cert), locs[0].CertPath, locs[0].KeyPath, h.clock.Now())
	require.NoError(t, err)
	l, err := h.svc.GetLocation(h.ctx, locs[0].ID)
	require.NoError(t, err)
	require.NotNil(t, l.ActiveDeploymentID)
	assert.Equal(t, depID, *l.ActiveDeploymentID)

	c, err := h.svc.GetCertificate(h.ctx, locs[0].Certificate.ID)
	require.NoError(t, err)
	assert.Len(t, c.Locations, 6)
	assert.Equal(t, 6, c.LocationCount)
	assert.Equal(t, web2.ID, c.Locations[0].TargetID, "newest first")

	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, web2.ID))
	c, err = h.svc.GetCertificate(h.ctx, c.ID)
	require.NoError(t, err)
	assert.Len(t, c.Locations, 3, "locations of a deleted target are not shown")
	_, err = h.svc.GetLocation(h.ctx, c.Locations[0].ID)
	require.NoError(t, err)
	web2Locs := h.count("SELECT count(*) FROM certificate_locations WHERE target_id = $1", web2.ID)
	assert.Equal(t, 3, web2Locs, "nothing is deleted")
	var gone uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT id FROM certificate_locations WHERE target_id = $1 LIMIT 1", web2.ID).Scan(&gone))
	_, err = h.svc.GetLocation(h.ctx, gone)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.ListLocations(h.ctx, web2.ID, true)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.GetLocation(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.GetCertificate(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

// The size bound boundServers uses is never below PostgreSQL's own rendering of the servers, for
// text that needs escaping, non-ASCII text and the empty lists.
func TestServersSizeBoundCoversPostgreSQL(t *testing.T) {
	h := newHarness(t)
	for _, servers := range [][]providers.CertServer{
		{},
		{{Names: []string{}, Listens: []providers.CertListen{}}},
		{{Names: []string{"a<b>&c", "q\"uote\\", "\x01\x1f\t\n\r\b\f", "\u2028\u2029", "İzmir ığdır 𝔘"}, File: "/x\x7f",
			Listens: []providers.CertListen{{Addr: "[::1]", Port: 443, DefaultServer: true}, {Port: 8443}}, Line: -1}},
		{{Names: []string{"a"}}, {Names: []string{"b", "c"}, Listens: []providers.CertListen{{Port: 1}}}},
	} {
		raw, err := json.Marshal(servers)
		require.NoError(t, err)
		var rendered int
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT octet_length($1::jsonb::text)", raw).Scan(&rendered))
		assert.GreaterOrEqual(t, inventory.ServersTextBound(servers), rendered, "%s", raw)
	}
}

// Alice's own deployment is never a change outside Alice: the certificate a deployment in flight
// installs or restores, and those of the last finished one, are expected in the file before (or
// after) deployed_fingerprint records them.
func TestReconcileChangedOutsideKnowsAlicesDeployments(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	a, x, z := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	loc := cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")
	scan := func(leaf pki.Leaf) inventory.CertificateLocation {
		t.Helper()
		_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(loc, leaf)}})
		require.NoError(t, err)
		return byPath(t, h, web.ID, true)["/etc/nginx/ssl/www.crt"]
	}
	l := scan(a)
	xID := uuid.Must(uuid.NewV7())
	_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at) VALUES ($1, $2, $3, $4, 'ecdsa', $5, $6, 'uploaded', $7, $7, $7)`,
		xID, pki.Fingerprint(x.Cert), x.Cert.NotBefore, x.Cert.NotAfter, sha([]byte("x")), string(x.FullchainPEM), h.clock.Now())
	require.NoError(t, err)
	depID := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, previous_fingerprint, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'deploying', 'running', $5, $6, $7, $8, $9)`,
		depID, xID, l.ID, web.ID, pki.Fingerprint(x.Cert), pki.Fingerprint(a.Cert), l.CertPath, l.KeyPath, h.clock.Now())
	require.NoError(t, err)

	// The scan runs while the deployment is being verified: the file already holds X.
	l = scan(x)
	assert.Equal(t, pki.Fingerprint(x.Cert), l.Certificate.Fingerprint)
	assert.Nil(t, l.ChangedOutsideAt, "the certificate a deployment in flight installs")
	// The deployment rolls back: the file holds A again.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE deployments SET state = 'done', status = 'rolled_back', finished_at = $2 WHERE id = $1", depID, h.clock.Now())
	require.NoError(t, err)
	l = scan(a)
	assert.Nil(t, l.ChangedOutsideAt, "the certificate the last deployment restored")
	assert.Zero(t, h.audits("location.changed_outside"))

	// A third certificate is somebody else's.
	l = scan(z)
	require.NotNil(t, l.ChangedOutsideAt)
	d := h.auditDetails("location.changed_outside")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"location_id": l.ID.String(), "target_id": web.ID.String(), "cert_path": "/etc/nginx/ssl/www.crt",
		"fingerprint": pki.Fingerprint(z.Cert), "previous_fingerprint": pki.Fingerprint(a.Cert)}, d[0])
}

// The certificate half of a result is stored for Nginx targets only.
func TestReconcileIgnoresCertificatesOfOtherTargetTypes(t *testing.T) {
	h := newHarness(t)
	linux := okTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	sum, err := h.svc.Reconcile(h.ctx, linux.ID, providers.DiscoveryResult{Nginx: nginxOK, SSHD: sshdRead, ReadFiles: []string{deployFile},
		SSHKeys:      []providers.DiscoveredSSHKey{dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "x")},
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), leaf)}})
	require.NoError(t, err)
	assert.Equal(t, inventory.ReconcileSummary{Keys: 1, New: 1}, sum)
	assert.Zero(t, h.count("SELECT count(*) FROM certificate_locations")+h.count("SELECT count(*) FROM certificates"))
	got, err := h.svc.GetTarget(h.ctx, linux.ID)
	require.NoError(t, err)
	assert.Nil(t, got.Facts.Nginx)
	assert.NotNil(t, got.Facts.SSHD)
	d := h.auditDetails("target.discovered")
	assert.NotContains(t, d[0], "location_count")
}

// An unchanged location is not rewritten: only last_seen_at moves (a large servers value is not
// written again on every scan).
func TestReconcileDoesNotRewriteAnUnchangedLocation(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	for _, stmt := range []string{
		"CREATE TABLE t13_server_writes (location_id uuid)",
		`CREATE FUNCTION t13_log_servers() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN INSERT INTO t13_server_writes VALUES (NEW.id); RETURN NEW; END $$`,
		"CREATE TRIGGER t13_servers BEFORE UPDATE OF servers ON certificate_locations FOR EACH ROW EXECUTE FUNCTION t13_log_servers()",
	} {
		_, err := h.db.Owner.Exec(h.ctx, stmt)
		require.NoError(t, err)
	}
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	loc := cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")
	scan := func(l providers.CertLocation) {
		t.Helper()
		_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(l, leaf)}})
		require.NoError(t, err)
	}
	scan(loc)
	h.clock.Advance(time.Hour)
	scan(loc)
	assert.Zero(t, h.count("SELECT count(*) FROM t13_server_writes"), "nothing changed: servers is not written")
	l := byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"]
	assert.Equal(t, h.clock.Now(), l.LastSeenAt)
	assert.Equal(t, 1, l.Version)
	loc.Servers[0].Names = append(loc.Servers[0].Names, "www2.example.test")
	scan(loc)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM t13_server_writes"))
	assert.Equal(t, 2, byPath(t, h, web.ID, false)["/etc/nginx/ssl/www.crt"].Version)
}

// The location lists are bounded: ListLocations returns at most MaxListedLocations, the locations
// that are not missing first (a target never has that many: the provider lists at most 1000), and
// GetCertificate at most as many, saying so.
func TestLocationListsAreBounded(t *testing.T) {
	h := newHarness(t)
	web := nginxTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/zz.crt", "/etc/nginx/ssl/zz.key", "zz.example.test"), leaf)}})
	require.NoError(t, err)
	live := byPath(t, h, web.ID, false)["/etc/nginx/ssl/zz.crt"]
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, certificate_id, supported, servers,
first_seen_at, last_seen_at, missing_since)
SELECT gen_random_uuid(), $1, 'nginx_file', '/etc/nginx/old/' || i || '.crt', $2, true, '[{"names":["aaa"]}]', $3, $3, $3
FROM generate_series(1, $4::int) i`, web.ID, live.Certificate.ID, h.clock.Now(), inventory.MaxListedLocations)
	require.NoError(t, err)

	locs, err := h.svc.ListLocations(h.ctx, web.ID, true)
	require.NoError(t, err)
	assert.Len(t, locs, inventory.MaxListedLocations)
	assert.Equal(t, live.ID, locs[0].ID, "the locations in use come first")
	locs, err = h.svc.ListLocations(h.ctx, web.ID, false)
	require.NoError(t, err)
	assert.Len(t, locs, 1)

	c, err := h.svc.GetCertificate(h.ctx, live.Certificate.ID)
	require.NoError(t, err)
	assert.Len(t, c.Locations, inventory.MaxListedLocations)
	assert.True(t, c.LocationsTruncated)
	assert.Equal(t, live.ID, c.Locations[0].ID)
	assert.Equal(t, 1, c.LocationCount)
}
