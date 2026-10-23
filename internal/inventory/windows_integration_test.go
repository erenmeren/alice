//go:build integration

package inventory_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R60 Task 12: a Windows server through the inventory, with the real Windows provider registered (its configuration
// rule and capabilities; nothing here dials).

const winRMAppID = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"

// withWindowsProvider adds the Windows provider to the harness's registry.
func withWindowsProvider() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(windows.New(windows.Options{}))
		reg.Freeze()
		c.Registry = reg
	}
}

// winTarget creates a Windows server through CreateTarget and marks it connected.
func winTarget(t *testing.T, h *harness, a inventory.Actor, name string) inventory.Target {
	t.Helper()
	tg, _, err := h.svc.CreateTarget(h.ctx, a, inventory.NewTarget{Name: name, Type: "windows", Host: name + ".corp.example"})
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'ok' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	tg.Status = inventory.StatusOK
	return tg
}

// iisOK is what a Windows discovery reports with IIS installed.
var iisOK = &providers.WebServerFacts{Software: "iis", Version: "10.0", Found: true, ConfigValid: true}

func derSHA(leaf pki.Leaf) string {
	s := sha256.Sum256(leaf.Cert.Raw)
	return hex.EncodeToString(s[:])
}

// winBinding is an ipport http.sys entry on 0.0.0.0:port of IIS used by one site binding, as the provider's convert
// reports it (the site's binding its server, section = the site name), with the bound certificate (nil: none) by its
// DER hash.
func winBinding(port int, site string, leaf *pki.Leaf) providers.DiscoveredCertificate {
	return winEntry(port, winproto.AppIDIIS, site, leaf)
}

// winEntry is winBinding of any application; no site makes it a foreign binding (win_foreign_app).
func winEntry(port int, appID, site string, leaf *pki.Leaf) providers.DiscoveredCertificate {
	text := "http.sys/ipport/0.0.0.0:" + strconv.Itoa(port)
	loc := providers.CertLocation{Kind: providers.LocationWinSSLBinding, CertPath: text, Supported: true, Servers: []providers.CertServer{},
		Locator: providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": port, "app_id": appID},
		Details: map[string]any{"app_id": appID, "application": winproto.KnownApps[appID], "store": "MY", "flags": 0,
			"cert_check_mode": 0, "ctl_identifier": "", "ctl_store": ""}}
	if site != "" {
		loc.Servers = []providers.CertServer{{Names: []string{}, Section: site, Listens: []providers.CertListen{{Addr: "*", Port: port}}}}
	} else {
		loc.Supported, loc.Unsupported = false, windows.UnsupportedForeignApp
	}
	d := providers.DiscoveredCertificate{Location: loc}
	if leaf != nil {
		d.PEMChain, d.FileSHA256 = leaf.FullchainPEM, derSHA(*leaf)
	}
	return d
}

// warningCodes are the codes of the target's stored facts warnings.
func (h *harness) warningCodes(target uuid.UUID) []string {
	h.t.Helper()
	got, err := h.svc.GetTarget(h.ctx, target)
	require.NoError(h.t, err)
	out := []string{}
	for _, w := range got.Facts.Warnings {
		out = append(out, w.Code)
	}
	return out
}

func (h *harness) missingLocations(target uuid.UUID) int {
	return h.count("SELECT count(*) FROM certificate_locations WHERE target_id = $1 AND missing_since IS NOT NULL", target)
}

// Review Focus 1: a domain account reaches targets.config verbatim; a Linux target still refuses it; a Windows server
// counts toward the license (L-74).
func TestCreateWindowsTargetKeepsTheDomainAccount(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg, job, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "iis-01", Type: "windows", Host: "IIS-01.corp.example",
		Username: `CORP\alice-svc`})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, job, "the first connection test is queued")
	assert.Equal(t, inventory.TypeWindows, tg.Type)
	assert.Equal(t, `CORP\alice-svc`, tg.Username)
	var stored string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT config->>'username' FROM targets WHERE id = $1", tg.ID).Scan(&stored))
	assert.Equal(t, `CORP\alice-svc`, stored, "stored as typed")
	assert.Equal(t, []string{"cleanup_certificates", "deploy_certificate", "discover_certificates", "test_connection", "verify_deployment"}, tg.Capabilities,
		"W2 (R61): the Windows provider deploys; W3 (R62): it cleans up")
	assert.Equal(t, `CORP\alice-svc`, h.auditDetails("target.created")[0]["username"])

	plain, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "iis-02", Type: "windows", Host: "iis-02.corp.example"})
	require.NoError(t, err)
	assert.Equal(t, "alice", plain.Username, "the Windows default account")

	for typ, u := range map[string]string{"linux": `CORP\alice-svc`, "windows": `CORP\-alice`} {
		_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "bad-" + typ, Type: typ, Host: "bad.corp.example", Username: u})
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, typ)
		require.Len(t, errs, 1, typ)
		assert.Equal(t, "username", errs[0].Field, typ)
		assert.Equal(t, validate.Pattern, errs[0].Code, typ)
	}

	addN(h, admin, 1, 3) // five targets: the evaluation's limit
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "iis-06", Type: "windows", Host: "iis-06.corp.example"})
	var limit *license.TargetLimitError
	require.True(t, errors.As(err, &limit), "%v", err)
	assert.Equal(t, 5, liveTargets(h))
}

// A scan stores one win_sslbinding row per http.sys entry, its certificate linked by fingerprint (so network discovery
// reads it managed), and counts as the target's discovery (Ruling 10); the SSH half stays empty (Ruling 11).
func TestWindowsScanStoresBindingLocations(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "iis-01")
	require.Nil(t, tg.LastDiscoveryAt)
	ca := pki.NewCA("Win", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	b := winBinding(443, "Default Web Site", &leaf)
	b.Location.Details["cert_sha1"], b.Location.Details["friendly_name"] = "00112233445566778899aabbccddeeff00112233", "www"
	sum, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{b},
		SSHKeys: []providers.DiscoveredSSHKey{dk("alice", `C:\ProgramData\ssh\administrators_authorized_keys`, 1,
			"SHA256:ccc0000000000000000000000000000000000000000", "x")},
		// An SSH half a Windows result never carries (Ruling 11): none of it is stored.
		SSHD:            providers.SSHDSummary{Read: true, KeysManagedElsewhere: true},
		HostKeys:        []providers.DiscoveredHostKey{{KeyType: "ssh-ed25519", Fingerprint: "SHA256:ddd0000000000000000000000000000000000000000"}},
		UnreadableLines: []providers.UnreadableLine{{OSUser: "alice", FilePath: "x", LineNo: 1}},
		UID0Users:       []string{"root"},
		KeyFiles:        []providers.UserKeyFiles{{OSUser: "alice", Files: []string{"x"}}}})
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Locations)
	assert.Equal(t, 1, sum.NewLocations)
	assert.Zero(t, sum.Keys, "a Windows server has no SSH key inventory")

	locs := byPath(t, h, tg.ID, false)
	require.Len(t, locs, 1)
	l := locs["http.sys/ipport/0.0.0.0:443"]
	assert.Equal(t, providers.LocationWinSSLBinding, l.Kind)
	assert.True(t, l.Locator.Equal(providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": 443, "app_id": winproto.AppIDIIS}))
	assert.Empty(t, l.KeyPath)
	assert.Empty(t, l.KeyMode)
	assert.True(t, l.Supported, l.UnsupportedReason)
	require.Len(t, l.Servers, 1)
	assert.Equal(t, "Default Web Site", l.Servers[0].Section)
	assert.Equal(t, "iis", l.Details["application"])
	assert.Equal(t, "00112233445566778899aabbccddeeff00112233", l.Details["cert_sha1"])
	assert.Equal(t, derSHA(leaf), l.CertFileSHA256, "the DER hash is the compare-and-swap token")
	require.NotNil(t, l.Certificate)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), l.Certificate.Fingerprint)
	assert.Equal(t, inventory.TypeWindows, l.TargetType)
	assert.True(t, l.Deployable, "W2 (R61): the Windows provider deploys; W3 (R62): it cleans up")

	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, issuer_cn, not_before, not_after,
    key_algorithm, pem, first_seen, last_seen) VALUES ($1, true, 'www.example.test', 'Win', $2, $3, 'ecdsa', $4, $5, $5)`,
		pki.Fingerprint(leaf.Cert), leaf.Cert.NotBefore, leaf.Cert.NotAfter, string(leaf.CertPEM), h.clock.Now())
	require.NoError(t, err)
	rows, err := discovery.ListCertificates(h.ctx, h.db.App, discovery.CertificateFilter{Fingerprint: pki.Fingerprint(leaf.Cert)})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, discovery.StatusManaged, rows[0].Status, "the binding's certificate is monitored")

	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastDiscoveryAt, "the certificate scan is the Windows server's discovery (Ruling 10)")
	assert.Equal(t, h.clock.Now(), got.LastDiscoveryAt.UTC())
	assert.Nil(t, got.Facts.SSHD, "no SSH facts")
	assert.Empty(t, got.Facts.HostKeys)
	assert.Empty(t, got.Facts.Unreadable)
	assert.Empty(t, got.Facts.UID0Users)
	assert.Empty(t, got.Facts.KeyFiles)
	assert.False(t, got.KeysManagedElsewhere)
	assert.Empty(t, got.Facts.Warnings)
	require.NotNil(t, got.Facts.WebServer)
	assert.Equal(t, "iis", got.Facts.WebServer.Software)
	assert.Zero(t, h.count("SELECT count(*) FROM ssh_key_locations WHERE target_id = $1", tg.ID))
}

// Review Focus 3: without IIS the foreign bindings are still listed, unsupported, and the facts say IIS is missing.
func TestWindowsScanWithoutIISStoresForeignLocations(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "plain-01")
	ca := pki.NewCA("Win", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "plain-01.corp.example", SANs: []string{"plain-01.corp.example"}}, h.clock.Now())
	sum, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{
		WebServer:    &providers.WebServerFacts{Software: "iis", Found: false, ConfigValid: true},
		Certificates: []providers.DiscoveredCertificate{winEntry(5986, winRMAppID, "", &leaf)},
		Warnings:     []providers.Warning{{Code: providers.WarnWebServerNotFound, Params: map[string]string{}}}})
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Locations)
	locs := byPath(t, h, tg.ID, false)
	require.Len(t, locs, 1)
	l := locs["http.sys/ipport/0.0.0.0:5986"]
	assert.False(t, l.Supported)
	assert.Equal(t, windows.UnsupportedForeignApp, l.UnsupportedReason)
	assert.Equal(t, "winrm", l.Details["application"])
	require.NotNil(t, l.Certificate, "a foreign binding's certificate is still known")
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Facts.WebServer)
	assert.False(t, got.Facts.WebServer.Found, "IIS not installed")
	assert.Equal(t, []string{providers.WarnWebServerNotFound}, h.warningCodes(tg.ID), "the scan's warning is stored")
	assert.Equal(t, "iis", got.Facts.WebServer.Software)
	assert.NotNil(t, got.LastDiscoveryAt)
	assert.Zero(t, h.count("SELECT count(*) FROM certificate_locations WHERE target_id = $1 AND supported", tg.ID))
}

// Review Focus 2: a scan that dropped locations marks nothing missing; a full one does.
func TestWindowsTruncatedScanMarksNothingMissing(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "iis-01")
	ca := pki.NewCA("Win", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	scan := func(warnings []providers.Warning, ports ...int) {
		t.Helper()
		var certs []providers.DiscoveredCertificate
		for _, p := range ports {
			certs = append(certs, winBinding(p, "Site", &leaf))
		}
		_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: iisOK, Certificates: certs, Warnings: warnings})
		require.NoError(t, err)
	}
	scan(nil, 443, 8443, 9443)
	assert.Len(t, byPath(t, h, tg.ID, false), 3)
	h.clock.Advance(time.Second)
	scan([]providers.Warning{{Code: providers.WarnListTruncated, Params: map[string]string{}},
		{Code: providers.WarnLocationsDropped, Params: map[string]string{}}}, 443)
	assert.Zero(t, h.missingLocations(tg.ID), "a cut dump proves nothing gone")
	assert.Equal(t, []string{providers.WarnListTruncated, providers.WarnLocationsDropped}, h.warningCodes(tg.ID), "the facts say the list is cut")
	h.clock.Advance(time.Second)
	scan(nil, 443)
	assert.Equal(t, 2, h.missingLocations(tg.ID))
	assert.Empty(t, h.warningCodes(tg.ID), "a full scan clears them")
	// A location the inventory cannot store (a malformed locator) is skipped: the facts say the list is cut.
	h.clock.Advance(time.Second)
	bad := winBinding(10443, "Site", &leaf)
	bad.Location.Locator = providers.Locator{}
	_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: iisOK,
		Certificates: []providers.DiscoveredCertificate{winBinding(443, "Site", &leaf), bad}})
	require.NoError(t, err)
	assert.Equal(t, []string{providers.WarnListTruncated}, h.warningCodes(tg.ID))
	assert.Len(t, byPath(t, h, tg.ID, false), 1)
}

// Ruling 9: a certificate missing from its store is a file problem without a certificate (the stored link goes); a key
// problem is a file problem whose certificate stays linked.
func TestWindowsProblemsAreFileProblems(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "iis-01")
	ca := pki.NewCA("Win", pki.ECDSA256, h.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: iisOK,
		Certificates: []providers.DiscoveredCertificate{winBinding(443, "Site", &leaf), winBinding(9443, "Site", &leaf)}})
	require.NoError(t, err)
	for _, p := range []string{"http.sys/ipport/0.0.0.0:443", "http.sys/ipport/0.0.0.0:9443"} {
		require.NotNil(t, byPath(t, h, tg.ID, false)[p].Certificate, "%s: first stored with its certificate", p)
	}

	gone := winBinding(443, "Site", nil) // the store no longer holds the bound certificate (the provider's output)
	gone.Location.Problem, gone.Location.Supported, gone.Location.Unsupported = windows.ProblemCertMissing, false, providers.UnsupportedFile
	key := winBinding(8443, "Site", &leaf)
	key.Location.KeyProblem, key.Location.Supported, key.Location.Unsupported = windows.ProblemKeyInaccessible, false, providers.UnsupportedFile
	bare := winBinding(9443, "Site", nil) // the inventory's own rule, without the provider's reason
	bare.Location.Problem = windows.ProblemCertMissing
	h.clock.Advance(time.Second)
	_, err = h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{gone, key, bare}})
	require.NoError(t, err)
	locs := byPath(t, h, tg.ID, false)
	for _, p := range []string{"http.sys/ipport/0.0.0.0:443", "http.sys/ipport/0.0.0.0:9443"} {
		l := locs[p]
		assert.Equal(t, windows.ProblemCertMissing, l.Problem, p)
		assert.False(t, l.Supported, p)
		assert.Equal(t, providers.UnsupportedFile, l.UnsupportedReason, p)
		assert.Nil(t, l.Certificate, "%s: the certificate link goes", p)
	}
	k := locs["http.sys/ipport/0.0.0.0:8443"]
	assert.Equal(t, windows.ProblemKeyInaccessible, k.KeyProblem)
	assert.False(t, k.Supported)
	assert.Equal(t, providers.UnsupportedFile, k.UnsupportedReason)
	require.NotNil(t, k.Certificate, "a key problem's certificate is still linked")
	assert.Equal(t, pki.Fingerprint(leaf.Cert), k.Certificate.Fingerprint)
}

// A connection test's Windows facts round-trip through GetTarget, cleaned.
func TestRecordConnectionOKStoresWindowsFacts(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "iis-01")
	stores := []string{}
	for i := range 20 {
		stores = append(stores, "Store"+strconv.Itoa(i+1))
	}
	w := &providers.WindowsFacts{Build: "10.0.20348.2700", Product: "Windows Server\x00 2022", InstallationType: "Server Core", Elevated: true,
		IISInstalled: true, IISVersion: "10.0", Stores: stores, OpenSSHVersion: "OpenSSH_for_Windows_8.1p1"}
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HelperVersion: "0.1.0", HelperProtocol: 1,
		OS: providers.OSRelease{ID: "windows", VersionID: "10.0.20348.2700", PrettyName: "Windows Server 2022"}, Windows: w,
		WebServer: &providers.WebServerFacts{Software: "iis", Version: "10.0", Found: true, ConfigValid: true}}))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Facts.Windows)
	f := *got.Facts.Windows
	assert.Equal(t, "Windows Server\ufffd 2022", f.Product, "a NUL is made storable")
	assert.Equal(t, "10.0.20348.2700", f.Build)
	assert.Equal(t, "Server Core", f.InstallationType)
	assert.True(t, f.Elevated)
	assert.True(t, f.IISInstalled)
	assert.Equal(t, "10.0", f.IISVersion)
	assert.Equal(t, stores[:16], f.Stores, "at most 16 stores")
	assert.Equal(t, "OpenSSH_for_Windows_8.1p1", f.OpenSSHVersion)
	assert.Equal(t, "windows", got.Facts.OS.ID)
	assert.Equal(t, "Windows Server\x00 2022", w.Product, "the report is not changed")

	// A report without Windows facts keeps the stored ones.
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HelperVersion: "0.1.0", HelperProtocol: 1}))
	again, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, got.Facts.Windows, again.Facts.Windows)
}

// Ruling 11: a stored Windows server is not IsServer (the predicate the key-files route,
// internal/api/sshkeys_handlers.go:402, and internal/sshkeys/deploy.go:217 refuse on), is an SSH target with certificate
// locations, and has no key locations or key files. The routes themselves are not driven here.
func TestWindowsTargetIsNoKeyServer(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg := winTarget(t, h, admin, "iis-01")
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.False(t, inventory.IsServer(got.Type), "the key-files route and sshkeys refuse it")
	assert.True(t, inventory.IsSSHTarget(got.Type), "it is reached over SSH")
	assert.True(t, inventory.HasCertificateLocations(got.Type))
	assert.Empty(t, got.Facts.KeyFiles)
	keys, err := h.svc.ListTargetKeys(h.ctx, tg.ID, true)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// SyncCapabilities rewrites a Windows server's set from the Windows provider.
func TestSyncCapabilitiesCoversWindows(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	id := h.seedTarget("iis-01", "windows", "iis-01.corp.example")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET capabilities = '{test_connection}' WHERE id = $1", id)
	require.NoError(t, err)
	n, err := h.svc.SyncCapabilities(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	var caps []string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT capabilities FROM targets WHERE id = $1", id).Scan(&caps))
	assert.Equal(t, []string{"cleanup_certificates", "deploy_certificate", "discover_certificates", "test_connection", "verify_deployment"}, caps)
}
