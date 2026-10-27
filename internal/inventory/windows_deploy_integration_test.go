//go:build integration

package inventory_test

import (
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is the certificate's SHA-1, an identifier, not a security measure
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R61 Task 10: Windows bindings are deployable locations, next to an Nginx server's files, with the real Windows
// provider registered (its deployment capability; nothing here dials).

// winDeployFixture: a connected Windows server iis-01 whose scan found five http.sys bindings holding the ECDSA leaf
// old (bound and spare: IIS, supported; foreign: WinRM's, win_foreign_app; keyProblem: a key Alice cannot use
// (Ruling 14: a file problem, unsupported); ccs: a Centralized Certificate Store binding, win_ccs), a connected Nginx
// server web-01 with one file of old, and the uploaded certificate nw with its key (its chain complete).
type winDeployFixture struct {
	h                                   *harness
	admin                               inventory.Actor
	ca                                  *pki.CA
	old, nw                             pki.Leaf
	cert                                inventory.Certificate
	win, web                            uuid.UUID
	bound, spare, foreign, keyProb, ccs uuid.UUID
	file                                uuid.UUID
}

// withNginxAndWindows: the harness's fake linuxssh provider, a fake Nginx provider and the real Windows provider.
func withNginxAndWindows() harnessOption {
	return func(c *inventory.Config) {
		ssh, _ := c.Registry.Get(providers.KindLinuxSSH)
		reg := providers.NewRegistry()
		reg.Register(ssh)
		reg.Register(fake.New(providers.KindNginx, nginxCaps...))
		reg.Register(windows.New(windows.Options{}))
		reg.Freeze()
		c.Registry = reg
	}
}

func thumbprint(l pki.Leaf) string {
	s := sha1.Sum(l.Cert.Raw) //nolint:gosec // G401: see the import
	return hex.EncodeToString(s[:])
}

func newWinDeployFixture(t *testing.T) *winDeployFixture {
	t.Helper()
	ca := pki.NewCA("Win", pki.ECDSA256, start)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	h := newHarness(t, withNginxAndWindows(), withRoots(roots))
	h.jobs.next = jobs.NewQueue(jobs.QueueConfig{Pool: h.db.App, Keyring: h.keyring, Audit: h.audit, Clock: h.clock, Gate: h.lic})
	f := &winDeployFixture{h: h, ca: ca, admin: h.user("ada", rbac.Admin, "ada@example.com")}
	www := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	f.old, f.nw = ca.Issue(www, h.clock.Now()), ca.Issue(www, h.clock.Now())

	f.win = winTarget(t, h, f.admin, "iis-01").ID
	bound := winBinding(443, "Default Web Site", &f.old)
	bound.Location.Details["cert_sha1"] = thumbprint(f.old)
	spare := winBinding(8443, "Shop", &f.old)
	spare.Location.Details["cert_sha1"] = thumbprint(f.old)
	foreign := winEntry(5986, winRMAppID, "", &f.old)
	keyProb := winBinding(9443, "Site", &f.old)
	keyProb.Location.KeyProblem, keyProb.Location.Supported, keyProb.Location.Unsupported = windows.ProblemKeyInaccessible, false,
		providers.UnsupportedFile
	ccs := providers.DiscoveredCertificate{Location: providers.CertLocation{Kind: providers.LocationWinSSLBinding, CertPath: "http.sys/ccs/10443",
		Locator: providers.Locator{"type": "ccs", "port": 10443, "app_id": winproto.AppIDIIS}, Supported: false, Unsupported: windows.UnsupportedCCS,
		Details: map[string]any{"app_id": winproto.AppIDIIS, "application": "iis"},
		Servers: []providers.CertServer{{Names: []string{"ccs.example.test"}, Section: "Ccs", Listens: []providers.CertListen{{Addr: "*", Port: 10443}}}}}}
	_, err := h.svc.Reconcile(h.ctx, f.win, providers.DiscoveryResult{WebServer: iisOK,
		Certificates: []providers.DiscoveredCertificate{bound, spare, foreign, keyProb, ccs}})
	require.NoError(t, err)
	locs := byPath(t, h, f.win, false)
	require.Len(t, locs, 5)
	f.bound, f.spare = locs["http.sys/ipport/0.0.0.0:443"].ID, locs["http.sys/ipport/0.0.0.0:8443"].ID
	f.foreign, f.keyProb, f.ccs = locs["http.sys/ipport/0.0.0.0:5986"].ID, locs["http.sys/ipport/0.0.0.0:9443"].ID, locs["http.sys/ccs/10443"].ID
	require.True(t, locs["http.sys/ipport/0.0.0.0:443"].Supported)
	require.False(t, locs["http.sys/ipport/0.0.0.0:9443"].Supported, "Ruling 14: a key problem stays unsupported")

	f.web = nginxTarget(t, h, f.admin, "web-01").ID
	_, err = h.svc.Reconcile(h.ctx, f.web, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old)}})
	require.NoError(t, err)
	f.file = byPath(t, h, f.web, false)["/etc/nginx/ssl/www.crt"].ID

	c, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.nw))
	require.NoError(t, err)
	require.True(t, c.ChainComplete)
	f.cert = c
	return f
}

func (f *winDeployFixture) request(loc uuid.UUID) inventory.RequestedDeployment {
	f.h.t.Helper()
	got, err := f.h.svc.RequestDeployment(f.h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{loc}})
	require.NoError(f.h.t, err)
	require.Len(f.h.t, got, 1)
	return got[0]
}

// start moves a requested deployment through its pre-check to the start record, as the engine does after a pre-check
// that found old served; between reads the material and the start record (a scan that ran meanwhile).
func (f *winDeployFixture) start(id uuid.UUID, between func()) inventory.SendValues {
	f.h.t.Helper()
	_, err := f.h.svc.BeginDeployment(f.h.ctx, id)
	require.NoError(f.h.t, err)
	m, err := f.h.svc.DeploymentMaterial(f.h.ctx, id, true)
	require.NoError(f.h.t, err)
	m.PrivateKeyPEM.Zero()
	if between != nil {
		between()
	}
	v := m.SendValues(pki.Fingerprint(f.old.Cert), 2)
	require.NoError(f.h.t, f.h.svc.StartDeployment(f.h.ctx, id, v))
	return v
}

func (f *winDeployFixture) rollbackInfo(id uuid.UUID) string {
	f.h.t.Helper()
	var raw string
	require.NoError(f.h.t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT rollback_info::text FROM deployments WHERE id = $1", id).Scan(&raw))
	return raw
}

// Ruling 20: a supported win_sslbinding is listed by its canonical text with no key path; an unsupported one (a foreign
// application), a CCS one and one with a key problem are not; the Nginx file is listed as before.
func TestListDeployableLocationsIncludesWindowsBindings(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	page, err := h.svc.ListDeployableLocations(h.ctx, inventory.LocationFilter{Limit: 200})
	require.NoError(t, err)
	got := map[uuid.UUID]inventory.DeployableLocation{}
	for _, l := range page.Items {
		got[l.ID] = l
	}
	assert.Len(t, got, 3, "two IIS bindings and the Nginx file")
	for _, id := range []uuid.UUID{f.foreign, f.keyProb, f.ccs} {
		assert.NotContains(t, got, id)
	}
	b := got[f.bound]
	assert.Equal(t, inventory.DeployableLocation{ID: f.bound, TargetID: f.win, TargetName: "iis-01", CertPath: "http.sys/ipport/0.0.0.0:443",
		KeyPath: "", KeyType: "ecdsa", ServerNames: []string{}}, b)
	assert.Equal(t, inventory.DeployableLocation{ID: f.file, TargetID: f.web, TargetName: "web-01", CertPath: "/etc/nginx/ssl/www.crt",
		KeyPath: "/etc/nginx/ssl/www.key", KeyType: "ecdsa", ServerNames: []string{"www.example.test"}}, got[f.file], "the file is listed as before")
	assert.Equal(t, []uuid.UUID{f.bound, f.spare, f.file}, ids(page.Items), "server name, then the canonical text or path")

	// The canonical text is searchable, the key type filters, and the cursor walks across both kinds.
	q, err := h.svc.ListDeployableLocations(h.ctx, inventory.LocationFilter{Query: "0.0.0.0:84"})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{f.spare}, ids(q.Items))
	rsa, err := h.svc.ListDeployableLocations(h.ctx, inventory.LocationFilter{KeyType: "rsa"})
	require.NoError(t, err)
	assert.Empty(t, rsa.Items)
	var walked []uuid.UUID
	cursor := ""
	for {
		p, err := h.svc.ListDeployableLocations(h.ctx, inventory.LocationFilter{Limit: 1, Cursor: cursor})
		require.NoError(t, err)
		walked = append(walked, ids(p.Items)...)
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	assert.Equal(t, []uuid.UUID{f.bound, f.spare, f.file}, walked)

	// A binding a later scan found gone is not listed.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET missing_since = now() WHERE id = $1", f.spare)
	require.NoError(t, err)
	page, err = h.svc.ListDeployableLocations(h.ctx, inventory.LocationFilter{})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{f.bound, f.file}, ids(page.Items))
}

func ids(ls []inventory.DeployableLocation) []uuid.UUID {
	out := []uuid.UUID{}
	for _, l := range ls {
		out = append(out, l.ID)
	}
	return out
}

// Ruling 20: a person's request queues one job for a Windows binding; the web server's configuration gate does not
// apply; an unsupported binding is location_unsupported; the trust of R49 refuses a cross-service request until a
// trust exists.
func TestRequestDeploymentToAWindowsBinding(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{web_server,config_valid}', 'false'::jsonb) WHERE id = $1", f.win)
	require.NoError(t, err)
	require.Equal(t, 1, h.count("SELECT count(*) FROM targets WHERE id = $1 AND facts->'web_server'->>'config_valid' = 'false'", f.win),
		"the server's configuration reads invalid")

	for name, loc := range map[string]uuid.UUID{"foreign": f.foreign, "key problem": f.keyProb, "ccs": f.ccs} {
		_, err := h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{loc}})
		var refused *inventory.LocationRefusalError
		require.ErrorAs(t, err, &refused, name)
		assert.Equal(t, loc, refused.LocationID, name)
		assert.ErrorIs(t, err, inventory.ErrLocationUnsupported, name)
	}
	assert.Equal(t, 3, h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND details->>'reason' = 'location_unsupported'"))

	def, pay := h.defaultService(), h.newService("Payments")
	h.moveTo("targets", f.win, pay)
	_, err = h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.bound}})
	assert.ErrorIs(t, err, inventory.ErrServiceUntrusted)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND details->>'reason' = $1",
		inventory.ReasonServiceUntrusted))
	h.trust(def, pay)

	r := f.request(f.bound)
	assert.NotEqual(t, uuid.Nil, r.JobID)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM jobs WHERE id = $1 AND type = $2", r.JobID, inventory.JobCertificateDeploy), "one deploy job")
	var kind, certPath, keyPath string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT location_kind, cert_path, key_path FROM deployments WHERE id = $1", r.ID).
		Scan(&kind, &certPath, &keyPath))
	assert.Equal(t, []string{"win_sslbinding", "http.sys/ipport/0.0.0.0:443", ""}, []string{kind, certPath, keyPath})

	m, err := h.svc.DeploymentMaterial(h.ctx, r.ID, true)
	require.NoError(t, err)
	defer m.PrivateKeyPEM.Zero()
	assert.Equal(t, providers.LocationWinSSLBinding, m.Location.Kind)
	assert.True(t, m.Location.Locator.Equal(providers.Locator{"type": "ipport", "ip": "0.0.0.0", "port": 443, "app_id": winproto.AppIDIIS}))
	assert.True(t, m.ConfigValid, "no web-server facts gate a binding")
	assert.Equal(t, derSHA(f.old), m.ExpectCertSHA256, "the DER hash is the compare-and-swap token")

	_, err = h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.bound}})
	assert.ErrorIs(t, err, inventory.ErrDeploymentInProgress)
}

// Ruling 17: the start record of a Windows deployment writes the previous certificate (store, SHA-1, DER SHA-256) and
// no backup folder; a rollback request carries it; a file's rollback_info is byte for byte what it was.
func TestStartDeploymentWritesTheWindowsBackupRef(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	r := f.request(f.bound)
	f.start(r.ID, nil)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(r.ID)), &got))
	assert.Equal(t, map[string]any{"operation_id": r.ID.String(), "store": "MY", "previous_sha1": thumbprint(f.old),
		"previous_sha256": derSHA(f.old)}, got)
	want := providers.BackupRef{OperationID: r.ID, Store: "MY", PreviousSHA1: thumbprint(f.old), PreviousSHA256: derSHA(f.old)}
	d, err := h.svc.Deployment(h.ctx, r.ID)
	require.NoError(t, err)
	require.NotNil(t, d.Backup)
	assert.Equal(t, want, *d.Backup)
	m, err := h.svc.DeploymentMaterial(h.ctx, r.ID, false)
	require.NoError(t, err)
	assert.Equal(t, want, m.RollbackRequest(m.Guard).Backup, "the rollback names the recorded previous certificate")

	// A scan between the material and the start record changed the binding's certificate: the token is still what the
	// send compares, but the details' store and thumbprint may be another certificate's, so both are left out.
	r2 := f.request(f.spare)
	f.start(r2.ID, func() {
		_, err := h.db.Owner.Exec(h.ctx, `UPDATE certificate_locations SET cert_file_sha256 = $2,
    details = jsonb_set(details, '{cert_sha1}', to_jsonb($3::text)) WHERE id = $1`, f.spare, derSHA(f.nw), thumbprint(f.nw))
		require.NoError(t, err)
	})
	got = nil
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(r2.ID)), &got))
	assert.Equal(t, map[string]any{"operation_id": r2.ID.String(), "previous_sha256": derSHA(f.old)}, got)

	// A file: exactly the Linux helper's backup folder, as before.
	rf := f.request(f.file)
	f.start(rf.ID, nil)
	assert.Equal(t, `{"dir": "`+inventory.BackupRoot+"/"+rf.ID.String()+`", "operation_id": "`+rf.ID.String()+`"}`, f.rollbackInfo(rf.ID))
	fm, err := h.svc.DeploymentMaterial(h.ctx, rf.ID, false)
	require.NoError(t, err)
	assert.Equal(t, providers.BackupRef{}, fm.RollbackRequest(fm.Guard).Backup, "a file's rollback request is as before")

	// A rollback failure names the previous certificate (Ruling 17's params, in place of backup_dir).
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		Result: "rollback_failed", FailedStep: "restore", ErrorCode: "windows.backup_missing",
		Params: map[string]string{"store": "MY", "previous_sha1": thumbprint(f.old), "secret": "x"}}))
	d, err = h.svc.Deployment(h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"store": "MY", "previous_sha1": thumbprint(f.old)}, d.ErrorParams)
}

// Ruling 16: the verify step's chain_differs, deployed_chain and built_chain are stored and returned.
func TestChainDiffersStepParamsAreKept(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	r := f.request(f.bound)
	f.start(r.ID, nil)
	require.NoError(t, h.svc.RecordDeploymentStep(h.ctx, r.ID, providers.StepNameVerify, providers.StepOK,
		map[string]string{"chain_differs": "true", "deployed_chain": "2", "built_chain": "3", "port": "443", "other": "x"}))
	d, err := h.svc.Deployment(h.ctx, r.ID)
	require.NoError(t, err)
	require.NotEmpty(t, d.Steps)
	last := d.Steps[len(d.Steps)-1]
	assert.Equal(t, providers.StepNameVerify, last.Name)
	assert.Equal(t, map[string]string{"chain_differs": "true", "deployed_chain": "2", "built_chain": "3", "port": "443"}, last.Params)
}

// W5 (R68): a CCS file's step params are kept: ccs_unlinked on the verify step (Ruling 8) and ccs_refresh_failed on
// the write_file and restore steps (F15 route (a)).
func TestCCSStepParamsAreKept(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	r := f.request(f.bound)
	f.start(r.ID, nil)
	require.NoError(t, h.svc.RecordDeploymentStep(h.ctx, r.ID, providers.StepNameWriteFile, providers.StepOK,
		map[string]string{"ccs_refresh_failed": "true", "other": "x"}))
	require.NoError(t, h.svc.RecordDeploymentStep(h.ctx, r.ID, providers.StepNameVerify, providers.StepSkipped,
		map[string]string{"ccs_unlinked": "true", "mode": "skipped"}))
	d, err := h.svc.Deployment(h.ctx, r.ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(d.Steps), 2)
	steps := d.Steps[len(d.Steps)-2:]
	assert.Equal(t, map[string]string{"ccs_refresh_failed": "true"}, steps[0].Params)
	assert.Equal(t, map[string]string{"ccs_unlinked": "true", "mode": "skipped"}, steps[1].Params)
}

// R61 helper_outdated names both versions (Ruling 3): a refusal's params are kept.
func TestWindowsRefusalParamsAreKept(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	r := f.request(f.bound)
	_, err := h.svc.BeginDeployment(h.ctx, r.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, Result: "no_change",
		ErrorCode: "windows.helper_outdated", Params: map[string]string{"helper_version": "0.1.0", "required_version": "0.2.0"}}))
	d, err := h.svc.Deployment(h.ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"helper_version": "0.1.0", "required_version": "0.2.0"}, d.ErrorParams)
}

// W2 final review Minor 2: after a successful deployment a Windows location names the deployed leaf's thumbprint, or
// none at all: when it cannot be derived (the token is not the stored chain's leaf, or unknown) the old thumbprint is
// removed, never kept next to the new token (the next deployment's rollback info would name the wrong certificate).
func TestASuccessWithoutADerivableThumbprintDropsTheOldOne(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	details := func(loc uuid.UUID) map[string]any {
		t.Helper()
		var raw []byte
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT details FROM certificate_locations WHERE id = $1", loc).Scan(&raw))
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		return m
	}
	finish := func(loc uuid.UUID, token string) uuid.UUID {
		t.Helper()
		r := f.request(loc)
		f.start(r.ID, nil)
		require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded,
			Verified: "remote", Result: "committed", Phase: "committed", CertFileSHA256: token}))
		return r.ID
	}

	// Positive control: the token is the deployed leaf's, so its thumbprint replaces the old one.
	finish(f.bound, derSHA(f.nw))
	assert.Equal(t, thumbprint(f.nw), details(f.bound)["cert_sha1"])

	// A token that is not the stored chain's leaf: no thumbprint, the old one removed, the rest of the details kept.
	require.Equal(t, thumbprint(f.old), details(f.spare)["cert_sha1"])
	other := pki.Fingerprint(f.ca.Intermediate)
	finish(f.spare, other)
	got := details(f.spare)
	assert.NotContains(t, got, "cert_sha1", "a thumbprint that cannot be derived is removed, not kept")
	assert.Equal(t, "MY", got["store"], "the other details stay")
	var token string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT cert_file_sha256 FROM certificate_locations WHERE id = $1", f.spare).Scan(&token))
	assert.Equal(t, other, token)

	// The next deployment's rollback info then names no thumbprint rather than a wrong one.
	r := f.request(f.spare)
	_, err := h.svc.BeginDeployment(h.ctx, r.ID)
	require.NoError(t, err)
	m, err := h.svc.DeploymentMaterial(h.ctx, r.ID, true)
	require.NoError(t, err)
	m.PrivateKeyPEM.Zero()
	require.NoError(t, h.svc.StartDeployment(h.ctx, r.ID, m.SendValues(other, 2)))
	var info map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(r.ID)), &info))
	assert.NotContains(t, info, "previous_sha1")
}
