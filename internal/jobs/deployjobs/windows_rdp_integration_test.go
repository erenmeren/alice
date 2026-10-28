//go:build integration

package deployjobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/jobs/driftjobs"
	"alice/internal/jobs/winjobs"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// R69 Task 6: Remote Desktop listener deployments through the whole stack (the real queue, runner, deployment engine,
// inventory on PostgreSQL, the Windows provider over SSH with its RDP probe, and the helper's own code on wintest's
// modelled host). The engine has no RDP branch: every test here runs the production code unchanged.

// rdpListenPort is the emulated listener's port (served on a random local port: Model.Endpoint).
const rdpListenPort = 3389

// rdpSteps is the step list of a committed RDP deployment that Alice verified.
var rdpSteps = []string{"verify_current:started", "verify_current:ok", "import_chain:ok", "import_certificate:ok", "grant_key_read:ok",
	"set_listener:ok", "verify:started", "verify:ok"}

// rdpServer is an emulated Windows server with addWinServer's IIS binding (www.example.test:443 naming the old
// certificate in My) and the RDP-Tcp listener (on, SecurityLayer 2, NLA on) with one self-signed certificate in Remote
// Desktop. With selfSigned the listener names no certificate (it serves the self-signed one); otherwise it names the
// old certificate too, whose key NETWORK SERVICE may read. loc is the listener's location, binding the binding's.
type rdpServer struct {
	*winServer
	binding  uuid.UUID
	self     pki.Leaf
	selfSHA1 string
}

// addRDPServer starts the emulated server, adds it as a target, confirms its host key and runs the first discovery:
// the listener is a deployable location.
func (e *env) addRDPServer(name string, selfSigned bool) *rdpServer {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	m := wintest.NewModel()
	m.SetLockWait(50 * time.Millisecond)
	m.AddIntermediate(e.ca.IntermediatePEM)
	s := &rdpServer{winServer: &winServer{model: m, locator: winproto.Locator{Type: winproto.BindingHostnamePort, Host: wwwName, Port: 443,
		AppID: winproto.AppIDIIS}}}
	s.oldSHA1 = m.AddCertificate("My", e.old.CertPEM, e.old.KeyPEM, wintest.CertOptions{FriendlyName: "www"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: wwwName, Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: s.oldSHA1, Store: "My"})
	m.AddSite(winproto.Site{Name: "Default Web Site", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:" + wwwName, SSLFlags: 1}}})
	s.self = pki.SelfSigned("win-rdp01", pki.ECDSA256, e.clock.Now())
	s.selfSHA1 = m.AddCertificate(winproto.RDPStoreSelfSigned, s.self.CertPEM, s.self.KeyPEM, wintest.CertOptions{})
	m.SetRDP(wintest.RDPConfig{Present: true, Enabled: true, NLA: true, Port: rdpListenPort, SecurityLayer: 2})
	if !selfSigned {
		require.NoError(e.t, m.Host().SetRDPKeyRead(context.Background(), "My", s.oldSHA1, true))
		m.SetRDPThumbprint(s.oldSHA1)
	}
	s.srv = wintest.NewServer(e.t, m) // after the listener: its port is served with the binding's
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk.PublicKey))
	require.NoError(e.t, err)
	s.srv.Authorize(pub)
	s.host, s.sshPort = s.srv.Addr()
	e.mu.Lock()
	e.wins = append(e.wins, s.winServer)
	e.mu.Unlock()
	tg, _, err := e.inv.CreateTarget(e.ctx, e.admin, inventory.NewTarget{Name: name, Type: inventory.TypeWindows, Host: s.host, Port: s.sshPort})
	require.NoError(e.t, err)
	s.target = tg.ID
	e.drain()
	keys, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, keys, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	list, err := e.inv.ListLocations(e.ctx, tg.ID, false)
	require.NoError(e.t, err)
	for _, l := range list.Items {
		switch l.CertPath {
		case winproto.RDPCanonical:
			require.True(e.t, l.Deployable, "the listener is deployable: %s", l.UnsupportedReason)
			s.loc = l.ID
		case winText:
			s.binding = l.ID
		}
	}
	require.NotEqual(e.t, uuid.Nil, s.loc, "the listener is a location")
	return s
}

// rdpServed is the leaf's SHA-256 a handshake with the listener shows after the RDP negotiation ("" when it fails).
func (e *env) rdpServed() string {
	p, err := winProber{wins: e.winList, rdp: true}.Probe(context.Background(), "", rdpListenPort, "", helperproto.ProbeAny)
	if err != nil {
		return ""
	}
	return p.LeafSHA256
}

// assertRDPServes checks the server and Alice's record against each other: the listener names exactly want, a
// handshake shows exactly want, NETWORK SERVICE can read want's key, and the location's token is want's DER hash.
func (e *env) assertRDPServes(s *rdpServer, want pki.Leaf) {
	e.t.Helper()
	assert.Equal(e.t, thumbprintOf(want.Cert.Raw), s.model.RDPThumbprint(), "the listener names the certificate the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), e.rdpServed(), "the listener serves the certificate the record claims")
	assert.True(e.t, s.model.KeyReadableByNetworkService("My", thumbprintOf(want.Cert.Raw)), "TermService can use the key")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), e.winLocation(s.winServer).CertFileSHA256, "Alice's token is what the listener names")
}

// deployTo uploads l (with its chain as given) and deploys it to locs through the engine.
func (e *env) deployTo(l pki.Leaf, chainPEM []byte, locs ...uuid.UUID) []inventory.Deployment {
	e.t.Helper()
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(chainPEM), PrivateKeyPEM: string(l.KeyPEM)})
	require.NoError(e.t, err)
	e.evaluate()
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: locs, ConfirmIncompleteChain: true})
	require.NoError(e.t, err)
	out := make([]inventory.Deployment, 0, len(got))
	for _, g := range got {
		out = append(out, e.settle(g.ID))
	}
	return out
}

// Review Focus 3: the first deployment over the self-signed certificate sets the value (level 2 with a private CA);
// with a listener that does not take it, the rollback deletes the value again, takes the NETWORK SERVICE grant back,
// and verify_old sees the self-signed certificate.
func TestWindowsRDPFirstDeployAndRollback(t *testing.T) {
	private := func(e *env) pki.Leaf {
		return pki.NewCA("Private", pki.ECDSA256, e.clock.Now()).Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	}
	t.Run("committed", func(t *testing.T) {
		e := newEnv(t)
		s := e.addRDPServer("iis-01", true)
		loc := e.winLocation(s.winServer)
		assert.Equal(t, providers.LocationWinRDP, loc.Kind)
		assert.Equal(t, pki.Fingerprint(s.self.Cert), loc.CertFileSHA256, "the token is the self-signed leaf (Ruling 4)")
		assert.Equal(t, true, loc.Details["self_signed"])
		l := private(e)
		d := e.deployTo(l, l.FullchainPEM, s.loc)[0]
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, rdpSteps, stepList(d.Steps))
		assert.Equal(t, providers.LevelServed, d.Level)
		require.NotNil(t, d.Backup)
		assert.Equal(t, providers.BackupRef{OperationID: d.ID, Store: winproto.RDPStoreSelfSigned, PreviousSHA1: s.selfSHA1,
			PreviousSHA256: pki.Fingerprint(s.self.Cert)}, *d.Backup, "the self-signed certificate's store (W6 Ruling 19)")
		e.assertRDPServes(s, l)
		after := e.winLocation(s.winServer)
		assert.Equal(t, "MY", after.Details["store"], "the next deployment's previous certificate is in My")
		assert.Equal(t, false, after.Details["self_signed"])
		assert.Equal(t, winproto.PhaseCommitted, s.phase(t, d.ID))
		assert.Equal(t, 1, s.sent(winproto.SubRDPDeploy))
		assert.Zero(t, s.sent(winproto.SubIISDeploy))
	})
	t.Run("rolled back", func(t *testing.T) {
		e := newEnv(t)
		s := e.addRDPServer("iis-01", true)
		s.model.ServeStaleRDP(true)
		l := private(e)
		d := e.deployTo(l, l.FullchainPEM, s.loc)[0]
		require.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
		assert.Contains(t, stepList(d.Steps), "verify_old:ok", "the self-signed certificate is served again")
		assert.Equal(t, winproto.PhaseRestored, s.phase(t, d.ID))
		assert.Empty(t, s.model.RDPThumbprint(), "the value is absent again")
		assert.False(t, s.model.KeyReadableByNetworkService("My", thumbprintOf(l.Cert.Raw)), "the grant is taken back")
		s.model.ServeStaleRDP(false)
		assert.Equal(t, pki.Fingerprint(s.self.Cert), e.rdpServed())
		assert.Equal(t, pki.Fingerprint(s.self.Cert), e.winLocation(s.winServer).CertFileSHA256)
	})
}

// Design §13 W6: a manual deployment over a certificate of My verifies at level 3 with the world's CA; a chain Windows
// builds longer than the one deployed is the verify step's chain_differs (W2 Ruling 16, win.chain_differs).
func TestWindowsRDPManualDeploy(t *testing.T) {
	t.Run("trusted", func(t *testing.T) {
		e := newEnv(t)
		s := e.addRDPServer("iis-01", false)
		id := e.request(s.loc)[0]
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, rdpSteps, stepList(d.Steps))
		assert.Equal(t, "remote", d.Verified)
		assert.Equal(t, providers.LevelTrusted, d.Level)
		assert.Equal(t, pki.Fingerprint(e.old.Cert), d.ExpectCertSHA256)
		require.NotNil(t, d.Backup)
		assert.Equal(t, providers.BackupRef{OperationID: id, Store: "MY", PreviousSHA1: s.oldSHA1, PreviousSHA256: pki.Fingerprint(e.old.Cert)}, *d.Backup)
		e.assertRDPServes(s, e.nw)
		assert.Equal(t, s.oldSHA1, s.bound(), "the binding is untouched")
		for _, c := range s.srv.Commands() {
			assert.NotContains(t, c, "PRIVATE KEY", "the key is never on a command line")
		}
	})
	t.Run("chain differs", func(t *testing.T) {
		e := newEnv(t)
		s := e.addRDPServer("iis-01", false)
		l := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
		d := e.deployTo(l, l.CertPEM, s.loc)[0] // the leaf alone: Windows builds it with the intermediate in CA
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		var params map[string]string
		for _, st := range d.Steps {
			if st.Name == providers.StepNameVerify && st.Status != "started" {
				params = st.Params
			}
		}
		assert.Equal(t, "true", params["chain_differs"], "%v", params)
		assert.Equal(t, "1", params["deployed_chain"])
		assert.Equal(t, "2", params["built_chain"])
		e.assertRDPServes(s, l)
	})
}

// Review Focus 4 (R48): with the previous certificate's key compromised during the deployment, the helper's guard
// refuses the restore: rollback_failed deployment.rollback_forbidden, the listener keeps the new certificate.
func TestWindowsRDPGuardForbids(t *testing.T) {
	e := newEnv(t)
	s := e.addRDPServer("iis-01", false)
	s.model.ServeStaleRDP(true)
	e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return deployWith{Session: sess, f: e.compromiseOld}
	})
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusRollbackFailed, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, providers.ReasonRollbackForbidden, d.ErrorCode)
	assert.Equal(t, providers.PhaseRestoreForbidden, d.Phase)
	assert.Equal(t, providers.StepNameRestore, d.FailedStep)
	assert.Equal(t, thumbprintOf(e.nw.Cert.Raw), s.model.RDPThumbprint(), "the compromised certificate is never put back")
	assert.Equal(t, winproto.PhaseRestoreForbidden, s.phase(t, id))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key LIKE 'deployment.rollback_forbidden%'"))
}

// rdpKillRows are the rows of rdp-deploy's and iis-restore's crash points (Task 2), by point.
var rdpKillRows = map[string]winKillRow{
	"rdp.locked":             {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhaseNone},
	"rdp.prepared":           {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"rdp.import_chain":       {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"rdp.import_certificate": {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"rdp.granted":            {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"rdp.grant_key_read":     {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"rdp.writing":            {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"rdp.set":                {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"rdp.read_back":          {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"rdp.committed":          {status: inventory.DeployStatusSucceeded, want: newLeaf},
	"restore.restoring":      {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.bound":          {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.restored":       {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
}

// Review Focus 1 and 2: the helper is killed at every crash point of an RDP deployment and its restore (it answers
// nothing), the server reboots, and Alice's recovery ends the deployment: the listener then names exactly the previous
// or the new certificate, the listener serves what the record claims, and no NETWORK SERVICE grant is left on the new
// key unless it is the listener's; a kill before writing is fenced.
func TestWindowsRDPCrashTable(t *testing.T) {
	e := newEnv(t)
	s := e.addRDPServer("iis-01", false)
	s.model.ServeStaleRDP(true)
	e.request(s.loc)
	e.drain()
	points := s.model.Points()
	require.Len(t, points, len(rdpKillRows), "%v", points)
	for _, p := range points {
		require.Contains(t, rdpKillRows, p, "a crash point without a row")
	}

	for _, point := range points {
		tc := rdpKillRows[point]
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addRDPServer("iis-01", false)
			s.model.ServeStaleRDP(tc.stale)
			s.model.KillAt(point)
			id := e.request(s.loc)[0]
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "a killed helper is an uncertain outcome")

			s.model.ServeStaleRDP(false)
			s.model.Reboot()
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertRDPServes(s, tc.want(e))
			if tc.status != inventory.DeployStatusSucceeded {
				assert.False(t, s.model.KeyReadableByNetworkService("My", thumbprintOf(e.nw.Cert.Raw)), "no grant is left on the new key")
			}
			if tc.status == inventory.DeployStatusRolledBack {
				assert.Equal(t, winproto.PhaseRestored, s.phase(t, id), "the helper's journal agrees with the record")
			}
			assert.Equal(t, 1, s.sent(winproto.SubRDPDeploy), "the certificate is sent at most once")
			if tc.fenced {
				assert.Equal(t, winproto.PhaseFenced, s.phase(t, id))
				assert.Equal(t, tc.phase, d.Phase)
			}
		})
	}
}

// Design §13 W6: automatic deployment reaches the listener: an ACME binding (the first certificate and its renewal) and
// a Key Vault binding's new version.
func TestWindowsRDPACMEAndKeyVault(t *testing.T) {
	t.Run("acme", func(t *testing.T) {
		w := newACMEWorld(t)
		s := w.addRDPServer("iis-01", false)
		c := w.define()
		_, err := w.inv.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
		require.NoError(t, err)
		w.drain()
		cert1, fp1 := w.current(c.ID)
		_, err = w.inv.AddACMEBinding(w.ctx, w.admin, c.ID, s.loc, true)
		require.NoError(t, err)
		ids := w.planDeploy(cert1)
		require.Len(t, ids, 1)
		w.drain()
		d := w.deployment(ids[0])
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, fp1, w.rdpServed())

		cert2, fp2 := w.renew(w.acmeCert(c.ID))
		ids = w.planDeploy(cert2)
		require.Len(t, ids, 1)
		w.drain()
		d = w.deployment(ids[0])
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, inventory.TriggerACMERenewal, d.Trigger)
		assert.Equal(t, fp1, d.PreviousFingerprint)
		assert.Equal(t, rdpSteps, stepList(d.Steps))
		assert.Equal(t, fp2, w.rdpServed())
		assert.Equal(t, fp2, w.winLocation(s.winServer).CertFileSHA256)
	})
	t.Run("key vault", func(t *testing.T) {
		w := newKVWorld(t)
		s := w.addRDPServer("iis-01", false)
		b := w.bind(s.loc)
		first := w.settle(w.deploy(b, false)[0])
		require.Equal(t, inventory.DeployStatusSucceeded, first.Status, "%s %v", first.ErrorCode, first.ErrorParams)
		w.assertRDPServes(s, w.nw)
		b, err := w.inv.SetAutoDeploy(w.ctx, w.admin, b.ID, b.Version, true)
		require.NoError(t, err)
		w.clock.Advance(time.Minute)
		l := w.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, w.clock.Now())
		ver2 := fmt.Sprintf("%032x", 2)
		w.renewVersion(l, ver2)
		w.serve(append(append([]byte(nil), l.KeyPEM...), l.FullchainPEM...))
		n, err := w.inv.PlanKVAutoDeploy(w.ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n, "one automatic deployment")
		var id uuid.UUID
		require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT id FROM deployments WHERE location_id = $1 AND trigger = 'kv_renewal'", s.loc).Scan(&id))
		d := w.settle(id)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, ver2, d.KVVersion)
		w.assertRDPServes(s, l)
	})
}

// W6 Ruling 21: a third party re-points the listener to another certificate: the location drifts, and mode auto
// repairs it through the engine (trigger drift_repair), guarded by the token.
func TestWindowsRDPDriftRepaired(t *testing.T) {
	w := newACMEWorld(t)
	require.NoError(t, w.fake.SetLeafLifetime(90*24*time.Hour))
	driftjobs.Register(w.runner, driftjobs.Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: w.log()})
	s := w.addRDPServer("iis-01", false)
	s.model.SetNow(w.clock.Now())
	w.loc = s.loc
	d := &driftWorld{acmeWorld: w, schedule: driftjobs.ScheduleTask(w.inv, time.Minute, w.log()),
		repair: driftjobs.RepairTask(w.inv, time.Minute, w.log())}
	d.acme, d.c2 = w.issueFirst()
	require.Equal(t, d.c2, w.rdpServed(), "the listener serves C2")
	o := d.observe()
	require.Equal(t, inventory.HealthInSync, o.Health)
	require.Equal(t, inventory.DriftModeAuto, o.Mode)

	s.model.SetRDPThumbprint(s.oldSHA1) // another tool points the listener at C1
	o = d.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	require.NotNil(t, o.TLS)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), o.TLS.Fingerprint, "the listener serves C1")

	deploys := s.sent(winproto.SubRDPDeploy)
	assert.Equal(t, []string{inventory.DeployStatusSucceeded}, d.repairNow())
	assert.Equal(t, deploys+1, s.sent(winproto.SubRDPDeploy), "through rdp-deploy")
	assert.Equal(t, d.c2, w.rdpServed(), "the listener serves C2 again")
	o = d.observe()
	assert.Equal(t, inventory.HealthInSync, o.Health)
	assert.Empty(t, d.repairNow(), "nothing more to repair")
}

// W6 Ruling 9: Remote Desktop turned off after the location was discovered: the deployment is refused by the helper
// with nothing changed (windows.rdp_disabled, ALC-WIN-0021).
func TestWindowsRDPDisabledRefuses(t *testing.T) {
	e := newEnv(t)
	s := e.addRDPServer("iis-01", false)
	s.model.SetRDP(wintest.RDPConfig{Present: true, Enabled: false, NLA: true, Port: rdpListenPort, SecurityLayer: 2})
	e.setSkip(s.winServer, true) // nothing serves the listener now: the precheck would stop first; the helper's refusal is tested
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "windows.rdp_disabled", d.ErrorCode)
	assert.Equal(t, "", s.phase(t, id), "a refusal before any change writes no journal")
	assert.Equal(t, s.oldSHA1, s.model.RDPThumbprint(), "the listener is untouched")
	assert.Empty(t, s.model.Imported(), "nothing imported")
	assert.Zero(t, s.sent(winproto.SubIISRestore))
}

// W6 Ruling 9 step 6: NETWORK SERVICE cannot be given read access to the new key: the helper answers restored before
// any listener write (its own restore, as for a failed import in W2: the engine records rolled_back), with
// windows.rdp_key_acl_failed (ALC-WIN-0023) and the listener untouched.
func TestWindowsRDPKeyACLFails(t *testing.T) {
	e := newEnv(t)
	s := e.addRDPServer("iis-01", false)
	s.model.FailKeyACL(true)
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "windows.rdp_key_acl_failed", d.ErrorCode)
	assert.Equal(t, providers.StepNameGrantKeyRead, d.FailedStep)
	assert.Equal(t, winproto.PhaseRestored, s.phase(t, id))
	assert.Equal(t, s.oldSHA1, s.model.RDPThumbprint(), "the listener is untouched")
	assert.Equal(t, pki.Fingerprint(e.old.Cert), e.rdpServed())
	assert.False(t, s.model.KeyReadableByNetworkService("My", thumbprintOf(e.nw.Cert.Raw)))
	assert.Zero(t, s.sent(winproto.SubIISRestore))
}

// W6 Ruling 7 (and Ruling 26's emulator half): C2 on a binding and on the listener. Once the listener's deployment is
// replaced by C3, windows.cleanup keeps C2 while the binding names it; once the binding moves too, C2 is removed with
// its key after the week.
func TestWindowsRDPSharedCertificateCleanup(t *testing.T) {
	e := newEnv(t)
	winjobs.Register(e.runner, winjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.clock, Log: e.log()})
	s := e.addRDPServer("iis-01", false)
	s.model.SetNow(e.clock.Now())
	require.NotEqual(t, uuid.Nil, s.binding)
	for _, id := range e.request(s.binding, s.loc) {
		require.Equal(t, inventory.DeployStatusSucceeded, e.settle(id).Status)
	}
	c2SHA1 := thumbprintOf(e.nw.Cert.Raw)
	require.Equal(t, c2SHA1, s.bound())
	require.Equal(t, c2SHA1, s.model.RDPThumbprint())
	c3 := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	d := e.deployTo(c3, c3.FullchainPEM, s.loc)[0]
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)

	e.advanceBoth(s.winServer, 8*24*time.Hour)
	status, res := e.cleanupNow(s.winServer)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 0, res["removed"], "%v", res)
	assert.True(t, s.model.HasCertificate("My", c2SHA1), "the binding still names C2")
	assert.Equal(t, c2SHA1, s.bound())

	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: d.CertificateID, LocationIDs: []uuid.UUID{s.binding}})
	require.NoError(t, err)
	d = e.settle(got[0].ID)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	status, res = e.cleanupNow(s.winServer) // the helper counts C2's week from today, the first day nothing names it
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 0, res["removed"], "%v", res)
	e.advanceBoth(s.winServer, 8*24*time.Hour)
	status, res = e.cleanupNow(s.winServer)
	require.Equal(t, "succeeded", status, "%v", res)
	assert.EqualValues(t, 1, res["removed"], "%v", res)
	assert.False(t, s.model.HasCertificate("My", c2SHA1), "C2 is removed once nothing uses it")
	assert.False(t, s.model.HasKey("My", c2SHA1), "with its key, and the grant with it")
	assert.True(t, s.model.HasCertificate("My", thumbprintOf(c3.Cert.Raw)), "the listener's certificate is kept")
	assert.True(t, s.model.HasCertificate(winproto.RDPStoreSelfSigned, s.selfSHA1), "the self-signed certificate is never Alice's")
}
