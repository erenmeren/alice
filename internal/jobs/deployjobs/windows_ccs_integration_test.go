//go:build integration

package deployjobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/jobs/driftjobs"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// R68 Task 7: CCS file deployments through the whole stack (the real queue, runner, deployment engine, inventory on
// PostgreSQL with the server's sealed CCS password, the Windows provider over SSH, and the helper's own code on wintest's
// modelled host). The engine has no CCS branch: every test here runs the production code unchanged.

const ccsFolder = `C:\CCS`

// ccsText is the CCS file's location (its cert path): the folder and the file IIS reads for www.example.test.
const ccsText = ccsFolder + `\` + wwwName + ".pfx"

// ccsSteps is the step list of a committed CCS deployment that Alice verified.
var ccsSteps = []string{"verify_current:started", "verify_current:ok", "import_chain:ok", "write_file:ok", "verify:started", "verify:ok"}

// ccsServer is an emulated Windows server whose IIS has the Centralized Certificate Store on at C:\CCS: the file
// www.example.test.pfx holds the old certificate under the store's password pw, served by the http.sys record ccs:443
// and the site "CCS Site" (https *:443:www.example.test, sslFlags 3). Alice holds pw as the server's CCS password.
type ccsServer struct {
	*winServer
	pw       string
	oldBytes []byte // the file as the server held it before Alice
}

// addCCSServer starts the emulated CCS server, adds it as a target, sets its CCS password (an Administrator's act),
// confirms its host key and runs the first discovery: the CCS file is a deployable location.
func (e *env) addCCSServer(name string) *ccsServer {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	pw := "ccs-" + rand.Text()
	m := wintest.NewModel()
	m.SetLockWait(50 * time.Millisecond)
	m.AddIntermediate(e.ca.IntermediatePEM)
	m.SetCCS(true, ccsFolder)
	m.SetCCSPassword(pw)
	m.PutCCSFile(wwwName+".pfx", e.old.Cert, []*x509.Certificate{e.ca.Intermediate}, e.old.Key, pw)
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS})
	m.AddSite(winproto.Site{Name: "CCS Site", ID: 3, State: "Started", Bindings: []winproto.SiteBinding{
		{Protocol: "https", Information: "*:443:" + wwwName, SSLFlags: 3}}})
	s := &ccsServer{winServer: &winServer{model: m}, pw: pw}
	s.oldBytes, _ = m.CCSFile(wwwName + ".pfx")
	s.srv = wintest.NewServer(e.t, m)
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
	_, err = e.inv.SetCCSPassword(e.ctx, e.admin, tg.ID, tg.Version, secrets.NewPlaintext([]byte(pw)))
	require.NoError(e.t, err)
	e.drain()
	keys, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, keys, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	got, err := e.inv.GetTarget(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Equal(e.t, inventory.StatusOK, got.Status, "the Windows server is connected and discovered")
	list, err := e.inv.ListLocations(e.ctx, tg.ID, false)
	require.NoError(e.t, err)
	for _, l := range list.Items {
		if l.CertPath == ccsText {
			require.True(e.t, l.Deployable, "the CCS file is deployable: %s", l.UnsupportedReason)
			s.loc = l.ID
		}
	}
	require.NotEqual(e.t, uuid.Nil, s.loc, "the CCS file is a location")
	return s
}

// file is the leaf the CCS file holds now ("" when there is none or the password does not open it).
func (s *ccsServer) file() string {
	data, ok := s.model.CCSFile(wwwName + ".pfx")
	if !ok {
		return ""
	}
	leaf, _, _, err := pki.OpenPFXKey(data, []byte(s.pw))
	if err != nil {
		return ""
	}
	c, err := x509.ParseCertificate(leaf)
	if err != nil {
		return ""
	}
	return pki.Fingerprint(c)
}

// backup is the name of a backup the helper keeps in the folder ("" when there is none).
func (s *ccsServer) backup() string {
	for _, n := range s.model.CCSNames() {
		if strings.HasSuffix(n, ".bak") {
			return n
		}
	}
	return ""
}

// assertCCSServes checks the server and Alice's record against each other: the file holds exactly want, a handshake
// shows exactly want, and the location's compare-and-swap token is want's DER hash.
func (e *env) assertCCSServes(s *ccsServer, want pki.Leaf) {
	e.t.Helper()
	assert.Equal(e.t, pki.Fingerprint(want.Cert), s.file(), "the file holds the certificate the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), s.served(), "the website serves the certificate the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), e.winLocation(s.winServer).CertFileSHA256, "Alice's token is the file's leaf")
}

// Design §13 W5: a manual deployment writes the CCS file (import_chain, write_file) and verifies through the linked
// binding: level 3 with the world's CA, level 2 with a private CA.
func TestWindowsCCSManualDeploy(t *testing.T) {
	t.Run("trusted", func(t *testing.T) {
		e := newEnv(t)
		s := e.addCCSServer("iis-01")
		loc := e.winLocation(s.winServer)
		assert.Equal(t, providers.LocationWinCCSFile, loc.Kind)
		assert.Equal(t, pki.Fingerprint(e.old.Cert), loc.CertFileSHA256)
		id := e.request(s.loc)[0]
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, ccsSteps, stepList(d.Steps))
		assert.Equal(t, "remote", d.Verified)
		assert.Equal(t, providers.LevelTrusted, d.Level)
		assert.Equal(t, pki.Fingerprint(e.old.Cert), d.ExpectCertSHA256, "the token is the file's leaf (W5 Ruling 13)")
		require.NotNil(t, d.Backup)
		assert.Equal(t, providers.BackupRef{OperationID: id, PreviousSHA256: pki.Fingerprint(e.old.Cert)}, *d.Backup, "W5 Ruling 21")
		e.assertCCSServes(s, e.nw)
		assert.Equal(t, winproto.PhaseCommitted, s.phase(t, id))
		assert.Equal(t, 1, s.sent(winproto.SubCCSDeploy))
		assert.Zero(t, s.sent(winproto.SubIISDeploy))
		assert.Empty(t, s.model.Imported(), "nothing is imported into a store")
		assert.NotEmpty(t, s.backup(), "the backup stays in the folder until the prune")
		for _, c := range s.srv.Commands() {
			assert.NotContains(t, c, s.pw, "the password is never on a command line")
			assert.NotContains(t, c, "PRIVATE KEY")
		}
		for _, table := range []string{"audit_log", "deployments", "jobs", "certificate_locations", "notifications_outbox"} {
			assert.Zero(t, e.count("SELECT count(*) FROM "+table+" r WHERE r::text LIKE '%' || $1 || '%'", s.pw), "never in %s", table)
		}
	})
	t.Run("served: a private CA", func(t *testing.T) {
		e := newEnv(t)
		s := e.addCCSServer("iis-01")
		other := pki.NewCA("Private", pki.ECDSA256, e.clock.Now()).Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
		c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(other.FullchainPEM), PrivateKeyPEM: string(other.KeyPEM)})
		require.NoError(t, err)
		e.evaluate()
		got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc},
			ConfirmIncompleteChain: true})
		require.NoError(t, err)
		e.drain()
		d := e.deployment(got[0].ID)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, providers.LevelServed, d.Level)
		e.assertCCSServes(s, other)
	})
}

// Review Focus 3: IIS does not pick the new file up (ServeStaleCCS): the verification fails, iis-restore moves the backup
// back, and the file holds the previous bytes exactly.
func TestCCSFailedVerificationRestoresBackup(t *testing.T) {
	e := newEnv(t)
	s := e.addCCSServer("iis-01")
	s.model.ServeStaleCCS(true)
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
	assert.Equal(t, winproto.PhaseRestored, s.phase(t, id))
	assert.Equal(t, 1, s.sent(winproto.SubIISRestore))
	data, _ := s.model.CCSFile(wwwName + ".pfx")
	assert.True(t, bytes.Equal(s.oldBytes, data), "the file holds the previous bytes")
	assert.Empty(t, s.backup(), "the restore consumed the backup")
	s.model.ServeStaleCCS(false)
	e.assertCCSServes(s, e.old)
}

// Review Focus 4 (R48): with the previous certificate's key compromised during the deployment, the helper's guard
// refuses the restore: rollback_failed deployment.rollback_forbidden, the file keeps the new certificate.
func TestWindowsCCSGuardForbids(t *testing.T) {
	e := newEnv(t)
	s := e.addCCSServer("iis-01")
	s.model.ServeStaleCCS(true)
	e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return deployWith{Session: sess, f: e.compromiseOld}
	})
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStateDone, d.State)
	e.assertForbidden(d)
	assert.Equal(t, pki.Fingerprint(e.nw.Cert), s.file(), "the compromised certificate is never written back")
	assert.Equal(t, winproto.PhaseRestoreForbidden, s.phase(t, id))
	assert.NotEmpty(t, s.backup(), "the backup is kept, never restored")
}

// ccsKillRows are the rows of ccs-deploy's and iis-restore's crash points (Task 3), by point.
var ccsKillRows = map[string]winKillRow{
	"ccs.locked":        {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhaseNone},
	"ccs.prepared":      {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"ccs.import_chain":  {status: inventory.DeployStatusFailed, reason: "deployment.interrupted", want: oldLeaf, fenced: true, phase: winproto.PhasePrepared},
	"ccs.writing":       {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"ccs.temp_written":  {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"ccs.replaced":      {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"ccs.read_back":     {status: inventory.DeployStatusRolledBack, reason: "deployment.interrupted", want: oldLeaf},
	"ccs.committed":     {status: inventory.DeployStatusSucceeded, want: newLeaf},
	"restore.restoring": {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.bound":     {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
	"restore.restored":  {stale: true, status: inventory.DeployStatusRolledBack, reason: "deployment.verify_failed", want: oldLeaf},
}

// Review Focus 4: the helper is killed at every crash point of a CCS deployment and its restore (it answers nothing),
// the server reboots (the lock and IIS's stale files are gone; the folder, the backups and the journals stay), and
// Alice's recovery ends the deployment: the file then holds exactly the previous or the new certificate, the website
// serves what the record claims, no temporary file is left, and a kill before prepared is fenced. A restore whose
// backup was pruned meanwhile fails closed: rollback_failed windows.backup_missing, the file untouched.
func TestWindowsCCSCrashTable(t *testing.T) {
	e := newEnv(t)
	s := e.addCCSServer("iis-01")
	s.model.ServeStaleCCS(true)
	e.request(s.loc)
	e.drain()
	points := s.model.Points()
	require.Len(t, points, len(ccsKillRows), "%v", points)
	for _, p := range points {
		require.Contains(t, ccsKillRows, p, "a crash point without a row")
	}

	for _, point := range points {
		tc := ccsKillRows[point]
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.addCCSServer("iis-01")
			s.model.ServeStaleCCS(tc.stale)
			s.model.KillAt(point)
			id := e.request(s.loc)[0]
			e.drain()
			require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State, "a killed helper is an uncertain outcome")
			require.Equal(t, 1, s.sent(winproto.SubCCSDeploy))

			s.model.ServeStaleCCS(false)
			s.model.Reboot()
			d := e.settle(id)
			assert.Equal(t, tc.status, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
			assert.Equal(t, tc.reason, d.ErrorCode)
			e.assertCCSServes(s, tc.want(e))
			if tc.status == inventory.DeployStatusRolledBack {
				assert.Equal(t, winproto.PhaseRestored, s.phase(t, id), "the helper's journal agrees with the record")
				data, _ := s.model.CCSFile(wwwName + ".pfx")
				assert.True(t, bytes.Equal(s.oldBytes, data), "the previous bytes")
			}
			for _, n := range s.model.CCSNames() {
				assert.False(t, strings.HasSuffix(n, ".tmp"), "no temporary file is left: %s", n)
			}
			assert.Equal(t, 1, s.sent(winproto.SubCCSDeploy), "the certificate is sent at most once")
			if tc.fenced {
				assert.Equal(t, winproto.PhaseFenced, s.phase(t, id))
				assert.Equal(t, tc.phase, d.Phase)
			}
		})
	}

	t.Run("the backup pruned before the recovery's restore", func(t *testing.T) {
		e := newEnv(t)
		s := e.addCCSServer("iis-01")
		s.model.ServeStaleCCS(true)
		s.model.KillAt("restore.restoring")
		id := e.request(s.loc)[0]
		e.drain()
		require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
		require.Equal(t, winproto.PhaseRestoring, s.phase(t, id))
		backup := s.backup()
		require.NotEmpty(t, backup)
		require.NoError(t, s.model.Host().RemoveCCS(context.Background(), ccsFolder, backup), "the 7-day prune, or a person")
		s.model.Reboot()
		d := e.settle(id)
		assert.Equal(t, inventory.DeployStatusRollbackFailed, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, "windows.backup_missing", d.ErrorCode)
		assert.Equal(t, pki.Fingerprint(e.nw.Cert), s.file(), "nothing written: the file keeps the new certificate")
		assert.Equal(t, pki.Fingerprint(e.nw.Cert), s.served())
		assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1",
			inventory.WindowsCCSTemplate(inventory.TemplateDeploymentRollbackFailed)), "the CCS text names the file and its backup")
	})
}

// Design §13 W5: automatic deployment reaches the linked file: an ACME binding (the first certificate and its renewal)
// and a Key Vault binding's new version.
func TestWindowsCCSACMEAndKeyVault(t *testing.T) {
	t.Run("acme", func(t *testing.T) {
		w := newACMEWorld(t)
		s := w.addCCSServer("iis-01")
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
		assert.Equal(t, fp1, s.file())

		cert2, fp2 := w.renew(w.acmeCert(c.ID))
		ids = w.planDeploy(cert2)
		require.Len(t, ids, 1)
		w.drain()
		d = w.deployment(ids[0])
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, inventory.TriggerACMERenewal, d.Trigger)
		assert.Equal(t, fp1, d.PreviousFingerprint)
		assert.Equal(t, ccsSteps, stepList(d.Steps))
		assert.Equal(t, fp2, s.file())
		assert.Equal(t, fp2, s.served())
		assert.Equal(t, fp2, w.winLocation(s.winServer).CertFileSHA256)
	})
	t.Run("key vault", func(t *testing.T) {
		w := newKVWorld(t)
		s := w.addCCSServer("iis-01")
		b := w.bind(s.loc)
		first := w.settle(w.deploy(b, false)[0])
		require.Equal(t, inventory.DeployStatusSucceeded, first.Status, "%s %v", first.ErrorCode, first.ErrorParams)
		w.assertCCSServes(s, w.nw)
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
		w.assertCCSServes(s, l)
	})
}

// W5 Ruling 22: a third party replaces the CCS file with another certificate: the location drifts, and mode auto
// repairs it through the engine (trigger drift_repair), guarded by the token.
func TestWindowsCCSDriftRepaired(t *testing.T) {
	w := newACMEWorld(t)
	require.NoError(t, w.fake.SetLeafLifetime(90*24*time.Hour))
	driftjobs.Register(w.runner, driftjobs.Deps{Inventory: w.inv, Registry: w.reg, Clock: w.clock, Log: w.log()})
	s := w.addCCSServer("iis-01")
	s.model.SetNow(w.clock.Now())
	w.loc = s.loc
	d := &driftWorld{acmeWorld: w, schedule: driftjobs.ScheduleTask(w.inv, time.Minute, w.log()),
		repair: driftjobs.RepairTask(w.inv, time.Minute, w.log())}
	d.acme, d.c2 = w.issueFirst()
	require.Equal(t, d.c2, s.file(), "the file holds C2")
	o := d.observe()
	require.Equal(t, inventory.HealthInSync, o.Health)
	require.Equal(t, inventory.DriftModeAuto, o.Mode)

	// Another tool writes C1 into the file, under the store's password.
	s.model.PutCCSFile(wwwName+".pfx", w.old.Cert, []*x509.Certificate{w.ca.Intermediate}, w.old.Key, s.pw)
	o = d.observe()
	require.Equal(t, inventory.HealthDrifted, o.Health)
	require.NotNil(t, o.TLS)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), o.TLS.Fingerprint, "the website serves C1")

	deploys := s.sent(winproto.SubCCSDeploy)
	assert.Equal(t, []string{inventory.DeployStatusSucceeded}, d.repairNow())
	assert.Equal(t, deploys+1, s.sent(winproto.SubCCSDeploy), "through ccs-deploy")
	assert.Equal(t, d.c2, s.file(), "the file holds C2 again")
	assert.Equal(t, d.c2, s.served())
	o = d.observe()
	assert.Equal(t, inventory.HealthInSync, o.Health)
	assert.Empty(t, d.repairNow(), "nothing more to repair")
}

// W5 Ruling 17: CCS turned off after the location was discovered: the queued deployment is refused by the helper
// with nothing changed (windows.ccs_disabled, ALC-WIN-0015).
func TestWindowsCCSDisabledRefuses(t *testing.T) {
	e := newEnv(t)
	s := e.addCCSServer("iis-01")
	s.model.SetCCS(false, ccsFolder)
	e.setSkip(s.winServer, true) // IIS serves no CCS file now: the precheck would stop first; the helper's refusal is tested
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "windows.ccs_disabled", d.ErrorCode)
	assert.Equal(t, "", s.phase(t, id), "a refusal before any change writes no journal")
	data, _ := s.model.CCSFile(wwwName + ".pfx")
	assert.True(t, bytes.Equal(s.oldBytes, data), "the file is untouched")
	assert.Equal(t, []string{wwwName + ".pfx"}, s.model.CCSNames(), "no temporary file, no backup")
	assert.Zero(t, s.sent(winproto.SubIISRestore))
}
