//go:build integration

package deployjobs

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is an identifier, not a security hash
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// R61 Task 11: Windows deployments through the whole stack (the real queue, runner, deployment engine, inventory on
// PostgreSQL, the Windows provider over SSH, and the helper's own code on wintest's modelled host). The engine has no
// Windows branch (Ruling 20): every test here runs the production code of internal/jobs/deployjobs unchanged.

// winSteps is the step list of a committed Windows deployment that Alice verified.
var winSteps = []string{"verify_current:started", "verify_current:ok", "import_chain:ok", "import_certificate:ok", "bind:ok", "verify:started",
	"verify:ok"}

func thumbprintOf(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // G401: see the import
	return hex.EncodeToString(sum[:])
}

// bound is the SHA-1 the http.sys record names now ("" when the record is gone).
func (s *winServer) bound() string {
	b, ok := s.model.Binding(s.locator)
	if !ok {
		return ""
	}
	return b.CertSHA1
}

// served is the leaf's SHA-256 a handshake to the binding shows now ("" when it fails).
func (s *winServer) served() string {
	leaf, _, ok := s.model.Served("127.0.0.1", 443, wwwName)
	if !ok {
		return ""
	}
	return leaf
}

// phase is the phase of the operation's journal on the server ("" when there is none).
func (s *winServer) phase(t *testing.T, op uuid.UUID) string {
	t.Helper()
	b, ok := s.model.Journal(op.String())
	if !ok {
		return ""
	}
	var j struct {
		Phase string `json:"phase"`
	}
	require.NoError(t, json.Unmarshal(b, &j))
	return j.Phase
}

// sent counts the commands of a subcommand the server received.
func (s *winServer) sent(sub string) int {
	n := 0
	for _, c := range s.srv.Commands() {
		if first, _, _ := strings.Cut(c, " "); first == sub {
			n++
		}
	}
	return n
}

// winLocation is the binding's location as inventory holds it now.
func (e *env) winLocation(s *winServer) inventory.CertificateLocation {
	e.t.Helper()
	l, err := e.inv.GetLocation(e.ctx, s.loc)
	require.NoError(e.t, err)
	return l
}

// assertWinServes checks the server and Alice's record against each other: the http.sys record names exactly want,
// a handshake shows exactly want, and the location's compare-and-swap token is want's DER hash.
func (e *env) assertWinServes(s *winServer, want pki.Leaf) {
	e.t.Helper()
	assert.Equal(e.t, thumbprintOf(want.Cert.Raw), s.bound(), "the binding names the certificate the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), s.served(), "the website serves the certificate the record claims")
	assert.Equal(e.t, pki.Fingerprint(want.Cert), e.winLocation(s).CertFileSHA256, "Alice's token is what the binding names")
}

// setSkip switches the binding's verification off (or on).
func (e *env) setSkip(s *winServer, skip bool) {
	e.t.Helper()
	l := e.winLocation(s)
	_, err := e.inv.UpdateLocation(e.ctx, e.admin, s.loc, l.Version, inventory.LocationPatch{SkipVerify: &skip})
	require.NoError(e.t, err)
}

// deployWith runs f right before every DeployCertificate of the sessions opened from now on.
type deployWith struct {
	providers.Session
	f func()
}

func (s deployWith) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	s.f()
	return s.Session.DeployCertificate(ctx, req, log)
}

// Design §13 W2 item 1: a manual deployment imports the chain and the certificate, re-points the binding, and
// verifies at level 3 (the world's trust store holds the test CA).
func TestWindowsManualDeployment(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	require.Equal(t, s.oldSHA1, s.bound())
	id := e.request(s.loc)[0]
	e.drain()

	d := e.deployment(id)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, winSteps, stepList(d.Steps), "the Windows steps")
	assert.Equal(t, "remote", d.Verified)
	assert.Equal(t, providers.LevelTrusted, d.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true}, d.Trust)
	assert.Equal(t, pki.Fingerprint(e.old.Cert), d.PreviousFingerprint)
	assert.Equal(t, pki.Fingerprint(e.old.Cert), d.ExpectCertSHA256, "the compare-and-swap token is the DER hash of the bound certificate")
	require.NotNil(t, d.Backup)
	assert.Equal(t, providers.BackupRef{OperationID: id, Store: "My", PreviousSHA1: s.oldSHA1, PreviousSHA256: pki.Fingerprint(e.old.Cert)}, *d.Backup,
		"the previous certificate is the rollback info (Ruling 17)")
	e.assertWinServes(s, e.nw)
	assert.Equal(t, pki.Fingerprint(e.nw.Cert), e.winLocation(s).DeployedFingerprint)
	assert.Equal(t, winproto.PhaseCommitted, s.phase(t, id))
	assert.Equal(t, 1, s.sent(winproto.SubIISDeploy))
	assert.Zero(t, s.sent(winproto.SubIISRestore))
	assert.Equal(t, []string{thumbprintOf(e.nw.Cert.Raw)}, s.model.Imported(), "Alice imported the new certificate")
	for _, a := range []string{"deployment.requested", "deployment.precheck_started", "deployment.started", "deployment.succeeded"} {
		assert.Equal(t, 1, e.audits(a), a)
	}
	for _, c := range s.srv.Commands() {
		assert.NotContains(t, c, "PRIVATE KEY", "the key is never on a command line")
	}
}

// R61 Task 14 (found by the e2e journey): after a deployment the location names the thumbprint the binding names now,
// so the next deployment's rollback info (Ruling 17) and a rollback's "Previous certificate" line name the certificate
// Alice deployed, not the one the last discovery read before it.
func TestWindowsNextDeploymentNamesTheDeployedCertificateAsPrevious(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	first := e.request(s.loc)[0]
	e.drain()
	require.Equal(t, inventory.DeployStatusSucceeded, e.deployment(first).Status)
	var sha1 string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT coalesce(details->>'cert_sha1', '') FROM certificate_locations WHERE id = $1", s.loc).Scan(&sha1))
	assert.Equal(t, thumbprintOf(e.nw.Cert.Raw), sha1, "the location names the deployed certificate's thumbprint")

	third := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName, apiName}}, e.clock.Now())
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(third.FullchainPEM), PrivateKeyPEM: string(third.KeyPEM)})
	require.NoError(t, err)
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc}})
	require.NoError(t, err)
	e.drain()
	d := e.deployment(got[0].ID)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	require.NotNil(t, d.Backup)
	assert.Equal(t, providers.BackupRef{OperationID: got[0].ID, Store: "My", PreviousSHA1: thumbprintOf(e.nw.Cert.Raw),
		PreviousSHA256: pki.Fingerprint(e.nw.Cert)}, *d.Backup, "the previous certificate is the one Alice deployed")
	e.assertWinServes(s, third)
}

// Design §13 W2 item 1: the R51 levels on Windows. A private CA Alice has no root of: served, the untrusted chain a
// warning (not enforced). Verification skipped: installed.
func TestWindowsDeploymentLevels(t *testing.T) {
	t.Run("served: a private CA not in the trust policy", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		other := pki.NewCA("Private", pki.ECDSA256, e.clock.Now()).Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
		c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(other.FullchainPEM),
			PrivateKeyPEM: string(other.KeyPEM)})
		require.NoError(t, err)
		e.evaluate()
		got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc},
			ConfirmIncompleteChain: true})
		require.NoError(t, err)
		e.drain()
		d := e.deployment(got[0].ID)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, providers.LevelServed, d.Level)
		assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
			Store: providers.TrustStoreSystem}, d.Trust)
		e.assertWinServes(s, other)
	})
	t.Run("installed: verification skipped", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		e.setSkip(s, true)
		id := e.request(s.loc)[0]
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		assert.Equal(t, providers.LevelInstalled, d.Level)
		assert.Equal(t, "skipped", d.Verified)
		assert.Equal(t, []string{"verify_current:skipped", "import_chain:ok", "import_certificate:ok", "bind:ok", "verify:started", "verify:skipped"}, stepList(d.Steps))
		e.assertWinServes(s, e.nw)
	})
}

// Design §13 W2 item 2: someone re-pointed the binding between Alice's read and her write. The helper's
// compare-and-swap refuses: nothing changed, the deployment failed with the Windows reason, no restore was sent.
func TestWindowsHashMismatchChangesNothing(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	third := e.ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	thirdSHA1 := s.model.AddCertificate("My", third.CertPEM, third.KeyPEM, wintest.CertOptions{FriendlyName: "someone else"})
	e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
		return deployWith{Session: sess, f: func() {
			b, ok := s.model.Binding(s.locator)
			require.True(t, ok)
			b.CertSHA1 = thirdSHA1
			require.NoError(t, s.model.Host().UpdateBinding(context.Background(), b))
		}}
	})
	id := e.request(s.loc)[0]
	e.drain()
	e.setWrap(nil)
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, "windows.binding_changed", d.ErrorCode)
	assert.Equal(t, thirdSHA1, s.bound(), "the binding is as the other party left it")
	assert.Equal(t, pki.Fingerprint(third.Cert), s.served())
	assert.Equal(t, "", s.phase(t, id), "a refusal before any change writes no journal")
	assert.Empty(t, s.model.Imported(), "nothing was imported")
	assert.Zero(t, s.sent(winproto.SubIISRestore))
	assert.Equal(t, 1, s.sent(winproto.SubIISDeploy))
}

// Design §13 W2 item 2: a deployment of the certificate the binding already names, with the chain Alice's last bind
// left served: the helper answers unchanged and writes nothing.
func TestWindowsUnchanged(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	first := e.request(s.loc)[0]
	e.drain()
	require.Equal(t, inventory.DeployStatusSucceeded, e.deployment(first).Status)
	// A request of the same certificate again (as after a lost record of the first).
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE certificate_locations SET deployed_fingerprint = '' WHERE id = $1", s.loc)
	require.NoError(t, err)
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: e.cert.ID, LocationIDs: []uuid.UUID{s.loc}})
	require.NoError(t, err)
	e.drain()
	d := e.deployment(got[0].ID)
	require.Equal(t, inventory.DeployStatusUnchanged, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, winproto.PhaseUnchanged, s.phase(t, got[0].ID))
	assert.Equal(t, providers.LevelTrusted, d.Level)
	assert.Equal(t, []string{thumbprintOf(e.nw.Cert.Raw)}, s.model.Imported(), "imported once")
	e.assertWinServes(s, e.nw)
}

// A website that did not take the change (StaleTLS): the verification fails, the provider's iis-restore puts the
// previous record back, and the previous leaf is served.
func TestWindowsFailedVerificationRollsBack(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	s.model.StaleTLS(true)
	before := e.winLocation(s).Details["cert_sha1"]
	require.Equal(t, s.oldSHA1, before)
	id := e.request(s.loc)[0]
	e.drain()
	d := e.deployment(id)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, before, e.winLocation(s).Details["cert_sha1"], "a rolled-back deployment leaves the recorded thumbprint as it was")
	require.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "deployment.verify_failed", d.ErrorCode)
	assert.Equal(t, providers.StepNameVerify, d.FailedStep)
	assert.Equal(t, providers.LevelNone, d.Level)
	assert.Equal(t, winproto.PhaseRestored, s.phase(t, id))
	assert.Equal(t, 1, s.sent(winproto.SubIISRestore))
	e.assertWinServes(s, e.old)
	// A Windows deployment's notice is queued in its Windows text (notify-windows, 2db347aa).
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = '"+inventory.WindowsTemplate(inventory.TemplateDeploymentFailed)+"'"))
}

// incidentOn opens an incident of the old certificate with the location pending (an incident replacement: the
// guard is Required although nothing is forbidden).
func (e *env) incidentOn(loc uuid.UUID) {
	e.t.Helper()
	var cert uuid.UUID
	var spki string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT id, public_key_sha256 FROM certificates WHERE fingerprint_sha256 = $1",
		pki.Fingerprint(e.old.Cert)).Scan(&cert, &spki))
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
VALUES ($1, $2, $3, 'awaiting_replacement', 'not_possible', $4, $4)`, id, cert, spki, e.clock.Now())
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO certificate_incident_locations (incident_id, location_id, status, updated_at) VALUES ($1, $2, 'pending', $3)`,
		id, loc, e.clock.Now())
	require.NoError(e.t, err)
}

// Design §13 W2 item 3 and Review Focus 3 (mirror of rollbackguard_integration_test.go): with the previous
// certificate's key compromised, no restore path puts it back: the helper checks the guard on the server, answers
// restore_forbidden and the binding keeps the new certificate. An incident replacement (a Required guard) runs on
// Windows, because the helper checks the guard itself.
func TestWindowsRollbackGuardRows(t *testing.T) {
	assertForbidden := func(e *env, s *winServer, d inventory.Deployment) {
		e.t.Helper()
		e.assertForbidden(d)
		assert.Equal(e.t, thumbprintOf(e.nw.Cert.Raw), s.bound(), "the compromised certificate is never bound again")
		assert.Equal(e.t, winproto.PhaseRestoreForbidden, s.phase(e.t, d.ID), "the helper's journal records the refusal")
		assert.Equal(e.t, 1, s.sent(winproto.SubIISDeploy), "never sent twice")
	}
	t.Run("the inline restore, compromised during the deployment", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		s.model.StaleTLS(true)
		e.setWrap(func(_ providers.TargetRef, sess providers.Session) providers.Session {
			return deployWith{Session: sess, f: e.compromiseOld}
		})
		id := e.request(s.loc)[0]
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStateDone, d.State)
		assertForbidden(e, s, d)
		assert.Equal(t, providers.StepNameVerify, d.CauseStep, "why it was rolled back: %+v", d)
		assert.Equal(t, "deployment.verify_failed", stepParams(d, "verify", "failed")["reason"])
		assert.Equal(t, 1, s.sent(winproto.SubIISRestore), "the restore was sent, with the guard read again; the helper refused it")
	})
	t.Run("the recovery's restore, compromised after the answer was lost", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		s.model.StaleTLS(true)
		s.model.KillAt("deploy.committed")
		id := e.request(s.loc)[0]
		e.drain()
		require.Equal(t, inventory.DeployStateRecovering, e.deployment(id).State)
		require.Equal(t, winproto.PhaseCommitted, s.phase(t, id))
		e.compromiseOld()
		d := e.settle(id)
		assertForbidden(e, s, d)
		assert.Equal(t, "deployment.verify_failed", d.VerifyFailedReason, "why it was rolled back")
	})
	t.Run("the helper's own restore, compromised before the deployment", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		e.compromiseOld()
		s.model.CorruptReadBack(true)
		id := e.request(s.loc)[0]
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStateDone, d.State)
		assertForbidden(e, s, d)
		assert.Equal(t, providers.StepNameBind, d.CauseStep)
		assert.Zero(t, s.sent(winproto.SubIISRestore), "the helper refused its own restore")
		started := e.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.started' AND details->>'rollback' = 'forbidden'")
		assert.Equal(t, 1, started, "the plan-time verdict is audited")
	})
	t.Run("an incident replacement runs", func(t *testing.T) {
		e := newEnv(t)
		s := e.addWinServer("iis-01")
		e.incidentOn(s.loc)
		id := e.request(s.loc)[0]
		guard, err := e.inv.RollbackGuard(e.ctx, id)
		require.NoError(t, err)
		require.True(t, guard.Required, "an incident replacement needs a server that checks the guard")
		e.drain()
		d := e.deployment(id)
		require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
		e.assertWinServes(s, e.nw)
	})
}

// Design §13 W2 item 5: an ACME binding to a Windows location deploys the first certificate and its renewal
// automatically, through the engine.
func TestWindowsACMEAutomaticDeployment(t *testing.T) {
	w := newACMEWorld(t)
	s := w.addWinServer("iis-01")
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
	assert.Equal(t, fp1, s.served())

	cert2, fp2 := w.renew(w.acmeCert(c.ID))
	ids = w.planDeploy(cert2)
	require.Len(t, ids, 1)
	assert.Empty(t, w.planDeploy(cert2), "nothing twice")
	w.drain()
	d = w.deployment(ids[0])
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, inventory.TriggerACMERenewal, d.Trigger)
	assert.Equal(t, fp1, d.PreviousFingerprint)
	assert.Equal(t, fp2, d.NewFingerprint)
	assert.Equal(t, winSteps, stepList(d.Steps))
	assert.Equal(t, fp2, s.served())
	assert.Equal(t, fp2, w.winLocation(s).DeployedFingerprint)
	assert.Equal(t, fp2, w.winLocation(s).CertFileSHA256)
	assert.Empty(t, w.planDeploy(cert2), "deployed: nothing more")
}

// Design §13 W2 item 5: a new Key Vault version of a certificate bound to a Windows location with automatic
// deployment on is deployed by the planner and commits.
func TestWindowsKeyVaultAutomaticDeployment(t *testing.T) {
	w := newKVWorld(t)
	s := w.addWinServer("iis-01")
	b := w.bind(s.loc)
	// Version 1 deployed by a person first: the renewal's send then expects the token a vault deployment recorded.
	first := w.settle(w.deploy(b, false)[0])
	require.Equal(t, inventory.DeployStatusSucceeded, first.Status, "%s %v", first.ErrorCode, first.ErrorParams)
	w.assertWinServes(s, w.nw)
	b, err := w.inv.SetAutoDeploy(w.ctx, w.admin, b.ID, b.Version, true)
	require.NoError(t, err)

	// The vault's certificate renewed: version 2 is a new leaf, created after the binding.
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
	assert.Equal(t, "kv_renewal", d.Trigger)
	assert.Equal(t, "key_vault", d.Source)
	assert.Equal(t, ver2, d.KVVersion)
	assert.Equal(t, 2, w.reads(), "one secret read per deployment")
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), d.PreviousFingerprint)
	w.assertWinServes(s, l)
}

// renewVersion lets a poll see version ver (leaf l, created now) as the vault certificate's current version, the
// first version (e.nw) still listed.
func (w *kvWorld) renewVersion(l pki.Leaf, ver string) {
	w.t.Helper()
	now := w.clock.Now()
	th, nb, exp := azureid.ThumbprintOf(l.Cert.Raw), l.Cert.NotBefore.UTC(), l.Cert.NotAfter.UTC()
	th1, nb1, exp1 := azureid.ThumbprintOf(w.nw.Cert.Raw), w.nw.Cert.NotBefore.UTC(), w.nw.Cert.NotAfter.UTC()
	cert := providers.KVCertificate{Name: "web-cert", Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &now, Updated: &now,
		Details: &providers.KVCertificateDetails{Version: ver, Thumbprint: th, Updated: &now, CER: l.Cert.Raw, Exportable: ptr(true), KeyType: "ecdsa",
			KeySize: 256, ContentType: "pkcs12", IssuerName: "Unknown", AutoRenew: true},
		Versions: []providers.KVCertificateVersion{{Version: w.ver, Thumbprint: th1, Enabled: true, NotBefore: &nb1, Expires: &exp1},
			{Version: ver, Thumbprint: th, Enabled: true, NotBefore: &nb, Expires: &exp, Created: &now}}}
	_, err := w.inv.ReconcileKV(w.ctx, w.vault, providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: []providers.KVCertificate{cert}}})
	require.NoError(w.t, err)
}

// Design §13 W2 item 5 (R49): service A's certificate goes to service B's Windows server only with a trust.
func TestWindowsCrossServiceNeedsTrust(t *testing.T) {
	e := newEnv(t)
	s := e.addWinServer("iis-01")
	def, pay := e.defaultService(), e.newService("Payments")
	e.moveTarget(s.target, pay)
	c := e.upload()
	require.Equal(t, def, c.ServiceID)
	e.evaluate()
	_, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.loc}})
	var untrusted *authz.UntrustedError
	require.ErrorAs(t, err, &untrusted)
	assert.Equal(t, authz.UntrustedError{Source: def, Target: pay}, *untrusted)
	assert.Zero(t, e.count("SELECT count(*) FROM deployments"))
	assert.Zero(t, s.sent(winproto.SubIISDeploy))

	e.trust(def, pay)
	id := e.request(s.loc)[0]
	e.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(id).Status)
	e.assertWinServes(s, e.nw)
}
