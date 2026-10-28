//go:build integration

package inventory_test

import (
	"crypto/sha1" //nolint:gosec // G505: a Windows thumbprint is the certificate's SHA-1, an identifier, not a security measure
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/notify"
	"alice/internal/providers"
	"alice/internal/providers/windows"
	"alice/internal/providers/windows/winproto"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
	"alice/locales"
)

// R62 W3 Task 8: R52 for Windows bindings. The engine is R52's; the new rule is the scan's (a bound binding that
// loses its certificate or key was changed outside Alice), the derived cause, the refused repair and the Windows texts.

// winDriftFixture is winDeployFixture with a fake ACME authority whose certificate (cur) is bound to iis-01's
// bindings :443 (bound) and :8443 (spare) and to web-01's www.crt (file), deployed to the three (finished succeeded)
// and found there by a scan: every location is in sync.
type winDriftFixture struct {
	*winDeployFixture
	w           *acmeDeployWorld
	acme        inventory.ACMECertificate
	cur         uuid.UUID
	curFP       string
	curPEM      []byte
	curDER      []byte
	deployments []uuid.UUID
}

func newWinDriftFixture(t *testing.T, auto bool) *winDriftFixture {
	t.Helper()
	f := &winDriftFixture{winDeployFixture: newWinDeployFixture(t)}
	h := f.h
	h.installLicense("LIC-WIN-DRIFT", 5, 3650)
	require.NoError(t, h.lic.Tick(h.ctx))
	fake, err := fakeacme.New(fakeacme.Options{Now: h.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	f.w = &acmeDeployWorld{deployFixture: &deployFixture{h: h, admin: f.admin, operator: h.user("oya", rbac.Operator, "")}, fake: fake}
	f.w.provider = f.w.newProvider("Win CA", true)
	none := 0
	f.w.hook, err = h.svc.CreateACMEHook(h.ctx, f.admin, inventory.ACMEHookInput{Name: "dns", URL: fake.Credentials().HookURL,
		CABundlePEM: string(fake.CAPEM()), Secret: secrets.NewPlaintext([]byte(fake.Credentials().HookSecret)),
		AllowedSuffixes: []string{"example.test"}, PropagationWaitSeconds: &none, PollTimeoutSeconds: 5})
	require.NoError(t, err)
	f.acme, f.cur = f.w.issued("www.example.test")
	var chain string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT fingerprint_sha256, pem_chain FROM certificates WHERE id = $1", f.cur).Scan(&f.curFP, &chain))
	f.curPEM = []byte(chain)
	block, _ := pem.Decode(f.curPEM)
	require.NotNil(t, block)
	f.curDER = block.Bytes

	f.w.bind(f.acme, auto, f.bound, f.spare, f.file)
	got, err := h.svc.DeployACMENow(h.ctx, f.admin, f.acme.ID, inventory.ACMEDeployInput{LocationIDs: []uuid.UUID{f.bound, f.spare, f.file}})
	require.NoError(t, err)
	require.Len(t, got, 3)
	h.clock.Advance(time.Minute)
	for _, d := range got {
		f.w.finish(d.ID, inventory.DeployStatusSucceeded, "")
		f.deployments = append(f.deployments, d.ID)
	}
	h.clock.Advance(time.Minute)
	f.scanWin(f.binding(443, "Default Web Site"), f.binding(8443, "Shop"))
	f.scanFile(providers.DiscoveredCertificate{Location: cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")})
	for _, l := range []uuid.UUID{f.bound, f.spare, f.file} {
		o := f.observation(l)
		require.Equal(t, inventory.HealthInSync, o.Health, "every location is in sync after its deployment and the scan")
		require.NotNil(t, o.File)
		require.Equal(t, f.curFP, o.File.Fingerprint)
		require.Nil(t, o.File.ChangedOutsideAt)
	}
	h.clock.Advance(time.Minute)
	return f
}

// binding is the IIS binding on port of site holding cur, as the provider reports it.
func (f *winDriftFixture) binding(port int, site string) providers.DiscoveredCertificate {
	d := winBinding(port, site, nil)
	sum := sha256.Sum256(f.curDER)
	tp := sha1.Sum(f.curDER) //nolint:gosec // G401: see the import
	d.PEMChain, d.FileSHA256 = f.curPEM, hex.EncodeToString(sum[:])
	d.Location.Details["cert_sha1"] = hex.EncodeToString(tp[:])
	return d
}

// broken is binding with the problem the provider reports: cert_missing (the store no longer holds the certificate:
// no certificate is sent) or a key problem (the certificate is sent with it); both are file problems.
func (f *winDriftFixture) broken(port int, site, problem, keyProblem string) providers.DiscoveredCertificate {
	d := f.binding(port, site)
	if problem != "" {
		d.PEMChain, d.FileSHA256 = nil, ""
	}
	d.Location.Problem, d.Location.KeyProblem = problem, keyProblem
	d.Location.Supported, d.Location.Unsupported = false, providers.UnsupportedFile
	return d
}

// repointed is binding naming leaf instead of cur (someone bound another certificate outside Alice).
func repointed(port int, site string, leaf pki.Leaf) providers.DiscoveredCertificate {
	d := winBinding(port, site, &leaf)
	d.Location.Details["cert_sha1"] = thumbprint(leaf)
	return d
}

// scanWin is a discovery of iis-01 reporting bound and spare (the other bindings as the fixture found them), with the
// facts' warnings.
func (f *winDriftFixture) scanWin(bound, spare providers.DiscoveredCertificate, warnings ...providers.Warning) {
	f.h.t.Helper()
	foreign := winEntry(5986, winRMAppID, "", &f.old)
	_, err := f.h.svc.Reconcile(f.h.ctx, f.win, providers.DiscoveryResult{WebServer: iisOK, Warnings: warnings,
		Certificates: []providers.DiscoveredCertificate{bound, spare, foreign}})
	require.NoError(f.h.t, err)
}

// scanFile is a discovery of web-01 reporting www (its certificate cur when the leaf is empty).
func (f *winDriftFixture) scanFile(www providers.DiscoveredCertificate) {
	f.h.t.Helper()
	if www.Location.Problem == "" && len(www.PEMChain) == 0 {
		www.PEMChain, www.FileSHA256 = f.curPEM, sha(f.curPEM)
	}
	_, err := f.h.svc.Reconcile(f.h.ctx, f.web, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{www}})
	require.NoError(f.h.t, err)
}

func (f *winDriftFixture) observation(loc uuid.UUID) inventory.LocationObservation {
	f.h.t.Helper()
	o, err := f.h.svc.LocationObservation(f.h.ctx, loc)
	require.NoError(f.h.t, err)
	return o
}

// unreachable records, as iis-01's observation job, a probe of the locations that completed no handshake (an http.sys
// binding without a usable certificate completes none).
func (f *winDriftFixture) unreachable(target uuid.UUID, locs ...uuid.UUID) {
	f.h.t.Helper()
	var rs []inventory.DriftResult
	for _, l := range locs {
		rs = append(rs, inventory.DriftResult{LocationID: l, At: f.h.clock.Now(), Error: "deployment.verify_unreachable"})
	}
	_, err := f.h.svc.RecordDriftObservations(f.h.ctx, target, rs)
	require.NoError(f.h.t, err)
}

func (f *winDriftFixture) served(target, loc uuid.UUID, fp string) {
	f.h.t.Helper()
	_, err := f.h.svc.RecordDriftObservations(f.h.ctx, target, []inventory.DriftResult{{LocationID: loc, At: f.h.clock.Now(), Reached: true,
		Served: fp, Probe: inventory.DriftProbeHelper, Level: 2, Trust: providers.TrustTrusted}})
	require.NoError(f.h.t, err)
}

func (f *winDriftFixture) setMode(loc uuid.UUID, mode string) {
	f.h.t.Helper()
	require.NoError(f.h.t, f.h.lic.Tick(f.h.ctx))
	_, err := f.h.svc.SetDriftMode(f.h.ctx, f.admin, loc, mode, true)
	require.NoError(f.h.t, err)
}

// driftMails are the location.drift_* e-mails queued (one per recipient; ada is the only one), oldest first.
func (f *winDriftFixture) driftMails() []queuedMail {
	f.h.t.Helper()
	rows, err := f.h.db.Owner.Query(f.h.ctx, `SELECT template_key, params FROM notifications_outbox WHERE template_key LIKE 'location.drift%'
ORDER BY created_at, id`)
	require.NoError(f.h.t, err)
	defer rows.Close()
	var out []queuedMail
	for rows.Next() {
		var (
			m   queuedMail
			raw []byte
		)
		require.NoError(f.h.t, rows.Scan(&m.Template, &raw))
		require.NoError(f.h.t, json.Unmarshal(raw, &m.Params))
		out = append(out, m)
	}
	require.NoError(f.h.t, rows.Err())
	return out
}

// repairs counts the drift repairs (trigger drift_repair) of the location.
func (f *winDriftFixture) repairs(loc uuid.UUID) int {
	return f.h.count("SELECT count(*) FROM deployments WHERE location_id = $1 AND trigger = $2", loc, inventory.TriggerDriftRepair)
}

// R62 Review Focus 4 (Rulings 14, 15): a bound binding whose certificate leaves the store, or whose key http.sys can no
// longer use, was changed outside Alice: it is drifted with its cause, automatic repair plans no deployment over three
// runs and never backs off (no repair failed: none was made), and a person's repair is refused. A re-pointed binding
// is drifted with its own cause and repaired as R52 repairs. A file whose certificate is missing stays as R52 decides.
func TestBrokenBindingIsDriftedNotRepaired(t *testing.T) {
	for name, tc := range map[string]struct {
		problem, keyProblem, cause string
	}{
		"certificate removed from the store": {windows.ProblemCertMissing, "", inventory.DriftCauseCertRemoved},
		"key inaccessible":                   {"", windows.ProblemKeyInaccessible, inventory.DriftCauseKeyUnusable},
		"key missing":                        {"", windows.ProblemKeyMissing, inventory.DriftCauseKeyUnusable},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWinDriftFixture(t, true)
			h := f.h
			f.scanWin(f.broken(443, "Default Web Site", tc.problem, tc.keyProblem), f.binding(8443, "Shop"))
			scanned := h.clock.Now()
			o := f.observation(f.bound)
			require.NotNil(t, o.File)
			require.NotNil(t, o.File.ChangedOutsideAt, "Alice never removes a bound certificate nor changes a key: a change outside Alice")
			assert.Equal(t, scanned, *o.File.ChangedOutsideAt)
			assert.Equal(t, inventory.HealthDrifted, o.Health)
			assert.Equal(t, tc.cause, o.Cause)
			assert.Equal(t, inventory.DriftModeAuto, o.Mode)
			if tc.problem == "" {
				assert.Equal(t, f.curFP, o.File.Fingerprint, "the binding still names the desired certificate")
			}
			changed := h.auditDetails("location.changed_outside")
			require.Len(t, changed, 1)
			assert.Equal(t, f.bound.String(), changed[0]["location_id"])
			assert.Equal(t, tc.problem+tc.keyProblem, changed[0]["problem"], "the problem that broke it")
			spare := f.observation(f.spare)
			assert.Equal(t, inventory.HealthInSync, spare.Health, "the other binding is untouched")
			assert.Empty(t, spare.Cause, "no cause without a drift")

			for i := range 3 {
				h.clock.Advance(time.Hour)
				f.scanWin(f.broken(443, "Default Web Site", tc.problem, tc.keyProblem), f.binding(8443, "Shop"))
				f.unreachable(f.win, f.bound)
				o = f.observation(f.bound)
				require.Equal(t, inventory.HealthDrifted, o.Health, "run %d", i)
				require.NotNil(t, o.DriftSince, "run %d: the episode is open", i)
				run, err := h.svc.PlanDriftRepairs(h.ctx)
				require.NoError(t, err)
				assert.Equal(t, inventory.DriftRepairRun{}, run, "run %d: no repair, no back-off", i)
			}
			assert.Zero(t, f.repairs(f.bound), "never repaired into a failure loop")
			o = f.observation(f.bound)
			assert.Nil(t, o.BackedOffAt, "nothing failed, so nothing backs off")
			assert.Equal(t, inventory.DriftModeAuto, o.Mode)
			assert.Equal(t, scanned, *o.File.ChangedOutsideAt, "a binding still broken is not changed again")
			assert.Len(t, h.auditDetails("location.changed_outside"), 1)
			mails := f.driftMails()
			require.Len(t, mails, 1, "mailed once, when no repair ended the drift within an hour")
			assert.Equal(t, map[string]string{inventory.DriftCauseCertRemoved: inventory.TemplateDriftDetectedWindowsCertRemoved,
				inventory.DriftCauseKeyUnusable: inventory.TemplateDriftDetectedWindowsKeyUnusable}[tc.cause], mails[0].Template)

			_, err := h.svc.RepairDrift(h.ctx, f.admin, f.bound, true)
			assert.ErrorIs(t, err, inventory.ErrDriftNotRepairable)
			assert.Zero(t, h.count("SELECT count(*) FROM deployments WHERE location_id = $1 AND state <> 'done'", f.bound), "nothing was requested")
		})
	}

	t.Run("re-pointed", func(t *testing.T) {
		f := newWinDriftFixture(t, true)
		h := f.h
		f.scanWin(repointed(443, "Default Web Site", f.old), f.binding(8443, "Shop"))
		o := f.observation(f.bound)
		require.NotNil(t, o.File.ChangedOutsideAt)
		assert.Equal(t, inventory.HealthDrifted, o.Health)
		assert.Equal(t, inventory.DriftCauseRepointed, o.Cause)
		assert.Equal(t, pki.Fingerprint(f.old.Cert), o.File.Fingerprint)
		f.served(f.win, f.bound, pki.Fingerprint(f.old.Cert))
		run, err := h.svc.PlanDriftRepairs(h.ctx)
		require.NoError(t, err)
		assert.Equal(t, inventory.DriftRepairRun{Created: 1}, run, "R52 repairs a re-pointed binding")
		assert.Equal(t, 1, f.repairs(f.bound))
	})

	t.Run("a file whose certificate is missing", func(t *testing.T) {
		f := newWinDriftFixture(t, true)
		gone := providers.DiscoveredCertificate{Location: cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test")}
		gone.Location.Problem, gone.Location.Supported, gone.Location.Unsupported = providers.CertProblemMissing, false, providers.UnsupportedFile
		f.scanFile(gone)
		o := f.observation(f.file)
		require.NotNil(t, o.File)
		assert.Nil(t, o.File.ChangedOutsideAt, "R52: a file Alice cannot read was not judged changed")
		assert.NotEqual(t, inventory.HealthDrifted, o.Health)
		assert.Empty(t, o.Cause)
		assert.False(t, o.AutoCertRebind)
		assert.Empty(t, f.h.auditDetails("location.changed_outside"))
	})

	t.Run("only a bound binding is judged", func(t *testing.T) {
		f := newWinDriftFixture(t, true)
		h := f.h
		f.scanWin(f.binding(443, "Default Web Site"), f.broken(8443, "Shop", "", windows.ProblemKeyInaccessible))
		require.Len(t, h.auditDetails("location.changed_outside"), 1, "spare broke while bound")
		h.clock.Advance(time.Minute)
		// The foreign WinRM binding loses its key: it follows no binding, so nothing is judged.
		foreign := winEntry(5986, winRMAppID, "", &f.old)
		foreign.Location.KeyProblem = windows.ProblemKeyMissing
		_, err := h.svc.Reconcile(h.ctx, f.win, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{
			f.binding(443, "Default Web Site"), f.broken(8443, "Shop", "", windows.ProblemKeyInaccessible), foreign}})
		require.NoError(t, err)
		assert.Len(t, h.auditDetails("location.changed_outside"), 1, "an unbound binding is not judged; a binding still broken is not again")
		var changed *time.Time
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT changed_outside_at FROM certificate_locations WHERE id = $1", f.foreign).Scan(&changed))
		assert.Nil(t, changed)
	})
}

// R62 Ruling 15: the AutoCertRebind hint of a Windows binding follows the server's facts (the scan's warning
// win_autocertrebind); a file never has it.
func TestAutoCertRebindHint(t *testing.T) {
	f := newWinDriftFixture(t, false)
	assert.False(t, f.observation(f.bound).AutoCertRebind)
	f.scanWin(f.broken(443, "Default Web Site", windows.ProblemCertMissing, ""), f.binding(8443, "Shop"),
		providers.Warning{Code: winproto.WarnAutoCertRebind, Params: map[string]string{}})
	o := f.observation(f.bound)
	assert.Equal(t, inventory.HealthDrifted, o.Health)
	assert.True(t, o.AutoCertRebind)
	assert.True(t, f.observation(f.spare).AutoCertRebind, "a fact of the server: every binding of it")
	assert.False(t, f.observation(f.file).AutoCertRebind)
	f.h.clock.Advance(time.Minute)
	f.scanWin(f.broken(443, "Default Web Site", windows.ProblemCertMissing, ""), f.binding(8443, "Shop"))
	assert.False(t, f.observation(f.bound).AutoCertRebind, "the task is off now")
}

// R62 Ruling 16: a Windows binding's drift e-mails are the Windows texts of its cause, with windows_note=autocertrebind
// when the server's AutoCertRebind task is on; an approve-mode drift that cannot be repaired gets the detected text of
// its cause; a file's are R52's, with R52's params only.
func TestWindowsDriftMail(t *testing.T) {
	f := newWinDriftFixture(t, false)
	h := f.h
	acr := providers.Warning{Code: winproto.WarnAutoCertRebind, Params: map[string]string{}}
	f.setMode(f.spare, inventory.DriftModeApprove)
	f.scanWin(f.broken(443, "Default Web Site", windows.ProblemCertMissing, ""), f.broken(8443, "Shop", "", windows.ProblemKeyInaccessible), acr)
	f.unreachable(f.win, f.bound, f.spare)
	f.served(f.web, f.file, pki.Fingerprint(f.old.Cert))
	base := func(path, observed string) map[string]string {
		return map[string]string{"target_name": "iis-01", "cert_path": path, "certificate_name": "www.example.test", "observed_name": observed}
	}
	removed := base("http.sys/ipport/0.0.0.0:443", "-")
	removed["windows_note"] = "autocertrebind"
	key := base("http.sys/ipport/0.0.0.0:8443", "www.example.test")
	key["windows_note"] = "autocertrebind"
	file := base("/etc/nginx/ssl/www.crt", "www.example.test")
	file["target_name"] = "web-01"
	assert.ElementsMatch(t, []queuedMail{
		{"location.drift_detected_windows_cert_removed", removed},
		{"location.drift_detected_windows_key_unusable", key},
		{inventory.TemplateDriftDetected, file},
	}, f.driftMails())

	// Once per episode.
	h.clock.Advance(2 * time.Hour)
	f.unreachable(f.win, f.bound, f.spare)
	assert.Len(t, f.driftMails(), 3)

	// A re-pointed binding in mode approve, the task off: the prepared repair's text, no note.
	g := newWinDriftFixture(t, false)
	g.setMode(g.bound, inventory.DriftModeApprove)
	g.scanWin(repointed(443, "Default Web Site", g.old), g.binding(8443, "Shop"))
	g.served(g.win, g.bound, pki.Fingerprint(g.old.Cert))
	assert.Equal(t, []queuedMail{{"location.drift_repair_ready_windows", base("http.sys/ipport/0.0.0.0:443", "www.example.test")}}, g.driftMails())
}

// R62 Ruling 17: Alice lost the connection to a Windows server during a deployment also when the cause is
// deployment.interrupted or windows.helper_missing (a Windows OpenSSH session that ended with no answer): the
// lost-connection text for the binding; another cause keeps the unconfirmed text.
func TestWindowsNeedsAttentionLostConnection(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	base := func(id uuid.UUID, path string) map[string]string {
		return map[string]string{"target_name": "iis-01", "cert_path": path, "deployment_id": id.String()}
	}
	attention := func(loc uuid.UUID, code, jobCode string) uuid.UUID {
		r := f.request(loc)
		f.start(r.ID, nil)
		rec := inventory.DeployOutcomeRecord(providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError(code, true, nil, nil), false)
		require.NoError(t, h.svc.RecordOutcome(h.ctx, r.ID, rec, h.clock.Now().Add(time.Minute)))
		if jobCode != "" {
			_, err := h.svc.RequestRecovery(h.ctx, r.ID)
			require.NoError(t, err)
			_, err = h.db.Owner.Exec(h.ctx, "UPDATE jobs SET last_error_code = $2 WHERE dedupe_key = $1", inventory.JobDeployRecover+":"+r.ID.String(),
				jobCode)
			require.NoError(t, err)
		}
		require.NoError(t, h.svc.MarkRecovering(h.ctx, r.ID, h.clock.Now().Add(15*time.Minute), true))
		mails := f.deploymentMails(r.ID)
		require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
			ErrorCode: "deployment.outcome_unknown"}))
		require.NotEmpty(t, mails)
		assert.Equal(t, base(r.ID, "http.sys/ipport/0.0.0.0:443"), mails[0].Params)
		h.clock.Advance(time.Minute)
		return r.ID
	}
	lost := inventory.WindowsTemplate(inventory.TemplateDeploymentNeedsAttention)
	unconfirmed := inventory.WindowsTemplate(inventory.TemplateDeploymentNeedsAttentionUnconfirmed)
	for name, tc := range map[string]struct{ code, jobCode, want string }{
		"the helper's answer was lost (recorded deployment.interrupted)": {"windows.helper_missing", "", lost},
		"interrupted":                     {"deployment.interrupted", "", lost},
		"the recovery found no helper":    {"windows.io_error", "windows.helper_missing", lost},
		"the recovery could not connect":  {"windows.io_error", "ssh.unreachable", lost},
		"the server answered, unexpected": {"windows.io_error", "", unconfirmed},
	} {
		id := attention(f.bound, tc.code, tc.jobCode)
		assert.Equal(t, tc.want, f.deploymentMails(id)[0].Template, name)
	}
}

// R62 Review Focus 5: a file's needs-attention e-mail is decided as before: the lost-connection text only for an SSH
// cause, the unconfirmed text for deployment.interrupted.
func TestLinuxNeedsAttentionUnchanged(t *testing.T) {
	f := newWinDeployFixture(t)
	h := f.h
	for name, tc := range map[string]struct{ code, want string }{
		"interrupted":     {"deployment.interrupted", inventory.TemplateDeploymentNeedsAttentionUnconfirmed},
		"helper missing":  {"ssh.helper_missing", inventory.TemplateDeploymentNeedsAttentionUnconfirmed},
		"unreachable":     {"ssh.unreachable", inventory.TemplateDeploymentNeedsAttention},
		"nginx was busy:": {"nginx.busy", inventory.TemplateDeploymentNeedsAttentionUnconfirmed},
	} {
		r := f.request(f.file)
		f.start(r.ID, nil)
		rec := inventory.DeployOutcomeRecord(providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError(tc.code, true, nil, nil), false)
		require.NoError(t, h.svc.RecordOutcome(h.ctx, r.ID, rec, h.clock.Now().Add(time.Minute)))
		require.NoError(t, h.svc.MarkRecovering(h.ctx, r.ID, h.clock.Now().Add(15*time.Minute), true))
		assert.Equal(t, []queuedMail{{tc.want, map[string]string{"target_name": "web-01", "cert_path": "/etc/nginx/ssl/www.crt",
			"deployment_id": r.ID.String()}}}, f.deploymentMails(r.ID), name)
		require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
			ErrorCode: "deployment.outcome_unknown"}))
		h.clock.Advance(time.Minute)
	}
}

// W5 final review I1 (fixes batch 3 C1, WIN-67): the drift probe of a Windows location carries the location's stored
// warnings, as the deployment's material does, so a cut CCS file (list_truncated) is never observed as skipped; a file's
// request keeps none.
func TestDriftProbeCarriesTheStoredWarnings(t *testing.T) {
	f := newWinDriftFixture(t, true)
	h := f.h
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET warnings = ARRAY['list_truncated'] WHERE id = $1", f.bound)
	require.NoError(t, err)
	probes, err := h.svc.DriftProbes(h.ctx, f.win)
	require.NoError(t, err)
	var bound *inventory.DriftProbe
	for i := range probes {
		if probes[i].LocationID == f.bound {
			bound = &probes[i]
		}
	}
	require.NotNil(t, bound, "the bound binding is probed")
	assert.Contains(t, bound.Request.Location.Warnings, "list_truncated")

	probes, err = h.svc.DriftProbes(h.ctx, f.web)
	require.NoError(t, err)
	require.Len(t, probes, 1)
	assert.Equal(t, f.file, probes[0].LocationID)
	assert.Nil(t, probes[0].Request.Location.Warnings, "a file's request is unchanged")
}

// W6 final review M2 (fixes batch 3, fix round 1; Review Focus 5): the automatic-deployment stop notice renders the
// reason of the last failed deployment. When that deployment was the Remote Desktop listener's, the notice carries
// reason_variant=rdp and its reason is the listener title (errors.windows.<code>.title_rdp), never the binding's; a
// binding's last failure queues no variant and renders the binding title as before.
func TestACMEAutoDeployStopNamesTheRDPListener(t *testing.T) {
	f := newWinDriftFixture(t, false)
	h := f.h
	rf := &rdpFixture{winDeployFixture: f.winDeployFixture}
	rf.server = winTarget(t, h, f.admin, "iis-02").ID
	rf.scan(3389)
	rdp := byPath(t, h, rf.server, false)["rdp/RDP-Tcp"].ID
	iis3 := winTarget(t, h, f.admin, "iis-03").ID
	b := winBinding(443, "Default Web Site", &f.old)
	b.Location.Details["cert_sha1"] = thumbprint(f.old)
	_, err := h.svc.Reconcile(h.ctx, iis3, providers.DiscoveryResult{WebServer: iisOK, Certificates: []providers.DiscoveredCertificate{b}})
	require.NoError(t, err)
	binding := byPath(t, h, iis3, false)["http.sys/ipport/0.0.0.0:443"].ID

	// stop binds a new certificate for name to loc (automatic) and fails its deployments until the wave stops; the params
	// of the stop notice.
	stop := func(name string, loc uuid.UUID) map[string]string {
		t.Helper()
		c, cur := f.w.issued(name)
		f.w.bind(c, true, loc)
		for i := range inventory.AutoDeployMaxFailed {
			require.Equal(t, 1, f.w.plan().Created, "%s: attempt %d", name, i+1)
			f.w.finishAll(cur, inventory.DeployStatusFailed, "windows.binding_changed")
			h.clock.Advance(inventory.AutoDeployRetryAfter)
		}
		require.Equal(t, inventory.ACMEDeployRun{Stopped: 1}, f.w.plan(), name)
		var raw []byte
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT params FROM notifications_outbox WHERE template_key = $1 AND params->>'name' = $2
ORDER BY created_at, id LIMIT 1`, inventory.TemplateACMEAutoDeployStopped, name).Scan(&raw))
		var p map[string]string
		require.NoError(t, json.Unmarshal(raw, &p))
		return p
	}
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	listener, bindingTitle := cat.T("en", "errors.windows.binding_changed.title_rdp", nil), cat.T("en", "errors.windows.binding_changed.title", nil)

	p := stop("rdp.example.test", rdp)
	assert.Equal(t, "windows.binding_changed", p["error_reason"])
	assert.Equal(t, "rdp", p["reason_variant"])
	body := s.Render("ada@example.com", inventory.TemplateACMEAutoDeployStopped, "en", p).Body
	assert.Contains(t, body, "Reason of the last failed deployment: "+listener)
	assert.NotContains(t, body, bindingTitle)

	q := stop("shop.example.test", binding)
	assert.Equal(t, "windows.binding_changed", q["error_reason"])
	assert.NotContains(t, q, "reason_variant", "a binding's stop notice is unchanged")
	assert.Contains(t, s.Render("ada@example.com", inventory.TemplateACMEAutoDeployStopped, "en", q).Body, "Reason of the last failed deployment: "+bindingTitle)
}
