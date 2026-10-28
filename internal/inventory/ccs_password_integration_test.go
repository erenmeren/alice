//go:build integration

package inventory_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// The CCS password of a Windows server (R68, W5 Rulings 9-11): one sealed credentials row per setting, the newest is
// the password, read only through the platform credential source for that server.

// ccsPassword is a password of the CCS rule, built at run time (never a literal).
func ccsPassword() []byte { return []byte("Ccs-" + strings.ReplaceAll(uuid.NewString(), "-", "")) }

func ccsSource(t *testing.T, h *harness) providers.CCSPasswordSource {
	t.Helper()
	src, ok := h.svc.Credentials().(providers.CCSPasswordSource)
	require.True(t, ok, "the platform credential source answers the CCS password")
	return src
}

// setCCS sets pw (a copy: the inventory zeroes what it is given) on target and returns the updated target.
func setCCS(t *testing.T, h *harness, a inventory.Actor, target inventory.Target, pw []byte) (inventory.Target, error) {
	t.Helper()
	return h.svc.SetCCSPassword(h.ctx, a, target.ID, target.Version, secrets.NewPlaintext(bytes.Clone(pw)))
}

func TestSetCCSPassword(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winTarget(t, h, admin, "iis-01")
	got, err := h.svc.GetTarget(h.ctx, win.ID)
	require.NoError(t, err)
	assert.Nil(t, got.CCSPasswordSetAt, "no password yet")
	_, _, err = ccsSource(t, h).CCSPassword(h.ctx, win.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)

	first := ccsPassword()
	given := bytes.Clone(first)
	updated, err := h.svc.SetCCSPassword(h.ctx, admin, win.ID, win.Version, secrets.NewPlaintext(given))
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(first)), given, "the inventory zeroes the password it was given")
	require.NotNil(t, updated.CCSPasswordSetAt)
	assert.Equal(t, h.clock.Now().UTC(), *updated.CCSPasswordSetAt)
	assert.Equal(t, win.Version+1, updated.Version, "the target's version moves (its ETag names the new state)")

	var purpose, kind string
	var owner uuid.UUID
	var ciphertext []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT purpose, kind, target_id, ciphertext FROM credentials WHERE target_id = $1`, win.ID).
		Scan(&purpose, &kind, &owner, &ciphertext))
	assert.Equal(t, "win_ccs", purpose)
	assert.Equal(t, "win_ccs_password", kind)
	assert.Equal(t, win.ID, owner)
	assert.False(t, bytes.Contains(ciphertext, first), "sealed")

	var details string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT details::text FROM audit_log WHERE action = 'target.ccs_password_set' AND object_id = $1`,
		win.ID.String()).Scan(&details))
	assert.NotContains(t, details, string(first), "the audit row holds no secret")

	_, err = setCCS(t, h, admin, win, ccsPassword())
	assert.ErrorIs(t, err, inventory.ErrVersionMismatch, "If-Match names the version read")

	h.clock.Advance(time.Hour)
	second := ccsPassword()
	updated, err = setCCS(t, h, admin, updated, second)
	require.NoError(t, err)
	assert.Equal(t, h.clock.Now().UTC(), *updated.CCSPasswordSetAt, "ccs_password_set_at follows the newest row")
	assert.Equal(t, 2, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", win.ID), "rows are append-only")

	pt, release, err := ccsSource(t, h).CCSPassword(h.ctx, win.ID)
	require.NoError(t, err)
	assert.Equal(t, second, pt.Bytes(), "the newest row is the password")
	release()
	assert.Equal(t, make([]byte, len(second)), pt.Bytes(), "release zeroes it")
	listed, err := h.svc.ListTargets(h.ctx)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, updated.CCSPasswordSetAt, listed[0].CCSPasswordSetAt)
}

func TestCCSPasswordForeign(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	a, b := winTarget(t, h, admin, "iis-01"), winTarget(t, h, admin, "iis-02")
	web := nginxTarget(t, h, admin, "web-01")
	_, err := setCCS(t, h, admin, b, ccsPassword())
	require.NoError(t, err)
	src := ccsSource(t, h)

	pt, release, err := src.CCSPassword(h.ctx, a.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound, "another server's password is never this one's")
	assert.Nil(t, release)
	assert.Empty(t, pt.Bytes())

	_, err = setCCS(t, h, admin, web, ccsPassword())
	require.ErrorIs(t, err, inventory.ErrNotWindowsTarget)
	// A row that names a server of another type (as a bug or the owner role could write) is refused, never opened.
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
SELECT $2, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, $3 FROM credentials WHERE target_id = $1`, b.ID, uuid.New(), web.ID)
	require.NoError(t, err)
	pt, release, err = src.CCSPassword(h.ctx, web.ID)
	require.ErrorIs(t, err, inventory.ErrForeignCredential)
	assert.Nil(t, release)
	assert.Empty(t, pt.Bytes())

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", b.ID)
	require.NoError(t, err)
	_, _, err = src.CCSPassword(h.ctx, b.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound, "a deleted server has no password")
	_, err = setCCS(t, h, admin, b, ccsPassword())
	require.ErrorIs(t, err, inventory.ErrNotFound, "a deleted server takes no password")
	_, err = h.svc.SetCCSPassword(h.ctx, admin, uuid.New(), 1, secrets.NewPlaintext(ccsPassword()))
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, _, err = src.CCSPassword(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func TestCCSPasswordRule(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winTarget(t, h, admin, "iis-01")
	pw := ccsPassword()
	for name, bad := range map[string][]byte{
		"11 characters": pw[:11],
		"a space":       append(bytes.Clone(pw[:12]), ' '),
		"empty":         nil,
	} {
		_, err := setCCS(t, h, admin, win, bad)
		assert.ErrorIs(t, err, inventory.ErrCCSPasswordInvalid, name)
		if err != nil && len(bad) > 0 {
			assert.NotContains(t, err.Error(), string(bad), name)
		}
	}
	assert.Zero(t, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", win.ID), "nothing stored")
	assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE action = 'target.ccs_password_set'"))
}

// Ruling 13: the token of a CCS file is the SHA-256 of the leaf's DER, as for an http.sys binding.
func TestNewCertSHA256ForCCS(t *testing.T) {
	now := time.Now()
	leaf := pki.NewCA("Token", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), inventory.NewCertSHA256(providers.LocationWinCCSFile, leaf.FullchainPEM))
	assert.Empty(t, inventory.NewCertSHA256(providers.LocationWinCCSFile, []byte("not PEM")))
}

// ccsFixture is winDeployFixture plus a second Windows server iis-02 with one CCS file holding old.
type ccsFixture struct {
	*winDeployFixture
	server, file uuid.UUID
}

func newCCSFixture(t *testing.T) *ccsFixture {
	t.Helper()
	f := &ccsFixture{winDeployFixture: newWinDeployFixture(t)}
	h := f.h
	f.server = winTarget(t, h, f.admin, "iis-02").ID
	loc := providers.CertLocation{Kind: providers.LocationWinCCSFile, CertPath: `C:\CCS\www.example.test.pfx`, Supported: true,
		Locator: providers.Locator{"type": "ccs_file", "path": `C:\CCS`, "host": "www.example.test"},
		Details: map[string]any{"ccs_path": `C:\CCS`, "file_name": "www.example.test.pfx"},
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Section: "Default Web Site",
			Listens: []providers.CertListen{{Addr: "*", Port: 443}}}}}
	_, err := h.svc.Reconcile(h.ctx, f.server, providers.DiscoveryResult{WebServer: iisOK,
		Certificates: []providers.DiscoveredCertificate{{Location: loc, PEMChain: f.old.FullchainPEM, FileSHA256: derSHA(f.old)}}})
	require.NoError(t, err)
	l := byPath(t, h, f.server, false)[`C:\CCS\www.example.test.pfx`]
	require.True(t, l.Supported)
	require.Equal(t, providers.LocationWinCCSFile, l.Kind)
	f.file = l.ID
	return f
}

// Ruling 21: the start record of a CCS deployment names the operation and the token only (the helper's journal holds
// the backup file); the location's details stay the file's.
func TestStartBackupRefForCCS(t *testing.T) {
	f := newCCSFixture(t)
	r := f.request(f.file)
	f.start(r.ID, nil)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.rollbackInfo(r.ID)), &got))
	assert.Equal(t, map[string]any{"operation_id": r.ID.String(), "previous_sha256": derSHA(f.old)}, got)

	require.NoError(t, f.h.svc.FinishDeployment(f.h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded,
		Result: "deployed", CertFileSHA256: derSHA(f.nw), Verified: "remote"}))
	var details string
	require.NoError(t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT details::text FROM certificate_locations WHERE id = $1", f.file).Scan(&details))
	assert.NotContains(t, details, "cert_sha1", "the thumbprint update is a binding's only")
}

// Ruling 21: a CCS deployment whose Windows session ended without an answer lost its connection, as a binding's; its
// e-mail keeps the file texts (notify.go), because it is a file.
func TestWindowsLostIncludesCCS(t *testing.T) {
	f := newCCSFixture(t)
	h := f.h
	r := f.request(f.file)
	f.start(r.ID, nil)
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE deployments SET error_code = 'deployment.interrupted' WHERE id = $1", r.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.MarkRecovering(h.ctx, r.ID, time.Time{}, true))
	mails := f.deploymentMails(r.ID)
	require.Len(t, mails, 1)
	assert.Equal(t, inventory.TemplateDeploymentNeedsAttention, mails[0].Template, "the lost-connection text, not the unconfirmed one")
}

// W5-5: a CCS file's rollback_failed e-mail is its CCS text, naming the previous certificate in place of backup_dir; a
// deployment that failed before any change keeps the file text.
func TestCCSDeploymentEmails(t *testing.T) {
	f := newCCSFixture(t)
	h := f.h
	base := func(id uuid.UUID) map[string]string {
		return map[string]string{"target_name": "iis-02", "cert_path": `C:\CCS\www.example.test.pfx`, "deployment_id": id.String()}
	}
	r := f.request(f.file)
	f.start(r.ID, nil)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusRollbackFailed,
		Result: "rollback_failed", FailedStep: "restore", ErrorCode: "windows.backup_missing"}))
	want := base(r.ID)
	want["previous_certificate"] = "SHA-256 " + derSHA(f.old)
	assert.Equal(t, []queuedMail{{inventory.WindowsCCSTemplate(inventory.TemplateDeploymentRollbackFailed), want}}, f.deploymentMails(r.ID))

	r2 := f.request(f.file)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r2.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
		ErrorCode: "windows.ccs_disabled"}))
	assert.Equal(t, []queuedMail{{inventory.TemplateDeploymentFailed, base(r2.ID)}}, f.deploymentMails(r2.ID), "the file text")
}

// The refusals of SetCCSPassword and CCSPassword that store or open nothing: a licence lock, a stale If-Match, a row this
// master key cannot open (ErrCCSPasswordUnusable, never the missing password), a database that cannot be read.
func TestCCSPasswordRefusals(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winTarget(t, h, admin, "iis-01")
	src := ccsSource(t, h)

	_, err := setCCS(t, h, admin, inventory.Target{ID: win.ID, Version: win.Version + 1}, ccsPassword())
	require.ErrorIs(t, err, inventory.ErrVersionMismatch)
	updated, err := setCCS(t, h, admin, win, ccsPassword())
	require.NoError(t, err)

	// A row whose envelope this master key cannot open is unusable: discovery must not take it for a missing password.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET ciphertext = '\\x00' WHERE target_id = $1", win.ID)
	require.NoError(t, err)
	pt, release, err := src.CCSPassword(h.ctx, win.ID)
	require.ErrorIs(t, err, providers.ErrCCSPasswordUnusable)
	assert.NotErrorIs(t, err, providers.ErrNoCCSPassword)
	assert.Nil(t, release)
	assert.Empty(t, pt.Bytes())

	_, _, err = src.CCSPassword(h.ctx, uuid.New())
	require.ErrorIs(t, err, providers.ErrNoCCSPassword, "no password is the provider's sentinel too")

	cancelled, cancel := context.WithCancel(h.ctx)
	cancel()
	_, _, err = src.CCSPassword(cancelled, win.ID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, inventory.ErrNotFound, "a read that failed is no missing password")
	_, err = h.svc.SetCCSPassword(cancelled, admin, win.ID, updated.Version, secrets.NewPlaintext(ccsPassword()))
	require.Error(t, err)

	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, err = setCCS(t, h, admin, updated, ccsPassword())
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", win.ID), "nothing stored after the first")
}

// A platform key this master key cannot open is refused, never used.
func TestUnreadablePlatformKeyIsRefused(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	_, err := h.svc.EnsurePlatformKey(h.ctx)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET ciphertext = '\\x00' WHERE purpose = 'platform_ssh'")
	require.NoError(t, err)
	signer, release, err := h.svc.Credentials().SSHSigner(h.ctx)
	require.Error(t, err)
	assert.NotErrorIs(t, err, inventory.ErrNoPlatformKey)
	assert.Nil(t, signer)
	assert.Nil(t, release)
}

// The paths a Windows server's page, its CCS password, its cleanup and its deployments' records take report a database
// that cannot be reached as an error of their own (TestServicePathsReportADatabaseFailure's rule): never as not found, no
// password, no key or success.
func TestWindowsServerPathsReportADatabaseFailure(t *testing.T) {
	h := newHarness(t, withClosedPool())
	h.installLicense("LIC-DEAD-DB-W5", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	a := h.user("ada", rbac.Admin, "")
	id := uuid.New()
	ctx, svc := h.ctx, h.svc
	name := "iis-02"
	for what, call := range map[string]func() error{
		"SetCCSPassword": func() error {
			_, err := svc.SetCCSPassword(ctx, a, id, 1, secrets.NewPlaintext(ccsPassword()))
			return err
		},
		"CCSPassword": func() error {
			_, _, err := svc.Credentials().(providers.CCSPasswordSource).CCSPassword(ctx, id)
			return err
		},
		"SSHSigner":         func() error { _, _, err := svc.Credentials().SSHSigner(ctx); return err },
		"PlatformKey":       func() error { _, err := svc.PlatformKey(ctx); return err },
		"EnsurePlatformKey": func() error { _, err := svc.EnsurePlatformKey(ctx); return err },
		"SetupGuide":        func() error { _, err := svc.SetupGuide(ctx, ""); return err },
		"CreateTarget": func() error {
			_, _, err := svc.CreateTarget(ctx, a, inventory.NewTarget{Name: name, Type: "linux", Host: name + ".corp.example"})
			return err
		},
		"UpdateTarget": func() error {
			_, err := svc.UpdateTarget(ctx, a, id, 1, inventory.TargetPatch{Name: &name})
			return err
		},
		"RecordConnectionOK":     func() error { return svc.RecordConnectionOK(ctx, id, providers.ConnectionReport{}) },
		"CleanupWatch":           func() error { _, err := svc.CleanupWatch(ctx, id); return err },
		"JudgeCleanup":           func() error { _, err := svc.JudgeCleanup(ctx, id, providers.CleanupPlan{}); return err },
		"ScheduleWindowsCleanup": func() error { _, err := svc.ScheduleWindowsCleanup(ctx); return err },
		"RecordDeploymentStep": func() error {
			return svc.RecordDeploymentStep(ctx, id, providers.StepNameWriteFile, providers.StepOK, nil)
		},
		"Rollout":          func() error { _, err := svc.Rollout(ctx, id); return err },
		"RolloutDetail":    func() error { _, err := svc.RolloutDetail(ctx, id); return err },
		"PurgeHeldBackups": func() error { _, err := svc.PurgeHeldBackups(ctx); return err },
		"AdvanceRollouts":  func() error { _, err := svc.AdvanceRollouts(ctx); return err },
	} {
		err := call()
		require.Error(t, err, what)
		for _, refusal := range []error{inventory.ErrNotFound, providers.ErrNoCCSPassword, inventory.ErrNoPlatformKey} {
			assert.NotErrorIs(t, err, refusal, what)
		}
	}
}

// Fixes batch 3 C2 (WIN-67; defence in depth, the provider refuses the skip first): the W5 Ruling 8 exception that
// records a skipped verification of a CCS file no binding uses needs an uncut file. With list_truncated stored, the skip
// is refused as for any other location (TestSkippedVerificationNeedsTheSetting) and the outcome stays uncertain.
func TestCCSSkipNeedsAnUncutFile(t *testing.T) {
	f := newCCSFixture(t)
	h := f.h
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET servers = '[]' WHERE id = $1", f.file)
	require.NoError(t, err)
	skipped := inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Result: "deployed", CertFileSHA256: derSHA(f.nw), Verified: "skipped"}
	r := f.request(f.file)
	f.start(r.ID, nil)
	require.NoError(t, h.svc.FinishDeployment(h.ctx, r.ID, skipped), "an uncut file no binding uses: the helper's read-back is its check")

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET warnings = ARRAY['list_truncated'] WHERE id = $1", f.file)
	require.NoError(t, err)
	r2 := f.request(f.file)
	f.start(r2.ID, nil)
	assert.ErrorIs(t, h.svc.FinishDeployment(h.ctx, r2.ID, skipped), inventory.ErrDeploymentState, "a cut file: the bindings may be unknown")
	outcome := providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Verified: "skipped"}
	require.NoError(t, h.svc.RecordOutcome(h.ctx, r2.ID, inventory.DeployOutcomeRecord(outcome, nil, false), h.clock.Now().Add(time.Minute)))
	d, err := h.svc.Deployment(h.ctx, r2.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateRecovering, d.State, "an unrequested skip is not a success")
	assert.Equal(t, "uncertain", d.Result)
}

// W5-5 (fixes batch 3, Ruling 9; WIN-47): the target's type is checked before the password rule, so a server that is
// not Windows answers the conflict whatever the password; nothing is stored or audited.
func TestSetCCSPasswordOnANonWindowsTargetIsAConflict(t *testing.T) {
	f := newCCSFixture(t)
	h := f.h
	web, err := h.svc.GetTarget(h.ctx, f.web)
	require.NoError(t, err)
	_, err = setCCS(t, h, f.admin, web, []byte("short"))
	require.ErrorIs(t, err, inventory.ErrNotWindowsTarget)
	assert.NotErrorIs(t, err, inventory.ErrCCSPasswordInvalid)
	assert.Zero(t, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", f.web), "nothing stored")
	assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE action = 'target.ccs_password_set'"))
}
