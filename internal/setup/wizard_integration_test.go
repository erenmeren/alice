//go:build integration

package setup_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/notify"
	"alice/internal/platform/db"
	"alice/internal/rbac"
	"alice/internal/setup"
)

// wizardEnv is newEnv with the mail settings wired, as cmd/alice wires them.
type wizardEnv struct {
	*env
	mail *notify.Settings
}

func newWizardEnv(t *testing.T) *wizardEnv {
	t.Helper()
	e := newEnv(t)
	log := audit.New(e.clk)
	mail := notify.NewSettings(notify.SettingsConfig{Pool: e.db.App, Keyring: e.keyring, Audit: log, Clock: e.clk})
	e.setup = setup.New(setup.Config{Pool: e.db.App, Auth: e.auth, Keyring: e.keyring, Audit: log, Clock: e.clk,
		Hasher: auth.NewHasher(fastParams, 4), BackupKDF: fastKDF, License: e.license, Mail: mail})
	return &wizardEnv{env: e, mail: mail}
}

func (e *wizardEnv) admin(t *testing.T) auth.Principal {
	t.Helper()
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	return p
}

func (e *wizardEnv) status(t *testing.T) setup.Status {
	t.Helper()
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	return st
}

func (e *wizardEnv) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log WHERE action = $1", action).Scan(&n))
	return n
}

func (e *wizardEnv) settingsCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM settings").Scan(&n))
	return n
}

func TestWizardPositionIsDerived(t *testing.T) {
	e := newWizardEnv(t)
	st := e.status(t)
	assert.Empty(t, st.NextStep, "before the administrator exists the position is the browser's")
	assert.False(t, st.HTTPSChosen)
	assert.False(t, st.MailChosen)

	p := e.admin(t)
	assert.Equal(t, "passphrase", e.status(t).NextStep)

	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	assert.Equal(t, "https", e.status(t).NextStep)

	st, err := e.setup.KeepTemporaryCertificate(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.HTTPSChosen)
	assert.Equal(t, "mail", st.NextStep)

	_, err = e.mail.SaveSMTP(e.ctx, audit.SystemActor("test"), 0, notify.SMTPInput{Host: "smtp.example.com", Port: 587,
		TLSMode: notify.TLSModeSTARTTLS, From: "alice@example.com"})
	require.NoError(t, err)
	st = e.status(t)
	assert.True(t, st.MailChosen, "configured mail counts as chosen")
	assert.Equal(t, "license", st.NextStep)

	st, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, "platform", st.NextStep)

	st, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, "done", st.NextStep)
}

func TestMailSkippedCountsAsChosen(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	_, err := e.setup.KeepTemporaryCertificate(e.ctx, p, ip1)
	require.NoError(t, err)
	st, err := e.setup.SkipMail(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.MailChosen)
	assert.Equal(t, "license", st.NextStep)
}

func TestKeepTemporaryAndSkipMailAreAudited(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	for range 2 { // idempotent: a second call writes no second row
		_, err := e.setup.KeepTemporaryCertificate(e.ctx, p, ip1)
		require.NoError(t, err)
		_, err = e.setup.SkipMail(e.ctx, p, ip1)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, e.auditCount(t, "setup.https_kept_temporary"))
	assert.Equal(t, 1, e.auditCount(t, "setup.mail_skipped"))
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx,
		"SELECT details FROM audit_log WHERE action = 'setup.https_kept_temporary'").Scan(&details))
	assert.Equal(t, map[string]string{"choice": "temporary"}, details)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'setup.mail_skipped'").Scan(&details))
	assert.Equal(t, map[string]string{"choice": "skipped"}, details)
	assert.Equal(t, `"temporary"`, e.settingRaw(t, "setup.https_choice"))
	assert.Equal(t, `"skipped"`, e.settingRaw(t, "setup.mail_choice"))

	operator := p // the same session with the Operator role: settings.manage is refused
	operator.Role = rbac.Operator
	_, err := e.setup.KeepTemporaryCertificate(e.ctx, operator, ip1)
	assert.ErrorIs(t, err, setup.ErrForbidden)
	_, err = e.setup.SkipMail(e.ctx, operator, ip1)
	assert.ErrorIs(t, err, setup.ErrForbidden)
}

func TestSkipMailWhenMailIsConfiguredChangesNothing(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	_, err := e.mail.SaveSMTP(e.ctx, audit.SystemActor("test"), 0, notify.SMTPInput{Host: "smtp.example.com", Port: 587,
		TLSMode: notify.TLSModeSTARTTLS, From: "alice@example.com"})
	require.NoError(t, err)
	st, err := e.setup.SkipMail(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.MailChosen)
	assert.Zero(t, e.auditCount(t, "setup.mail_skipped"))
	assert.Empty(t, e.settingRaw(t, "setup.mail_choice"))
}

func TestRecordCertificateUploaded(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	_, err := e.setup.KeepTemporaryCertificate(e.ctx, p, ip1)
	require.NoError(t, err)
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.setup.RecordCertificateUploaded(e.ctx, tx, p) }))
	assert.Equal(t, `"uploaded"`, e.settingRaw(t, "setup.https_choice"), "an upload replaces the temporary choice")
	assert.True(t, e.status(t).HTTPSChosen)

	// The caller's transaction decides: a rollback keeps the earlier choice.
	e2 := newWizardEnv(t)
	p2 := e2.admin(t)
	errRollback := errors.New("rollback")
	err = db.InTx(e2.ctx, e2.db.App, func(tx pgx.Tx) error {
		require.NoError(t, e2.setup.RecordCertificateUploaded(e2.ctx, tx, p2))
		return errRollback
	})
	require.ErrorIs(t, err, errRollback)
	assert.Empty(t, e2.settingRaw(t, "setup.https_choice"))

	operator := p // the same session with the Operator role: settings.manage is refused
	operator.Role = rbac.Operator
	err = db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.setup.RecordCertificateUploaded(e.ctx, tx, operator) })
	assert.ErrorIs(t, err, setup.ErrForbidden)
}

func TestServerRefusesAFairPassphrase(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	weak := "aaaaaaaaaaaaaaaa"
	require.Equal(t, setup.StrengthFair, setup.PassphraseStrength(weak))
	require.ErrorIs(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, weak, weak), setup.ErrPassphraseTooWeak)
	assert.Empty(t, e.settingRaw(t, "backup.key"))
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM setting_secrets WHERE key = 'backup.sender'").Scan(&n))
	assert.Zero(t, n, "no sender key either")
	assert.Zero(t, e.auditCount(t, "setup.recovery_passphrase_set"))
	assert.NotContains(t, setup.ErrPassphraseTooWeak.Error(), weak)

	good := "Abcdefgh12345678"
	require.Equal(t, setup.StrengthGood, setup.PassphraseStrength(good))
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, good, good), "good is enough")
}

func TestCompleteStillNeedsOnlyPassphraseAndLicense(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	_, err := e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err)
	st, err := e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.Completed)
	assert.False(t, st.HTTPSChosen, "the dashboard checklist shows the HTTPS step")
	assert.False(t, st.MailChosen, "and the mail step")
	assert.Equal(t, "done", st.NextStep)
}

func TestKeepTemporaryAndSkipMailAfterCompletionChangeNothing(t *testing.T) {
	e := newWizardEnv(t)
	p := e.admin(t)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	_, err := e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err)
	done, err := e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	settingsBefore := e.settingsCount(t)
	var rowsBefore int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log").Scan(&rowsBefore))

	st, err := e.setup.KeepTemporaryCertificate(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, done, st)
	st, err = e.setup.SkipMail(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, done, st)

	assert.Equal(t, settingsBefore, e.settingsCount(t), "no setting written")
	var rowsAfter int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM audit_log").Scan(&rowsAfter))
	assert.Equal(t, rowsBefore, rowsAfter, "no audit row")
	assert.Empty(t, e.settingRaw(t, "setup.https_choice"))
	assert.Empty(t, e.settingRaw(t, "setup.mail_choice"))
}
