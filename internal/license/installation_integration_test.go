//go:build integration

package license_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// Tests of the installation seal (Phase 2 final review B1, spec §16.1(a)): the installation
// row cannot be changed, removed or swapped to reset the evaluation or bind a shared license.

// wantSeal computes the seal independently of the service: HMAC-SHA256 under the dedicated
// HKDF label over the installation ID and the timestamp in microseconds.
func (e *env) wantSeal(id string, at time.Time) []byte {
	key := e.keyring.Derive(secrets.LabelInstallation)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("alice-installation-v1\n" + id + "\n" + strconv.FormatInt(at.UTC().UnixMicro(), 10)))
	return m.Sum(nil)
}

func (e *env) storedSeal() []byte {
	e.t.Helper()
	var seal []byte
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT installation_seal FROM license WHERE id = 1").Scan(&seal))
	return seal
}

func (e *env) ownerExec(sql string, args ...any) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, sql, args...)
	require.NoError(e.t, err, sql)
}

// requireTamperedLock checks that the installation is evaluated as an ended evaluation: the
// gate refuses changes and no license file counts.
func (e *env) requireTamperedLock() {
	e.t.Helper()
	snap := e.svc.Snapshot()
	assert.True(e.t, snap.InstallationTampered)
	assert.Equal(e.t, license.PhaseEvaluationExpired, snap.Eval.Phase)
	assert.Nil(e.t, snap.Eval.Current, "no license file counts for an untrusted installation")
	err := e.svc.Allow(license.ClassChange)
	assert.ErrorIs(e.t, err, license.ErrLocked)
	assert.True(e.t, license.ConfirmedLock(err), "an evaluated lock: the runner holds queued changes as in any lock")
	assert.Equal(e.t, "evaluation_expired", e.state())
	assert.Equal(e.t, "evaluation_ended", snap.Banners(false)[0].Kind, "the banner of an ended evaluation, for everyone")
}

func TestStartSealsTheInstallation(t *testing.T) {
	e := newEnv(t)
	snap := e.svc.Snapshot()
	seal := e.storedSeal()
	require.Len(t, seal, sha256.Size)
	assert.Equal(t, e.wantSeal(snap.InstallationID, snap.InstalledAt), seal, "MAC under alice/installation/v1")
	assert.NotEqual(t, e.keyring.Derive(secrets.LabelInstallation), e.keyring.Derive(secrets.LabelHWM), "a dedicated sub-key")
	assert.False(t, snap.InstallationTampered)
	assert.Zero(t, e.auditCount("license.installation_sealed"), "a new installation is sealed when it is created")

	e.restart()
	assert.Equal(t, seal, e.storedSeal(), "the seal is written once")
	assert.False(t, e.svc.Snapshot().InstallationTampered)
}

// (b) An installation timestamp moved forward would restart the 30-day evaluation.
func TestChangedInstallationTimeLocks(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(29 * day))
	e.ownerExec("UPDATE license SET installed_at = $1", installedAt.Add(29*day))
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, 1, e.auditCount("license.installation_tampered"))
	assert.Equal(t, map[string]string{"problem": "seal_mismatch", "installation_id": e.installation(), "episode": "1"},
		e.auditDetails("license.installation_tampered"), "the details name the problem, never the seal")

	e.tickAt(installedAt.Add(29*day + time.Hour))
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, 1, e.auditCount("license.installation_tampered"), "audited once")

	// A valid license for this installation ID does not count while the row is untrusted.
	now := e.clk.Now()
	res, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	assert.Equal(t, license.PhaseEvaluationExpired, res.Phase, "the reported phase is the one the gate enforces")
	e.requireTamperedLock()
	d, err := e.svc.Detail(e.ctx)
	require.NoError(t, err)
	require.Len(t, d.Files, 1)
	assert.Equal(t, "invalid", d.Files[0].Status)

	// Putting the original value back restores trust.
	e.ownerExec("UPDATE license SET installed_at = $1", installedAt)
	e.restart()
	assert.False(t, e.svc.Snapshot().InstallationTampered)
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
}

// (b) Another installation's ID would let a license issued for it work here.
func TestChangedInstallationIDLocks(t *testing.T) {
	e := newEnv(t)
	other := license.NewInstallationID()
	e.ownerExec("UPDATE license SET installation_id = $1", other)
	e.restart()
	require.Equal(t, other, e.installation())
	e.requireTamperedLock()

	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-SHARED", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	e.requireTamperedLock()
	assert.Zero(t, e.auditCount("license.tampered"), "the stored file is not reported as changed")
}

// (b) A seal changed or removed is tampering. There is no installation "not sealed yet": every
// row is sealed when it is created, and nothing seals an existing row (AUD-18).
func TestDamagedOrRemovedSealLocks(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = decode(repeat('00', 32), 'hex')")
		e.restart()
		e.requireTamperedLock()
	})
	t.Run("removed", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		snap, err := e.newService().Inspect(e.ctx)
		require.NoError(t, err)
		assert.True(t, snap.InstallationTampered, "alice license status reports it too")
		assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase)

		e.restart()
		e.requireTamperedLock()
		assert.Equal(t, map[string]string{"problem": "seal_missing", "installation_id": e.installation(), "episode": "1"},
			e.auditDetails("license.installation_tampered"))
		e.clk.Advance(day)
		e.restart()
		e.requireTamperedLock()
		assert.Nil(t, e.storedSeal(), "never sealed again")
		assert.Equal(t, 1, e.auditCount("license.installation_tampered"), "one episode")
		assert.Zero(t, e.auditCount("license.installation_sealed"))
	})
}

// AUD-18 (audit PoC 3, inverted): on day 29 of the evaluation the database owner clears the
// seal and moves the installation time to now. Before, the next start sealed the edited row as
// "an installation from before the seal" and the evaluation began again with 30 days. Now the
// evaluation counts as ended, during the run and after every restart, and the row is never sealed.
func TestRemovedSealIsTamperingOnEveryInstallation(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(29 * day))
	require.Equal(t, 1, e.svc.Snapshot().Eval.DaysLeft)

	e.ownerExec("UPDATE license SET installation_seal = NULL, installed_at = $1", installedAt.Add(29*day))
	e.tickAt(installedAt.Add(29*day + time.Hour))
	e.requireTamperedLock()

	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, "seal_missing", e.auditDetails("license.installation_tampered")["problem"])
	assert.Zero(t, e.auditCount("license.installation_sealed"))
	assert.Nil(t, e.storedSeal())
	assert.NotEqual(t, 30, e.svc.Snapshot().Eval.DaysLeft)
}

// AUD-18: a seal cleared on a database whose audit log has an old one-time upgrade seal, or
// none, is the same tampering (the upgrade path and its audit marker are gone).
func TestRemovedSealDoesNotDependOnTheAuditLog(t *testing.T) {
	e := newEnv(t)
	e.appendAudit("license.installation_sealed", audit.Success, map[string]string{"reason": "upgrade", "installation_id": e.installation()})
	e.ownerExec("UPDATE license SET installation_seal = NULL")
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, 1, e.auditCount("license.installation_sealed"), "nothing new written")
}

// emptyAuditLog removes every audit event (the owner role, with the append-only triggers off).
func (e *env) emptyAuditLog() {
	e.t.Helper()
	e.ownerExec("ALTER TABLE audit_log DISABLE TRIGGER USER")
	e.ownerExec("TRUNCATE audit_log")
	e.ownerExec("ALTER TABLE audit_log ENABLE TRIGGER USER")
}

// removeTimeRecords removes both copies of the time record.
func (e *env) removeTimeRecords() {
	e.t.Helper()
	e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'")
	require.NoError(e.t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
}

// served writes what serve writes right after the license service's first start: the
// platform key's audit event (cmd/alice; the license tests run without the inventory).
func (e *env) served() {
	e.t.Helper()
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := audit.New(e.clk).Append(e.ctx, tx, audit.Event{Actor: audit.SystemActor("inventory"),
			Action: "platform_key.created", ObjectType: "credential", ObjectID: "platform", Result: audit.Success})
		return err
	}))
}

// (c) A removed installation row is not a fresh evaluation when the installation existed
// (AUD-18: also when only the audit log, or a time record that no longer verifies, shows it).
func TestRemovedInstallationIsNotAFreshEvaluation(t *testing.T) {
	cases := map[string]struct {
		extra    func(e *env)
		evidence string
	}{
		"time record left":           {func(*env) {}, "time_record"},
		"license tables truncated":   {func(e *env) { e.ownerExec("TRUNCATE license_files, license_history") }, "time_record"},
		"state directory copy only":  {func(e *env) { e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'") }, "time_record"},
		"database copy only":         {func(e *env) { require.NoError(e.t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName))) }, "time_record"},
		"only setup completion left": {func(e *env) { e.removeTimeRecords(); e.setupCompleted() }, "setup_completed"},
		"only the audit log left": {func(e *env) {
			e.removeTimeRecords()
			e.ownerExec("TRUNCATE license_files, license_history")
		}, "audit_log"},
		"a damaged time record left": {func(e *env) {
			e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'")
			require.NoError(e.t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), []byte(`{"v":1,"data":"x","mac":"y"}`), 0o600))
			e.emptyAuditLog()
		}, "time_record_damaged"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.served()
			old := e.installation()
			e.tickAt(installedAt.Add(10 * day))
			e.ownerExec("DELETE FROM license")
			tc.extra(e)
			e.restart()

			snap := e.svc.Snapshot()
			assert.NotEqual(t, old, snap.InstallationID, "a new installation ID")
			assert.False(t, snap.InstallationTampered, "the new row is sealed")
			assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase, "no new 30-day evaluation")
			assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
			assert.Equal(t, 1, e.auditCount("license.installation_tampered"))
			details := e.auditDetails("license.installation_tampered")
			assert.Equal(t, "installation_missing", details["problem"])
			assert.Equal(t, tc.evidence, details["evidence"])
			assert.Equal(t, snap.InstallationID, details["installation_id"])

			e.clk.Advance(time.Hour)
			e.restart()
			assert.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase, "still ended after a restart")
			assert.Equal(t, 1, e.auditCount("license.installation_tampered"))

			// A license for the new installation ID works as usual.
			now := e.clk.Now()
			_, err := e.upload(e.payload("LIC-NEW", now, now.AddDate(1, 0, 0), 10))
			require.NoError(t, err)
			assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
		})
	}
}

// Accepted bypass (R36): with every trace of the installation gone from the database and the
// state directory, the installation is new (the e2e reset does exactly this).
func TestEmptiedDatabaseStartsAFreshEvaluation(t *testing.T) {
	e := newEnv(t)
	e.served()
	e.setupCompleted()
	e.ownerExec("TRUNCATE license, license_files, license_history, settings")
	e.emptyAuditLog()
	require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
	e.restart()
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
	assert.Equal(t, 30, e.svc.Snapshot().Eval.DaysLeft)
	assert.False(t, e.svc.Snapshot().InstallationTampered)
	assert.Zero(t, e.auditCount("license.installation_tampered"))
}

// setupCompleted writes the setup module's completion marker.
func (e *env) setupCompleted() {
	e.t.Helper()
	e.ownerExec(`INSERT INTO settings (key, value, updated_at) VALUES ('setup.completed_at', '"2026-10-01T09:00:00Z"', now())`)
}

// AUD-18: every way the database owner (who also controls the state volume) could try to get a
// fresh evaluation, and what Alice does. The trial runs 20 days, then the attempt is made.
func TestEvaluationRestartAttempts(t *testing.T) {
	newKey := keyring(t, 9)
	cases := map[string]struct {
		attempt func(e *env)
		// want: "tampered" (the row is kept, not trusted), "removed" (a new row whose evaluation
		// has ended, evidence named), "continues" (nothing gained), "fresh" (indistinguishable).
		want, evidence string
	}{
		"seal cleared": {func(e *env) { e.ownerExec("UPDATE license SET installation_seal = NULL") }, "tampered", ""},
		"seal cleared and the time moved": {func(e *env) {
			e.ownerExec("UPDATE license SET installation_seal = NULL, installed_at = $1", e.clk.Now())
		}, "tampered", ""},
		"time moved under the old seal":     {func(e *env) { e.ownerExec("UPDATE license SET installed_at = $1", e.clk.Now()) }, "tampered", ""},
		"installation row deleted":          {func(e *env) { e.ownerExec("DELETE FROM license") }, "removed", "time_record"},
		"all license tables truncated":      {func(e *env) { e.ownerExec("TRUNCATE license, license_files, license_history") }, "removed", "time_record"},
		"license rows and settings deleted": {func(e *env) { e.ownerExec("TRUNCATE license, license_files, license_history, settings") }, "removed", "time_record"},
		"database recreated empty, state directory kept": {func(e *env) {
			e.ownerExec("TRUNCATE license, license_files, license_history, settings")
			e.emptyAuditLog()
		}, "removed", "time_record"},
		"database recreated empty and master key replaced, state directory kept": {func(e *env) {
			e.ownerExec("TRUNCATE license, license_files, license_history, settings")
			e.emptyAuditLog()
			e.keyring = newKey
		}, "removed", "time_record_damaged"},
		"state directory wiped, database kept": {func(e *env) {
			require.NoError(e.t, os.RemoveAll(e.stateDir))
		}, "continues", ""},
		"state directory wiped, installation records deleted, audit log kept": {func(e *env) {
			require.NoError(e.t, os.RemoveAll(e.stateDir))
			e.ownerExec("TRUNCATE license, license_files, license_history, settings")
		}, "removed", "audit_log"},
		"both wiped": {func(e *env) {
			require.NoError(e.t, os.RemoveAll(e.stateDir))
			e.ownerExec("TRUNCATE license, license_files, license_history, settings")
			e.emptyAuditLog()
		}, "fresh", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.served()
			e.setupCompleted()
			old := e.installation()
			e.tickAt(installedAt.Add(20 * day))
			require.Equal(t, 10, e.svc.Snapshot().Eval.DaysLeft)

			tc.attempt(e)
			e.clk.Advance(time.Minute)
			e.restart()
			snap := e.svc.Snapshot()
			switch tc.want {
			case "tampered":
				e.requireTamperedLock()
				assert.Equal(t, old, snap.InstallationID)
				assert.Equal(t, 1, e.auditCount("license.installation_tampered"))
			case "removed":
				assert.NotEqual(t, old, snap.InstallationID)
				assert.False(t, snap.InstallationTampered, "the new row is sealed and trusted")
				assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase, "its evaluation has already ended")
				assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
				assert.Equal(t, "evaluation_ended", snap.Banners(false)[0].Kind)
				d := e.auditDetails("license.installation_tampered")
				assert.Equal(t, map[string]string{"problem": "installation_missing", "evidence": tc.evidence, "installation_id": snap.InstallationID}, d)
			case "continues":
				assert.Equal(t, old, snap.InstallationID)
				assert.False(t, snap.InstallationTampered)
				assert.Equal(t, 10, snap.Eval.DaysLeft, "the evaluation goes on from where it was")
			case "fresh":
				assert.NotEqual(t, old, snap.InstallationID)
				assert.Equal(t, license.PhaseEvaluation, snap.Eval.Phase)
				assert.Equal(t, 30, snap.Eval.DaysLeft, "accepted: nothing is left to tell it from a new installation")
				assert.Zero(t, e.auditCount("license.installation_tampered"))
			}
			assert.Zero(t, e.auditCount("license.installation_sealed"), "no row is ever sealed after its creation")

			// Restarting changes nothing.
			e.clk.Advance(time.Hour)
			e.restart()
			assert.Equal(t, snap.InstallationID, e.installation())
			assert.Equal(t, snap.Eval.Phase, e.svc.Snapshot().Eval.Phase)
		})
	}
}

// AUD-18: how an honest customer recovers. A changed or unsealed record comes back by restoring
// the original row (from a backup); a record that cannot be restored is removed, and the next
// start creates a new Installation ID whose evaluation has ended, for which the vendor issues a
// license (the same path as a database lost without a backup while the state volume remains).
func TestRecoveryFromAnUnsealedRecord(t *testing.T) {
	t.Run("restore the original record", func(t *testing.T) {
		e := newEnv(t)
		seal := e.storedSeal()
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		e.restart()
		e.requireTamperedLock()
		e.ownerExec("UPDATE license SET installation_seal = $1", seal)
		e.restart()
		assert.False(t, e.svc.Snapshot().InstallationTampered)
		assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
		assert.Equal(t, 1, e.auditCount("license.installation_restored"))
	})
	t.Run("a vendor license for a new Installation ID", func(t *testing.T) {
		e := newEnv(t)
		old := e.installation()
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		e.restart()
		e.requireTamperedLock()
		now := e.clk.Now()
		_, err := e.upload(e.payload("LIC-OLD", now, now.AddDate(1, 0, 0), 10))
		require.NoError(t, err)
		e.requireTamperedLock() // a license for the unsealed record does not count

		e.ownerExec("DELETE FROM license")
		e.restart()
		require.NotEqual(t, old, e.installation())
		assert.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase)
		_, err = e.upload(e.payload("LIC-NEW", now, now.AddDate(1, 0, 0), 10))
		require.NoError(t, err)
		assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
		assert.NoError(t, e.svc.Allow(license.ClassChange))
	})
}

// The application role cannot change the installation ID or timestamp at all (B1(d)).
func TestAppRoleCannotRewriteTheInstallation(t *testing.T) {
	e := newEnv(t)
	for _, sql := range []string{
		"UPDATE license SET installed_at = now()",
		"UPDATE license SET installation_id = 'ALICE-0000'",
		"DELETE FROM license",
	} {
		_, err := e.db.App.Exec(e.ctx, sql)
		require.ErrorContains(t, err, "permission denied", sql)
	}
}

// A seal or tamper record that cannot be written stops the start and changes nothing; the
// next start does the work.
func TestInstallationSealFaults(t *testing.T) {
	t.Run("audit log unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("DELETE FROM license")
		e.removeTimeRecords()
		e.revoke("SELECT", "audit_log")
		require.ErrorContains(t, e.newService().Start(e.ctx), "read the audit log")
		assert.Zero(t, e.countWhere("license", "true"), "no installation is created on a guess")
	})
	t.Run("removed installation not recorded", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("DELETE FROM license")
		undo := e.failOn("audit_log", "INSERT", "NEW.action = 'license.installation_tampered'")
		requireInjected(t, e.newService().Start(e.ctx))
		assert.Zero(t, e.countWhere("license", "true"), "no installation without its audit row")
		undo()
		e.restart()
		assert.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase)
	})
	t.Run("setup state unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("DELETE FROM license")
		e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'")
		require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
		e.revoke("SELECT", "settings")
		require.Error(t, e.newService().Start(e.ctx))
		assert.Zero(t, e.countWhere("license", "true"))
	})
	t.Run("installation unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.revoke("SELECT", "license")
		require.ErrorContains(t, e.newService().Start(e.ctx), "read the installation")
	})
}

// notices returns the installation notices of the history in the order they were written.
func (e *env) installationNotices() []string {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, `SELECT notice FROM license_history
WHERE event = 'notice' AND (notice LIKE 'installation\_tampered:%' OR notice LIKE 'installation\_restored:%') ORDER BY at, id`)
	require.NoError(e.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		require.NoError(e.t, rows.Scan(&n))
		out = append(out, n)
	}
	require.NoError(e.t, rows.Err())
	return out
}

func (e *env) auditEpisodes(action string) []string {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT details->>'episode' FROM audit_log WHERE action = $1 ORDER BY seq", action)
	require.NoError(e.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		require.NoError(e.t, rows.Scan(&n))
		out = append(out, n)
	}
	require.NoError(e.t, rows.Err())
	return out
}

// Carry 4a: every tamper episode is audited once; restoring the original record closes the
// episode, and a later change opens a new one.
func TestInstallationTamperEpisodes(t *testing.T) {
	e := newEnv(t)
	id := e.installation()
	original := e.svc.Snapshot().InstalledAt

	e.ownerExec("UPDATE license SET installed_at = $1", original.Add(20*day))
	e.tickAt(installedAt.Add(time.Hour))
	e.requireTamperedLock()
	e.tickAt(installedAt.Add(2 * time.Hour))
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_tampered"), "one episode, audited once")

	e.ownerExec("UPDATE license SET installed_at = $1", original)
	e.tickAt(installedAt.Add(3 * time.Hour))
	assert.False(t, e.svc.Snapshot().InstallationTampered, "the original record is trusted again")
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_restored"))
	assert.Equal(t, map[string]string{"installation_id": id, "episode": "1"}, e.auditDetails("license.installation_restored"))
	e.tickAt(installedAt.Add(4 * time.Hour))
	assert.Equal(t, 1, e.auditCount("license.installation_restored"), "a clean record closes an episode once")

	e.ownerExec("UPDATE license SET installation_seal = decode(repeat('ab', 32), 'hex')")
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, []string{"1", "2"}, e.auditEpisodes("license.installation_tampered"), "the second tampering is recorded")
	assert.Equal(t, []string{
		"installation_tampered:" + id + ":1",
		"installation_restored:" + id + ":1",
		"installation_tampered:" + id + ":2",
	}, e.installationNotices())
}

// appendAudit appends an audit event through the audit log, as the application role would.
func (e *env) appendAudit(action string, result audit.Result, details map[string]string) {
	e.t.Helper()
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := audit.New(e.clk).Append(e.ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, Name: "system"},
			Action: action, ObjectType: "license", ObjectID: e.installation(), Result: result, Details: details})
		return err
	}))
}

// An installation tampered under Phase 2 has an audit event without an episode number: it counts
// as the open episode 1, so it is not reported again, and restoring the record closes it with
// the upgrade reason.
func TestPhase2TamperAuditCountsAsEpisodeOne(t *testing.T) {
	e := newEnv(t)
	id := e.installation()
	original := e.svc.Snapshot().InstalledAt
	e.appendAudit("license.installation_tampered", audit.Failure, map[string]string{"problem": "seal_mismatch", "installation_id": id})
	e.ownerExec("UPDATE license SET installed_at = $1", original.Add(20*day))
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, 1, e.auditCount("license.installation_tampered"), "episode 1 was already recorded by Phase 2")

	e.ownerExec("UPDATE license SET installed_at = $1", original)
	e.tickAt(installedAt.Add(time.Hour))
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_restored"))
	assert.Equal(t, map[string]string{"installation_id": id, "episode": "1", "reason": "upgrade"}, e.auditDetails("license.installation_restored"))
	assert.Contains(t, e.installationNotices(), "installation_restored:"+id+":1")
}

// The "record removed" event of a new installation is not an episode of the new installation.
func TestInstallationMissingEventIsNotAnEpisode(t *testing.T) {
	e := newEnv(t)
	e.appendAudit("license.installation_tampered", audit.Failure, map[string]string{"problem": "installation_missing", "installation_id": e.installation()})
	e.tickAt(installedAt.Add(time.Hour))
	assert.Zero(t, e.auditCount("license.installation_restored"))
}

// Forged notices written as the application role (it may insert into license_history) never
// suppress the audit: the episode state comes from the audit log.
func TestForgedNoticesDoNotSuppressTheAudit(t *testing.T) {
	e := newEnv(t)
	id := e.installation()
	for _, n := range []struct{ licenseID, notice string }{
		{"", "installation_tampered:" + id}, {"", "installation_tampered:" + id + ":1"},
		{"", "installation_tampered:" + id + ":2"}, {"", "installation_restored:" + id + ":2"},
		{"LIC-X", "installation_tampered:" + id + ":1"}, // with a license ID: not even shaped like an installation notice
	} {
		_, err := e.db.App.Exec(e.ctx, `INSERT INTO license_history (id, at, event, license_id, notice, details)
VALUES (gen_random_uuid(), now(), 'notice', $1, $2, '{}')`, n.licenseID, n.notice)
		require.NoError(t, err)
	}
	e.ownerExec("UPDATE license SET installed_at = installed_at + interval '1 day'")
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_tampered"), "the forged notices did not suppress the audit")
}
