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
	assert.ErrorIs(e.t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.Equal(e.t, "evaluation_expired", e.state())
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

// (b) A seal changed or removed after it was written is tampering, not an old installation.
func TestDamagedOrRemovedSealLocks(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = decode(repeat('00', 32), 'hex')")
		e.restart()
		e.requireTamperedLock()
	})
	t.Run("removed after the upgrade seal", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		e.restart() // the one-time upgrade seal
		require.Equal(t, 1, e.auditCount("license.installation_sealed"))
		e.ownerExec("UPDATE license SET installation_seal = NULL, installed_at = $1", installedAt.Add(20*day))
		e.restart()
		e.requireTamperedLock()
		assert.Equal(t, "seal_missing", e.auditDetails("license.installation_tampered")["problem"])
		assert.Equal(t, 1, e.auditCount("license.installation_sealed"), "never sealed a second time")
		assert.Nil(t, e.storedSeal())
	})
}

// (a) An installation created before the seal existed is sealed once, on the first start
// after the upgrade, and keeps its ID, timestamp and evaluation.
func TestInstallationFromBeforeTheSealIsSealedOnce(t *testing.T) {
	e := newEnv(t)
	before := e.svc.Snapshot()
	e.ownerExec("UPDATE license SET installation_seal = NULL") // the row as an older version left it

	_, err := e.newService().Inspect(e.ctx)
	require.NoError(t, err, "alice license status works before the first start after the upgrade")
	assert.Nil(t, e.storedSeal(), "Inspect writes nothing")

	e.clk.Advance(day)
	e.restart()
	assert.Equal(t, e.wantSeal(before.InstallationID, before.InstalledAt), e.storedSeal())
	assert.Equal(t, 1, e.auditCount("license.installation_sealed"))
	assert.Equal(t, map[string]string{"reason": "upgrade", "installation_id": before.InstallationID},
		e.auditDetails("license.installation_sealed"))
	snap := e.svc.Snapshot()
	assert.False(t, snap.InstallationTampered)
	assert.Equal(t, before.InstallationID, snap.InstallationID)
	assert.True(t, snap.InstalledAt.Equal(before.InstalledAt))
	assert.Equal(t, license.PhaseEvaluation, snap.Eval.Phase)
	assert.Equal(t, 29, snap.Eval.DaysLeft)

	e.restart()
	assert.Equal(t, 1, e.auditCount("license.installation_sealed"), "sealed once")
}

// (c) A removed installation row is not a fresh evaluation when the installation existed.
func TestRemovedInstallationIsNotAFreshEvaluation(t *testing.T) {
	cases := map[string]func(e *env){
		"time record left": func(*env) {},
		"only setup completion left": func(e *env) {
			e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'")
			require.NoError(e.t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
			e.ownerExec(`INSERT INTO settings (key, value, updated_at) VALUES ('setup.completed_at', '"2026-10-01T09:00:00Z"', now())`)
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			old := e.installation()
			e.tickAt(installedAt.Add(10 * day))
			e.ownerExec("DELETE FROM license")
			extra(e)
			e.restart()

			snap := e.svc.Snapshot()
			assert.NotEqual(t, old, snap.InstallationID, "a new installation ID")
			assert.False(t, snap.InstallationTampered, "the new row is sealed")
			assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase, "no new 30-day evaluation")
			assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
			assert.Equal(t, 1, e.auditCount("license.installation_tampered"))
			details := e.auditDetails("license.installation_tampered")
			assert.Equal(t, "installation_missing", details["problem"])
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

// Accepted bypass (R36): with every trace of the installation gone, the database is new.
func TestEmptiedDatabaseStartsAFreshEvaluation(t *testing.T) {
	e := newEnv(t)
	e.ownerExec("DELETE FROM license")
	e.ownerExec("DELETE FROM settings WHERE key = 'time.hwm'")
	require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
	e.restart()
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
	assert.Zero(t, e.auditCount("license.installation_tampered"))
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
	t.Run("upgrade seal refused", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		undo := e.failOn("audit_log", "INSERT", "NEW.action = 'license.installation_sealed'")
		requireInjected(t, e.newService().Start(e.ctx))
		assert.Nil(t, e.storedSeal(), "the seal and its audit row are written together")
		undo()
		e.restart()
		assert.NotNil(t, e.storedSeal())
		assert.False(t, e.svc.Snapshot().InstallationTampered)
	})
	t.Run("seal record unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.ownerExec("UPDATE license SET installation_seal = NULL")
		e.revoke("SELECT", "audit_log")
		require.ErrorContains(t, e.newService().Start(e.ctx), "read the installation seal record")
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
	for _, n := range []string{
		"installation_tampered:" + id, "installation_tampered:" + id + ":1",
		"installation_tampered:" + id + ":2", "installation_restored:" + id + ":2",
	} {
		_, err := e.db.App.Exec(e.ctx, `INSERT INTO license_history (id, at, event, license_id, notice, details)
VALUES (gen_random_uuid(), now(), 'notice', '', $1, '{}')`, n)
		require.NoError(t, err)
	}
	e.ownerExec("UPDATE license SET installed_at = installed_at + interval '1 day'")
	e.restart()
	e.requireTamperedLock()
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_tampered"), "the forged notices did not suppress the audit")
}

// A notice with a license ID is not an installation notice; it changes nothing either.
func TestInstallationNoticeWithLicenseIDIsIgnored(t *testing.T) {
	e := newEnv(t)
	id := e.installation()
	e.ownerExec(`INSERT INTO license_history (id, at, event, license_id, notice, details)
VALUES (gen_random_uuid(), now(), 'notice', 'LIC-X', $1, '{}')`, "installation_tampered:"+id+":1")
	e.ownerExec("UPDATE license SET installed_at = installed_at + interval '1 day'")
	e.restart()
	assert.Equal(t, []string{"1"}, e.auditEpisodes("license.installation_tampered"))
}
