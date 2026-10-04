//go:build integration

package license_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var uploader = audit.Actor{Type: audit.ActorUser, ID: uuid.MustParse("0190f5a0-0000-7000-8000-000000000001"), Name: "admin"}

type recordingNotifier struct {
	mu    sync.Mutex
	sent  []string
	calls []map[string]string
	fail  error // returned instead of recording, to make the evaluation's transaction fail

	// entered and release hold an evaluation inside its transaction: the notifier signals
	// entered, then waits for release (both nil = never wait).
	entered chan struct{}
	release chan struct{}
}

func (r *recordingNotifier) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	if r.entered != nil {
		r.entered <- struct{}{}
		<-r.release
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.sent = append(r.sent, template)
	r.calls = append(r.calls, params)
	return nil
}

func (r *recordingNotifier) templates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

type env struct {
	t         *testing.T
	ctx       context.Context
	db        *pgtest.DB
	clk       *clock.Fake
	keyring   *secrets.Keyring
	stateDir  string
	buildTime time.Time
	notices   *recordingNotifier
	noMail    bool
	targets   license.TargetCounter
	svc       *license.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(installedAt), keyring: keyring(t, 3),
		stateDir: t.TempDir(), notices: &recordingNotifier{}, targets: license.NoTargets{},
	}
	e.restart()
	return e
}

func (e *env) newService() *license.Service {
	return license.New(license.Config{
		Pool: e.db.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk,
		Keys: licensetest.KeySet(), StateDir: e.stateDir, BuildTime: e.buildTime, Notifier: e.notifier(),
		Targets: e.targets, Log: slog.New(slog.DiscardHandler),
	})
}

// notifier returns the recording notifier, or none when the test runs without email (L-18).
func (e *env) notifier() license.Notifier {
	if e.noMail {
		return nil
	}
	return e.notices
}

// tickAt moves the fake clock to at (counting the time as uptime) and runs the hourly evaluation.
func (e *env) tickAt(at time.Time) {
	e.t.Helper()
	e.clk.Set(at)
	require.NoError(e.t, e.svc.Tick(e.ctx))
}

// restart builds a new Service on the same database, state directory and clock (a process restart).
func (e *env) restart() {
	e.t.Helper()
	e.svc = e.newService()
	require.NoError(e.t, e.svc.Start(e.ctx))
}

func (e *env) installation() string { return e.svc.Snapshot().InstallationID }

func (e *env) payload(id string, from, until time.Time, targets int) license.Payload {
	p := licensetest.Payload(e.installation(), from, until, targets)
	p.LicenseID = id
	return p
}

func (e *env) upload(p license.Payload) (license.UploadResult, error) {
	return e.svc.Install(e.ctx, licensetest.Sign(p), uploader, uuid.Nil)
}

func (e *env) countWhere(table, cond string) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()+" WHERE "+cond).Scan(&n))
	return n
}

func (e *env) auditCount(action string) int {
	return e.countWhere("audit_log", "action = '"+action+"'")
}

func (e *env) state() string {
	e.t.Helper()
	var s string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT state FROM license WHERE id = 1").Scan(&s))
	return s
}

func TestStartCreatesTheInstallationOnce(t *testing.T) {
	e := newEnv(t)
	snap := e.svc.Snapshot()
	require.True(t, snap.Ready)
	id, err := license.ParseInstallationID(snap.InstallationID)
	require.NoError(t, err)
	assert.Equal(t, id, snap.InstallationID)
	assert.True(t, snap.InstalledAt.Equal(installedAt))
	assert.Equal(t, license.PhaseEvaluation, snap.Eval.Phase) // L-01
	assert.Equal(t, 30, snap.Eval.DaysLeft)
	assert.Zero(t, e.countWhere("audit_log", "true"), "first start writes no audit row (the chain starts with setup.admin_created)")

	e.clk.Advance(time.Hour)
	e.restart()
	assert.Equal(t, snap.InstallationID, e.installation(), "the ID is created once")
	assert.True(t, e.svc.Snapshot().InstalledAt.Equal(installedAt))

	var settingRaw []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingRaw))
	fileRaw, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(t, err)
	codec := license.NewHWMCodec(e.keyring)
	for _, raw := range [][]byte{settingRaw, fileRaw} {
		rec, err := codec.Decode(raw)
		require.NoError(t, err)
		assert.True(t, rec.At.Equal(installedAt.Add(time.Hour)), "the time record is written to both stores")
	}
}

// L-05, L-30: a license takes effect at once; the audit trail says so.
func TestUploadActivatesImmediately(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	assert.Equal(t, license.PhaseActive, res.Phase)
	assert.False(t, res.Duplicate)
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
	assert.Equal(t, "active", e.state())
	assert.Equal(t, 1, e.auditCount("license.activated"))
	assert.Equal(t, 1, e.countWhere("license_history", "event = 'installed' AND license_id = 'LIC-A' AND from_state = 'evaluation' AND to_state = 'active'"))
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'license.activated'").Scan(&details))
	assert.Equal(t, "Test Company", details["customer"])
	assert.Equal(t, "10", details["max_targets"])
	assert.Equal(t, licensetest.KeyID, details["key_id"])

	renamed := e.payload("LIC-B", now, now.AddDate(2, 0, 0), 20)
	renamed.Customer = "Yeni Unvan A.Ş." // L-33: the name is informational; the installation ID binds
	_, err = e.upload(renamed)
	require.NoError(t, err)
	assert.Equal(t, 1, e.auditCount("license.renewed"))
	assert.Equal(t, 20, e.svc.Snapshot().Eval.MaxTargets)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'license.renewed'").Scan(&details))
	assert.Equal(t, "Yeni Unvan A.Ş.", details["customer"], "the audit trail shows the name change")
	assert.Empty(t, e.notices.templates(), "an upload is confirmed on the page; no email is queued")
}

// L-40..L-45: rejected uploads are audited and change nothing.
func TestUploadRejections(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	good := licensetest.Sign(e.payload("LIC-B", now, now.AddDate(1, 0, 0), 10))
	other := licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10)

	cases := map[string]struct {
		raw    []byte
		is     error
		action string
	}{
		"edited (L-40)":             {bytes.Replace(good, []byte(`"max_targets": 10`), []byte(`"max_targets": 1000`), 1), license.ErrInvalid, "license.upload.invalid_signature"},
		"garbage (L-41)":            {[]byte("not a license"), license.ErrInvalid, "license.upload.invalid"},
		"unknown key (L-42)":        {licensetest.SignWith(otherKey, "vk-2099-01", e.payload("LIC-C", now, now.AddDate(1, 0, 0), 10)), license.ErrUnknownKey, "license.upload.unknown_key"},
		"other installation (L-43)": {licensetest.Sign(other), license.ErrWrongInstallation, "license.upload.wrong_installation"},
		"newer format (L-45)":       {bytes.Replace(good, []byte("\"format\": 1,\n  \"key_id\""), []byte("\"format\": 99,\n  \"key_id\""), 1), license.ErrUnsupportedFormat, "license.upload.unsupported_format"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.Install(e.ctx, tc.raw, uploader, uuid.Nil)
			require.ErrorIs(t, err, tc.is)
			assert.Equal(t, 1, e.auditCount(tc.action))
			assert.Equal(t, 1, e.countWhere("license_files", "true"), "nothing stored")
			assert.Equal(t, "LIC-A", e.svc.Snapshot().Eval.Key(), "the installed license is untouched")
		})
	}
	_, err = e.svc.Install(e.ctx, licensetest.Sign(other), uploader, uuid.Nil)
	var wi *license.WrongInstallationError
	require.ErrorAs(t, err, &wi)
	assert.Equal(t, license.IDSuffix(e.installation()), wi.Expected)
	assert.Equal(t, license.IDSuffix(other.InstallationID), wi.Got)
	assert.Equal(t, 6, e.countWhere("license_history", "event = 'rejected'"))
}

// §16.3: an older license is refused unless it lasts longer or is a correction (R7).
func TestOlderLicenseIsRefusedUnlessCorrection(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)

	_, err = e.upload(e.payload("LIC-OLD", now.Add(-10*day), now.Add(300*day), 10))
	require.ErrorIs(t, err, license.ErrOlderThanInstalled)
	assert.Equal(t, 1, e.auditCount("license.upload.older_than_installed"))
	assert.Equal(t, "LIC-A", e.svc.Snapshot().Eval.Key())

	_, err = e.upload(e.payload("LIC-LONGER", now.Add(-10*day), now.Add(400*day), 10))
	require.NoError(t, err, "an older issue date with a later valid_until is accepted")

	assert.Equal(t, "LIC-A", e.svc.Snapshot().Eval.Key(), "LIC-A started last, so it stays in force")

	// Issued before LIC-A and shorter: refused unless it is a correction of the license in force.
	correction := e.payload("LIC-FIX", now, now.Add(100*day), 12)
	correction.IssuedAt = now.Add(-20 * day)
	_, err = e.upload(correction)
	require.ErrorIs(t, err, license.ErrOlderThanInstalled)
	correction.Replaces = "LIC-A"
	res, err := e.upload(correction)
	require.NoError(t, err)
	assert.True(t, res.Correction)
	assert.Equal(t, "LIC-FIX", e.svc.Snapshot().Eval.Key())
}

// Uploading the same license again (also reformatted) is reported, not stored twice.
func TestDuplicateUploadIsIdempotent(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	raw := licensetest.Sign(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	_, err := e.svc.Install(e.ctx, raw, uploader, uuid.Nil)
	require.NoError(t, err)
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, raw))
	for _, again := range [][]byte{raw, compact.Bytes()} {
		res, err := e.svc.Install(e.ctx, again, uploader, uuid.Nil)
		require.NoError(t, err)
		assert.True(t, res.Duplicate)
	}
	assert.Equal(t, 1, e.countWhere("license_files", "true"))
	assert.Equal(t, 1, e.auditCount("license.activated"))
}

// L-32 and L-48.
func TestExpiredAndPendingUploads(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.upload(e.payload("LIC-OLD", now.Add(-400*day), now.Add(-3*day), 10))
	require.NoError(t, err)
	assert.True(t, res.AlreadyExpired)
	assert.Equal(t, license.PhaseGrace, res.Phase, "3 days after valid_until")

	res, err = e.upload(e.payload("LIC-NEXT", now.Add(2*day), now.Add(367*day), 20))
	require.NoError(t, err)
	assert.True(t, res.Pending)
	snap := e.svc.Snapshot()
	assert.Equal(t, "LIC-OLD", snap.Eval.Key(), "the previous license continues until the new one starts")
	require.NotNil(t, snap.Eval.Pending)

	d, err := e.svc.Detail(e.ctx)
	require.NoError(t, err)
	require.Len(t, d.Files, 2)
	assert.Equal(t, "pending", d.Files[0].Status)
	assert.Equal(t, "current", d.Files[1].Status)
	require.NotEmpty(t, d.History)
	assert.Equal(t, "renewed", d.History[0].Event)
}

func TestPreviewStoresNothing(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.svc.Preview(e.ctx, licensetest.Sign(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10)))
	require.NoError(t, err)
	assert.Equal(t, "Test Company", res.Payload.Customer)
	assert.Equal(t, license.PhaseActive, res.Phase, "the phase the upload would give")
	assert.Zero(t, e.countWhere("license_files", "true"))
	assert.Zero(t, e.countWhere("audit_log", "true"))
	_, err = e.svc.Preview(e.ctx, []byte("junk"))
	require.ErrorIs(t, err, license.ErrInvalid)
	assert.Zero(t, e.countWhere("audit_log", "true"), "a preview is not an upload")
}

// Review Focus 2: concurrent uploads are serialized by the license row lock.
func TestConcurrentUploadsAreSerialized(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	same := licensetest.Sign(e.payload("LIC-SAME", now, now.AddDate(1, 0, 0), 10))
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.upload(e.payload(fmt.Sprintf("LIC-P-%d", i), now, now.AddDate(1, i, 0), 10))
			errs <- err
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Install(e.ctx, same, uploader, uuid.Nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 9, e.countWhere("license_files", "true"))
	assert.Equal(t, 9, e.countWhere("license_files", "seq BETWEEN 1 AND 9"), "gapless upload order")
	assert.Equal(t, 9, e.countWhere("license_history", "event IN ('installed', 'renewed')"))
	assert.Equal(t, 1, e.auditCount("license.activated"))
	assert.Equal(t, 8, e.auditCount("license.renewed"))
	assert.Equal(t, "active", e.state())
}

// L-49: a stored file edited in the database no longer counts; the previous one (or the
// evaluation) applies and Admins are told.
func TestStoredFileEditedDirectlyIsIgnored(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	_, err = e.upload(e.payload("LIC-B", now, now.AddDate(1, 0, 0), 20))
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file =
		convert_to(replace(convert_from(raw_file, 'UTF8'), '"max_targets": 20', '"max_targets": 2000'), 'UTF8') WHERE seq = 2`)
	require.NoError(t, err)

	e.restart()
	snap := e.svc.Snapshot()
	assert.True(t, snap.Tampered)
	assert.Equal(t, "LIC-A", snap.Eval.Key(), "falls back to the last valid stored license")
	assert.Equal(t, 10, snap.Eval.MaxTargets)
	assert.Contains(t, kinds(snap.Banners(true)), "tampered/danger")
	d, err := e.svc.Detail(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "invalid", d.Files[0].Status)
	assert.Nil(t, d.Files[0].Payload)

	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file = convert_to('{}', 'UTF8') WHERE seq = 1`)
	require.NoError(t, err)
	e.restart()
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase, "no valid file left: the evaluation rules apply")
}

func TestAllowFollowsThePhase(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, e.svc.Allow(license.ClassChange))
	assert.ErrorIs(t, e.svc.Allow(license.ClassUnset), license.ErrUnclassified)

	e.clk.Advance(30 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase)
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.ErrorIs(t, e.svc.Allow(license.ClassReadOnly), license.ErrLocked)
	assert.NoError(t, e.svc.Allow(license.ClassAlways), "sign-in, uploads, backups keep working")

	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	assert.NoError(t, e.svc.Allow(license.ClassChange), "a renewal unlocks at once, without a restart")

	notStarted := e.newService()
	assert.ErrorIs(t, notStarted.Allow(license.ClassChange), license.ErrLocked, "fail closed before Start")
}

type tableCounter struct{}

func (tableCounter) CountTargets(ctx context.Context, q db.Querier) (int, error) {
	var n int
	err := q.QueryRow(ctx, "SELECT count(*) FROM test_targets").Scan(&n)
	return n, err
}

// L-04, L-71, L-74: the limit check and the insert happen in one transaction under a lock.
func TestCheckCanAddTargetIsTransactional(t *testing.T) {
	e := newEnv(t)
	for _, stmt := range []string{
		"CREATE TABLE test_targets (id serial PRIMARY KEY)",
		"GRANT SELECT, INSERT ON test_targets TO alice_app",
		"GRANT USAGE ON SEQUENCE test_targets_id_seq TO alice_app",
		"INSERT INTO test_targets (id) SELECT nextval('test_targets_id_seq') FROM generate_series(1, 4)",
	} {
		_, err := e.db.Owner.Exec(e.ctx, stmt)
		require.NoError(t, err, stmt)
	}
	e.targets = tableCounter{}
	e.restart()

	var wg sync.WaitGroup
	results := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
				if err := e.svc.CheckCanAddTarget(e.ctx, tx); err != nil {
					return err
				}
				_, err := tx.Exec(e.ctx, "INSERT INTO test_targets DEFAULT VALUES")
				return err
			})
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
			continue
		}
		var tl *license.TargetLimitError
		require.ErrorAs(t, err, &tl)
		assert.Equal(t, license.TargetLimitError{Max: 5, Used: 5}, *tl)
	}
	assert.Equal(t, 1, ok, "exactly one of the concurrent adds wins")
	assert.Equal(t, 5, e.countWhere("test_targets", "true"), "the count never exceeds the limit")

	e.clk.Advance(31 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	err := db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.svc.CheckCanAddTarget(e.ctx, tx) })
	assert.ErrorIs(t, err, license.ErrLocked)
}

// L-53, L-54, L-55: which time record wins at start, and what is audited.
func TestStartChoosesTheTimeRecord(t *testing.T) {
	t.Run("a damaged settings record is ignored and audited (L-54)", func(t *testing.T) {
		e := newEnv(t)
		e.clk.Advance(5 * day)
		require.NoError(t, e.svc.Tick(e.ctx))
		_, err := e.db.Owner.Exec(e.ctx, `UPDATE settings SET value = jsonb_set(value, '{mac}', '"AAAA"') WHERE key = 'time.hwm'`)
		require.NoError(t, err)
		e.clk.Set(installedAt) // the clock is also set back
		e.restart()
		assert.Equal(t, 1, e.auditCount("clock.hwm_damaged"))
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(5*day)), "the file record still holds")
	})
	t.Run("a replayed older record loses (L-55)", func(t *testing.T) {
		e := newEnv(t)
		old, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
		require.NoError(t, err)
		e.clk.Advance(10 * day)
		require.NoError(t, e.svc.Tick(e.ctx))
		require.NoError(t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), old, 0o600))
		e.clk.Set(installedAt)
		e.restart()
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(10*day)))
		assert.Zero(t, e.auditCount("clock.hwm_damaged"), "an old record is valid, just older")
	})
	t.Run("both missing: time reference reset, build time is the floor (L-53)", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, `DELETE FROM settings WHERE key = 'time.hwm'`)
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
		e.buildTime = installedAt.Add(3 * day)
		e.restart()
		assert.Equal(t, 1, e.auditCount("clock.time_reference_reset"))
		assert.Equal(t, 1, e.countWhere("license_history", "event = 'clock_anomaly'"))
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(3*day)), "max(system clock, build time)")
	})
}

func TestInspectChangesNothing(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.stateDir, license.HWMFileName)
	before, err := os.ReadFile(file)
	require.NoError(t, err)
	var settingBefore []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingBefore))

	e.clk.Advance(40 * day)
	snap, err := e.newService().Inspect(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase)

	after, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	var settingAfter []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingAfter))
	assert.JSONEq(t, string(settingBefore), string(settingAfter))

	blank := pgtest.New(t)
	_, err = license.New(license.Config{Pool: blank.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk,
		Keys: licensetest.KeySet()}).Inspect(e.ctx)
	assert.ErrorIs(t, err, license.ErrNoInstallation)
}

func TestInstalledReportsAnyStoredLicense(t *testing.T) {
	e := newEnv(t)
	ok, err := e.svc.Installed(e.ctx, e.db.App)
	require.NoError(t, err)
	assert.False(t, ok)
	now := e.clk.Now()
	_, err = e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	ok, err = e.svc.Installed(e.ctx, e.db.App)
	require.NoError(t, err)
	assert.True(t, ok)

	// B4: it reads through the caller's transaction (here it sees the transaction's own row).
	blank := newEnv(t)
	err = db.InTx(e.ctx, blank.db.App, func(tx pgx.Tx) error {
		_, err := tx.Exec(e.ctx, `INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at)
VALUES (gen_random_uuid(), 1, '\x01', '{}', now())`)
		require.NoError(t, err)
		ok, err := blank.svc.Installed(e.ctx, tx)
		require.NoError(t, err)
		assert.True(t, ok)
		return errors.New("roll back")
	})
	require.Error(t, err)
}

// Pre-flight ruling (Task 8): an upload reports the phase the gate enforces, also when a
// correction license accepts a held clock jump (L-61).
func TestCorrectionDuringAHeldJumpReportsTheGatePhase(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	require.NotNil(t, e.svc.Snapshot().Reading.Jump, "the jump is held")
	require.NoError(t, e.svc.Allow(license.ClassChange), "license time stays where it was before the jump")

	fix := e.payload("LIC-FIX", now, now.Add(150*day), 10)
	fix.Replaces = "LIC-A"
	res, err := e.upload(fix)
	require.NoError(t, err)
	assert.Equal(t, license.PhaseLocked, res.Phase, "the correction confirms the new time: 50 days after valid_until")
	assert.Equal(t, res.Phase, e.svc.Snapshot().Eval.Phase)
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked, "the reported phase is the one the gate enforces")
	assert.Nil(t, e.svc.Snapshot().Reading.Jump)
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	assert.Equal(t, "locked", e.state())
}

func (e *env) auditDetails(action string) map[string]string {
	e.t.Helper()
	var d map[string]string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = $1", action).Scan(&d))
	return d
}

func (e *env) saveHWM(rec license.HWMRecord, file bool) {
	e.t.Helper()
	raw, err := license.NewHWMCodec(e.keyring).Encode(rec)
	require.NoError(e.t, err)
	if file {
		require.NoError(e.t, license.FileHWMStore{Path: filepath.Join(e.stateDir, license.HWMFileName)}.Save(e.ctx, raw))
		return
	}
	require.NoError(e.t, license.SettingsHWMStore{Q: e.db.App, Clock: e.clk}.Save(e.ctx, raw))
}

func (e *env) loadHWM(file bool) license.HWMRecord {
	e.t.Helper()
	var raw []byte
	var err error
	if file {
		raw, err = license.FileHWMStore{Path: filepath.Join(e.stateDir, license.HWMFileName)}.Load(e.ctx)
	} else {
		raw, err = license.SettingsHWMStore{Q: e.db.App, Clock: e.clk}.Load(e.ctx)
	}
	require.NoError(e.t, err)
	rec, err := license.NewHWMCodec(e.keyring).Decode(raw)
	require.NoError(e.t, err)
	return rec
}

// Task 6 carry-in: an unreadable time record file (a dangling symlink) is one damaged copy;
// the settings copy is used and the next save replaces the link with a valid file.
func TestStartFallsBackWhenTheTimeFileIsUnreadable(t *testing.T) {
	e := newEnv(t)
	e.clk.Advance(5 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	file := filepath.Join(e.stateDir, license.HWMFileName)
	require.NoError(t, os.Remove(file))
	require.NoError(t, os.Symlink(filepath.Join(e.stateDir, "missing"), file))
	e.clk.Set(installedAt)

	e.restart()
	assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(5*day)), "the settings record holds")
	assert.Equal(t, map[string]string{"problem": "hwm_damaged", "stores": "file"}, e.auditDetails("clock.hwm_damaged"))
	assert.Zero(t, e.auditCount("clock.time_reference_reset"))
	info, err := os.Lstat(file)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
	assert.True(t, e.loadHWM(true).At.Equal(installedAt.Add(5*day)))
}

// Task 6 carry-in: the larger valid record wins, and the next record's sequence is higher
// than both copies, so neither older copy can win a later comparison.
func TestStartPrefersTheLaterRecordAndOutnumbersBoth(t *testing.T) {
	e := newEnv(t)
	e.saveHWM(license.HWMRecord{At: installedAt.Add(10 * day), Seq: 50}, false)
	e.saveHWM(license.HWMRecord{At: installedAt.Add(20 * day), Seq: 3}, true)
	e.restart()
	assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(20*day)))
	for _, file := range []bool{false, true} {
		rec := e.loadHWM(file)
		assert.True(t, rec.At.Equal(installedAt.Add(20*day)))
		assert.Equal(t, uint64(51), rec.Seq)
	}

	e.saveHWM(license.HWMRecord{At: installedAt.Add(30 * day), Seq: 60}, false)
	e.saveHWM(license.HWMRecord{At: installedAt.Add(30 * day), Seq: 90}, true)
	e.restart()
	assert.Equal(t, uint64(91), e.loadHWM(false).Seq, "equal times: the higher sequence")
	assert.Zero(t, e.auditCount("clock.hwm_damaged"))
}

// Task 6 carry-in: the settings store on a real database.
func TestSettingsHWMStore(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	st := license.SettingsHWMStore{Q: d.App, Clock: clock.NewFake(installedAt)}
	assert.Equal(t, "settings", st.Name())
	raw, err := st.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, raw, "no record yet")

	codec := license.NewHWMCodec(keyring(t, 3))
	for _, rec := range []license.HWMRecord{{At: installedAt, Seq: 7}, {At: installedAt.Add(day), Seq: 8}} {
		enc, err := codec.Encode(rec)
		require.NoError(t, err)
		require.NoError(t, st.Save(ctx, enc))
		raw, err := st.Load(ctx)
		require.NoError(t, err)
		got, err := codec.Decode(raw)
		require.NoError(t, err)
		assert.Equal(t, rec, got)
	}

	closed := pgtest.New(t)
	closed.App.Close()
	_, err = license.SettingsHWMStore{Q: closed.App, Clock: clock.NewFake(installedAt)}.Load(ctx)
	assert.Error(t, err)
}

// Both copies damaged: both findings are audited and time starts from max(system clock, build time).
func TestStartWithBothTimeRecordsDamaged(t *testing.T) {
	e := newEnv(t)
	_, err := e.db.Owner.Exec(e.ctx, `UPDATE settings SET value = jsonb_set(value, '{mac}', '"AAAA"') WHERE key = 'time.hwm'`)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), []byte("junk"), 0o600))
	e.clk.Advance(2 * day)
	e.restart()
	assert.Equal(t, map[string]string{"problem": "hwm_damaged", "stores": "settings,file"}, e.auditDetails("clock.hwm_damaged"))
	assert.Equal(t, 1, e.auditCount("clock.time_reference_reset"))
	assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(2*day)), "the system clock is later than the build time")
}

// A damaged installation row stops the start instead of evaluating with a wrong ID or time.
func TestStartRefusesADamagedInstallation(t *testing.T) {
	e := newEnv(t)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE license SET installation_id = lower(installation_id)")
	require.NoError(t, err)
	require.Error(t, e.newService().Start(e.ctx), "only the canonical form is accepted")
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE license SET installation_id = 'ALICE-0000'")
	require.NoError(t, err)
	require.Error(t, e.newService().Start(e.ctx))
}

// §16.5: the time record is also saved on a graceful shutdown.
func TestShutdownSavesTheTimeRecord(t *testing.T) {
	e := newEnv(t)
	e.clk.Advance(2 * time.Hour)
	require.NoError(t, e.svc.Shutdown(e.ctx))
	for _, file := range []bool{false, true} {
		rec := e.loadHWM(file)
		assert.True(t, rec.At.Equal(installedAt.Add(2*time.Hour)))
		assert.Positive(t, rec.Seq)
	}
}

// A time record file that cannot be written (here: a directory in its place) is logged, not
// fatal: the settings copy still protects the license.
func TestTickSurvivesAnUnwritableTimeFile(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.stateDir, license.HWMFileName)
	require.NoError(t, os.Remove(file))
	require.NoError(t, os.MkdirAll(filepath.Join(file, "blocker"), 0o700))
	e.clk.Advance(3 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.True(t, e.loadHWM(false).At.Equal(installedAt.Add(3*day)), "the settings copy is saved")
}

// Task 16 ruling: a full reset waits for an evaluation that is in flight, so the evaluation
// cannot write the old time record back after the reset removed it.
func TestRestartWaitsForAnInFlightTick(t *testing.T) {
	e := newEnv(t)
	oldInstallation := e.installation()
	e.clk.Set(installedAt.Add(23 * day)) // an evaluation warning is due
	e.notices.entered, e.notices.release = make(chan struct{}), make(chan struct{})
	tickErr := make(chan error, 1)
	go func() { tickErr <- e.svc.Tick(e.ctx) }()
	<-e.notices.entered // the tick is inside its transaction

	var called atomic.Bool
	var savedBy time.Time
	restartErr := make(chan error, 1)
	go func() {
		restartErr <- e.svc.Restart(e.ctx, func(ctx context.Context) error {
			called.Store(true)
			savedBy = e.loadHWM(true).At // what the finished tick left behind
			// As the e2e reset: every trace of the installation goes, the audit log included
			// (AUD-18: an audit event of a started installation shows that one existed).
			for _, stmt := range []string{"ALTER TABLE audit_log DISABLE TRIGGER USER",
				"TRUNCATE license, license_files, license_history, settings, audit_log", "ALTER TABLE audit_log ENABLE TRIGGER USER"} {
				if _, err := e.db.Owner.Exec(ctx, stmt); err != nil {
					return err
				}
			}
			e.clk.Set(installedAt)
			return os.Remove(filepath.Join(e.stateDir, license.HWMFileName))
		})
	}()
	time.Sleep(200 * time.Millisecond)
	assert.False(t, called.Load(), "the reset waits while a tick holds the evaluation lock")

	close(e.notices.release)
	require.NoError(t, <-tickErr)
	require.NoError(t, <-restartErr)
	assert.True(t, called.Load())
	assert.False(t, savedBy.Before(installedAt.Add(23*day)), "the tick saved its record before the reset ran")
	assert.True(t, e.loadHWM(true).At.Before(installedAt.Add(day)), "the old time record did not come back")
	assert.NotEqual(t, oldInstallation, e.installation(), "a fresh installation exists after the reset")
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase, "with a fresh evaluation")
	assert.Equal(t, 1, e.countWhere("license", "true"))
	assert.True(t, e.svc.Snapshot().Ready)
}

func TestRestartKeepsTheStateWhenTheResetFails(t *testing.T) {
	e := newEnv(t)
	before := e.installation()
	require.Error(t, e.svc.Restart(e.ctx, func(context.Context) error { return errors.New("boom") }))
	assert.Equal(t, before, e.installation())
}
