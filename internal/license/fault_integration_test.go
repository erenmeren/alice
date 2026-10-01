//go:build integration

package license_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
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
	"alice/internal/testutil/pgtest"
)

// Fault injection (Task 22, R36 item 15): the database refuses one chosen statement, and the
// service must fail that operation as a whole — nothing half-written, nothing published —
// and work normally once the fault is gone.

const injectedFault = "injected fault"

// failOn makes the database raise an error for every row of op (INSERT, UPDATE or DELETE)
// on table that matches when (a trigger WHEN condition over OLD/NEW; "" = every row). The
// returned function removes the fault.
func (e *env) failOn(table, op, when string) func() {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, `CREATE OR REPLACE FUNCTION alice_test_fault() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault'; END $$`)
	require.NoError(e.t, err)
	name := pgx.Identifier{"alice_test_fault_" + table}.Sanitize()
	cond := ""
	if when != "" {
		cond = " WHEN (" + when + ")"
	}
	_, err = e.db.Owner.Exec(e.ctx, "CREATE TRIGGER "+name+" BEFORE "+op+" ON "+pgx.Identifier{table}.Sanitize()+
		" FOR EACH ROW"+cond+" EXECUTE FUNCTION alice_test_fault()")
	require.NoError(e.t, err)
	return func() {
		_, err := e.db.Owner.Exec(e.ctx, "DROP TRIGGER "+name+" ON "+pgx.Identifier{table}.Sanitize())
		require.NoError(e.t, err)
	}
}

// revoke takes a privilege of the application role away for the rest of the test.
func (e *env) revoke(privilege, table string) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "REVOKE "+privilege+" ON "+pgx.Identifier{table}.Sanitize()+" FROM alice_app")
	require.NoError(e.t, err)
}

func requireInjected(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Contains(t, err.Error(), injectedFault)
}

type failingCounter struct{}

func (failingCounter) CountTargets(context.Context, db.Querier) (int, error) {
	return 0, errors.New("target count unavailable")
}

// Every write of an evaluation is part of one transaction: whichever statement fails, the
// state column, the history, the audit log and the published snapshot stay as they were,
// and the next evaluation does the whole work once.
func TestTickFaultsChangeNothing(t *testing.T) {
	type fault struct{ table, op, when string }
	cases := map[string]struct {
		setup  func(e *env) // brings the service to the edge of the event; the failing Tick follows
		fault  fault
		silent bool // the event writes no history or audit row (only the time record)
	}{
		"state change: license row": {
			setup: func(e *env) { e.clk.Set(installedAt.Add(31 * day)) },
			fault: fault{"license", "UPDATE", "NEW.state IS DISTINCT FROM OLD.state"},
		},
		"state change: history": {
			setup: func(e *env) { e.clk.Set(installedAt.Add(31 * day)) },
			fault: fault{"license_history", "INSERT", "NEW.event = 'state_change'"},
		},
		"state change: audit": {
			setup: func(e *env) { e.clk.Set(installedAt.Add(31 * day)) },
			fault: fault{"audit_log", "INSERT", ""},
		},
		"time record": {
			setup:  func(e *env) { e.clk.Advance(time.Hour) },
			fault:  fault{"settings", "UPDATE", ""},
			silent: true,
		},
		"clock set back: history": {
			setup: func(e *env) { e.tickAt(installedAt.Add(10 * day)); e.clk.JumpWall(-5 * day) },
			fault: fault{"license_history", "INSERT", "NEW.notice LIKE 'clock_behind:%'"},
		},
		"forward jump: license row": {
			setup: func(e *env) { e.tickAt(installedAt.Add(time.Hour)); e.clk.JumpWall(200 * day) },
			fault: fault{"license", "UPDATE", "NEW.clock_jump IS NOT NULL"},
		},
		"forward jump: history": {
			setup: func(e *env) { e.tickAt(installedAt.Add(time.Hour)); e.clk.JumpWall(200 * day) },
			fault: fault{"license_history", "INSERT", "NEW.details->>'problem' = 'forward_jump'"},
		},
		"jump cleared: license row": {
			setup: func(e *env) {
				e.tickAt(installedAt.Add(time.Hour))
				e.clk.JumpWall(200 * day)
				require.NoError(e.t, e.svc.Tick(e.ctx))
				e.clk.JumpWall(-200 * day)
				e.clk.Advance(time.Hour)
			},
			fault: fault{"license", "UPDATE", "NEW.clock_jump IS NULL AND OLD.clock_jump IS NOT NULL"},
		},
		"jump cleared: history": {
			setup: func(e *env) {
				e.tickAt(installedAt.Add(time.Hour))
				e.clk.JumpWall(200 * day)
				require.NoError(e.t, e.svc.Tick(e.ctx))
				e.clk.JumpWall(-200 * day)
				e.clk.Advance(time.Hour)
			},
			fault: fault{"license_history", "INSERT", "NEW.details->>'problem' = 'jump_cleared'"},
		},
		"tampered file: history": {
			setup: func(e *env) {
				now := e.clk.Now()
				_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
				require.NoError(e.t, err)
				_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file =
					convert_to(replace(convert_from(raw_file, 'UTF8'), 'Test Company', 'Evil Company'), 'UTF8')`)
				require.NoError(e.t, err)
				e.clk.Advance(time.Hour)
			},
			fault: fault{"license_history", "INSERT", "NEW.notice LIKE 'tampered:%'"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e)
			before := e.svc.Snapshot()
			history, audits, state := e.countWhere("license_history", "true"), e.countWhere("audit_log", "true"), e.state()

			undo := e.failOn(tc.fault.table, tc.fault.op, tc.fault.when)
			requireInjected(t, e.svc.Tick(e.ctx))
			assert.Equal(t, before, e.svc.Snapshot(), "nothing is published")
			assert.Equal(t, history, e.countWhere("license_history", "true"))
			assert.Equal(t, audits, e.countWhere("audit_log", "true"))
			assert.Equal(t, state, e.state())

			undo()
			require.NoError(t, e.svc.Tick(e.ctx), "the next evaluation succeeds")
			if tc.silent {
				return
			}
			assert.Greater(t, e.countWhere("license_history", "true")+e.countWhere("audit_log", "true"), history+audits,
				"and records what the failed one could not")
		})
	}
}

// A failed upload stores nothing and changes nothing; the same file installs once the fault is gone.
func TestUploadFaultsStoreNothing(t *testing.T) {
	cases := map[string]struct{ table, op, when string }{
		"file":          {"license_files", "INSERT", ""},
		"history":       {"license_history", "INSERT", "NEW.event IN ('installed', 'renewed')"},
		"license row":   {"license", "UPDATE", ""},
		"audit":         {"audit_log", "INSERT", "NEW.action = 'license.renewed'"},
		"jump accepted": {"audit_log", "INSERT", "NEW.action = 'clock.jump_accepted'"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			now := e.clk.Now()
			_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
			require.NoError(t, err)
			e.clk.Advance(time.Hour)
			require.NoError(t, e.svc.Tick(e.ctx))
			e.clk.JumpWall(200 * day) // held: a correction license accepts it
			require.NoError(t, e.svc.Tick(e.ctx))
			jumped := e.clk.Now()
			fix := e.payload("LIC-FIX", jumped.Add(-time.Hour), jumped.Add(365*day), 10)
			fix.Replaces, fix.Features = "LIC-A", []string{"future-feature"}

			before := e.svc.Snapshot()
			undo := e.failOn(tc.table, tc.op, tc.when)
			_, err = e.upload(fix)
			requireInjected(t, err)
			assert.Equal(t, 1, e.countWhere("license_files", "true"))
			assert.Zero(t, e.countWhere("license_history", "license_id = 'LIC-FIX'"))
			assert.Equal(t, 1, e.countWhere("license", "clock_jump IS NOT NULL"), "the hold stays")
			assert.Equal(t, before, e.svc.Snapshot())

			undo()
			_, err = e.upload(fix)
			require.NoError(t, err)
			assert.Equal(t, "LIC-FIX", e.svc.Snapshot().Eval.Key())
			assert.Nil(t, e.svc.Snapshot().Reading.Jump)
			assert.Equal(t, "future-feature", e.auditDetails("license.renewed")["features"], "unknown features are listed (L-47)")
		})
	}
}

// A refused upload is still refused with its own reason when recording the refusal fails.
func TestRejectionIsReportedWhenItsRecordFails(t *testing.T) {
	e := newEnv(t)
	e.failOn("license_history", "INSERT", "NEW.event = 'rejected'")
	_, err := e.svc.Install(e.ctx, []byte("not a license"), uploader, uuid.Nil)
	require.ErrorIs(t, err, license.ErrInvalid)
	assert.Zero(t, e.auditCount("license.upload.invalid"), "the audit row shares the failed transaction")
}

// The uploading user is recorded with the file.
func TestUploadRecordsTheUploader(t *testing.T) {
	e := newEnv(t)
	user := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, email, role, password_hash, locale, created_at, updated_at)
VALUES ($1, 'uploader', 'Uploader', 'uploader@example.com', 'admin', 'x', 'en', now(), now())`, user)
	require.NoError(t, err)
	now := e.clk.Now()
	_, err = e.svc.Install(e.ctx, licensetest.Sign(e.payload("LIC-A", now, now.Add(100*day), 10)), uploader, user)
	require.NoError(t, err)
	assert.Equal(t, 1, e.countWhere("license_files", "uploaded_by = '"+user.String()+"'"))
}

// Start fails rather than run on a time record whose problems it cannot record; the next
// start records them.
func TestStartFaultsWhileRecordingTimeRecordProblems(t *testing.T) {
	cases := map[string]struct {
		damage func(e *env)
		when   string
		table  string
	}{
		"damaged copy": {
			damage: func(e *env) {
				require.NoError(e.t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), []byte("junk"), 0o600))
			},
			table: "license_history", when: "NEW.details->>'problem' = 'hwm_damaged'",
		},
		"both copies lost": {
			damage: func(e *env) {
				require.NoError(e.t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
				_, err := e.db.Owner.Exec(e.ctx, "DELETE FROM settings WHERE key = 'time.hwm'")
				require.NoError(e.t, err)
			},
			table: "license_history", when: "NEW.details->>'problem' = 'time_reference_reset'",
		},
		"audit": {
			damage: func(e *env) {
				require.NoError(e.t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), []byte("junk"), 0o600))
			},
			table: "audit_log", when: "NEW.action = 'clock.hwm_damaged'",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			tc.damage(e)
			undo := e.failOn(tc.table, "INSERT", tc.when)
			requireInjected(t, e.newService().Start(e.ctx))
			assert.Zero(t, e.countWhere("license_history", "event = 'clock_anomaly'"))
			undo()
			e.restart()
			assert.Equal(t, 1, e.countWhere("license_history", "event = 'clock_anomaly'"))
		})
	}
}

// Start on a fresh database fails when the installation cannot be created, or when the
// clock is not set at all; it never evaluates without an installation.
func TestStartFaultsOnAFreshDatabase(t *testing.T) {
	t.Run("insert refused", func(t *testing.T) {
		e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(installedAt), keyring: keyring(t, 3),
			stateDir: t.TempDir(), notices: &recordingNotifier{}, targets: license.NoTargets{}}
		e.failOn("license", "INSERT", "")
		svc := e.newService()
		requireInjected(t, svc.Start(e.ctx))
		assert.False(t, svc.Snapshot().Ready)
		assert.ErrorIs(t, svc.Allow(license.ClassChange), license.ErrLocked, "fails closed")
	})
	t.Run("clock not set", func(t *testing.T) {
		e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(time.Time{}), keyring: keyring(t, 3),
			stateDir: t.TempDir(), notices: &recordingNotifier{}, targets: license.NoTargets{}}
		require.ErrorContains(t, e.newService().Start(e.ctx), "clock is not set")
		assert.Zero(t, e.countWhere("license", "true"))
	})
}

// A build without any vendor key still starts and runs the evaluation (R36 item 1); it logs
// an error that names the vendor guide, and refuses every upload as an unknown key.
func TestStartWithoutVendorKeys(t *testing.T) {
	e := newEnv(t)
	var logs bytes.Buffer // Start logs from this goroutine only
	svc := license.New(license.Config{
		Pool: e.db.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk,
		StateDir: e.stateDir, Log: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	require.NoError(t, svc.Start(e.ctx))
	assert.Contains(t, logs.String(), "docs/vendor/licensing-vendor.md")
	assert.Equal(t, license.PhaseEvaluation, svc.Snapshot().Eval.Phase)
	now := e.clk.Now()
	_, err := svc.Install(e.ctx, licensetest.Sign(e.payload("LIC-A", now, now.Add(100*day), 10)), uploader, uuid.Nil)
	require.ErrorIs(t, err, license.ErrUnknownKey)
}

// Reads and evaluations report database failures instead of answering from partial data.
func TestReadFaults(t *testing.T) {
	t.Run("license files unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.revoke("SELECT", "license_files")
		_, err := e.svc.Installed(e.ctx)
		require.Error(t, err)
		_, err = e.svc.Detail(e.ctx)
		require.Error(t, err)
		_, err = e.svc.Inspect(e.ctx)
		require.Error(t, err)
		require.Error(t, e.svc.Tick(e.ctx))
	})
	t.Run("history unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.revoke("SELECT", "license_history")
		_, err := e.svc.Detail(e.ctx)
		require.ErrorContains(t, err, "permission denied")
	})
	t.Run("history details damaged", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO license_history (id, at, event, details) VALUES ($1, now(), 'clock_anomaly', '[1]')`,
			uuid.Must(uuid.NewV7()))
		require.NoError(t, err)
		_, err = e.svc.Detail(e.ctx)
		require.ErrorContains(t, err, "read license history")
	})
	t.Run("time record unreadable", func(t *testing.T) {
		e := newEnv(t)
		e.revoke("SELECT", "settings")
		_, err := e.svc.Inspect(e.ctx)
		require.Error(t, err)
		require.Error(t, e.newService().Start(e.ctx))
	})
	t.Run("time record unwritable", func(t *testing.T) {
		e := newEnv(t)
		e.failOn("settings", "UPDATE", "")
		e.clk.Advance(time.Hour)
		requireInjected(t, e.svc.Shutdown(e.ctx))
	})
	t.Run("installation removed", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, "DELETE FROM license")
		require.NoError(t, err)
		require.ErrorIs(t, e.svc.Tick(e.ctx), license.ErrNoInstallation)
		require.ErrorIs(t, e.svc.Shutdown(e.ctx), license.ErrNoInstallation)
		_, err = e.svc.Inspect(e.ctx)
		require.ErrorIs(t, err, license.ErrNoInstallation)
		now := e.clk.Now()
		_, err = e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
		require.ErrorIs(t, err, license.ErrNoInstallation)
	})
	t.Run("installation time damaged", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE license SET installed_at = '0001-01-01T00:00:00Z'")
		require.NoError(t, err)
		require.ErrorContains(t, e.newService().Start(e.ctx), "installation time is damaged")
	})
	t.Run("database gone", func(t *testing.T) {
		e := newEnv(t)
		ctx, cancel := context.WithCancel(e.ctx)
		cancel()
		_, err := e.svc.Inspect(ctx)
		require.ErrorIs(t, err, context.Canceled)
	})
}

// Before Start, nothing can be checked against the installation, and Detail has nothing to show.
func TestServiceBeforeStart(t *testing.T) {
	e := newEnv(t)
	svc := e.newService()
	_, err := svc.Preview(e.ctx, licensetest.Sign(e.payload("LIC-A", e.clk.Now(), e.clk.Now().Add(day), 10)))
	require.ErrorIs(t, err, license.ErrNoInstallation)
	_, err = svc.Detail(e.ctx)
	require.ErrorIs(t, err, license.ErrNoInstallation)
}

// A target counter that fails stops the evaluation, the preview, the upload and the target
// check: Alice never assumes zero targets.
func TestTargetCountFaults(t *testing.T) {
	e := newEnv(t)
	e.targets = failingCounter{}
	require.ErrorContains(t, e.newService().Start(e.ctx), "count targets")

	// A started service whose counter then fails.
	flaky := &switchCounter{}
	e.targets = flaky
	e.restart()
	flaky.fail = true
	now := e.clk.Now()
	raw := licensetest.Sign(e.payload("LIC-A", now, now.Add(100*day), 10))
	_, err := e.svc.Preview(e.ctx, raw)
	require.ErrorContains(t, err, "count targets")
	_, err = e.svc.Install(e.ctx, raw, uploader, uuid.Nil)
	require.ErrorContains(t, err, "count targets")
	_, err = e.svc.Inspect(e.ctx)
	require.ErrorContains(t, err, "count targets")
	err = db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.svc.CheckCanAddTarget(e.ctx, tx) })
	require.ErrorContains(t, err, "count targets")
	assert.Zero(t, e.countWhere("license_files", "true"))
}

// CheckCanAddTarget reports a transaction that can no longer take the target lock.
func TestCheckCanAddTargetInABrokenTransaction(t *testing.T) {
	e := newEnv(t)
	err := db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, _ = tx.Exec(e.ctx, "SELECT 1/0")
		return e.svc.CheckCanAddTarget(e.ctx, tx)
	})
	require.ErrorContains(t, err, "lock the target count")
}

type switchCounter struct{ fail bool }

func (c *switchCounter) CountTargets(context.Context, db.Querier) (int, error) {
	if c.fail {
		return 0, errors.New("target count unavailable")
	}
	return 0, nil
}

// hookCounter counts n targets and runs during once, the first time it counts.
type hookCounter struct {
	n      int
	during func()
}

func (c *hookCounter) CountTargets(context.Context, db.Querier) (int, error) {
	if f := c.during; f != nil {
		c.during = nil
		f()
	}
	return c.n, nil
}

// B3: CheckCanAddTarget decides from one evaluation. When the license locks while the
// targets are counted, the lock check and the limit come from the same (new) state, so a
// target is never added in lock because the lock check saw the state before.
func TestCheckCanAddTargetDecidesFromOneEvaluation(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(10*day), 10))
	require.NoError(t, err)
	counter := &hookCounter{n: 7}
	e.targets = counter
	e.restart()
	require.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)

	counter.during = func() { e.tickAt(now.Add(10*day + license.GracePeriod + time.Hour)) } // locks
	err = db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.svc.CheckCanAddTarget(e.ctx, tx) })
	require.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, license.PhaseLocked, e.svc.Snapshot().Eval.Phase)
}
