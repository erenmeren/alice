//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// dbFaults makes the database refuse writes to a table while the table is named in test_faults (a
// fault of the database itself, not a guard: every store path must fail cleanly and write nothing).
func (e *env) dbFaults() func(table string, on bool) {
	e.t.Helper()
	for _, sql := range []string{
		"CREATE TABLE test_faults (name text PRIMARY KEY)",
		`CREATE FUNCTION test_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.test_faults WHERE name = TG_TABLE_NAME) THEN
        RAISE EXCEPTION 'test fault on %', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END $$`,
	} {
		_, err := e.db.Owner.Exec(e.ctx, sql)
		require.NoError(e.t, err)
	}
	for _, table := range []string{"rotation_steps", "rotations", "rotation_locations", "audit_log", "ssh_keys", "rotation_policies"} {
		_, err := e.db.Owner.Exec(e.ctx, "CREATE TRIGGER test_fault BEFORE INSERT OR UPDATE ON "+table+" FOR EACH ROW EXECUTE FUNCTION test_fault()")
		require.NoError(e.t, err)
	}
	return func(table string, on bool) {
		e.t.Helper()
		var err error
		if on {
			_, err = e.db.Owner.Exec(e.ctx, "INSERT INTO test_faults VALUES ($1)", table)
		} else {
			_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM test_faults WHERE name = $1", table)
		}
		require.NoError(e.t, err)
	}
}

// Each step of a run's life fails cleanly on a database failure of each table it writes, and then
// succeeds: nothing half-written blocks the next attempt.
func TestEveryStepFailsCleanlyOnADatabaseFault(t *testing.T) {
	e := newEnv(t)
	fault := e.dbFaults()
	try := func(name string, step func() error) {
		t.Helper()
		// The tables most steps write first; a step stops at the first table it does not touch.
		for _, table := range []string{"rotation_steps", "audit_log", "rotations", "rotation_locations", "ssh_keys", "rotation_policies"} {
			fault(table, true)
			err := step() // may or may not touch the table
			fault(table, false)
			if err == nil {
				return // the step did not touch that table and is done
			}
		}
		require.NoError(t, step(), name)
	}
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 1, 24)
	var pv sshkeys.Preview
	try("preview", func() (err error) { pv, err = e.svc.Preview(e.ctx, e.admin, p.ID); return err })
	var r sshkeys.Rotation
	try("run now", func() (err error) {
		r, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
		if err != nil {
			// a run Run now created and could not start is cancelled: preview again for the next try
			pv, _ = e.svc.Preview(e.ctx, e.admin, p.ID)
		}
		return err
	})
	loc := r.Locations[0].ID
	try("begin add", func() error { _, err := e.svc.BeginAdd(e.claimed(), loc); return err })
	try("finish add", func() error {
		err := e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 1})
		if err != nil && e.locState(r, "deploy") == "added" {
			return nil
		}
		return err
	})
	try("verify", func() error {
		return e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted})
	})
	try("advance to overlap", func() error { return e.svc.Advance(e.ctx, r.ID) })
	require.Equal(t, "overlap", e.run(r.ID).Status)
	e.clock.Advance(24 * time.Hour)
	e.gate.lock()
	try("pause", func() error { return e.svc.Advance(e.ctx, r.ID) })
	require.True(t, e.run(r.ID).PausedLicense)
	e.gate.unlock()
	try("renotify", func() error { return e.svc.Advance(e.ctx, r.ID) })
	try("continue", func() error {
		err := e.svc.Continue(e.ctx, e.admin, r.ID)
		if err != nil && !e.run(r.ID).PausedLicense {
			return nil
		}
		return err
	})
	try("advance to removing", func() error { return e.svc.Advance(e.ctx, r.ID) })
	require.Equal(t, "removing_old", e.run(r.ID).Status)
	e.clock.Advance(time.Minute)
	try("reverify", func() error {
		return e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted})
	})
	try("begin remove", func() error { _, err := e.svc.BeginRemove(e.claimed(), loc); return err })
	try("finish remove", func() error {
		return e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Removed: 1,
			Res: providers.AuthKeyResult{Removed: 1}})
	})
	try("complete", func() error { return e.svc.Advance(e.ctx, r.ID) })
	assert.Equal(t, "completed", e.run(r.ID).Status)

	// The rollback side.
	k2 := e.deployed("ci2", e.server("web-02"), "deploy")
	p2 := e.policy(k2.ID, 90, 7, 24)
	r2 := e.runNow(p2)
	loc2 := r2.Locations[0].ID
	e.drive(loc2, providers.KeyLoginRefused)
	try("roll back", func() error { return e.svc.Advance(e.ctx, r2.ID) })
	try("begin undo", func() error { _, err := e.svc.BeginUndo(e.claimed(), loc2); return err })
	try("finish undo", func() error {
		return e.svc.FinishUndo(e.claimed(), e.jobActor(), loc2, sshkeys.UndoRecord{Definite: true})
	})
	try("abort", func() error { return e.svc.Advance(e.ctx, r2.ID) })
	assert.Equal(t, "aborted", e.run(r2.ID).Status)

	// Policies and the decisions on a previewed run.
	k3 := e.deployed("ci3", e.server("web-03"), "deploy")
	var p3 sshkeys.Policy
	try("create policy", func() (err error) {
		p3, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k3.ID, Name: "p3", IntervalDays: 30})
		return err
	})
	try("enable", func() (err error) {
		p3, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p3.ID, p3.Version, true)
		return err
	})
	e.clock.Advance(29 * 24 * time.Hour)
	try("plan due", func() error { _, err := e.svc.PlanDue(e.ctx); return err })
	id3 := e.openRun(p3.ID)
	try("stop a previewed run", func() error { return e.svc.Abort(e.ctx, e.admin, id3) })
	assert.Equal(t, "cancelled", e.run(id3).Status)
	try("delete policy", func() error { return e.svc.DeletePolicy(e.ctx, e.admin, p3.ID, e.reloadPolicy(p3.ID).Version) })
}
