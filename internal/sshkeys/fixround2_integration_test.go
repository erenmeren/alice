//go:build integration

package sshkeys_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

func (e *env) setKeyFiles(srv uuid.UUID, files []providers.UserKeyFiles) {
	e.t.Helper()
	raw, err := json.Marshal(files)
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET facts = jsonb_set(facts, '{key_files}', $2) WHERE id = $1", srv, raw)
	require.NoError(e.t, err)
}

// N1: a server whose connection account's key files are not known (not scanned again since the
// upgrade) is skipped in the preview with its own reason, and the run is the preview; a location
// whose file is one of the connection account's files is skipped too.
func TestPreviewEqualsRunForUnscannedServers(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	e.setKeyFiles(web2, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	skips := map[uuid.UUID]string{}
	for _, a := range pv.Plan.Actions {
		skips[a.TargetID] = a.Skip
	}
	assert.Equal(t, map[uuid.UUID]string{web1: "", web2: plan.SkipConnectionFilesUnknown}, skips)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	for _, l := range r.Locations {
		if l.TargetID == web2 {
			assert.Equal(t, "skipped", l.State)
			assert.Equal(t, "connection_files_unknown", l.SkipReason)
		} else {
			assert.Equal(t, "planned", l.State)
		}
	}

	e2 := newEnv(t)
	srv := e2.server("web-01")
	k2 := e2.deployed("ci", srv, "deploy")
	e2.setKeyFiles(srv, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true},
		{OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys", "/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	pv2, err := e2.svc.Preview(e2.ctx, e2.admin, e2.policy(k2.ID, 90, 7, 24).ID)
	require.NoError(t, err)
	assert.Equal(t, plan.SkipConnectionAccountFile, pv2.Plan.Actions[0].Skip)
}

// N1 second line: when the connection account's files become unknown after the start, BeginAdd ends
// the location at once with that reason (no retries, no rollback of the others); the run carries on
// and counts the place where the old key stays.
func TestBeginAddRefusalIsRecordedAtOnce(t *testing.T) {
	e := newEnv(t)
	web1, web2 := e.server("web-01"), e.server("web-02")
	k := e.deployed("ci", web1, "deploy")
	e.addLocation(k.ID, web2, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 0, 24))
	locs := map[uuid.UUID]uuid.UUID{}
	for _, l := range r.Locations {
		locs[l.TargetID] = l.ID
	}
	e.setKeyFiles(web2, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	_, err := e.svc.BeginAdd(e.claimed(), locs[web2])
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	got := e.run(r.ID)
	for _, l := range got.Locations {
		if l.TargetID == web2 {
			assert.Equal(t, "cancelled", l.State)
			assert.Equal(t, "sshkey.connection_files_unknown", l.ErrorCode)
		}
	}
	e.drive(locs[web1], providers.KeyLoginAccepted)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "overlap", e.run(r.ID).Status, "no rollback for a cause known in advance")
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	e.removeAt(locs[web1])
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got = e.run(r.ID)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 1, got.KeptCount)

	// Every changing location refused: nothing to rotate, the run ends aborted with that reason.
	e2 := newEnv(t)
	srv := e2.server("web-01")
	k2 := e2.deployed("ci", srv, "deploy")
	r2 := e2.runNow(e2.policy(k2.ID, 90, 7, 24))
	e2.setKeyFiles(srv, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}, Complete: true}})
	_, err = e2.svc.BeginAdd(e2.claimed(), r2.Locations[0].ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	require.NoError(t, e2.svc.Advance(e2.ctx, r2.ID))
	require.NoError(t, e2.svc.Advance(e2.ctx, r2.ID))
	got = e2.run(r2.ID)
	assert.Equal(t, "aborted", got.Status)
	assert.Equal(t, "sshkey.connection_files_unknown", got.ResultCode)
}

// N2: a job queued just before a licence lock does not use up a retry.
func TestLockDoesNotUseUpARetry(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.failLocationJobs()
	_, err = e.svc.Sweep(e.ctx) // re-queued: job_count 1
	require.NoError(t, err)
	require.Equal(t, 1, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc))
	e.gate.lock()
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrPaused)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID)) // the pause
	assert.Zero(t, e.count("SELECT job_count FROM rotation_locations WHERE id = $1", loc), "the pause gives the retries back")
}

// N3 and G25: a re-send is recorded on the row; an ANSWERED re-send does not end S3's wait while the
// first send may still be running.
func TestAnsweredResendKeepsTheUndoWaiting(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	e.clock.Advance(10 * time.Second)
	_, err = e.svc.BeginAdd(e.claimed(), loc) // the re-send
	require.NoError(t, err)
	resentAt := e.clock.Now()
	assert.Equal(t, 1, e.count("SELECT add_resend_count FROM rotation_locations WHERE id = $1", loc))
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: false, Reason: "ssh.helper_refused"}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID)) // add_failed: rolls back
	require.Equal(t, "rolling_back", e.run(r.ID).Status)
	e.clock.Set(resentAt.Add(helperproto.HelperBudget + 30*time.Second - time.Second))
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "the first send may still be running")
	e.clock.Advance(time.Second)
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.NoError(t, err)
}

// N4: the bounded undo of an adding row ends undo_failed with the truth recorded (no undo was sent),
// a scan of the server queued, and the attention mail names the server.
func TestBoundedUndoOfAnAddingRowTellsTheTruth(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	for range 3 * sshkeys.MaxLocationJobs {
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(r.ID)
	require.Equal(t, "needs_attention", got.Status)
	var names []string
	for _, s := range got.Steps {
		names = append(names, s.Name)
	}
	assert.Contains(t, names, "undo_not_sent")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", srv))
	m := e.mails("rotation.needs_attention")
	require.Len(t, m, 1)
	assert.Equal(t, "web-01", m[0]["undo_failed_servers"])
	assert.Equal(t, "1", m[0]["undo_failed_count"])
}

// N5: a repeated late result mails once; kept_count does not count a place a late removal removed.
// M13: the FinishRemove late path.
func TestLateRemovalIsCountedOnce(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	id, loc := e.runInRemoving(k)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	for range 2*sshkeys.MaxLocationJobs + 3 { // the removing row's bound, then the failed removal's retries
		e.failLocationJobs()
		_, err := e.svc.Sweep(e.ctx)
		require.NoError(t, err)
	}
	got := e.run(id)
	require.Equal(t, "needs_attention", got.Status)
	require.Equal(t, "remove_failed", got.Locations[0].State)
	require.Equal(t, 1, got.KeptCount)

	for range 2 {
		require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Removed: 1,
			Res: providers.AuthKeyResult{Changed: true, Removed: 1}}))
	}
	got = e.run(id)
	assert.Equal(t, "remove_failed", got.Locations[0].State, "the row stays as the guards require")
	assert.Zero(t, got.KeptCount, "the late removal removed the old key there")
	assert.Len(t, e.mails("rotation.late_result"), 1, "one mail per location")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", k.ID))
}

// N7: Run now on a run the sweep cancelled meanwhile answers a closed error, not the cancelled run.
func TestRunNowOnARunCancelledMeanwhile(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	sshkeys.OnBeforeStart(t, func() {
		e.clock.Advance(sshkeys.ManualStartGrace)
		id := e.openRun(p.ID)
		require.NoError(t, e.svc.Advance(e.ctx, id)) // the sweep cancels the manual run
	})
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrNotWaiting)
}

// N8: the hourly retirement re-checks, under the key's lock, that no policy uses the key.
func TestRetirementRechecksThePolicyUnderTheLock(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	id, loc := e.runInRemoving(k)
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: e.server("web-03"), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	require.NoError(t, err)
	e.clock.Advance(time.Minute)
	e.removeAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, id))
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'cancelled' WHERE type = 'sshkey.add'")
	require.NoError(t, err)
	sshkeys.OnRetireCandidates(t, func() {
		_, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "again", IntervalDays: 30})
		require.NoError(t, err)
	})
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Nil(t, mustKey(e, k.ID).RetiredAt, "a policy was created meanwhile")
}

// N9: when the renewal notice cannot be queued, the run says so (notice pending with a closed
// sub-reason) and each failure is logged; Abort stays possible.
func TestRenewalNoticeFailureIsVisible(t *testing.T) {
	e := newEnv(t)
	f := e.withFaults()
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	e.gate.lock()
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.True(t, e.run(r.ID).PausedLicense)
	e.gate.unlock()
	f.mail.Store(true)
	assert.ErrorIs(t, e.svc.Advance(e.ctx, r.ID), errInjected)
	got := e.run(r.ID)
	assert.Equal(t, "rotation.notice_pending", got.NoticeState)
	assert.Equal(t, "notify.queue_failed", got.NoticeError)
	assert.Contains(t, e.logs.String(), "could not queue the renewal notice")
	assert.Contains(t, sshkeys.AllowedActions(got, true), "abort")
	f.mail.Store(false)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got = e.run(r.ID)
	assert.Empty(t, got.NoticeState)
	assert.Empty(t, got.NoticeError)
}

// N6: a guard refusal on the controller path is logged with its SQLSTATE and constraint.
func TestGuardRefusalIsLoggedWithItsCode(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	_, err := e.db.Owner.Exec(e.ctx, `CREATE FUNCTION test_refuse_loc() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'refused for the test' USING ERRCODE = 'Z1011', CONSTRAINT = 'test_constraint'; END $$`)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "CREATE TRIGGER test_refuse_loc BEFORE UPDATE ON rotation_locations FOR EACH ROW EXECUTE FUNCTION test_refuse_loc()")
	require.NoError(t, err)
	e.failLocationJobs()
	_, err = e.svc.Sweep(e.ctx) // the re-queue's counter update is refused
	var g *sshkeys.GuardRefusal
	require.ErrorAs(t, err, &g)
	assert.Equal(t, "Z1011", g.Code)
	_ = r
	assert.Contains(t, e.logs.String(), "sqlstate=Z1011")
	assert.Contains(t, e.logs.String(), "constraint=test_constraint")
}

// G18 at store level, the rows constructed directly (S10 keeps the planner from producing them): a
// verified location whose file has a skipped sibling keeps the old key at the overlap's end.
func TestFileWithASkippedSiblingKeepsTheOldKey(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	var sibling uuid.UUID
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		var err error
		sibling, err = e.inv.RecordKeyAddedTx(e.ctx, tx, inventory.KeyAdded{SSHKeyID: k.ID, TargetID: srv, OSUser: "backup",
			FilePath: keyFile("deploy"), Comment: k.Comment, LineNo: 2, Actor: audit.SystemActor("test")})
		return err
	}))
	tx, err := e.db.Owner.Begin(e.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(e.ctx, "ALTER TABLE rotation_locations DISABLE TRIGGER rotation_locations_guard")
	require.NoError(t, err)
	_, err = tx.Exec(e.ctx, `INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state,
    skip_reason, updated_at) VALUES ($1, $2, 2, $3, $4, 'backup', $5, 'skipped', 'shared_file_skipped', $6)`,
		uuid.Must(uuid.NewV7()), r.ID, sibling, srv, keyFile("deploy"), e.clock.Now())
	require.NoError(t, err)
	_, err = tx.Exec(e.ctx, "ALTER TABLE rotation_locations ENABLE TRIGGER rotation_locations_guard")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	e.clock.Advance(7 * 24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	assert.Equal(t, "removing_old", got.Status)
	assert.Equal(t, "kept_old", e.locState(got, "deploy"))
	assert.Zero(t, e.jobsOf("remove"))
	_, err = e.svc.BeginRemove(e.claimed(), ids["deploy"])
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got = e.run(r.ID)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 2, got.KeptCount)
}

// M13: a decision that waits for a store transaction holding the run sees the state that
// transaction committed (no sleep: a lock-wait barrier).
func TestDecisionWaitsForAStoreCallOnTheRun(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	e.clock.Advance(7 * 24 * time.Hour)
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(e.ctx, "SELECT id FROM rotations WHERE id = $1 FOR UPDATE", r.ID)
	require.NoError(t, err)
	var finishErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		finishErr = e.svc.FinishNow(e.ctx, e.admin, r.ID)
	}()
	e.waitForLockWait()
	_, err = tx.Exec(e.ctx, `UPDATE rotations SET status = 'removing_old', removal_allowed = true, updated_at = $2, version = version + 1
WHERE id = $1`, r.ID, e.clock.Now())
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	wg.Wait()
	assert.ErrorIs(t, finishErr, sshkeys.ErrNotWaiting, "the decision read the committed state after the wait")
}
