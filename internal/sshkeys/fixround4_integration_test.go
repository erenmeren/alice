//go:build integration

package sshkeys_test

import (
	"context"
	"fmt"
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
)

// runningDeploy requests a deploy of a new key to deploy's file on a new server and makes its job
// running (attempt 1); it returns the job's claim context, the job id and the deploy.
func (e *env) runningDeploy(name string) (context.Context, uuid.UUID, sshkeys.DeployJob) {
	e.t.Helper()
	srv := e.server(name)
	k := e.generate("ci-" + name)
	jobID, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'running', attempts = 1, started_at = $2 WHERE id = $1", jobID, e.clock.Now())
	require.NoError(e.t, err)
	claimed := inventory.WithClaim(e.ctx, inventory.Claim{JobID: jobID, Attempt: 1})
	d, err := e.svc.DeployJob(claimed, jobID, srv, e.job(jobID).Payload)
	require.NoError(e.t, err)
	return claimed, jobID, d
}

var (
	provenAbsent = sshkeys.DeployEvidence{Coverage: providers.CoverageComplete, Absent: true}
	foundPresent = sshkeys.DeployEvidence{Coverage: providers.CoverageComplete}
)

// Re-review A-I1: a line is the deploy's own only when a listing that read the file completely proved
// it absent before the FIRST send (re-sends keep that evidence), and no answer of the helper said it
// was already there. A send recorded but never made no longer makes a line that was there "owned".
func TestDeployLineOwnedOnlyWithProvenAbsenceBeforeTheFirstSend(t *testing.T) {
	e := newEnv(t)

	// The walk of A-I1: the line was there before the job; attempt 1's send never reached the helper.
	ctx, jobID, d := e.runningDeploy("web-01")
	s1, err := e.svc.BeginDeploySendWith(ctx, jobID, d, foundPresent)
	require.NoError(t, err)
	assert.False(t, s1.Record.Owned(), "present before the first send")
	e.clock.Advance(time.Minute)
	s2, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	assert.True(t, s2.Resend)
	rec, err := e.svc.DeploySends(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, 2, rec.Count)
	assert.False(t, rec.AbsentBefore, "the first send's evidence is kept")
	assert.Equal(t, providers.CoverageComplete, rec.FirstCoverage)
	assert.False(t, rec.Owned(), "a line that was there before the job is never the job's")
	assert.Equal(t, "false", e.lastAuditDetail("sshkey.add_sent", "absent_before"))
	assert.Equal(t, "complete", e.lastAuditDetail("sshkey.add_sent", "coverage_before"))
	assert.Equal(t, "1", e.lastAuditDetail("sshkey.add_sent", "attempt"))

	// Proven absent before the first send: owned across attempts (attempt 2 finds its own earlier line).
	ctx, jobID, d = e.runningDeploy("web-02")
	s1, err = e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	assert.True(t, s1.Record.Owned())
	s2, err = e.svc.BeginDeploySendWith(ctx, jobID, d, foundPresent)
	require.NoError(t, err)
	assert.True(t, s2.Record.Owned(), "the line found now is the first send's")
	// The helper's own answer "already there" overrides the listing.
	rec, err = e.svc.RecordDeployAnswer(ctx, d, s2, false)
	require.NoError(t, err)
	assert.True(t, rec.AnsweredPresent)
	assert.False(t, rec.Owned(), "the helper said it was already there")
	rec, err = e.svc.DeploySends(ctx, jobID)
	require.NoError(t, err)
	assert.False(t, rec.Owned(), "durable")

	// Coverage not complete: ownership unknown, never owned (an Absent without complete coverage is no proof).
	ctx, jobID, d = e.runningDeploy("web-03")
	s1, err = e.svc.BeginDeploySendWith(ctx, jobID, d, sshkeys.DeployEvidence{Coverage: providers.CoveragePartial, Absent: true})
	require.NoError(t, err)
	assert.False(t, s1.Record.Owned())
	assert.Equal(t, "partial", e.lastAuditDetail("sshkey.add_sent", "coverage_before"))

	// No evidence at all (the listing failed, or the call without it): unknown; the helper's "added" proves it.
	ctx, jobID, d = e.runningDeploy("web-04")
	s1, err = e.svc.BeginDeploySend(ctx, jobID, d)
	require.NoError(t, err)
	assert.False(t, s1.Record.Owned())
	assert.Equal(t, "none", e.lastAuditDetail("sshkey.add_sent", "coverage_before"), "no listing")
	rec, err = e.svc.RecordDeployAnswer(ctx, d, s1, true)
	require.NoError(t, err)
	assert.True(t, rec.AnsweredAdded)
	assert.True(t, rec.Owned(), "the helper wrote it")
	assert.Equal(t, "added", e.lastAuditDetail("sshkey.add_answered", "answer"))
	assert.Equal(t, "1", e.lastAuditDetail("sshkey.add_answered", "send_count"))

	// An answer without a send on record is refused.
	_, _, d5 := e.runningDeploy("web-05")
	ctx5 := inventory.WithClaim(e.ctx, inventory.Claim{JobID: e.jobOf(d5), Attempt: 1})
	_, err = e.svc.RecordDeployAnswer(ctx5, d5, sshkeys.DeploySend{Count: 1}, true)
	assert.ErrorIs(t, err, sshkeys.ErrNoSendOnRecord)
}

// jobOf is the id of the deploy job of d (the only sshkey.add job of its key).
func (e *env) jobOf(d sshkeys.DeployJob) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM jobs WHERE type = 'sshkey.add' AND payload->>'ssh_key_id' = $1",
		d.KeyID.String()).Scan(&id))
	return id
}

// Re-review A-m7: a send and an answer are recorded only by the job run that holds the job: no claim,
// or another job's claim, is refused and records nothing.
func TestDeploySendIsBoundToTheJobsClaim(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	_, err := e.svc.BeginDeploySend(e.ctx, jobID, d)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim, "no claim")
	_, err = e.svc.BeginDeploySendWith(e.claimed(), jobID, d, provenAbsent)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim, "another job's claim")
	assert.Zero(t, e.audits("sshkey.add_sent"))
	s, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	_, err = e.svc.RecordDeployAnswer(e.ctx, d, s, true)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim)
	_, err = e.svc.RecordDeployAnswer(e.claimed(), d, s, true)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim, "the deploy is not the claim's job")
	assert.Zero(t, e.audits("sshkey.add_answered"))
	_, _, other := e.runningDeploy("web-02")
	_, err = e.svc.BeginDeploySendWith(ctx, jobID, other, provenAbsent)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim, "another job's deploy under this job's claim")
	assert.Equal(t, 1, e.audits("sshkey.add_sent"))
}

// Re-review A-m6: the send lookup reads only audit rows written after the job was created (less a day
// for a clock step): a row of the job's id written long before (forged, here) is not read.
func TestDeploySendLookupIsBoundedByTheJobsCreation(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	now := e.clock.Now()
	e.clock.Set(now.Add(-72 * time.Hour))
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: jobID.String()},
			Action: "sshkey.add_sent", ObjectType: "ssh_key", ObjectID: d.KeyID.String(), Result: audit.Success,
			Details: map[string]string{"job_id": jobID.String(), "send_count": "1", "sent_at": e.clock.Now().Format(time.RFC3339Nano),
				"absent_before": "true", "coverage_before": "complete"}})
		return err
	}))
	e.clock.Set(now)
	rec, err := e.svc.DeploySends(ctx, jobID)
	require.NoError(t, err)
	assert.Zero(t, rec.Count, "rows before the job's creation are outside the lookup")
	s, err := e.svc.BeginDeploySendWith(ctx, jobID, d, foundPresent)
	require.NoError(t, err)
	assert.Equal(t, 1, s.Count)
	assert.False(t, s.Record.Owned())
	rec, err = e.svc.DeploySends(ctx, uuid.New())
	require.NoError(t, err)
	assert.Zero(t, rec.Count, "an unknown job has no sends")
}

// Coordinator's addition: a deploy whose job ended without its handler's outcome after a send was
// recorded (killed on the last attempt, discarded while held) is reconciled once by the hourly task,
// after the wait for a stalled write: one sshkey.add_outcome_unknown row and a scan of the server;
// nothing is removed. A job that finished normally, one still live, and one whose wait is not over
// are left alone.
func TestUnfinishedDeploySendsAreReconciledOnce(t *testing.T) {
	e := newEnv(t)
	end := func(jobID uuid.UUID, status string) {
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = $2, finished_at = $3 WHERE id = $1", jobID, status, e.clock.Now())
		require.NoError(t, err)
	}
	scans := func(target uuid.UUID) int {
		return e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", target)
	}
	killedCtx, killed, kd := e.runningDeploy("web-01")
	ks, err := e.svc.BeginDeploySendWith(killedCtx, killed, kd, provenAbsent)
	require.NoError(t, err)
	_, err = e.svc.RecordDeployAnswer(killedCtx, kd, ks, true) // killed after the helper's answer
	require.NoError(t, err)
	e.clock.Advance(time.Second) // the next job is younger
	heldCtx, held, hd := e.runningDeploy("web-02")
	hs, err := e.svc.BeginDeploySend(heldCtx, held, hd) // no listing before it
	require.NoError(t, err)
	_, err = e.svc.RecordDeployAnswer(heldCtx, hd, hs, false)
	require.NoError(t, err)
	end(held, "cancelled") // retried, held by the licence, discarded
	e.clock.Advance(time.Second)
	end(killed, "dead") // ends after a younger job
	okCtx, ok, od := e.runningDeploy("web-03")
	_, err = e.svc.BeginDeploySendWith(okCtx, ok, od, provenAbsent)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishDeploy(okCtx, audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: ok.String()}, od,
		sshkeys.DeployOutcome{Result: sshkeys.DeployVerified, LineNo: 1}))
	end(ok, "succeeded")
	liveCtx, live, ld := e.runningDeploy("web-04")
	_, err = e.svc.BeginDeploySendWith(liveCtx, live, ld, provenAbsent)
	require.NoError(t, err)
	_, _, unsent := e.runningDeploy("web-05")
	end(e.jobOf(unsent), "dead")

	// Within the wait for a stalled write nothing is reconciled.
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, e.audits("sshkey.add_outcome_unknown"))
	assert.Zero(t, scans(kd.TargetID))

	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	for range 2 {
		_, err = e.svc.DestroyRetiredKeys(e.ctx)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, e.audits("sshkey.add_outcome_unknown"), "the killed and the discarded job, once each")
	for _, c := range []struct {
		job    uuid.UUID
		target uuid.UUID
		want   int
	}{{killed, kd.TargetID, 1}, {held, hd.TargetID, 1}, {ok, od.TargetID, 0}, {live, ld.TargetID, 0}, {e.jobOf(unsent), unsent.TargetID, 0}} {
		assert.Equal(t, c.want, e.count("SELECT count(*) FROM audit_log WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1",
			c.job.String()), "job %s", c.job)
		assert.Equal(t, c.want, scans(c.target), "scan of %s", c.target)
	}
	assert.Equal(t, "dead", e.count2("SELECT details->>'job_status' FROM audit_log WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1",
		killed.String()))
	assert.Equal(t, "true", e.count2("SELECT details->>'absent_before' FROM audit_log WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1",
		killed.String()))
	for job, want := range map[uuid.UUID][4]string{killed: {"true", "complete", "added", "true"}, held: {"false", "none", "already_present", "false"}} {
		for i, key := range []string{"absent_before", "coverage_before", "answer", "owned"} {
			assert.Equal(t, want[i], e.count2("SELECT details->>$2 FROM audit_log WHERE action = 'sshkey.add_outcome_unknown' AND request_id = $1",
				job.String(), key), key)
		}
	}

	// A job that comes back after the reconciliation is not reconciled a second time.
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'running', attempts = 2, finished_at = NULL WHERE id = $1", killed)
	require.NoError(t, err)
	back := inventory.WithClaim(e.ctx, inventory.Claim{JobID: killed, Attempt: 2})
	_, err = e.svc.BeginDeploySendWith(back, killed, kd, foundPresent)
	require.NoError(t, err)
	end(killed, "dead")
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, e.audits("sshkey.add_outcome_unknown"), "exactly once per request")
}

// count2 reads one text value.
func (e *env) count2(sql string, args ...any) string {
	e.t.Helper()
	var s string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, sql, args...).Scan(&s))
	return s
}

// Re-review A-m1: an adding row refused at send time keeps its skip reason (the API shows it).
func TestAddingRowRefusedAtSendKeepsItsSkipReason(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET keys_managed_elsewhere = true WHERE id = $1", srv)
	require.NoError(t, err)
	_, err = e.svc.BeginAdd(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, "add_failed", got.State)
	assert.Equal(t, "rotation.skipped_at_send", got.ErrorCode)
	assert.Equal(t, "keys_managed_elsewhere", got.SkipReason)
}

// Re-review A-m2: a stale connection state (unreachable, checking, auth_failed) is not a reason found at
// send time: a planned place is still tried, and a re-send of an adding place does not end it (the
// run does not roll back). The job finds the connection itself.
func TestStaleConnectionStateDoesNotEndAPlaceAtSend(t *testing.T) {
	for _, status := range []string{"unreachable", "checking", "auth_failed"} {
		t.Run(status, func(t *testing.T) {
			e := newEnv(t)
			srv := e.server("web-01")
			k := e.deployed("ci", srv, "deploy")
			r := e.runNow(e.policy(k.ID, 90, 7, 24))
			loc := r.Locations[0].ID
			e.setTargetStatus(srv, status)
			_, err := e.svc.BeginAdd(e.claimed(), loc)
			require.NoError(t, err, "a planned place is tried")
			e.clock.Advance(time.Minute)
			_, err = e.svc.BeginAdd(e.claimed(), loc)
			require.NoError(t, err, "a re-send is not refused")
			got := e.run(r.ID)
			assert.Equal(t, "adding", got.Locations[0].State)
			assert.Equal(t, 1, got.Locations[0].AddResendCount)
			require.NoError(t, e.svc.Advance(e.ctx, r.ID))
			assert.Equal(t, "adding_new", e.run(r.ID).Status, "no roll back")
		})
	}
}

// Re-review A-m2 / section 6: a second location of the key that appeared in the file since the start
// is the planner's shared-file rule, found at send time: the place is cancelled with that reason.
func TestSharedFileFoundAtSendCancelsThePlace(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := e.inv.RecordKeyAddedTx(e.ctx, tx, inventory.KeyAdded{SSHKeyID: k.ID, TargetID: srv, OSUser: "bob",
			FilePath: keyFile("deploy"), Comment: "x", LineNo: 1, Actor: audit.SystemActor("test")})
		return err
	}))
	_, err := e.svc.BeginAdd(e.claimed(), r.Locations[0].ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	got := e.run(r.ID).Locations[0]
	assert.Equal(t, "cancelled", got.State)
	assert.Equal(t, "shared_file_skipped", got.SkipReason)
	assert.Equal(t, "rotation.skipped_at_send", got.ErrorCode)
}

// Re-review A-m3: a refusal the sweep handled (the row ended in its failed state) is not an error of
// the tick, and the run advances in the same sweep.
func TestHandledRefusalIsNotASweepError(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	id, loc := e.runInRemoving(k)
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE ssh_key_locations SET is_alice_connection_key = true WHERE id = (SELECT old_location_id
FROM rotation_locations WHERE id = $1)`, loc)
	require.NoError(t, err)
	e.failLocationJobs()
	sum, err := e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, sum.Failed)
	got := e.run(id)
	assert.Equal(t, "remove_failed", got.Locations[0].State)
	assert.Equal(t, "needs_attention", got.Status, "advanced in the same sweep")
	assert.Contains(t, e.logs.String(), "the database refused a location's re-queue", "still logged once")
}

// Re-review A-m4: a refused row ends only by an edge the database allows in the run's status; a row
// with no such edge is left as it is (and the refusal stays an error).
func TestFailRefusedPicksAnEdgeOfTheRunStatus(t *testing.T) {
	t.Run("adding_new", func(t *testing.T) {
		e := newEnv(t)
		web1, web2, web3 := e.server("web-01"), e.server("web-02"), e.server("web-03")
		k := e.deployed("ci", web1, "deploy")
		e.addLocation(k.ID, web2, "deploy")
		e.addLocation(k.ID, web3, "deploy")
		r := e.runNow(e.policy(k.ID, 90, 7, 24))
		ids := map[uuid.UUID]uuid.UUID{}
		for _, l := range r.Locations {
			ids[l.TargetID] = l.ID
		}
		_, err := e.svc.BeginAdd(e.claimed(), ids[web2])
		require.NoError(t, err)
		_, err = e.svc.BeginAdd(e.claimed(), ids[web3])
		require.NoError(t, err)
		require.NoError(t, e.svc.FinishAdd(e.claimed(), ids[web3], sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
		for target, want := range map[uuid.UUID]string{web1: "planned", web2: "adding", web3: "added"} {
			require.Equal(t, want, e.locByID(r.ID, ids[target]).State)
			ended, err := sshkeys.FailRefused(e.ctx, e.svc, ids[target])
			require.NoError(t, err, want)
			assert.True(t, ended, want)
			assert.Equal(t, "add_failed", e.locByID(r.ID, ids[target]).State, want)
		}
	})
	t.Run("rolling_back", func(t *testing.T) {
		e := newEnv(t)
		web1, web2 := e.server("web-01"), e.server("web-02")
		k := e.deployed("ci", web1, "deploy")
		e.addLocation(k.ID, web2, "deploy")
		r := e.runNow(e.policy(k.ID, 90, 7, 24))
		ids := map[uuid.UUID]uuid.UUID{}
		for _, l := range r.Locations {
			ids[l.TargetID] = l.ID
		}
		e.drive(ids[web1], providers.KeyLoginAccepted)
		_, err := e.svc.BeginAdd(e.claimed(), ids[web2])
		require.NoError(t, err)
		require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
		require.Equal(t, "rolling_back", e.run(r.ID).Status)
		ended, err := sshkeys.FailRefused(e.ctx, e.svc, ids[web1])
		require.NoError(t, err)
		assert.True(t, ended)
		got := e.locByID(r.ID, ids[web1])
		assert.Equal(t, "undo_failed", got.State, "a verified row of a rolling-back run: undo_failed, not remove_failed")
		assert.Equal(t, "rotation.guard_refused", got.ErrorCode)
		assert.Equal(t, 1, e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", web1),
			"the new key may be left there: a scan")
		ended, err = sshkeys.FailRefused(e.ctx, e.svc, ids[web2])
		require.NoError(t, err)
		assert.False(t, ended, "an adding row has no edge without an undo send (G17)")
		assert.Equal(t, "adding", e.locByID(r.ID, ids[web2]).State)
	})
	t.Run("removing_old", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		id, loc := e.runInRemoving(k)
		ended, err := sshkeys.FailRefused(e.ctx, e.svc, loc)
		require.NoError(t, err)
		assert.True(t, ended)
		assert.Equal(t, "remove_failed", e.locByID(id, loc).State, "verified → remove_failed")
		ended, err = sshkeys.FailRefused(e.ctx, e.svc, loc)
		require.NoError(t, err)
		assert.False(t, ended, "a failed removal has no other edge")
	})
	t.Run("overlap", func(t *testing.T) {
		e := newEnv(t)
		k := e.deployed("ci", e.server("web-01"), "deploy")
		r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
		require.Equal(t, "overlap", r.Status)
		ended, err := sshkeys.FailRefused(e.ctx, e.svc, ids["deploy"])
		require.NoError(t, err)
		assert.False(t, ended, "no location job waits in overlap")
		assert.Equal(t, "verified", e.locByID(r.ID, ids["deploy"]).State)
	})
}

// locByID is one location of the run.
func (e *env) locByID(runID, locID uuid.UUID) sshkeys.RotationLocation {
	e.t.Helper()
	for _, l := range e.run(runID).Locations {
		if l.ID == locID {
			return l
		}
	}
	e.t.Fatalf("no location %s", locID)
	return sshkeys.RotationLocation{}
}

// Re-review A-m9: the sweep's own move of an adding row to undoing has BeginUndo's clock check: on a
// clock behind the latest send it waits (no database refusal), and moves once the clock passed it.
func TestSweepUndoOfAnAddingRowWaitsForTheClock(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	sent := e.clock.Now()
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	// An answered add (no S3 wait) whose undo jobs did not get through.
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO rotation_steps (id, rotation_id, n, location_id, name, status, at, params)
VALUES ($1, $2, (SELECT coalesce(max(n), 0) + 1 FROM rotation_steps WHERE rotation_id = $2), $3, 'add_answered', 'ok', $4, '{"added": "true"}')`,
		uuid.Must(uuid.NewV7()), r.ID, loc, sent)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE rotation_locations SET job_count = $2 WHERE id = $1", loc, sshkeys.MaxLocationJobs)
	require.NoError(t, err)
	e.failLocationJobs()
	e.clock.Set(sent.Add(-time.Minute))
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err, "no 23514 on a clock behind the send")
	assert.Equal(t, "adding", e.run(r.ID).Locations[0].State)
	e.clock.Set(sent.Add(time.Second))
	_, err = e.svc.Sweep(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "undoing", e.run(r.ID).Locations[0].State)
}

// Re-review A-m5: after a downtime of many intervals, a plan with nothing to rotate mails once and
// moves the next run past now in one step (to the first boundary whose notice is still ahead).
func TestNothingToRotateAfterDowntimeMailsOnce(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	e.setTargetStatus(srv, "unreachable")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	first := *p.NextRunAt
	e.clock.Advance(10*90*24*time.Hour + time.Hour) // ten intervals missed
	for range 5 {
		_, err := e.svc.PlanDue(e.ctx)
		require.NoError(t, err)
		e.clock.Advance(time.Minute)
	}
	require.Len(t, e.mails("rotation.nothing_to_rotate"), 1)
	next := *e.reloadPolicy(p.ID).NextRunAt
	assert.Equal(t, first.Add(10*90*24*time.Hour), next, "the first boundary whose notice is after now")
	assert.True(t, next.Add(-24*time.Hour).After(e.clock.Now()), "the next notice is ahead")
}

// Re-review A-m5, same shape: a scheduled run cancelled for an undelivered notice long after its
// start moves the next run past now in one step.
func TestNoticeUndeliveredAfterDowntimeMovesPastNow(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	first := *p.NextRunAt
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	e.clock.Set(r.PlannedFor.Add(5*90*24*time.Hour + time.Hour)) // five intervals of downtime
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	require.Equal(t, "cancelled", e.run(r.ID).Status)
	next := *e.reloadPolicy(p.ID).NextRunAt
	assert.Equal(t, first.Add(6*90*24*time.Hour), next, fmt.Sprintf("now %s", e.clock.Now()))
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "nothing is due right away")
}

// The reconciliation's re-checks under the job's lock: a job live again, a deploy that finished or was
// reconciled meanwhile, a wait not over, and a job without a send are left alone; an unknown job is an
// error.
func TestReconcileDeployRechecksUnderTheJobsLock(t *testing.T) {
	e := newEnv(t)
	ctx, jobID, d := e.runningDeploy("web-01")
	_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	require.NoError(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, jobID), "running: left alone")
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1", jobID, e.clock.Now())
	require.NoError(t, err)
	e.clock.Set(e.clock.Now().Add(-time.Minute))
	require.NoError(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, jobID), "within the wait: left alone")
	assert.Zero(t, e.audits("sshkey.add_outcome_unknown"))
	e.clock.Advance(time.Minute)
	require.NoError(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, jobID))
	require.NoError(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, jobID), "reconciled: once")
	assert.Equal(t, 1, e.audits("sshkey.add_outcome_unknown"))
	_, _, d2 := e.runningDeploy("web-02")
	j2 := e.jobOf(d2)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1", j2, e.clock.Now())
	require.NoError(t, err)
	require.NoError(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, j2), "nothing sent")
	assert.Equal(t, 1, e.audits("sshkey.add_outcome_unknown"))
	assert.Error(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, uuid.New()))
}

// The deploy record's reads and writes fail cleanly on a database failure: an error, nothing written.
func TestDeployRecordFailsCleanlyOnADatabaseFault(t *testing.T) {
	e := newEnv(t)
	fault := e.dbFaults()
	ctx, jobID, d := e.runningDeploy("web-01")
	revoke := func(sql string) func() {
		_, err := e.db.Owner.Exec(e.ctx, sql)
		require.NoError(t, err)
		return func() {
			_, err := e.db.Owner.Exec(e.ctx, "GRANT SELECT ON audit_log, jobs TO alice_app")
			require.NoError(t, err)
		}
	}

	fault("audit_log", true)
	_, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	assert.Error(t, err)
	fault("audit_log", false)
	s, err := e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	require.NoError(t, err)
	fault("audit_log", true)
	_, err = e.svc.RecordDeployAnswer(ctx, d, s, true)
	assert.Error(t, err)
	fault("audit_log", false)

	// Reads of the audit log refused, except the bound (seq and at stay readable).
	restore := revoke("REVOKE SELECT ON audit_log FROM alice_app; GRANT SELECT (seq, at) ON audit_log TO alice_app")
	_, err = e.svc.DeploySends(e.ctx, jobID)
	assert.Error(t, err, "the record's rows")
	_, err = e.svc.RecordDeployAnswer(ctx, d, s, true)
	assert.Error(t, err, "the record's rows")
	_, err = e.svc.BeginDeploySendWith(ctx, jobID, d, provenAbsent)
	assert.Error(t, err, "the record's rows")
	restore()
	restore = revoke("REVOKE SELECT ON audit_log FROM alice_app")
	_, err = e.svc.DeploySends(e.ctx, jobID)
	assert.Error(t, err, "the bound")
	restore()
	restore = revoke("REVOKE SELECT ON jobs FROM alice_app")
	_, err = e.svc.DeploySends(e.ctx, jobID)
	assert.Error(t, err, "the job's creation")
	_, err = e.svc.RecordDeployAnswer(e.ctx, d, s, true)
	assert.ErrorIs(t, err, sshkeys.ErrNoJobClaim)
	restore()
	restore = revoke("REVOKE SELECT ON jobs FROM alice_app; GRANT SELECT (id, attempts, status, created_at) ON jobs TO alice_app")
	_, err = e.svc.RecordDeployAnswer(ctx, d, s, true)
	assert.Error(t, err, "the deploy's job")
	assert.NotErrorIs(t, err, sshkeys.ErrNoJobClaim)
	restore()

	// The reconciliation's reads refused: an error, nothing written.
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1", jobID, e.clock.Now())
	require.NoError(t, err)
	e.clock.Advance(helperproto.HelperBudget + 31*time.Second)
	for _, sql := range []string{"REVOKE SELECT ON jobs FROM alice_app", "REVOKE SELECT ON audit_log FROM alice_app",
		"REVOKE SELECT ON audit_log FROM alice_app; GRANT SELECT (seq, at) ON audit_log TO alice_app"} {
		restore = revoke(sql)
		_, err = e.svc.DestroyRetiredKeys(e.ctx)
		assert.Error(t, err, sql)
		assert.Error(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, jobID), sql)
		restore()
	}
	assert.Zero(t, e.audits("sshkey.add_outcome_unknown"))

	// A reconciliation that cannot write is logged, and done by a later run.
	fault("audit_log", true)
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	assert.Error(t, err)
	fault("audit_log", false)
	assert.Contains(t, e.logs.String(), "could not reconcile a deploy's send")
	_, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, e.audits("sshkey.add_outcome_unknown"))

	// A send row whose time cannot be read is an error, not a guess.
	ctx2, job2, d2 := e.runningDeploy("web-02")
	_, err = e.svc.BeginDeploySendWith(ctx2, job2, d2, provenAbsent)
	require.NoError(t, err)
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: job2.String()},
			Action: "sshkey.add_sent", ObjectType: "ssh_key", ObjectID: d2.KeyID.String(), Result: audit.Success,
			Details: map[string]string{"job_id": job2.String(), "sent_at": "yesterday"}})
		return err
	}))
	_, err = e.svc.DeploySends(e.ctx, job2)
	assert.Error(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'dead', finished_at = $2 WHERE id = $1", job2, e.clock.Now())
	require.NoError(t, err)
	assert.Error(t, sshkeys.ReconcileDeploy(e.ctx, e.svc, job2))
}

// A previewed run cancelled for an undelivered notice whose policy was switched off meanwhile gets no
// next run.
func TestNoticeUndeliveredOfASwitchedOffPolicyPlansNothing(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE rotation_policies SET enabled = false, next_run_at = NULL WHERE id = $1", p.ID)
	require.NoError(t, err)
	e.clock.Set(r.PlannedFor)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "cancelled", e.run(r.ID).Status)
	assert.Nil(t, e.reloadPolicy(p.ID).NextRunAt)
}
