//go:build integration

package sshkeyjobs_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/jobs"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

const deployFile = "/home/deploy/.ssh/authorized_keys"

// deploy queues the deploy of the key to the deploy user's file of the server.
func (e *env) deploy(k sshkeys.ManagedKey, srv uuid.UUID, from string) uuid.UUID {
	e.t.Helper()
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile,
		From: from})
	require.NoError(e.t, err)
	return job
}

// discoveries counts the discovery jobs queued for the server (the record catches up with the file).
func (e *env) discoveries(srv uuid.UUID) int {
	return e.count("SELECT count(*) FROM jobs WHERE type = 'target.discover' AND target_id = $1", srv)
}

func TestDeployVerifiesLogin(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	e.world.Put(srv, "deploy", deployFile, e.otherKeyLine(t)) // an existing key of someone else
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "verified", v.Result["result"])
	assert.Equal(t, k.ID.String(), v.Result["ssh_key_id"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
	assert.Len(t, e.world.Lines(srv, deployFile), 2, "the other key is untouched")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND line_no = 2", k.ID))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.added", "verified"))
	logins := e.events("VerifyKeyLogin")
	require.Len(t, logins, 1)
	assert.Equal(t, k.Fingerprint, logins[0].Fingerprint, "the login offered the new key only")
	assert.Equal(t, "deploy", logins[0].OSUser)
	assert.Zero(t, e.discoveries(srv))
}

func TestDeployUnverifiedWithFrom(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse // Alice's address is not in from=
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "10.0.0.0/8")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "unverified", v.Result["result"])
	assert.Equal(t, "from_option", v.Result["note"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "kept: Alice cannot know whether from= excludes her")
	assert.Equal(t, "false", e.lastAuditDetail("sshkey.added", "verified"))
}

func TestDeployUnprovableLoginIsUnverified(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultUnprovable // the server let Alice in without asking for the key
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "unverified", v.Result["result"])
	assert.Equal(t, "login_without_key", v.Result["note"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
}

// A test login that cannot connect after a definite add keeps the key: the add is known, only its proof
// is missing (and a removal over the same broken connection would fail as well).
func TestDeployLoginUnavailableKeepsADefiniteAdd(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultUnreachable
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "unverified", v.Result["result"])
	assert.Equal(t, "login_unavailable", v.Result["note"])
	assert.Equal(t, "ok", e.targetStatus(srv), "a failed test login never marks the server")
}

func TestDeployRefusedLoginIsUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	other := e.otherKeyLine(t)
	e.world.Put(srv, "deploy", deployFile, other)
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.login_failed", v.LastErrorCode)
	assert.Equal(t, "undone", v.Result["result"])
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint), "Alice removed the key it had added")
	assert.Equal(t, []string{other}, e.world.Lines(srv, deployFile))
	assert.Equal(t, "sshkey.login_failed", e.lastAuditDetail("sshkey.add_failed", "reason"))
	assert.Equal(t, "ok", e.targetStatus(srv), "a refused test login never marks the server")
	removals := e.events("RemoveAuthorizedKey")
	require.Len(t, removals, 1)
	assert.Equal(t, k.Fingerprint, removals[0].Fingerprint, "the undo removes the new key only")
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID))
}

func TestDeployUncertainWriteResolvedByLogin(t *testing.T) {
	for _, loginWorks := range []bool{true, false} {
		e := newEnv(t)
		srv := e.server("web-01")
		k := e.generate("ci")
		e.setFault(func(p fake.FaultPoint) fake.Fault {
			switch {
			case p.Method == "AddAuthorizedKey":
				return fake.FaultAfterWrite // written, then the connection dropped
			case p.Method == "VerifyKeyLogin" && !loginWorks:
				return fake.FaultRefuse
			}
			return fake.FaultNone
		})
		job := e.deploy(k, srv, "")
		e.drain()
		v := e.job(job)
		if loginWorks {
			assert.Equal(t, "verified", v.Result["result"])
			assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
			assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID), "recorded")
			assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
		} else {
			assert.Equal(t, "uncertain", v.Result["result"], "S3: not undone while the unanswered send may still land")
			assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "an uncertain write is never re-sent blindly by the queue")
			assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
			e.clock.Advance(e.keys.UndoWait())
			e.drain()
			v = e.job(job)
			// The record owns the line (a complete listing proved it absent before the first send): removed.
			assert.Equal(t, "undone", v.Result["result"])
			assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint), "the uncertain line is removed by its fingerprint")
			assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "found by the listing: not sent again")
		}
	}
}

// S3: an uncertain write whose line is not there (yet) is not concluded "undone": the job waits until the
// helper's budget after the send has passed, then starts over; the late line is then found and removed.
func TestDeployLateWriteIsNeverConcludedUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	adds := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "AddAuthorizedKey":
			adds++
			if adds == 1 {
				return fake.FaultLateWrite // the call times out; the line lands later
			}
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusQueued, v.Status, "not concluded while the write may still land")
	assert.Equal(t, "sshkey.add_uncertain", v.LastErrorCode)
	assert.Equal(t, start.Add(helperproto.HelperBudget+30*time.Second), v.RunAt.UTC(), "the retry waits the helper's budget and 30 s")
	assert.Equal(t, 1, e.world.PendingLate())
	assert.Zero(t, e.audits("sshkey.add_failed"), "nothing recorded as undone")

	e.clock.Advance(helperproto.HelperBudget + 30*time.Second)
	require.Equal(t, 1, e.world.LateLanded(), "the stalled write landed after the call gave up")
	e.drain()
	v = e.job(job)
	// The next attempt finds the late line; the record owns it (absent before the first send): removed.
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "undone", v.Result["result"])
	assert.Equal(t, "sshkey.login_failed", v.LastErrorCode)
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint), "the late line was removed")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "found by the listing: not sent again")
}

func TestDeployAlreadyPresentIsNeverUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.world.Put(srv, "deploy", deployFile, k.PublicKey+" "+k.Comment) // already there (added by hand)
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "already_present", v.Result["result"])
	assert.Equal(t, "login_refused", v.Result["note"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "Alice did not add it, so it never removes it")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Zero(t, e.countEvents("AddAuthorizedKey"), "a line listed before any send: nothing is sent")
	assert.Zero(t, e.audits("sshkey.add_sent"), "and no send is recorded")
	assert.Equal(t, 1, e.discoveries(srv), "a discovery is queued so the record catches up with the file")
}

func TestDeployUndoFailedNeedsAttention(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		case "RemoveAuthorizedKey":
			return fake.FaultUnreachable
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.add_undo_failed", v.LastErrorCode)
	assert.Equal(t, "undo_failed", v.Result["result"])
	assert.Equal(t, true, v.Result["needs_attention"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "the line stays until a person or a later run removes it")
	assert.Equal(t, "sshkey.add_undo_failed", e.lastAuditDetail("sshkey.add_failed", "reason"))
	assert.Equal(t, 1, e.discoveries(srv), "a discovery is queued so the record catches up with the file")
	assert.Equal(t, "unreachable", e.targetStatus(srv), "the failed removal was a connection failure")
}

// A refusal of the add before anything was written ends the job; a retryable one is retried and audited
// only once it is final (scan row 10).
func TestDeployAddRefusals(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		e := newEnv(t)
		srv := e.server("web-01")
		k := e.generate("ci")
		e.setFault(func(p fake.FaultPoint) fake.Fault {
			if p.Method == "AddAuthorizedKey" {
				return fake.FaultRefuse
			}
			return fake.FaultNone
		})
		job := e.deploy(k, srv, "")
		e.drain()
		v := e.job(job)
		assert.Equal(t, jobs.StatusFailed, v.Status)
		assert.Equal(t, "ssh.helper_refused", v.LastErrorCode)
		assert.Equal(t, 1, e.audits("sshkey.add_failed"))
		assert.Zero(t, e.countEvents("VerifyKeyLogin"))
	})
	t.Run("unreachable then reachable", func(t *testing.T) {
		e := newEnv(t)
		srv := e.server("web-01")
		k := e.generate("ci")
		calls := 0
		e.setFault(func(p fake.FaultPoint) fake.Fault {
			if p.Method == "AddAuthorizedKey" {
				calls++
				if calls == 1 {
					return fake.FaultUnreachable
				}
			}
			return fake.FaultNone
		})
		job := e.deploy(k, srv, "")
		e.drain()
		assert.Equal(t, jobs.StatusQueued, e.job(job).Status)
		assert.Zero(t, e.audits("sshkey.add_failed"), "a retryable failure is not final")
		assert.Equal(t, "unreachable", e.targetStatus(srv))
		assert.Equal(t, start.Add(e.keys.UndoWait()), e.job(job).RunAt.UTC(), "the next send waits out this one (S3)")
		e.clock.Advance(e.keys.UndoWait())
		e.drain()
		v := e.job(job)
		assert.Equal(t, jobs.StatusSucceeded, v.Status)
		assert.Equal(t, "verified", v.Result["result"])
		assert.Zero(t, e.audits("sshkey.add_failed"))
	})
	t.Run("file changed on every attempt", func(t *testing.T) {
		e := newEnv(t)
		srv := e.server("web-01")
		k := e.generate("ci")
		e.setFault(func(p fake.FaultPoint) fake.Fault {
			if p.Method == "AddAuthorizedKey" {
				return fake.FaultFileChanged
			}
			return fake.FaultNone
		})
		job := e.deploy(k, srv, "")
		for range 3 {
			e.drain()
			e.clock.Advance(time.Hour)
		}
		v := e.job(job)
		assert.Equal(t, jobs.StatusDead, v.Status)
		assert.Equal(t, "ssh.file_changed", v.LastErrorCode)
		assert.Equal(t, 1, e.audits("sshkey.add_failed"), "audited once, on the last attempt")
		assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint))
	})
}

// The job reads the deploy again: a key retired after the request is refused, nothing is sent.
func TestDeployJobRefusedWhenTheKeyChanged(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", k.ID, e.clock.Now())
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.retired", v.LastErrorCode)
	assert.Empty(t, e.world.Events(), "nothing was sent")
	assert.Equal(t, "sshkey.retired", e.lastAuditDetail("sshkey.add_failed", "reason"))
}

// A server whose host key changed after the request is refused before anything is opened.
func TestDeployRefusesAChangedServer(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = 'host_key_changed' WHERE id = $1", srv)
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "target.host_key_changed", v.LastErrorCode)
	assert.Empty(t, e.world.Events())
}

// L-81 with the deploy job: queued before the lock, held, confirmed after the renewal.
func TestDeployHeldInLockThenConfirmed(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	e.gate.lock()
	e.drain()
	assert.Equal(t, jobs.StatusBlocked, e.job(job).Status)
	assert.Empty(t, e.world.Events(), "no remote command in lock")
	e.gate.unlock()
	e.drain()
	assert.Equal(t, jobs.StatusBlocked, e.job(job).Status, "it does not run on its own after the renewal (R29)")
	require.NoError(t, e.queue.Confirm(e.ctx, e.adminAudit, e.adminID, job))
	e.drain()
	assert.Equal(t, jobs.StatusSucceeded, e.job(job).Status)
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
}

// Alice is killed right after the add was written, before anything was recorded: after the restart the
// job runs again, finds the line it wrote, proves it with a login and records it once; nothing is sent
// twice blindly.
func TestDeployKilledAfterTheAddConverges(t *testing.T) {
	for _, point := range []string{"session:after:AddAuthorizedKey", "session:after:VerifyKeyLogin", "before:FinishDeploy"} {
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			srv := e.server("web-01")
			k := e.generate("ci")
			job := e.deploy(k, srv, "")
			kill := newKiller(point)
			e.setKiller(kill)
			e.drainDying()
			require.Equal(t, point, kill.firedAt())
			assert.Equal(t, jobs.StatusRunning, e.job(job).Status, "the dead process still holds the job")
			e.setKiller(nil)
			e.restart()
			e.drain()
			assert.Equal(t, "uncertain", e.job(job).Result["result"], "the killed send may still land: nothing is sent before the wait")
			e.clock.Advance(e.keys.UndoWait())
			e.drain()
			v := e.job(job)
			assert.Equal(t, jobs.StatusSucceeded, v.Status)
			assert.Equal(t, "verified", v.Result["result"], "the line found again is this job's own (record: absent before the first send)")
			assert.Equal(t, 1, e.audits("job.recovered"))
			assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID))
			assert.Len(t, e.world.Lines(srv, deployFile), 1, "one line, never two")
			assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
		})
	}
}

// A kill after the add with a refused login: the restarted job owns the line it finds (the record: a
// complete listing proved it absent before the first send) and removes it.
func TestDeployKilledWithARefusedLoginIsUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	kill := newKiller("session:after:AddAuthorizedKey")
	e.setKiller(kill)
	e.drainDying()
	require.Equal(t, "session:after:AddAuthorizedKey", kill.firedAt())
	e.setKiller(nil)
	e.restart()
	e.drain()
	assert.Equal(t, "uncertain", e.job(job).Result["result"], "the killed send may still land: nothing is sent before the wait")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"))
	e.clock.Advance(e.keys.UndoWait())
	e.drain()
	v := e.job(job)
	assert.Equal(t, "undone", v.Result["result"])
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint))
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "the second attempt found the line: nothing sent again")
	assert.Equal(t, 1, e.countEvents("VerifyKeyLogin"))
	assert.Equal(t, 1, e.countEvents("RemoveAuthorizedKey"))
	assert.Equal(t, 2, e.countEvents("ListKeys"), "the file is listed before each send")
}

// Review I1: a line that was there before the job is never removed, also on a retry after a send was
// recorded: ownership comes from a complete listing right before the send (or the helper's "written"),
// never from the attempt number or the send record alone.
func TestDeployRetryNeverRemovesALineThatWasThere(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	byHand := `from="10.0.0.0/8" ` + k.PublicKey + " " + k.Comment
	e.world.Put(srv, "deploy", deployFile, byHand) // Alice is outside from=: the login is refused
	calls, lists := 0, 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "ListKeys":
			if lists++; lists == 1 {
				return fake.FaultUnread // the first listing does not see the line
			}
		case "AddAuthorizedKey":
			calls++
			if calls == 1 {
				return fake.FaultUnreachable // a transient first attempt, nothing written
			}
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	require.Equal(t, jobs.StatusQueued, e.job(job).Status)
	require.Equal(t, 1, e.audits("sshkey.add_sent"), "a send is on record although nothing was written")
	e.clock.Advance(e.keys.UndoWait())
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "already_present", v.Result["result"])
	assert.Equal(t, []string{byHand}, e.world.Lines(srv, deployFile), "the line that was there is kept")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
}

// Review I1 (coordinator's case): the answer of the add is lost and the listing before the send did not
// read the file, so whose line it is cannot be known: the line is never removed; the deploy fails with
// sshkey.add_uncertain for a person, and a scan is queued.
func TestDeployUnknownOwnershipKeepsTheLine(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "ListKeys":
			return fake.FaultUnread
		case "AddAuthorizedKey":
			return fake.FaultAfterWrite
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.add_uncertain", v.LastErrorCode)
	assert.Equal(t, true, v.Result["needs_attention"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "kept: Alice cannot prove the line is hers")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
	assert.Zero(t, e.discoveries(srv), "no scan before a stalled write can land: the store's reconciliation queues it (N-m1)")
	assert.Equal(t, "sshkey.add_uncertain", e.lastAuditDetail("sshkey.add_failed", "reason"))
}

// Mirror of TestDeployRetryNeverRemovesALineThatWasThere: the line is absent with complete coverage before
// the first send, the add's answer is lost, the second attempt finds the line and the login is refused:
// the record owns the line, so the undo removes it.
func TestDeployOwnedLineWithLostAnswerIsUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	adds := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "AddAuthorizedKey":
			if adds++; adds == 1 {
				return fake.FaultAfterWrite // written, answer lost
			}
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	require.Equal(t, jobs.StatusQueued, e.job(job).Status, "waits out the lost send (S3)")
	assert.Equal(t, "complete", e.lastAuditDetail("sshkey.add_sent", "coverage_before"))
	e.clock.Advance(e.keys.UndoWait())
	e.drain()
	v := e.job(job)
	assert.Equal(t, "undone", v.Result["result"])
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint))
	assert.Equal(t, 1, e.removalsOf(k.Fingerprint))
}

// M7 (store reconciliation): a deploy killed on its last attempt after a send never reaches its handler
// again; the hourly task, once the wait after the send is over, records the unknown outcome once and
// queues a scan; it removes nothing.
func TestDeployKilledOnItsLastAttemptIsReconciled(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET attempts = max_attempts - 1 WHERE id = $1", job)
	require.NoError(t, err)
	kill := newKiller("session:after:AddAuthorizedKey")
	e.setKiller(kill)
	e.drainDying()
	require.Equal(t, "session:after:AddAuthorizedKey", kill.firedAt())
	e.setKiller(nil)
	e.restart()
	require.Equal(t, jobs.StatusDead, e.job(job).Status)
	_, err = e.keys.DestroyRetiredKeys(e.ctx) // the hourly task, before the wait: nothing yet
	require.NoError(t, err)
	assert.Zero(t, e.audits("sshkey.add_outcome_unknown"))
	e.clock.Advance(time.Hour)
	_, err = e.keys.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	_, err = e.keys.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, e.audits("sshkey.add_outcome_unknown"), "reconciled once")
	assert.Equal(t, 1, e.discoveries(srv))
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "nothing removed")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
}

// N-m5: a re-send answered "already present" on a line the record owns (an earlier send of this job wrote
// it) is an answered send: the undo does not wait for it, also on the last attempt.
func TestDeployAnsweredResendOnAnOwnedLineIsUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	lists := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "ListKeys":
			if lists++; lists > 1 {
				return fake.FaultUnread // later listings do not see the file: the job sends again
			}
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	kill := newKiller("session:after:VerifyKeyLogin") // attempt 1: added (answered), then killed
	e.setKiller(kill)
	e.drainDying()
	require.Equal(t, "session:after:VerifyKeyLogin", kill.firedAt())
	e.setKiller(nil)
	e.restart()
	e.drain() // attempt 2: inside the send's wait
	e.clock.Advance(e.keys.UndoWait())
	e.drain() // attempt 3, the last: re-send answered "already present", login refused
	v := e.job(job)
	assert.Equal(t, 3, v.Attempts)
	assert.Equal(t, "undone", v.Result["result"])
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint))
	assert.Equal(t, 2, e.countEvents("AddAuthorizedKey"))
}

// N-m8: a deploy whose context ends after a send (a shutdown, a slow host) is retried only after the send's
// wait (S3), as a lost lease would be.
func TestDeployInterruptedAfterASendKeepsTheWait(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	hung := false
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" && !hung {
			hung = true
			return fake.FaultHang
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusQueued, v.Status)
	assert.Equal(t, "ssh.timeout", v.LastErrorCode)
	assert.Equal(t, start.Add(e.keys.UndoWait()), v.RunAt.UTC(), "not before the send's wait")
	e.clock.Advance(e.keys.UndoWait())
	e.drain()
	assert.Equal(t, "verified", e.job(job).Result["result"])
}

// N-m6, the deploy path under every listing fault: a line that was there before the job is never removed,
// no other line is touched, and a line left in the file has a record (a location) or a failure a person
// sees (needs attention). Pre-existing line × first listing (complete, unread, partial) × add fault × login.
func TestDeployOwnershipUnderListingFaults(t *testing.T) {
	slots := make(chan struct{}, parallelScenarios)
	for _, pre := range []bool{false, true} {
		for _, listing := range []fake.Fault{fake.FaultNone, fake.FaultUnread, fake.FaultPartial} {
			for _, add := range []fake.Fault{fake.FaultNone, fake.FaultUnreachable, fake.FaultAfterWrite, fake.FaultLateWrite} {
				for _, refused := range []bool{false, true} {
					name := fmt.Sprintf("pre=%t/list=%d/add=%d/refused=%t", pre, listing, add, refused)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						slots <- struct{}{}
						defer func() { <-slots }()
						e := newEnv(t)
						srv := e.server("web-01")
						k := e.generate("ci")
						other := e.otherKeyLine(t)
						lines := []string{other}
						if pre {
							lines = append(lines, k.PublicKey+" "+k.Comment)
						}
						e.world.Put(srv, "deploy", deployFile, lines...)
						lists, adds := 0, 0
						e.setFault(func(p fake.FaultPoint) fake.Fault {
							switch p.Method {
							case "ListKeys":
								if lists++; lists == 1 {
									return listing
								}
							case "AddAuthorizedKey":
								if adds++; adds == 1 {
									return add
								}
							case "VerifyKeyLogin":
								if refused {
									return fake.FaultRefuse
								}
							}
							return fake.FaultNone
						})
						job := e.deploy(k, srv, "")
						for range 6 {
							e.drain()
							e.clock.Advance(e.keys.UndoWait() + time.Minute)
						}
						v := e.job(job)
						require.NotEqual(t, jobs.StatusQueued, v.Status, "the deploy ends")
						got := e.world.Lines(srv, deployFile)
						assert.Contains(t, got, other, "another key's line is never touched")
						for _, ev := range e.events("RemoveAuthorizedKey") {
							assert.Equal(t, k.Fingerprint, ev.Fingerprint)
						}
						if pre {
							assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "a line that was there before the job is never removed")
							assert.Zero(t, e.removalsOf(k.Fingerprint))
						}
						if e.world.Has(srv, deployFile, k.Fingerprint) {
							recorded := e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NULL", k.ID) > 0
							assert.True(t, recorded || v.Result["needs_attention"] == true,
								"a line left in the file has a record or a person looks (%s, %v)", v.Status, v.Result["result"])
						}
						if v.Result["result"] == "undone" {
							assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint))
						}
					})
				}
			}
		}
	}
}

// N-m2: a send whose helper call failed before anything was written owns nothing. The listing proved the
// line absent and the first add was refused before its write step; the same key is then added by hand with
// from=; the retry finds it, the login is refused: the line is the operator's and stays.
func TestDeployUnwrittenSendOwnsNothing(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	byHand := `from="10.0.0.0/8" ` + k.PublicKey + " " + k.Comment
	adds := 0
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "AddAuthorizedKey":
			if adds++; adds == 1 {
				return fake.FaultUnreachable
			}
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	e.drain()
	require.Equal(t, jobs.StatusQueued, e.job(job).Status)
	assert.Equal(t, "not_written", e.lastAuditDetail("sshkey.add_answered", "answer"))
	e.world.Put(srv, "deploy", deployFile, byHand)
	e.clock.Advance(e.keys.UndoWait())
	e.drain()
	v := e.job(job)
	assert.Equal(t, "already_present", v.Result["result"])
	assert.Equal(t, []string{byHand}, e.world.Lines(srv, deployFile), "the operator's line stays")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
}

// A deploy job of a key that is the new key of an unfinished rotation fails for good with
// sshkey.in_rotation (a rollback would remove the deployed line); nothing is sent.
func TestDeployOfARunsNewKeyIsRefused(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	require.Equal(t, sshkeys.StatusOverlap, e.run(r.ID).Status)
	_, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: *r.NewKeyID, TargetID: web, OSUser: "app", FilePath: keyFile("app")})
	require.ErrorIs(t, err, sshkeys.ErrInRotation, "refused at request time")
	job, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.SSHKeyAdd, Kind: jobs.KindUser, TargetID: web, CreatedBy: e.operator.UserID,
		Payload: map[string]string{"ssh_key_id": r.NewKeyID.String(), "os_user": "app", "file_path": keyFile("app"), "options": ""}})
	require.NoError(t, err)
	calls := e.worldCalls()
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status, "permanent: never retried")
	assert.Equal(t, "sshkey.in_rotation", v.LastErrorCode)
	assert.Equal(t, calls, e.worldCalls(), "nothing sent")
}

// The reconciliation also covers a last attempt that ended undo_failed while a send may still have
// landed (N-m1): one scan after the wait, nothing removed.
func TestDeployUndoFailedOnTheLastAttemptIsReconciled(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "AddAuthorizedKey":
			return fake.FaultLateWrite // every send stalls; the line lands later
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job := e.deploy(k, srv, "")
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET attempts = max_attempts - 1 WHERE id = $1", job)
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	require.Equal(t, "undo_failed", v.Result["result"], "the last attempt cannot wait out its own send")
	assert.Zero(t, e.discoveries(srv), "no scan before the stalled write can land")
	_, err = e.keys.DestroyRetiredKeys(e.ctx) // the hourly task, inside the wait: nothing yet
	require.NoError(t, err)
	assert.Zero(t, e.discoveries(srv))
	e.clock.Advance(time.Hour + time.Minute) // past the send's wait and the store's settle hour
	for range 2 {
		_, err = e.keys.DestroyRetiredKeys(e.ctx)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, e.discoveries(srv), "one scan after the wait")
	assert.Zero(t, e.removalsOf(k.Fingerprint), "nothing removed")
}

// L-29: a lock that begins after the runner's gate check (here: while the deploy is read again) lets no
// command reach the server; the job is held for a confirmation after the renewal.
func TestDeployLockedAfterTheClaimSendsNothing(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job := e.deploy(k, srv, "")
	kill := newKiller()
	kill.on = map[string]func(){"after:DeployJob": e.gate.lock}
	e.setKiller(kill)
	e.drain()
	e.setKiller(nil)
	assert.Empty(t, e.world.Events(), "no command in lock")
	assert.Zero(t, e.provider.Count("Open"))
	e.drain()
	assert.Equal(t, jobs.StatusBlocked, e.job(job).Status, "held for an Administrator after the renewal")
}
