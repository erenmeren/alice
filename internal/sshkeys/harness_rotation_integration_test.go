//go:build integration

package sshkeys_test

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/sshkeys"
)

// keyFile is the authorized_keys file of a user on the helper servers of these tests.
func keyFile(user string) string {
	if user == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return "/home/" + user + "/.ssh/authorized_keys"
}

// deployed generates a key and records it in the user's key file on the target, as a verified
// deploy does.
func (e *env) deployed(label string, target uuid.UUID, user string) sshkeys.ManagedKey {
	e.t.Helper()
	k := e.generate(label)
	e.addLocation(k.ID, target, user)
	return k
}

// addLocation records a line of the key in the user's key file on the target (RecordKeyAddedTx).
func (e *env) addLocation(keyID, target uuid.UUID, user string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		var comment string
		if err := tx.QueryRow(e.ctx, "SELECT key_comment FROM ssh_keys WHERE id = $1", keyID).Scan(&comment); err != nil {
			return err
		}
		var err error
		id, err = e.inv.RecordKeyAddedTx(e.ctx, tx, inventory.KeyAdded{SSHKeyID: keyID, TargetID: target, OSUser: user, FilePath: keyFile(user),
			Comment: comment, LineNo: 1, Actor: audit.SystemActor("test"), Verified: true})
		return err
	}))
	return id
}

func (e *env) policy(keyID uuid.UUID, interval, overlapDays, notifyHours int) sshkeys.Policy {
	e.t.Helper()
	p, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: keyID, Name: "policy " + keyID.String()[:8],
		IntervalDays: interval, OverlapDays: overlapDays, NotifyBeforeHours: notifyHours})
	require.NoError(e.t, err)
	return p
}

func (e *env) enabledPolicy(keyID uuid.UUID, interval, overlapDays, notifyHours int) sshkeys.Policy {
	e.t.Helper()
	p := e.policy(keyID, interval, overlapDays, notifyHours)
	p, err := e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	require.NoError(e.t, err)
	return p
}

func (e *env) reloadPolicy(id uuid.UUID) sshkeys.Policy {
	e.t.Helper()
	p, err := e.svc.Policy(e.ctx, id)
	require.NoError(e.t, err)
	return p
}

func (e *env) run(id uuid.UUID) sshkeys.Rotation {
	e.t.Helper()
	r, err := e.svc.Rotation(e.ctx, id)
	require.NoError(e.t, err)
	return r
}

// onlyRun is the one run of the policy (the test fails when there is not exactly one).
func (e *env) onlyRun(policyID uuid.UUID) sshkeys.Rotation {
	e.t.Helper()
	require.Equal(e.t, 1, e.count("SELECT count(*) FROM rotations WHERE policy_id = $1", policyID))
	var id uuid.UUID
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM rotations WHERE policy_id = $1", policyID).Scan(&id))
	return e.run(id)
}

// runNow previews the policy and starts a run with the previewed digest.
func (e *env) runNow(p sshkeys.Policy) sshkeys.Rotation {
	e.t.Helper()
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(e.t, err)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(e.t, err)
	return r
}

// mails are the params of every email of the template the module asked for.
func (e *env) mails(template string) []map[string]string {
	e.notifier.mu.Lock()
	defer e.notifier.mu.Unlock()
	var out []map[string]string
	for _, c := range e.notifier.calls {
		if c.template == template {
			out = append(out, c.params)
		}
	}
	return out
}

// openRun is the id of the policy's unfinished run.
func (e *env) openRun(policyID uuid.UUID) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, `SELECT id FROM rotations WHERE policy_id = $1
AND status NOT IN ('completed', 'aborted', 'needs_attention', 'cancelled')`, policyID).Scan(&id))
	return id
}

// claimJob inserts a running rotation.location job (attempt 1) and returns its id.
func (e *env) claimJob() uuid.UUID {
	e.t.Helper()
	id, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.Type{Name: sshkeys.JobRotationLocation, Class: license.ClassAlways},
		Kind: jobs.KindSystem, Payload: map[string]string{"n": uuid.NewString()}})
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'running', attempts = 1, started_at = $2 WHERE id = $1", id, e.clock.Now())
	require.NoError(e.t, err)
	return id
}

// claimed is a context carrying the claim of a running location job (as the runner's).
func (e *env) claimed() context.Context {
	e.t.Helper()
	if e.claim == uuid.Nil {
		e.claim = e.claimJob()
	}
	return inventory.WithClaim(e.ctx, inventory.Claim{JobID: e.claim, Attempt: 1})
}

// lostClaim is a context whose job was taken back (its own job, so claimed() stays valid).
func (e *env) lostClaim() context.Context {
	e.t.Helper()
	id := e.claimJob()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'queued' WHERE id = $1", id)
	require.NoError(e.t, err)
	return inventory.WithClaim(e.ctx, inventory.Claim{JobID: id, Attempt: 1})
}

func (e *env) jobActor() audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: e.claim.String()}
}

// locState is the state of the run's location of the user.
func (e *env) locState(r sshkeys.Rotation, user string) string {
	e.t.Helper()
	for _, l := range e.run(r.ID).Locations {
		if l.OSUser == user {
			return l.State
		}
	}
	e.t.Fatalf("no location of %s", user)
	return ""
}

// drive adds the new key at a location and records the login outcome, as the add job does.
func (e *env) drive(loc uuid.UUID, outcome providers.KeyLoginOutcome) {
	e.t.Helper()
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(e.t, err)
	require.NoError(e.t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
	if outcome != "" {
		require.NoError(e.t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: outcome}))
	}
}

// runToDecisionWith runs a policy with a 7-day overlap on the key, drives every location with the
// outcome of its user and advances once; it returns the run and the location ids by user.
func (e *env) runToDecisionWith(k sshkeys.ManagedKey, outcomes map[string]providers.KeyLoginOutcome) (sshkeys.Rotation, map[string]uuid.UUID) {
	e.t.Helper()
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	ids := map[string]uuid.UUID{}
	for _, l := range r.Locations {
		ids[l.OSUser] = l.ID
		if l.State == "planned" {
			e.drive(l.ID, outcomes[l.OSUser])
		}
	}
	require.NoError(e.t, e.svc.Advance(e.ctx, r.ID))
	return e.run(r.ID), ids
}

// runInRemoving drives a run with one accepted location through the overlap: the run is removing_old.
func (e *env) runInRemoving(k sshkeys.ManagedKey) (uuid.UUID, uuid.UUID) {
	e.t.Helper()
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(e.t, "overlap", r.Status)
	e.clock.Advance(7 * 24 * time.Hour)
	require.NoError(e.t, e.svc.Advance(e.ctx, r.ID))
	require.Equal(e.t, "removing_old", e.run(r.ID).Status)
	return r.ID, ids["deploy"]
}

// removeAt drives a removal at a location of a run in removing_old: re-check, begin, finish.
func (e *env) removeAt(loc uuid.UUID) {
	e.t.Helper()
	require.NoError(e.t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(e.t, err)
	require.NoError(e.t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Removed: 1,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}}))
}

// undoAt drives an undo at a location of a rolling-back run.
func (e *env) undoAt(loc uuid.UUID) {
	e.t.Helper()
	_, err := e.svc.BeginUndo(e.claimed(), loc)
	require.NoError(e.t, err)
	require.NoError(e.t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1}}))
}

// jobsOf counts the rotation.location jobs of a phase.
func (e *env) jobsOf(phase string) int {
	return e.count("SELECT count(*) FROM jobs WHERE type = 'rotation.location' AND payload->>'phase' = $1", phase)
}
