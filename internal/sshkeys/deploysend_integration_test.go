//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// Store request S-1: every send of a deploy job is recorded durably before the helper call, in a
// claim-fenced transaction; the job learns whether a send by THIS job is on record, and when its undo
// may start.
func TestDeploySendsAreRecorded(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	jobID, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'running', attempts = 1 WHERE id = $1", jobID)
	require.NoError(t, err)
	claimed := inventory.WithClaim(e.ctx, inventory.Claim{JobID: jobID, Attempt: 1})
	d, err := e.svc.DeployJob(claimed, jobID, srv, e.job(jobID).Payload)
	require.NoError(t, err)

	rec, err := e.svc.DeploySends(claimed, jobID)
	require.NoError(t, err)
	assert.Zero(t, rec.Count, "nothing sent yet")
	assert.True(t, rec.UndoNotBefore(e.svc.UndoWait(), true).IsZero())

	first := e.clock.Now()
	s1, err := e.svc.BeginDeploySend(claimed, jobID, d)
	require.NoError(t, err)
	assert.False(t, s1.Resend)
	assert.Equal(t, jobID, s1.OperationID)
	e.clock.Advance(20 * time.Second)
	s2, err := e.svc.BeginDeploySend(claimed, jobID, d)
	require.NoError(t, err)
	assert.True(t, s2.Resend, "a send by this job is on record")
	rec, err = e.svc.DeploySends(claimed, jobID)
	require.NoError(t, err)
	assert.Equal(t, 2, rec.Count)
	assert.Equal(t, first, rec.FirstAt)
	assert.Equal(t, e.clock.Now(), rec.LastAt)
	wait := e.svc.UndoWait()
	assert.Equal(t, helperproto.HelperBudget+30*time.Second, wait)
	assert.Equal(t, rec.LastAt.Add(wait), rec.UndoNotBefore(wait, false), "the latest send is unanswered")
	assert.Equal(t, first.Add(wait), rec.UndoNotBefore(wait, true), "the latest send answered: the earlier one may still run")

	// A job that lost its claim records nothing.
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE jobs SET status = 'queued' WHERE id = $1", jobID)
	require.NoError(t, err)
	_, err = e.svc.BeginDeploySend(claimed, jobID, d)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.ErrorIs(t, e.svc.FinishDeploy(claimed, e.jobActor(), d, sshkeys.DeployOutcome{Result: sshkeys.DeployFailed, Reason: "ssh.unreachable"}),
		inventory.ErrClaimLost, "a failure record is claim-fenced too")
	assert.Zero(t, e.audits("sshkey.add_failed"))
	// Another job's sends are not this job's.
	rec, err = e.svc.DeploySends(e.ctx, uuid.New())
	require.NoError(t, err)
	assert.Zero(t, rec.Count)
}
