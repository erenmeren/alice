//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/sshkeys"
)

// G3': a failed removal is retried only with a re-check strictly newer than the one used before and
// later than the failed send.
func TestRemovalRetryNeedsANewerRecheck(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r, loc := e.runInRemoving(k)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc, sshkeys.RemoveRecord{Definite: true, Reason: "ssh.helper_refused"}))
	assert.ErrorIs(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}), sshkeys.ErrNotYourTurn,
		"the same instant as the failed send")
	assert.Equal(t, "remove_failed", e.locState(e.run(r), "deploy"))
	e.clock.Advance(time.Second)
	e.removeAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, r))
	assert.Equal(t, "completed", e.run(r).Status)
}

// G16: add_sent_at is set when the location enters adding and never changes; a resumed add is
// recorded as a step, and the S3 wait of an undo counts from the latest send.
func TestResentAddKeepsItsFirstSendAndDelaysTheUndo(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	op, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	first := e.clock.Now()
	e.clock.Advance(10 * time.Second)
	op2, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	assert.Equal(t, op, op2)
	got := e.run(r.ID)
	assert.Equal(t, first, *got.Locations[0].AddSentAt, "add_sent_at never changes")
	assert.Equal(t, 1, e.count("SELECT add_resend_count FROM rotation_locations WHERE id = $1", loc), "the re-send is on the row (G25)")
	require.NoError(t, e.svc.Abort(e.ctx, e.admin, r.ID))
	e.clock.Set(first.Add(helperproto.HelperBudget + 30*time.Second))
	_, err = e.svc.BeginUndo(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "the re-send may still land")
	// G17: an adding row is never ended without a real undo attempt.
	assert.ErrorIs(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true, Reason: sshkeys.ReasonOldKeyGone}),
		sshkeys.ErrNotYourTurn)
	e.clock.Advance(10 * time.Second)
	e.undoAt(loc)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "aborted", e.run(r.ID).Status)
}
