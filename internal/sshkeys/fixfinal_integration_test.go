//go:build integration

package sshkeys_test

import (
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
	"alice/internal/sshkeys"
)

// sibling records, as a scan does, a live place of the key for another user in the same file as the user's
// (an absolute AuthorizedKeysFile that a new account's sshd also reads): a place outside any run.
func (e *env) sibling(keyID, target uuid.UUID, user, file string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		var err error
		id, err = e.inv.RecordKeyAddedTx(e.ctx, tx, inventory.KeyAdded{SSHKeyID: keyID, TargetID: target, OSUser: user, FilePath: file,
			Comment: "x", LineNo: 1, Actor: audit.SystemActor("test")})
		return err
	}))
	return id
}

// FB-1 (old-key rule 2), the decision: a place of the old key that appeared during the overlap in the same
// file as a verified location, for a user the run never verified, keeps the old key in that file. The
// location ends kept_old (rotation.old_kept) and the run completes with the place counted as kept.
func TestOverlapEndKeepsOldForASiblingOutsideTheRun(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r, ids := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	e.sibling(k.ID, srv, "bob", keyFile("deploy"))
	e.clock.Advance(7 * 24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	require.Equal(t, "removing_old", got.Status)
	require.Len(t, got.Locations, 1)
	assert.Equal(t, ids["deploy"], got.Locations[0].ID)
	assert.Equal(t, "kept_old", got.Locations[0].State)
	assert.Zero(t, e.jobsOf("remove"), "no removal is queued")
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got = e.run(r.ID)
	assert.Equal(t, "completed", got.Status)
	assert.Equal(t, 1, got.KeptCount)
	assert.Len(t, e.mails(sshkeys.TemplateCompletedPartial), 1)
}

// FB-1, a sibling that is missing, or that Alice removed, is not live and does not block the file.
func TestOverlapEndIgnoresADeadSiblingOutsideTheRun(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r, _ := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted})
	require.Equal(t, "overlap", r.Status)
	sib := e.sibling(k.ID, srv, "bob", keyFile("deploy"))
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_key_locations SET missing_since = $2 WHERE id = $1", sib, e.clock.Now())
	require.NoError(t, err)
	e.sibling(k.ID, srv, "carol", "/etc/ssh/keys/elsewhere") // another file of the same server does not block
	e.clock.Advance(7 * 24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	got := e.run(r.ID)
	require.Equal(t, "removing_old", got.Status)
	assert.Equal(t, "verified", got.Locations[0].State)
	assert.Equal(t, 1, e.jobsOf("remove"))
}

// FB-1, the store: a sibling that appears between the decision (the overlap's end) and the send is
// refused at BeginRemove with ErrNotYourTurn; nothing changes. Once that place is gone (missing), the
// removal may be sent.
func TestBeginRemoveRefusesASiblingOutsideTheRun(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	_, loc := e.runInRemoving(k)
	sib := e.sibling(k.ID, srv, "bob", keyFile("deploy"))
	e.clock.Advance(time.Minute)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	require.ErrorIs(t, err, sshkeys.ErrNotYourTurn)
	assert.Equal(t, 0, e.count("SELECT count(*) FROM rotation_locations WHERE id = $1 AND (state <> 'verified' OR remove_op_id IS NOT NULL)", loc),
		"the location is still verified and no removal was sent")

	_, err = e.db.Owner.Exec(e.ctx, "UPDATE ssh_key_locations SET missing_since = $2 WHERE id = $1", sib, e.clock.Now())
	require.NoError(t, err)
	op, err := e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, op)
}
