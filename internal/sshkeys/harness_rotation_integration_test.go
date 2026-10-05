//go:build integration

package sshkeys_test

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/db"
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
