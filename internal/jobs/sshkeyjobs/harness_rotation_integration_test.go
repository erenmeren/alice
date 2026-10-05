//go:build integration

package sshkeyjobs_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/keymat"
)

// place records a line of the key in the user's key file on the target (as a scan or a deploy records
// it) and writes the line into the world's file.
func (e *env) place(k sshkeys.ManagedKey, target uuid.UUID, user string) {
	e.t.Helper()
	e.placeWithOptions(k, target, user, "")
}

func (e *env) placeWithOptions(k sshkeys.ManagedKey, target uuid.UUID, user, options string) {
	e.t.Helper()
	e.placeIn(k, target, user, keyFile(user), options)
}

func (e *env) placeIn(k sshkeys.ManagedKey, target uuid.UUID, user, file, options string) {
	e.t.Helper()
	line, err := keymat.Line(options, k.PublicKey, k.Comment)
	require.NoError(e.t, err)
	lines := e.world.Lines(target, file)
	if !slices.Contains(lines, line) {
		lines = append(lines, line)
	}
	e.world.Put(target, user, file, lines...)
	require.NoError(e.t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		_, err := e.inv.RecordKeyAddedTx(e.ctx, tx, inventory.KeyAdded{SSHKeyID: k.ID, TargetID: target, OSUser: user, FilePath: file,
			Options: options, Comment: k.Comment, LineNo: slices.Index(lines, line) + 1, Actor: audit.SystemActor("test"), Verified: true})
		return err
	}))
}

// policy creates a policy on the key (90-day interval, the overlap in days, notice 24 h before).
func (e *env) policy(keyID uuid.UUID, overlapDays int) sshkeys.Policy {
	e.t.Helper()
	p, err := e.keys.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: keyID, Name: "policy " + keyID.String()[:8],
		IntervalDays: 90, OverlapDays: overlapDays, NotifyBeforeHours: 24})
	require.NoError(e.t, err)
	return p
}

// runNow previews the policy and starts a run with the previewed digest (the Administrator's Run now).
func (e *env) runNow(p sshkeys.Policy) sshkeys.Rotation {
	e.t.Helper()
	for {
		pv, err := e.keys.Preview(e.ctx, e.admin, p.ID)
		require.NoError(e.t, err)
		r, err := e.keys.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
		if errors.Is(err, sshkeys.ErrGenerateBusy) { // parallel scenarios share the generation slots
			time.Sleep(5 * time.Millisecond)
			continue
		}
		require.NoError(e.t, err)
		return r
	}
}

func (e *env) run(id uuid.UUID) sshkeys.Rotation {
	e.t.Helper()
	r, err := e.keys.Rotation(e.ctx, id)
	require.NoError(e.t, err)
	return r
}

// loc is the run's location of the user on the target.
func (e *env) loc(runID, target uuid.UUID, user string) sshkeys.RotationLocation {
	e.t.Helper()
	for _, l := range e.run(runID).Locations {
		if l.TargetID == target && l.OSUser == user {
			return l
		}
	}
	e.t.Fatalf("no location of %s", user)
	return sshkeys.RotationLocation{}
}

// sweep runs the rotation sweep once (the task rotation.sweep).
func (e *env) sweep() {
	e.t.Helper()
	_, err := e.keys.Sweep(e.ctx)
	require.NoError(e.t, err)
}

// finished reports whether the run reached a final status.
func finished(status string) bool {
	return slices.Contains([]string{sshkeys.StatusCompleted, sshkeys.StatusAborted, sshkeys.StatusNeedsAttention, sshkeys.StatusCancelled}, status)
}

// settleRun sweeps and drains a minute apart on the clock until the run is finished (at most 60 rounds).
func (e *env) settleRun(id uuid.UUID) sshkeys.Rotation {
	e.t.Helper()
	for range 60 {
		e.drain()
		r := e.run(id)
		if finished(r.Status) && e.liveLocationJobs() == 0 {
			return r
		}
		e.clock.Advance(time.Minute)
		e.sweep()
		if r.PausedLicense && !e.gate.locked.Load() {
			_ = e.keys.Continue(e.ctx, e.admin, id) // refused until the sweep queued the renewal notice
		}
	}
	return e.run(id)
}

func (e *env) liveLocationJobs() int {
	return e.count("SELECT count(*) FROM jobs WHERE type = 'rotation.location' AND status IN ('queued', 'running')")
}

// fileRef is one (target, file) of a key.
type fileRef struct {
	target uuid.UUID
	path   string
}

// files are the (target, file) pairs the key was placed in.
func (e *env) files(k sshkeys.ManagedKey) []fileRef {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT DISTINCT target_id, file_path FROM ssh_key_locations WHERE ssh_key_id = $1", k.ID)
	require.NoError(e.t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (fileRef, error) {
		var f fileRef
		err := r.Scan(&f.target, &f.path)
		return f, err
	})
	require.NoError(e.t, err)
	require.NotEmpty(e.t, out)
	return out
}

// removalsOf counts the removals of the fingerprint that changed a file (late landings included).
func (e *env) removalsOf(fp string) int {
	n := 0
	for _, ev := range e.world.Events() {
		if ev.Method == "RemoveAuthorizedKey" && ev.Fingerprint == fp && ev.Changed {
			n++
		}
	}
	return n
}

// mails are the params of every email of the template the module queued.
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

// usersOf are the users with a rotation location in the (target, file).
func (e *env) usersOf(target uuid.UUID, file string) []string {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT DISTINCT os_user FROM rotation_locations WHERE target_id = $1 AND file_path = $2", target, file)
	require.NoError(e.t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(e.t, err)
	return out
}

// assertEveryRemovalFollowedAFreshLogin is invariant I1, read from the world's own event log (never the
// store's belief): every removal of the old key that changed a file was sent right after a login with the
// new key, accepted, as a user of a rotation location in that file, on that server (no other call on the
// server in between), and for every user of a rotation location in that file an accepted login with the
// new key lies after the last change of the file before the removal. A late landing counts at the call
// that sent it.
func (e *env) assertEveryRemovalFollowedAFreshLogin(t *testing.T, oldFP, newFP string) {
	t.Helper()
	evs := e.world.Events()
	callAt := func(ev fake.Event) int { // index of the call that sent the change
		for i, x := range evs {
			if !x.Landed && x.N == ev.N {
				return i
			}
		}
		return -1
	}
	for i, ev := range evs {
		if ev.Method != "RemoveAuthorizedKey" || ev.Fingerprint != oldFP || !ev.Changed {
			continue
		}
		at := i
		if ev.Landed {
			at = callAt(ev)
		}
		require.GreaterOrEqual(t, at, 0)
		users := e.usersOf(ev.Target, ev.FilePath)
		require.NotEmpty(t, users, "a removal of the old key in a file without a rotation location (event %d)", ev.N)
		prev := -1
		for j := at - 1; j >= 0; j-- {
			if !evs[j].Landed && evs[j].Target == ev.Target {
				prev = j
				break
			}
		}
		require.GreaterOrEqual(t, prev, 0, "a removal without a login before it (event %d)", ev.N)
		p := evs[prev]
		assert.True(t, p.Method == "VerifyKeyLogin" && p.Fingerprint == newFP && p.Outcome == providers.KeyLoginAccepted &&
			slices.Contains(users, p.OSUser), "the call before the removal (event %d) is an accepted login with the new key: %+v", ev.N, p)
		sent := e.call(evs[at].N).begun
		for _, u := range users {
			// Every accepted login of the user with the new key since the file last changed (the add of
			// the new key is that change): the verification and the re-check (review I5).
			var logins []time.Time
			for j := at - 1; j >= 0; j-- {
				x := evs[j]
				if x.Target == ev.Target && x.FilePath == ev.FilePath && x.Changed && x.Method != "VerifyKeyLogin" {
					break // the file changed since: an earlier login does not count
				}
				if !x.Landed && x.Method == "VerifyKeyLogin" && x.Target == ev.Target && x.OSUser == u && x.Fingerprint == newFP &&
					x.Outcome == providers.KeyLoginAccepted {
					logins = append(logins, e.call(x.N).at)
				}
			}
			if !assert.GreaterOrEqual(t, len(logins), 2,
				"user %s of %s: a removal needs the verification and a later re-check, both accepted logins with the new key (event %d)",
				u, ev.FilePath, ev.N) {
				continue
			}
			latest, earliest := logins[0], logins[len(logins)-1]
			assert.True(t, latest.After(earliest), "the re-check is strictly later than the verification (event %d)", ev.N)
			assert.LessOrEqual(t, sent.Sub(latest), sshkeys.ReverifyFreshness, "the re-check is at most 15 minutes before the send (event %d)", ev.N)
		}
	}
}

// removeLine deletes every line of the key from the world's file (a person editing the file).
func (e *env) removeLine(target uuid.UUID, user, file, fp string) {
	e.t.Helper()
	var keep []string
	for _, l := range e.world.Lines(target, file) {
		if lineFP(e.t, l) != fp {
			keep = append(keep, l)
		}
	}
	e.world.Put(target, user, file, keep...)
}

func lineFP(t *testing.T, line string) string {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}
