//go:build integration

package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Licence lock and rotation over the wire (L-29, L-83..L-88 at API level, S6): the lock comes from the real licence
// service (the evaluation ends after 30 days on the stack's clock), the renewal is a licence upload by the
// Administrator, the scheduled work runs through the real scheduler and its gate.

// lockNow moves the clock past the end of the evaluation (31 days after setup at most) and requires the lock.
func (e *keyEnv) lockNow() {
	e.t.Helper()
	end := e.license.Snapshot().Eval.EndsAt
	e.advance(end.Sub(e.clock.Now()) + time.Hour)
	require.True(e.t, e.license.Snapshot().Eval.Locked(), "the evaluation ended: locked")
}

// renew uploads a licence for a year as the stepped-up Administrator (allowed in lock) and requires the gate open.
func (e *keyEnv) renew() {
	e.t.Helper()
	e.stepUp(e.admin, e.adminAcct)
	now := e.clock.Now()
	rec := e.admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": e.signedLicense("LIC-RENEW", now, now.AddDate(1, 0, 0), 10)})
	requireStatus(e.t, rec, http.StatusOK)
	require.False(e.t, e.license.Snapshot().Eval.Locked())
}

// hourly runs the scheduled work (the three rotation tasks, then the jobs) every hour for d.
func (e *keyEnv) hourly(d time.Duration) {
	e.t.Helper()
	for end := e.clock.Now().Add(d); e.clock.Now().Before(end); {
		e.clock.Advance(time.Hour)
		require.NoError(e.t, e.license.Tick(context.Background()))
		_ = e.task("rotation.plan")
		_ = e.task("rotation.sweep")
		_ = e.task("sshkey.destroy_retired")
		e.drain()
	}
	for c, a := range e.clients {
		e.signIn(c, a)
	}
}

// phase6Rows counts the rows a lock must never delete.
func (e *keyEnv) phase6Rows() map[string]int {
	out := map[string]int{}
	for _, t := range []string{"ssh_keys", "managed_private_keys", "ssh_key_locations", "rotation_policies", "rotations", "rotation_locations",
		"rotation_steps"} {
		out[t] = e.count(t)
	}
	return out
}

// overlapRun is a run of a deployed key with the given overlap, started now and verified (status overlap).
func (e *keyEnv) overlapRun(overlapDays int) (keyLine, string, string) {
	e.t.Helper()
	k := e.generate(e.admin, "locked", "ed25519")
	e.deployed(k)
	policyID, _ := e.createPolicy(e.admin, k.id, overlapDays)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	require.Equal(e.t, "overlap", e.run(e.admin, runID).Status)
	return k, policyID, runID
}

// lockedOverlap is L-83's start: a run in overlap whose end comes 3 days after the lock begins; the lock begins.
func lockedOverlap(t *testing.T) (*keyEnv, keyLine, string, string) {
	e := newKeyEnv(t)
	until := e.license.Snapshot().Eval.EndsAt.Add(4 * 24 * time.Hour)
	days := int(until.Sub(e.clock.Now()).Hours() / 24)
	k, policyID, runID := e.overlapRun(days)
	e.lockNow()
	return e, k, policyID, runID
}

// phase6Writes are the Phase 6 routes that change something, with a body each would accept.
func (e *keyEnv) phase6Writes(keyID, policyID, runID, etag string) []struct {
	method, path string
	body         any
	header       []reqOpt
} {
	type w = struct {
		method, path string
		body         any
		header       []reqOpt
	}
	p := "/api/v1/rotation/policies/" + policyID
	r := "/api/v1/rotation/runs/" + runID
	ifm := []reqOpt{withHeader("If-Match", etag)}
	return []w{
		{http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": "in lock", "key_type": "ed25519"}, nil},
		{http.MethodPost, "/api/v1/ssh-keys/" + keyID + "/actions/deploy", map[string]any{"target_id": e.targetID, "os_user": "root", "file_path": rootKeysPath}, nil},
		{http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": keyID, "name": "in lock", "interval_days": 30}, nil},
		{http.MethodPatch, p, map[string]any{"name": "renamed"}, ifm},
		{http.MethodDelete, p, nil, ifm},
		{http.MethodPost, p + "/actions/enable", nil, ifm},
		{http.MethodPost, p + "/actions/disable", nil, ifm},
		{http.MethodPost, p + "/actions/preview", nil, nil},
		{http.MethodPost, p + "/actions/run", map[string]string{"plan_digest": strings.Repeat("a", 64)}, nil},
		{http.MethodPost, r + "/actions/continue", nil, nil},
		{http.MethodPost, r + "/actions/finish-now", nil, nil},
		{http.MethodPost, r + "/actions/keep-old", map[string]any{"location_ids": []string{runID}}, nil},
	}
}

// TestRotationInLockRunsNoCommand is L-29 and L-83 for rotation over the wire: a run in overlap when the licence locks;
// every Phase 6 route that changes something answers 403 ALC-LIC-0001 except the download (R41 row 5) and Stop and undo
// (L-86); three days of the scheduler's rotation.plan, rotation.sweep and sshkey.destroy_retired, during which the
// overlap ends, send no command to the server and delete no row; the run stays in overlap, paused_license, with both
// keys in the file, one email, and only Stop and undo offered.
func TestRotationInLockRunsNoCommand(t *testing.T) {
	e, k, policyID, runID := lockedOverlap(t)
	etag := e.admin.do(http.MethodGet, "/api/v1/rotation/policies/"+policyID, nil).Header().Get("ETag")
	commands := len(e.f.server.Commands())
	rows := e.phase6Rows()
	denied := e.deniedRefusals()

	e.stepUp(e.admin, e.adminAcct)
	for _, w := range e.phase6Writes(k.id, policyID, runID, etag) {
		requireError(t, e.admin.do(w.method, w.path, w.body, w.header...), http.StatusForbidden, "ALC-LIC-0001")
	}
	assert.Equal(t, len(e.phase6Writes(k.id, policyID, runID, etag)), e.deniedRefusals()-denied, "every refusal audited")
	rec := download(e.admin, k.id, downloadReason, nil)
	requireStatus(t, rec, http.StatusOK)
	_, err := ssh.ParsePrivateKey(rec.Body.Bytes())
	require.NoError(t, err, "the download is allowed in lock")

	e.hourly(3*24*time.Hour + time.Hour)
	assert.Len(t, e.f.server.Commands(), commands, "no remote command in lock (L-29)")
	assert.Equal(t, []string{deployKeysPath, deployKeysPath}, e.f.emu.Writes(), "only the deploy and the run's add before the lock wrote")
	after := e.phase6Rows()
	for table, n := range rows {
		assert.GreaterOrEqual(t, after[table], n, "no row of %s deleted", table)
	}
	r := e.run(e.admin, runID)
	assert.Equal(t, "overlap", r.Status)
	assert.True(t, r.PausedLicense, "the overlap's end in lock pauses the run (L-83)")
	assert.True(t, r.OverlapUntil.Before(e.clock.Now()), "the overlap timer has ended")
	assert.Equal(t, []string{"abort"}, r.ActionsAllowed)
	require.NotNil(t, r.NoticeState)
	assert.Equal(t, "rotation.paused_license", r.NoticeState["reason"])
	file := e.f.file(deployKeysPath)
	assert.Contains(t, file, k.blob(), "the old key stays")
	assert.Contains(t, file, newBlob(t, e, r), "the new key stays")
	assert.Equal(t, 1, e.outboxTemplates()["rotation.paused_license"])
	assert.Zero(t, e.auditCount("sshkey.removed"))
	e.assertGETsChangeNothing(k.id, policyID, runID)
}

// newBlob is the run's new key as "type base64".
func newBlob(t *testing.T, e *keyEnv, r runDoc) string {
	t.Helper()
	require.NotNil(t, r.NewSSHKeyID)
	k := decodeBody[map[string]any](t, e.admin.do(http.MethodGet, "/api/v1/ssh-keys/"+*r.NewSSHKeyID, nil))
	f := strings.Fields(k["public_key"].(string))
	return f[0] + " " + f[1]
}

// TestContinueAfterRenewalOverTheWire is L-84 over the wire (S6, R29): from L-83, a renewal after 20 days of lock; the
// run stays paused; Continue is not offered and is refused 409 ALC-ROT-0021 until the sweep has queued the renewal
// notice; then it is offered, refused without step-up and for a token, and accepted with step-up; the removal follows
// only after a fresh login with the new key; one rotation.preview_after_license email.
func TestContinueAfterRenewalOverTheWire(t *testing.T) {
	e, k, policyID, runID := lockedOverlap(t)
	token, _ := createToken(t, e.stack, e.admin, e.adminAcct, "operate", 60)
	api := e.client("198.51.100.80")
	api.bearer = token
	e.hourly(3*24*time.Hour + time.Hour)
	e.advance(17 * 24 * time.Hour)
	e.sweep(1)
	removals := e.auditCount("sshkey.removed")
	e.renew()

	r := e.run(e.admin, runID)
	assert.True(t, r.PausedLicense, "still paused after the renewal (R29)")
	assert.NotContains(t, r.ActionsAllowed, "continue", "not before the renewal notice")
	require.NotNil(t, r.NoticeState)
	assert.Equal(t, "rotation.notice_pending", r.NoticeState["reason"])
	assert.Equal(t, "ALC-ROT-0021", r.NoticeState["code"])
	e.stepUp(e.admin, e.adminAcct)
	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/continue", nil)
	requireError(t, rec, http.StatusConflict, "ALC-ROT-0021")
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
	assert.Zero(t, e.outboxTemplates()["rotation.preview_after_license"])

	require.NoError(t, e.task("rotation.sweep"))
	e.drain()
	assert.Equal(t, 1, e.outboxTemplates()["rotation.preview_after_license"], "the sweep tells the Administrators first")
	r = e.run(e.admin, runID)
	assert.True(t, r.PausedLicense)
	assert.Equal(t, []string{"continue", "abort"}, r.ActionsAllowed)
	assert.Equal(t, removals, e.auditCount("sshkey.removed"), "nothing removed before Continue")
	assert.Contains(t, e.f.file(deployKeysPath), k.blob())

	requireError(t, api.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/continue", nil), http.StatusForbidden, "ALC-AUTH-0002")
	e.advance(6 * time.Minute)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/continue", nil), http.StatusForbidden, "ALC-AUTH-0003")
	e.stepUp(e.admin, e.adminAcct)
	continued := e.clock.Now()
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/continue", nil), http.StatusNoContent)
	e.advance(time.Minute)
	e.sweep(3)
	r = e.run(e.admin, runID)
	require.Equal(t, "completed", r.Status, "%+v", r)
	re, err := time.Parse(time.RFC3339Nano, r.Locations[0]["reverified_at"].(string))
	require.NoError(t, err)
	assert.False(t, re.Before(continued), "the removal followed a fresh login after Continue")
	assert.NotContains(t, e.f.file(deployKeysPath), k.blob())
	assert.Contains(t, e.f.file(deployKeysPath), newBlob(t, e, r))
	assert.Equal(t, 1, e.outboxTemplates()["rotation.preview_after_license"], "Continue sends no second notice")
	assert.Equal(t, 1, e.auditCount("rotation.continued"))
	_ = policyID
}

// TestAbortInLockUndoesOverTheWire (L-86 for Stop and undo): in lock an Administrator's operate token stops the run
// without step-up; the undo runs in lock and removes only the new key; the old key and every other line stay.
func TestAbortInLockUndoesOverTheWire(t *testing.T) {
	e := newKeyEnv(t)
	k, _, runID := e.overlapRun(60)
	before := e.f.file(deployKeysPath)
	r := e.run(e.admin, runID)
	nb := newBlob(t, e, r)
	e.lockNow()
	token, _ := createToken(t, e.stack, e.admin, e.adminAcct, "operate", 30)
	api := e.client("198.51.100.81")
	api.bearer = token
	require.Equal(t, []string{"abort"}, decodeBody[runDoc](t, api.do(http.MethodGet, "/api/v1/rotation/runs/"+runID, nil)).ActionsAllowed)
	requireStatus(t, api.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/abort", nil), http.StatusNoContent)
	e.drain()
	e.sweep(2)
	r = e.run(e.admin, runID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.stopped", r.Result["reason"])
	after := e.f.file(deployKeysPath)
	assert.NotContains(t, after, nb, "the undo removed the new key in lock")
	assert.Contains(t, after, k.blob(), "the old key is untouched")
	assert.Equal(t, strings.Join(withoutLine(before, nb), "\n"), strings.TrimSuffix(after, "\n"), "every other line stays")
	assert.Equal(t, 1, e.auditCount("rotation.stop_requested"))
}

// withoutLine are the lines of text without the one holding blob.
func withoutLine(text, blob string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if !strings.Contains(l, blob) {
			out = append(out, l)
		}
	}
	return out
}

// lockDuringAdd makes the first add written to path on f begin the lock (as the clock reaches the evaluation's end
// while the helper writes); the write itself proceeds.
func (e *keyEnv) lockDuringAdd(f *sshFixture, path string) {
	var once bool
	f.emu.BeforeWrite(func(p string) {
		if p != path || once {
			return
		}
		once = true
		end := e.license.Snapshot().Eval.EndsAt
		e.clock.Advance(end.Sub(e.clock.Now()) + time.Hour)
		require.NoError(e.t, e.license.Tick(context.Background()))
	})
}

// TestL85AndL86LockDuringTheAddOverTheWire: the lock begins while the run's first add is being written. L-85: that add
// completes and its verification runs; nothing more is added (the second server sees no write) and nothing is
// removed; the run is paused in adding_new. L-86: the new key's login is then refused: the run rolls back in lock, the
// undo removes the new key it added, the old key is untouched, and the run ends aborted.
func TestL85AndL86LockDuringTheAddOverTheWire(t *testing.T) {
	t.Run("L-85", func(t *testing.T) {
		e := newKeyEnv(t)
		f2, t2 := e.addKeyServer("web-02")
		k := e.generate(e.admin, "two servers", "ed25519")
		e.deployed(k)
		job := e.deploy(e.admin, k.id, t2, "deploy", deployKeysPath)
		e.drain()
		require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
		policyID, _ := e.createPolicy(e.admin, k.id, 7)
		p := e.preview(e.admin, policyID)
		require.Equal(t, 2, p.ChangeCount)
		first, second := e.f, f2
		if p.Actions[0]["target_id"] == t2 {
			first, second = f2, e.f
		}
		e.lockDuringAdd(first, deployKeysPath)
		w2 := len(second.helperWrites())
		runID := e.runNow(policyID, p.PlanDigest)
		e.drain()
		require.True(t, e.license.Snapshot().Eval.Locked())
		e.hourly(6 * time.Hour)
		r := e.run(e.admin, runID)
		assert.Equal(t, "adding_new", r.Status)
		assert.True(t, r.PausedLicense)
		states := map[string]string{}
		for _, l := range r.Locations {
			states[l["target_id"].(string)] = l["state"].(string)
		}
		firstID := e.targetID
		if first == f2 {
			firstID = t2
		}
		assert.Equal(t, "verified", states[firstID], "the add in flight completed and was verified")
		assert.Len(t, second.helperWrites(), w2, "no further add in lock")
		assert.Zero(t, e.auditCount("sshkey.removed"))
		assert.Equal(t, 1, e.outboxTemplates()["rotation.paused_license"])
	})

	t.Run("L-86", func(t *testing.T) {
		e := newKeyEnv(t)
		k := e.generate(e.admin, "refused", "ed25519")
		e.deployed(k)
		original := e.f.file(deployKeysPath)
		// From now on only the old key (and Alice's) logs in as deploy: the new key's test login is refused.
		e.f.server.SetLoginCheck(func(user string, key ssh.PublicKey) bool {
			return bytes.Equal(key.Marshal(), k.pub.Marshal()) && e.f.emu.AcceptsLogin(user, key)
		})
		e.lockDuringAdd(e.f, deployKeysPath)
		policyID, _ := e.createPolicy(e.admin, k.id, 7)
		runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
		e.drain()
		require.True(t, e.license.Snapshot().Eval.Locked())
		e.hourly(3 * time.Hour)
		r := e.run(e.admin, runID)
		assert.Equal(t, "aborted", r.Status, "%+v", r)
		assert.Equal(t, "rotation.verify_failed", r.Result["reason"])
		assert.Equal(t, "undone", r.Locations[0]["state"])
		assert.Equal(t, original, e.f.file(deployKeysPath), "the new key was removed, the old key and every byte stay")
		assert.Positive(t, e.auditCount("rotation.location_changed"))
		assert.Equal(t, 1, e.outboxTemplates()["rotation.aborted"])
	})
}

// TestDecisionDeadlineDoesNotRunInLock (S6) over the wire: a run waits for the Administrator's decision on a place
// that cannot be tested (root with PermitRootLogin no); the licence locks; Keep old and Finish now answer 403
// ALC-LIC-0001; 20 days of lock pass the 14-day decision deadline without rolling the run back; after the renewal, the
// renewal notice and Continue, the deadline has moved by the pause and Keep old (step-up) carries the run on.
func TestDecisionDeadlineDoesNotRunInLock(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "undecided", "ed25519")
	e.deployed(k)
	job := e.deploy(e.admin, k.id, e.targetID, "root", rootKeysPath)
	e.drain()
	require.Equal(t, "succeeded", e.job(e.admin, job)["status"])
	e.f.emu.SetSSHD(strings.Replace(sshdOf(e.f), "permitrootlogin prohibit-password", "permitrootlogin no", 1))
	e.discover(e.targetID)
	// Start late in the evaluation, so the lock comes before the 14-day deadline.
	e.advance(e.license.Snapshot().Eval.EndsAt.Sub(e.clock.Now()) - 5*24*time.Hour)
	policyID, _ := e.createPolicy(e.admin, k.id, 1)
	runID := e.runNow(policyID, e.preview(e.admin, policyID).PlanDigest)
	e.drain()
	e.sweep(1)
	r := e.run(e.admin, runID)
	require.Equal(t, "verifying_new", r.Status, "%+v", r)
	require.NotNil(t, r.DecisionDueAt)
	due := *r.DecisionDueAt
	var rootLoc string
	for _, l := range r.Locations {
		if l["os_user"] == "root" {
			rootLoc = l["id"].(string)
			assert.Equal(t, "unverifiable", l["state"])
		}
	}
	require.NotEmpty(t, rootLoc)
	assert.ElementsMatch(t, []string{"keep_old", "abort"}, r.ActionsAllowed)

	e.lockNow()
	e.stepUp(e.admin, e.adminAcct)
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/keep-old", map[string]any{"location_ids": []string{rootLoc}}),
		http.StatusForbidden, "ALC-LIC-0001")
	requireError(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/finish-now", nil), http.StatusForbidden, "ALC-LIC-0001")
	lockedAt := e.clock.Now()
	e.hourly(24 * time.Hour)
	assert.Equal(t, []string{"abort"}, e.run(e.admin, runID).ActionsAllowed)
	e.advance(19 * 24 * time.Hour)
	e.sweep(2)
	require.True(t, e.clock.Now().After(due), "the original deadline has passed in lock")
	r = e.run(e.admin, runID)
	assert.Equal(t, "verifying_new", r.Status, "the deadline does not run in lock")
	assert.True(t, r.PausedLicense)
	e.assertGETsChangeNothing(k.id, policyID, runID)

	e.renew()
	e.sweep(1)
	e.stepUp(e.admin, e.adminAcct)
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/continue", nil), http.StatusNoContent)
	r = e.run(e.admin, runID)
	assert.Equal(t, "verifying_new", r.Status)
	require.NotNil(t, r.DecisionDueAt)
	assert.True(t, r.DecisionDueAt.After(due.Add(e.clock.Now().Sub(lockedAt)-48*time.Hour)), "the deadline moved by the pause")
	assert.Contains(t, r.ActionsAllowed, "keep_old")
	requireStatus(t, e.admin.do(http.MethodPost, "/api/v1/rotation/runs/"+runID+"/actions/keep-old", map[string]any{"location_ids": []string{rootLoc}}),
		http.StatusNoContent)
	e.drain()
	assert.Equal(t, "overlap", e.run(e.admin, runID).Status)
}

// TestL88LockWhenTheNoticeIsDueOverTheWire: the lock begins when a scheduled run's notice becomes due: the planner is
// paused by the gate, no run is created and no email queued; after the renewal the next tick previews the run.
func TestL88LockWhenTheNoticeIsDueOverTheWire(t *testing.T) {
	e := newKeyEnv(t)
	k := e.generate(e.admin, "l88", "ed25519")
	e.deployed(k)
	end := e.license.Snapshot().Eval.EndsAt
	// A policy whose notice falls due just after the evaluation ends.
	days := int(end.Sub(e.clock.Now()).Hours()/24) + 2
	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": k.id, "name": "l88", "interval_days": days,
		"notify_before_hours": 24})
	requireStatus(t, rec, http.StatusCreated)
	policyID := decodeBody[map[string]any](t, rec)["id"].(string)
	e.stepUp(e.admin, e.adminAcct)
	rec = e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/enable", nil, withHeader("If-Match", rec.Header().Get("ETag")))
	requireStatus(t, rec, http.StatusOK)
	previews := e.outboxTemplates()["rotation.preview"]

	e.lockNow()
	e.hourly(2 * 24 * time.Hour)
	assert.Zero(t, e.count("rotations"), "no run in lock")
	assert.Equal(t, previews, e.outboxTemplates()["rotation.preview"], "no notice in lock")

	e.renew()
	require.NoError(t, e.task("rotation.plan"))
	assert.Equal(t, 1, e.count("rotations"), "after the renewal the next tick previews")
	assert.Equal(t, previews+1, e.outboxTemplates()["rotation.preview"])
}

// TestL83FlaggedWhenTheLockEnters is L-83's first sentence as the spec words it: when the lock enters during the
// overlap (4 days left), the rotation "stays in OVERLAP, flagged paused_license" (06-quality.md §23.8, R24): the run
// read after the next sweep says paused_license, its notice state names the lock and the pause email is queued.
func TestL83FlaggedWhenTheLockEnters(t *testing.T) {
	t.Skip("DEFECT T14-D1: L-83 says a run in overlap is flagged paused_license when the lock enters; the controller " +
		"(internal/sshkeys/controller.go, the overlap row of contract C8) flags it only once overlap_until has passed in lock, " +
		"so for the rest of the overlap the run reads paused_license=false and no rotation.paused_license email is queued")
	e, k, _, runID := lockedOverlap(t)
	e.hourly(2 * time.Hour)
	r := e.run(e.admin, runID)
	require.True(t, r.OverlapUntil.After(e.clock.Now()), "the overlap has days left")
	assert.Equal(t, "overlap", r.Status)
	assert.Contains(t, e.f.file(deployKeysPath), k.blob())
	assert.True(t, r.PausedLicense, "flagged when the lock enters")
	require.NotNil(t, r.NoticeState)
	assert.Equal(t, "rotation.paused_license", r.NoticeState["reason"])
	assert.Equal(t, 1, e.outboxTemplates()["rotation.paused_license"])
}
