//go:build integration

package sshkeyjobs_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

// F-36 at rotation level: Alice's own key is never rotated. Its key row gets no policy (refused and
// audited own_key); a generated key in the connection account's file, or in any file that account reads,
// is skipped by the plan with that reason and nothing is sent there; a job naming such a location sends
// nothing; every add and removal of every test carries Alice's fingerprint as protected (harness); and a
// key that becomes protected after its re-check is not removed. The database's own refusal is pinned by
// migration 00010's tests.
func TestF36OwnKeyNeverRotated(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01", providers.UserKeyFiles{OSUser: "ops", Files: []string{keyFile(fake.ConnectionAccount)}, Complete: true})
	_, err := e.inv.Reconcile(e.ctx, web, providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{{OSUser: fake.ConnectionAccount, FilePath: keyFile(fake.ConnectionAccount), LineNo: 1,
			PublicKey: e.platform.PublicKey, Fingerprint: e.platform.Fingerprint, KeyType: "ssh-ed25519", Bits: 256}},
		SSHD: providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes"}, ReadFiles: []string{keyFile(fake.ConnectionAccount)},
		KeyFiles: e.keyFilesOf(web)})
	require.NoError(t, err)
	var platformRow uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM ssh_keys WHERE fingerprint_sha256 = $1", e.platform.Fingerprint).Scan(&platformRow))
	_, err = e.keys.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: platformRow, Name: "own", IntervalDays: 30, OverlapDays: 1})
	require.ErrorIs(t, err, sshkeys.ErrOwnKeyProtected, "no policy for Alice's own key")
	assert.Equal(t, "own_key", e.lastAuditDetail("rotation.policy.denied", "reason"))
	assert.Zero(t, e.count("SELECT count(*) FROM rotation_policies"))

	// A generated key in the connection account's own file, and in a file of another user that the
	// connection account reads: both skipped with their reasons; the deploy user's location changes.
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.placeIn(k, web, fake.ConnectionAccount, keyFile(fake.ConnectionAccount), "")
	p := e.policy(k.ID, 1)
	pv, err := e.keys.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	skips := map[string]string{}
	for _, a := range pv.Plan.Actions {
		skips[a.OSUser] = a.Skip
	}
	assert.Equal(t, map[string]string{"deploy": "", fake.ConnectionAccount: plan.SkipConnectionAccount}, skips)
	r := e.runNow(p)
	e.drain()
	for _, ev := range e.world.Events() {
		assert.NotEqual(t, keyFile(fake.ConnectionAccount), ev.FilePath, "nothing is sent to the connection account's file")
	}
	// A rotation.location job naming the skipped location sends nothing and says why.
	var skipped sshkeys.RotationLocation
	for _, l := range e.run(r.ID).Locations {
		if l.OSUser == fake.ConnectionAccount {
			skipped = l
		}
	}
	require.Equal(t, sshkeys.LocSkipped, skipped.State)
	calls := e.worldCalls()
	for _, phase := range []string{"add", "remove", "undo"} {
		forged, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.RotationLocation, Kind: jobs.KindSystem, TargetID: web, DedupeKey: "forged:" + phase,
			Payload: map[string]string{"rotation_id": r.ID.String(), "location_id": skipped.ID.String(), "phase": phase}})
		require.NoError(t, err)
		e.drain()
		v := e.job(forged)
		assert.Equal(t, jobs.StatusSucceeded, v.Status, phase)
		assert.True(t, v.Result["state"] == sshkeys.LocSkipped || v.Result["stopped"] == "not_your_turn", "%s: %v", phase, v.Result)
	}
	assert.Equal(t, calls, e.worldCalls(), "nothing was sent for a skipped location")
	assert.True(t, e.world.Has(web, keyFile(fake.ConnectionAccount), k.Fingerprint))
	assert.True(t, e.world.Has(web, keyFile(fake.ConnectionAccount), e.platform.Fingerprint))
}

// keyFilesOf are the key files the server's facts list (a scan in a test keeps them).
func (e *env) keyFilesOf(target uuid.UUID) []providers.UserKeyFiles {
	e.t.Helper()
	tg, err := e.inv.GetTarget(e.ctx, target)
	require.NoError(e.t, err)
	return tg.Facts.KeyFiles
}

// Addendum 3: a server whose last scan did not list the connection account's key files completely is
// skipped as a whole: the preview changes nothing there and names connection_files_unknown.
func TestIncompleteConnectionFilesSkipEverything(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	files := e.keyFilesOf(web)
	for i := range files {
		if files[i].OSUser == fake.ConnectionAccount {
			files[i].Complete = false
		}
	}
	e.setKeyFiles(web, files)
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, web, "app")
	pv, err := e.keys.Preview(e.ctx, e.admin, e.policy(k.ID, 1).ID)
	require.NoError(t, err)
	require.Len(t, pv.Plan.Actions, 2)
	for _, a := range pv.Plan.Actions {
		assert.Equal(t, plan.SkipConnectionFilesUnknown, a.Skip, a.OSUser)
	}
	assert.Zero(t, pv.Plan.Changes)
}

// newRealEnv is the harness with the real linuxssh provider over an emulated helper (linuxsshtest)
// instead of the fake key world, and the target handlers that connect and discover servers.
func newRealEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvWith(t, func(e *env) {
		pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: e.inv.HostKeyStore()}, linuxssh.MaxConnections, 16,
			linuxssh.IdleTimeout)
		t.Cleanup(pool.Close)
		e.reg.Register(linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true}))
	})
	targetjobs.Register(e.runner, targetjobs.Deps{Inventory: e.inv, Registry: e.reg, Clock: e.tick, Log: e.log})
	return e
}

const realDeployFile = "/home/deploy/.ssh/authorized_keys"

// realServer starts an emulated server whose deploy user's file holds content, adds it as a target,
// confirms its host key and runs the first test and discovery.
func (e *env) realServer(name string, content string) (*linuxsshtest.Emulator, uuid.UUID) {
	e.t.Helper()
	emu := linuxsshtest.NewEmulator()
	emu.SetFile("/var/lib/alice-svc/.ssh/authorized_keys", []byte(e.platform.PublicKey+"\n"))
	emu.SetFile(realDeployFile, []byte(content))
	srv := linuxsshtest.NewServer(e.t, emu.Handler())
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.platform.PublicKey))
	require.NoError(e.t, err)
	srv.Authorize(pub)
	srv.SetLoginCheck(emu.AcceptsLogin)
	host, port := srv.Addr()
	tg, _, err := e.inv.CreateTarget(e.ctx, e.admin, inventory.NewTarget{Name: name, Type: inventory.TypeLinux, Host: host, Port: port})
	require.NoError(e.t, err)
	e.drain()
	keys, err := e.inv.ListHostKeys(e.ctx, tg.ID)
	require.NoError(e.t, err)
	require.Len(e.t, keys, 1)
	_, err = e.inv.ConfirmHostKey(e.ctx, e.admin, tg.ID, keys[0].ID, keys[0].Fingerprint)
	require.NoError(e.t, err)
	e.drain()
	require.Equal(e.t, inventory.StatusOK, e.targetStatus(tg.ID), "connected and discovered")
	return emu, tg.ID
}

func fileOf(emu *linuxsshtest.Emulator) string {
	b, _ := emu.File(realDeployFile)
	return string(b)
}

// F-37: the deploy user's file has no trailing newline; the rotation adds the new key on its own line,
// the earlier bytes stay as they were, and the run completes.
func TestF37RotationIntoFileWithoutNewline(t *testing.T) {
	e := newRealEnv(t)
	k := e.generate("ci")
	other := e.otherKeyLine(t)
	original := other + "\n" + k.PublicKey + " " + k.Comment // no newline at the end
	emu, web := e.realServer("web-01", original)
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	r = e.run(r.ID)
	require.Equal(t, sshkeys.StatusOverlap, r.Status)
	got := fileOf(emu)
	assert.True(t, strings.HasPrefix(got, original+"\n"), "the earlier lines are byte-equal; the new key starts its own line")
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	require.Len(t, lines, 3)
	var newPub string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT public_key FROM ssh_keys WHERE id = $1", *r.NewKeyID).Scan(&newPub))
	assert.Contains(t, lines[2], strings.Fields(newPub)[1], "the new key's line")
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status)
	got = fileOf(emu)
	assert.True(t, strings.HasPrefix(got, other+"\n"), "the other key's line is untouched")
	assert.NotContains(t, got, strings.Fields(k.PublicKey)[1], "the old key is gone")
	assert.Equal(t, sshkeys.LocRemoved, e.loc(r.ID, web, "deploy").State)
}

// F-38: the file changes between Alice's read and her write. Once: the provider reads again and the add
// succeeds. Before every attempt: the add ends ssh.file_changed and the run is undone; the old key stays.
func TestF38RotationFileChangedBetweenReadAndWrite(t *testing.T) {
	for _, every := range []bool{false, true} {
		t.Run(map[bool]string{false: "once", true: "every attempt"}[every], func(t *testing.T) {
			e := newRealEnv(t)
			k := e.generate("ci")
			emu, web := e.realServer("web-01", k.PublicKey+" "+k.Comment+"\n")
			var changes atomic.Int32
			emu.BeforeWrite(func(path string) {
				if path == realDeployFile && (every || changes.Load() == 0) {
					changes.Add(1)
					b, _ := emu.File(path)
					emu.SetFile(path, append(b, []byte("# touched by someone\n")...))
				}
			})
			r := e.runNow(e.policy(k.ID, 7))
			r = e.settleRun(r.ID)
			got := fileOf(emu)
			assert.Contains(t, got, strings.Fields(k.PublicKey)[1], "the old key stays")
			if !every {
				assert.Equal(t, int32(1), changes.Load())
				r = e.run(r.ID)
				assert.Equal(t, sshkeys.StatusOverlap, r.Status, "the add was read again and written")
				assert.Equal(t, sshkeys.LocVerified, e.loc(r.ID, web, "deploy").State)
				return
			}
			assert.Equal(t, sshkeys.StatusAborted, r.Status)
			assert.Equal(t, sshkeys.ReasonAddFailed, r.ResultCode)
			l := e.loc(r.ID, web, "deploy")
			assert.Equal(t, "ssh.file_changed", l.ErrorCode)
			assert.Equal(t, int32(3), changes.Load(), "three attempts, each refused by the compare-and-set")
		})
	}
}

// F-39: a slow host (ruling M4, as the spec says: "the job fails cleanly with a timeout message"). The
// second location's add hangs until the job's deadline: the attempt fails retryably with ssh.timeout, the
// location stays adding (uncertain) and its session is closed; the next attempt logs in first and sends
// the add again only after the login was refused; nothing is removed meanwhile.
func TestF39SlowHostDuringRotation(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	hung := false
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" && p.Target == db && !hung {
			hung = true
			return fake.FaultHang
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	l := e.loc(r.ID, db, "deploy")
	assert.Equal(t, sshkeys.LocAdding, l.State, "uncertain")
	assert.Equal(t, 2, e.provider.Count("Close"), "both sessions were closed, the hung one too")
	var hungJob jobs.View
	list, _, err := e.queue.List(e.ctx, jobs.ListFilter{TargetID: db})
	require.NoError(t, err)
	for _, v := range list {
		if v.Type == jobs.RotationLocation.Name {
			hungJob = v
		}
	}
	assert.Equal(t, jobs.StatusQueued, hungJob.Status, "a retryable failure")
	assert.Equal(t, "ssh.timeout", hungJob.LastErrorCode, "the timeout message")
	e.clock.Advance(time.Minute)
	e.drain()
	var dbCalls []string
	for _, ev := range e.world.Events() {
		if ev.Target == db {
			dbCalls = append(dbCalls, ev.Method)
		}
	}
	assert.Equal(t, []string{"AddAuthorizedKey", "VerifyKeyLogin", "AddAuthorizedKey", "VerifyKeyLogin"}, dbCalls,
		"the next attempt logged in first; it sent the add again only after the login was refused")
	assert.Equal(t, sshkeys.StatusOverlap, e.run(r.ID).Status)
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
}

// G14: a clock stepped back. A removal whose re-check would be dated before the verification is refused
// (nothing recorded, nothing sent), retried once the clock is past it again, and the old key is there
// until then.
func TestBackwardClockStepIsRefusedAndRetried(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	verified := *e.loc(r.ID, web, "deploy").VerifiedAt
	e.clock.Advance(24 * time.Hour)
	e.sweep()
	require.Equal(t, sshkeys.StatusRemovingOld, e.run(r.ID).Status)
	stepped := false
	e.setFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" && !stepped {
			stepped = true
			e.clock.Set(verified.Add(-2 * time.Hour)) // the clock goes back while the re-check runs
		}
		return fake.FaultNone
	})
	e.drain()
	l := e.loc(r.ID, web, "deploy")
	assert.Equal(t, sshkeys.LocVerified, l.State, "refused: nothing recorded")
	assert.Nil(t, l.ReverifiedAt)
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"), "nothing sent")
	assert.True(t, e.world.Has(web, keyFile("deploy"), k.Fingerprint), "the old key is still there")
	e.clock.Set(verified.Add(25 * time.Hour))
	e.sweep()
	r = e.settleRun(r.ID)
	assert.Equal(t, sshkeys.StatusCompleted, r.Status, "retried once the clock is past the verification again")
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, r.NewFingerprint)
}
