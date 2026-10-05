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
)

// F-36 at rotation level: Alice's own key is never rotated. Its key row gets no policy; a forged
// rotation.location job is refused before anything is sent; the world refuses its removal; the
// database's own refusal of a run on the platform key is tested with migration 00010.
func TestF36OwnKeyNeverRotated(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	_, err := e.inv.Reconcile(e.ctx, web, providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{{OSUser: fake.ConnectionAccount, FilePath: keyFile(fake.ConnectionAccount), LineNo: 1,
			PublicKey: e.platform.PublicKey, Fingerprint: e.platform.Fingerprint, KeyType: "ssh-ed25519", Bits: 256}},
		SSHD: providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes"}, ReadFiles: []string{keyFile(fake.ConnectionAccount)}})
	require.NoError(t, err)
	var platformRow uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM ssh_keys WHERE fingerprint_sha256 = $1", e.platform.Fingerprint).Scan(&platformRow))
	_, err = e.keys.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: platformRow, Name: "own", IntervalDays: 30, OverlapDays: 1})
	require.Error(t, err, "no policy for Alice's own key")
	assert.Zero(t, e.count("SELECT count(*) FROM rotation_policies"))

	// A rotation.location job whose payload names a location of another run (or none) does nothing.
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 1))
	e.drain()
	calls := e.worldCalls()
	forged, _, err := e.queue.Enqueue(e.ctx, jobs.Spec{Type: jobs.RotationLocation, Kind: jobs.KindSystem, TargetID: web,
		Payload: map[string]string{"rotation_id": uuid.NewString(), "location_id": r.Locations[0].ID.String(), "phase": "remove"}})
	require.NoError(t, err)
	e.drain()
	v := e.job(forged)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "rotation.not_waiting", v.LastErrorCode)
	assert.Equal(t, calls, e.worldCalls(), "nothing was sent")

	// The world (as the helper) refuses a removal of a protected fingerprint before anything happens.
	sess, err := e.provider.Open(e.ctx, providers.TargetRef{ID: web, Kind: providers.KindLinuxSSH}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = sess.RemoveAuthorizedKey(e.ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: fake.ConnectionAccount,
		FilePath: keyFile(fake.ConnectionAccount), Fingerprint: e.platform.Fingerprint, ProtectedFingerprints: []string{e.platform.Fingerprint}}, nil)
	require.Error(t, err)
	assert.True(t, e.world.Has(web, keyFile(fake.ConnectionAccount), e.platform.Fingerprint))
	for _, ev := range e.world.Events() {
		assert.NotEqual(t, e.platform.Fingerprint, ev.Fingerprint, "the platform key is never named in a change")
	}
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

// F-39: a slow host. The second location's add hangs until the job's deadline (2 s per run, F10): the
// job ends with the location still adding (uncertain) and its session closed; the sweep's next job
// verifies first, then sends once more; nothing is removed meanwhile. As built the job ends without an
// error (result stopped=interrupted) rather than failing with a timeout: the location's state carries it.
func TestF39SlowHostDuringRotation(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	hung := false
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" && p.Target == db && !hung {
			hung = true
			return fake.FaultHang
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	started := time.Now()
	e.drain()
	assert.Less(t, time.Since(started), time.Minute)
	closes := e.provider.Count("Close")
	l := e.loc(r.ID, db, "deploy")
	assert.Equal(t, sshkeys.LocAdding, l.State, "uncertain")
	assert.Equal(t, 2, closes, "both sessions were closed, the hung one too")
	var hungJob jobs.View
	list, _, err := e.queue.List(e.ctx, jobs.ListFilter{TargetID: db})
	require.NoError(t, err)
	for _, v := range list {
		if v.Type == jobs.RotationLocation.Name {
			hungJob = v
		}
	}
	assert.Equal(t, jobs.StatusSucceeded, hungJob.Status)
	assert.Equal(t, "interrupted", hungJob.Result["stopped"])
	e.clock.Advance(time.Minute)
	e.sweep()
	e.drain()
	evs := e.world.Events()
	var dbCalls []string
	for _, ev := range evs {
		if ev.Target == db {
			dbCalls = append(dbCalls, ev.Method)
		}
	}
	assert.Equal(t, []string{"AddAuthorizedKey", "VerifyKeyLogin", "AddAuthorizedKey", "VerifyKeyLogin"}, dbCalls,
		"the next job logged in first; it sent the add again only after the login was refused")
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
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
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
