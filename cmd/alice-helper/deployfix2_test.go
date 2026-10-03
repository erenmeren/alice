//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

func (w *deployWorld) age(t *testing.T, op string, d time.Duration) {
	t.Helper()
	at := testNow.Add(-d)
	require.NoError(t, os.Chtimes(w.opPath(op), at, at))
}

// Fix round 2, New-1: a committed operation whose certificate someone re-issued (certbot
// --reuse-key: the key still holds the deployed content) cannot be rolled back; it is not kept for
// recovery: cleanup removes it, the sweep applies the 30-day cap.
func TestUnrestorableOperationIsNotKeptForever(t *testing.T) {
	setup := func(t *testing.T) *deployWorld {
		w := newDeployWorld(t)
		w.deployFrom(t, opA, w.leaf, w.newLeaf)
		w.f.write("/etc/nginx/ssl/www.crt", foreignCert, 0o644)
		code, r := w.f.run("nginx-restore", "--op", opA)
		require.Equal(t, helperproto.ExitPrecondition, code, "%v", r)
		require.Equal(t, helperproto.CodeHashMismatch, r["code"])
		return w
	}
	w := setup(t)
	code, c := w.f.run("cleanup", "--op", opA)
	require.Equal(t, 0, code, "%v", c)
	assert.NoDirExists(t, w.opPath(opA))

	w = setup(t)
	w.age(t, opA, 20*24*time.Hour)
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA), "restore_failed keeps the 30-day cap")
	w.age(t, opA, 400*24*time.Hour)
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
}

// Fix round 2, New-2: the certificate is changed between the renames AND putting the key back
// fails. The journal remembers that this transaction found someone else's file, so a later
// nginx-restore of the operation applies the same rule: it puts the key back and leaves the
// certificate.
func TestPartialRollbackIsRepairedByNginxRestore(t *testing.T) {
	w := newDeployWorld(t)
	calls := 0
	w.f.s.beforeRename = func() error {
		switch calls++; calls {
		case 2:
			w.f.write("/etc/nginx/ssl/www.crt", foreignCert, 0o644)
		case 3:
			return unix.EIO
		}
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRestore, m["failed_step"])
	assert.Equal(t, helperproto.StepWriteCert, m["cause_step"])
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"))
	assert.Equal(t, foreignCert, w.f.read("/etc/nginx/ssl/www.crt"))
	w.f.s.beforeRename = nil

	code, c := w.f.run("cleanup", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code, "the key can still be put back: %v", c)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestoreFailed, r["phase"])
	assert.Equal(t, helperproto.StepWriteCert, r["failed_step"])
	assert.Equal(t, helperproto.StepWriteCert, r["cause_step"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, r["error"])
	assert.Equal(t, []string{"restore:ok"}, stepsOf(r))
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the key is back")
	assert.Equal(t, foreignCert, w.f.read("/etc/nginx/ssl/www.crt"), "the other party's certificate stays")
	w.assertNoLeftovers(t)
	assert.Equal(t, 0, w.reloads)

	before := w.f.read(helperproto.BackupRoot + "/" + opA + "/journal.json")
	code, r = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", r)
	assert.Equal(t, helperproto.CodeHashMismatch, r["code"])
	assert.Equal(t, before, w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json"), "nothing to do: nothing rewritten")
	code, c = w.f.run("cleanup", "--op", opA)
	require.Equal(t, 0, code, "%v", c)
}

// Fix round 2, New-3 (a): B dies after its pair record and before its writing journal; its
// re-run is refused before the first rename. The record goes back to A (the true previous), not
// to B, and A stays restorable.
func TestRerunKeepsTheTruePreviousPairRecord(t *testing.T) {
	w := newDeployWorld(t)
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.deployFrom(t, opA, w.leaf, w.newLeaf)
	in := input(third.FullchainPEM, third.KeyPEM)
	args := []string{"nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)), "--content-sha256", hexOf(in)}
	w.f.s.afterDeployStep = func(p string) error {
		if p == "pair record renamed" {
			return errKilled
		}
		return nil
	}
	code, _ := w.f.runWith(in, args...)
	require.Equal(t, helperproto.ExitFailed, code)
	w.revive()
	w.f.s.beforeRename = func() error {
		w.f.write("/etc/nginx/ssl/www.key", string(w.newLeaf.KeyPEM)+"\n", 0o600) // B's re-run is refused
		return nil
	}
	code, m := w.f.runWith(in, args...)
	require.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	w.f.s.beforeRename = nil
	op, err := w.f.s.pairRecord(journal{CertResolved: "/etc/nginx/ssl/www.crt", KeyResolved: "/etc/nginx/ssl/www.key"})
	require.NoError(t, err)
	assert.Equal(t, opA, op)
	w.f.write("/etc/nginx/ssl/www.key", string(w.newLeaf.KeyPEM), 0o600)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
}

// Fix round 2, New-3 (b): putting the previous record back fails on a refusal. The record then
// names an operation that never replaced anything, which supersedes nothing.
func TestAGhostPairRecordSupersedesNothing(t *testing.T) {
	w := newDeployWorld(t)
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.deployFrom(t, opA, w.leaf, w.newLeaf)
	records := 0
	w.f.s.afterDeployStep = func(p string) error {
		if p == "pair record staged" {
			if records++; records == 2 {
				return errInjected
			}
		}
		return nil
	}
	w.f.s.beforeRename = func() error {
		w.f.write("/etc/nginx/ssl/www.key", string(w.newLeaf.KeyPEM)+"\n", 0o600)
		return nil
	}
	in := input(third.FullchainPEM, third.KeyPEM)
	code, m := w.f.runWith(in, "nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)), "--content-sha256", hexOf(in))
	require.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	w.revive()
	w.f.s.beforeRename = nil
	w.f.write("/etc/nginx/ssl/www.key", string(w.newLeaf.KeyPEM), 0o600)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
}

// Fix round 2, New-4: cleanup of an authorized_keys operation never waits for the Nginx lock.
func TestAuthorizedKeysCleanupDoesNotWaitForTheNginxLock(t *testing.T) {
	w := newDeployWorld(t)
	old := lockWait
	lockWait = 2 * time.Second
	defer func() { lockWait = old }()
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	defer func() { _ = lock.Close() }()
	w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
	w.f.write(helperproto.BackupRoot+"/"+opA+"/1.bak", "keys", 0o600)
	w.f.write(helperproto.BackupRoot+"/"+opA+"/1.json", "{}", 0o600)
	w.f.mkdir(helperproto.BackupRoot+"/"+opB, 0o700) // empty: an authorized_keys write that discarded its backup
	start := time.Now()
	for _, op := range []string{opA, opB} {
		code, c := w.f.run("cleanup", "--op", op)
		require.Equal(t, 0, code, "%v", c)
		assert.Equal(t, float64(1), c["removed"])
		assert.NoDirExists(t, w.opPath(op))
	}
	assert.Less(t, time.Since(start), time.Second, "no wait for the Nginx lock")

	op3 := "0190f5a0-0000-7000-8000-0000000000d3"
	w.f.mkdir(helperproto.BackupRoot+"/"+op3, 0o700)
	w.f.write(helperproto.BackupRoot+"/"+op3+"/key.bak", "k", 0o600) // an Nginx operation before its journal
	lockWait = 100 * time.Millisecond
	code, c := w.f.run("cleanup", "--op", op3)
	assert.Equal(t, helperproto.ExitFailed, code, "%v", c)
	assert.Equal(t, helperproto.CodeBusy, c["code"])
}

// Fix round 2, New-5: the sweep (which runs in every privileged call, nginx-dump included) never
// opens a key file: it decides by the inode and size the journal recorded.
func TestSweepNeverOpensAKeyFile(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	calls := 0
	w.f.s.beforeRename = func() error {
		if calls++; calls == 4 {
			return unix.EIO // the key's restore fails: cert old, key new (kept for recovery)
		}
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	w.f.s.beforeRename = nil
	var keySt unix.Stat_t
	require.NoError(t, unix.Stat(w.f.host("/etc/nginx/ssl/www.key"), &keySt))
	opened := 0
	inner := w.f.s.fsMagic
	w.f.s.fsMagic = func(fd int) (int64, error) {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && sameFile(st, keySt) {
			opened++ // checkFS runs on the file right before it is opened
		}
		return inner(fd)
	}
	w.age(t, opA, 400*24*time.Hour)
	_, d := w.f.run("nginx-dump")
	require.Equal(t, true, d["config_valid"])
	assert.DirExists(t, w.opPath(opA), "the key still holds the deployed content (by its inode)")
	assert.Zero(t, opened, "neither nginx-dump nor its sweep opened the key file")

	// The key put back by hand (a new inode with the old content): no longer recognisable by stat,
	// so the sweep applies the normal retention without reading it.
	w.f.write("/etc/nginx/ssl/www.key.new", string(w.leaf.KeyPEM), 0o600)
	require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl/www.key.new"), w.f.host("/etc/nginx/ssl/www.key")))
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
	assert.Zero(t, opened)
}
