//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

// AUD-05: recovery fences an operation it found without a journal before it records "nothing was
// written"; a helper that starts late (a sudo or PAM stall) must then refuse that operation.

func (w *deployWorld) fence(t *testing.T, op string) (int, map[string]any) {
	t.Helper()
	return w.f.run("nginx-fence", "--op", op)
}

func TestFenceThenTheSameOperationsDeployIsRefusedNothingWritten(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.fence(t, opA)
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseFenced, m["phase"])
	assert.Equal(t, false, m["active"])
	assert.Equal(t, helperproto.BackupRoot+"/"+opA, m["backup_dir"])

	code, m = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeFenced, m["code"])
	w.assertPair(t, false)
	assert.Equal(t, 0, w.reloads)
	w.assertNoLeftovers(t)

	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseFenced, st["phase"])
	assert.Equal(t, "", st["new_cert_sha256"])
	assert.Equal(t, "", st["current_cert_sha256"])

	// Idempotent, and nginx-restore of a fenced operation restores nothing.
	code, m = w.fence(t, opA)
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseFenced, m["phase"])
	code, m = w.restoreWith(opA, "") // the refused deploy left its stdin unread
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseFenced, m["phase"])
	assert.Equal(t, []any{}, m["steps"])
	w.assertPair(t, false)

	// Another operation is not affected.
	code, m = w.deploy(opB, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
}

// A fence that finds a journal changes nothing and answers it (recovery proceeds from it); a
// prepared one (nothing replaced) is fenced, its pair record handed back.
func TestFenceWhenAJournalExists(t *testing.T) {
	t.Run("committed", func(t *testing.T) {
		w := newDeployWorld(t)
		_, m := w.deploy(opA, w.newInput(), w.oldSHA())
		require.Equal(t, helperproto.PhaseCommitted, m["phase"])
		code, m := w.fence(t, opA)
		assert.Equal(t, helperproto.ExitOK, code, m)
		assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
		assert.Equal(t, hexOf(string(w.newLeaf.FullchainPEM)), m["new_cert_sha256"])
		assert.Equal(t, hexOf(string(w.newLeaf.FullchainPEM)), m["current_cert_sha256"])
		w.assertPair(t, true)
		_, r := w.f.run("nginx-restore", "--op", opA)
		assert.Equal(t, helperproto.PhaseRestored, r["phase"], "the fence did not touch the journal")
	})
	t.Run("writing (interrupted)", func(t *testing.T) {
		w := newDeployWorld(t)
		w.f.s.afterDeployStep = func(name string) error {
			if name == helperproto.StepReload {
				return errKilled
			}
			return nil
		}
		w.deploy(opA, w.newInput(), w.oldSHA())
		w.revive()
		_, st := w.f.run("nginx-status", "--op", opA)
		require.Equal(t, helperproto.PhaseWriting, st["phase"])
		_, m := w.fence(t, opA)
		assert.Equal(t, helperproto.PhaseWriting, m["phase"])
		_, r := w.f.run("nginx-restore", "--op", opA)
		assert.Equal(t, helperproto.PhaseRestored, r["phase"])
		w.assertPair(t, false)
	})
	t.Run("unchanged", func(t *testing.T) {
		w := newDeployWorld(t)
		in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
		_, m := w.deploy(opA, in, w.oldSHA())
		require.Equal(t, helperproto.PhaseUnchanged, m["phase"])
		_, m = w.fence(t, opA)
		assert.Equal(t, helperproto.PhaseUnchanged, m["phase"])
	})
	t.Run("prepared: fenced, the record goes back to the operation before", func(t *testing.T) {
		w := newDeployWorld(t)
		_, m := w.deploy(opB, w.newInput(), w.oldSHA()) // B is the pair's latest
		require.Equal(t, helperproto.PhaseCommitted, m["phase"])
		w.f.s.afterDeployStep = func(name string) error {
			if name == "pair record renamed" {
				return errKilled
			}
			return nil
		}
		in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
		w.deploy(opA, in, hexOf(string(w.newLeaf.FullchainPEM)))
		w.revive()
		_, st := w.f.run("nginx-status", "--op", opA)
		require.Equal(t, helperproto.PhasePrepared, st["phase"])
		_, m = w.fence(t, opA)
		assert.Equal(t, helperproto.PhaseFenced, m["phase"])
		assert.NoFileExists(t, w.opPath(opA)+"/"+certBackup)
		assert.NoFileExists(t, w.opPath(opA)+"/"+keyBackup)
		code, m := w.deploy(opA, in, hexOf(string(w.newLeaf.FullchainPEM)))
		assert.Equal(t, helperproto.CodeFenced, m["code"], code)
		// The tombstone supersedes nothing: B is still the pair's latest and can be restored.
		_, r := w.restoreWith(opB, "") // the refused deploy left its stdin unread
		assert.Equal(t, helperproto.PhaseRestored, r["phase"])
		w.assertPair(t, false)
	})
	t.Run("unreadable journal: refused, nothing overwritten", func(t *testing.T) {
		w := newDeployWorld(t)
		w.f.mkdir(helperproto.BackupRoot, 0o700)
		w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
		w.f.write(helperproto.BackupRoot+"/"+opA+"/journal.json", "{not json", 0o600)
		code, m := w.fence(t, opA)
		assert.Equal(t, helperproto.ExitFailed, code, m)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		assert.Equal(t, "{not json", w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json"))
	})
}

// A fence never supersedes the pair's real latest operation: a fenced id has no pair.
func TestFenceDoesNotSupersedeTheLatestOperation(t *testing.T) {
	w := newDeployWorld(t)
	_, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.PhaseCommitted, m["phase"])
	_, m = w.fence(t, opB)
	require.Equal(t, helperproto.PhaseFenced, m["phase"])
	_, r := w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
}

// The helper dies at each point of the fence: a fence again (or the deploy) still ends safe.
func TestFenceKilledAtEveryPoint(t *testing.T) {
	var points []string
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(name string) error { points = append(points, name); return nil }
	w.fence(t, opA)
	require.NotEmpty(t, points)
	for i, p := range points {
		t.Run(p, func(t *testing.T) {
			w := newDeployWorld(t)
			w.killAt(i)
			code, _ := w.fence(t, opA)
			require.Equal(t, helperproto.ExitFailed, code)
			w.revive()
			// Either the tombstone is there, or nothing is: the late deploy then finds no fence and
			// runs (recovery recorded nothing, its next fence or status sees the journal).
			_, st := w.f.run("nginx-status", "--op", opA)
			require.Contains(t, []string{helperproto.PhaseFenced, helperproto.PhaseNone}, st["phase"])
			code, m := w.fence(t, opA)
			require.Equal(t, helperproto.ExitOK, code, m)
			assert.Equal(t, helperproto.PhaseFenced, m["phase"])
			_, m = w.deploy(opA, w.newInput(), w.oldSHA())
			assert.Equal(t, helperproto.CodeFenced, m["code"])
			w.assertPair(t, false)
		})
	}
}

// The fence waits for the Nginx lock: while a deployment holds it the fence answers BUSY (and
// recovery records nothing).
func TestFenceWaitsForTheLock(t *testing.T) {
	w := newDeployWorld(t)
	old := lockWait
	lockWait = 50 * time.Millisecond
	defer func() { lockWait = old }()
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	code, m := w.fence(t, opA)
	assert.Equal(t, helperproto.ExitFailed, code, m)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	_ = lock.Close()
	assert.NoDirExists(t, w.opPath(opA))
}

// A tombstone outlives cleanup --op (its job is to stay) and is swept like a finished operation.
func TestFenceTombstoneCleanupAndSweep(t *testing.T) {
	w := newDeployWorld(t)
	w.fence(t, opA)
	code, m := w.f.run("cleanup", "--op", opA)
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, 0.0, m["removed"])
	assert.FileExists(t, w.opPath(opA)+"/"+journalName)
	at := testNow.Add(-helperproto.NginxBackupKeep - time.Hour)
	require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
}

// The fence is not limited by maxNginxOps (a tombstone holds no backup).
func TestFenceIsNotLimitedByTheBackupCap(t *testing.T) {
	w := newDeployWorld(t)
	old := maxNginxOps
	maxNginxOps = 1
	defer func() { maxNginxOps = old }()
	_, m := w.deploy(opB, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.PhaseCommitted, m["phase"])
	code, m := w.fence(t, opA)
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseFenced, m["phase"])
}

func TestFenceArguments(t *testing.T) {
	w := newDeployWorld(t)
	for _, args := range [][]string{{}, {"--op"}, {"--op", opA, "x"}, {"--opx", opA}} {
		code, m := w.f.run(append([]string{"nginx-fence"}, args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, m)
		assert.Equal(t, helperproto.CodeUsage, m["code"])
	}
	code, m := w.f.run("nginx-fence", "--op", "../x")
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeInvalidArgument, m["code"])
	w.f.s.euid = func() int { return 1000 }
	code, m = w.f.run("nginx-fence", "--op", opA)
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodeNotRoot, m["code"])
}

// The audit's PoC (AUD-05), adapted: status reads none, Alice's recovery fences, then the stalled
// nginx-deploy starts ten minutes later with the stdin it was sent: refused, nothing written.
func TestLateDeployAfterTheRecoveryFenceIsRefused(t *testing.T) {
	w := newDeployWorld(t)
	code, st := w.f.run("nginx-status", "--op", opA)
	require.Equal(t, helperproto.ExitOK, code)
	require.Equal(t, helperproto.PhaseNone, st["phase"])
	_, m := w.fence(t, opA)
	require.Equal(t, helperproto.PhaseFenced, m["phase"])

	base := w.f.s.now()
	w.f.s.now = func() time.Time { return base.Add(10 * time.Minute) }
	code, out := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, out)
	assert.Equal(t, helperproto.CodeFenced, out["code"])
	assert.Zero(t, w.reloads)
	w.assertPair(t, false)
}

// Fix round 1, Important 2: tombstones do not count against maxNginxOps (at the cap every
// deployment would answer NO_SPACE for 7 days); fences have their own bound, which answers an error.
func TestTombstonesDoNotCountAgainstTheBackupCap(t *testing.T) {
	w := newDeployWorld(t)
	oldOps, oldFences := maxNginxOps, maxNginxFences
	maxNginxOps, maxNginxFences = 1, 2
	defer func() { maxNginxOps, maxNginxFences = oldOps, oldFences }()
	for _, op := range []string{opA, opB} {
		_, m := w.fence(t, op)
		require.Equal(t, helperproto.PhaseFenced, m["phase"])
	}
	const opC, opD = "0190f5a0-0000-7000-8000-0000000000d3", "0190f5a0-0000-7000-8000-0000000000d4"
	code, m := w.deploy(opC, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
	code, m = w.fence(t, opD)
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeNoSpace, m["code"])
	assert.NoDirExists(t, w.opPath(opD))
	_, m = w.fence(t, opA)
	assert.Equal(t, helperproto.PhaseFenced, m["phase"], "an existing tombstone still answers at the bound")
}

// Fix round 1, minor 1: a fenced operation is refused before its input is read: even an input that
// does not match its hash answers FENCED.
func TestFencedDeployIsRefusedBeforeItsInputIsRead(t *testing.T) {
	w := newDeployWorld(t)
	w.fence(t, opA)
	in := w.newInput()
	read := false
	w.f.s.stdin = readerFunc(func([]byte) (int, error) { read = true; return 0, errFailedWrite })
	code, m := w.f.run("nginx-deploy", "--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in+"x"))
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeFenced, m["code"])
	assert.False(t, read, "stdin was not read")
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// Fix round 1, minor 3: an id whose directory holds authorized_keys backups is not fenced (a
// tombstone there would shorten their 30-day retention to 7 days).
func TestFenceRefusesAnotherKindOfOperation(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir(helperproto.BackupRoot, 0o700)
	w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
	w.f.write(helperproto.BackupRoot+"/"+opA+"/1.bak", "ssh-ed25519 AAAA x\n", 0o600)
	code, m := w.fence(t, opA)
	assert.Equal(t, helperproto.ExitRefused, code, m)
	assert.Equal(t, helperproto.CodeInvalidArgument, m["code"])
	assert.NoFileExists(t, w.opPath(opA)+"/"+journalName)
	assert.FileExists(t, w.opPath(opA)+"/1.bak")
}

// Fix round 1, Important 1 (a) and minor 5: RECOVERY_PENDING names the blocking operation, also
// when its journal cannot be read.
func TestRecoveryPendingNamesTheOperation(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(name string) error {
		if name == helperproto.StepReload {
			return errKilled
		}
		return nil
	}
	w.deploy(opA, w.newInput(), w.oldSHA())
	w.revive()
	in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
	code, m := w.deploy(opB, in, hexOf(string(w.newLeaf.FullchainPEM)))
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeRecoveryPending, m["code"])
	assert.Equal(t, opA, m["pending_op"])

	// The same with A's journal unreadable (an older helper wrote it): still pending, named.
	w.f.write(helperproto.BackupRoot+"/"+opA+"/journal.json", "{garbled", 0o600)
	code, m = w.deploy(opB, in, hexOf(string(w.newLeaf.FullchainPEM)))
	assert.Equal(t, helperproto.CodeRecoveryPending, m["code"], code)
	assert.Equal(t, opA, m["pending_op"])
	code, r := w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code, r)
	assert.Equal(t, helperproto.CodeIOError, r["code"], "the restore of an unreadable journal")

	// Every other error answer carries no pending_op.
	_, m = w.f.run("nginx-status", "--op", "bad")
	_, has := m["pending_op"]
	assert.False(t, has)
}
