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
	code, m = w.f.run("nginx-restore", "--op", opA)
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
		_, r := w.f.run("nginx-restore", "--op", opB)
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
