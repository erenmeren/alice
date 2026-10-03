//go:build linux

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const opC = "0190f5a0-0000-7000-8000-0000000000d3"

func (w *deployWorld) restoreCode(t *testing.T, op string) (int, map[string]any) {
	t.Helper()
	return w.f.run("nginx-restore", "--op", op)
}

// abWorld: A (old -> new) and B (new -> third) committed.
func abWorld(t *testing.T) (*deployWorld, pki.Leaf) {
	w := newDeployWorld(t)
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.deployFrom(t, opA, w.leaf, w.newLeaf)
	w.deployFrom(t, opB, w.newLeaf, third)
	return w, third
}

// crashC runs C (third -> fourth) and kills it right after it took the pair record.
func (w *deployWorld) crashC(t *testing.T, cur, next pki.Leaf) {
	t.Helper()
	in := input(next.FullchainPEM, next.KeyPEM)
	w.f.s.afterDeployStep = func(p string) error {
		if p == "pair record renamed" {
			return errKilled
		}
		return nil
	}
	code, _ := w.f.runWith(in, "nginx-deploy", "--op", opC, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(cur.FullchainPEM)), "--content-sha256", hexOf(in))
	require.Equal(t, helperproto.ExitFailed, code)
	w.revive()
}

// Fix round 3 (Important): the reviewer's seven steps. Once B, the pair's latest operation, is
// cleaned up, no older retained operation of the pair can be restored.
func TestCleanedUpLatestOperationKeepsOlderOnesSuperseded(t *testing.T) {
	w, _ := abWorld(t)
	code, r := w.restoreCode(t, opA)
	assert.Equal(t, helperproto.CodeSuperseded, r["code"], "%d", code)
	code, r = w.restoreCode(t, opB)
	require.Equal(t, 0, code, "%v", r)
	code, r = w.restoreCode(t, opA)
	assert.Equal(t, helperproto.CodeSuperseded, r["code"], "%d", code)
	code, c := w.f.run("cleanup", "--op", opB)
	require.Equal(t, 0, code, "%v", c)
	code, r = w.restoreCode(t, opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", r)
	assert.Equal(t, helperproto.CodeSuperseded, r["code"])
	w.assertPair(t, true) // A's new pair stays: the pre-A key never comes back
}

// Fix round 3: C dies after taking the record (prepared). The record resolves through C to B: B
// stays restorable and repeatable, A stays superseded — also after B is restored, after C is
// cleaned up or swept, and after C is re-run as unchanged.
func TestRecordOfANoOpResolvesToTheOperationBefore(t *testing.T) {
	fourth := pki.NewCA("Fourth", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	t.Run("crashed C", func(t *testing.T) {
		w, third := abWorld(t)
		w.crashC(t, third, fourth)
		code, r := w.restoreCode(t, opB)
		require.Equal(t, 0, code, "%v", r)
		assert.Equal(t, helperproto.PhaseRestored, r["phase"])
		code, r = w.restoreCode(t, opB)
		require.Equal(t, 0, code, "repeatable: %v", r)
		code, r = w.restoreCode(t, opA)
		assert.Equal(t, helperproto.ExitPrecondition, code)
		assert.Equal(t, helperproto.CodeSuperseded, r["code"])
	})
	t.Run("crashed C cleaned up", func(t *testing.T) {
		w, third := abWorld(t)
		w.crashC(t, third, fourth)
		code, c := w.f.run("cleanup", "--op", opC)
		require.Equal(t, 0, code, "%v", c)
		code, r := w.restoreCode(t, opB)
		require.Equal(t, 0, code, "removing a no-op does not take the latest property away: %v", r)
		code, r = w.restoreCode(t, opA)
		assert.Equal(t, helperproto.CodeSuperseded, r["code"], "%d", code)
	})
	t.Run("crashed C swept", func(t *testing.T) {
		w, third := abWorld(t)
		w.crashC(t, third, fourth)
		w.age(t, opC, 8*24*time.Hour)
		w.f.s.sweepBackups()
		assert.NoDirExists(t, w.opPath(opC))
		code, r := w.restoreCode(t, opB)
		require.Equal(t, 0, code, "%v", r)
		code, r = w.restoreCode(t, opA)
		assert.Equal(t, helperproto.CodeSuperseded, r["code"], "%d", code)
	})
	t.Run("crashed C re-run as unchanged", func(t *testing.T) {
		w, third := abWorld(t)
		w.crashC(t, third, fourth)
		// Someone installs C's pair by hand; C's re-run finds it already there.
		w.f.write("/etc/nginx/ssl/www.crt", string(fourth.FullchainPEM), 0o644)
		w.f.write("/etc/nginx/ssl/www.key", string(fourth.KeyPEM), 0o600)
		m := w.deployFrom(t, opC, fourth, fourth)
		require.Equal(t, helperproto.PhaseUnchanged, m["phase"])
		code, r := w.restoreCode(t, opA)
		assert.Equal(t, helperproto.ExitPrecondition, code)
		assert.Equal(t, helperproto.CodeSuperseded, r["code"])
		sup, err := w.f.s.superseded(journal{Op: opB, CertResolved: "/etc/nginx/ssl/www.crt", KeyResolved: "/etc/nginx/ssl/www.key"})
		require.NoError(t, err)
		assert.False(t, sup, "B is still the operation that last replaced files")
	})
}

// A loop in the chain of records (only a corrupted state can make one) counts as superseding.
func TestRecordChainLoopSupersedes(t *testing.T) {
	w, third := abWorld(t)
	fourth := pki.NewCA("Fourth", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.crashC(t, third, fourth)
	j, ok := w.f.s.nginxJournal(mustBackupRoot(t, w), opC)
	require.True(t, ok)
	j.PrevRecord = opC
	dir, err := w.f.s.opDir(opC, false)
	require.NoError(t, err)
	require.NoError(t, w.f.s.writeJournal(dir, j))
	require.NoError(t, dir.Close())
	sup, err := w.f.s.superseded(journal{Op: opB, CertResolved: "/etc/nginx/ssl/www.crt", KeyResolved: "/etc/nginx/ssl/www.key"})
	require.NoError(t, err)
	assert.True(t, sup)
}

func mustBackupRoot(t *testing.T, w *deployWorld) *os.File {
	t.Helper()
	root, err := w.f.s.openBackupRoot(false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// Fix round 3, minor: the lock-free cleanup path removes only authorized_keys entries; anything an
// Nginx deployment wrote meanwhile stays, and the directory is then decided under the lock.
func TestLockFreeCleanupRemovesOnlyAuthorizedKeysEntries(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
	for _, n := range []string{"1.bak", "1.json", "journal.json", "key.bak"} {
		w.f.write(helperproto.BackupRoot+"/"+opA+"/"+n, "x", 0o600)
	}
	root := mustBackupRoot(t, w)
	assert.False(t, removeAuthKeysOp(root, opA))
	for _, n := range []string{"journal.json", "key.bak"} {
		assert.FileExists(t, w.opPath(opA)+"/"+n)
	}
	assert.NoFileExists(t, w.opPath(opA)+"/1.bak")
	w.f.mkdir(helperproto.BackupRoot+"/"+opB, 0o700)
	w.f.write(helperproto.BackupRoot+"/"+opB+"/2.bak", "x", 0o600)
	assert.True(t, removeAuthKeysOp(root, opB))
	assert.NoDirExists(t, w.opPath(opB))
}
