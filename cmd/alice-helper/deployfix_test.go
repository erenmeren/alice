//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// errInjected is what a test's afterDeployStep returns to make the operation at that point fail
// (an I/O error) without killing the helper.
var errInjected = errors.New("injected failure (test)")

const foreignCert = "a certificate someone else put there"

// Fix round 1, Important 1 (a): the certificate is changed (in place, or replaced by a new file)
// after it was read and before the key is replaced. The key is never replaced: the answer is a
// refusal and the pair is exactly what the other party left.
func TestDeployCertificateChangedBeforeTheKeyRename(t *testing.T) {
	for name, change := range map[string]func(w *deployWorld){
		"edited in place": func(w *deployWorld) { w.f.write("/etc/nginx/ssl/www.crt", foreignCert, 0o644) },
		"replaced by another file": func(w *deployWorld) {
			w.f.write("/etc/nginx/ssl/www.crt.new", foreignCert, 0o644)
			require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl/www.crt.new"), w.f.host("/etc/nginx/ssl/www.crt")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newDeployWorld(t)
			calls := 0
			w.f.s.beforeRename = func() error {
				if calls++; calls == 1 {
					change(w)
				}
				return nil
			}
			code, m := w.deploy(opA, w.newInput(), w.oldSHA())
			assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
			assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
			assert.Equal(t, string(w.leaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the key is never replaced")
			assert.Equal(t, foreignCert, w.f.read("/etc/nginx/ssl/www.crt"))
			assert.Equal(t, 0, w.reloads)
			_, st := w.f.run("nginx-status", "--op", opA)
			assert.Equal(t, helperproto.PhaseNone, st["phase"], "a refusal leaves no operation behind")
		})
	}
}

// Fix round 1, Important 1 (b): the certificate is changed after the key was replaced. The
// transaction (under the lock: nothing newer exists) puts back the file it wrote, the key; the
// other party's certificate is left. The answer says so: restore_failed, failed_step write_cert,
// error file_changed, the restore step ok, no rollback test or reload. The operation is then
// final: nginx-restore refuses without rewriting the journal, and cleanup may remove it.
func TestDeployCertificateChangedBetweenTheRenames(t *testing.T) {
	w := newDeployWorld(t)
	calls := 0
	w.f.s.beforeRename = func() error {
		if calls++; calls == 2 {
			w.f.write("/etc/nginx/ssl/www.crt", foreignCert, 0o644)
		}
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepWriteCert, m["failed_step"])
	assert.Equal(t, helperproto.StepWriteCert, m["cause_step"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, m["error"])
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:failed", "restore:ok"}, stepsOf(m))
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "the transaction put its own file back")
	assert.Equal(t, foreignCert, w.f.read("/etc/nginx/ssl/www.crt"), "and left the other party's")
	assert.Equal(t, 0, w.reloads)
	w.assertNoLeftovers(t)

	journalBefore := w.f.read(helperproto.BackupRoot + "/" + opA + "/journal.json")
	var before unix.Stat_t
	require.NoError(t, unix.Stat(w.opPath(opA)+"/journal.json", &before))
	code, r := w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", r)
	assert.Equal(t, helperproto.CodeHashMismatch, r["code"])
	var after unix.Stat_t
	require.NoError(t, unix.Stat(w.opPath(opA)+"/journal.json", &after))
	assert.Equal(t, journalBefore, w.f.read(helperproto.BackupRoot+"/"+opA+"/journal.json"), "minor 6: nothing changed, nothing rewritten")
	assert.Equal(t, before.Ino, after.Ino)
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestoreFailed, st["phase"])
	assert.Equal(t, helperproto.StepWriteCert, st["failed_step"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, st["error"])
	code, c := w.f.run("cleanup", "--op", opA)
	require.Equal(t, 0, code, "%v", c)
	assert.NoDirExists(t, w.opPath(opA), "no file holds this operation's content: its backups are not needed")
}

// Fix round 1, Important 1: the certificate is changed at every point between its read and its
// rename. Whatever the point, the key on disk is the old one at the end (a refusal, or the
// transaction put it back), the certificate is the other party's, and nothing is left behind.
func TestDeployCertificateInterferenceMatrix(t *testing.T) {
	points := deployPoints(t, func(*deployWorld) {})
	end := slices.Index(points, "renamed "+stagedName(opA, kindCert))
	require.Positive(t, end)
	for i, p := range points[:end] {
		t.Run(fmt.Sprintf("%02d %s", i, p), func(t *testing.T) {
			w := newDeployWorld(t)
			n := 0
			w.f.s.afterDeployStep = func(string) error {
				if n++; n == i+1 {
					w.f.write("/etc/nginx/ssl/www.crt", foreignCert, 0o644)
				}
				return nil
			}
			code, m := w.deploy(opA, w.newInput(), w.oldSHA())
			switch code {
			case helperproto.ExitPrecondition:
				assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
			case 0:
				assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
				assert.Equal(t, helperproto.RestoreErrFileChanged, m["error"])
			default:
				t.Fatalf("unexpected answer %d %v", code, m)
			}
			assert.Equal(t, string(w.leaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"))
			assert.Equal(t, foreignCert, w.f.read("/etc/nginx/ssl/www.crt"))
			w.assertNoLeftovers(t)
			assert.Equal(t, 0, w.reloads)
		})
	}
}

// Fix round 1, Important 2: the rollback restored the certificate but the key's restore rename
// failed. The answer says the restore step failed (cause_step keeps the step that started the
// rollback); cleanup and the sweep keep the backups (the pair is mixed); nginx-restore repairs it.
func TestRestoreFailedWithAMixedPairKeepsItsBackups(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	calls := 0
	w.f.s.beforeRename = func() error {
		if calls++; calls == 4 {
			return errors.New("injected rename failure")
		}
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRestore, m["failed_step"])
	assert.Equal(t, helperproto.StepConfigTest, m["cause_step"])
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, m["error"], "the class of the step that started the rollback")
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "mixed")
	w.f.s.beforeRename = nil

	code, c := w.f.run("cleanup", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code, "%v", c)
	assert.Equal(t, helperproto.CodeBusy, c["code"])
	at := testNow.Add(-40 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA), "the sweep keeps it too")
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.StepRestore, st["failed_step"])

	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	w.assertPair(t, false)
	code, c = w.f.run("cleanup", "--op", opA)
	require.Equal(t, 0, code, "%v", c)
	assert.NoDirExists(t, w.opPath(opA))
}

// deployFrom deploys a new pair over the current one (expected: the current certificate).
// setPhase rewrites an operation's journal phase (a state an older helper could leave).
func (w *deployWorld) setPhase(t *testing.T, op, phase string) {
	t.Helper()
	dir, err := w.f.s.opDir(op, false)
	require.NoError(t, err)
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir, op)
	require.NoError(t, err)
	require.True(t, found)
	j.Phase = phase
	require.NoError(t, w.f.s.writeJournal(dir, j))
}

func (w *deployWorld) deployFrom(t *testing.T, op string, cur, next pki.Leaf) map[string]any {
	t.Helper()
	in := input(next.FullchainPEM, next.KeyPEM)
	code, m := w.f.runWith(in, "nginx-deploy", "--op", op, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(cur.FullchainPEM)), "--content-sha256", hexOf(in))
	require.Equal(t, 0, code, "%v", m)
	return m
}

// Fix round 1, Important 3 (ruling): an operation superseded by a later one for the same pair is
// never restored. Rule: the helper records, per resolved (certificate, key) pair, the last
// operation that started replacing files (written under the lock before the journal says
// writing); nginx-restore (and a re-sent interrupted deployment) of any other operation for that
// pair is refused with SUPERSEDED. Restoring the latest operation does not change the record, so
// restoring B and then A stays refused even though the pair then holds A's new content.
func TestRestoreRefusesASupersededOperation(t *testing.T) {
	w := newDeployWorld(t)
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.deployFrom(t, opA, w.leaf, w.newLeaf)
	w.deployFrom(t, opB, w.newLeaf, third)
	code, r := w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", r)
	assert.Equal(t, helperproto.CodeSuperseded, r["code"])
	code, r = w.f.run("nginx-restore", "--op", opB)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	w.assertPair(t, true) // A's new pair, B's old one
	code, r = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, "restoring B does not reopen the way back to A's old key")
	assert.Equal(t, helperproto.CodeSuperseded, r["code"])
	w.assertPair(t, true)
	code, r = w.f.run("nginx-restore", "--op", opB)
	require.Equal(t, 0, code, "the latest operation's restore stays repeatable")
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseCommitted, st["phase"], "the refusal changes nothing")
}

// A later operation that never replaced anything (unchanged, or refused before its first rename)
// does not supersede the earlier one: its rollback stays possible.
func TestRestoreIsNotSupersededByANoOp(t *testing.T) {
	w := newDeployWorld(t)
	w.deployFrom(t, opA, w.leaf, w.newLeaf)
	m := w.deployFrom(t, opB, w.newLeaf, w.newLeaf)
	assert.Equal(t, helperproto.PhaseUnchanged, m["phase"])
	in := w.newInput()
	code, _ := w.f.runWith(in, "nginx-deploy", "--op", "0190f5a0-0000-7000-8000-0000000000d3", "--cert", "/etc/nginx/ssl/www.crt",
		"--key", "/etc/nginx/ssl/www.key", "--expect-cert-sha256", strings.Repeat("e", 64), "--content-sha256", hexOf(in))
	assert.Equal(t, helperproto.ExitPrecondition, code)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	w.assertPair(t, false)
}

// A deployment interrupted and then superseded by a later one is never rolled back: re-sending it
// is refused, and its journal no longer blocks the sweep's 30-day cap.
func TestInterruptedOperationSupersededLater(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(p string) error {
		if p == helperproto.StepConfigTest {
			return errKilled
		}
		return nil
	}
	code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitFailed, code)
	w.revive()
	third := pki.NewCA("Third", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	// Final review A1 m1: the helper itself refuses B while A is interrupted. The state the rest of
	// this test checks (an interrupted A that a later B superseded, as a helper before that fix could
	// leave it) is made by hand: A finished, B committed, then A's journal set back to writing.
	in := input(third.FullchainPEM, third.KeyPEM)
	code, m := w.f.runWith(in, "nginx-deploy", "--op", opB, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", hexOf(string(w.newLeaf.FullchainPEM)), "--content-sha256", hexOf(in))
	require.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	require.Equal(t, helperproto.CodeRecoveryPending, m["code"])
	_, m = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, helperproto.PhaseRestored, m["phase"])
	w.deployFrom(t, opB, w.leaf, third)
	w.setPhase(t, opA, helperproto.PhaseWriting)
	code, m = w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	assert.Equal(t, helperproto.CodeSuperseded, m["code"])
	assert.Equal(t, string(third.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"))
	at := testNow.Add(-40 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
}

// Fix round 1, minor 1: cleanup and the sweep decide under the Nginx lock, even for a directory
// without a journal (a deployment between creating its directory and its first journal). Round 2
// (New-4): cleanup of an empty or authorized_keys directory does not need the lock.
func TestCleanupAndSweepAlwaysTakeTheLock(t *testing.T) {
	w := newDeployWorld(t)
	old := lockWait
	lockWait = 100 * time.Millisecond
	defer func() { lockWait = old }()
	w.f.mkdir(helperproto.BackupRoot+"/"+opA, 0o700)
	at := testNow.Add(-40 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(w.opPath(opA), at, at))
	w.f.mkdir(helperproto.BackupRoot+"/"+opB, 0o700) // an Nginx operation before its first journal
	w.f.write(helperproto.BackupRoot+"/"+opB+"/cert.bak", "c", 0o600)
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	code, m := w.f.run("cleanup", "--op", opB)
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	assert.DirExists(t, w.opPath(opB))
	w.f.s.sweepBackups()
	assert.DirExists(t, w.opPath(opA))
	require.NoError(t, lock.Close())
	w.f.s.sweepBackups()
	assert.NoDirExists(t, w.opPath(opA))
}

// Fix round 1, minor 2: the journal cannot say "writing": nothing was replaced, so the answer is a
// refusal and nginx -t and the reload never run.
func TestDeployWritingJournalFailureIsARefusal(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.afterDeployStep = func(p string) error {
		if p == "journal "+helperproto.PhaseWriting+" staged" {
			return errInjected
		}
		return nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitFailed, code, "%v", m)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	w.assertPair(t, false)
	w.assertNoLeftovers(t)
	assert.Equal(t, 0, w.reloads)
	assert.NotContains(t, w.calls, "-t")
	w.f.s.afterDeployStep = nil
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Contains(t, []any{helperproto.PhaseNone, helperproto.PhasePrepared}, st["phase"])
}

// Fix round 1, minor 3: a refusal after the operation directory was created removes it again.
func TestDeployRefusalsRemoveTheNewOperationDirectory(t *testing.T) {
	w := newDeployWorld(t)
	w.f.s.statfs = func(fd int) (int64, error) {
		var st, op unix.Stat_t
		if unix.Fstat(fd, &st) == nil && unix.Stat(w.opPath(opA), &op) == nil && sameFile(st, op) {
			return 1 << 20, nil
		}
		return 1 << 30, nil
	}
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitPrecondition, code, "%v", m)
	assert.Equal(t, helperproto.CodeNoSpace, m["code"])
	assert.NoDirExists(t, w.opPath(opA))

	w = newDeployWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.f.s.statfs = func(fd int) (int64, error) {
		var st, op unix.Stat_t
		if unix.Fstat(fd, &st) == nil && unix.Stat(w.opPath(opA), &op) == nil && sameFile(st, op) {
			cancel() // the budget ends right after the directory was made
		}
		return 1 << 30, nil
	}
	in := w.newInput()
	w.f.s.stdin = strings.NewReader(in)
	_, err := cmdNginxDeploy(ctx, w.f.s, []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in)})
	var he *helperError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, helperproto.CodeIOError, he.code)
	assert.NoDirExists(t, w.opPath(opA))

	for _, p := range []string{"journal " + helperproto.PhasePrepared + " staged", "backup " + kindCert} {
		w = newDeployWorld(t)
		w.f.s.afterDeployStep = func(q string) error {
			if q == p {
				return errInjected
			}
			return nil
		}
		code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
		assert.Equal(t, helperproto.ExitFailed, code, p)
		assert.NoDirExists(t, w.opPath(opA), p)
	}
}

// Fix round 1, minor 4: a forged section that exactly matches a root-only file (here an empty one)
// is not reached by any include of an earlier section: the dump is untrusted, whether or not a
// writable file came first, and the answer is the same as for a missing file.
func TestAttackForgedSectionMatchingAnEmptyRootFile(t *testing.T) {
	for _, writable := range []bool{false, true} {
		answers := map[string]any{}
		for _, probe := range []string{"/root/empty.txt", "/root/nope.txt"} {
			w := newNginxWorld(t)
			w.f.write("/root/empty.txt", "", 0o600)
			dump := w.dumpText()
			if writable {
				w.f.write("/etc/nginx/conf.d/evil.conf", "", 0o666)
				dump += "# configuration file /etc/nginx/conf.d/evil.conf:\n\n"
			}
			w.setDump(dump + "# configuration file " + probe + ":\n\n")
			_, m := w.f.run("nginx-dump")
			assert.Equal(t, false, m["config_valid"], "%s writable=%v", probe, writable)
			answers[probe] = fmt.Sprint(m["config_error"], m["config_error_reason"], m["config_error_file"])
		}
		assert.Equal(t, answers["/root/empty.txt"], answers["/root/nope.txt"], "writable=%v", writable)
	}
}

// Minor 4 keeps real layouts working: includes inside location blocks, relative includes, globs,
// and an include of mime.types at the http level.
func TestIncludedSectionsAreAccepted(t *testing.T) {
	w := newNginxWorld(t)
	w.f.mkdir("/etc/nginx/snippets", 0o755)
	main := "http { include mime.types; include conf.d/*.conf; }\n"
	site := wwwConf + "server { listen 80; location / { include snippets/proxy.conf; } }\n"
	w.setConf(confFile{"/etc/nginx/nginx.conf", main}, confFile{"/etc/nginx/mime.types", "types { text/html html; }\n"},
		confFile{"/etc/nginx/conf.d/www.conf", site}, confFile{"/etc/nginx/snippets/proxy.conf", "proxy_pass http://127.0.0.1:8080;\n"})
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, true, m["config_valid"], "%v", m)
}

// Fix round 1, minor 5: the key's group is compared with root's group through the same
// indirection as its owner.
func TestKeyOpenUsesRootsGroup(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.key"), 0o640))
	_, m := w.f.run("nginx-dump")
	assert.NotContains(t, m["warnings"], helperproto.WarnKeyGroupOpen, "root's group (the fixture's)")
	w.f.s.rootGID++
	_, m = w.f.run("nginx-dump")
	assert.Contains(t, m["warnings"], helperproto.WarnKeyGroupOpen)
}
