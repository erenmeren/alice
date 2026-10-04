//go:build linux

package main

import (
	"context"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

// wildcardDir is an acme.sh-style certificate directory: a name outside the helper's argument
// vocabulary (A1-I1 of the final review).
const wildcardDir = "/etc/nginx/ssl/*.example.test"

// linkIntoWildcardDir moves the pair into wildcardDir and makes the configured names root's links
// to it: the configured paths are valid, the resolved ones are not.
func linkIntoWildcardDir(t *testing.T, w *deployWorld) {
	t.Helper()
	w.f.mkdir(wildcardDir, 0o755)
	w.f.write(wildcardDir+"/fullchain.cer", string(w.leaf.FullchainPEM), 0o644)
	w.f.write(wildcardDir+"/*.example.test.key", string(w.leaf.KeyPEM), 0o600)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.crt")))
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	require.NoError(t, os.Symlink(wildcardDir+"/fullchain.cer", w.f.host("/etc/nginx/ssl/www.crt")))
	require.NoError(t, os.Symlink(wildcardDir+"/*.example.test.key", w.f.host("/etc/nginx/ssl/www.key")))
}

// A1-I1 part 1: a pair whose files resolve to a name the vocabulary cannot carry is refused before
// anything is written (its journal could never be read back).
func TestDeployRefusesAResolvedPathOutsideTheVocabulary(t *testing.T) {
	w := newDeployWorld(t)
	linkIntoWildcardDir(t, w)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code, m)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read(wildcardDir+"/fullchain.cer"))
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read(wildcardDir+"/*.example.test.key"))
	assert.NoDirExists(t, w.opPath(opA), "nothing written: no operation directory")
	assert.Equal(t, 0, w.reloads)

	// Status of that operation is "none", not an unreadable journal.
	code, m = w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseNone, m["phase"])
}

// A1-I1 part 2: nginx-dump reports such a file with a closed problem, so Alice shows the location
// unsupported.
func TestNginxDumpReportsAResolvedNameOutsideTheVocabulary(t *testing.T) {
	w := newDeployWorld(t)
	linkIntoWildcardDir(t, w)
	_, m := w.f.run("nginx-dump")
	cert := fileOf(t, m, "cert", "/etc/nginx/ssl/www.crt")
	assert.Equal(t, helperproto.FileNameNotAllowed, cert["problem"])
	assert.Equal(t, "", cert["pem"], "the file is not read")
	key := fileOf(t, m, "key", "/etc/nginx/ssl/www.key")
	assert.Equal(t, helperproto.FileNameNotAllowed, key["problem"])
}

// A1-I1 part 3: the helper never writes a journal it cannot read back.
func TestWriteJournalRefusesAJournalItCouldNotRead(t *testing.T) {
	w := newDeployWorld(t)
	dir, err := w.f.s.opDir(opA, true)
	require.NoError(t, err)
	defer func() { _ = dir.Close() }()
	j := validJournal(opA)
	j.CertResolved = wildcardDir + "/fullchain.cer"
	require.Error(t, w.f.s.writeJournal(dir, j))
	_, found, err := readJournal(dir, opA)
	require.NoError(t, err)
	assert.False(t, found, "nothing was written")
}

func validJournal(op string) journal {
	return journal{Op: op, Phase: helperproto.PhaseCommitted, CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key",
		CertResolved: "/etc/nginx/ssl/www.crt", KeyResolved: "/etc/nginx/ssl/www.key", Steps: []helperproto.NginxStep{}}
}

// The property: every journal writeJournal accepts is one readJournal reads back, equal.
func TestEveryJournalWriteJournalAcceptsIsReadable(t *testing.T) {
	w := newDeployWorld(t)
	dir, err := w.f.s.opDir(opA, true)
	require.NoError(t, err)
	defer func() { _ = dir.Close() }()
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a deterministic test generator
	paths := []string{"/etc/nginx/ssl/www.crt", "/", "", "relative.crt", "/a b.crt", "/*.x/c.pem", "/etc/../x.pem", "/é.pem",
		"/etc/ssl/a,b.pem", "/~x.pem", "/-x.pem", "/" + strings.Repeat("a", 5000)}
	phases := append(append([]string{}, journalPhases...), "", "bogus", helperproto.PhaseNone)
	ops := []string{opA, opB, "", "not-an-op"}
	accepted := 0
	for range 3000 {
		j := journal{Op: opA, Phase: phases[r.IntN(len(phases))],
			CertPath: paths[r.IntN(len(paths))], KeyPath: paths[r.IntN(len(paths))],
			CertResolved: paths[r.IntN(len(paths))], KeyResolved: paths[r.IntN(len(paths))],
			PrevRecord: ops[r.IntN(len(ops))], Steps: make([]helperproto.NginxStep, r.IntN(maxSteps+3))}
		if r.IntN(8) == 0 {
			j.Op = ops[r.IntN(len(ops))]
		}
		if r.IntN(4) == 0 {
			j.CertPath, j.KeyPath, j.CertResolved, j.KeyResolved = paths[0], "/etc/nginx/ssl/www.key", paths[0], "/etc/nginx/ssl/www.key"
		}
		if err := w.f.s.writeJournal(dir, j); err != nil {
			continue
		}
		accepted++
		got, found, err := readJournal(dir, opA)
		require.NoError(t, err, "%+v", j)
		require.True(t, found)
		assert.Equal(t, j.Phase, got.Phase)
		assert.Equal(t, j.CertResolved, got.CertResolved)
	}
	assert.Positive(t, accepted, "the generator produces valid journals too")
}

// A1-I1 part 4: cleanup --op never removes an operation whose journal exists but cannot be read
// (its backups may be the only way back; the sweep keeps it 30 days).
func TestCleanupKeepsAnOperationWhoseJournalCannotBeRead(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitOK, code, m)
	w.f.write(helperproto.BackupRoot+"/"+opA+"/journal.json", `{"op":"`+opA+`","phase":"writing","cert_path":"/a b"}`, 0o600)
	code, m = w.f.run("cleanup", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code, m)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	assert.FileExists(t, w.opPath(opA)+"/"+certBackup)
	assert.FileExists(t, w.opPath(opA)+"/"+keyBackup)
}

// A1-I2: once nginx-restore has put a file back, a key changed by someone else before its own
// rename is not "HASH_MISMATCH, left as it is" (Alice would read "nothing was restored"): the
// answer is exit 0, restore_failed, failed_step restore, error file_changed, as the journal says.
func TestRestoreKeyChangedBetweenTheRestoreRenames(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitOK, code, m)
	require.Equal(t, helperproto.PhaseCommitted, m["phase"])
	w.f.s.afterDeployStep = func(name string) error {
		if name == "renamed "+stagedName(opA, kindCert) {
			w.f.write("/etc/nginx/ssl/www.key", "someone else's key\n", 0o600)
		}
		return nil
	}
	code, m = w.f.run("nginx-restore", "--op", opA)
	w.f.s.afterDeployStep = nil
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRestore, m["failed_step"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, m["error"])
	assert.Equal(t, string(w.leaf.FullchainPEM), w.f.read("/etc/nginx/ssl/www.crt"), "the certificate was put back")
	assert.Equal(t, "someone else's key\n", w.f.read("/etc/nginx/ssl/www.key"), "the other party's key is left")
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, helperproto.PhaseRestoreFailed, st["phase"])
	assert.Equal(t, helperproto.RestoreErrFileChanged, st["error"])

	// Another nginx-restore changes nothing now: that one is the refusal.
	code, m = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
}

// A1-I2 before any rename: the refusal stays HASH_MISMATCH and nothing is restored.
func TestRestoreFileChangedBeforeAnyRenameIsARefusal(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitOK, code, m)
	w.f.s.afterDeployStep = func(name string) error {
		if name == "staged "+stagedName(opA, kindCert) {
			w.f.write("/etc/nginx/ssl/www.crt", "someone else's certificate\n", 0o644)
		}
		return nil
	}
	code, m = w.f.run("nginx-restore", "--op", opA)
	w.f.s.afterDeployStep = nil
	assert.Equal(t, helperproto.ExitPrecondition, code, m)
	assert.Equal(t, helperproto.CodeHashMismatch, m["code"])
	assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"), "nothing restored")
}

// m6: nothing is renamed while the journal cannot say restoring; nginx-restore refuses (nothing was
// restored) and the deployment's own rollback answers restore_failed at its restore step.
func TestRestoreRefusesWhenTheRestoringJournalCannotBeWritten(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, w.newInput(), w.oldSHA())
	require.Equal(t, helperproto.ExitOK, code, m)
	w.f.s.afterDeployStep = func(name string) error {
		if strings.HasPrefix(name, "journal restoring") {
			return errFailedWrite
		}
		return nil
	}
	code, m = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitFailed, code, m)
	assert.Equal(t, helperproto.CodeIOError, m["code"])
	w.assertPair(t, true)

	// Inside a deployment's own rollback (nginx -t fails), the answer is restore_failed / restore.
	w.f.s.afterDeployStep = func(name string) error {
		if strings.HasPrefix(name, "journal restoring") {
			return errFailedWrite
		}
		return nil
	}
	w.testFail = 1
	in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
	code, m = w.deploy(opB, in, hexOf(string(w.newLeaf.FullchainPEM)))
	w.f.s.afterDeployStep = nil
	assert.Equal(t, helperproto.ExitOK, code, m)
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRestore, m["failed_step"])
	assert.Equal(t, helperproto.StepConfigTest, m["cause_step"])
}

var errFailedWrite = errorString("disk full (test)")

type errorString string

func (e errorString) Error() string { return string(e) }

// m1: the helper itself refuses a new operation on a pair whose latest operation was interrupted
// (writing or restoring): a new one would supersede it, and its rollback would never be possible.
func TestDeployRefusesAPairWhoseLatestOperationWasInterrupted(t *testing.T) {
	for _, point := range []string{helperproto.StepReload, "journal restoring renamed"} {
		t.Run(point, func(t *testing.T) {
			w := newDeployWorld(t)
			if point != helperproto.StepReload {
				w.reloadFail = 1 // the deployment rolls back; it dies during that rollback
			}
			w.f.s.afterDeployStep = func(name string) error {
				if name == point {
					return errKilled
				}
				return nil
			}
			code, _ := w.deploy(opA, w.newInput(), w.oldSHA())
			require.Equal(t, helperproto.ExitFailed, code)
			w.revive()
			_, st := w.f.run("nginx-status", "--op", opA)
			require.Contains(t, []string{helperproto.PhaseWriting, helperproto.PhaseRestoring}, st["phase"])
			before := w.f.read("/etc/nginx/ssl/www.crt")

			cur := hexOf(before)
			in := input(w.leaf.FullchainPEM, w.leaf.KeyPEM)
			if before == string(w.leaf.FullchainPEM) {
				in = w.newInput()
			}
			code, m := w.deploy(opB, in, cur)
			assert.Equal(t, helperproto.ExitPrecondition, code, m)
			assert.Equal(t, helperproto.CodeRecoveryPending, m["code"])
			assert.NoDirExists(t, w.opPath(opB))
			assert.Equal(t, before, w.f.read("/etc/nginx/ssl/www.crt"))

			// The interrupted operation is still the pair's latest: nginx-restore repairs it, and then
			// a new operation goes through.
			code, r := w.f.run("nginx-restore", "--op", opA)
			require.Equal(t, helperproto.ExitOK, code, r)
			w.assertPair(t, false)
			code, m = w.deploy(opB, w.newInput(), w.oldSHA())
			assert.Equal(t, helperproto.ExitOK, code, m)
			assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
		})
	}
}

// m3: without systemctl, or with Nginx not running, a reload cannot work: refused before anything
// is written.
func TestDeployRefusesWhenNginxIsNotRunning(t *testing.T) {
	for name, fail := range map[string]error{
		"inactive":          errorString("exit status 3"),
		"systemctl missing": &os.PathError{Op: "fork/exec", Path: systemctlPath, Err: os.ErrNotExist},
	} {
		t.Run(name, func(t *testing.T) {
			w := newDeployWorld(t)
			var calls []string
			w.f.s.runSystemctl = func(_ context.Context, args ...string) error {
				calls = append(calls, strings.Join(args, " "))
				return fail
			}
			code, m := w.deploy(opA, w.newInput(), w.oldSHA())
			assert.Equal(t, helperproto.ExitPrecondition, code, m)
			assert.Equal(t, helperproto.CodeNginxNotRunning, m["code"])
			assert.Equal(t, []string{"is-active --quiet nginx"}, calls)
			w.assertPair(t, false)
			assert.NoDirExists(t, w.opPath(opA))
		})
	}
	t.Run("systemctl killed: nothing changed, IO_ERROR", func(t *testing.T) {
		w := newDeployWorld(t)
		w.f.s.runSystemctl = func(context.Context, ...string) error { return errProgramKilled }
		code, m := w.deploy(opA, w.newInput(), w.oldSHA())
		assert.Equal(t, helperproto.ExitFailed, code, m)
		assert.Equal(t, helperproto.CodeIOError, m["code"])
		w.assertPair(t, false)
	})
}

// The typed-error guard: once a file was renamed, nginx-deploy and nginx-restore never answer an
// error that reads as a refusal (nothing changed); an unexpected one becomes OUTCOME_UNKNOWN, which
// no refusal table of Alice holds.
func TestNoRefusalAfterTheFirstRename(t *testing.T) {
	s := &sys{}
	for _, err := range []error{errorString("untyped"), refused(helperproto.CodePathNotAllowed, "x"),
		precondition(helperproto.CodeHashMismatch, "x"), failed(helperproto.CodeIOError, "x")} {
		s.renamed = false
		assert.Equal(t, err, s.afterRename(err), "before a rename an error passes")
		s.renamed = true
		var he *helperError
		require.ErrorAs(t, s.afterRename(err), &he)
		assert.Equal(t, helperproto.CodeOutcomeUnknown, he.code)
		assert.Equal(t, helperproto.ExitFailed, he.exit)
	}
	assert.NoError(t, s.afterRename(nil))
}
