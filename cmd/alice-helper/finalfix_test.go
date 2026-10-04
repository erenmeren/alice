//go:build linux

package main

import (
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
