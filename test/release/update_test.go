//go:build release

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

func rollbackSentence(to, from string) string {
	return "The update to " + to + " failed and Alice was returned to " + from + ". Your data is unchanged as of "
}

// update runs alice-update.sh from the installation directory, as C4 says (cd <dir> && ./alice-update.sh …).
func (i *inst) update(pkg, pass string) result {
	i.t.Helper()
	r := i.in(i.dir, "./alice-update.sh", pkg, "--passphrase-file", pass, "--non-interactive")
	i.t.Logf("alice-update.sh %s (exit %d):\n%s", filepath.Base(pkg), r.Code, r.Out)
	return r
}

// TestReleaseUpdateAndRollback: rc.1 is updated to rc.2 with a pre-upgrade backup; then a failing migration, a killed
// migration and a wrong image are each rolled back or stopped, and rc.2 keeps running with its data (F-68, M-4, S-15).
func TestReleaseUpdateAndRollback(t *testing.T) {
	i := newInst(t, "update", "debian12", 19445)
	r := i.install(rc1)
	require.Equal(t, 0, r.Code)
	i.code = setupCode(t, r.Out)
	c, admin := i.wizard(i.client(), nil, nil)
	stepUp(c, admin)
	createUser(c, &account{username: "operator1", password: "release harness operator1 lantern 7", role: "operator"})
	createUser(c, &account{username: "auditor1", password: "release harness auditor1 lantern 7", role: "auditor"})
	now := time.Now()
	leaf := pki.NewCA("Alice release update", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "update.alice-rel.test"}, now)
	upload(c, "update", string(leaf.FullchainPEM), string(leaf.KeyPEM))
	seeded := i.counts()
	require.Equal(t, int64(3), seeded["users"])
	require.Equal(t, int64(1), seeded["certificates"])
	pass := i.passphraseFile("pass", passphrase)

	r = i.update(i.download(rc2), pass)
	require.Equal(t, 0, r.Code)
	assert.Contains(t, r.Out, "[WARN] This package is signed with a TEST key. Never install it for production.\n")
	assert.Contains(t, r.Out, "Alice is now version "+rc2+".\n")
	assert.Equal(t, rc2, i.installedVersion())
	assert.Equal(t, rc2, i.runningVersion())
	i.selfcheck()
	afterUpdate := i.counts()
	assert.Equal(t, seeded["users"], afterUpdate["users"], "the users are still there")
	assert.Equal(t, seeded["certificates"], afterUpdate["certificates"], "the certificate is still there")
	backups := must(t, i.sh("cd \"$1\" && ls", filepath.Join(i.dir, "backups")), "ls backups").Out
	assert.Regexp(t, regexp.MustCompile(`(?m)^alice-backup-[0-9A-Z]{8}-[0-9]{8}T[0-9]{6}Z-pre-upgrade-`+regexp.QuoteMeta(rc1)+`\.alicebak$`), backups)
	signInAgain := func() {
		uc := i.signIn(admin)
		uc.expect(http.StatusOK, http.MethodGet, "/api/v1/certificates", nil)
	}
	signInAgain()

	// unchanged checks what every refused or rolled-back update must leave: rc.2 installed, running and healthy, the
	// same data. The attempt records its pre-update backup (backup.created and the backup.state setting) and, when it
	// returned to the backup, the restore (system.restored, the backup.restore_id setting, sessions ended).
	unchanged := func(t *testing.T, before snapshot, restored bool) {
		t.Helper()
		assert.Equal(t, rc2, i.installedVersion())
		assert.Equal(t, rc2, i.runningVersion())
		i.t = t
		i.selfcheck()
		i.requireSame(before, []string{"backup.created", "system.restored"}, []string{"backup.state", "backup.restore_id"}, restored)
		assert.Empty(t, i.psql("SELECT pid FROM pg_stat_activity WHERE query LIKE '%pg_sleep%' AND pid <> pg_backend_pid()"), "no leftover migration")
	}
	parent := i.t
	defer func() { i.t = parent }()

	t.Run("failing-migration", func(t *testing.T) {
		i.t = t
		before := i.snapshot()
		r := i.update(i.download(rc3), pass)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, rollbackSentence(rc3, rc2))
		unchanged(t, before, true)
	})

	t.Run("killed-migration", func(t *testing.T) {
		i.t = t
		before := i.snapshot()
		dl := i.download(rc4)
		name := i.project + "-updater"
		trackContainer(name)
		done := make(chan result, 1)
		go func() {
			args := append([]string{"run", "--rm", "--name", name, "--network", "none", "-v", "/var/run/docker.sock:/var/run/docker.sock",
				"-v", i.work + ":" + i.work, "-w", i.dir, installImage(i.distro)}, "./alice-update.sh", dl, "--passphrase-file", pass, "--non-interactive")
			done <- runCmd(t, nil, "docker", args...)
		}()
		var migrate string
		eventually(t, 5*time.Minute, time.Second, "the migrate container of the update", func() (bool, string) {
			migrate = strings.TrimSpace(docker(t, "ps", "-q", "--filter", "label=com.docker.compose.project="+i.project,
				"--filter", "label=com.docker.compose.service=migrate").Out)
			return migrate != "", ""
		})
		time.Sleep(10 * time.Second)
		assert.NotEmpty(t, i.psql("SELECT pid FROM pg_stat_activity WHERE query LIKE '%pg_sleep%' AND pid <> pg_backend_pid()"),
			"the slow migration runs")
		must(t, docker(t, "kill", migrate), "docker kill the migrate container")
		var r result
		select {
		case r = <-done:
		case <-time.After(10 * time.Minute):
			t.Fatal("alice-update.sh did not end within 10 minutes after the kill")
		}
		t.Logf("alice-update.sh %s with the migrate container killed (exit %d):\n%s", filepath.Base(dl), r.Code, r.Out)
		assert.Equal(t, 1, r.Code, "rolled back, not exit 3")
		assert.Contains(t, r.Out, rollbackSentence(rc4, rc2))
		unchanged(t, before, true)
	})

	t.Run("stopped-before-change", func(t *testing.T) {
		i.t = t
		before := i.snapshot()
		pkg := restagedWithImageID(t, rc3, rc2)
		dl := filepath.Join(i.work, "dl-restaged")
		r := docker(t, "run", "--rm", "--network", "none", "-v", i.work+":"+i.work, "-v", filepath.Dir(pkg)+":"+filepath.Dir(pkg)+":ro",
			installImage("ubuntu22"), "bash", "-c", "set -e; install -d -m 0755 \"$1\"; for f in \"$2\" \"$2.sha256\" \"$2.sha256.sig\"; do install -m 0644 \"$f\" \"$1/\"; done",
			"bash", dl, pkg)
		must(t, r, "copy the restaged package")
		r = i.update(filepath.Join(dl, filepath.Base(pkg)), pass)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, "[FAIL] The installation package is damaged or incomplete. Download it again and compare the checksum.\n")
		assert.Contains(t, r.Out, "The update was stopped before any change; Alice is running version "+rc2+" again.\n")
		unchanged(t, before, false)
	})
	i.t = parent
	signInAgain()
}

// restagedWithImageID is a copy of the stage of version v whose RELEASE names the image of version other (ALICE_IMAGE_ID
// and ALICE_IMAGE_DIGEST), with SHA256SUMS made again and signed again with the test key, packed with its .sha256 and
// .sha256.sig: a correctly signed package whose image does not match its RELEASE (S-15). It returns the tarball.
func restagedWithImageID(t *testing.T, v, other string) string {
	t.Helper()
	root := filepath.Join(workRoot, "restaged-"+v)
	require.NoError(t, os.RemoveAll(root))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	require.NoError(t, os.MkdirAll(root, 0o755))
	stage := filepath.Join(root, "alice")
	run(t, repo, "cp", "-a", filepath.Join(releaseDir, "alice-"+v, "alice"), stage)

	rel, err := os.ReadFile(filepath.Join(stage, "RELEASE")) //nolint:gosec // G304: the harness's own stage copy
	require.NoError(t, err)
	otherRel, err := os.ReadFile(filepath.Join(releaseDir, "alice-"+other, "alice", "RELEASE")) //nolint:gosec // G304: a stage
	require.NoError(t, err)
	out := string(rel)
	for _, key := range []string{"ALICE_IMAGE_ID", "ALICE_IMAGE_DIGEST"} {
		re := regexp.MustCompile(`(?m)^` + key + `=.*$`)
		want := re.FindString(string(otherRel))
		require.NotEmpty(t, want, key)
		require.NotEqual(t, want, re.FindString(out), key)
		out = re.ReplaceAllLiteralString(out, want)
	}
	require.NoError(t, os.WriteFile(filepath.Join(stage, "RELEASE"), []byte(out), 0o644)) //nolint:gosec // G306: a package file

	// SHA256SUMS: every file but itself and its signature, relative paths sorted (C5).
	var names []string
	require.NoError(t, filepath.WalkDir(stage, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rp, err := filepath.Rel(stage, p)
		if err == nil && rp != "SHA256SUMS" && rp != "SHA256SUMS.sig" {
			names = append(names, rp)
		}
		return err
	}))
	sort.Strings(names)
	var sums strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sums, "%s  %s\n", fileSHA256(t, filepath.Join(stage, n)), n)
	}
	require.NoError(t, os.WriteFile(filepath.Join(stage, "SHA256SUMS"), []byte(sums.String()), 0o644)) //nolint:gosec // G306: a package file
	require.NoError(t, os.Remove(filepath.Join(stage, "SHA256SUMS.sig")))
	testKey := filepath.Join(repo, "bin", "release-test-key", "test-release.key")
	run(t, repo, "go", "run", "./tools/releasesign", "sign", testKey, filepath.Join(stage, "SHA256SUMS"))

	pkg := filepath.Join(root, "alice-"+v+".tar.gz")
	run(t, root, "tar", "-czf", pkg, "alice")
	require.NoError(t, os.WriteFile(pkg+".sha256", []byte(fileSHA256(t, pkg)+"  "+filepath.Base(pkg)+"\n"), 0o644)) //nolint:gosec // G306: a package file
	run(t, repo, "go", "run", "./tools/releasesign", "sign", testKey, pkg+".sha256")
	return pkg
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the harness's own files
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}
