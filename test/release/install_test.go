//go:build release

package release

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preflightOK are the [ OK ] lines of install.sh's preflight that every distribution container must show. "Clock sane"
// is not among them: the containers have no systemd, so timedatectl is missing and install.sh prints the C4 clock
// warning instead (asserted below; the [ OK ] line is checked on the owner's VM).
var preflightOK = []string{
	"Running as root", "Linux x86_64", "Docker installed and running", "Docker 24 or newer with the compose plugin",
	"Docker socket restricted", "OpenSSL 3", "Free disk ≥ 20 GB", "Memory ≥ 4 GB, CPU ≥ 2", "Port free", "Package signature",
	"Package complete", "Package lists exactly its files", "No installation yet", "Images loaded and checked",
}

const clockWarning = "[WARN] Alice could not confirm that the clock is synchronised. Make sure NTP is running; licenses depend on the time."

// TestReleaseInstallMatrix installs rc.2 in Ubuntu 22.04, Debian 12 and Rocky Linux 9 containers without network and
// checks the running stack: health, the C3 hardening of the running containers, selfcheck, the setup code, no pull.
func TestReleaseInstallMatrix(t *testing.T) {
	for n, distro := range distros {
		t.Run(distro, func(t *testing.T) {
			i := newInst(t, "matrix-"+distro, distro, 19440+n)
			start := time.Now()
			r := i.install(rc2)
			end := time.Now()
			require.Equal(t, 0, r.Code, redactSetupCode(r.Out))
			for _, label := range preflightOK {
				assert.Contains(t, r.Out, ok+label+"\n")
			}
			assert.NotContains(t, r.Out, "[FAIL]")
			if !strings.Contains(r.Out, ok+"Clock sane\n") {
				assert.Contains(t, r.Out, clockWarning+"\n", "without timedatectl the clock line is the C4 warning")
			}
			assert.Contains(t, r.Out, "[WARN] This package is signed with a TEST key. Never install it for production.\n")
			assert.Contains(t, r.Out, "Package signed by release key rk-test-01 (SHA-256 fingerprint "+fingerprint+
				"). Compare this fingerprint with the one your vendor published.\n")
			assert.Contains(t, r.Out, "\nAlice "+rc2+" is installed and running.\n")
			assert.Contains(t, r.Out, "  Open this address in your web browser:   https://"+hostName+":"+itoa(i.port)+"/setup\n")
			code := setupCode(t, r.Out)
			log := string(i.readFile(filepath.Join(i.dir, "install.log")))
			// Plain booleans: a failing Contains would print the log and the code into the test log (M-1).
			assert.False(t, strings.Contains(log, code), "the setup code is printed to the terminal only (S-4)")
			assert.True(t, strings.Contains(log, "Setup code printed to the terminal (not logged)."), "install.log names where the setup code went")

			// Both services healthy; migrate ran (and was removed) before alice started.
			ps := must(t, i.compose("ps", "--all", "--format", "{{.Service}} {{.State}} {{.Health}}"), "compose ps").Out
			assert.ElementsMatch(t, []string{"alice running healthy", "postgres running healthy"}, lines(strings.TrimSpace(ps)), ps)
			assert.Equal(t, latestMigration(t), i.psql("SELECT max(version_id) FROM goose_db_version WHERE is_applied"), "the migrate service applied every migration")

			// What this engine reports for the loaded images, against the two identifiers RELEASE records (the config
			// digest for a classic image store, the manifest or index digest for a containerd store; fedcd79).
			rel := string(i.readFile(filepath.Join(i.dir, "RELEASE")))
			for _, img := range []struct{ tag, key string }{{"alice:" + rc2, "ALICE"}, {"alice-postgres:" + rc2, "POSTGRES"}} {
				id := strings.TrimSpace(must(t, docker(t, "image", "inspect", "--format", "{{.Id}}", img.tag), "image inspect").Out)
				cfg, dig := releaseValue(rel, img.key+"_IMAGE_ID"), releaseValue(rel, img.key+"_IMAGE_DIGEST")
				t.Logf("%s: docker image inspect .Id %s (RELEASE %s_IMAGE_ID %s, %s_IMAGE_DIGEST %s)", img.tag, id, img.key, cfg, img.key, dig)
				assert.Contains(t, []string{cfg, dig}, id)
			}

			checkHardening(t, i)
			i.selfcheck()

			c := i.client()
			c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/session", map[string]string{"code": code})

			assert.Empty(t, pulls(t, start, end), "no image was pulled during the install (the container had --network none)")
		})
	}
}

// checkHardening asserts C3 on the running containers.
func checkHardening(t *testing.T, i *inst) {
	t.Helper()
	for _, svc := range []string{"alice", "postgres"} {
		id := i.container(svc)
		require.NotEmpty(t, id, svc)
		info := inspect(t, id)
		assert.True(t, info.HostConfig.ReadonlyRootfs, "%s: read-only root file system", svc)
		assert.Equal(t, []string{"ALL"}, info.HostConfig.CapDrop, "%s: every capability dropped", svc)
		assert.Empty(t, info.HostConfig.CapAdd, "%s: no capability added", svc)
		assert.Contains(t, info.HostConfig.SecurityOpt, "no-new-privileges:true", svc)
		assert.False(t, info.HostConfig.Privileged, svc)
		secrets := map[string]bool{}
		for _, m := range info.Mounts {
			if strings.HasPrefix(m.Destination, "/run/secrets/") {
				secrets[strings.TrimPrefix(m.Destination, "/run/secrets/")] = true
				assert.Equal(t, filepath.Join(i.dir, "secrets", filepath.Base(m.Destination)), m.Source, svc)
			}
		}
		switch svc {
		case "alice":
			assert.Equal(t, "10001:10001", info.Config.User)
			for _, e := range info.Config.Env {
				assert.False(t, strings.HasPrefix(e, "ALICE_MIGRATE_DATABASE_"), "alice holds no owner credential: %s", e)
			}
			assert.Contains(t, info.Config.Env, "ALICE_MIGRATE=external")
			assert.Equal(t, map[string]bool{"db_app_password": true}, secrets, "alice: only the app password")
			binds := map[string]string{}
			for _, m := range info.Mounts {
				if m.Type == "bind" && !strings.HasPrefix(m.Destination, "/run/secrets/") {
					binds[m.Destination] = m.Source
				}
			}
			assert.Equal(t, map[string]string{
				"/opt/alice/keys": filepath.Join(i.dir, "keys"), "/opt/alice/state": filepath.Join(i.dir, "state"),
				"/opt/alice/backups": filepath.Join(i.dir, "backups"),
			}, binds)
			published := info.NetworkSettings.Ports["8443/tcp"]
			require.NotEmpty(t, published)
			for _, p := range published {
				assert.Equal(t, "127.0.0.1", p.HostIP, "--bind 127.0.0.1")
				assert.Equal(t, itoa(i.port), p.HostPort)
			}
		case "postgres":
			assert.Equal(t, "70:70", info.Config.User)
			assert.Empty(t, info.HostConfig.PortBindings, "postgres publishes no port")
			for port, b := range info.NetworkSettings.Ports {
				assert.Empty(t, b, "postgres publishes no port (%s)", port)
			}
			assert.Equal(t, map[string]bool{"db_postgres_password": true, "db_owner_password": true, "db_app_password": true}, secrets)
		}
	}
	// The secret files on the host: modes and owners of C2.
	r := must(t, i.sh("cd \"$1\" && stat -c '%n %a %u:%g' *", filepath.Join(i.dir, "secrets")), "stat secrets")
	assert.ElementsMatch(t, []string{"db_app_password 440 70:10001", "db_owner_password 440 70:10001", "db_postgres_password 400 70:70"},
		lines(strings.TrimSpace(r.Out)))
}

// TestReleaseRefusesTamperedAndDowngrade: a package whose image changed with a re-made SHA256SUMS but the old
// signature, the original package with a .sha256.sig of another key, and an older package are all refused, and the
// installation is unchanged.
func TestReleaseRefusesTamperedAndDowngrade(t *testing.T) {
	i := newInst(t, "tamper", "rocky9", 19446)
	require.Equal(t, 0, i.install(rc2).Code)
	before := must(t, i.compose("ps", "--format", "{{.Service}} {{.ID}} {{.State}}"), "compose ps").Out

	const installSig = "[FAIL] The package signature is not valid. Do not install this package; download it again and check it with your vendor."
	const updateSig = "[FAIL] The update package signature is not valid. Do not install this package; download it again and check it with your vendor."

	t.Run("changed-image-old-signature", func(t *testing.T) {
		pkg := i.extract(rc2)
		tampered := filepath.Join(i.work, "tampered", "alice")
		must(t, i.sh(`set -e
mkdir -p "$(dirname "$2")"; cp -a "$1" "$2"; cd "$2"
f=images/alice-$3.tar
b=$(od -An -tu1 -j 4096 -N1 "$f" | tr -d ' ')
printf "$(printf '\\%03o' $(( (b + 1) % 256 )))" | dd of="$f" bs=1 seek=4096 conv=notrunc status=none
find . -type f ! -path ./SHA256SUMS ! -path ./SHA256SUMS.sig | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS`,
			pkg, tampered, rc2), "tamper with the package")
		require.NotEqual(t, i.readFile(filepath.Join(pkg, "SHA256SUMS")), i.readFile(filepath.Join(tampered, "SHA256SUMS")))

		other := newInstDir(i, "tamper-install")
		// Should a regression let this install get past the signature check, its containers and volumes go (M-2).
		t.Cleanup(func() { composeDown(t, "alice-rel-tamper-install") })
		r := i.in(tampered, "./install.sh", "--dir", other, "--port", "19448", "--bind", "127.0.0.1", "--hostname", hostName,
			"--non-interactive", "--project", "alice-rel-tamper-install", "--fingerprint", fingerprint)
		t.Logf("install.sh of the tampered package (exit %d):\n%s", r.Code, r.Out)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, installSig+"\n")
		assert.Equal(t, 1, i.sh("test -e \"$1\"", other).Code, "nothing was installed")

		r = i.in(i.dir, "./alice-update.sh", tampered, "--passphrase-file", i.passphraseFile("pass", passphrase), "--non-interactive")
		t.Logf("alice-update.sh with the tampered package (exit %d):\n%s", r.Code, r.Out)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, updateSig+"\n")
	})

	t.Run("signature-of-another-key", func(t *testing.T) {
		keyDir := filepath.Join(workRoot, "tamper-other-key")
		require.NoError(t, os.RemoveAll(keyDir))
		t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
		run(t, repo, "go", "run", "./tools/releasesign", "generate", keyDir)
		sha := filepath.Join(keyDir, filepath.Base(tarball(rc2))+".sha256")
		data, err := os.ReadFile(tarball(rc2) + ".sha256")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(sha, data, 0o600))
		run(t, repo, "go", "run", "./tools/releasesign", "sign", filepath.Join(keyDir, "test-release.key"), sha)
		sig, err := os.ReadFile(sha + ".sig")
		require.NoError(t, err)

		dl := i.download(rc2)
		i.writeFile(dl+".sha256.sig", sig, "0:0", "0644")
		r := i.in(i.dir, "./alice-update.sh", dl, "--passphrase-file", i.passphraseFile("pass", passphrase), "--non-interactive")
		t.Logf("alice-update.sh with another key's signature (exit %d):\n%s", r.Code, r.Out)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, updateSig+"\n")
	})

	t.Run("downgrade", func(t *testing.T) {
		dl := i.download(rc1)
		r := i.in(i.dir, "./alice-update.sh", dl, "--passphrase-file", i.passphraseFile("pass", passphrase), "--non-interactive")
		t.Logf("alice-update.sh with %s (exit %d):\n%s", rc1, r.Code, r.Out)
		assert.Equal(t, 1, r.Code)
		assert.Contains(t, r.Out, "Going back to an older version is only possible by restoring a backup.\n")
	})

	assert.Equal(t, before, must(t, i.compose("ps", "--format", "{{.Service}} {{.ID}} {{.State}}"), "compose ps").Out, "the same containers run")
	assert.Equal(t, rc2, i.installedVersion())
	assert.Equal(t, rc2, i.runningVersion())
	assert.Empty(t, strings.TrimSpace(i.sh("ls -A \"$1\"", filepath.Join(i.dir, "backups")).Out), "no backup was made")
}

// newInstDir is a second installation directory inside i's work directory (cleaned up with it).
func newInstDir(i *inst, name string) string { return filepath.Join(i.work, name) }

// TestReleaseUninstallKeepsData: --uninstall removes the containers and keeps every directory and backup; --purge
// --confirm DELETE removes the installation directory.
func TestReleaseUninstallKeepsData(t *testing.T) {
	i := newInst(t, "uninstall", "ubuntu22", 19447)
	r := i.install(rc2)
	require.Equal(t, 0, r.Code)
	i.code = setupCode(t, r.Out)
	i.wizard(i.client(), nil, nil)
	backup := must(t, i.alicectl("backup"), "alicectl backup").Out
	require.Contains(t, backup, "Backup written: /opt/alice/backups/")

	pkg := i.extract(rc2)
	r = i.in(pkg, "./install.sh", "--uninstall", "--dir", i.dir)
	t.Logf("install.sh --uninstall (exit %d):\n%s", r.Code, r.Out)
	require.Equal(t, 0, r.Code)
	assert.Contains(t, r.Out, "Alice was stopped and its containers removed. Your data and backups are still in "+i.dir+".\n")
	assert.Empty(t, strings.TrimSpace(docker(t, "ps", "-aq", "--filter", "label=com.docker.compose.project="+i.project).Out), "no container is left")
	for _, d := range []string{"keys", "state", "backups", "data/postgres", "secrets", "release-keys", "lib"} {
		assert.Equal(t, 0, i.sh("test -d \"$1\"", filepath.Join(i.dir, d)).Code, d)
	}
	for _, f := range []string{"keys/master.key", "keys/tls.crt", "docker-compose.yml", ".env", "VERSION", "alicectl"} {
		assert.Equal(t, 0, i.sh("test -f \"$1\"", filepath.Join(i.dir, f)).Code, f)
	}
	assert.Equal(t, 0, i.sh("ls \"$1\"/*.alicebak", filepath.Join(i.dir, "backups")).Code, "the backup is still there")

	r = i.in(pkg, "./install.sh", "--uninstall", "--purge", "--confirm", "DELETE", "--dir", i.dir)
	t.Logf("install.sh --uninstall --purge (exit %d):\n%s", r.Code, r.Out)
	require.Equal(t, 0, r.Code)
	assert.Contains(t, r.Out, "Alice and all its data were deleted from "+i.dir+".\n")
	assert.Equal(t, 1, i.sh("test -e \"$1\"", i.dir).Code, "the installation directory is gone")
}

// run runs a host command in dir and fails the test on an error.
func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...) //nolint:gosec // G204: the harness's own tools
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %s: %s", name, strings.Join(args, " "), out)
}

// latestMigration is the version of the newest migration of this tree (migrations/NNNNN_name.sql), as goose records it.
func latestMigration(t testing.TB) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repo, "migrations", "*.sql"))
	require.NoError(t, err)
	latest := 0
	for _, f := range files {
		prefix, _, found := strings.Cut(filepath.Base(f), "_")
		if n, err := strconv.Atoi(prefix); found && err == nil && n > latest {
			latest = n
		}
	}
	require.Positive(t, latest, "no migration in %s", filepath.Join(repo, "migrations"))
	return strconv.Itoa(latest)
}

// releaseValue is the value of KEY= in a RELEASE file.
func releaseValue(rel, key string) string {
	for _, l := range lines(rel) {
		if v, found := strings.CutPrefix(l, key+"="); found {
			return v
		}
	}
	return ""
}
