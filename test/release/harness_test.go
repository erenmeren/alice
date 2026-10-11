//go:build release

// Package release is the release harness (Task 13, make test-release): it installs real test-signed release packages
// with the shipped install.sh, alice-update.sh and alicectl in Ubuntu 22.04, Debian 12 and Rocky Linux 9 containers that
// have no network (--network none) and drive the host's Docker engine through its socket, exactly as on a server. It
// runs the backup-wipe-restore drill (F-85), the restore refusals, the update with its automatic rollback (F-68), the
// refusal of tampered and older packages, and the uninstall.
//
// Docker rules: TestMain refuses to start when one of the image tags it would create already exists (it never removes
// an image it did not create, M-22), every installation uses its own compose project alice-rel-<name> and a port in
// 19440-19449 on 127.0.0.1, and every container, network, volume, work directory and image tag the run created is
// removed again. Nothing is pruned. The work directories live under bin/release-work/ of this tree (M-23); they are
// created and removed through a root container because the installation's files belong to root and to the
// container users.
package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rc1 = "1.0.0-rc.1"
	rc2 = "1.0.0-rc.2"
	rc3 = "1.0.0-rc.3" // BROKEN=fail: an extra migration "SELECT 1/0;"
	rc4 = "1.0.0-rc.4" // BROKEN=sleep: an extra migration "SELECT pg_sleep(120);"

	// hostName is the certificate name of every test installation (--hostname).
	hostName = "alice-rel.test"
	// passphrase is the recovery passphrase of the drill (§20.6); the other installations use it too.
	passphrase = "amber canyon violet orbit lantern harbor"
	// targetImage is the e2e SSH and Nginx target (test/images/e2e-target), built under a tag of this harness.
	targetImage = "alice-test/release-target:phase8"
	// minFree is the free space the work directories need (four packages of ~130 MB, their copies, images, M-23).
	minFree = 25 << 30

	ok = "[ OK ] "
)

var (
	distros  = []string{"ubuntu22", "debian12", "rocky9"}
	versions = []string{rc1, rc2, rc3, rc4}

	repo       string // the repository root
	workRoot   string // <repo>/bin/release-work
	releaseDir string // <repo>/bin/release
	keyFile    string // <repo>/bin/release-test-key/rk-test-01.pem
	// fingerprint is the SHA-256 of the DER form of the test release key: what install.sh shows and --fingerprint takes.
	fingerprint string

	// stopped records the containers a test started besides compose projects, for the final sweep.
	startedMu sync.Mutex
	started   []string
)

func installImage(distro string) string { return "alice-test/install-" + distro + ":phase8" }

// harnessTags are the image tags this harness creates; every one must be absent when it starts (M-22).
func harnessTags() []string {
	var tags []string
	for _, v := range versions {
		tags = append(tags, "alice:"+v, "alice-postgres:"+v)
	}
	for _, d := range distros {
		tags = append(tags, installImage(d))
	}
	return append(tags, targetImage)
}

func TestMain(m *testing.M) { os.Exit(runMain(m)) }

func runMain(m *testing.M) int {
	var err error
	if repo, err = filepath.Abs(filepath.Join("..", "..")); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	workRoot = filepath.Join(repo, "bin", "release-work")
	releaseDir = filepath.Join(repo, "bin", "release")
	keyFile = filepath.Join(repo, "bin", "release-test-key", "rk-test-01.pem")

	for _, tag := range harnessTags() {
		if imageExists(tag) {
			fmt.Fprintf(os.Stderr, "release harness: the image %s already exists. This harness creates and removes it itself and "+
				"never removes an image it did not create; remove it yourself (docker rmi %s), then run again.\n", tag, tag)
			return 1
		}
	}
	// From here on every tag of the list that exists was created by this run.
	defer removeHarnessTags()
	defer sweepContainers()

	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(workRoot, &st); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	if free := st.Bavail * uint64(st.Bsize); free < minFree { //nolint:gosec // G115: block size is positive
		fmt.Fprintf(os.Stderr, "release harness: the file system of %s has %.1f GB free; the harness needs 25 GB.\n", workRoot, float64(free)/1e9)
		return 1
	}
	if err := buildImages(); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	if err := buildReleases(); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	if fingerprint, err = keyFingerprint(keyFile); err != nil {
		fmt.Fprintln(os.Stderr, "release harness:", err)
		return 1
	}
	return m.Run()
}

func imageExists(tag string) bool {
	return exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", tag).Run() == nil //nolint:gosec // G204: a fixed tag
}

func removeHarnessTags() {
	for _, tag := range harnessTags() {
		if imageExists(tag) {
			if out, err := exec.Command("docker", "rmi", tag).CombinedOutput(); err != nil { //nolint:gosec // G204: a fixed tag
				fmt.Fprintf(os.Stderr, "release harness: docker rmi %s: %v: %s\n", tag, err, out)
			}
		}
	}
}

// sweepContainers removes containers a test started and could not remove itself (an aborted run).
func sweepContainers() {
	startedMu.Lock()
	defer startedMu.Unlock()
	for _, name := range started {
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: a harness container name
	}
}

// hostRun runs a command on the host with its output shown (the builds).
func hostRun(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...) //nolint:gosec // G204: the harness's own build commands
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// buildImages builds the three install hosts and the SSH target. The target's build context is a copy of the few
// paths its Dockerfile reads (the helper's sources), so the build does not upload the whole tree.
func buildImages() error {
	for _, d := range distros {
		if err := hostRun(repo, nil, "docker", "build", "--network", "host", "-q", "-t", installImage(d),
			"-f", "test/images/install/"+d+".Dockerfile", "test/images/install"); err != nil {
			return err
		}
	}
	ctx := filepath.Join(workRoot, ".target-context")
	if err := os.RemoveAll(ctx); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(ctx) }()
	for _, p := range []string{"go.mod", "go.sum", "cmd/alice-helper", "internal/providers/linuxssh/helperproto",
		"internal/providers/linuxssh/sshdconf", "internal/providers/nginx/nginxconf", "test/images/e2e-target"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(ctx, p)), 0o755); err != nil {
			return err
		}
		if err := hostRun(repo, nil, "cp", "-a", p, filepath.Join(ctx, p)); err != nil {
			return err
		}
	}
	return hostRun(ctx, nil, "docker", "build", "--network", "host", "-q", "-t", targetImage, "-f", "test/images/e2e-target/Dockerfile", ".")
}

// buildReleases builds rc.1 and rc.2 with make release-test and the two broken packages with make release-broken
// (Task 12, M-7, M-27); all four share the test key of bin/release-test-key. The image tags the builds leave are
// removed afterwards, so every installation loads its images from the package, as on a server.
// RELEASE_HARNESS_REUSE=1 (a development aid; make test-release never sets it) keeps a package that is already built.
func buildReleases() error {
	commit, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	env := []string{"RELEASE_COMMIT=" + strings.TrimSpace(string(commit))}
	if os.Getenv("TRIVY_IMAGE") == "" {
		// Containers on the default bridge cannot reach the LAN DNS on the harness hosts (global constraints).
		env = append(env, "TRIVY_IMAGE=--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969")
	}
	reuse := os.Getenv("RELEASE_HARNESS_REUSE") == "1"
	for _, v := range versions {
		if reuse && packageBuilt(v) {
			fmt.Fprintf(os.Stderr, "release harness: reusing the package %s (RELEASE_HARNESS_REUSE=1)\n", v)
			continue
		}
		var args []string
		switch v {
		case rc3:
			args = []string{"release-broken", "VERSION=" + v, "BROKEN=fail", "SIGN=test"}
		case rc4:
			args = []string{"release-broken", "VERSION=" + v, "BROKEN=sleep", "SIGN=test"}
		default:
			args = []string{"release-test", "VERSION=" + v}
		}
		if err := hostRun(repo, env, "make", args...); err != nil {
			return err
		}
		if !packageBuilt(v) {
			return fmt.Errorf("make %s did not produce the package %s", strings.Join(args, " "), v)
		}
	}
	removeHarnessReleaseTags()
	return nil
}

func removeHarnessReleaseTags() {
	for _, v := range versions {
		for _, tag := range []string{"alice:" + v, "alice-postgres:" + v} {
			if imageExists(tag) {
				_ = exec.Command("docker", "rmi", tag).Run() //nolint:gosec // G204: a harness tag
			}
		}
	}
}

func packageBuilt(v string) bool {
	for _, f := range []string{"", ".sha256", ".sha256.sig"} {
		if _, err := os.Stat(tarball(v) + f); err != nil {
			return false
		}
	}
	return true
}

func tarball(v string) string { return filepath.Join(releaseDir, "alice-"+v+".tar.gz") }

// keyFingerprint is the SHA-256 of the DER public key in a release key file (C5: openssl pkey -outform DER | sha256sum).
func keyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the harness's test key
	if err != nil {
		return "", err
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return "", fmt.Errorf("%s holds no PUBLIC KEY block", path)
		}
		if b.Type == "PUBLIC KEY" {
			sum := sha256.Sum256(b.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
}

// ---- containers ----

// result is what a command in a container printed and how it ended.
type result struct {
	Out    string // standard output and standard error, interleaved
	Stdout []byte
	Code   int
}

// docker runs the host's docker CLI.
func docker(t testing.TB, args ...string) result {
	t.Helper()
	return runCmd(t, nil, "docker", args...)
}

func runCmd(t testing.TB, stdin []byte, name string, args ...string) result {
	t.Helper()
	cmd := exec.Command(name, args...) //nolint:gosec // G204: the harness's own commands
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	// out receives both streams from two goroutines of exec: it must be locked.
	var out lockedBuffer
	var stdout bytes.Buffer
	cmd.Stdout = io.MultiWriter(&out, &stdout)
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return result{Out: out.String(), Stdout: stdout.Bytes(), Code: code}
}

// lockedBuffer is a bytes.Buffer safe for concurrent writers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// must fails the test unless the command exited 0.
func must(t testing.TB, r result, what string) result {
	t.Helper()
	require.Equal(t, 0, r.Code, "%s:\n%s", what, r.Out)
	return r
}

// trackContainer registers a container for the final sweep.
func trackContainer(name string) {
	startedMu.Lock()
	defer startedMu.Unlock()
	started = append(started, name)
}

// ---- installations ----

// inst is one test installation: its work directory bin/release-work/<name> (root-owned 0755, so install.sh's
// ancestor check passes inside the container, where its parents are the root-owned mount points), the installation
// directory <work>/opt, the compose project alice-rel-<name> and a port on 127.0.0.1.
type inst struct {
	t       *testing.T
	name    string
	distro  string
	work    string
	dir     string
	project string
	port    int
	extra   []string // containers started for this installation (the SSH target)
	code    string   // the setup code the installer printed
}

func newInst(t *testing.T, name, distro string, port int) *inst {
	t.Helper()
	i := &inst{t: t, name: name, distro: distro, work: filepath.Join(workRoot, name), port: port, project: "alice-rel-" + name}
	i.dir = filepath.Join(i.work, "opt")
	if _, err := os.Lstat(i.work); err == nil {
		t.Fatalf("the work directory %s exists (a former run?); remove it first", i.work)
	}
	if ids := strings.TrimSpace(docker(t, "ps", "-aq", "--filter", "label=com.docker.compose.project="+i.project).Out); ids != "" {
		t.Fatalf("Docker already has containers of the project %s (a former run?); remove them first", i.project)
	}
	must(t, i.rootSh(workRoot, "install -d -m 0755 -o 0 -g 0 \"$1\"", i.work), "create the work directory")
	t.Cleanup(i.teardown)
	return i
}

// teardown removes what the installation started and its work directory.
func (i *inst) teardown() {
	t := i.t
	for _, c := range i.extra {
		docker(t, "rm", "-f", "-v", c)
	}
	if r := docker(t, "compose", "-p", i.project, "down", "-v", "--remove-orphans"); r.Code != 0 {
		t.Logf("docker compose -p %s down: %s", i.project, r.Out)
	}
	if r := i.rootSh(workRoot, "rm -rf -- \"$1\"", i.work); r.Code != 0 {
		t.Errorf("remove %s: %s", i.work, r.Out)
	}
}

// containerArgs are the docker run arguments of a command in the installation's distribution container: no network,
// the Docker socket, and the work directory at the same path inside and outside (so compose's relative mounts resolve
// on the host).
func (i *inst) containerArgs(wd string, interactive bool) []string {
	args := []string{"run", "--rm", "--network", "none", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", i.work + ":" + i.work}
	if interactive {
		args = append(args, "-i")
	}
	if wd != "" {
		args = append(args, "-w", wd)
	}
	return append(args, installImage(i.distro))
}

// in runs a command in the distribution container with wd as working directory ("" for the image's).
func (i *inst) in(wd string, cmd ...string) result {
	i.t.Helper()
	r := docker(i.t, append(i.containerArgs(wd, false), cmd...)...)
	return r
}

// inStdin is in with stdin.
func (i *inst) inStdin(stdin []byte, wd string, cmd ...string) result {
	i.t.Helper()
	return runCmd(i.t, stdin, "docker", append(i.containerArgs(wd, true), cmd...)...)
}

// rootSh runs a bash script as root in the Ubuntu install image with only mount mounted (no network, no socket);
// args are $1...
func (i *inst) rootSh(mount, script string, args ...string) result {
	i.t.Helper()
	cmd := []string{"run", "--rm", "--network", "none", "-v", mount + ":" + mount, installImage("ubuntu22"), "bash", "-c", script, "bash"}
	return docker(i.t, append(cmd, args...)...)
}

// sh runs a bash script in the installation's container (with the socket); args are $1...
func (i *inst) sh(script string, args ...string) result {
	i.t.Helper()
	return i.in("", append([]string{"bash", "-c", script, "bash"}, args...)...)
}

// extract unpacks the package of version v into <work>/pkg-<v> and returns the package directory (…/alice).
func (i *inst) extract(v string) string {
	i.t.Helper()
	dst := filepath.Join(i.work, "pkg-"+v)
	r := docker(i.t, "run", "--rm", "--network", "none", "-v", i.work+":"+i.work, "-v", releaseDir+":"+releaseDir+":ro",
		installImage("ubuntu22"), "bash", "-c", "set -e; [ -d \"$1\" ] || { install -d -m 0755 \"$1\"; tar xzf \"$2\" -C \"$1\"; }", "bash", dst, tarball(v))
	must(i.t, r, "extract "+v)
	return filepath.Join(dst, "alice")
}

// download copies the tarball of v with its .sha256 and .sha256.sig into <work>/dl and returns the tarball's path, as an
// operator downloads an update next to the installation.
func (i *inst) download(v string) string {
	i.t.Helper()
	dl := filepath.Join(i.work, "dl")
	r := docker(i.t, "run", "--rm", "--network", "none", "-v", i.work+":"+i.work, "-v", releaseDir+":"+releaseDir+":ro",
		installImage("ubuntu22"), "bash", "-c", "set -e; install -d -m 0755 \"$1\"; for f in \"$2\" \"$2.sha256\" \"$2.sha256.sig\"; do install -m 0644 \"$f\" \"$1/\"; done",
		"bash", dl, tarball(v))
	must(i.t, r, "copy the package "+v)
	return filepath.Join(dl, filepath.Base(tarball(v)))
}

// install runs install.sh of version v's package in the installation's distribution container.
func (i *inst) install(v string, extra ...string) result {
	i.t.Helper()
	pkg := i.extract(v)
	return i.installFrom(pkg, extra...)
}

func (i *inst) installFrom(pkg string, extra ...string) result {
	i.t.Helper()
	args := append([]string{"./install.sh", "--dir", i.dir, "--port", strconv.Itoa(i.port), "--bind", "127.0.0.1", "--hostname", hostName,
		"--non-interactive", "--project", i.project, "--fingerprint", fingerprint}, extra...)
	r := i.in(pkg, args...)
	i.t.Logf("install.sh %s (exit %d):\n%s", strings.Join(extra, " "), r.Code, redactSetupCode(r.Out))
	return r
}

var setupCodeLine = regexp.MustCompile(`(?m)^ {7}([A-Za-z0-9-]{4,64})$`)

// setupCode is the one-time setup code in the installer's closing text.
func setupCode(t testing.TB, out string) string {
	t.Helper()
	m := setupCodeLine.FindStringSubmatch(out)
	require.NotNil(t, m, "no setup code in:\n%s", out)
	return m[1]
}

func redactSetupCode(out string) string {
	return setupCodeLine.ReplaceAllString(out, "       <setup code>")
}

// compose runs docker compose for the installation in its distribution container.
func (i *inst) compose(args ...string) result {
	i.t.Helper()
	return i.in("", append([]string{"docker", "compose", "-p", i.project, "-f", filepath.Join(i.dir, "docker-compose.yml"),
		"--env-file", filepath.Join(i.dir, ".env")}, args...)...)
}

// alicectl runs the installation's alicectl in its distribution container.
func (i *inst) alicectl(args ...string) result {
	i.t.Helper()
	r := i.in(i.dir, append([]string{filepath.Join(i.dir, "alicectl")}, args...)...)
	i.t.Logf("alicectl %s (exit %d):\n%s", strings.Join(args, " "), r.Code, r.Out)
	return r
}

// selfcheck asserts seven "[ OK ]" lines of alicectl selfcheck.
func (i *inst) selfcheck() {
	i.t.Helper()
	r := must(i.t, i.alicectl("selfcheck"), "alicectl selfcheck")
	require.Equal(i.t, 7, strings.Count(r.Out, ok), "seven [ OK ] lines:\n%s", r.Out)
	require.NotContains(i.t, r.Out, "[FAIL]")
}

// psql runs one query as the postgres superuser on database alice and returns the unaligned rows.
func (i *inst) psql(query string) string {
	i.t.Helper()
	r := must(i.t, i.compose("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "alice", "-v", "ON_ERROR_STOP=1", "-tAq", "-c", query), "psql")
	return strings.TrimSpace(string(r.Stdout))
}

// counts are the row counts of every table of the public schema (counts only, nothing of the rows' content).
func (i *inst) counts() map[string]int64 {
	i.t.Helper()
	out := i.psql(`SELECT table_name || '=' || (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text
FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`)
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		name, n, found := strings.Cut(line, "=")
		require.True(i.t, found, "count line %q", line)
		v, err := strconv.ParseInt(n, 10, 64)
		require.NoError(i.t, err)
		m[name] = v
	}
	require.NotEmpty(i.t, m)
	return m
}

// volatile are the tables whose row counts change while Alice runs untouched: the periodic tasks (C1: backup.schedule,
// tls.renew, audit.forward, jobs.heartbeat and the earlier phases' tasks) add rows to jobs on their own.
var volatile = map[string]bool{"jobs": true}

// stable removes the volatile tables from counts.
func stable(c map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range c {
		if !volatile[k] {
			out[k] = v
		}
	}
	return out
}

// snapshot is the state an attempt that changes nothing must leave: the row counts of the stable tables, the last
// audit entry and the setting keys.
type snapshot struct {
	counts   map[string]int64
	auditSeq string
	settings []string
}

func (i *inst) snapshot() snapshot {
	i.t.Helper()
	return snapshot{counts: stable(i.counts()), auditSeq: i.psql("SELECT max(seq) FROM audit_log"),
		settings: strings.Split(i.psql("SELECT string_agg(key, ',' ORDER BY key) FROM settings"), ",")}
}

// auditSince lists the actions of the audit entries after seq, in order.
func (i *inst) auditSince(seq string) []string {
	i.t.Helper()
	out := i.psql("SELECT coalesce(string_agg(action, ',' ORDER BY seq), '') FROM audit_log WHERE seq > " + seq)
	if out == "" {
		return nil
	}
	return strings.Split(out, ",")
}

// requireSame compares the installation with a snapshot taken before an attempt that must change no data. The attempt
// may add only the audit entries of its own bookkeeping (allowedAudit, for example backup.created of the automatic
// backup), setting keys of allowedSettings, and end the sessions when a restore ran (sessionsEnded).
func (i *inst) requireSame(before snapshot, allowedAudit, allowedSettings []string, sessionsEnded bool) {
	t := i.t
	t.Helper()
	after := i.snapshot()
	added := i.auditSince(before.auditSeq)
	for _, a := range added {
		assert.Contains(t, allowedAudit, a, "audit entries added by the attempt: %v", added)
	}
	for _, k := range after.settings {
		if !slices.Contains(before.settings, k) {
			assert.Contains(t, allowedSettings, k, "setting keys added by the attempt")
		}
	}
	for _, k := range before.settings {
		assert.Contains(t, after.settings, k, "setting keys removed by the attempt")
	}
	want := maps.Clone(before.counts)
	want["audit_log"] += int64(len(added))
	want["settings"] = int64(len(after.settings))
	if sessionsEnded {
		want["sessions"] = 0
	}
	assert.Equal(t, want, after.counts, "row counts")
}

// keysHash is the SHA-256 of every file in keys/ (name and hash lines, sorted).
func (i *inst) keysHash() string {
	i.t.Helper()
	r := must(i.t, i.sh("cd \"$1\" && find . -type f -print0 | sort -z | xargs -0 sha256sum", filepath.Join(i.dir, "keys")), "hash keys/")
	return strings.TrimSpace(r.Out)
}

// readFile returns a file of the installation (read as root).
func (i *inst) readFile(path string) []byte {
	i.t.Helper()
	r := i.in("", "cat", path)
	require.Equal(i.t, 0, r.Code, "cat %s: %s", path, r.Out)
	return r.Stdout
}

// writeFile writes data to path as root with the owner and mode given (as an operator copies a file in).
func (i *inst) writeFile(path string, data []byte, owner, mode string) {
	i.t.Helper()
	r := i.inStdin(data, "", "bash", "-c", "set -e; cat >\"$1\"; chown \"$2\" \"$1\"; chmod \"$3\" \"$1\"", "bash", path, owner, mode)
	must(i.t, r, "write "+path)
}

// passphraseFile writes a passphrase file (0600 root) into the work directory and returns its path.
func (i *inst) passphraseFile(name, value string) string {
	i.t.Helper()
	p := filepath.Join(i.work, name)
	i.writeFile(p, []byte(value+"\n"), "0:0", "0600")
	return p
}

// container is the ID of the running container of a compose service ("" when none).
func (i *inst) container(service string) string {
	i.t.Helper()
	r := docker(i.t, "ps", "-q", "--filter", "label=com.docker.compose.project="+i.project, "--filter", "label=com.docker.compose.service="+service)
	return strings.TrimSpace(r.Out)
}

// inspect decodes docker inspect of a container.
func inspect(t testing.TB, id string) containerInfo {
	t.Helper()
	r := must(t, docker(t, "inspect", id), "docker inspect")
	var v []containerInfo
	require.NoError(t, json.Unmarshal(r.Stdout, &v))
	require.Len(t, v, 1)
	return v[0]
}

type containerInfo struct {
	Image  string
	Config struct {
		User   string
		Env    []string
		Image  string
		Labels map[string]string
	}
	State struct {
		Running bool
		Health  *struct{ Status string }
	}
	HostConfig struct {
		ReadonlyRootfs bool
		CapAdd         []string
		CapDrop        []string
		SecurityOpt    []string
		Privileged     bool
		PortBindings   map[string][]struct{ HostIP, HostPort string }
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
	NetworkSettings struct {
		Ports map[string][]struct{ HostIP, HostPort string }
	}
}

// runningVersion is the image tag of the running alice container.
func (i *inst) runningVersion() string {
	i.t.Helper()
	id := i.container("alice")
	require.NotEmpty(i.t, id, "the alice container runs")
	info := inspect(i.t, id)
	require.True(i.t, info.State.Running)
	require.NotNil(i.t, info.State.Health)
	require.Equal(i.t, "healthy", info.State.Health.Status)
	return strings.TrimPrefix(info.Config.Image, "alice:")
}

// installedVersion is the VERSION file of the installation.
func (i *inst) installedVersion() string {
	return strings.TrimSpace(string(i.readFile(filepath.Join(i.dir, "VERSION"))))
}

// ---- the API ----

// client is a browser-like HTTPS client of an installation: cookies, the CSRF token of the last answer that carried
// one, and trust in the installation's own certificate (keys/tls.crt) plus extra roots.
type client struct {
	t    testing.TB
	base string
	hc   *http.Client
	csrf string
}

// client returns a new client that trusts keys/tls.crt of the installation and the extra root certificates.
func (i *inst) client(extraRoots ...*x509.Certificate) *client {
	i.t.Helper()
	pool := x509.NewCertPool()
	require.True(i.t, pool.AppendCertsFromPEM(i.readFile(filepath.Join(i.dir, "keys", "tls.crt"))), "keys/tls.crt holds a certificate")
	for _, c := range extraRoots {
		pool.AddCert(c)
	}
	jar, err := cookiejar.New(nil)
	require.NoError(i.t, err)
	return &client{t: i.t, base: "https://127.0.0.1:" + strconv.Itoa(i.port), hc: &http.Client{
		Jar:     jar,
		Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: hostName, MinVersion: tls.VersionTLS12,
		}},
	}}
}

// call sends one request; a 429 is waited out (Retry-After) and sent again, as a person would. A body that holds a
// TOTP code is passed as func() any so the code is made after the wait.
func (c *client) call(method, path string, body any, header ...string) (int, []byte, http.Header) {
	c.t.Helper()
	for attempt := 0; ; attempt++ {
		// A body given as func() any is built again for every attempt: a TOTP code must be fresh after a wait.
		b := body
		if f, isFunc := body.(func() any); isFunc {
			b = f()
		}
		var data []byte
		if b != nil {
			var err error
			data, err = json.Marshal(b)
			require.NoError(c.t, err)
		}
		req, err := http.NewRequest(method, c.base+path, bytes.NewReader(data))
		require.NoError(c.t, err)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-Alice-Activity", "1")
		if b != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.csrf != "" && method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		for k := 0; k+1 < len(header); k += 2 {
			req.Header.Set(header[k], header[k+1])
		}
		res, err := c.hc.Do(req)
		require.NoError(c.t, err, "%s %s", method, path)
		out, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		require.NoError(c.t, err)
		if res.StatusCode == http.StatusTooManyRequests && attempt < 20 {
			wait, _ := strconv.Atoi(res.Header.Get("Retry-After"))
			if wait < 1 {
				wait = 5
			}
			time.Sleep(time.Duration(wait)*time.Second + 500*time.Millisecond)
			continue
		}
		var probe struct {
			CSRFToken string `json:"csrf_token"`
		}
		if json.Unmarshal(out, &probe) == nil && probe.CSRFToken != "" {
			c.csrf = probe.CSRFToken
		}
		return res.StatusCode, out, res.Header
	}
}

// expect sends a request and requires the status; it returns the decoded body (nil for an empty body).
func (c *client) expect(want int, method, path string, body any, header ...string) map[string]any {
	c.t.Helper()
	code, out, _ := c.call(method, path, body, header...)
	require.Equal(c.t, want, code, "%s %s: %s", method, path, out)
	if len(bytes.TrimSpace(out)) == 0 {
		return nil
	}
	var v map[string]any
	require.NoError(c.t, json.Unmarshal(out, &v), "%s %s: %s", method, path, out)
	return v
}

// account is a user as the harness knows it; last is the TOTP step last used (codes are never replayed, SEC-006).
type account struct {
	username, password, role, secret string
	last                             int64
}

// code is a TOTP code for a step after the last one used: the server accepts one step either side of now and only
// steps after the last accepted one, so the harness waits when it has used up the current window.
func (a *account) code(t testing.TB) string {
	t.Helper()
	for {
		now := time.Now().Unix() / 30
		step := now - 1
		if a.last+1 > step {
			step = a.last + 1
		}
		if step <= now+1 {
			code, err := totp.GenerateCodeCustom(a.secret, time.Unix(step*30, 0), totp.ValidateOpts{
				Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
			})
			require.NoError(t, err)
			a.last = step
			return code
		}
		time.Sleep(time.Until(time.Unix((step-1)*30, 0)) + 200*time.Millisecond)
	}
}

func str(t testing.TB, v map[string]any, keys ...string) string {
	t.Helper()
	var cur any = v
	for _, k := range keys {
		m, isMap := cur.(map[string]any)
		require.True(t, isMap, "%v: %s is not an object", v, k)
		cur = m[k]
	}
	s, isStr := cur.(string)
	require.True(t, isStr, "%v: %s is not a string", v, strings.Join(keys, "."))
	return s
}

// wizard runs the setup wizard on c through the API with the installer's setup code (i.code): the administrator with TOTP, the recovery
// passphrase, the HTTPS and mail steps (https and mail run as given; nil keeps the temporary certificate or skips mail),
// the evaluation license and completion. It returns the signed-in administrator's client and account.
func (i *inst) wizard(c *client, https func(c *client, admin *account), mail func(c *client, admin *account)) (*client, *account) {
	t := i.t
	t.Helper()
	admin := &account{username: "ada", password: "release harness ada staple 42", role: "admin"}
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/session", map[string]string{"code": i.code})
	c.expect(http.StatusNoContent, http.MethodPut, "/api/v1/setup/language", map[string]string{"language": "en"})
	enr := c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/admin/enrollment", map[string]string{
		"username": admin.username, "display_name": "Ada Admin", "email": "", "password": admin.password,
	})
	admin.secret = str(t, enr, "secret")
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/admin", func() any { return map[string]string{"code": admin.code(t)} })
	c.expect(http.StatusNoContent, http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{
		"passphrase": passphrase, "passphrase_confirm": passphrase,
	})
	stepUp(c, admin)
	if https != nil {
		https(c, admin)
	} else {
		c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/https/keep-temporary", nil)
	}
	if mail != nil {
		mail(c, admin)
	} else {
		c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/mail/skip", nil)
	}
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/evaluation", nil)
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/setup/complete", nil)
	return c, admin
}

// stepUp confirms the session with a fresh code (admin changes need it for 5 minutes).
func stepUp(c *client, a *account) {
	c.t.Helper()
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/stepup", func() any { return map[string]string{"code": a.code(c.t)} })
}

// createUser creates a user as the stepped-up administrator.
func createUser(c *client, a *account) {
	c.t.Helper()
	c.expect(http.StatusCreated, http.MethodPost, "/api/v1/users", map[string]string{
		"username": a.username, "display_name": "User " + a.username, "email": "", "role": a.role, "password": a.password,
	})
}

// signIn signs an account in on a new client: the first sign-in enrols TOTP, later ones use it.
func (i *inst) signIn(a *account, roots ...*x509.Certificate) *client {
	i.t.Helper()
	c := i.client(roots...)
	v := c.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": a.username, "password": a.password})
	switch str(i.t, v, "status") {
	case "mfa_enrollment_required":
		require.Empty(i.t, a.secret, "%s enrolled before", a.username)
		enr := c.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
		a.secret = str(i.t, enr, "secret")
	case "mfa_required":
		require.NotEmpty(i.t, a.secret, "%s has no TOTP secret in the harness", a.username)
	default:
		i.t.Fatalf("sign-in of %s: %v", a.username, v)
	}
	c.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/mfa/verify", func() any { return map[string]string{"code": a.code(i.t)} })
	return c
}

// ---- docker events (M-17) ----

// pulls lists the image pulls of the release images and the three base images between since and until.
func pulls(t testing.TB, since, until time.Time) string {
	t.Helper()
	r := must(t, docker(t, "events", "--since", strconv.FormatInt(since.Unix(), 10), "--until", strconv.FormatInt(until.Unix()+1, 10),
		"--filter", "type=image", "--filter", "event=pull",
		"--filter", "image=alice", "--filter", "image=alice-postgres", "--filter", "image=ubuntu", "--filter", "image=debian",
		"--filter", "image=rockylinux/rockylinux"), "docker events")
	return strings.TrimSpace(r.Out)
}

// ---- small helpers ----

func itoa(n int) string { return strconv.Itoa(n) }

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}
