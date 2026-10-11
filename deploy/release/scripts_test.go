package release

// Tests of the host scripts install.sh, alice-update.sh and alicectl (Task 11, C4): every run uses
// the stub commands of testdata/stubs (docker, chown, ss, timedatectl, uname, id, nproc, df, stat)
// in temporary directories; nothing here touches the host's Docker or runs as root. The release
// key is an Ed25519 key generated per test; the real openssl verifies the signatures exactly as on
// a customer's server (C5).

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	shSetupCode  = "K7QX2M-9TPD4R-WB5H8N-3VZC6A"
	shCanary     = "canary-passphrase-7f3a9c1e-never-logged"
	shAliceID    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	shPostgresID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	shTestKeyID  = "rk-test-01"
	shDamaged    = "The installation package is damaged or incomplete. Download it again and compare the checksum."
	shBadSig     = "The package signature is not valid. Do not install this package; download it again and check it with your vendor."
	shBadUpdSig  = "The update package signature is not valid. Do not install this package; download it again and check it with your vendor."
	shTestWarn   = "[WARN] This package is signed with a TEST key. Never install it for production."
)

var shScripts = []string{"install.sh", "alice-update.sh", "alicectl", "lib/alice-lib.sh"}

// shEnv is one test's world: the stubs, a package directory, an installation directory below a
// directory the stat stub reports as root-owned, and the stub settings.
type shEnv struct {
	t       *testing.T
	root    string
	bin     string
	srv     string
	inst    string
	log     string
	vars    map[string]string
	env     map[string]string
	path    string
	key     ed25519.PrivateKey
	keyPEM  []byte
	keyHash string
}

func shNew(t *testing.T) *shEnv {
	t.Helper()
	root := t.TempDir()
	e := &shEnv{t: t, root: root, bin: filepath.Join(root, "bin"), srv: filepath.Join(root, "srv"),
		log: filepath.Join(root, "stub.log"), vars: map[string]string{}, env: map[string]string{}}
	e.inst = filepath.Join(e.srv, "alice")
	require.NoError(t, os.MkdirAll(e.srv, 0o755))
	require.NoError(t, os.MkdirAll(e.bin, 0o755))
	stubs, err := os.ReadDir("testdata/stubs")
	require.NoError(t, err)
	for _, s := range stubs {
		b, err := os.ReadFile(filepath.Join("testdata/stubs", s.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(e.bin, s.Name()), b, 0o755))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, "proc"), 0o755))
	e.setMemKB(8 * 1024 * 1024)
	e.path = e.bin + ":" + os.Getenv("PATH")
	e.vars = map[string]string{
		"STUB_LOG": e.log, "STUB_REAL_PATH": os.Getenv("PATH"), "STUB_UID": "0", "STUB_ARCH": "x86_64",
		"STUB_DOCKER": "ok", "STUB_DOCKER_VERSION": "27.3.1", "STUB_NTP": "yes", "STUB_DISK_GB": "100",
		"STUB_CPUS": "4", "STUB_SOCK_MODE": "660", "STUB_STAT_TRUST": e.inst, "STUB_TZ": "Europe/Istanbul",
		"STUB_IMAGE_IDS": "alice:1.0.0=" + shAliceID + " alice-postgres:1.0.0=" + shPostgresID,
	}
	e.env["ALICE_PROC_DIR"] = filepath.Join(root, "proc")
	e.newKey()
	return e
}

func (e *shEnv) setMemKB(kb int) {
	e.t.Helper()
	body := fmt.Sprintf("MemTotal:       %d kB\nMemFree:        1000 kB\n", kb)
	require.NoError(e.t, os.WriteFile(filepath.Join(e.root, "proc", "meminfo"), []byte(body), 0o644))
}

func (e *shEnv) newKey() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(e.t, err)
	e.key = priv
	e.keyPEM, e.keyHash = shPubPEM(e.t, pub, shTestKeyID)
}

func shPubPEM(t *testing.T, pub ed25519.PublicKey, id string) ([]byte, string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	var b bytes.Buffer
	fmt.Fprintf(&b, "key-id: %s\n", id)
	require.NoError(t, pem.Encode(&b, &pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return b.Bytes(), hex.EncodeToString(sum[:])
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (e *shEnv) writeStubEnv() {
	e.t.Helper()
	keys := make([]string, 0, len(e.vars))
	for k := range e.vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, shQuote(e.vars[k]))
	}
	require.NoError(e.t, os.WriteFile(filepath.Join(e.bin, "stub.env"), []byte(b.String()), 0o644))
}

type shResult struct {
	out  string
	code int
}

func (e *shEnv) cmd(stdin, script string, args ...string) *exec.Cmd {
	e.writeStubEnv()
	c := exec.Command(script, args...)
	c.Dir = e.root
	env := []string{"PATH=" + e.path, "HOME=" + e.root, "LC_ALL=C"}
	for k, v := range e.env {
		env = append(env, k+"="+v)
	}
	c.Env = env
	c.Stdin = strings.NewReader(stdin)
	// A new session without a controlling terminal: /dev/tty cannot be opened unless a test
	// gives the script a pseudo-terminal (runTTY), even when go test runs in a terminal.
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return c
}

func (e *shEnv) run(stdin, script string, args ...string) shResult {
	e.t.Helper()
	c := e.cmd(stdin, script, args...)
	out, err := c.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		require.ErrorAs(e.t, err, &ee, "run %s: %v\n%s", script, err, out)
		code = ee.ExitCode()
	}
	return shResult{out: string(out), code: code}
}

// ---- packages ----

type shPkgOpts struct {
	version    string
	minFrom    string
	buildTime  string
	testSigned bool
	extraKeys  map[string][]byte // more release-keys/<name> files
	skipKey    bool              // ship no rk-test-01.pem
}

func shCopyScripts(t *testing.T, dst string) {
	t.Helper()
	for _, s := range shScripts {
		b, err := os.ReadFile(s)
		require.NoError(t, err)
		mode := fs.FileMode(0o755)
		if strings.HasPrefix(s, "lib/") {
			mode = 0o644
		}
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dst, s)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dst, s), b, mode))
	}
}

func shWrite(t *testing.T, path, body string, mode fs.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), mode))
}

func shRelease(o shPkgOpts) string {
	r := fmt.Sprintf("VERSION=%s\nMIN_UPGRADE_FROM=%s\nSCHEMA_VERSION=42\nALICE_IMAGE=alice:%s\nALICE_IMAGE_ID=%s\n"+
		"POSTGRES_IMAGE=alice-postgres:%s\nPOSTGRES_IMAGE_ID=%s\nBUILD_COMMIT=%s\nBUILD_TIME=%s\nRELEASE_KEY_ID=%s\n",
		o.version, o.minFrom, o.version, shAliceID, o.version, shPostgresID, strings.Repeat("a", 40), o.buildTime, shTestKeyID)
	if o.testSigned {
		r += "TEST_SIGNED=1\n"
	}
	return r
}

// buildPkg writes an unsigned package into dir (C5 layout, the parts the scripts read).
func (e *shEnv) buildPkg(dir string, o shPkgOpts) {
	t := e.t
	t.Helper()
	if o.version == "" {
		o.version = "1.0.0"
	}
	if o.minFrom == "" {
		o.minFrom = "1.0.0-rc.1"
	}
	if o.buildTime == "" {
		o.buildTime = "2026-01-02T03:04:05Z"
	}
	shCopyScripts(t, dir)
	shWrite(t, filepath.Join(dir, "lib/initdb/10-alice-roles.sh"), "#!/bin/sh\necho roles\n", 0o644)
	shWrite(t, filepath.Join(dir, "docker-compose.yml"), "services: {} # version "+o.version+"\n", 0o644)
	shWrite(t, filepath.Join(dir, ".env.template"), "COMPOSE_PROJECT_NAME=alice\n", 0o644)
	shWrite(t, filepath.Join(dir, "VERSION"), o.version+"\n", 0o644)
	shWrite(t, filepath.Join(dir, "RELEASE"), shRelease(o), 0o644)
	if !o.skipKey {
		shWrite(t, filepath.Join(dir, "release-keys", shTestKeyID+".pem"), string(e.keyPEM), 0o644)
	}
	for n, b := range o.extraKeys {
		shWrite(t, filepath.Join(dir, "release-keys", n), string(b), 0o644)
	}
	a := "alice image " + o.version
	p := "postgres image " + o.version
	shWrite(t, filepath.Join(dir, "images", "alice-"+o.version+".tar"), a, 0o644)
	shWrite(t, filepath.Join(dir, "images", "postgres-"+o.version+".tar"), p, 0o644)
	shWrite(t, filepath.Join(dir, "images", "images.sha256"), fmt.Sprintf("%s  alice-%s.tar\n%s  postgres-%s.tar\n",
		shHex([]byte(a)), o.version, shHex([]byte(p)), o.version), 0o644)
	shWrite(t, filepath.Join(dir, "docs", "install-guide.md"), "# Install\n", 0o644)
}

func shHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// sign writes SHA256SUMS over every regular file and its signature by key.
func shSign(t *testing.T, dir string, key ed25519.PrivateKey) {
	t.Helper()
	var lines []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "SHA256SUMS" || rel == "SHA256SUMS.sig" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines = append(lines, shHex(b)+"  "+rel)
		return nil
	}))
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	sums := strings.Join(lines, "\n") + "\n"
	shWrite(t, filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
	shWrite(t, filepath.Join(dir, "SHA256SUMS.sig"), string(ed25519.Sign(key, []byte(sums))), 0o644)
}

func (e *shEnv) pkg(o shPkgOpts) string {
	dir := filepath.Join(e.root, "pkg-"+shRandName(), "alice")
	e.buildPkg(dir, o)
	shSign(e.t, dir, e.key)
	return dir
}

func shRandName() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// tarball packs dir (as alice/) into <out>/alice-<v>.tar.gz with its .sha256 and .sha256.sig.
func shTarball(t *testing.T, dir, out, version string, key ed25519.PrivateKey) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(out, 0o755))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		name := filepath.ToSlash(filepath.Join("alice", rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.Uid, hdr.Gid = 1000, 1000
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !d.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			_, err = tw.Write(b)
			return err
		}
		return nil
	}))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	name := "alice-" + version + ".tar.gz"
	path := filepath.Join(out, name)
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
	sum := shHex(buf.Bytes()) + "  " + name + "\n"
	require.NoError(t, os.WriteFile(path+".sha256", []byte(sum), 0o644))
	require.NoError(t, os.WriteFile(path+".sha256.sig", ed25519.Sign(key, []byte(sum)), 0o644))
	return path
}

// ---- stub log ----

type shCall struct {
	name  string
	args  []string
	env   []string
	stdin *string
}

func (c shCall) line() string { return c.name + " " + strings.Join(c.args, " ") }

func shUnesc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			if s[i] == 'n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (e *shEnv) calls() []shCall {
	e.t.Helper()
	b, err := os.ReadFile(e.log)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	require.NoError(e.t, err)
	var out []shCall
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		f := strings.Split(l, "\x1f")
		for i := range f {
			f[i] = shUnesc(f[i])
		}
		switch f[0] {
		case "C":
			out = append(out, shCall{name: f[1], args: f[2:]})
		case "E":
			out[len(out)-1].env = f[1:]
		case "I":
			s := strings.Join(f[1:], "\x1f")
			out[len(out)-1].stdin = &s
		}
	}
	return out
}

func (e *shEnv) dockerCalls() []shCall {
	var out []shCall
	for _, c := range e.calls() {
		if c.name == "docker" {
			out = append(out, c)
		}
	}
	return out
}

// shHas reports whether args contain the words in this order; a word "~text" matches an argument
// that contains text.
func shHas(args []string, words ...string) bool {
	i := 0
	for _, a := range args {
		if i < len(words) && (a == words[i] || strings.HasPrefix(words[i], "~") && strings.Contains(a, words[i][1:])) {
			i++
		}
	}
	return i == len(words)
}

// shIndex returns the index of the first call at or after from whose arguments contain the words.
func shIndex(calls []shCall, from int, words ...string) int {
	for i := from; i < len(calls); i++ {
		if shHas(calls[i].args, words...) {
			return i
		}
	}
	return -1
}

// shOrder asserts that each step (words) occurs after the previous one; it returns the indexes.
func shOrder(t *testing.T, calls []shCall, steps ...[]string) []int {
	t.Helper()
	var idx []int
	from := 0
	for _, s := range steps {
		i := shIndex(calls, from, s...)
		if !assert.GreaterOrEqual(t, i, 0, "step %q not found after call %d in:\n%s", s, from, shDump(calls)) {
			return idx
		}
		idx = append(idx, i)
		from = i + 1
	}
	return idx
}

func shDump(calls []shCall) string {
	var b strings.Builder
	for i, c := range calls {
		fmt.Fprintf(&b, "%3d %s\n", i, c.line())
	}
	return b.String()
}

// ---- install helpers ----

func (e *shEnv) installArgs(extra ...string) []string {
	a := []string{"--dir", e.inst, "--port", "19443", "--bind", "127.0.0.1", "--hostname", "alice.test",
		"--non-interactive", "--fingerprint", e.keyHash, "--project", "alice-unit"}
	return append(a, extra...)
}

func (e *shEnv) install(pkg string, extra ...string) shResult {
	return e.run("", filepath.Join(pkg, "install.sh"), e.installArgs(extra...)...)
}

func shNoDir(t *testing.T, p string) {
	t.Helper()
	_, err := os.Lstat(p)
	assert.ErrorIs(t, err, fs.ErrNotExist, "%s must not exist", p)
}

func shMode(t *testing.T, p string, want fs.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if assert.NoError(t, err) {
		assert.Equal(t, want, fi.Mode().Perm(), "mode of %s", p)
	}
}

// ---- preflight ----

type shCheck struct {
	label string
	set   func(e *shEnv, o *shPkgOpts) // changes the stubs or the package so this check fails
	msg   string                       // the exact [FAIL] text; {inst}, {parent} and {year} are replaced
}

// The checks of install.sh in their order (C4 table).
var shChecks = []shCheck{
	{"Running as root", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_UID"] = "1000" },
		"This installer must be run with administrator rights. Run it again as: sudo ./install.sh"},
	{"Linux x86_64", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_ARCH"] = "aarch64" },
		"Alice needs a 64-bit Intel/AMD Linux server. This machine is aarch64."},
	{"Docker installed and running", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_DOCKER"] = "missing" },
		"Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again."},
	{"Docker 24 or newer with the compose plugin", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_DOCKER"] = "old" },
		"Your Docker is too old (found 20.10.24). Alice needs version 24 or newer."},
	{"Docker socket restricted", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_SOCK_MODE"] = "666" },
		"The Docker socket /var/run/docker.sock can be used by every user on this server. Restrict it to the docker group (chmod 660), then run this installer again."},
	{"OpenSSL 3", func(e *shEnv, _ *shPkgOpts) { e.path = e.bin + ":" + e.noOpenSSLDir() },
		"OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again."},
	{"Free disk ≥ 20 GB", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_DISK_GB"] = "6" },
		"Not enough free disk space in {parent}: 6 GB free, 20 GB needed."},
	{"Memory ≥ 4 GB, CPU ≥ 2", func(e *shEnv, _ *shPkgOpts) { e.setMemKB(2 * 1024 * 1024) },
		"This server has 2 GB of memory. Alice needs at least 4 GB."},
	{"Port free", func(e *shEnv, _ *shPkgOpts) { e.vars["STUB_PORT_BUSY"] = "nginx" },
		"Another program is already using port 19443 (nginx, pid 812). Stop it or run the installer with --port 8443."},
	{"Package signature", nil, shBadSig},
	{"Package complete", nil, shDamaged},
	{"Package lists exactly its files", nil, shDamaged},
	{"Clock sane", func(_ *shEnv, o *shPkgOpts) { o.buildTime = "2099-01-01T00:00:00Z" },
		"The server clock looks wrong (it says {year}). Fix the date/time first; licenses depend on it."},
	{"No installation yet", func(e *shEnv, _ *shPkgOpts) {
		shWrite(e.t, filepath.Join(e.inst, "docker-compose.yml"), "x", 0o644)
	}, "Alice is already installed in {inst}. To upgrade use ./alice-update.sh."},
}

// noOpenSSLDir builds a directory of links to every command of PATH except openssl.
func (e *shEnv) noOpenSSLDir() string {
	dir := filepath.Join(e.root, "nossl")
	require.NoError(e.t, os.MkdirAll(dir, 0o755))
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, en := range ents {
			if en.Name() == "openssl" {
				continue
			}
			_ = os.Symlink(filepath.Join(d, en.Name()), filepath.Join(dir, en.Name()))
		}
	}
	return dir
}

func TestPreflightMessages(t *testing.T) {
	t.Parallel()
	for i, c := range shChecks {
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()
			e := shNew(t)
			o := shPkgOpts{}
			if c.set != nil {
				c.set(e, &o)
			}
			dir := filepath.Join(e.root, "pkg", "alice")
			e.buildPkg(dir, o)
			shSign(t, dir, e.key)
			switch c.label {
			case "Package signature":
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				shSign(t, dir, priv)
			case "Package complete":
				shWrite(t, filepath.Join(dir, "docker-compose.yml"), "changed\n", 0o644)
			case "Package lists exactly its files":
				shWrite(t, filepath.Join(dir, "docs", "extra.md"), "unlisted\n", 0o644)
			}
			r := e.install(dir)
			want := "[FAIL] " + strings.NewReplacer("{inst}", e.inst, "{parent}", e.srv,
				"{year}", fmt.Sprint(time.Now().UTC().Year())).Replace(c.msg)
			assert.Contains(t, r.out, want+"\n")
			for _, earlier := range shChecks[:i] {
				assert.Contains(t, r.out, "[ OK ] "+earlier.label+"\n", "earlier check %q", earlier.label)
			}
			assert.Equal(t, 1, r.code, r.out)
			if c.label != "No installation yet" {
				shNoDir(t, e.inst)
			}
			assert.Equal(t, -1, shIndex(e.dockerCalls(), 0, "load"), "nothing is loaded")
		})
	}
	t.Run("docker down", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_DOCKER"] = "down"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "[FAIL] "+shChecks[2].msg+"\n")
		assert.Equal(t, 1, r.code)
	})
	t.Run("compose plugin missing", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_DOCKER"] = "nocompose"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "[FAIL] The Docker compose plugin is missing. Install docker-compose-plugin (see docs/install-guide.md), then run this installer again.\n")
		assert.Equal(t, 1, r.code)
	})
	t.Run("too few CPUs", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_CPUS"] = "1"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "[FAIL] This server has 1 CPU. Alice needs at least 2.\n")
		assert.Equal(t, 1, r.code)
		shNoDir(t, e.inst)
	})
	t.Run("memory warning continues", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.setMemKB(3*1024*1024 + 512*1024)
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "[WARN] This server has 3 GB of memory. Alice needs at least 4 GB.\n")
		assert.NotContains(t, r.out, "[FAIL]")
		assert.Equal(t, 0, r.code, r.out)
	})
	t.Run("clock not synchronised warns", func(t *testing.T) {
		t.Parallel()
		for _, ntp := range []string{"no", "missing"} {
			e := shNew(t)
			e.vars["STUB_NTP"] = ntp
			r := e.install(e.pkg(shPkgOpts{}))
			assert.Contains(t, r.out, "[WARN] Alice could not confirm that the clock is synchronised. Make sure NTP is running; licenses depend on the time.\n")
			assert.Equal(t, 0, r.code, r.out)
		}
	})
}

func TestPreflightListsEveryFailureBeforeStopping(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	e.vars["STUB_UID"] = "1000"
	e.vars["STUB_ARCH"] = "armv7l"
	e.vars["STUB_DISK_GB"] = "3"
	r := e.install(e.pkg(shPkgOpts{}))
	assert.Equal(t, 3, strings.Count(r.out, "[FAIL] "), r.out)
	assert.Contains(t, r.out, "[FAIL] "+shChecks[0].msg)
	assert.Contains(t, r.out, "This machine is armv7l.")
	assert.Contains(t, r.out, "3 GB free, 20 GB needed.")
	// The last check still ran after the failures.
	assert.Contains(t, r.out, "[ OK ] No installation yet")
	assert.Equal(t, 1, r.code)
	shNoDir(t, e.inst)
}

// ---- install ----

func TestInstallHappyPath(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	pkg := e.pkg(shPkgOpts{})
	r := e.install(pkg)
	require.Equal(t, 0, r.code, r.out)
	in := e.inst

	shMode(t, in, 0o750)
	for _, f := range []string{"VERSION", "RELEASE", "docker-compose.yml", "lib/alice-lib.sh", "lib/initdb/10-alice-roles.sh",
		"release-keys/" + shTestKeyID + ".pem", "docs/install-guide.md"} {
		shMode(t, filepath.Join(in, f), 0o644)
	}
	for _, f := range []string{"install.sh", "alice-update.sh", "alicectl"} {
		shMode(t, filepath.Join(in, f), 0o755)
	}
	shMode(t, filepath.Join(in, ".env"), 0o640)
	shMode(t, filepath.Join(in, "install.log"), 0o600)
	for _, d := range []string{"secrets", "keys", "state", "backups", "data/postgres"} {
		shMode(t, filepath.Join(in, d), 0o700)
	}
	shMode(t, filepath.Join(in, "secrets/db_postgres_password"), 0o400)
	shMode(t, filepath.Join(in, "secrets/db_owner_password"), 0o440)
	shMode(t, filepath.Join(in, "secrets/db_app_password"), 0o440)
	shMode(t, filepath.Join(in, "keys/master.key"), 0o400)

	owners := map[string]string{}
	for _, c := range e.calls() {
		if c.name == "chown" && len(c.args) >= 2 {
			for _, p := range c.args[1:] {
				owners[p] = c.args[0]
			}
		}
	}
	for p, want := range map[string]string{"keys": "10001:10001", "state": "10001:10001", "backups": "10001:10001",
		"keys/master.key": "10001:10001", "data/postgres": "70:70", "secrets/db_postgres_password": "70:70",
		"secrets/db_owner_password": "70:10001", "secrets/db_app_password": "70:10001"} {
		assert.Equal(t, want, owners[filepath.Join(in, p)], "owner of %s", p)
	}

	pw := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	seen := map[string]bool{}
	for _, n := range []string{"db_postgres_password", "db_owner_password", "db_app_password"} {
		b, err := os.ReadFile(filepath.Join(in, "secrets", n))
		require.NoError(t, err)
		assert.Regexp(t, pw, string(b), n)
		assert.False(t, seen[string(b)], "passwords differ")
		seen[string(b)] = true
	}
	mk, err := os.ReadFile(filepath.Join(in, "keys/master.key"))
	require.NoError(t, err)
	assert.Regexp(t, `^[A-Za-z0-9+/]{43}=\n$`, string(mk))

	env, err := os.ReadFile(filepath.Join(in, ".env"))
	require.NoError(t, err)
	for _, l := range []string{"COMPOSE_PROJECT_NAME=alice-unit", "ALICE_IMAGE=alice:1.0.0", "POSTGRES_IMAGE=alice-postgres:1.0.0",
		"ALICE_BIND=127.0.0.1", "ALICE_PORT=19443", "ALICE_TLS_HOSTS=alice.test", "ALICE_TZ=Europe/Istanbul"} {
		assert.Contains(t, string(env), l+"\n")
	}
	for s := range seen {
		assert.NotContains(t, string(env), s)
	}
	assert.NotContains(t, string(env), strings.TrimSpace(string(mk)))

	calls := e.dockerCalls()
	shOrder(t, calls, []string{"load", "-i", "~/alice/images/alice-1.0.0.tar"},
		[]string{"load", "-i", "~/alice/images/postgres-1.0.0.tar"},
		[]string{"image", "inspect", "alice:1.0.0"}, []string{"image", "inspect", "alice-postgres:1.0.0"},
		[]string{"compose", "up", "-d", "--wait", "--wait-timeout", "180", "postgres"},
		[]string{"compose", "run", "--rm", "migrate"},
		[]string{"compose", "up", "-d", "--wait", "--wait-timeout", "180", "alice"},
		[]string{"compose", "exec", "-T", "alice", "/usr/local/bin/alice", "setup-token", "--reset"})
	for _, c := range calls {
		assert.NotContains(t, c.args, "pull", c.line())
		if len(c.args) > 0 && c.args[0] == "compose" && !shHas(c.args, "version") {
			assert.True(t, shHas(c.args, "--project-name", "alice-unit", "-f", filepath.Join(in, "docker-compose.yml")), c.line())
			if shHas(c.args, "up") || shHas(c.args, "run") {
				assert.True(t, shHas(c.args, "--pull", "never"), c.line())
			}
		}
	}

	assert.Contains(t, r.out, shSetupCode)
	assert.Contains(t, r.out, "Alice 1.0.0 is installed and running.")
	assert.Contains(t, r.out, "https://alice.test:19443/setup")
	assert.Contains(t, r.out, "sudo "+in+"/alicectl setup-token --reset")
	logb, err := os.ReadFile(filepath.Join(in, "install.log"))
	require.NoError(t, err)
	assert.NotContains(t, string(logb), shSetupCode)
	assert.Contains(t, string(logb), "Setup code printed to the terminal (not logged).")
	assert.Contains(t, string(logb), "[ OK ] Running as root")
	assert.Contains(t, r.out, "Package signed by release key "+shTestKeyID+" (SHA-256 fingerprint "+e.keyHash+"). Compare this fingerprint with the one your vendor published.")
	for s := range seen {
		assert.NotContains(t, string(logb), s)
		assert.NotContains(t, r.out, s)
	}
}

func TestInstallStartFailureShowsTheLogs(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	e.vars["STUB_COMPOSE_FAIL"] = "up alice"
	r := e.install(e.pkg(shPkgOpts{}))
	assert.Equal(t, 1, r.code, r.out)
	assert.Contains(t, r.out, "---- last 30 log lines of postgres ----\nstub log line\n")
	assert.Contains(t, r.out, "---- last 30 log lines of alice ----\nstub log line\n")
	assert.Contains(t, r.out, "Alice did not start. Send "+e.inst+"/install.log to support.\n")
	calls := e.dockerCalls()
	shOrder(t, calls, []string{"logs", "--tail", "30", "postgres"}, []string{"logs", "--tail", "30", "alice"})
	assert.Equal(t, -1, shIndex(calls, 0, "setup-token"))
}

func TestImageIDMismatchStopsTheInstall(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	e.vars["STUB_IMAGE_IDS"] = "alice:1.0.0=sha256:" + strings.Repeat("9", 64) + " alice-postgres:1.0.0=" + shPostgresID
	r := e.install(e.pkg(shPkgOpts{}))
	assert.Contains(t, r.out, "[FAIL] "+shDamaged+"\n")
	assert.Equal(t, 1, r.code)
	assert.Equal(t, -1, shIndex(e.dockerCalls(), 0, "compose", "up"))
}

func TestSignatureChecks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(e *shEnv, dir string)
		msg    string
	}{
		{"tampered SHA256SUMS", func(_ *shEnv, dir string) {
			b, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
			require.NoError(t, err)
			s := string(b)
			s = strings.Replace(s, s[:1], map[bool]string{true: "1", false: "0"}[s[0] == '0'], 1)
			shWrite(t, filepath.Join(dir, "SHA256SUMS"), s, 0o644)
		}, shBadSig},
		{"signed by another key", func(_ *shEnv, dir string) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			shSign(t, dir, priv)
		}, shBadSig},
		{"unlisted initdb script", func(_ *shEnv, dir string) {
			shWrite(t, filepath.Join(dir, "lib/initdb/20-x.sh"), "#!/bin/sh\nevil\n", 0o644)
		}, shDamaged},
		{"unlisted release key", func(e *shEnv, dir string) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			b, _ := shPubPEM(t, pub, "rk-evil")
			shWrite(t, filepath.Join(dir, "release-keys/rk-evil.pem"), string(b), 0o644)
		}, shDamaged},
		{"symlink in the package", func(_ *shEnv, dir string) {
			require.NoError(t, os.Symlink("/etc/hostname", filepath.Join(dir, "docs", "link.md")))
		}, shDamaged},
		{"image differs from SHA256SUMS", func(_ *shEnv, dir string) {
			shWrite(t, filepath.Join(dir, "images/alice-1.0.0.tar"), "other bytes", 0o644)
		}, shDamaged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := shNew(t)
			dir := e.pkg(shPkgOpts{})
			c.mutate(e, dir)
			r := e.install(dir)
			assert.Contains(t, r.out, "[FAIL] "+c.msg+"\n")
			if c.msg == shBadSig {
				assert.NotContains(t, r.out, shDamaged)
			}
			assert.Equal(t, 1, r.code)
			shNoDir(t, e.inst)
		})
	}
	t.Run("no openssl", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		dir := e.pkg(shPkgOpts{})
		e.path = e.bin + ":" + e.noOpenSSLDir()
		r := e.install(dir)
		assert.Contains(t, r.out, "[FAIL] OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again.\n")
		assert.Equal(t, 1, r.code)
		shNoDir(t, e.inst)
	})
	t.Run("valid package prints the fingerprint", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Regexp(t, `Package signed by release key rk-test-01 \(SHA-256 fingerprint [0-9a-f]{64}\)\.`, r.out)
		assert.Contains(t, r.out, e.keyHash)
		assert.Equal(t, 0, r.code, r.out)
	})
}

func TestInstallNeedsTheFingerprintConfirmed(t *testing.T) {
	t.Parallel()
	t.Run("interactive no", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		pkg := e.pkg(shPkgOpts{})
		r := e.run("no\n", filepath.Join(pkg, "install.sh"), "--dir", e.inst, "--hostname", "alice.test", "--port", "19443")
		assert.Contains(t, r.out, "Does this fingerprint match the one your vendor published? Type yes to continue: ")
		assert.Contains(t, r.out, "Nothing was changed.\n")
		assert.Equal(t, 1, r.code)
		shNoDir(t, e.inst)
	})
	t.Run("interactive yes", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		pkg := e.pkg(shPkgOpts{})
		r := e.run("yes\n", filepath.Join(pkg, "install.sh"), "--dir", e.inst, "--hostname", "alice.test", "--port", "19443")
		assert.Equal(t, 0, r.code, r.out)
	})
	t.Run("non-interactive without fingerprint", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		pkg := e.pkg(shPkgOpts{})
		r := e.run("", filepath.Join(pkg, "install.sh"), "--dir", e.inst, "--hostname", "alice.test", "--non-interactive")
		assert.Equal(t, 2, r.code, r.out)
		shNoDir(t, e.inst)
	})
	t.Run("non-interactive with a wrong fingerprint", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		pkg := e.pkg(shPkgOpts{})
		r := e.run("", filepath.Join(pkg, "install.sh"), "--dir", e.inst, "--hostname", "alice.test", "--port", "19443",
			"--non-interactive", "--fingerprint", strings.Repeat("ab", 32))
		assert.Contains(t, r.out, "The package fingerprint does not match --fingerprint. Nothing was changed.\n")
		assert.Equal(t, 1, r.code)
		shNoDir(t, e.inst)
	})
}

func TestInstallWarnsOnTestSignedPackage(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	r := e.install(e.pkg(shPkgOpts{testSigned: true}))
	assert.Contains(t, r.out, shTestWarn+"\n")
	assert.Equal(t, 0, r.code, r.out)

	u := shNewInstalled(t, "1.0.0-rc.2")
	tb := shTarball(t, u.pkg(shPkgOpts{version: "1.0.0-rc.3", testSigned: true}), filepath.Join(u.root, "dl"), "1.0.0-rc.3", u.key)
	r = u.update(tb)
	assert.Contains(t, r.out, shTestWarn+"\n")
	assert.Equal(t, 0, r.code, r.out)

	plain := shNew(t)
	r = plain.install(plain.pkg(shPkgOpts{}))
	assert.NotContains(t, r.out, "TEST key")
}

func TestInstallValidatesEnvValues(t *testing.T) {
	t.Parallel()
	bad := [][]string{
		{"--hostname", "a$(id)"}, {"--hostname", "a\nb"}, {"--hostname", "-a.test"}, {"--hostname", "a.test,b#c"},
		{"--project", "A B"}, {"--project", "x\ny"}, {"--bind", "1.2.3"}, {"--bind", "1.2.3.400"},
		{"--port", "70000"}, {"--port", "0"}, {"--port", "44a"}, {"--dir", "relative/path"}, {"--unknown"},
	}
	for _, b := range bad {
		t.Run(strings.Join(b, "="), func(t *testing.T) {
			t.Parallel()
			e := shNew(t)
			pkg := e.pkg(shPkgOpts{})
			args := append(e.installArgs(), b...)
			r := e.run("", filepath.Join(pkg, "install.sh"), args...)
			assert.Equal(t, 2, r.code, r.out)
			shNoDir(t, e.inst)
			assert.Empty(t, e.dockerCalls())
		})
	}
	t.Run("good values", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		pkg := e.pkg(shPkgOpts{})
		r := e.run("", filepath.Join(pkg, "install.sh"), append(e.installArgs(), "--hostname", "alice.test,alice-2.example.com", "--bind", "::1")...)
		assert.Equal(t, 0, r.code, r.out)
		env, err := os.ReadFile(filepath.Join(e.inst, ".env"))
		require.NoError(t, err)
		assert.Contains(t, string(env), "ALICE_TLS_HOSTS=alice.test,alice-2.example.com\n")
		assert.Contains(t, string(env), "ALICE_BIND=::1\n")
	})
	t.Run("zone with a newline", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_TZ"] = "Europe/Istanbul\nEVIL=1"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Equal(t, 0, r.code, r.out)
		assert.Contains(t, r.out, "[WARN] The time zone of this server could not be read; Alice uses UTC.\n")
		env, err := os.ReadFile(filepath.Join(e.inst, ".env"))
		require.NoError(t, err)
		assert.Contains(t, string(env), "ALICE_TZ=UTC\n")
		assert.NotContains(t, string(env), "EVIL")
	})
}

func TestInstallRefusesAnUnsafeDir(t *testing.T) {
	t.Parallel()
	t.Run("world-writable parent", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		bad := filepath.Join(e.srv, "open")
		require.NoError(t, os.Mkdir(bad, 0o755))
		require.NoError(t, os.Chmod(bad, 0o777))
		e.inst = filepath.Join(bad, "alice")
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "The installation directory "+e.inst+" has a parent that other users can change ("+bad+"). Choose another --dir.\n")
		assert.Equal(t, 2, r.code)
		shNoDir(t, e.inst)
	})
	t.Run("parent owned by a user", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		bad := filepath.Join(e.srv, "home")
		require.NoError(t, os.Mkdir(bad, 0o755))
		e.inst = filepath.Join(bad, "alice")
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "The installation directory "+e.inst+" has a parent that other users can change ("+bad+"). Choose another --dir.\n")
		assert.Equal(t, 2, r.code)
		shNoDir(t, e.inst)
	})
}

func shEnvHas(env []string, name string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, name+"=") {
			return true
		}
	}
	return false
}

func TestComposeIgnoresCallerEnvironment(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	for k, v := range map[string]string{"ALICE_IMAGE": "evil:1", "POSTGRES_IMAGE": "evil:2", "DOCKER_HOST": "tcp://x",
		"COMPOSE_FILE": "/x", "COMPOSE_PROFILES": "admin", "DOCKER_CONFIG": "/x"} {
		e.env[k] = v
	}
	r := e.install(e.pkg(shPkgOpts{}))
	require.Equal(t, 0, r.code, r.out)
	calls := e.dockerCalls()
	require.NotEmpty(t, calls)
	for _, c := range calls {
		for _, n := range []string{"ALICE_IMAGE", "POSTGRES_IMAGE", "DOCKER_HOST", "COMPOSE_FILE", "COMPOSE_PROFILES", "DOCKER_CONFIG",
			"ALICE_PROC_DIR", "ALICE_DOCKER_SOCK"} {
			assert.False(t, shEnvHas(c.env, n), "%s reached %s", n, c.line())
		}
	}
}

func TestTestOverridesAreAnnounced(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	sock := filepath.Join(e.root, "docker.sock")
	shWrite(t, sock, "", 0o660)
	e.env["ALICE_DOCKER_SOCK"] = sock
	r := e.install(e.pkg(shPkgOpts{}))
	require.Equal(t, 0, r.code, r.out)
	for _, n := range []string{"ALICE_PROC_DIR", "ALICE_DOCKER_SOCK"} {
		line := "[WARN] Test override " + n + " is set; results of this check are not real.\n"
		assert.Contains(t, r.out, line)
		logb, err := os.ReadFile(filepath.Join(e.inst, "install.log"))
		require.NoError(t, err)
		assert.Contains(t, string(logb), line)
	}
	for _, c := range e.dockerCalls() {
		assert.False(t, shEnvHas(c.env, "ALICE_PROC_DIR"), c.line())
		assert.False(t, shEnvHas(c.env, "ALICE_DOCKER_SOCK"), c.line())
	}

	quiet := shNew(t)
	delete(quiet.env, "ALICE_PROC_DIR")
	quiet.vars["STUB_UID"] = "1000" // stop after the preflight; the real /proc/meminfo is read
	r = quiet.install(quiet.pkg(shPkgOpts{}))
	assert.NotContains(t, r.out, "Test override")
}

func TestInstallRefusesAnExistingInstallation(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	pkg := e.pkg(shPkgOpts{})
	require.Equal(t, 0, e.install(pkg).code)
	before := len(e.dockerCalls())
	r := e.install(pkg)
	assert.Contains(t, r.out, "[FAIL] Alice is already installed in "+e.inst+". To upgrade use ./alice-update.sh.\n")
	assert.Equal(t, 1, r.code)
	assert.Equal(t, -1, shIndex(e.dockerCalls(), before, "compose", "up"))
}

func TestRestoreModeStartsOnlyPostgres(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	r := e.install(e.pkg(shPkgOpts{}), "--restore-mode")
	require.Equal(t, 0, r.code, r.out)
	shNoDir(t, filepath.Join(e.inst, "keys/master.key"))
	calls := e.dockerCalls()
	shOrder(t, calls, []string{"compose", "up", "postgres"})
	for _, c := range calls {
		if shHas(c.args, "compose", "up") {
			assert.False(t, shHas(c.args, "alice"), c.line())
		}
		assert.False(t, shHas(c.args, "setup-token"), c.line())
	}
	assert.Equal(t, -1, shIndex(calls, 0, "compose", "run", "migrate"))
	assert.Contains(t, r.out, "Alice is ready for a restore. Copy the backup file into "+e.inst+"/backups, then run: sudo "+e.inst+"/alicectl restore "+e.inst+"/backups/<file>\n")
	for _, n := range []string{"db_postgres_password", "db_owner_password", "db_app_password"} {
		_, err := os.Stat(filepath.Join(e.inst, "secrets", n))
		assert.NoError(t, err)
	}
}

func TestUninstallKeepsData(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	pkg := e.pkg(shPkgOpts{})
	require.Equal(t, 0, e.install(pkg).code)
	before := len(e.dockerCalls())
	r := e.run("", filepath.Join(e.inst, "install.sh"), "--dir", e.inst, "--uninstall")
	require.Equal(t, 0, r.code, r.out)
	assert.Contains(t, r.out, "Alice was stopped and its containers removed. Your data and backups are still in "+e.inst+".\n")
	calls := e.dockerCalls()[before:]
	i := shIndex(calls, 0, "compose", "down")
	require.GreaterOrEqual(t, i, 0)
	assert.NotContains(t, calls[i].args, "-v")
	assert.NotContains(t, calls[i].args, "--volumes")
	assert.True(t, shHas(calls[i].args, "--project-name", "alice-unit"))
	for _, d := range []string{"keys", "state", "backups", "data/postgres", "secrets"} {
		_, err := os.Stat(filepath.Join(e.inst, d))
		assert.NoError(t, err)
	}
}

func TestPurgeNeedsTypedDelete(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	require.Equal(t, 0, e.install(e.pkg(shPkgOpts{})).code)
	script := filepath.Join(e.inst, "install.sh")
	r := e.run("yes\n", script, "--dir", e.inst, "--uninstall", "--purge")
	assert.Contains(t, r.out, "This deletes "+e.inst+" with all data and backups. Type DELETE to continue: ")
	assert.Contains(t, r.out, "Nothing was deleted.\n")
	assert.Equal(t, 1, r.code)
	_, err := os.Stat(e.inst)
	require.NoError(t, err)

	r = e.run("DELETE\n", script, "--dir", e.inst, "--uninstall", "--purge")
	assert.Equal(t, 0, r.code, r.out)
	shNoDir(t, e.inst)

	e2 := shNew(t)
	require.Equal(t, 0, e2.install(e2.pkg(shPkgOpts{})).code)
	r = e2.run("", filepath.Join(e2.inst, "install.sh"), "--dir", e2.inst, "--uninstall", "--purge", "--confirm", "DELETE")
	assert.Equal(t, 0, r.code, r.out)
	shNoDir(t, e2.inst)
}

// ---- version comparison ----

func TestVersionCompare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, want string
		code       int
	}{
		{"1.0.0", "1.0.0-rc.9", "1", 0}, {"1.0.0-rc.9", "1.0.0", "-1", 0}, {"1.0.0-rc.10", "1.0.0-rc.9", "1", 0},
		{"1.10.0", "1.9.9", "1", 0}, {"1.9.9", "1.10.0", "-1", 0}, {"2.0.0", "2.0.0", "0", 0},
		{"1.0.0-rc.2", "1.0.0-rc.2", "0", 0}, {"0.0.10", "0.0.9", "1", 0}, {"1.0.1", "1.0.0", "1", 0},
		{"1.0", "1.0.0", "", 2}, {"1.0.0", "v1.0.0", "", 2}, {"1.0.0-beta.1", "1.0.0", "", 2}, {"1.0.0\n", "1.0.0", "", 2},
	}
	lib, err := filepath.Abs("lib/alice-lib.sh")
	require.NoError(t, err)
	for _, c := range cases {
		out, err := exec.Command("bash", "-c", `. "$1"; alice_version_cmp "$2" "$3"`, "x", lib, c.a, c.b).CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		assert.Equal(t, c.code, code, "%q vs %q: %s", c.a, c.b, out)
		if c.code == 0 {
			assert.Equal(t, c.want+"\n", string(out), "%q vs %q", c.a, c.b)
		}
	}
}

// ---- update ----

// shNewInstalled builds an installation of version v (scripts, VERSION, RELEASE, keys, the
// container directories) as install.sh leaves it, and a passphrase file holding the canary.
func shNewInstalled(t *testing.T, v string, oldKeys ...string) *shEnv {
	e := shNew(t)
	in := e.inst
	shCopyScripts(t, in)
	shWrite(t, filepath.Join(in, "VERSION"), v+"\n", 0o644)
	shWrite(t, filepath.Join(in, "RELEASE"), shRelease(shPkgOpts{version: v, minFrom: "1.0.0-rc.1", buildTime: "2026-01-02T03:04:05Z"}), 0o644)
	shWrite(t, filepath.Join(in, "docker-compose.yml"), "services: {} # installed "+v+"\n", 0o644)
	shWrite(t, filepath.Join(in, ".env"), "COMPOSE_PROJECT_NAME=alice-unit\nALICE_IMAGE=alice:"+v+"\nPOSTGRES_IMAGE=alice-postgres:"+v+
		"\nALICE_BIND=127.0.0.1\nALICE_PORT=19443\nALICE_TLS_HOSTS=alice.test\nALICE_TZ=UTC\nSOME_PASSWORD=leak\nX_SECRET_Y=leak\nAPI_KEY=leak\n", 0o640)
	shWrite(t, filepath.Join(in, "lib/initdb/10-alice-roles.sh"), "#!/bin/sh\n", 0o644)
	shWrite(t, filepath.Join(in, "release-keys", shTestKeyID+".pem"), string(e.keyPEM), 0o644)
	for _, k := range oldKeys {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		b, _ := shPubPEM(t, pub, strings.TrimSuffix(k, ".pem"))
		shWrite(t, filepath.Join(in, "release-keys", k), string(b), 0o644)
	}
	for _, d := range []string{"keys", "state", "backups", "data/postgres", "secrets"} {
		require.NoError(t, os.MkdirAll(filepath.Join(in, d), 0o700))
	}
	shWrite(t, filepath.Join(e.root, "pass"), shCanary+"\n", 0o600)
	e.vars["STUB_IMAGE_IDS"] = ""
	for _, ver := range []string{"1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.3", "1.0.0-rc.4", "1.0.0", "1.1.0", "9.9.9"} {
		e.vars["STUB_IMAGE_IDS"] += " alice:" + ver + "=" + shAliceID + " alice-postgres:" + ver + "=" + shPostgresID
	}
	return e
}

func (e *shEnv) update(pkg string, extra ...string) shResult {
	args := append([]string{pkg, "--passphrase-file", filepath.Join(e.root, "pass"), "--non-interactive"}, extra...)
	return e.run("", filepath.Join(e.inst, "alice-update.sh"), args...)
}

func (e *shEnv) snapshot() map[string]string {
	e.t.Helper()
	m := map[string]string{}
	require.NoError(e.t, filepath.WalkDir(e.inst, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(e.inst, p)
		if strings.HasPrefix(rel, "update-") || strings.HasPrefix(rel, "backups/") || rel == ".lock" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m[rel] = string(b)
		return nil
	}))
	return m
}

func shNoUpdateDirs(t *testing.T, inst string) {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(inst, ".update-*"))
	require.NoError(t, err)
	assert.Empty(t, m, "work directories left behind")
}

// shNoCanary asserts that the passphrase appears in no argument list or environment of any
// recorded call, nor in a file of the installation.
func (e *shEnv) shNoCanary() {
	t := e.t
	t.Helper()
	for _, c := range e.calls() {
		assert.NotContains(t, strings.Join(c.args, " "), shCanary, c.line())
		assert.NotContains(t, strings.Join(c.env, " "), shCanary, c.line())
	}
	_ = filepath.WalkDir(e.inst, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, rerr := os.ReadFile(p)
			if rerr == nil {
				assert.NotContains(t, string(b), shCanary, p)
			}
		}
		return nil
	})
}

func TestUpdateRefusesTamperedAndDowngrade(t *testing.T) {
	t.Parallel()
	type tc struct {
		name  string
		build func(e *shEnv) string // returns the package argument
		msg   string
	}
	cases := []tc{
		{"tampered outer sha256", func(e *shEnv) string {
			tb := shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
			shWrite(t, tb+".sha256", strings.Repeat("0", 64)+"  alice-1.0.0.tar.gz\n", 0o644)
			return tb
		}, shBadUpdSig},
		{"outer signature by an unknown key", func(e *shEnv) string {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", other)
		}, shBadUpdSig},
		{"inner sums signed by a key only the package ships", func(e *shEnv) string {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			b, _ := shPubPEM(t, pub, "rk-test-02")
			dir := filepath.Join(e.root, "evil", "alice")
			e.buildPkg(dir, shPkgOpts{version: "1.0.0", extraKeys: map[string][]byte{"rk-test-02.pem": b}})
			shSign(t, dir, priv)
			return shTarball(t, dir, filepath.Join(e.root, "dl"), "1.0.0", e.key)
		}, shBadUpdSig},
		{"downgrade", func(e *shEnv) string {
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0-rc.1"}), filepath.Join(e.root, "dl"), "1.0.0-rc.1", e.key)
		}, "Going back to an older version is only possible by restoring a backup."},
		{"same version", func(e *shEnv) string {
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0-rc.2"}), filepath.Join(e.root, "dl"), "1.0.0-rc.2", e.key)
		}, "This installation is already at version 1.0.0-rc.2."},
		{"minimum version", func(e *shEnv) string {
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0-rc.4", minFrom: "1.0.0-rc.3"}), filepath.Join(e.root, "dl"), "1.0.0-rc.4", e.key)
		}, "Alice 1.0.0-rc.2 cannot be updated directly to 1.0.0-rc.4. Install 1.0.0-rc.3 first."},
		{"not enough disk", func(e *shEnv) string {
			e.vars["STUB_DISK_GB"] = "3"
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
		}, "Not enough free disk space in {inst}: 3 GB free, 6 GB needed for the update."},
		{"selfcheck fails", func(e *shEnv) string {
			e.vars["STUB_COMPOSE_FAIL"] = "exec selfcheck"
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
		}, "Alice is not healthy now (selfcheck failed). Fix it before updating; see {inst}/update-"},
		{"invalid value in .env", func(e *shEnv) string {
			b, err := os.ReadFile(filepath.Join(e.inst, ".env"))
			require.NoError(t, err)
			shWrite(t, filepath.Join(e.inst, ".env"), strings.Replace(string(b), "ALICE_PORT=19443", "ALICE_PORT=1$(id)", 1), 0o640)
			return shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
		}, "holds a value that is not valid"},
		{"missing signature file", func(e *shEnv) string {
			tb := shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
			require.NoError(t, os.Remove(tb+".sha256.sig"))
			return tb
		}, shBadUpdSig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := shNewInstalled(t, "1.0.0-rc.2")
			arg := c.build(e)
			before := e.snapshot()
			r := e.update(arg)
			assert.Contains(t, r.out, strings.ReplaceAll(c.msg, "{inst}", e.inst))
			assert.Equal(t, 1, r.code, r.out)
			calls := e.dockerCalls()
			assert.Equal(t, -1, shIndex(calls, 0, "compose", "stop"), shDump(calls))
			assert.Equal(t, -1, shIndex(calls, 0, "compose", "backup"), shDump(calls))
			assert.Equal(t, -1, shIndex(calls, 0, "load"), shDump(calls))
			assert.Equal(t, before, e.snapshot())
			shNoUpdateDirs(t, e.inst)
		})
	}
}

func TestUpdateHappyPathOrder(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2", "rk-old-01.pem")
	pkg := e.pkg(shPkgOpts{version: "1.0.0"})
	tb := shTarball(t, pkg, filepath.Join(e.root, "dl"), "1.0.0", e.key)
	r := e.update(tb)
	require.Equal(t, 0, r.code, r.out)
	assert.Contains(t, r.out, "Alice is now version 1.0.0.\n")
	calls := e.dockerCalls()
	bk := "/opt/alice/backups/alice-backup-0123abcd-20261011T000000Z-pre-upgrade-1.0.0-rc.2.alicebak"
	idx := shOrder(t, calls,
		[]string{"exec", "alice", "selfcheck"},
		[]string{"compose", "stop", "alice"},
		[]string{"exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c",
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'alice' AND usename IN ('alice_app','alice_owner')"},
		[]string{"run", "--rm", "alice-admin", "backup", "--reason", "pre-upgrade-1.0.0"},
		[]string{"run", "--rm", "alice-admin", "backup", "verify", bk, "--deep", "--passphrase-stdin"},
		[]string{"load", "-i"},
		[]string{"load", "-i"},
		[]string{"compose", "run", "--rm", "migrate"},
		[]string{"compose", "up", "-d", "--wait", "alice"},
		[]string{"exec", "alice", "selfcheck"})
	if len(idx) > 4 {
		v := calls[idx[4]]
		require.NotNil(t, v.stdin)
		assert.Equal(t, shCanary+"\n", *v.stdin)
	}
	e.shNoCanary()
	// The rollback copy was taken before the images were loaded.
	rb := filepath.Join(e.inst, "rollback", "1.0.0-rc.2")
	for _, f := range []string{"docker-compose.yml", ".env", "RELEASE", "VERSION", "install.sh", "alice-update.sh", "alicectl",
		"lib/alice-lib.sh", "release-keys/rk-old-01.pem"} {
		_, err := os.Stat(filepath.Join(rb, f))
		assert.NoError(t, err, f)
	}
	b, err := os.ReadFile(filepath.Join(rb, "docker-compose.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(b), "installed 1.0.0-rc.2")
	// New files installed; release-keys replaced (S-35).
	b, err = os.ReadFile(filepath.Join(e.inst, "VERSION"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0\n", string(b))
	b, err = os.ReadFile(filepath.Join(e.inst, "docker-compose.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(b), "version 1.0.0")
	shNoDir(t, filepath.Join(e.inst, "release-keys", "rk-old-01.pem"))
	_, err = os.Stat(filepath.Join(e.inst, "release-keys", shTestKeyID+".pem"))
	assert.NoError(t, err)
	shNoDir(t, filepath.Join(e.inst, "release-keys.new"))
	shNoDir(t, filepath.Join(e.inst, "release-keys.old"))
	env, err := os.ReadFile(filepath.Join(e.inst, ".env"))
	require.NoError(t, err)
	assert.Contains(t, string(env), "ALICE_IMAGE=alice:1.0.0\n")
	assert.Contains(t, string(env), "POSTGRES_IMAGE=alice-postgres:1.0.0\n")
	assert.Contains(t, string(env), "COMPOSE_PROJECT_NAME=alice-unit\n")
	assert.Contains(t, string(env), "ALICE_PORT=19443\n")
	shNoUpdateDirs(t, e.inst)
	logs, _ := filepath.Glob(filepath.Join(e.inst, "update-*.log"))
	require.Len(t, logs, 1)
	shMode(t, logs[0], 0o600)
}

func TestUpdateVerifiesACopy(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	tb := shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
	evil := shTarball(t, e.pkg(shPkgOpts{version: "9.9.9"}), filepath.Join(e.root, "evil"), "9.9.9", e.key)
	swapDir, err := filepath.Abs("testdata/swap-openssl")
	require.NoError(t, err)
	swapLog := filepath.Join(e.root, "swap.log")
	e.env["SWAP_REAL_PATH"] = os.Getenv("PATH")
	e.env["SWAP_LOG"] = swapLog
	e.env["SWAP_ORIGINAL"] = tb
	e.env["SWAP_REPLACEMENT"] = evil
	e.path = swapDir + ":" + e.path
	r := e.update(tb)
	require.Equal(t, 0, r.code, r.out)
	_, err = os.Stat(swapLog + ".swapped")
	require.NoError(t, err, "the original was replaced during the run")
	b, err := os.ReadFile(filepath.Join(e.inst, "VERSION"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0\n", string(b))
	assert.Contains(t, r.out, "Alice is now version 1.0.0.\n")
	sl, err := os.ReadFile(swapLog)
	require.NoError(t, err)
	first := ""
	for _, l := range strings.Split(string(sl), "\n") {
		if strings.HasPrefix(l, "pkeyutl ") {
			first = l
			break
		}
	}
	assert.Regexp(t, `^pkeyutl -verify -pubin -inkey `+regexp.QuoteMeta(e.inst)+`/release-keys/rk-test-01\.pem -rawin -in `+
		regexp.QuoteMeta(e.inst)+`/\.update-[0-9TZ]+/in/alice-1\.0\.0\.tar\.gz\.sha256 -sigfile `+
		regexp.QuoteMeta(e.inst)+`/\.update-[0-9TZ]+/in/alice-1\.0\.0\.tar\.gz\.sha256\.sig$`, first)
}

func TestUpdateDirectoryWithAnExtraFileIsRefused(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	dir := e.pkg(shPkgOpts{version: "1.0.0"})
	shWrite(t, filepath.Join(dir, "lib/initdb/20-x.sh"), "#!/bin/sh\nevil\n", 0o644)
	before := e.snapshot()
	r := e.update(dir)
	assert.Contains(t, r.out, shDamaged+"\n")
	assert.Equal(t, 1, r.code)
	assert.Equal(t, before, e.snapshot())
	assert.Equal(t, -1, shIndex(e.dockerCalls(), 0, "compose", "stop"))
	shNoUpdateDirs(t, e.inst)

	// The same directory without the extra file is accepted.
	require.NoError(t, os.Remove(filepath.Join(dir, "lib/initdb/20-x.sh")))
	r = e.update(dir)
	assert.Equal(t, 0, r.code, r.out)
}

func TestUpdateRestartsAliceWhenTheBackupFails(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	e.vars["STUB_COMPOSE_FAIL"] = "backup --reason"
	before := e.snapshot()
	r := e.update(shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key))
	assert.Contains(t, r.out, "The update was stopped before any change; Alice is running version 1.0.0-rc.2 again.\n")
	assert.Equal(t, 1, r.code)
	calls := e.dockerCalls()
	shOrder(t, calls, []string{"compose", "stop", "alice"}, []string{"backup", "--reason"}, []string{"compose", "up", "-d", "--wait", "alice"})
	assert.Equal(t, -1, shIndex(calls, 0, "load"))
	assert.Equal(t, -1, shIndex(calls, 0, "restore"))
	shNoDir(t, filepath.Join(e.inst, "rollback"))
	assert.Equal(t, before, e.snapshot())
	shNoUpdateDirs(t, e.inst)
}

func TestUpdateExit3WhenAliceDoesNotStartAgain(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	e.vars["STUB_COMPOSE_FAIL"] = "backup --reason;up alice"
	r := e.update(shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key))
	assert.Equal(t, 3, r.code, r.out)
	assert.Regexp(t, `Alice could not be started again\. Details: `+regexp.QuoteMeta(e.inst)+`/update-[0-9TZ]+\.log\. Please send this file to support\.\n`, r.out)
	m, err := filepath.Glob(filepath.Join(e.inst, ".update-*"))
	require.NoError(t, err)
	assert.Len(t, m, 1, "the work directory is kept on exit 3")
}

func TestUpdateRollsBackWhenMigrationFails(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	e.vars["STUB_COMPOSE_FAIL"] = "run migrate"
	before := e.snapshot()
	r := e.update(shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key))
	assert.Equal(t, 1, r.code, r.out)
	assert.Regexp(t, `The update to 1\.0\.0 failed and Alice was returned to 1\.0\.0-rc\.2\. Your data is unchanged as of `+
		`[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC\. Details: `+regexp.QuoteMeta(e.inst)+`/update-[0-9TZ]+\.log\. Please send this file to support\.\n`, r.out)
	calls := e.dockerCalls()
	bk := "/opt/alice/backups/alice-backup-0123abcd-20261011T000000Z-pre-upgrade-1.0.0-rc.2.alicebak"
	mig := shIndex(calls, 0, "compose", "run", "migrate")
	require.GreaterOrEqual(t, mig, 0)
	idx := shOrder(t, calls[mig+1:],
		[]string{"compose", "stop", "alice"},
		[]string{"exec", "-T", "postgres", "psql", "~pg_terminate_backend"},
		[]string{"run", "--rm", "alice-admin", "restore", bk, "--db-only", "--confirm", "RESTORE", "--passphrase-stdin"},
		[]string{"compose", "up", "-d", "--wait", "alice"},
		[]string{"selfcheck"})
	// The update stops Alice and ends the sessions itself before it runs alicectl restore, which
	// does both again: two stops and two cleanups after migrate, the first pair before the restore's
	// deep verify.
	after := calls[mig+1:]
	stops, terms := 0, 0
	for _, c := range after {
		if shHas(c.args, "compose", "stop", "alice") {
			stops++
		}
		if shHas(c.args, "psql", "~pg_terminate_backend") {
			terms++
		}
	}
	assert.Equal(t, 2, stops, shDump(after))
	assert.Equal(t, 2, terms, shDump(after))
	shOrder(t, after, []string{"compose", "stop", "alice"}, []string{"psql", "~pg_terminate_backend"},
		[]string{"backup", "verify", bk, "--deep"})
	// The session cleanup command matches by substring of its SQL argument.
	if len(idx) == 5 {
		rs := calls[mig+1+idx[2]]
		require.NotNil(t, rs.stdin)
		assert.Equal(t, shCanary+"\n", *rs.stdin)
	}
	snap := e.snapshot()
	for _, f := range []string{"docker-compose.yml", ".env", "RELEASE", "VERSION"} {
		assert.Equal(t, before[f], snap[f], "%s restored byte for byte", f)
	}
	_, err := os.Stat(filepath.Join(e.inst, "backups", "alice-backup-0123abcd-20261011T000000Z-pre-upgrade-1.0.0-rc.2.alicebak"))
	assert.NoError(t, err, "the pre-update backup is kept")
	e.shNoCanary()
	shNoUpdateDirs(t, e.inst)
}

func TestUpdateExit3WhenTheRollbackFails(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	e.vars["STUB_COMPOSE_FAIL"] = "run migrate;alice-admin restore"
	r := e.update(shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key))
	assert.Equal(t, 3, r.code, r.out)
	host := e.inst + "/backups/alice-backup-0123abcd-20261011T000000Z-pre-upgrade-1.0.0-rc.2.alicebak"
	assert.Regexp(t, `The update to 1\.0\.0 failed and Alice could not be returned to 1\.0\.0-rc\.2 automatically\. Your backup is `+
		regexp.QuoteMeta(host)+`\. Restore it by hand: cd `+regexp.QuoteMeta(e.inst)+` && sudo \./alicectl restore `+regexp.QuoteMeta(host)+
		`   \(details: `+regexp.QuoteMeta(e.inst)+`/update-[0-9TZ]+\.log\)\n`, r.out)
	_, err := os.Stat(host)
	assert.NoError(t, err)
}

func TestUpdateInterruptedAfterStopRollsBack(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	e.vars["STUB_SLEEP"] = "run migrate"
	e.vars["STUB_SLEEP_SECS"] = "2"
	tb := shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
	c := e.cmd("", filepath.Join(e.inst, "alice-update.sh"), tb, "--passphrase-file", filepath.Join(e.root, "pass"), "--non-interactive")
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	require.NoError(t, c.Start())
	deadline := time.Now().Add(60 * time.Second)
	for shIndex(e.dockerCalls(), 0, "compose", "run", "migrate") < 0 {
		require.True(t, time.Now().Before(deadline), "migrate never started")
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	// Only the script gets the signal: the sleeping migrate stub is not killed and succeeds, so the
	// update returns only because its INT trap ran (an ignored or untrapped signal would end in
	// "Alice is now version 1.0.0." or exit 130).
	require.NoError(t, syscall.Kill(c.Process.Pid, syscall.SIGINT))
	err := c.Wait()
	var ee *exec.ExitError
	require.ErrorAs(t, err, &ee, out.String())
	assert.Equal(t, 1, ee.ExitCode(), out.String())
	assert.Contains(t, out.String(), "\nInterrupted.\n")
	assert.NotContains(t, out.String(), "Alice is now version")
	if !assert.Contains(t, out.String(), "The update to 1.0.0 failed and Alice was returned to 1.0.0-rc.2.") {
		logs, _ := filepath.Glob(filepath.Join(e.inst, "update-*.log"))
		for _, l := range logs {
			b, _ := os.ReadFile(l)
			t.Logf("update log %s:\n%s", l, b)
		}
		t.Logf("docker calls:\n%s", shDump(e.dockerCalls()))
	}
	calls := e.dockerCalls()
	mig := shIndex(calls, 0, "compose", "run", "migrate")
	shOrder(t, calls[mig+1:], []string{"compose", "stop", "alice"}, []string{"alice-admin", "restore"}, []string{"compose", "up", "alice"})
}

// ---- alicectl ----

func (e *shEnv) ctl(stdin string, args ...string) shResult {
	return e.run(stdin, filepath.Join(e.inst, "alicectl"), args...)
}

func TestAlicectl(t *testing.T) {
	t.Parallel()
	t.Run("backup", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		r := e.ctl("", "backup")
		require.Equal(t, 0, r.code, r.out)
		shOrder(t, e.dockerCalls(), []string{"compose", "exec", "-T", "alice", "/usr/local/bin/alice", "backup"})
		r = e.ctl("", "backup", "--reason", "pre-upgrade-1.1.0", "--out", "x.alicebak")
		require.Equal(t, 0, r.code, r.out)
		c := e.dockerCalls()
		last := c[len(c)-1]
		assert.True(t, shHas(last.args, "exec", "-T", "alice", "/usr/local/bin/alice", "backup"), last.line())
		assert.True(t, shHas(last.args, "--reason", "pre-upgrade-1.1.0") && shHas(last.args, "--out", "x.alicebak"), last.line())
		assert.True(t, shHas(last.args, "--project-name", "alice-unit", "-f", filepath.Join(e.inst, "docker-compose.yml")), last.line())
	})
	t.Run("restore", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		shWrite(t, filepath.Join(e.inst, "backups/x.alicebak"), "", 0o600)
		r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"),
			"--confirm", "RESTORE")
		require.Equal(t, 0, r.code, r.out)
		calls := e.dockerCalls()
		idx := shOrder(t, calls,
			[]string{"exec", "-T", "alice", "/usr/local/bin/alice", "backup", "verify", "/opt/alice/backups/x.alicebak", "--deep", "--passphrase-stdin"},
			[]string{"compose", "stop", "alice"},
			[]string{"exec", "-T", "postgres", "psql", "~pg_terminate_backend"},
			[]string{"run", "--rm", "alice-admin", "restore", "/opt/alice/backups/x.alicebak", "--free-bytes", fmt.Sprint(int64(100) << 30), "--passphrase-stdin"},
			[]string{"compose", "up", "-d", "--wait", "alice"},
			[]string{"exec", "alice", "/usr/local/bin/alice", "selfcheck"})
		for _, i := range []int{0, 3} {
			if i < len(idx) {
				require.NotNil(t, calls[idx[i]].stdin, calls[idx[i]].line())
				assert.Equal(t, shCanary+"\n", *calls[idx[i]].stdin)
			}
		}
		e.shNoCanary()
		r = e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"),
			"--no-safety-backup", "--db-only", "--confirm", "RESTORE", "--accept-broken-audit-log")
		require.Equal(t, 0, r.code, r.out)
		calls = e.dockerCalls()
		i := len(calls) - 1
		for ; i >= 0 && !shHas(calls[i].args, "alice-admin", "restore"); i-- {
		}
		require.GreaterOrEqual(t, i, 0)
		for _, f := range []string{"--no-safety-backup", "--db-only", "--accept-broken-audit-log"} {
			assert.Contains(t, calls[i].args, f)
		}
		assert.True(t, shHas(calls[i].args, "--confirm", "RESTORE"))
	})
	t.Run("file outside backups", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		out := filepath.Join(e.root, "x.alicebak")
		shWrite(t, out, "", 0o600)
		r := e.ctl("", "restore", out, "--passphrase-file", filepath.Join(e.root, "pass"))
		assert.Contains(t, r.out, "The backup file must be in "+e.inst+"/backups. Copy it there first.\n")
		assert.Equal(t, 2, r.code)
		assert.Empty(t, e.dockerCalls())
		r = e.ctl("", "backup", "verify", filepath.Join(e.inst, "backups", "missing.alicebak"))
		assert.Equal(t, 2, r.code)
	})
	t.Run("setup-token", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		r := e.ctl("", "setup-token", "--reset")
		require.Equal(t, 0, r.code, r.out)
		assert.Contains(t, r.out, shSetupCode)
		shOrder(t, e.dockerCalls(), []string{"exec", "alice", "/usr/local/bin/alice", "setup-token", "--reset"})
		_ = filepath.WalkDir(e.inst, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				assert.NotContains(t, string(b), shSetupCode, p)
			}
			return nil
		})
	})
	t.Run("backup list while alice is stopped", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		e.vars["STUB_RUNNING"] = "postgres"
		r := e.ctl("", "backup", "list")
		require.Equal(t, 0, r.code, r.out)
		calls := e.dockerCalls()
		shOrder(t, calls, []string{"compose", "ps", "--status", "running", "--services"}, []string{"compose", "run", "--rm", "alice-admin", "backup", "list"})
		assert.Equal(t, -1, shIndex(calls, 0, "exec"))
	})
	t.Run("support-bundle", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		r := e.ctl("", "support-bundle")
		require.Equal(t, 0, r.code, r.out)
		m, err := filepath.Glob(filepath.Join(e.inst, "support-bundle-*.tar.gz"))
		require.NoError(t, err)
		require.Len(t, m, 1)
		shMode(t, m[0], 0o600)
		files := shReadTarGz(t, m[0])
		for _, n := range []string{"ps.txt", "logs-alice.txt", "logs-postgres.txt", "bundle.json", "docker-version.txt", "df.txt", "env.txt"} {
			assert.Contains(t, files, n)
		}
		assert.Contains(t, files["env.txt"], "ALICE_PORT=19443")
		assert.NotContains(t, files["env.txt"], "leak")
		assert.Contains(t, files["bundle.json"], `"stub":true`)
		left, _ := filepath.Glob(filepath.Join(e.inst, ".support-*"))
		assert.Empty(t, left)
	})
	t.Run("selfcheck and audit verify", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		require.Equal(t, 0, e.ctl("", "selfcheck").code)
		require.Equal(t, 0, e.ctl("", "audit", "verify").code)
		shOrder(t, e.dockerCalls(), []string{"exec", "alice", "selfcheck"}, []string{"exec", "alice", "audit", "verify"})
		r := e.ctl("", "help")
		assert.Equal(t, 0, r.code)
		assert.Contains(t, r.out, "restore FILE")
		assert.Equal(t, 2, e.ctl("", "frobnicate").code)
	})
	t.Run("group-readable passphrase file", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		shWrite(t, filepath.Join(e.inst, "backups/x.alicebak"), "", 0o600)
		require.NoError(t, os.Chmod(filepath.Join(e.root, "pass"), 0o640))
		r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
		assert.Equal(t, 2, r.code, r.out)
		assert.Contains(t, r.out, "[WARN] ")
		assert.Empty(t, e.dockerCalls())
	})
	t.Run("no passphrase without a terminal", func(t *testing.T) {
		t.Parallel()
		e := shNewInstalled(t, "1.0.0")
		shWrite(t, filepath.Join(e.inst, "backups/x.alicebak"), "", 0o600)
		r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--confirm", "RESTORE")
		assert.Contains(t, r.out, "A passphrase is needed. Run this command in a terminal, or pass --passphrase-file to alicectl.\n")
		assert.Equal(t, 2, r.code)
	})
}

func shReadTarGz(t *testing.T, p string) map[string]string {
	t.Helper()
	f, err := os.Open(p)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	m := map[string]string{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(tr)
		m[strings.TrimPrefix(h.Name, "./")] = b.String()
	}
	return m
}

func TestAlicectlWrongPassphraseNeverStopsAlice(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0")
	e.vars["STUB_COMPOSE_FAIL"] = "backup verify"
	e.vars["STUB_FAIL_OUTPUT"] = "The passphrase is wrong or the file is damaged. Nothing was changed."
	shWrite(t, filepath.Join(e.inst, "backups/x.alicebak"), "", 0o600)
	r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
	assert.Equal(t, 1, r.code, r.out)
	assert.Contains(t, r.out, "The passphrase is wrong or the file is damaged. Nothing was changed.\n")
	calls := e.dockerCalls()
	assert.Equal(t, -1, shIndex(calls, 0, "compose", "stop"), shDump(calls))
	assert.Equal(t, -1, shIndex(calls, 0, "restore"), shDump(calls))
}

func TestAlicectlRestartsAliceAfterAFailedRestore(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0")
	e.vars["STUB_COMPOSE_FAIL"] = "alice-admin restore"
	shWrite(t, filepath.Join(e.inst, "backups/x.alicebak"), "", 0o600)
	r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
	assert.Equal(t, 1, r.code, r.out)
	shOrder(t, e.dockerCalls(), []string{"compose", "stop", "alice"}, []string{"alice-admin", "restore"},
		[]string{"compose", "up", "-d", "--wait", "alice"}, []string{"selfcheck"})
}

func TestAlicectlRefusesASymlinkedBackup(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0")
	outside := filepath.Join(e.root, "secret.alicebak")
	shWrite(t, outside, "", 0o600)
	require.NoError(t, os.Symlink(outside, filepath.Join(e.inst, "backups/x.alicebak")))
	r := e.ctl("", "restore", filepath.Join(e.inst, "backups/x.alicebak"), "--passphrase-file", filepath.Join(e.root, "pass"))
	assert.Contains(t, r.out, "The backup file must be in "+e.inst+"/backups. Copy it there first.\n")
	assert.Equal(t, 2, r.code)
	assert.Empty(t, e.dockerCalls())
}

func TestSupportBundleRefusesExistingOut(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0")
	regular := filepath.Join(e.root, "exists.tar.gz")
	shWrite(t, regular, "keep", 0o644)
	target := filepath.Join(e.root, "target")
	shWrite(t, target, "keep", 0o644)
	link := filepath.Join(e.root, "link.tar.gz")
	require.NoError(t, os.Symlink(target, link))
	dangling := filepath.Join(e.root, "dangling.tar.gz")
	require.NoError(t, os.Symlink(filepath.Join(e.root, "nothing"), dangling))
	for _, out := range []string{regular, link, dangling} {
		r := e.ctl("", "support-bundle", "--out", out)
		assert.Contains(t, r.out, "The file "+out+" already exists.\n")
		assert.Equal(t, 2, r.code)
	}
	for _, p := range []string{regular, target} {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, "keep", string(b))
	}
	shNoDir(t, filepath.Join(e.root, "nothing"))
	fresh := filepath.Join(e.root, "fresh.tar.gz")
	r := e.ctl("", "support-bundle", "--out", fresh)
	require.Equal(t, 0, r.code, r.out)
	shMode(t, fresh, 0o600)
}

// ---- static checks ----

func shSources(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, s := range shScripts {
		b, err := os.ReadFile(s)
		require.NoError(t, err)
		m[s] = string(b)
	}
	return m
}

// shStrip blanks quoted text and comments, keeping the line structure; it reports unquoted
// expansions ($name or ${...}) outside [[ ]], (( )), $(( )) and plain assignments.
func shStrip(src string) (code string, unquoted []string) {
	type mode int
	const (
		top mode = iota
		sq
		dq
		cmd
		arith
		dbr
	)
	var out []byte
	stack := []mode{top}
	parens := []int{0}
	lineNo := 1
	assign := false
	wordStart := true
	cur := func() mode { return stack[len(stack)-1] }
	assignRE := regexp.MustCompile(`^(?:(?:local|declare|readonly)(?: -[a-zA-Z]+)* )?[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=`)
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\n' {
			lineNo++
		}
		m := cur()
		switch m {
		case sq:
			switch c {
			case '\'':
				stack = stack[:len(stack)-1]
				out = append(out, c)
			case '\n':
				out = append(out, c)
			default:
				out = append(out, ' ')
			}
			continue
		case dq:
			switch {
			case c == '\\' && i+1 < len(src):
				out = append(out, ' ', ' ')
				i++
			case c == '"':
				stack = stack[:len(stack)-1]
				out = append(out, c)
			case strings.HasPrefix(src[i:], "$(("):
				stack = append(stack, arith)
				parens = append(parens, 0)
				out = append(out, "$(("...)
				i += 2
			case strings.HasPrefix(src[i:], "$("):
				stack = append(stack, cmd)
				parens = append(parens, 0)
				out = append(out, "$("...)
				i++
				wordStart = true
			case c == '\n':
				out = append(out, c)
			default:
				out = append(out, ' ')
			}
			continue
		case arith:
			if c == '(' {
				parens[len(parens)-1]++
			} else if c == ')' {
				if parens[len(parens)-1] == 0 && i+1 < len(src) && src[i+1] == ')' {
					stack = stack[:len(stack)-1]
					parens = parens[:len(parens)-1]
					out = append(out, "))"...)
					i++
					continue
				}
				parens[len(parens)-1]--
			}
			out = append(out, c)
			continue
		}
		// top, cmd and dbr: shell words.
		if c == '#' && wordStart {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			i--
			continue
		}
		if wordStart && m != dbr && assignRE.MatchString(src[i:]) {
			assign = true
		}
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '|' || c == '&':
			assign = false
			wordStart = true
			out = append(out, c)
			continue
		case c == '\\' && i+1 < len(src):
			out = append(out, c, src[i+1])
			i++
		case c == '\'':
			stack = append(stack, sq)
			out = append(out, c)
		case c == '"':
			stack = append(stack, dq)
			out = append(out, c)
		case strings.HasPrefix(src[i:], "$(("):
			stack = append(stack, arith)
			parens = append(parens, 0)
			out = append(out, "$(("...)
			i += 2
		case strings.HasPrefix(src[i:], "(("):
			stack = append(stack, arith)
			parens = append(parens, 0)
			out = append(out, "(("...)
			i++
		case strings.HasPrefix(src[i:], "$("):
			stack = append(stack, cmd)
			parens = append(parens, 0)
			out = append(out, "$("...)
			i++
			wordStart = true
			continue
		case m != dbr && strings.HasPrefix(src[i:], "[["):
			stack = append(stack, dbr)
			parens = append(parens, 0)
			out = append(out, "[["...)
			i++
		case m == dbr && strings.HasPrefix(src[i:], "]]"):
			stack = stack[:len(stack)-1]
			parens = parens[:len(parens)-1]
			out = append(out, "]]"...)
			i++
		case m == cmd && c == '(':
			parens[len(parens)-1]++
			out = append(out, c)
		case m == cmd && c == ')':
			if parens[len(parens)-1] == 0 {
				stack = stack[:len(stack)-1]
				parens = parens[:len(parens)-1]
			} else {
				parens[len(parens)-1]--
			}
			out = append(out, c)
		case c == '$' && i+1 < len(src) && (src[i+1] == '{' || src[i+1] == '_' || (src[i+1]|0x20 >= 'a' && src[i+1]|0x20 <= 'z')):
			if m != dbr && !assign {
				end := i + 1
				for end < len(src) && src[end] != '\n' && src[end] != ' ' {
					end++
				}
				unquoted = append(unquoted, fmt.Sprintf("line %d: %s", lineNo, src[i:end]))
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
		wordStart = false
	}
	return string(out), unquoted
}

func TestScriptsNeverSourcePackageFiles(t *testing.T) {
	t.Parallel()
	// Unquoted expansions that are allowed, by file and text (none so far).
	allowed := map[string][]string{}
	sourceRE := regexp.MustCompile(`(?m)^\s*(?:\.|source)\s+(.*)$`)
	for name, src := range shSources(t) {
		code, unq := shStrip(src)
		lines := strings.Split(src, "\n")
		if name != "lib/alice-lib.sh" {
			assert.Equal(t, "#!/usr/bin/env bash", lines[0], name)
			head := strings.Join(lines[:min(len(lines), 40)], "\n")
			assert.Contains(t, head, "\nset -Eeuo pipefail\n", name)
			assert.Contains(t, head, "\numask 077\n", name)
			srcs := sourceRE.FindAllStringSubmatch(src, -1)
			if assert.Len(t, srcs, 1, "%s: one sourced file", name) {
				assert.Equal(t, `"$here/lib/alice-lib.sh"`, strings.TrimSpace(srcs[0][1]), name)
			}
			assert.Regexp(t, `(?m)^here=\$\(cd -P "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)" && pwd\)$`, src, name)
			assert.Regexp(t, `(?m)^# shellcheck source=lib/alice-lib\.sh\n\. "\$here/lib/alice-lib\.sh"$`, src, name)
		} else {
			assert.Empty(t, sourceRE.FindAllString(code, -1), name)
		}
		for _, u := range unq {
			ok := false
			for _, a := range allowed[name] {
				if strings.Contains(u, a) {
					ok = true
				}
			}
			assert.True(t, ok, "%s: unquoted expansion %s", name, u)
		}
		for _, re := range []string{`\beval\b`, `\bcurl\b`, `\bwget\b`, `docker\s+pull\b`, `\b(apt|apt-get|dnf|yum)\b`,
			`set\s+-[a-zA-Z]*x`, `BASH_XTRACEFD`, `<<<`, `(?i)export\s+\S*pass`, `\bsource\b`} {
			assert.NotRegexp(t, re, code, "%s: %s", name, re)
		}
		// Every docker call goes through alice_docker or alice_compose (S-6): the word docker in
		// command position appears only in the one env -i line of the library.
		for i, l := range strings.Split(code, "\n") {
			if regexp.MustCompile(`(^|[\s;&|(])docker(\s|$)`).MatchString(l) {
				assert.True(t, name == "lib/alice-lib.sh" && strings.Contains(lines[i], `env -i PATH="$PATH" HOME=/root LC_ALL=C docker`),
					"%s:%d: docker called directly: %s", name, i+1, lines[i])
			}
		}
	}
}

func TestScriptsNeverTouchContainerDirs(t *testing.T) {
	t.Parallel()
	cmdRE := regexp.MustCompile(`(^|[\s;&|(])(chown|chmod|cp|cat|rm|mv|ln|install|tee|truncate|sha256sum)\b|>`)
	pathRE := regexp.MustCompile(`/(keys|state|backups|data)\b`)
	marker := "# ---- end of the layout step (S-8) ----"
	for name, src := range shSources(t) {
		code, _ := shStrip(src)
		raw := strings.Split(src, "\n")
		start := 0
		if name == "install.sh" {
			for i, l := range raw {
				if strings.TrimSpace(l) == marker {
					start = i + 1
				}
			}
			require.Positive(t, start, "install.sh has the layout marker")
		}
		for i, l := range strings.Split(code, "\n")[start:] {
			full := raw[start+i]
			l = regexp.MustCompile(`[0-9]?>&[0-9]|[0-9]?>/dev/null`).ReplaceAllString(l, "")
			if strings.HasPrefix(strings.TrimSpace(full), "#") {
				continue
			}
			if cmdRE.MatchString(l) && pathRE.MatchString(full) {
				t.Errorf("%s:%d touches a container-writable directory: %s", name, start+i+1, full)
			}
		}
	}
}

// TestStaticScannerFindsUnquotedExpansions proves that the static check above catches what it
// is meant to catch, and leaves the safe forms alone.
func TestStaticScannerFindsUnquotedExpansions(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{`rm -rf $dir`, `cp "$a" ${b}/x`, `x=$(cat $f)`, `echo "$(ls $d)"`, "echo ok\nchmod 600 $f\n"} {
		_, unq := shStrip(bad)
		assert.NotEmpty(t, unq, bad)
	}
	for _, good := range []string{`rm -rf -- "$dir"`, `x=$y`, `local a=${b%%/*}`, `[[ $a == "$b" ]]`, `(( n = $# + 1 ))`,
		`echo $((a + b))`, `echo 'it is $x'`, `echo "$(ls "$d")"`, `# a comment with $x`, `printf '%s\n' "${arr[@]}"`} {
		_, unq := shStrip(good)
		assert.Empty(t, unq, good)
	}
	code, _ := shStrip(`echo "docker pull x" # docker pull`)
	assert.NotContains(t, code, "docker")
}

// ---- fixes of the Task 11 review ----

// shNoStage asserts that install.sh removed its private copy of the package.
func shNoStage(t *testing.T, parent string) {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(parent, ".alice-install-*"))
	require.NoError(t, err)
	assert.Empty(t, m, "the private package copy is left behind")
}

// TestInstallVerifiesACopy (review I-1): right after the first signature check the release key and
// alicectl of the extracted package are replaced. install.sh must fingerprint, install and load
// only the copy it verified.
func TestInstallVerifiesACopy(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	pkg := e.pkg(shPkgOpts{})
	keyPath := filepath.Join(pkg, "release-keys", shTestKeyID+".pem")
	signedKey, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	signedCtl, err := os.ReadFile(filepath.Join(pkg, "alicectl"))
	require.NoError(t, err)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	evilKey, _ := shPubPEM(t, pub, shTestKeyID)
	shWrite(t, filepath.Join(e.root, "evil.pem"), string(evilKey), 0o644)
	shWrite(t, filepath.Join(e.root, "evil-alicectl"), "#!/bin/sh\necho evil\n", 0o755)
	swapDir, err := filepath.Abs("testdata/swap-openssl")
	require.NoError(t, err)
	swapLog := filepath.Join(e.root, "swap.log")
	e.env["SWAP_REAL_PATH"] = os.Getenv("PATH")
	e.env["SWAP_LOG"] = swapLog
	e.env["SWAP_ORIGINAL"] = keyPath
	e.env["SWAP_REPLACEMENT"] = filepath.Join(e.root, "evil.pem")
	e.env["SWAP_SECOND_ORIGINAL"] = filepath.Join(pkg, "alicectl")
	e.env["SWAP_SECOND_REPLACEMENT"] = filepath.Join(e.root, "evil-alicectl")
	e.path = swapDir + ":" + e.path

	r := e.install(pkg)
	require.Equal(t, 0, r.code, r.out)
	_, err = os.Stat(swapLog + ".swapped")
	require.NoError(t, err, "the package was changed during the run")
	assert.Contains(t, r.out, "(SHA-256 fingerprint "+e.keyHash+")")
	b, err := os.ReadFile(filepath.Join(e.inst, "release-keys", shTestKeyID+".pem"))
	require.NoError(t, err)
	assert.Equal(t, string(signedKey), string(b), "the installed release key is the verified one")
	b, err = os.ReadFile(filepath.Join(e.inst, "alicectl"))
	require.NoError(t, err)
	assert.Equal(t, string(signedCtl), string(b), "the installed alicectl is the verified one")
	sl, err := os.ReadFile(swapLog)
	require.NoError(t, err)
	for _, l := range strings.Split(string(sl), "\n") {
		assert.NotContains(t, l, pkg+"/", "openssl read the extracted package itself: %s", l)
	}
	for _, c := range e.dockerCalls() {
		for _, a := range c.args {
			assert.False(t, strings.HasPrefix(a, pkg+"/"), "docker read the extracted package itself: %s", c.line())
		}
	}
	shNoStage(t, e.srv)
}

func TestInstallRefusesAnotherProjectsContainers(t *testing.T) {
	t.Parallel()
	msg := func(p string) string {
		return "[FAIL] Docker already has containers of the project " + p +
			". Choose another --project, or update the installation that uses it with its own alice-update.sh.\n"
	}
	noCompose := func(t *testing.T, e *shEnv) {
		t.Helper()
		for _, c := range e.dockerCalls() {
			assert.False(t, len(c.args) > 0 && c.args[0] == "compose" && !shHas(c.args, "version"), c.line())
			assert.False(t, shHas(c.args, "load"), c.line())
		}
	}
	t.Run("named project", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_PROJECTS"] = "alice-unit"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, msg("alice-unit"))
		assert.Equal(t, 1, r.code, r.out)
		shNoDir(t, e.inst)
		noCompose(t, e)
		shOrder(t, e.dockerCalls(), []string{"ps", "-a", "-q", "--filter", "label=com.docker.compose.project=alice-unit"})
	})
	t.Run("default project", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_PROJECTS"] = "pt-other alice"
		pkg := e.pkg(shPkgOpts{})
		r := e.run("", filepath.Join(pkg, "install.sh"), "--dir", e.inst, "--port", "19443", "--bind", "127.0.0.1",
			"--hostname", "alice.test", "--non-interactive", "--fingerprint", e.keyHash)
		assert.Contains(t, r.out, msg("alice"))
		assert.Equal(t, 1, r.code, r.out)
		shNoDir(t, e.inst)
		noCompose(t, e)
	})
	t.Run("containers of other projects do not matter", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_PROJECTS"] = "alice alice-unit-2"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Equal(t, 0, r.code, r.out)
		assert.Contains(t, r.out, "[ OK ] No installation yet\n")
	})
	t.Run("docker cannot list the containers", func(t *testing.T) {
		t.Parallel()
		e := shNew(t)
		e.vars["STUB_PS_FAIL"] = "1"
		r := e.install(e.pkg(shPkgOpts{}))
		assert.Contains(t, r.out, "[FAIL] The containers of the project alice-unit could not be listed. Check that Docker is running, then run this installer again.\n")
		assert.Equal(t, 1, r.code, r.out)
		shNoDir(t, e.inst)
	})
}

func TestUninstallRefusesAnotherProject(t *testing.T) {
	t.Parallel()
	e := shNew(t)
	require.Equal(t, 0, e.install(e.pkg(shPkgOpts{})).code)
	script := filepath.Join(e.inst, "install.sh")
	before := len(e.dockerCalls())
	for _, args := range [][]string{{"--project", "alice"}, {"--project", "alice", "--purge", "--confirm", "DELETE"}} {
		r := e.run("", script, append([]string{"--dir", e.inst, "--uninstall"}, args...)...)
		assert.Contains(t, r.out, "--project alice is not the project of the installation in "+e.inst+" (alice-unit). Leave out --project.\n")
		assert.Equal(t, 2, r.code, r.out)
		assert.Empty(t, e.dockerCalls()[before:])
		_, err := os.Stat(filepath.Join(e.inst, "VERSION"))
		require.NoError(t, err)
	}

	// A .env without a valid project name is refused even with --project.
	envPath := filepath.Join(e.inst, ".env")
	good, err := os.ReadFile(envPath)
	require.NoError(t, err)
	shWrite(t, envPath, strings.Replace(string(good), "COMPOSE_PROJECT_NAME=alice-unit", "COMPOSE_PROJECT_NAME=", 1), 0o640)
	r := e.run("", script, "--dir", e.inst, "--uninstall", "--project", "alice")
	assert.Contains(t, r.out, "The project name in "+e.inst+"/.env is not valid. Fix COMPOSE_PROJECT_NAME there, then run this again.\n")
	assert.Equal(t, 2, r.code, r.out)
	assert.Empty(t, e.dockerCalls()[before:])

	// The project of .env, given or not, is accepted.
	shWrite(t, envPath, string(good), 0o640)
	r = e.run("", script, "--dir", e.inst, "--uninstall", "--project", "alice-unit")
	require.Equal(t, 0, r.code, r.out)
	calls := e.dockerCalls()[before:]
	i := shIndex(calls, 0, "compose", "down")
	require.GreaterOrEqual(t, i, 0)
	assert.True(t, shHas(calls[i].args, "--project-name", "alice-unit"), calls[i].line())
}

// shOpenPty opens a pseudo-terminal pair (master, slave).
func shOpenPty(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	require.NoError(t, err)
	var unlock int32
	if _, _, en := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); en != 0 {
		t.Fatalf("unlockpt: %v", en)
	}
	var n uint32
	if _, _, en := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); en != 0 {
		t.Fatalf("ptsname: %v", en)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	require.NoError(t, err)
	return m, s
}

// runTTY runs script with a pseudo-terminal as its controlling terminal (/dev/tty), ttyInput
// typed on it, and stdin as standard input; it returns the result (standard output and error)
// and what the script wrote to the terminal.
func (e *shEnv) runTTY(stdin, ttyInput, script string, args ...string) (shResult, string) {
	t := e.t
	t.Helper()
	m, s := shOpenPty(t)
	c := e.cmd(stdin, script, args...)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	c.ExtraFiles = []*os.File{s}
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	require.NoError(t, c.Start())
	var tty bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&tty, m) // ends with EIO once no process holds the terminal open
		close(done)
	}()
	_, err := m.WriteString(ttyInput)
	require.NoError(t, err)
	err = c.Wait()
	// The test keeps the terminal open until the script has ended (the script closes its inherited
	// descriptor and opens /dev/tty when it needs it), so everything it wrote is read.
	require.NoError(t, s.Close())
	<-done
	_ = m.Close()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		require.ErrorAs(t, err, &ee, out.String())
		code = ee.ExitCode()
	}
	return shResult{out: out.String(), code: code}, tty.String()
}

// TestAlicectlRestoreAsksOnTheTerminal (review I-3): without --confirm the wrapper asks for RESTORE
// on the terminal after the deep verification and before Alice is stopped; the container itself is
// always given --confirm RESTORE and never asked.
func TestAlicectlRestoreAsksOnTheTerminal(t *testing.T) {
	t.Parallel()
	const prompt = "Type RESTORE to replace all current data: "
	setup := func(t *testing.T) (*shEnv, string) {
		e := shNewInstalled(t, "1.0.0")
		bk := filepath.Join(e.inst, "backups/x.alicebak")
		shWrite(t, bk, "", 0o600)
		return e, bk
	}
	restoreCall := func(t *testing.T, e *shEnv) shCall {
		t.Helper()
		calls := e.dockerCalls()
		i := shIndex(calls, 0, "alice-admin", "restore")
		require.GreaterOrEqual(t, i, 0, shDump(calls))
		return calls[i]
	}
	t.Run("no terminal and no --confirm", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		r := e.ctl("", "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"))
		assert.Contains(t, r.out, "Without a terminal, pass --confirm RESTORE to confirm the restore.\n")
		assert.Equal(t, 2, r.code, r.out)
		assert.Empty(t, e.dockerCalls())
	})
	t.Run("cancelled before Alice is stopped", func(t *testing.T) {
		t.Parallel()
		for _, answer := range []string{"no\n", "restore\n", "\x04"} {
			e, bk := setup(t)
			r, tty := e.runTTY("", answer, filepath.Join(e.inst, "alicectl"), "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"))
			assert.Equal(t, 1, r.code, r.out)
			assert.Contains(t, r.out, "Restore cancelled. Nothing was changed.\n")
			assert.Contains(t, tty, prompt)
			calls := e.dockerCalls()
			assert.GreaterOrEqual(t, shIndex(calls, 0, "backup", "verify", "/opt/alice/backups/x.alicebak", "--deep"), 0, shDump(calls))
			assert.Equal(t, -1, shIndex(calls, 0, "compose", "stop"), shDump(calls))
			assert.Equal(t, -1, shIndex(calls, 0, "restore"), shDump(calls))
			assert.Equal(t, -1, shIndex(calls, 0, "compose", "up"), shDump(calls))
		}
	})
	t.Run("confirmed on the terminal", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		r, tty := e.runTTY("", "RESTORE\n", filepath.Join(e.inst, "alicectl"), "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"))
		require.Equal(t, 0, r.code, r.out)
		assert.Contains(t, tty, prompt)
		shOrder(t, e.dockerCalls(), []string{"backup", "verify", "--deep"}, []string{"compose", "stop", "alice"},
			[]string{"alice-admin", "restore", "/opt/alice/backups/x.alicebak", "--confirm", "RESTORE", "--passphrase-stdin"},
			[]string{"compose", "up", "alice"}, []string{"selfcheck"})
		rs := restoreCall(t, e)
		require.NotNil(t, rs.stdin)
		assert.Equal(t, shCanary+"\n", *rs.stdin)
	})
	t.Run("passphrase on standard input, confirmation on the terminal", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		r, _ := e.runTTY(shCanary+"\n", "RESTORE\n", filepath.Join(e.inst, "alicectl"), "restore", bk, "--db-only", "--passphrase-stdin")
		require.Equal(t, 0, r.code, r.out)
		rs := restoreCall(t, e)
		assert.True(t, shHas(rs.args, "--db-only", "--confirm", "RESTORE"), rs.line())
		require.NotNil(t, rs.stdin)
		assert.Equal(t, shCanary+"\n", *rs.stdin)
		e.shNoCanary()
	})
	t.Run("the printed recovery command: passphrase and confirmation on the terminal", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		// cd <dir> && sudo ./alicectl restore <backup>: nothing but the terminal.
		r, tty := e.runTTY("", shCanary+"\nRESTORE\n", filepath.Join(e.inst, "alicectl"), "restore", bk)
		require.Equal(t, 0, r.code, r.out)
		assert.Contains(t, tty, prompt)
		calls := e.dockerCalls()
		v := shIndex(calls, 0, "backup", "verify", "--deep", "--passphrase-stdin")
		require.GreaterOrEqual(t, v, 0, shDump(calls))
		require.NotNil(t, calls[v].stdin)
		assert.Equal(t, shCanary+"\n", *calls[v].stdin)
		rs := restoreCall(t, e)
		assert.True(t, shHas(rs.args, "--confirm", "RESTORE"), rs.line())
		require.NotNil(t, rs.stdin)
		assert.Equal(t, shCanary+"\n", *rs.stdin)
		assert.NotContains(t, r.out, shCanary)
		e.shNoCanary()
	})
}

// TestAlicectlRestoreMode covers the branch of an installation prepared with --restore-mode: Alice
// is started only after a successful restore, and only then is the marker removed.
func TestAlicectlRestoreMode(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*shEnv, string) {
		e := shNewInstalled(t, "1.0.0")
		e.vars["STUB_RUNNING"] = "postgres"
		shWrite(t, filepath.Join(e.inst, ".restore-mode"), "", 0o600)
		bk := filepath.Join(e.inst, "backups/x.alicebak")
		shWrite(t, bk, "", 0o600)
		return e, bk
	}
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		r := e.ctl("", "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
		require.Equal(t, 0, r.code, r.out)
		shNoDir(t, filepath.Join(e.inst, ".restore-mode"))
		shOrder(t, e.dockerCalls(), []string{"run", "--rm", "alice-admin", "backup", "verify", "--deep"},
			[]string{"run", "--rm", "alice-admin", "restore", "/opt/alice/backups/x.alicebak", "--confirm", "RESTORE"},
			[]string{"compose", "up", "-d", "--wait", "alice"}, []string{"exec", "alice", "selfcheck"})
	})
	t.Run("failed restore leaves Alice stopped and the marker in place", func(t *testing.T) {
		t.Parallel()
		e, bk := setup(t)
		e.vars["STUB_COMPOSE_FAIL"] = "alice-admin restore"
		r := e.ctl("", "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
		assert.Equal(t, 1, r.code, r.out)
		_, err := os.Stat(filepath.Join(e.inst, ".restore-mode"))
		assert.NoError(t, err, "the marker stays for the next attempt")
		calls := e.dockerCalls()
		rs := shIndex(calls, 0, "alice-admin", "restore")
		require.GreaterOrEqual(t, rs, 0, shDump(calls))
		assert.Equal(t, -1, shIndex(calls, rs+1, "compose", "up"), shDump(calls))
		assert.Equal(t, -1, shIndex(calls, rs+1, "selfcheck"), shDump(calls))
	})
}

// TestUpdateAndRestoreTakeTheLock: while another process holds <dir>/.lock, neither an update nor
// a restore starts.
func TestUpdateAndRestoreTakeTheLock(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2")
	tb := shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key)
	bk := filepath.Join(e.inst, "backups/x.alicebak")
	shWrite(t, bk, "", 0o600)
	f, err := os.OpenFile(filepath.Join(e.inst, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	busy := "Another update or restore of Alice is running in " + e.inst + ". Wait until it has finished, then run this again.\n"
	before := e.snapshot()

	r := e.update(tb)
	assert.Contains(t, r.out, busy)
	assert.Equal(t, 1, r.code, r.out)
	r = e.ctl("", "restore", bk, "--passphrase-file", filepath.Join(e.root, "pass"), "--confirm", "RESTORE")
	assert.Contains(t, r.out, busy)
	assert.Equal(t, 1, r.code, r.out)
	assert.Empty(t, e.dockerCalls(), "nothing ran while the lock was held")
	assert.Equal(t, before, e.snapshot())
	shNoUpdateDirs(t, e.inst)

	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_UN))
	require.NoError(t, f.Close())
	r = e.update(tb)
	assert.Equal(t, 0, r.code, r.out)
}

// TestUpdateKeepsTheReleaseKeysWhenTheSwapFails: the new release-keys/ is written completely and
// renamed into place; when that rename fails the installed keys are still there.
func TestUpdateKeepsTheReleaseKeysWhenTheSwapFails(t *testing.T) {
	t.Parallel()
	e := shNewInstalled(t, "1.0.0-rc.2", "rk-old-01.pem")
	failDir, err := filepath.Abs("testdata/fail-mv")
	require.NoError(t, err)
	e.path = failDir + ":" + e.path
	r := e.update(shTarball(t, e.pkg(shPkgOpts{version: "1.0.0"}), filepath.Join(e.root, "dl"), "1.0.0", e.key))
	assert.Equal(t, 3, r.code, r.out)
	assert.Contains(t, r.out, "Alice 1.0.0 is running, but the update could not install all its files.")
	for _, k := range []string{"rk-old-01.pem", shTestKeyID + ".pem"} {
		_, err := os.Stat(filepath.Join(e.inst, "release-keys", k))
		assert.NoError(t, err, "release key %s", k)
	}
	shNoDir(t, filepath.Join(e.inst, "release-keys.old"))
}
