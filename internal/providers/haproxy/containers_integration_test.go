//go:build integration

package haproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// The real-HAProxy matrix (discovery only): Alice's HAProxy provider end to end against real
// OpenSSH, real sudo, the real alice-helper and the distribution's real HAProxy on Ubuntu 22.04
// (2.4), Debian 12 (2.6) and Rocky 9 (2.8) (test/images/sshd, the images TestRealOpenSSH,
// TestRealNginx and TestRealApache use). Each host is prepared with the exact setup script Alice
// generates for the haproxy profile; when the test binary carries the helper checksums (make
// test-ssh links them in) the script checks the release-built helper against them, as on a
// customer server.
//
// HAProxy is installed but never started: haproxy-dump only runs "haproxy -v" and "haproxy -c",
// and the images' Nginx owns ports 80 and 443. The fixture binds 9443, 9444 and 9445 only.
// Certificates come from a throwaway test CA.
//
//	ALICE_REAL_MATRIX=1 ALICE_SSH_IMAGES=debian12 go test -count=1 -tags integration -run '^TestRealHAProxy' ./internal/providers/haproxy/
//
// Only containers created here through testcontainers are touched. Every helper of this file is
// prefixed with rh (real HAProxy).

// rhMatrixEnv gates the matrix: it runs only through make test-ssh, which sets it.
const rhMatrixEnv = "ALICE_REAL_MATRIX"

var rhDistros = map[string]string{"ubuntu22": "ubuntu", "debian12": "debian", "rocky9": "rocky"} // image -> os-release ID

// rhVersions are the HAProxy branches the images ship.
var rhVersions = map[string]string{"ubuntu22": "2.4", "debian12": "2.6", "rocky9": "2.8"}

// rhDotfilesLoaded (Ruling 18) are the images whose HAProxy loads dotfiles of a crt directory:
// below 2.6 (Ruling 10), so Ubuntu 22.04's 2.4. Debian 12's 2.6 and Rocky 9's 2.8 skip them.
var rhDotfilesLoaded = map[string]bool{"ubuntu22": true, "debian12": false, "rocky9": false}

func rhSelectedDistros(t *testing.T) []string {
	t.Helper()
	sel := os.Getenv("ALICE_SSH_IMAGES")
	if sel == "" {
		sel = "ubuntu22,debian12,rocky9"
	}
	var out []string
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(name)
		if _, ok := rhDistros[name]; !ok {
			t.Fatalf("ALICE_SSH_IMAGES: unknown image %q (known: ubuntu22, debian12, rocky9)", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func rhRepoRoot() string { return filepath.Join("..", "..", "..") }

// rhHelper returns the alice-helper binary to install: the release build of make helper when the
// helper checksums are linked into this test binary (make test-ssh; the setup script then checks
// it), else one built here, which the development script installs without checking.
func rhHelper(t *testing.T) (path string, verified bool) {
	t.Helper()
	if linuxssh.HelperChecksumsKnown() {
		bin := filepath.Join(rhRepoRoot(), "bin", "alice-helper-linux-"+runtime.GOARCH)
		_, err := os.Stat(bin)
		require.NoError(t, err, "the helper checksums are linked in, so make helper must have built %s", bin)
		return bin, true
	}
	t.Log("no helper checksums linked in: the setup script installs a helper built by the test without checking it (make test-ssh checks it)")
	bin := filepath.Join(t.TempDir(), "alice-helper")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/alice-helper")
	cmd.Dir = rhRepoRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build alice-helper: %s", out)
	return bin, false
}

type rhSigner struct{ s ssh.Signer }

func (c rhSigner) SSHSigner(context.Context) (ssh.Signer, func(), error) { return c.s, func() {}, nil }

// rhHost is one running container prepared with the haproxy profile's setup script.
type rhHost struct {
	t        *testing.T
	image    string
	ctr      testcontainers.Container
	ip       string
	target   uuid.UUID
	hk       *memHostKeys
	signer   ssh.Signer
	prov     *Provider
	ca       *pki.CA
	helper   []byte
	verified bool
	// cfg is the fixture configuration the test writes (fixture).
	cfg string
}

func startHAProxyHost(t *testing.T, image, helper string, verified bool) *rhHost {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				// testcontainers builds the image on every run (Docker's layer cache keeps it quick),
				// so a Dockerfile change is always in the image; the tag is only its name.
				Context:    filepath.Join(rhRepoRoot(), "test", "images"),
				Dockerfile: "sshd/" + image + ".Dockerfile",
				Repo:       "alice-test/sshd-" + image,
				Tag:        "phase4",
				KeepImage:  true,
			},
			ExposedPorts: []string{"22/tcp"},
			WaitingFor:   wait.ForListeningPort("22/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)
	ip, err := ctr.ContainerIP(ctx)
	require.NoError(t, err)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	require.NoError(t, err, "the HAProxy matrix reaches the container at %s directly: Docker's bridge network must be routable from this host", ip)
	_ = conn.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	helperBytes, err := os.ReadFile(helper)
	require.NoError(t, err)
	h := &rhHost{t: t, image: image, ctr: ctr, ip: ip, target: uuid.New(), hk: &memHostKeys{}, signer: signer,
		ca: pki.NewCA("Real HAProxy "+image, pki.ECDSA256, time.Now()), helper: helperBytes, verified: verified}
	h.setup("haproxy")
	h.connect()
	return h
}

// setup runs the setup script of profile exactly as Alice shows it. The first run with the
// checksums first refuses a helper that is not this version's (nothing installed).
func (h *rhHost) setup(profile string) {
	t := h.t
	t.Helper()
	ctx := context.Background()
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(h.signer.PublicKey())))
	script, err := linuxssh.SetupScript(profile, linuxssh.AuthorizedKeysLine(pub, ""), !h.verified)
	require.NoError(t, err)
	if code, _ := h.exec("test", "-e", helperproto.HelperPath); code != 0 && h.verified {
		require.NoError(t, h.ctr.CopyToContainer(ctx, append(append([]byte{}, h.helper...), 0), "/root/bad/alice-helper", 0o755))
		require.NoError(t, h.ctr.CopyToContainer(ctx, []byte(script), "/root/bad/setup.sh", 0o700))
		code, out := h.exec("sh", "-c", "cd /root/bad && sh ./setup.sh")
		require.NotZero(t, code, out)
		require.Contains(t, out, "is not the alice-helper of this Alice version")
		code, _ = h.exec("test", "-e", helperproto.HelperPath)
		require.NotZero(t, code, "a helper that fails the checksum is never installed")
	}
	require.NoError(t, h.ctr.CopyToContainer(ctx, []byte(script), "/root/bundle/setup.sh", 0o700))
	require.NoError(t, h.ctr.CopyToContainer(ctx, h.helper, "/root/bundle/alice-helper", 0o755))
	out := h.sh("cd /root/bundle && sh ./setup.sh 2>&1")
	require.Contains(t, out, "This server is ready for Alice.")
	if h.verified {
		require.NotContains(t, out, "cannot verify alice-helper", "the release helper was checked against its checksum")
	}
	sum := sha256.Sum256(h.helper)
	require.Equal(t, hex.EncodeToString(sum[:]), h.fileSHA(helperproto.HelperPath), "the installed helper is the one copied")
	want, err := linuxssh.Sudoers(profile)
	require.NoError(t, err)
	require.Equal(t, want, h.sh("cat /etc/sudoers.d/alice"), "the %s profile's sudoers file, as generated", profile)
}

// connect pins the server's host key as the administrator would and builds the HAProxy provider
// on Alice's SSH provider.
func (h *rhHost) connect() {
	t := h.t
	t.Helper()
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.sh("cat /etc/ssh/ssh_host_ed25519_key.pub")))
	require.NoError(t, err)
	pin := linuxssh.HostKeyOf(hostPub)
	h.hk.pinned = &pin
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: h.hk}, linuxssh.MaxConnections, 4, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	h.prov = New(Options{SSH: linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: !h.verified})})
}

func (h *rhHost) session() providers.Session {
	h.t.Helper()
	ref := providers.TargetRef{ID: h.target, Name: "real-" + h.image, Kind: providers.KindHAProxy,
		Config: providers.TargetConfig{"host": h.ip, "port": 22, "username": linuxssh.ServiceUser}}
	s, err := h.prov.Open(context.Background(), ref, rhSigner{h.signer}, providers.Env{Clock: clock.Real{}, HostKeys: h.hk})
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = s.Close() })
	return s
}

func (h *rhHost) exec(cmd ...string) (int, string) {
	h.t.Helper()
	return h.execAs(nil, cmd...)
}

func (h *rhHost) execAs(opts []tcexec.ProcessOption, cmd ...string) (int, string) {
	h.t.Helper()
	code, r, err := h.ctr.Exec(context.Background(), cmd, append(opts, tcexec.Multiplexed())...)
	require.NoError(h.t, err)
	out, err := io.ReadAll(r)
	require.NoError(h.t, err)
	return code, string(out)
}

// sh runs a shell script as root and requires it to succeed.
func (h *rhHost) sh(script string) string {
	h.t.Helper()
	code, out := h.exec("sh", "-c", script)
	require.Zero(h.t, code, "%s: %s", script, out)
	return out
}

// write puts content at path (directories created), owned by owner (user:group) with mode.
func (h *rhHost) write(path string, content []byte, owner string, mode os.FileMode) {
	h.t.Helper()
	user, group, ok := strings.Cut(owner, ":")
	require.True(h.t, ok, owner)
	stage := "/root/.stage-" + uuid.NewString()
	require.NoError(h.t, h.ctr.CopyToContainer(context.Background(), content, stage, 0o600))
	h.sh("install -D -o " + user + " -g " + group + " -m " + strconv.FormatUint(uint64(mode), 8) + " " + stage + " " + path + " && rm -f " + stage)
}

func (h *rhHost) fileSHA(path string) string {
	h.t.Helper()
	return strings.Fields(h.sh("sha256sum " + path))[0]
}

// readOnly runs fn (Alice's calls) and then requires that nothing under /etc, the helper's state
// directory or HAProxy's chroot was written, created, renamed or chmodded meanwhile (every write
// of a step is the test's own, made before the stamp), and that no HAProxy process runs: "haproxy
// -c" only checks.
func (h *rhHost) readOnly(fn func()) {
	h.t.Helper()
	const stamp = "/root/.alice-stamp"
	h.sh("touch " + stamp)
	fn()
	out := h.sh("find /etc /var/lib/alice-helper /var/lib/haproxy -newer " + stamp + " -o -cnewer " + stamp)
	assert.Empty(h.t, strings.TrimSpace(out), "Alice's discovery changed nothing on the server")
	code, ps := h.exec("pgrep", "-a", "-x", "haproxy")
	assert.NotZero(h.t, code, "HAProxy is never started: %s", ps)
}

func (h *rhHost) testConnection() providers.ConnectionReport {
	h.t.Helper()
	var rep providers.ConnectionReport
	h.readOnly(func() {
		var err error
		rep, err = h.session().TestConnection(context.Background())
		require.NoError(h.t, err)
	})
	return rep
}

// discover runs a certificate discovery (no SSH keys) and indexes the locations by certificate path.
func (h *rhHost) discover() (providers.DiscoveryResult, map[string]providers.DiscoveredCertificate) {
	h.t.Helper()
	var res providers.DiscoveryResult
	h.readOnly(func() {
		var err error
		res, err = h.session().Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(h.t, err)
	})
	return res, locationsByPath(res)
}

// discoverFails runs a certificate discovery that must fail with reason.
func (h *rhHost) discoverFails(reason string) {
	h.t.Helper()
	h.readOnly(func() {
		res, err := h.session().Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		assert.Equal(h.t, reason, providerErr(h.t, err).Code)
		assert.Equal(h.t, providers.DiscoveryResult{}, res, "no partial data")
	})
}

func TestRealHAProxy(t *testing.T) {
	if os.Getenv(rhMatrixEnv) != "1" {
		t.Skip("the real-HAProxy matrix runs only through make test-ssh (it sets " + rhMatrixEnv + "=1)")
	}
	images := rhSelectedDistros(t)
	helper, verified := rhHelper(t)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			h := startHAProxyHost(t, image, helper, verified)
			// Each subtest leaves the host as the next one expects it; a failed one stops the rest of
			// this distribution.
			run := func(name string, fn func(t *testing.T)) {
				if !t.Run(name, func(t *testing.T) { h.t = t; fn(t) }) {
					h.t = t
					t.FailNow()
				}
				h.t = t
			}
			run("sudo", h.testSudo)
			run("untouched_default_configuration", h.testDefaultConfiguration)
			run("fixture", h.writeFixture)
			run("discovery", h.testDiscovery)
			run("missing_certificate_file", h.testMissingCertificate)
			run("config_file_writable", h.testWritableConfig)
			run("config_dir_not_read", h.testConfDir)
			run("profile_missing", h.testProfileMissing)
			run("not_found", h.testNotFound)
			run("untrusted_program", h.testUntrustedProgram)
		})
	}
}

// testSudo: the haproxy profile's built line passes the real sudo and reaches the helper; anything
// else is refused by sudo, apache-dump and nginx-dump included (not in this profile).
func (h *rhHost) testSudo(t *testing.T) {
	asSvc := []tcexec.ProcessOption{tcexec.WithUser(linuxssh.ServiceUser)}
	sudoRefused := regexp.MustCompile(`a password is required|is not allowed to (run|execute)`)
	code, out := h.exec("visudo", "-c")
	require.Zero(t, code, out)
	assert.Contains(t, out, "/etc/sudoers.d/alice: parsed OK")
	_, out = h.execAs(asSvc, "sh", "-c", linuxssh.CmdHAProxyDump().Line()+" </dev/null")
	assert.NotRegexp(t, sudoRefused, out, "sudo lets the built haproxy-dump line through")
	assert.Contains(t, out, `"ok":true`, "the helper ran and answered")
	for _, args := range [][]string{{"haproxy-dump", "extra"}, {"apache-dump"}, {"nginx-dump"}} {
		code, out := h.execAs(asSvc, append([]string{"sudo", "-n", helperproto.HelperPath}, args...)...)
		assert.NotZero(t, code, args)
		assert.Regexp(t, sudoRefused, out, "%q: refused by sudo", args)
		assert.NotContains(t, out, `"ok":`, "%q: the helper never ran", args)
	}
}

// testDefaultConfiguration: the distribution's haproxy.cfg as installed. The connection test finds
// HAProxy of the image's branch with a valid configuration; discovery lists no location and no
// warning (Debian and Ubuntu have no frontend; Rocky's frontend main binds *:5000 without ssl, and
// its conf.d exists but is empty).
func (h *rhHost) testDefaultConfiguration(t *testing.T) {
	_, v := h.exec("sh", "-c", "/usr/sbin/haproxy -v 2>&1 | head -n 1")
	t.Logf("%s: %s", h.image, strings.TrimSpace(v))
	if h.image == "rocky9" {
		cfg := h.sh("cat " + rhConf)
		assert.Regexp(t, `(?m)^frontend main\n\s+bind \*:5000\n`, cfg, "Rocky's default frontend binds *:5000 without ssl")
		assert.Equal(t, "directory 0 0", strings.TrimSpace(h.sh("stat -c '%F %u %g' /etc/haproxy/conf.d")), "Rocky's conf.d exists")
		assert.Empty(t, strings.TrimSpace(h.sh("ls -A /etc/haproxy/conf.d")), "and is empty")
	}
	rep := h.testConnection()
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
	assert.Equal(t, rhDistros[h.image], rep.OS.ID)
	require.NotNil(t, rep.WebServer)
	assert.Equal(t, "haproxy", rep.WebServer.Software)
	assert.True(t, rep.WebServer.Found)
	assert.Regexp(t, `^2\.(4|6|8)\.\d+`, rep.WebServer.Version)
	assert.True(t, strings.HasPrefix(rep.WebServer.Version, rhVersions[h.image]+"."), "%s ships HAProxy %s: %s", h.image, rhVersions[h.image], rep.WebServer.Version)
	assert.Equal(t, rhConf, rep.WebServer.ConfPath)
	assert.True(t, rep.WebServer.ConfigValid, "%+v", *rep.WebServer)
	assert.Empty(t, rep.Warnings)

	res, _ := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	assert.Empty(t, res.Certificates)
	assert.Empty(t, res.Warnings)
}

const (
	rhConf    = "/etc/haproxy/haproxy.cfg"
	rhCerts   = "/etc/haproxy/certs"
	rhCrtList = "/etc/haproxy/alice.crtlist"
	rhA       = rhCerts + "/a.pem"
	rhB       = rhCerts + "/b.pem"
	rhC       = rhCerts + "/c.pem"
	rhDir     = rhCerts + "/dir"
	rhD       = rhDir + "/d.pem"
	rhE       = rhDir + "/e.crt"
	rhOld     = rhDir + "/.old.pem"
	rhConfDir = "/etc/haproxy/conf.d"
	rhExtra   = rhConfDir + "/extra.cfg"
)

// The fixture's binds, each found once in the configuration (rhLine).
const (
	rhBindHTTPS = "    bind *:9443 ssl crt a.pem crt /etc/haproxy/certs/b.pem\n"
	rhBindNone  = "    bind *:9443 ssl crt /nonexistent.pem\n"
	rhBindNope  = "    bind *:9443 ssl crt /etc/haproxy/certs/a.pem\n"
	rhBindSNI   = "    bind 127.0.0.1:9444 ssl crt-list /etc/haproxy/alice.crtlist\n"
	rhBindDir   = "    bind :9445 ssl crt /etc/haproxy/certs/dir\n"
)

// rhFrontends are the test's sections, appended to the distribution's global and defaults.
const rhFrontends = `
frontend fe_https
` + rhBindHTTPS + `.if 0
` + rhBindNone + `.endif
.if defined(ALICE_NOPE)
` + rhBindNope + `.endif

listen li_sni
` + rhBindSNI + `
frontend fe_dir
` + rhBindDir

// writeFixture writes the test's certificates (keys root:root 0600, b's companion key 0644), the
// crt-list and the configuration: the distribution's global and defaults, with crt-base
// /etc/haproxy/certs in that global, and the test's sections. HAProxy refuses a second crt-base
// ("'crt-base' already specified", 2.4 and 2.6), so Debian's and Ubuntu's crt-base
// /etc/ssl/private is replaced, not overridden.
func (h *rhHost) writeFixture(t *testing.T) {
	leaf := func(cn string) pki.Leaf {
		return h.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}, KeyType: pki.ECDSA256}, time.Now())
	}
	combined := func(l pki.Leaf) []byte { return append(append([]byte{}, l.FullchainPEM...), l.KeyPEM...) }
	h.sh("install -d -m 0755 -o root -g root " + rhCerts + " " + rhDir)
	a, b, c, d, e, old := leaf("a.example.test"), leaf("b.example.test"), leaf("c.example.test"),
		leaf("d.example.test"), leaf("e.example.test"), leaf("old.example.test")
	h.write(rhA, combined(a), "root:root", 0o600)
	h.write(rhB, b.FullchainPEM, "root:root", 0o644)
	h.write(rhB+".key", b.KeyPEM, "root:root", 0o644)
	h.write(rhC, combined(c), "root:root", 0o600)
	h.write(rhD, combined(d), "root:root", 0o600)
	h.write(rhE, e.FullchainPEM, "root:root", 0o644)
	h.write(rhE+".key", e.KeyPEM, "root:root", 0o600)
	h.write(rhOld, combined(old), "root:root", 0o600)
	h.write(rhCrtList, []byte("c.pem [alpn h2] c.example.test *.c.example.test\n"), "root:root", 0o644)

	// The distribution's global and defaults: everything before its first proxy section.
	var base strings.Builder
	for _, l := range strings.SplitAfter(h.sh("cat "+rhConf), "\n") {
		if regexp.MustCompile(`^(frontend|backend|listen)[ \t]`).MatchString(l) {
			break
		}
		if regexp.MustCompile(`^[ \t]*crt-base[ \t]`).MatchString(l) {
			continue
		}
		base.WriteString(l)
		if strings.TrimRight(l, "\n") == "global" {
			base.WriteString("    crt-base " + rhCerts + "\n")
		}
	}
	require.Equal(t, 1, strings.Count(base.String(), "crt-base"), "one crt-base, in the distribution's global")
	h.cfg = base.String() + rhFrontends
	h.write(rhConf, []byte(h.cfg), "root:root", 0o644)
	// The distribution's own check accepts it (exit 0: it has listeners).
	h.sh("/usr/sbin/haproxy -c -f " + rhConf + " 2>&1")
	// The dotfile verdict of rhDotfilesLoaded is HAProxy's own: a broken dotfile fails its check
	// exactly where it is loaded.
	h.write(rhOld, []byte("not a certificate\n"), "root:root", 0o600)
	code, out := h.exec("/usr/sbin/haproxy", "-c", "-f", rhConf)
	assert.Equal(t, rhDotfilesLoaded[h.image], code != 0, "HAProxy %s loads crt directory dotfiles: %s", rhVersions[h.image], out)
	h.write(rhOld, combined(old), "root:root", 0o600)
	h.sh("/usr/sbin/haproxy -c -f " + rhConf + " 2>&1")
}

// rhLine is the line number of the configuration's bind (found once).
func (h *rhHost) rhLine(bind string) int {
	h.t.Helper()
	require.Equal(h.t, 1, strings.Count(h.cfg, bind), bind)
	i := strings.Index(h.cfg, bind)
	return strings.Count(h.cfg[:i], "\n") + 1
}

func (h *rhHost) wantPaths() []string {
	want := []string{rhA, rhB, rhC, rhD, rhE}
	if rhDotfilesLoaded[h.image] {
		want = append(want, rhOld)
	}
	sort.Strings(want)
	return want
}

func pathsOf(locs map[string]providers.DiscoveredCertificate) []string {
	out := make([]string, 0, len(locs))
	for p := range locs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// testDiscovery: exactly the fixture's certificate files (and the dotfile where HAProxy loads it),
// each with its frontend or listen, its SNI filters and its listens, and the file's SHA-256 as
// sha256sum computes it on the host. Nothing of the ".if 0" bind is listed. The ".if
// defined(ALICE_NOPE)" bind names a.pem, the file fe_https's "crt a.pem" loads: a location is
// keyed by its certificate path and is unsupported when any of its pairs is (the shared
// web-server rule: a deployment to it would reach the uncertain bind too), so a.pem is the one
// conditional location, with both binds; every other location is supported.
func (h *rhHost) testDiscovery(t *testing.T) {
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	assert.Empty(t, res.Warnings)
	require.Equal(t, h.wantPaths(), pathsOf(locs))
	assert.NotContains(t, locs, "/nonexistent.pem", "the .if 0 bind is not read")

	https := providers.CertServer{Names: []string{}, Listens: []providers.CertListen{{Port: 9443}}, File: rhConf,
		Line: h.rhLine(rhBindHTTPS), Section: "fe_https"}
	sni := providers.CertServer{Names: []string{"c.example.test", "*.c.example.test"},
		Listens: []providers.CertListen{{Addr: "127.0.0.1", Port: 9444}}, File: rhConf, Line: h.rhLine(rhBindSNI), Section: "li_sni"}
	dir := providers.CertServer{Names: []string{}, Listens: []providers.CertListen{{Port: 9445}}, File: rhConf,
		Line: h.rhLine(rhBindDir), Section: "fe_dir"}
	want := map[string][]providers.CertServer{rhA: {https}, rhB: {https}, rhC: {sni}, rhD: {dir}, rhE: {dir}, rhOld: {dir}}
	keys := map[string]string{rhA: rhA, rhB: rhB + ".key", rhC: rhC, rhD: rhD, rhE: rhE + ".key", rhOld: rhOld}
	sections := map[string]bool{}
	var conditional []string
	for path, c := range locs {
		l := c.Location
		if l.Unsupported == providers.UnsupportedConditional {
			conditional = append(conditional, path)
		} else {
			assert.True(t, l.Supported, "%s: %s", path, l.Unsupported)
		}
		assert.Empty(t, l.Problem, path)
		assert.Empty(t, l.KeyProblem, path)
		assert.True(t, l.KeyExists, path)
		assert.False(t, l.CustomLocation, path)
		assert.Equal(t, keys[path], l.KeyPath, path)
		assert.Equal(t, h.fileSHA(path), c.FileSHA256, "%s: the file's SHA-256", path)
		assert.NotEmpty(t, c.PEMChain, path)
		if path != rhA {
			assert.Equal(t, want[path], l.Servers, path)
		}
		for _, s := range l.Servers {
			sections[s.Section] = true
		}
	}
	assert.Equal(t, map[string]bool{"fe_https": true, "li_sni": true, "fe_dir": true}, sections)
	assert.Equal(t, []string{rhA}, conditional, "one conditional location: the .if defined(ALICE_NOPE) bind's")

	a := locs[rhA].Location
	assert.Equal(t, a.CertPath, a.KeyPath, "a's key is in its certificate file")
	assert.Equal(t, "0600", a.KeyMode)
	b := locs[rhB].Location
	assert.Equal(t, rhB+".key", b.KeyPath, "b's key is its companion file")
	assert.Equal(t, "0644", b.KeyMode)
	assert.Contains(t, b.Warnings, providers.WarnKeyModeOpen)
	assert.NotContains(t, a.Warnings, providers.WarnKeyModeOpen)

	assert.False(t, a.Supported)
	assert.Equal(t, providers.UnsupportedConditional, a.Unsupported)
	nope := providers.CertServer{Names: []string{}, Listens: []providers.CertListen{{Port: 9443}}, File: rhConf,
		Line: h.rhLine(rhBindNope), Section: "fe_https"}
	assert.Equal(t, []providers.CertServer{https, nope}, a.Servers, "fe_https's bind, then the conditional one")
}

// testMissingCertificate (Ruling 3): "haproxy -c" loads every certificate, so a crt-list entry
// whose file is gone makes the configuration invalid, class syntax, with the warning and no
// certificate (unlike Apache, where the location's certificate is missing). c.pem is put back.
func (h *rhHost) testMissingCertificate(t *testing.T) {
	h.sh("mv " + rhC + " /root/c.pem.away")
	defer h.sh("test -e " + rhC + " || mv /root/c.pem.away " + rhC)
	code, _ := h.exec("/usr/sbin/haproxy", "-c", "-f", rhConf)
	require.NotZero(t, code, "HAProxy's own check refuses it")
	res, _ := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.Found)
	assert.False(t, res.WebServer.ConfigValid)
	assert.Equal(t, providers.ConfigErrSyntax, res.WebServer.ConfigError)
	assert.Contains(t, warningCodes(res.Warnings), providers.WarnWebServerConfigInvalid)
	assert.Empty(t, res.Certificates)
	rep := h.testConnection()
	require.NotNil(t, rep.WebServer)
	assert.False(t, rep.WebServer.ConfigValid)
	assert.Equal(t, providers.ConfigErrSyntax, rep.WebServer.ConfigError)
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerConfigInvalid)
	h.sh("mv /root/c.pem.away " + rhC)
	_, locs := h.discover()
	h.baseline(locs)
}

// testWritableConfig (Ruling 4): a crt-list other users can change makes every pair
// config_file_writable (the conditional one too), with the warning naming it. Mode 0644 is put
// back.
func (h *rhHost) testWritableConfig(t *testing.T) {
	h.sh("chmod 0666 " + rhCrtList)
	defer h.sh("chmod 0644 " + rhCrtList)
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	// The writable list's entry is not looked at (not joined to crt-base, never opened): its
	// location is the line's text, c.pem, still with the list's SNI filters.
	want := []string{"c.pem"}
	for _, p := range h.wantPaths() {
		if p != rhC {
			want = append(want, p)
		}
	}
	sort.Strings(want)
	require.Equal(t, want, pathsOf(locs))
	require.Len(t, locs["c.pem"].Location.Servers, 1)
	assert.Equal(t, []string{"c.example.test", "*.c.example.test"}, locs["c.pem"].Location.Servers[0].Names)
	assert.Equal(t, "li_sni", locs["c.pem"].Location.Servers[0].Section)
	for path, c := range locs {
		assert.False(t, c.Location.Supported, path)
		assert.Equal(t, providers.UnsupportedConfigFileWritable, c.Location.Unsupported, path)
	}
	assert.Contains(t, res.Warnings, providers.Warning{Code: providers.WarnConfigFileWritable, Params: map[string]string{"path": rhCrtList}})
	h.sh("chmod 0644 " + rhCrtList)
	_, locs = h.discover()
	h.baseline(locs)
}

// baseline: the fixture's discovery as testDiscovery pins it: its paths, a.pem conditional and
// every other location supported.
func (h *rhHost) baseline(locs map[string]providers.DiscoveredCertificate) {
	h.t.Helper()
	require.Equal(h.t, h.wantPaths(), pathsOf(locs))
	for path, c := range locs {
		if path == rhA {
			assert.Equal(h.t, providers.UnsupportedConditional, c.Location.Unsupported, path)
		} else {
			assert.True(h.t, c.Location.Supported, "%s: %s", path, c.Location.Unsupported)
		}
	}
}

// testConfDir (Ruling 2, C14): a *.cfg in /etc/haproxy/conf.d (which Rocky's unit loads and Alice
// does not read) gives the warning config_dir_not_read; the locations stay. The file is removed
// again (and conf.d too where the test created it).
func (h *rhHost) testConfDir(t *testing.T) {
	code, _ := h.exec("test", "-d", rhConfDir)
	existed := code == 0
	assert.Equal(t, h.image == "rocky9", existed, "only Rocky's package ships conf.d")
	restore := "rm -f " + rhExtra
	if !existed {
		restore += " && rmdir " + rhConfDir
	}
	h.write(rhExtra, []byte("# Alice's real-HAProxy test\n"), "root:root", 0o644)
	defer h.sh("! test -e " + rhExtra + " || { " + restore + "; }")
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	assert.Equal(t, []string{providers.WarnConfigDirNotRead}, warningCodes(res.Warnings))
	h.baseline(locs)
	h.sh(restore)
	res, _ = h.discover()
	assert.Empty(t, res.Warnings)
}

// testProfileMissing: with the linux profile installed sudo refuses haproxy-dump:
// haproxy.profile_missing. The haproxy profile is then installed again.
func (h *rhHost) testProfileMissing(t *testing.T) {
	h.setup("linux")
	h.discoverFails("haproxy.profile_missing")
	h.setup("haproxy")
	_, locs := h.discover()
	h.baseline(locs)
}

// testNotFound: without /usr/sbin/haproxy discovery fails with haproxy.not_found and the
// connection test warns. It is then put back.
func (h *rhHost) testNotFound(t *testing.T) {
	h.sh("mv /usr/sbin/haproxy /root/haproxy.away")
	defer h.sh("test -e /usr/sbin/haproxy || mv /root/haproxy.away /usr/sbin/haproxy")
	h.discoverFails("haproxy.not_found")
	rep := h.testConnection()
	require.NotNil(t, rep.WebServer)
	assert.False(t, rep.WebServer.Found)
	assert.Equal(t, []string{providers.WarnWebServerNotFound}, warningCodes(rep.Warnings))
	h.sh("mv /root/haproxy.away /usr/sbin/haproxy")
	_, locs := h.discover()
	h.baseline(locs)
}

// testUntrustedProgram (Ruling 15): a /usr/sbin/haproxy that is group-writable, or owned by a
// user other than root, is never run as root: discovery and the connection test report the
// configuration untrusted, not_root_controlled, naming the program. Mode and owner are put back.
func (h *rhHost) testUntrustedProgram(t *testing.T) {
	const prog = "/usr/sbin/haproxy"
	require.Equal(t, "0:0 755", strings.TrimSpace(h.sh("stat -c '%u:%g %a' "+prog)))
	defer h.sh("chown 0:0 " + prog + " && chmod 0755 " + prog)
	for _, c := range []struct{ name, change string }{
		{"group_writable", "chmod g+w " + prog},
		{"not_root_owned", "chown 65534 " + prog},
	} {
		ok := t.Run(c.name, func(t *testing.T) {
			parent := h.t
			h.t = t
			defer func() { h.t = parent }()
			h.sh(c.change)
			defer h.sh("chown 0:0 " + prog + " && chmod 0755 " + prog)
			res, locs := h.discover()
			require.NotNil(t, res.WebServer)
			assert.True(t, res.WebServer.Found)
			assert.False(t, res.WebServer.ConfigValid)
			assert.Equal(t, providers.ConfigErrUntrusted, res.WebServer.ConfigError)
			assert.Equal(t, providers.ConfigReasonNotRootControlled, res.WebServer.ConfigErrorReason)
			assert.Equal(t, prog, res.WebServer.ConfigErrorFile)
			assert.Empty(t, locs)
			assert.Contains(t, warningCodes(res.Warnings), providers.WarnWebServerConfigInvalid)
			rep := h.testConnection()
			require.NotNil(t, rep.WebServer)
			assert.False(t, rep.WebServer.ConfigValid)
			assert.Equal(t, providers.ConfigErrUntrusted, rep.WebServer.ConfigError)
		})
		require.True(t, ok, c.name)
	}
	require.Equal(t, "0:0 755", strings.TrimSpace(h.sh("stat -c '%u:%g %a' "+prog)))
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	h.baseline(locs)
}
