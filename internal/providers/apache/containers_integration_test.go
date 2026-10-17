//go:build integration

package apache

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

// The real-Apache matrix (discovery only): Alice's Apache provider end to end against real
// OpenSSH, real sudo, the real alice-helper and the distribution's real Apache httpd on Ubuntu
// 22.04, Debian 12 and Rocky 9 (test/images/sshd, the images TestRealOpenSSH and TestRealNginx use).
// Each host is prepared with the exact setup script Alice generates for the apache profile; when
// the test binary carries the helper checksums (make test-ssh links them in) the script checks the
// release-built helper against them, as on a customer server.
//
// Apache is installed but never started: discovery only reads the configuration (apache-dump runs
// the control program's -D DUMP_* -t), and the images' Nginx owns ports 80 and 443. Debian and
// Ubuntu run /usr/sbin/apache2ctl, Rocky /usr/sbin/httpd itself (its apachectl refuses arguments).
// mod_ssl is enabled by the test on Debian and Ubuntu (a2enmod ssl); on Rocky ssl.conf's localhost
// pair is written by the test (the package leaves it to the service's first start). Certificates
// come from a throwaway test CA.
//
//	ALICE_REAL_MATRIX=1 ALICE_SSH_IMAGES=debian12 go test -count=1 -tags integration -run '^TestRealApache' ./internal/providers/apache/
//
// Only containers created here through testcontainers are touched. Every helper of this file is
// prefixed with ra (real Apache).

// raMatrixEnv gates the matrix: it runs only through make test-ssh, which sets it.
const raMatrixEnv = "ALICE_REAL_MATRIX"

var raDistros = map[string]string{"ubuntu22": "ubuntu", "debian12": "debian", "rocky9": "rocky"} // image -> os-release ID

func raSelectedDistros(t *testing.T) []string {
	t.Helper()
	sel := os.Getenv("ALICE_SSH_IMAGES")
	if sel == "" {
		sel = "ubuntu22,debian12,rocky9"
	}
	var out []string
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(name)
		if _, ok := raDistros[name]; !ok {
			t.Fatalf("ALICE_SSH_IMAGES: unknown image %q (known: ubuntu22, debian12, rocky9)", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func raRepoRoot() string { return filepath.Join("..", "..", "..") }

// raHelper returns the alice-helper binary to install: the release build of make helper when the
// helper checksums are linked into this test binary (make test-ssh; the setup script then checks
// it), else one built here, which the development script installs without checking.
func raHelper(t *testing.T) (path string, verified bool) {
	t.Helper()
	if linuxssh.HelperChecksumsKnown() {
		bin := filepath.Join(raRepoRoot(), "bin", "alice-helper-linux-"+runtime.GOARCH)
		_, err := os.Stat(bin)
		require.NoError(t, err, "the helper checksums are linked in, so make helper must have built %s", bin)
		return bin, true
	}
	t.Log("no helper checksums linked in: the setup script installs a helper built by the test without checking it (make test-ssh checks it)")
	bin := filepath.Join(t.TempDir(), "alice-helper")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/alice-helper")
	cmd.Dir = raRepoRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build alice-helper: %s", out)
	return bin, false
}

type raSigner struct{ s ssh.Signer }

func (c raSigner) SSHSigner(context.Context) (ssh.Signer, func(), error) { return c.s, func() {}, nil }

// raHost is one running container prepared with the apache profile's setup script.
type raHost struct {
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
	// ctl is the control program apache-dump runs, conf the configuration file the test adds and
	// rootConf the configuration's root.
	ctl, conf, rootConf string
}

func (h *raHost) debian() bool { return h.image != "rocky9" }

func startApacheHost(t *testing.T, image, helper string, verified bool) *raHost {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				// testcontainers builds the image on every run (Docker's layer cache keeps it quick),
				// so a Dockerfile change is always in the image; the tag is only its name.
				Context:    filepath.Join(raRepoRoot(), "test", "images"),
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
	require.NoError(t, err, "the Apache matrix reaches the container at %s directly: Docker's bridge network must be routable from this host", ip)
	_ = conn.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	helperBytes, err := os.ReadFile(helper)
	require.NoError(t, err)
	h := &raHost{t: t, image: image, ctr: ctr, ip: ip, target: uuid.New(), hk: &memHostKeys{}, signer: signer,
		ca: pki.NewCA("Real Apache "+image, pki.ECDSA256, time.Now()), helper: helperBytes, verified: verified}
	if h.debian() {
		h.ctl, h.conf, h.rootConf = "/usr/sbin/apache2ctl", "/etc/apache2/sites-enabled/alice.conf", "/etc/apache2/apache2.conf"
	} else {
		h.ctl, h.conf, h.rootConf = "/usr/sbin/httpd", "/etc/httpd/conf.d/alice.conf", "/etc/httpd/conf/httpd.conf"
	}
	h.setup("apache")
	h.connect()
	return h
}

// setup runs the setup script of profile exactly as Alice shows it. The first run with the
// checksums first refuses a helper that is not this version's (nothing installed).
func (h *raHost) setup(profile string) {
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

// connect pins the server's host key as the administrator would and builds the Apache provider on
// Alice's SSH provider.
func (h *raHost) connect() {
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

func (h *raHost) session() providers.Session {
	h.t.Helper()
	ref := providers.TargetRef{ID: h.target, Name: "real-" + h.image, Kind: providers.KindApache,
		Config: providers.TargetConfig{"host": h.ip, "port": 22, "username": linuxssh.ServiceUser}}
	s, err := h.prov.Open(context.Background(), ref, raSigner{h.signer}, providers.Env{Clock: clock.Real{}, HostKeys: h.hk})
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = s.Close() })
	return s
}

func (h *raHost) exec(cmd ...string) (int, string) {
	h.t.Helper()
	return h.execAs(nil, cmd...)
}

func (h *raHost) execAs(opts []tcexec.ProcessOption, cmd ...string) (int, string) {
	h.t.Helper()
	code, r, err := h.ctr.Exec(context.Background(), cmd, append(opts, tcexec.Multiplexed())...)
	require.NoError(h.t, err)
	out, err := io.ReadAll(r)
	require.NoError(h.t, err)
	return code, string(out)
}

// sh runs a shell script as root and requires it to succeed.
func (h *raHost) sh(script string) string {
	h.t.Helper()
	code, out := h.exec("sh", "-c", script)
	require.Zero(h.t, code, "%s: %s", script, out)
	return out
}

// write puts content at path (directories created), owned by owner (user:group) with mode.
func (h *raHost) write(path string, content []byte, owner string, mode os.FileMode) {
	h.t.Helper()
	user, group, ok := strings.Cut(owner, ":")
	require.True(h.t, ok, owner)
	stage := "/root/.stage-" + uuid.NewString()
	require.NoError(h.t, h.ctr.CopyToContainer(context.Background(), content, stage, 0o600))
	h.sh("install -D -o " + user + " -g " + group + " -m " + strconv.FormatUint(uint64(mode), 8) + " " + stage + " " + path + " && rm -f " + stage)
}

func (h *raHost) fileSHA(path string) string {
	h.t.Helper()
	return strings.Fields(h.sh("sha256sum " + path))[0]
}

// readOnly runs fn (Alice's calls) and then requires that nothing under /etc or the helper's state
// directory was written, created, renamed or chmodded meanwhile: every write of the step is the
// test's own, made before the stamp. Apache's runtime and lock directories under /run and /var
// (which apache2ctl may create, as on every start) are deliberately out of scope.
func (h *raHost) readOnly(fn func()) {
	h.t.Helper()
	const stamp = "/root/.alice-stamp"
	h.sh("touch " + stamp)
	fn()
	out := h.sh("find /etc /var/lib/alice-helper -newer " + stamp + " -o -cnewer " + stamp)
	assert.Empty(h.t, strings.TrimSpace(out), "Alice's discovery changed nothing on the server")
}

func (h *raHost) testConnection() providers.ConnectionReport {
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
func (h *raHost) discover() (providers.DiscoveryResult, map[string]providers.DiscoveredCertificate) {
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
func (h *raHost) discoverFails(reason string) {
	h.t.Helper()
	h.readOnly(func() {
		res, err := h.session().Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		assert.Equal(h.t, reason, providerErr(h.t, err).Code)
		assert.Equal(h.t, providers.DiscoveryResult{}, res, "no partial data")
	})
}

func TestRealApache(t *testing.T) {
	if os.Getenv(raMatrixEnv) != "1" {
		t.Skip("the real-Apache matrix runs only through make test-ssh (it sets " + raMatrixEnv + "=1)")
	}
	images := raSelectedDistros(t)
	helper, verified := raHelper(t)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			h := startApacheHost(t, image, helper, verified)
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
			run("untouched_default_layout", h.testUntouchedLayout)
			run("fixture", h.writeFixture)
			run("discovery", h.testDiscovery)
			run("invalid_configuration", h.testInvalidConfiguration)
			run("missing_certificate_file", h.testMissingCertificate)
			run("config_file_writable", h.testWritableConfig)
			run("untrusted_control_program", h.testUntrustedProgram)
			run("profile_missing", h.testProfileMissing)
			run("not_found", h.testNotFound)
		})
	}
}

// testSudo: the apache profile's built line passes the real sudo and reaches the helper; anything
// else is refused by sudo, nginx-dump included (not in this profile).
func (h *raHost) testSudo(t *testing.T) {
	asSvc := []tcexec.ProcessOption{tcexec.WithUser(linuxssh.ServiceUser)}
	sudoRefused := regexp.MustCompile(`a password is required|is not allowed to (run|execute)`)
	code, out := h.exec("visudo", "-c")
	require.Zero(t, code, out)
	assert.Contains(t, out, "/etc/sudoers.d/alice: parsed OK")
	_, out = h.execAs(asSvc, "sh", "-c", linuxssh.CmdApacheDump().Line()+" </dev/null")
	assert.NotRegexp(t, sudoRefused, out, "sudo lets the built apache-dump line through")
	assert.Contains(t, out, `"ok":true`, "the helper ran and answered")
	for _, args := range [][]string{{"apache-dump", "extra"}, {"nginx-dump"}, {"nginx-test"}} {
		code, out := h.execAs(asSvc, append([]string{"sudo", "-n", helperproto.HelperPath}, args...)...)
		assert.NotZero(t, code, args)
		assert.Regexp(t, sudoRefused, out, "%q: refused by sudo", args)
		assert.NotContains(t, out, `"ok":`, "%q: the helper never ran", args)
	}
}

// testUntouchedLayout: the distribution's configuration as installed. The connection test finds
// Apache with a valid configuration; Debian and Ubuntu (mod_ssl not enabled) have no location and
// no warning; Rocky's mod_ssl brings ssl.conf, whose localhost certificate does not exist before
// the service's first start: one location whose certificate file is missing.
func (h *raHost) testUntouchedLayout(t *testing.T) {
	_, v := h.exec("sh", "-c", h.ctl+" -v 2>&1")
	t.Logf("%s: %s", h.image, strings.TrimSpace(v))
	rep := h.testConnection()
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
	assert.Equal(t, raDistros[h.image], rep.OS.ID)
	require.NotNil(t, rep.WebServer)
	assert.Equal(t, "apache", rep.WebServer.Software)
	assert.True(t, rep.WebServer.Found)
	assert.Regexp(t, `^2\.4\.\d+$`, rep.WebServer.Version)
	assert.Equal(t, h.rootConf, rep.WebServer.ConfPath)
	assert.True(t, rep.WebServer.ConfigValid, "%+v", *rep.WebServer)
	assert.Empty(t, rep.Warnings)

	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	assert.Empty(t, res.Warnings)
	if h.debian() {
		assert.Empty(t, res.Certificates, "mod_ssl is not enabled: no TLS virtual host")
		return
	}
	require.Len(t, res.Certificates, 1)
	lh, ok := locs[raLocalhostCert]
	require.True(t, ok, "ssl.conf's _default_:443 pair is listed")
	assert.Equal(t, providers.CertProblemMissing, lh.Location.Problem)
	assert.Equal(t, raLocalhostKey, lh.Location.KeyPath)
}

const (
	raDir           = "/etc/ssl/alice"
	raARSA          = raDir + "/a-rsa.crt"
	raAEC           = raDir + "/a-ec.crt"
	raB             = raDir + "/b.pem"
	raLocalhostCert = "/etc/pki/tls/certs/localhost.crt"
	raLocalhostKey  = "/etc/pki/tls/private/localhost.key"
)

// raSites is the test's configuration file. Line 3 is a's <VirtualHost, line 12 b's.
const raSites = `Define CERTDIR ` + raDir + `
<IfDefine !NOPE>
<VirtualHost *:443>
    ServerName https://a.example.test:443
    ServerAlias www.a.example.test
    SSLEngine on
    SSLCertificateFile ${CERTDIR}/a-rsa.crt
    SSLCertificateKeyFile ${CERTDIR}/a-rsa.key
    SSLCertificateFile "${CERTDIR}/a-ec.crt"
    SSLCertificateKeyFile ${CERTDIR}/a-ec.key
</VirtualHost>
<VirtualHost *:443>
    ServerName b.example.test
    SSLEngine on
    SSLCertificateFile ${CERTDIR}/b.pem
</VirtualHost>
</IfDefine>
`

// writeFixture writes the test's pairs (keys root:root 0600) and configuration file, and enables
// mod_ssl (Debian, Ubuntu) or writes ssl.conf's localhost pair (Rocky).
func (h *raHost) writeFixture(t *testing.T) {
	leaf := func(cn string, kt pki.KeyType) pki.Leaf {
		return h.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}, KeyType: kt}, time.Now())
	}
	h.sh("install -d -m 0755 -o root -g root " + raDir)
	rsa, ec, b := leaf("a.example.test", pki.RSA2048), leaf("a.example.test", pki.ECDSA256), leaf("b.example.test", pki.ECDSA256)
	h.write(raARSA, rsa.FullchainPEM, "root:root", 0o644)
	h.write(raDir+"/a-rsa.key", rsa.KeyPEM, "root:root", 0o600)
	h.write(raAEC, ec.FullchainPEM, "root:root", 0o644)
	h.write(raDir+"/a-ec.key", ec.KeyPEM, "root:root", 0o600)
	h.write(raB, append(append([]byte{}, b.FullchainPEM...), b.KeyPEM...), "root:root", 0o600)
	if h.debian() {
		h.sh("a2enmod ssl >/dev/null")
	} else {
		lh := leaf("localhost", pki.ECDSA256)
		h.write(raLocalhostCert, lh.FullchainPEM, "root:root", 0o644)
		h.write(raLocalhostKey, lh.KeyPEM, "root:root", 0o600)
	}
	h.write(h.conf, []byte(raSites), "root:root", 0o644)
	h.sh(h.ctl + " -t 2>&1") // the distribution's own check accepts it
}

func (h *raHost) wantPaths() []string {
	want := []string{raARSA, raAEC, raB}
	if !h.debian() {
		want = append(want, raLocalhostCert)
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

// testDiscovery: exactly the fixture's certificate files (and Rocky's localhost), each supported,
// with its servers, and the file's SHA-256 as sha256sum computes it on the host.
func (h *raHost) testDiscovery(t *testing.T) {
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
	assert.Empty(t, res.Warnings)
	require.Equal(t, h.wantPaths(), pathsOf(locs))
	for path, c := range locs {
		l := c.Location
		assert.True(t, l.Supported, "%s: %s", path, l.Unsupported)
		assert.Empty(t, l.Problem, path)
		assert.Empty(t, l.KeyProblem, path)
		assert.True(t, l.KeyExists, path)
		assert.Equal(t, h.fileSHA(path), c.FileSHA256, "%s: the file's SHA-256", path)
		assert.NotEmpty(t, c.PEMChain, path)
		require.Len(t, l.Servers, 1, path)
		require.NotEmpty(t, l.Servers[0].Listens, path)
		for _, li := range l.Servers[0].Listens {
			assert.Equal(t, 443, li.Port, path)
			assert.Empty(t, li.Addr, path)
		}
	}
	a := []providers.CertServer{{Names: []string{"a.example.test", "www.a.example.test"}, File: h.conf, Line: 3,
		Listens: []providers.CertListen{{Port: 443, DefaultServer: true}}}}
	assert.Equal(t, a, locs[raARSA].Location.Servers)
	assert.Equal(t, a, locs[raAEC].Location.Servers)
	assert.Equal(t, raDir+"/a-rsa.key", locs[raARSA].Location.KeyPath)
	assert.Equal(t, raDir+"/a-ec.key", locs[raAEC].Location.KeyPath)
	bl := locs[raB].Location
	assert.Equal(t, bl.CertPath, bl.KeyPath, "b's key is in its certificate file")
	assert.Equal(t, []providers.CertServer{{Names: []string{"b.example.test"}, File: h.conf, Line: 12,
		Listens: []providers.CertListen{{Port: 443}}}}, bl.Servers)
	assert.Equal(t, "0600", bl.KeyMode)
	if !h.debian() {
		lh := locs[raLocalhostCert].Location
		assert.Equal(t, raLocalhostKey, lh.KeyPath)
		assert.Equal(t, "/etc/httpd/conf.d/ssl.conf", lh.Servers[0].File)
		assert.Equal(t, []providers.CertListen{{Port: 443, DefaultServer: true}}, lh.Servers[0].Listens)
	}
}

// testInvalidConfiguration: a directive Apache does not know makes the configuration invalid
// (class syntax) with the warning and no certificate.
func (h *raHost) testInvalidConfiguration(t *testing.T) {
	h.write(h.conf, []byte(raSites+"AliceNoSuchDirective on\n"), "root:root", 0o644)
	code, _ := h.exec("sh", "-c", h.ctl+" -t")
	require.NotZero(t, code, "the distribution's own check refuses it too")
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
	assert.Contains(t, warningCodes(rep.Warnings), providers.WarnWebServerConfigInvalid)
	h.write(h.conf, []byte(raSites), "root:root", 0o644)
}

// raChecksCertInDump are the images whose mod_ssl checks that an SSLCertificateFile exists and is
// not empty even in the config-dump mode of -D DUMP_* -t: Ubuntu 22.04's Apache 2.4.52. Debian
// 12's 2.4.68 and Rocky 9's 2.4.62 skip that check in dump mode. A plain -t (as a start or a
// reload runs) makes it on all three.
var raChecksCertInDump = map[string]bool{"ubuntu22": true}

// testMissingCertificate: a virtual host naming a certificate file that does not exist. Alice's
// verdict follows the helper's -D DUMP_INCLUDES -t: where dump mode skips the file check the
// configuration is valid and the location's certificate is missing; where it does not
// (raChecksCertInDump) the configuration is invalid, class syntax, with no certificate.
func (h *raHost) testMissingCertificate(t *testing.T) {
	h.write(h.conf, []byte(raSites+"<VirtualHost *:443>\n    ServerName c.example.test\n    SSLEngine on\n    SSLCertificateFile /nonexistent.pem\n</VirtualHost>\n"),
		"root:root", 0o644)
	const refusal = "SSLCertificateFile: file '/nonexistent.pem' does not exist or is empty"
	code, out := h.exec("sh", "-c", h.ctl+" -t 2>&1")
	assert.NotZero(t, code, "a plain -t (what a start runs) refuses the missing file")
	assert.Contains(t, out, refusal)
	code, out = h.exec("sh", "-c", h.ctl+" -D DUMP_INCLUDES -t 2>&1 >/dev/null")
	res, locs := h.discover()
	require.NotNil(t, res.WebServer)
	if raChecksCertInDump[h.image] {
		assert.NotZero(t, code, "dump mode refuses the missing file too")
		assert.Contains(t, out, refusal)
		assert.False(t, res.WebServer.ConfigValid)
		assert.Equal(t, providers.ConfigErrSyntax, res.WebServer.ConfigError)
		assert.Contains(t, warningCodes(res.Warnings), providers.WarnWebServerConfigInvalid)
		assert.Empty(t, res.Certificates)
	} else {
		assert.Zero(t, code, "dump mode does not open certificate files: %s", out)
		assert.True(t, res.WebServer.ConfigValid, "%+v", *res.WebServer)
		c, ok := locs["/nonexistent.pem"]
		require.True(t, ok, "the missing certificate's location is listed")
		assert.Equal(t, providers.CertProblemMissing, c.Location.Problem)
		assert.False(t, c.Location.Supported)
		assert.Len(t, locs, len(h.wantPaths())+1)
	}
	h.write(h.conf, []byte(raSites), "root:root", 0o644)
}

// testWritableConfig: a loaded configuration file other users can change makes every pair
// config_file_writable (Ruling 7: Apache's Define and Include reach is global).
func (h *raHost) testWritableConfig(t *testing.T) {
	h.sh("chmod 0666 " + h.conf)
	res, locs := h.discover()
	require.Equal(t, h.wantPaths(), pathsOf(locs))
	for path, c := range locs {
		assert.False(t, c.Location.Supported, path)
		assert.Equal(t, providers.UnsupportedConfigFileWritable, c.Location.Unsupported, path)
	}
	assert.Contains(t, res.Warnings, providers.Warning{Code: providers.WarnConfigFileWritable, Params: map[string]string{"path": h.conf}})
	h.sh("chmod 0644 " + h.conf)
	_, locs = h.discover()
	for path, c := range locs {
		assert.True(t, c.Location.Supported, path)
	}
}

// testUntrustedProgram (Ruling 15): a group-writable control program (and on Debian and Ubuntu
// a group-writable /etc/apache2/envvars or /usr/sbin/apache2, which apache2ctl sources and runs)
// is never run as root: discovery and the connection test report the configuration untrusted,
// not_root_controlled, naming the file. Each mode is put back.
func (h *raHost) testUntrustedProgram(t *testing.T) {
	paths := []string{h.ctl}
	if h.debian() {
		paths = append(paths, "/etc/apache2/envvars", "/usr/sbin/apache2")
	}
	// One subtest per file: the sessions discover and testConnection open close with it (the
	// pool holds a few per target).
	for _, p := range paths {
		ok := t.Run(strings.TrimPrefix(p, "/"), func(t *testing.T) {
			parent := h.t
			h.t = t
			defer func() { h.t = parent }()
			mode := strings.TrimSpace(h.sh("stat -L -c %a " + p))
			h.sh("chmod g+w " + p)
			defer h.sh("chmod " + mode + " " + p)
			res, locs := h.discover()
			require.NotNil(t, res.WebServer, p)
			assert.False(t, res.WebServer.ConfigValid, p)
			assert.Equal(t, providers.ConfigErrUntrusted, res.WebServer.ConfigError, p)
			assert.Equal(t, providers.ConfigReasonNotRootControlled, res.WebServer.ConfigErrorReason, p)
			assert.Equal(t, p, res.WebServer.ConfigErrorFile)
			assert.Empty(t, locs, p)
			assert.Contains(t, warningCodes(res.Warnings), providers.WarnWebServerConfigInvalid, p)
			rep := h.testConnection()
			require.NotNil(t, rep.WebServer, p)
			assert.False(t, rep.WebServer.ConfigValid, p)
			assert.Equal(t, providers.ConfigErrUntrusted, rep.WebServer.ConfigError, p)
		})
		require.True(t, ok, p)
	}
	_, locs := h.discover()
	assert.Equal(t, h.wantPaths(), pathsOf(locs))
}

// testProfileMissing: with the linux profile installed sudo refuses apache-dump:
// apache.profile_missing. The apache profile is then installed again.
func (h *raHost) testProfileMissing(t *testing.T) {
	h.setup("linux")
	h.discoverFails("apache.profile_missing")
	h.setup("apache")
	_, locs := h.discover()
	assert.Equal(t, h.wantPaths(), pathsOf(locs))
}

// testNotFound: without the control program (apache2ctl on Debian and Ubuntu, httpd on Rocky)
// discovery fails with apache.not_found and the connection test warns. It is then put back.
func (h *raHost) testNotFound(t *testing.T) {
	h.sh("mv " + h.ctl + " /root/ctl.away")
	h.discoverFails("apache.not_found")
	rep := h.testConnection()
	require.NotNil(t, rep.WebServer)
	assert.False(t, rep.WebServer.Found)
	assert.Equal(t, []string{providers.WarnWebServerNotFound}, warningCodes(rep.Warnings))
	h.sh("mv /root/ctl.away " + h.ctl)
	_, locs := h.discover()
	assert.Equal(t, h.wantPaths(), pathsOf(locs))
}
