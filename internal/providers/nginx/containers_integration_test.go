//go:build integration || systemd

package nginx

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// The real-Nginx matrix (spec §22.3; Phase 4 Task 20): Alice's Nginx provider end to end against
// real OpenSSH, real sudo, the real alice-helper and the distribution's real Nginx on Ubuntu 22.04,
// Debian 12 and Rocky 9 (test/images/sshd, the images TestRealOpenSSH uses). Each host is prepared
// with the exact setup script Alice generates for the nginx profile; when the test binary carries
// the helper checksums (make test-ssh links them in, as make build does) the script checks the
// release-built helper against them, as on a customer server.
//
// How the hosts differ from a real server: no systemd (the e2e target's systemctl shim handles
// exactly "reload nginx" and "is-active --quiet nginx"); /usr/sbin/nginx is the e2e target's
// pass-through wrapper (fault and block modes for "nginx -t" only); nginx is started by the test, not
// by a unit; the network is Docker's bridge, reached directly from the host at the container's
// address (no NAT, no firewall); certificates come from a throwaway test CA.
//
//	ALICE_REAL_MATRIX=1 ALICE_SSH_IMAGES=ubuntu22 go test -count=1 -tags integration -run '^TestRealNginx' ./internal/providers/nginx/
//
// Only containers created here through testcontainers are touched. Every helper of this file is
// prefixed with rn (real Nginx) so it cannot clash with the emulator tests of the package.

var rnDistros = map[string]string{"ubuntu22": "ubuntu", "debian12": "debian", "rocky9": "rocky"} // image -> os-release ID

// rnNginxVersions are the packaged versions the matrix expects (the oldest, Ubuntu's 1.18, is the
// floor carry 1 of Task 20 asks about).
var rnNginxVersions = map[string]string{"ubuntu22": "1.18.0", "debian12": "1.22.1", "rocky9": "1.20.1"}

func rnSelectedDistros(t *testing.T) []string {
	t.Helper()
	sel := os.Getenv("ALICE_SSH_IMAGES")
	if sel == "" {
		sel = "ubuntu22,debian12,rocky9"
	}
	var out []string
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(name)
		if _, ok := rnDistros[name]; !ok {
			t.Fatalf("ALICE_SSH_IMAGES: unknown image %q (known: ubuntu22, debian12, rocky9)", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func rnRepoRoot() string { return filepath.Join("..", "..", "..") }

// rnHelper returns the alice-helper binary to install. With the helper checksums linked into this
// test binary (make test-ssh) it is the release build of make helper, which the setup script then
// checks against them; without (a plain go test) it is built here and the development script, which
// says it cannot verify the helper, installs it.
func rnHelper(t *testing.T) (path string, verified bool) {
	t.Helper()
	if linuxssh.HelperChecksumsKnown() {
		bin := filepath.Join(rnRepoRoot(), "bin", "alice-helper-linux-"+runtime.GOARCH)
		_, err := os.Stat(bin)
		require.NoError(t, err, "the helper checksums are linked in, so make helper must have built %s", bin)
		return bin, true
	}
	t.Log("no helper checksums linked in: the setup script installs a helper built by the test without checking it (make test-ssh checks it)")
	bin := filepath.Join(t.TempDir(), "alice-helper")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/alice-helper")
	cmd.Dir = rnRepoRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build alice-helper: %s", out)
	return bin, false
}

type rnSigner struct{ s ssh.Signer }

func (c rnSigner) SSHSigner(context.Context) (ssh.Signer, func(), error) { return c.s, func() {}, nil }

// rnProberDown is Alice's TLS probe on a network where Alice cannot reach the website (F-07).
type rnProberDown struct{}

func (rnProberDown) Probe(context.Context, string, int, string, string) (Probe, error) {
	return Probe{}, ErrProbeUnreachable
}

// rnHost is one running container prepared with the nginx profile's setup script.
type rnHost struct {
	t        *testing.T
	image    string
	ctr      testcontainers.Container
	ip       string // the container's address: Alice's target host
	hostname string
	target   uuid.UUID
	hk       *memHostKeys
	signer   ssh.Signer
	lp       *linuxssh.Provider
	prov     *Provider
	ca       *pki.CA
	// leaves is the pair on disk (and served) per certificate path, kept up to date by the subtests.
	leaves map[string]pki.Leaf
	// scDir is where the ssl-cert style key lives (Debian's /etc/ssl/private; Rocky has no such
	// group, so its /etc/pki/tls/private with group nginx stands in) and scGroup its group.
	scCertDir, scKeyDir, scGroup string
	// modDir is a directory nginx.conf includes at main level (for stream {} and mail {}).
	modDir string
}

func startNginxHost(t *testing.T, image, helper string, verified bool) *rnHost {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    filepath.Join(rnRepoRoot(), "test", "images"),
				Dockerfile: "sshd/" + image + ".Dockerfile",
				Repo:       "alice-test/sshd-" + image,
				Tag:        "phase4",
				KeepImage:  true,
			},
			ExposedPorts: []string{"22/tcp"},
			// A small file system for the NO_SPACE case (F-10): 256 KiB, root's.
			Tmpfs:      map[string]string{"/etc/nginx/small": "size=256k,mode=0755"},
			WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	ip, err := ctr.ContainerIP(ctx)
	require.NoError(t, err)
	// Alice reaches the server, and its websites, at the container's own address, as it would reach
	// a real server: no published port, so Alice's TLS probe and the server-side probe see the same
	// listen addresses and ports. That needs Docker's bridge network to be routable from this host
	// (Linux Docker; not Docker Desktop).
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	require.NoError(t, err, "the Nginx matrix reaches the container at %s directly: Docker's bridge network must be routable from this host", ip)
	_ = conn.Close()

	h := newRNHost(t, image, ctr, ip)
	switch image {
	case "rocky9":
		h.scCertDir, h.scKeyDir, h.scGroup, h.modDir = "/etc/pki/tls/certs", "/etc/pki/tls/private", "nginx", "/usr/share/nginx/modules"
	default:
		h.scCertDir, h.scKeyDir, h.scGroup, h.modDir = "/etc/ssl/certs", "/etc/ssl/private", "ssl-cert", "/etc/nginx/modules-enabled"
	}
	h.runSetupScript(helper, verified)
	// Nginx starts with the distribution's configuration, as its unit would.
	h.sh(nginxBin)
	require.Eventually(t, func() bool { return len(h.workers()) > 0 }, 30*time.Second, 100*time.Millisecond, "nginx started")
	h.connect(verified)
	return h
}

// newRNHost is the host record of a started container at ip, with a new SSH key for Alice and a
// throwaway test CA (shared by TestRealNginx and TestRealSystemdNginx).
func newRNHost(t *testing.T, image string, ctr testcontainers.Container, ip string) *rnHost {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	h := &rnHost{t: t, image: image, ctr: ctr, ip: ip, target: uuid.New(), hk: &memHostKeys{}, signer: signer,
		ca: pki.NewCA("Real Nginx "+image, pki.ECDSA256, time.Now()), leaves: map[string]pki.Leaf{}}
	h.hostname = strings.TrimSpace(h.sh("hostname"))
	return h
}

// runSetupScript prepares the host with the setup script of the nginx profile, exactly as Alice shows
// it. With the checksums, a helper that is not this version's is refused first (nothing installed),
// then the real one is installed.
func (h *rnHost) runSetupScript(helper string, verified bool) {
	t := h.t
	t.Helper()
	ctx := context.Background()
	ctr := h.ctr
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(h.signer.PublicKey())))
	script, err := linuxssh.SetupScript("nginx", linuxssh.AuthorizedKeysLine(pub, ""), !verified)
	require.NoError(t, err)
	require.NoError(t, ctr.CopyToContainer(ctx, []byte(script), "/root/bundle/setup.sh", 0o700))
	helperBytes, err := os.ReadFile(helper)
	require.NoError(t, err)
	if verified {
		require.NoError(t, ctr.CopyToContainer(ctx, append(append([]byte{}, helperBytes...), 0), "/root/bad/alice-helper", 0o755))
		require.NoError(t, ctr.CopyToContainer(ctx, []byte(script), "/root/bad/setup.sh", 0o700))
		code, out := h.exec("sh", "-c", "cd /root/bad && sh ./setup.sh")
		require.NotZero(t, code, out)
		require.Contains(t, out, "is not the alice-helper of this Alice version")
		code, _ = h.exec("test", "-e", helperproto.HelperPath)
		require.NotZero(t, code, "a helper that fails the checksum is never installed")
		code, _ = h.exec("test", "-e", "/etc/sudoers.d/alice")
		require.NotZero(t, code, "nor are the sudoers lines")
	}
	require.NoError(t, ctr.CopyToContainer(ctx, helperBytes, "/root/bundle/alice-helper", 0o755))
	out := h.sh("cd /root/bundle && sh ./setup.sh 2>&1")
	require.Contains(t, out, "This server is ready for Alice.")
	if verified {
		require.NotContains(t, out, "cannot verify alice-helper", "the release helper was checked against its checksum")
	}
	sum := sha256.Sum256(helperBytes)
	require.Equal(t, hex.EncodeToString(sum[:]), strings.Fields(h.sh("sha256sum " + helperproto.HelperPath))[0], "the installed helper is the one copied")
}

// connect pins the server's host key as the administrator would and builds Alice's SSH provider and
// the Nginx provider on it.
func (h *rnHost) connect(verified bool) {
	t := h.t
	t.Helper()
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.sh("cat /etc/ssh/ssh_host_ed25519_key.pub")))
	require.NoError(t, err)
	pin := linuxssh.HostKeyOf(hostPub)
	h.hk.pinned = &pin

	// More connections per target than production's 2: a kill test keeps one session busy while
	// another reads the journal.
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: h.hk}, linuxssh.MaxConnections, 8, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	h.lp = linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: !verified})
	h.prov = h.provider(nil)
}

// provider is a provider on the host's pool (prober nil: Alice's real TLS probe).
func (h *rnHost) provider(prober Prober) *Provider {
	p := New(Options{SSH: h.lp, Prober: prober, RetryWait: 200 * time.Millisecond})
	p.restoreWait = 200 * time.Millisecond
	return p
}

func (h *rnHost) ref() providers.TargetRef {
	return providers.TargetRef{ID: h.target, Name: "real-" + h.image, Kind: providers.KindNginx,
		Config: providers.TargetConfig{"host": h.ip, "port": 22, "username": linuxssh.ServiceUser}}
}

// session opens a session of p (nil: the host's provider), closed when the (sub)test ends.
func (h *rnHost) session(p *Provider) providers.Session {
	h.t.Helper()
	if p == nil {
		p = h.prov
	}
	s, err := p.Open(context.Background(), h.ref(), rnSigner{h.signer}, providers.Env{Clock: clock.Real{}, HostKeys: h.hk})
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = s.Close() })
	return s
}

// exec runs a command in the container as root (or as opts say) and returns the exit code and the
// combined output.
func (h *rnHost) exec(cmd ...string) (int, string) {
	h.t.Helper()
	return h.execAs(nil, cmd...)
}

func (h *rnHost) execAs(opts []tcexec.ProcessOption, cmd ...string) (int, string) {
	h.t.Helper()
	code, r, err := h.ctr.Exec(context.Background(), cmd, append(opts, tcexec.Multiplexed())...)
	require.NoError(h.t, err)
	out, err := io.ReadAll(r)
	require.NoError(h.t, err)
	return code, string(out)
}

// sh runs a shell script as root and requires it to succeed.
func (h *rnHost) sh(script string) string {
	h.t.Helper()
	code, out := h.exec("sh", "-c", script)
	require.Zero(h.t, code, "%s: %s", script, out)
	return out
}

// write puts content at path (directories created), owned by owner (user:group) with mode. The
// content goes through a staging file: docker cp cannot write into a tmpfs mount.
func (h *rnHost) write(path string, content []byte, owner string, mode os.FileMode) {
	h.t.Helper()
	user, group, ok := strings.Cut(owner, ":")
	require.True(h.t, ok, owner)
	stage := "/root/.stage-" + uuid.NewString()
	require.NoError(h.t, h.ctr.CopyToContainer(context.Background(), content, stage, 0o600))
	h.sh("install -D -o " + user + " -g " + group + " -m " + strconv.FormatUint(uint64(mode), 8) + " " + stage + " " + path + " && rm -f " + stage)
}

func (h *rnHost) fileSHA(path string) string {
	h.t.Helper()
	return strings.Fields(h.sh("sha256sum " + path))[0]
}

func (h *rnHost) stat(path string) string {
	h.t.Helper()
	return strings.TrimSpace(h.sh("stat -c '%U:%G %a' " + path))
}

// nginxBin is the distribution's nginx itself: the test's own reloads never go through the fault
// wrapper at /usr/sbin/nginx, so they never consume an armed fault.
const nginxBin = "/usr/lib/alice-e2e/nginx"

// workers lists the PIDs of nginx's worker processes (children of the master in /run/nginx.pid).
func (h *rnHost) workers() []string {
	h.t.Helper()
	_, out := h.exec("sh", "-c", `pgrep -P "$(cat /run/nginx.pid)" | sort`)
	return strings.Fields(out)
}

// reloadNginx tests the configuration and reloads it, then waits until no worker of the previous
// configuration is left.
func (h *rnHost) reloadNginx() {
	h.t.Helper()
	before := h.workers()
	h.sh(nginxBin + " -t -q && " + nginxBin + " -s reload")
	require.Eventually(h.t, func() bool {
		now := h.workers()
		if len(now) == 0 {
			return false
		}
		for _, w := range now {
			if slices.Contains(before, w) {
				return false
			}
		}
		return true
	}, 30*time.Second, 100*time.Millisecond, "nginx reloaded")
}

// served is the SHA-256 fingerprint of the leaf nginx serves at addr:port for sni ("" sends no
// name), read inside the container with openssl s_client: independent of Alice's own TLS code.
// keyType rsa or ecdsa limits the client to TLS 1.2 with that key type's suites; "" accepts any.
// "" when no certificate was served.
func (h *rnHost) served(addr string, port int, sni, keyType string) string {
	h.t.Helper()
	args := "-connect " + net.JoinHostPort(addr, strconv.Itoa(port))
	if sni == "" {
		args += " -noservername"
	} else {
		args += " -servername " + sni
	}
	switch keyType {
	case helperproto.ProbeRSA:
		args += " -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256"
	case helperproto.ProbeECDSA:
		args += " -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256"
	}
	_, out := h.exec("sh", "-c", "openssl s_client "+args+" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null")
	_, fp, ok := strings.Cut(strings.TrimSpace(out), "=")
	if !ok {
		return ""
	}
	return asciiLower(strings.ReplaceAll(fp, ":", ""))
}

// settledServed waits until no worker is shutting down after a reload and addr:port serves want.
func (h *rnHost) settledServed(addr string, port int, sni, keyType, want, msg string) {
	h.t.Helper()
	var last string
	ok := assert.Eventually(h.t, func() bool {
		if code, _ := h.exec("pgrep", "-f", "worker process is shutting down"); code == 0 {
			return false
		}
		last = h.served(addr, port, sni, keyType)
		return last == want
	}, 30*time.Second, 100*time.Millisecond, "%s: %s:%d %s serves %s", msg, addr, port, sni, want)
	if !ok {
		h.t.Logf("last served: %q", last)
	}
}

// dialVerified dials the website from this host with full certificate verification against the
// test CA and returns the served leaf's fingerprint: a TLS client independent of Alice's probe.
func (h *rnHost) dialVerified(port int, sni string) string {
	h.t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(h.ca.Root)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(h.ip, strconv.Itoa(port)))
	require.NoError(h.t, err, "a verified TLS connection to %s:%d for %s", h.ip, port, sni)
	defer func() { _ = c.Close() }()
	tc, ok := c.(*tls.Conn)
	require.True(h.t, ok)
	return pki.Fingerprint(tc.ConnectionState().PeerCertificates[0])
}

// pair reads a certificate and key file pair back and checks that they belong together and that
// the certificate's leaf is want's.
func (h *rnHost) pair(certPath, keyPath string, want pki.Leaf) {
	h.t.Helper()
	cert := []byte(h.sh("cat " + certPath))
	key := []byte(h.sh("cat " + keyPath))
	kp, err := tls.X509KeyPair(cert, key)
	require.NoError(h.t, err, "%s and %s are a pair", certPath, keyPath)
	clear(key)
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	require.NoError(h.t, err)
	assert.Equal(h.t, pki.Fingerprint(want.Cert), pki.Fingerprint(leaf), "%s holds the expected leaf", certPath)
}

// discover runs a certificate (and SSH key) discovery and indexes the locations by certificate path.
func (h *rnHost) discover(sshKeys bool) (providers.DiscoveryResult, map[string]providers.DiscoveredCertificate) {
	h.t.Helper()
	res, err := h.session(nil).Discover(context.Background(), providers.DiscoverRequest{Certificates: true, SSHKeys: sshKeys})
	require.NoError(h.t, err)
	return res, locationsByPath(res)
}

// location is the discovered location of certPath, which must be listed.
func (h *rnHost) location(certPath string) providers.DiscoveredCertificate {
	h.t.Helper()
	_, locs := h.discover(false)
	c, ok := locs[certPath]
	require.True(h.t, ok, "%s is discovered", certPath)
	return c
}

func keyTypeOf(l pki.Leaf) string {
	switch l.Key.(type) {
	case *rsa.PrivateKey:
		return helperproto.ProbeRSA
	case *ecdsa.PrivateKey:
		return helperproto.ProbeECDSA
	}
	return ""
}

// request is the DeployRequest of leaf for a discovered location under a new operation, as the
// deploy engine builds it: the file's hash from the discovery, the pair on disk as the previous
// one, the new chain (with the intermediate when chain) and its length.
func (h *rnHost) request(c providers.DiscoveredCertificate, leaf pki.Leaf, chain bool) providers.DeployRequest {
	h.t.Helper()
	pem := leaf.CertPEM
	if chain {
		pem = leaf.FullchainPEM
	}
	old, ok := h.leaves[c.Location.CertPath]
	require.True(h.t, ok, "the test knows the pair on disk at %s", c.Location.CertPath)
	return providers.DeployRequest{
		OperationID:      uuid.New(),
		Location:         c.Location,
		ExpectCertSHA256: c.FileSHA256,
		CertificatePEM:   pem,
		PrivateKeyPEM:    secrets.NewPlaintext(append([]byte(nil), leaf.KeyPEM...)),
		Fingerprint:      pki.Fingerprint(leaf.Cert),
		SANs:             leaf.Cert.DNSNames,
		KeyType:          keyTypeOf(leaf),
		OldFingerprint:   pki.Fingerprint(old.Cert),
		OldSANs:          old.Cert.DNSNames,
		ChainLength:      chainLength(pem),
	}
}

// trustPolicy is the R51 policy for deploying chain with the test CA's root as the only root.
func (h *rnHost) trustPolicy(chain ...*x509.Certificate) *providers.TrustPolicy {
	roots := x509.NewCertPool()
	roots.AddCert(h.ca.Root)
	p := providers.TrustPolicyFor(chain, roots, providers.TrustStoreSystem, time.Now())
	return &p
}

func rollbackRequestOf(req providers.DeployRequest, oldChain int) providers.RollbackRequest {
	return providers.RollbackRequest{OperationID: req.OperationID, Location: req.Location, OldFingerprint: req.OldFingerprint,
		OldChainLength: oldChain, OldSANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify}
}

func verifyRequestOf(req providers.DeployRequest) providers.VerifyRequest {
	return providers.VerifyRequest{Location: req.Location, Fingerprint: req.Fingerprint, ChainLength: req.ChainLength,
		PreviousFingerprint: req.OldFingerprint, SANs: req.SANs, KeyType: req.KeyType, Verify: req.Verify}
}

// deploy runs DeployCertificate on a new session.
func (h *rnHost) deploy(p *Provider, req providers.DeployRequest) (providers.DeployOutcome, []string, error) {
	h.t.Helper()
	log := &steps{}
	out, err := h.session(p).DeployCertificate(context.Background(), req, log)
	require.NoError(h.t, providers.CheckDeployReturn(out, err), "a legal DeployCertificate return")
	return out, log.list(), err
}

func (h *rnHost) leaf(cn string, kt pki.KeyType) pki.Leaf {
	return h.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}, KeyType: kt}, time.Now())
}

// arm makes the next "nginx -t" (what "test") or "systemctl reload nginx" (what "reload") stop
// and wait for the test (the block-once mode of the e2e target's wrapper and shim).
func (h *rnHost) arm(what string) {
	h.t.Helper()
	file := map[string]string{"test": "test-mode", "reload": "reload-mode"}[what]
	require.NotEmpty(h.t, file)
	h.sh("rm -f /etc/alice-e2e/blocked /etc/alice-e2e/release && mkfifo -m 0600 /etc/alice-e2e/release && echo block-once > /etc/alice-e2e/" + file)
}

// waitBlocked waits until the helper's nginx -t or reload stopped at the armed point.
func (h *rnHost) waitBlocked(want string) {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		_, out := h.exec("cat", "/etc/alice-e2e/blocked")
		return strings.TrimSpace(out) == want
	}, 60*time.Second, 50*time.Millisecond, "the helper reached %q", want)
}

// release lets the blocked program go on ("go") or end without running (anything else).
func (h *rnHost) release(word string) {
	h.t.Helper()
	h.sh("timeout 10 sh -c 'echo " + word + " > /etc/alice-e2e/release'")
	require.Eventually(h.t, func() bool {
		code, _ := h.exec("test", "-e", "/etc/alice-e2e/blocked")
		return code != 0
	}, 10*time.Second, 50*time.Millisecond, "the blocked program went on")
}

// helperRunning reports whether an alice-helper process (or the sudo that runs one) is alive.
func (h *rnHost) helperRunning() bool {
	h.t.Helper()
	code, _ := h.exec("pgrep", "-f", helperproto.HelperPath+" nginx-")
	return code == 0
}

// killHelper sends sig to the running alice-helper and waits until it is gone.
func (h *rnHost) killHelper(sig string) {
	h.t.Helper()
	h.sh("pkill -" + sig + " -x alice-helper")
	require.Eventually(h.t, func() bool {
		code, _ := h.exec("pgrep", "-x", "alice-helper")
		return code != 0
	}, 10*time.Second, 50*time.Millisecond, "alice-helper is gone after SIG%s", sig)
}

// staged lists files a helper transaction stages next to the pair (S2: none may be left behind).
func (h *rnHost) staged() []string {
	h.t.Helper()
	_, out := h.exec("sh", "-c", "find /etc/nginx /etc/ssl /etc/pki /etc/letsencrypt -name '.alice-*' 2>/dev/null")
	return strings.Fields(out)
}

// rnRecovery is what the deploy engine's recovery (deployjobs.recoverDeployment) does, at the
// provider level: wait for a running helper, read the journal, then verify a committed operation
// or roll back an interrupted or restored one.
type rnRecovery struct {
	state    providers.DeploymentState
	verify   *providers.VerifyResult
	rollback *providers.RollbackOutcome
	err      error
}

func (h *rnHost) recover(req providers.DeployRequest, oldChain int) rnRecovery {
	h.t.Helper()
	sess := h.session(nil)
	ctx := context.Background()
	var st providers.DeploymentState
	require.Eventually(h.t, func() bool {
		if h.helperRunning() {
			return false
		}
		var err error
		st, err = sess.DeploymentStatus(ctx, req.OperationID)
		require.NoError(h.t, err)
		return !st.Active
	}, 60*time.Second, 100*time.Millisecond, "the operation's helper ended")
	require.NoError(h.t, st.Validate())
	r := rnRecovery{state: st}
	switch st.Phase {
	case providers.PhaseNone, providers.PhasePrepared:
		return r
	case providers.PhaseCommitted, providers.PhaseUnchanged:
		vr, err := sess.VerifyDeployment(ctx, verifyRequestOf(req))
		require.NoError(h.t, err)
		r.verify = &vr
		if vr.OK {
			return r
		}
	}
	out, err := sess.RollbackDeployment(ctx, rollbackRequestOf(req, oldChain), &steps{})
	require.NoError(h.t, providers.CheckRollbackReturn(out, err), "a legal RollbackDeployment return")
	r.rollback, r.err = &out, err
	return r
}

// background runs DeployCertificate (or any call) on its own goroutine; wait returns its result.
type rnCall[T any] struct {
	done chan struct{}
	out  T
	err  error
}

func rnGo[T any](fn func() (T, error)) *rnCall[T] {
	c := &rnCall[T]{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		c.out, c.err = fn()
	}()
	return c
}

func (c *rnCall[T]) wait(t *testing.T) (T, error) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Minute):
		t.Fatal("the call did not return")
	}
	return c.out, c.err
}

func rnReason(t *testing.T, err error) string {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	return pe.Code
}

// rnMatrixEnv gates the matrix: it runs only through make test-ssh, which sets it (never in make
// coverage or make test-integration, which run every integration test under -race and without the
// helper checksums).
const rnMatrixEnv = "ALICE_REAL_MATRIX"

func TestRealNginx(t *testing.T) {
	if os.Getenv(rnMatrixEnv) != "1" {
		t.Skip("the real-Nginx matrix runs only through make test-ssh (it sets " + rnMatrixEnv + "=1)")
	}
	images := rnSelectedDistros(t)
	helper, verified := rnHelper(t)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			h := startNginxHost(t, image, helper, verified)
			// Every subtest leaves the host as the next one expects it (files, served pairs, fault
			// modes); a failed one stops the rest of this distribution, whose state is then unknown.
			run := func(name string, fn func(t *testing.T)) {
				if !t.Run(name, func(t *testing.T) { h.t = t; fn(t) }) {
					h.t = t
					t.FailNow()
				}
				h.t = t
			}
			run("setup", h.testSetup)
			run("sudo", h.testSudo)
			run("untouched_default_layout", h.testUntouchedLayout)
			h.writeFixtures()
			run("discovery", h.testDiscovery)
			run("discovery_include_spellings", h.testIncludeSpellings)
			run("discovery_invalid_configuration", h.testInvalidConfiguration)
			run("deploy_verified_ecdsa_chain", h.testDeployVerified)
			run("deploy_rsa_leaf_only_mode_0640_kept", h.testDeployRSALeafOnly)
			run("deploy_ssl_cert_group_kept", h.testDeploySSLCertGroup)
			run("deploy_user_owned_key_keeps_owner", h.testDeployUserOwnedKey)
			run("letsencrypt_links", h.testLetsEncrypt)
			run("dual_rsa_ecdsa", h.testDual)
			run("listen_addresses", h.testListenAddresses)
			run("F-01_key_mismatch_real_nginx_t", h.testKeyMismatch)
			run("F-02_config_invalid_before_write", h.testConfigInvalidBeforeWrite)
			run("F-02b_config_test_fails_after_write", h.testConfigTestFailsAfterWrite)
			run("F-03_reload_fails_once", h.testReloadFailsOnce)
			run("F-04_rollback_reload_fails", h.testRollbackReloadFails)
			run("F-05_noop_reload", h.testNoopReload)
			run("verify_unreachable_port", h.testVerifyUnreachable)
			run("fail_safe_other_block", h.testOtherBlock)
			run("F-07_verify_local", h.testVerifyLocal)
			run("kill_deploy_sigterm_at_config_test", func(t *testing.T) { h.testKillDeploy(t, "test", "TERM", false) })
			run("kill_deploy_sigkill_at_reload", func(t *testing.T) { h.testKillDeploy(t, "reload", "KILL", false) })
			run("kill_deploy_sigkill_at_reload_new_pair_served", func(t *testing.T) { h.testKillDeploy(t, "reload", "KILL", true) })
			run("kill_restore_sigkill_at_config_test", func(t *testing.T) { h.testKillRestore(t, "test", "KILL") })
			run("kill_restore_sigterm_at_reload", func(t *testing.T) { h.testKillRestore(t, "reload", "TERM") })
			run("superseded_after_interruption", h.testSuperseded)
			run("F-08_connection_dropped_lock_held", h.testConnectionDroppedLockHeld)
			run("F-08_connection_dropped_100ms", h.testConnectionDropped100ms)
			run("F-10_no_space", h.testNoSpace)
			run("hard_link", h.testHardLink)
			run("user_owned_symlink", h.testUserSymlink)
			run("user_owned_directory", h.testUserDirectory)
			run("config_file_writable", h.testWritableConfig)
			run("untrusted_nginx_program", h.testUntrustedProgram)
			run("busy", h.testBusy)
			run("name_outside_vocabulary", h.testNameOutsideVocabulary)
			run("fence", h.testFence)
			run("acme_http01_webroot", h.testACMEHTTP01)
			run("nginx_not_running", h.testNginxNotRunning)
			assert.Empty(t, h.staged(), "no staged file of any transaction is left behind (S2)")
		})
	}
}
