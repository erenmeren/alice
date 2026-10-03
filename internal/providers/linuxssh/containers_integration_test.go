//go:build integration

package linuxssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"alice/internal/providers/linuxssh/helperproto"
)

// Real OpenSSH servers (spec §22.3, §26.5): Ubuntu 22.04, Debian 12 and Rocky 9 images from
// test/images/sshd, prepared with the exact setup script Alice generates and the real static
// alice-helper, reached through the production Dialer, Pool and Provider. Select distributions
// with ALICE_SSH_IMAGES (default: all three), for example
//
//	ALICE_SSH_IMAGES=ubuntu22 go test -count=1 -tags integration -run TestRealOpenSSH ./internal/providers/linuxssh/
//
// Only containers created here through testcontainers are touched.

var ctrDistros = map[string]string{"ubuntu22": "ubuntu", "debian12": "debian", "rocky9": "rocky"} // image -> os-release ID

func ctrSelectedDistros(t *testing.T) []string {
	t.Helper()
	sel := os.Getenv("ALICE_SSH_IMAGES")
	if sel == "" {
		sel = "ubuntu22,debian12,rocky9"
	}
	var out []string
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(name)
		if _, ok := ctrDistros[name]; !ok {
			t.Fatalf("ALICE_SSH_IMAGES: unknown image %q (known: ubuntu22, debian12, rocky9)", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ctrBuildHelper compiles the static alice-helper for the container's architecture.
func ctrBuildHelper(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "alice-helper")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/alice-helper")
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build alice-helper: %s", out)
	return bin
}

type ctrSigner struct{ s ssh.Signer }

func (c ctrSigner) SSHSigner(context.Context) (ssh.Signer, func(), error) { return c.s, func() {}, nil }

type ctrNoSteps struct{}

func (ctrNoSteps) Step(string, providers.StepStatus, map[string]string) {}

// ctrHost is one running container prepared with the setup script.
type ctrHost struct {
	t        *testing.T
	ctr      testcontainers.Container
	target   uuid.UUID
	cfg      Config
	keys     *memHostKeys // helpers_test.go: in-memory store, pinned only by the test (the administrator)
	signer   ssh.Signer
	platform string // the platform key's fingerprint
	osID     string
}

func startCtrHost(t *testing.T, image, helper string) *ctrHost {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    filepath.Join("..", "..", "..", "test", "images", "sshd"),
				Dockerfile: image + ".Dockerfile",
				Repo:       "alice-test/sshd-" + image,
				Tag:        "phase3",
				KeepImage:  true,
			},
			ExposedPorts: []string{"22/tcp"},
			WaitingFor:   wait.ForListeningPort("22/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	// A test build has no helper checksums, so only the development variant of the script exists.
	script, err := SetupScript("linux", AuthorizedKeysLine(pub, ""), true)
	require.NoError(t, err)
	require.NoError(t, ctr.CopyFileToContainer(ctx, helper, "/root/bundle/alice-helper", 0o755))
	require.NoError(t, ctr.CopyToContainer(ctx, []byte(script), "/root/bundle/setup.sh", 0o700))

	endpoint, err := ctr.PortEndpoint(ctx, "22/tcp", "")
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(endpoint)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	h := &ctrHost{t: t, ctr: ctr, target: uuid.New(), cfg: Config{Host: host, Port: port, Username: ServiceUser},
		keys: &memHostKeys{}, signer: signer, platform: ssh.FingerprintSHA256(signer.PublicKey()), osID: ctrDistros[image]}
	out := h.mustExec("sh", "-c", "cd /root/bundle && sh ./setup.sh")
	require.Contains(t, out, "This server is ready for Alice.")
	return h
}

// exec runs a command in the container (as root unless opts say otherwise) and returns the
// exit code and the combined output.
func (h *ctrHost) exec(cmd []string, opts ...tcexec.ProcessOption) (int, string) {
	h.t.Helper()
	code, r, err := h.ctr.Exec(context.Background(), cmd, append(opts, tcexec.Multiplexed())...)
	require.NoError(h.t, err)
	out, err := io.ReadAll(r)
	require.NoError(h.t, err)
	return code, string(out)
}

func (h *ctrHost) mustExec(cmd ...string) string {
	h.t.Helper()
	code, out := h.exec(cmd)
	require.Zero(h.t, code, "%v: %s", cmd, out)
	return out
}

// hostFingerprint is what an administrator sees when running the verification command on the server.
func (h *ctrHost) hostFingerprint() string {
	h.t.Helper()
	return strings.Fields(h.mustExec("ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"))[1]
}

// accepted counts successful public-key logins in sshd's log (sshd -D -e logs to stderr).
func (h *ctrHost) accepted() int {
	h.t.Helper()
	rc, err := h.ctr.Logs(context.Background())
	require.NoError(h.t, err)
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	require.NoError(h.t, err)
	return strings.Count(string(raw), "Accepted publickey")
}

func (h *ctrHost) newProvider() (*Provider, *Pool) {
	pool := NewPool(&Dialer{Clock: clock.Real{}, HostKeys: h.keys}, MaxConnections, MaxConnectionsPerTarget, IdleTimeout)
	h.t.Cleanup(pool.Close)
	return New(Options{Pool: pool}), pool
}

func (h *ctrHost) ref() providers.TargetRef {
	return providers.TargetRef{ID: h.target, Name: "real", Kind: providers.KindLinuxSSH,
		Config: providers.TargetConfig{"host": h.cfg.Host, "port": h.cfg.Port, "username": h.cfg.Username}}
}

func (h *ctrHost) open(p *Provider) (providers.Session, error) {
	return p.Open(context.Background(), h.ref(), ctrSigner{h.signer}, providers.Env{Clock: clock.Real{}, HostKeys: h.keys})
}

func (h *ctrHost) mustOpen(p *Provider) providers.Session {
	h.t.Helper()
	s, err := h.open(p)
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = s.Close() })
	return s
}

// lastObservation is the host key the dialer recorded most recently.
func (h *ctrHost) lastObservation() observation {
	h.t.Helper()
	obs := h.keys.observations()
	require.NotEmpty(h.t, obs, "the presented host key was recorded")
	return obs[len(obs)-1]
}

// pinKey is the administrator's confirmation of a presented key.
func (h *ctrHost) pinKey(k providers.HostKey) {
	h.t.Helper()
	pk, err := ssh.ParsePublicKey(k.PublicKey)
	require.NoError(h.t, err)
	h.keys.pin(pk)
}

func ctrRequireReason(t *testing.T, err error, code string) *providers.Error {
	t.Helper()
	pe := providerCode(t, err)
	require.Equal(t, code, pe.Code, "error: %v", err)
	return pe
}

type ctrKeyRow struct{ user, fingerprint, comment string }

// fixtureKeys reads the keys the inventory must list from the image.
func (h *ctrHost) fixtureKeys() []ctrKeyRow {
	h.t.Helper()
	var rows []ctrKeyRow
	sc := bufio.NewScanner(strings.NewReader(h.mustExec("cat", "/root/fixture-keys.tsv")))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		require.Len(h.t, f, 3, sc.Text())
		rows = append(rows, ctrKeyRow{f[0], f[1], f[2]})
	}
	require.NoError(h.t, sc.Err())
	require.Len(h.t, rows, 4, "deploy ×2, nonl, root")
	return rows
}

func ctrSortRows(rows []ctrKeyRow) []ctrKeyRow {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].user != rows[j].user {
			return rows[i].user < rows[j].user
		}
		return rows[i].fingerprint < rows[j].fingerprint
	})
	return rows
}

func (h *ctrHost) sha(path string) string {
	h.t.Helper()
	return strings.Fields(h.mustExec("sha256sum", path))[0]
}

// connOf is the pooled connection behind a session of this provider.
func connOf(t *testing.T, s providers.Session) *Conn {
	t.Helper()
	ls, ok := s.(*session)
	require.True(t, ok, "a linuxssh session")
	return ls.conn
}

func TestRealOpenSSH(t *testing.T) {
	images := ctrSelectedDistros(t)
	helper := ctrBuildHelper(t)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			h := startCtrHost(t, image, helper)
			prov, pool := h.newProvider()
			ctx := context.Background()

			// A-6: alice-svc's home holds only the root-owned .ssh (no /etc/skel files), and a re-run
			// removes a file alice-svc owns there (a .bashrc bash would source for every command).
			// A-3: the private copy of the helper the script checked and installed is gone.
			assert.Equal(t, ".ssh", strings.TrimSpace(h.mustExec("ls", "-A", "/var/lib/alice-svc")))
			h.mustExec("install", "-o", ServiceUser, "-g", ServiceUser, "-m", "0644", "/dev/null", "/var/lib/alice-svc/.bashrc")
			require.Contains(t, h.mustExec("sh", "-c", "cd /root/bundle && sh ./setup.sh"), "This server is ready for Alice.")
			assert.Equal(t, ".ssh", strings.TrimSpace(h.mustExec("ls", "-A", "/var/lib/alice-svc")))
			assert.Equal(t, "root:root 755", strings.TrimSpace(h.mustExec("stat", "-c", "%U:%G %a", "/var/lib/alice-svc")))
			assert.NotContains(t, h.mustExec("ls", "-A", "/var/lib/alice-helper"), "install.")

			// F-30: the first connection stops at the key exchange; the presented key is the
			// server's real key; no login happened.
			before := h.accepted()
			_, err := h.open(prov)
			_ = ctrRequireReason(t, err, "target.host_key_unconfirmed")
			first := h.lastObservation()
			assert.False(t, first.changed)
			assert.Equal(t, h.hostFingerprint(), first.key.Fingerprint)
			assert.Equal(t, "ssh-ed25519", first.key.Type)
			assert.Equal(t, before, h.accepted(), "no authentication before the fingerprint is confirmed")

			// The administrator confirms; the connection test reports the helper and the OS.
			h.pinKey(first.key)
			sess := h.mustOpen(prov)
			report, err := sess.TestConnection(ctx)
			require.NoError(t, err)
			assert.Equal(t, helperproto.Protocol, report.HelperProtocol)
			assert.Equal(t, h.osID, report.OS.ID)
			assert.Equal(t, first.key.Fingerprint, report.HostKey.Fingerprint)
			assert.Empty(t, report.Warnings, "sshd -T works through the real sudo")

			// An idle pooled connection is reused: real OpenSSH answers the keepalive probe
			// (with a request-failure reply, which still proves the connection alive), so no
			// second login reaches the server.
			conn := connOf(t, sess)
			logins := h.accepted()
			require.NoError(t, sess.Close())
			sess = h.mustOpen(prov)
			assert.Same(t, conn, connOf(t, sess), "the idle connection was reused, not redialed")
			assert.Equal(t, logins, h.accepted(), "no new login for a reused connection")

			// Exit criterion "inventory matches the seeded fixtures exactly": every fixture key with
			// its user, plus Alice's own key for alice-svc; nothing for noshell or linky.
			res, err := sess.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
			require.NoError(t, err)
			want := append(h.fixtureKeys(), ctrKeyRow{ServiceUser, h.platform, ""})
			var got []ctrKeyRow
			for _, k := range res.SSHKeys {
				got = append(got, ctrKeyRow{k.OSUser, k.Fingerprint, k.Comment})
				assert.NotContains(t, k.Flags, providers.FlagRootWithoutFrom, "the root key carries from=")
				if k.Comment == "ci@build" {
					assert.Equal(t, 3072, k.Bits)
					assert.NotContains(t, k.Flags, providers.FlagWeak)
				}
			}
			assert.Equal(t, ctrSortRows(want), ctrSortRows(got))
			assert.False(t, res.Partial)
			assert.True(t, res.SSHD.Read)
			assert.False(t, res.SSHD.KeysManagedElsewhere)
			assert.NotEmpty(t, res.HostKeys)
			// A-13: linky's authorized_keys leaves the home (a symlink to /etc/shadow): the helper
			// lists it as unsupported and Discover reports it with the user and the path.
			linky := false
			for _, w := range res.Warnings {
				if w.Code == helperproto.WarnUnsupportedPath && w.Params["user"] == "linky" {
					linky = linky || w.Params["path"] == "/home/linky/.ssh/authorized_keys"
				}
			}
			assert.True(t, linky, "the symlinked file of linky is reported, not read: %+v", res.Warnings)

			// The sudoers profile allows only the helper's linux subcommands.
			code, out := h.exec([]string{"sudo", "-n", "/bin/cat", "/etc/shadow"}, tcexec.WithUser(ServiceUser))
			assert.NotZero(t, code)
			assert.NotContains(t, out, "root:")
			code, _ = h.exec([]string{"sudo", "-n", helperproto.HelperPath, "nginx-dump"}, tcexec.WithUser(ServiceUser))
			assert.NotZero(t, code, "the linux profile has no nginx subcommands")

			// A-13: the helper refuses a path outside the candidate files, through the real sudo.
			c2, release, err := pool.Acquire(ctx, h.target, h.cfg, ctrSigner{h.signer})
			require.NoError(t, err)
			for _, path := range []string{"/etc/shadow", "/home/linky/.ssh/authorized_keys"} {
				cmd, err := CmdAuthKeysRead(path)
				require.NoError(t, err)
				r, err := c2.Run(ctx, cmd)
				require.NoError(t, err)
				_, err = DecodeHelper[helperproto.AuthKeysReadResponse](r, helperproto.SubAuthKeysRead)
				pe := ctrRequireReason(t, err, "ssh.helper_refused")
				assert.Equal(t, helperproto.CodePathNotAllowed, pe.Params["helper_code"], path)
				assert.NotContains(t, string(r.Stdout), "root:", path)
			}

			// A-1: with an absolute AuthorizedKeysFile pattern that points into the home, a user who
			// replaces ~/.ssh with a symlink to /root/.ssh gets neither a read nor a write of root's
			// file. sshd -T reads the file each time, so no reload is needed.
			rootFile := "/root/.ssh/authorized_keys"
			rootSHA := h.sha(rootFile)
			h.mustExec("sh", "-c", "cp -p /etc/ssh/sshd_config /root/sshd_config.orig && "+
				"sed -i '1i AuthorizedKeysFile /home/%u/.ssh/authorized_keys' /etc/ssh/sshd_config && sshd -t && "+
				"rm -rf /home/linky/.ssh && ln -s /root/.ssh /home/linky/.ssh")
			linkyFile := "/home/linky/.ssh/authorized_keys"
			readCmd, err := CmdAuthKeysRead(linkyFile)
			require.NoError(t, err)
			writeCmd, err := CmdAuthKeysWrite(linkyFile, rootSHA, uuid.New(), []byte("ssh-ed25519 AAAA attacker\n"))
			require.NoError(t, err)
			for _, cmd := range []HelperCommand{readCmd, writeCmd} {
				r, err := c2.Run(ctx, cmd)
				require.NoError(t, err)
				_, err = DecodeHelper[helperproto.AuthKeysReadResponse](r, cmd.Subcommand())
				pe := ctrRequireReason(t, err, "ssh.helper_refused")
				assert.Equal(t, helperproto.CodePathNotAllowed, pe.Params["helper_code"], cmd.Subcommand())
				assert.NotContains(t, string(r.Stdout), "root@bastion")
			}
			assert.Equal(t, rootSHA, h.sha(rootFile), "root's file is unchanged")
			h.mustExec("sh", "-c", "mv /root/sshd_config.orig /etc/ssh/sshd_config && sshd -t")
			release(true)

			// F-36: Alice's own key is never removed, and nothing is written.
			ownFile := "/var/lib/alice-svc/.ssh/authorized_keys"
			ownSHA := h.sha(ownFile)
			_, err = sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: ServiceUser,
				FilePath: ownFile, Fingerprint: h.platform, ProtectedFingerprints: []string{h.platform}}, ctrNoSteps{})
			_ = ctrRequireReason(t, err, "sshkey.own_key_protected")
			assert.Equal(t, ownSHA, h.sha(ownFile))
			assert.Equal(t, "root:root 644", strings.TrimSpace(h.mustExec("stat", "-c", "%U:%G %a", ownFile)))

			// F-37: adding to a file without a trailing newline starts a new line.
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			extra, err := ssh.NewSignerFromKey(priv)
			require.NoError(t, err)
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(extra.PublicKey()))) + " added@alice"
			nonl := "/home/nonl/.ssh/authorized_keys"
			oldNonl := h.mustExec("cat", nonl)
			require.False(t, strings.HasSuffix(oldNonl, "\n"), "the fixture has no trailing newline")
			res2, err := sess.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "nonl",
				FilePath: nonl, Line: line}, ctrNoSteps{})
			require.NoError(t, err)
			assert.True(t, res2.Changed)
			assert.True(t, res2.Verified)
			assert.Equal(t, oldNonl+"\n"+line+"\n", h.mustExec("cat", nonl))
			assert.Equal(t, "nonl:nonl 600", strings.TrimSpace(h.mustExec("stat", "-c", "%U:%G %a", nonl)), "owner and mode kept")

			// F-38: the file changes between Alice's read and write; the helper refuses the stale
			// write, Alice reads again and keeps the concurrent line.
			deployFile := "/home/deploy/.ssh/authorized_keys"
			var raced sync.Once
			hookCalls := 0
			beforeAuthKeysWrite = func(path string) {
				hookCalls++
				raced.Do(func() { h.mustExec("sh", "-c", "echo '# added by another admin' >> "+path) })
			}
			t.Cleanup(func() { beforeAuthKeysWrite = nil })
			var ciFP, laptopFP string
			for _, k := range h.fixtureKeys() {
				switch k.comment {
				case "ci@build":
					ciFP = k.fingerprint
				case "deploy@laptop":
					laptopFP = k.fingerprint
				}
			}
			require.NotEmpty(t, ciFP)
			require.NotEmpty(t, laptopFP)
			res3, err := sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
				FilePath: deployFile, Fingerprint: ciFP, ProtectedFingerprints: []string{h.platform}}, ctrNoSteps{})
			beforeAuthKeysWrite = nil
			require.NoError(t, err)
			assert.Equal(t, 2, hookCalls, "the stale write was refused and retried once")
			assert.Equal(t, 1, res3.Removed)
			assert.True(t, res3.Verified)
			after := h.mustExec("cat", deployFile)
			assert.Contains(t, after, "# added by another admin", "the concurrent change survived")
			assert.Contains(t, after, "deploy@laptop", "the other key is untouched")
			assert.NotContains(t, after, "ci@build")
			assert.Equal(t, "deploy:deploy 600", strings.TrimSpace(h.mustExec("stat", "-c", "%U:%G %a", deployFile)))

			// F-35: with AuthorizedKeysCommand the keys are still listed but not managed.
			h.mustExec("sh", "-c", "printf 'AuthorizedKeysCommand /bin/true\\nAuthorizedKeysCommandUser nobody\\n' >> /etc/ssh/sshd_config && sshd -t && pkill -HUP -o -x sshd")
			var res4 providers.DiscoveryResult
			require.Eventually(t, func() bool {
				res4, err = sess.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
				return err == nil && res4.SSHD.KeysManagedElsewhere
			}, 20*time.Second, 200*time.Millisecond, "sshd settings with AuthorizedKeysCommand are read")
			assert.NotEmpty(t, res4.SSHKeys)
			_, err = sess.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
				FilePath: deployFile, Fingerprint: laptopFP, ProtectedFingerprints: []string{h.platform}}, ctrNoSteps{})
			_ = ctrRequireReason(t, err, "ssh.keys_managed_elsewhere")
			assert.Contains(t, h.mustExec("cat", deployFile), "deploy@laptop", "nothing was removed")
			require.NoError(t, sess.Close())

			// F-31: new host keys; a new connection stops at the key exchange with the new key
			// recorded as changed, and no login reaches the server.
			oldFP := first.key.Fingerprint
			h.mustExec("sh", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && pkill -HUP -o -x sshd")
			newFP := h.hostFingerprint()
			require.NotEqual(t, oldFP, newFP)
			before = h.accepted()
			fresh, _ := h.newProvider() // a new pool: an idle connection opened before the rotation proves nothing
			var lastErr error
			require.Eventually(t, func() bool {
				_, lastErr = h.open(fresh) // sshd re-executes on SIGHUP: retry until it listens again
				var pe *providers.Error
				return lastErr != nil && errors.As(lastErr, &pe) && pe.Code == "target.host_key_changed"
			}, 20*time.Second, 200*time.Millisecond, "a changed host key is reported")
			pe := ctrRequireReason(t, lastErr, "target.host_key_changed")
			assert.Equal(t, oldFP, pe.Params["old_fingerprint"])
			assert.Equal(t, newFP, pe.Params["new_fingerprint"])
			changed := h.lastObservation()
			assert.True(t, changed.changed)
			assert.Equal(t, newFP, changed.key.Fingerprint)
			assert.Equal(t, before, h.accepted(), "no authentication with a changed host key")
		})
	}
}
