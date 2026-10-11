//go:build systemd

package nginx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// The real-systemd Nginx job (spec §22.3, R38 item 16; make test-systemd, nightly.yml): what
// TestRealNginx checks against test shims, here against Ubuntu 22.04 with systemd as PID 1
// (test/images/systemd): systemd starts sshd and Nginx from their units, "systemctl reload nginx"
// and "systemctl is-active nginx" are systemd's own, and "nginx -t" is the distribution's binary.
// The container runs privileged with the host's cgroup namespace (what systemd in a container
// needs); when the engine refuses that, or systemd does not boot, the test fails with the engine's
// or systemd's message and the job is recorded as NOT RUN for that machine (it stays in nightly).
//
//	make test-systemd     (links the helper checksums in, as make test-ssh does)
//
// Only the container created here (alice-sysd-<random>) is touched; t.Cleanup removes it.

const (
	sdDir      = "/etc/ssl/alice"
	sdCert     = sdDir + "/default.crt"
	sdKey      = sdDir + "/default.key"
	sdNeighbor = sdDir + "/neighbour.crt"
	sdSite     = "/etc/nginx/sites-available/default"
)

func TestRealSystemdNginx(t *testing.T) {
	helper, verified := rnHelper(t)
	h := startSystemdHost(t, helper, verified)

	// The default site gets TLS on 443 with a test pair.
	old := h.leaf("default.example.test", pki.ECDSA256)
	h.sh("install -d -m 0755 -o root -g root " + sdDir)
	h.write(sdCert, old.FullchainPEM, "root:root", 0o644)
	h.write(sdKey, old.KeyPEM, "root:root", 0o600)
	h.leaves[sdCert] = old
	h.sh(`sed -i 's#^\(\s*listen \[::\]:80 default_server;\)$#\1\n\tlisten 443 ssl default_server;\n\tssl_certificate ` + sdCert + `;\n\tssl_certificate_key ` + sdKey + `;#' ` + sdSite)
	require.Contains(t, h.sh("cat "+sdSite), "ssl_certificate_key "+sdKey, "TLS enabled on the default site")
	mainPID := h.systemdMainPID()
	h.sh("systemctl reload nginx")
	h.settledServed(h.ip, 443, "default.example.test", "", pki.Fingerprint(old.Cert), "the default site's first pair")
	require.Equal(t, mainPID, h.systemdMainPID(), "systemd reloaded nginx (same main process)")

	t.Run("discovery", func(t *testing.T) {
		h.t = t
		res, locs := h.discover(false)
		c, ok := locs[sdCert]
		require.True(t, ok, "the default site's pair is discovered: %+v", res)
		assert.Equal(t, sdKey, c.Location.KeyPath)
		assert.Equal(t, pki.Fingerprint(old.Cert), firstLeaf(t, string(c.PEMChain)))
		require.NotEmpty(t, c.Location.Servers, "the default server block uses it")
	})

	t.Run("deploy_committed_through_systemd", func(t *testing.T) {
		h.t = t
		before := h.reloads()
		c := h.location(sdCert)
		l := h.leaf("default.example.test", pki.ECDSA256)
		req := h.request(c, l, true)
		out, log, err := h.deploy(nil, req)
		// The same outcome and steps as TestRealNginx's deploy_verified_ecdsa_chain under the shims.
		h.committed(out, err, req, l, "remote")
		assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:started", "verify:ok"}, log)
		h.settledServed(h.ip, 443, "default.example.test", "", pki.Fingerprint(l.Cert), "the new leaf")
		assert.Equal(t, pki.Fingerprint(l.Cert), h.dialVerified(443, "default.example.test"), "the TLS handshake on 443 presents the new pair")
		assert.Equal(t, "active", strings.TrimSpace(h.sh("systemctl is-active nginx")), "nginx is active after the reload")
		assert.Equal(t, before+1, h.reloads(), "the helper reloaded nginx through systemd")
		assert.Equal(t, mainPID, h.systemdMainPID(), "a reload, not a restart")
		assert.Equal(t, "root:root 600", h.stat(sdKey))
	})

	t.Run("nginx_t_fails_restored", func(t *testing.T) {
		h.t = t
		// A neighbour site on 8443 uses a certificate for the key the default site now has (two
		// certificates, one key file: the F-01 layout of TestRealNginx), so a new pair for the default
		// site leaves the neighbour without its key and nginx -t fails.
		cur := h.leaves[sdCert]
		neighbour := h.ca.Issue(pki.Opts{CommonName: "neighbour.example.test", SANs: []string{"neighbour.example.test"}, Key: cur.Key}, time.Now())
		h.write(sdNeighbor, neighbour.FullchainPEM, "root:root", 0o644)
		h.write("/etc/nginx/sites-enabled/alice-neighbour", []byte("server {\n\tlisten 8443 ssl;\n\tserver_name neighbour.example.test;\n"+
			"\tssl_certificate "+sdNeighbor+";\n\tssl_certificate_key "+sdKey+";\n}\n"), "root:root", 0o644)
		h.sh("systemctl reload nginx")
		h.settledServed(h.ip, 8443, "neighbour.example.test", "", pki.Fingerprint(neighbour.Cert), "the neighbour")
		same := h.unchangedFiles(sdCert)
		neighbourSame := h.fileSHA(sdNeighbor)
		c := h.location(sdCert)
		req := h.request(c, h.leaf("default.example.test", pki.ECDSA256), true)
		out, _, err := h.deploy(nil, req)
		// The outcome of TestRealNginx's F-01_key_mismatch_real_nginx_t: nginx -t refuses the new key
		// for the neighbour's certificate, the helper restores the old pair and reloads it.
		require.NoError(t, err)
		require.Equal(t, providers.DeployRolledBack, out.Result, "%+v", out)
		assert.Equal(t, providers.PhaseRestored, out.Phase)
		assert.Equal(t, reasonKeyMismatch, out.Reason, "%+v", out)
		assert.Equal(t, helperproto.StepConfigTest, out.FailedStep)
		assert.Equal(t, providers.ConfigErrKeyMismatch, out.Error)
		assert.Equal(t, helperproto.StepConfigTest, out.CauseStep)
		assert.Equal(t, "remote", out.Verified, "the previous certificate is verified again")
		same()
		assert.Equal(t, neighbourSame, h.fileSHA(sdNeighbor))
		h.settledServed(h.ip, 443, "default.example.test", "", pki.Fingerprint(cur.Cert), "the previous pair is served")
		h.settledServed(h.ip, 8443, "neighbour.example.test", "", pki.Fingerprint(neighbour.Cert), "the neighbour")
		assert.Equal(t, "active", strings.TrimSpace(h.sh("systemctl is-active nginx")))
		assert.Empty(t, h.staged(), "no staged file is left behind (S2)")
	})
	h.t = t
}

// startSystemdHost builds test/images/systemd/ubuntu22.Dockerfile (host network: the build installs
// packages) and starts it privileged with the host's cgroups, waits until systemd reports the boot
// finished, then prepares the host with the nginx profile's setup script as TestRealNginx does.
func startSystemdHost(t *testing.T, helper string, verified bool) *rnHost {
	t.Helper()
	ctx := context.Background()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := "alice-sysd-" + hex.EncodeToString(suffix)
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:              filepath.Join(rnRepoRoot(), "test", "images"),
				Dockerfile:           "systemd/ubuntu22.Dockerfile",
				Repo:                 "alice-test/systemd-ubuntu22",
				Tag:                  "phase8",
				KeepImage:            true,
				BuildOptionsModifier: func(o *client.ImageBuildOptions) { o.NetworkMode = "host" },
			},
			Name:         name,
			ExposedPorts: []string{"22/tcp"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Privileged = true
				hc.CgroupnsMode = container.CgroupnsModeHost
				hc.Binds = append(hc.Binds, "/sys/fs/cgroup:/sys/fs/cgroup:rw")
				hc.Tmpfs = map[string]string{"/run": "", "/run/lock": ""}
			},
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err, "the engine must start a privileged container with the host's cgroups (else: NOT RUN on this machine)")

	ip, err := ctr.ContainerIP(ctx)
	require.NoError(t, err)
	h := newRNHost(t, "systemd-ubuntu22", ctr, ip)
	var state string
	booted := assert.Eventually(t, func() bool {
		_, out := h.exec("systemctl", "is-system-running")
		state = strings.TrimSpace(out)
		return state == "running" || state == "degraded"
	}, 3*time.Minute, 500*time.Millisecond, "systemd finishes booting")
	if !booted {
		_, out := h.exec("sh", "-c", "systemctl --failed --no-pager; journalctl -b --no-pager | tail -50")
		t.Fatalf("systemd did not boot (state %q):\n%s", state, out)
	}
	if state == "degraded" {
		_, out := h.exec("systemctl", "--failed", "--no-pager")
		t.Logf("systemd is degraded (units a container cannot run):\n%s", out)
	}
	for _, unit := range []string{"ssh", "nginx"} {
		require.Equal(t, "active", strings.TrimSpace(h.sh("systemctl is-active "+unit+" || true")), "%s is started by its unit", unit)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	require.NoError(t, err, "the job reaches the container at %s directly: Docker's bridge network must be routable from this host", ip)
	_ = conn.Close()
	t.Logf("systemd %s, %s", strings.Fields(h.sh("systemctl --version"))[1], strings.TrimSpace(h.sh("/usr/sbin/nginx -v 2>&1")))

	h.runSetupScript(helper, verified)
	h.connect(verified)
	return h
}

// systemdMainPID is the main process systemd tracks for nginx.service.
func (h *rnHost) systemdMainPID() string {
	h.t.Helper()
	return strings.TrimSpace(h.sh("systemctl show -p MainPID --value nginx"))
}

// reloads counts the reloads systemd ran for nginx.service (its journal).
func (h *rnHost) reloads() int {
	h.t.Helper()
	return strings.Count(h.sh("journalctl -u nginx --no-pager -o cat"), "Reloaded ")
}
