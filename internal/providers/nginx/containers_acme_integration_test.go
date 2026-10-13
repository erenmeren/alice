//go:build integration || systemd

package nginx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// The HTTP-01 webroot (protocol 7, ACME Task 7) on the real distribution: the administrator's
// preparation exactly as docs/nginx-host-preparation.md gives it (directories, the three-line location
// block in a port-80 server block, a reload they run themselves), then Alice publishes a token file
// through the real sudo and helper, fetches it over HTTP from this host through Nginx, replaces it and
// removes it. The refusals run against the real kernel: a link at the token name, a linked or
// world-writable challenge directory, a directory owned by another user, a token outside the
// vocabulary and an oversize body. The host is left as found (no file, no configuration).

const (
	rnACMEConf = "/etc/nginx/conf.d/alice-acme-test.conf"
	rnACMEHost = "acme-http01.example.test"
)

// rnACMESnippet is the guide's location block in a port-80 server block for the test's name, next to the two
// things the guide warns about: a "deny dot files" pattern block (^~ must win over it) and the HTTPS redirect,
// moved into location / as the guide says.
const rnACMESnippet = `server {
    listen 80;
    server_name ` + rnACMEHost + `;
    location ~ /\. {
        deny all;
    }
    location / {
        return 301 https://$host$request_uri;
    }
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/alice-acme;
    }
}
`

// rnACMEPrepare is the guide's directory preparation.
const rnACMEPrepare = `mkdir -p /var/www/alice-acme/.well-known/acme-challenge
chown root:root /var/www /var/www/alice-acme /var/www/alice-acme/.well-known /var/www/alice-acme/.well-known/acme-challenge
chmod 0755 /var/www /var/www/alice-acme /var/www/alice-acme/.well-known /var/www/alice-acme/.well-known/acme-challenge
`

func rnToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

func rnKeyAuth(token string) []byte {
	return []byte(token + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
}

// fetchChallenge fetches the token's URL from this host through the container's Nginx on port 80
// with the test name as Host (no proxy, no redirect).
func (h *rnHost) fetchChallenge(token string) (int, string) {
	h.t.Helper()
	return h.fetchPath(helperproto.ACMEChallengeURLPath(token))
}

// fetchPath fetches a path of the test name on port 80 (no proxy, no redirect followed).
func (h *rnHost) fetchPath(path string) (int, string) {
	h.t.Helper()
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://"+net.JoinHostPort(h.ip, "80")+path, nil)
	require.NoError(h.t, err)
	req.Host = rnACMEHost
	resp, err := client.Do(req)
	require.NoError(h.t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	require.NoError(h.t, err)
	return resp.StatusCode, string(b)
}

func helperCode(t *testing.T, err error) string {
	t.Helper()
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "ssh.helper_refused", pe.Code, "%v", err)
	return pe.Params["helper_code"]
}

func (h *rnHost) testACMEHTTP01(t *testing.T) {
	ctx := context.Background()
	s, err := h.lp.Open(ctx, h.ref(), rnSigner{h.signer}, providers.Env{Clock: clock.Real{}, HostKeys: h.hk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	conn, ok := linuxssh.ConnOf(s)
	require.True(t, ok)
	t.Cleanup(func() {
		_, _ = h.exec("sh", "-c", "rm -f "+rnACMEConf+" && rm -rf /var/www/alice-acme")
	})
	tok := rnToken(t)

	// Before the administrator prepared anything: put needs the directory (and never creates it),
	// rm has nothing to remove.
	code, _ := h.exec("test", "-e", "/var/www/alice-acme")
	require.NotZero(t, code, "the host starts without the webroot")
	err = conn.PublishHTTP01Token(ctx, tok, rnKeyAuth(tok))
	assert.Equal(t, helperproto.CodeNotFound, helperCode(t, err))
	removed, err := conn.RemoveHTTP01Token(ctx, tok)
	require.NoError(t, err)
	assert.False(t, removed)
	code, _ = h.exec("test", "-e", "/var/www/alice-acme")
	assert.NotZero(t, code, "the helper never creates a directory")

	// The administrator's preparation, as the guide says.
	h.sh(rnACMEPrepare)
	h.write(rnACMEConf, []byte(rnACMESnippet), "root:root", 0o644)
	h.reloadNginx()
	status, _ := h.fetchChallenge(tok)
	assert.Equal(t, http.StatusNotFound, status, "nothing published yet")
	status, _ = h.fetchPath("/index.html")
	assert.Equal(t, http.StatusMovedPermanently, status, "everything else is still redirected")

	// put -> fetched through Nginx -> replaced -> rm.
	require.NoError(t, conn.PublishHTTP01Token(ctx, tok, rnKeyAuth(tok)))
	status, body := h.fetchChallenge(tok)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, string(rnKeyAuth(tok)), body, "Nginx serves exactly the key authorization")
	assert.Equal(t, "root:root 644", h.stat(helperproto.ACMEChallengePath(tok)))
	other := []byte(tok + "." + strings.Repeat("Z", 43))
	require.NoError(t, conn.PublishHTTP01Token(ctx, tok, other))
	_, body = h.fetchChallenge(tok)
	assert.Equal(t, string(other), body)
	assert.Equal(t, tok, strings.TrimSpace(h.sh("ls -A "+helperproto.ACMEChallengeDir)), "one file in the directory, no temporary file left")
	removed, err = conn.RemoveHTTP01Token(ctx, tok)
	require.NoError(t, err)
	assert.True(t, removed)
	status, _ = h.fetchChallenge(tok)
	assert.Equal(t, http.StatusNotFound, status)
	removed, err = conn.RemoveHTTP01Token(ctx, tok)
	require.NoError(t, err)
	assert.False(t, removed, "a missing file is success")
	assert.Empty(t, strings.TrimSpace(h.sh("ls -A "+helperproto.ACMEChallengeDir)))

	// A token that starts with "-" (base64url) goes through sudo and the helper as --token's value.
	dash := "-" + tok[1:]
	require.NoError(t, conn.PublishHTTP01Token(ctx, dash, rnKeyAuth(dash)))
	_, body = h.fetchChallenge(dash)
	assert.Equal(t, string(rnKeyAuth(dash)), body)
	removed, err = conn.RemoveHTTP01Token(ctx, dash)
	require.NoError(t, err)
	assert.True(t, removed)

	// A link at the token name (to /etc/shadow): refused, the link and its target untouched.
	shadow := h.fileSHA("/etc/shadow")
	h.sh("ln -s /etc/shadow " + helperproto.ACMEChallengePath(tok))
	err = conn.PublishHTTP01Token(ctx, tok, rnKeyAuth(tok))
	assert.Equal(t, helperproto.CodeNotRegularFile, helperCode(t, err))
	_, err = conn.RemoveHTTP01Token(ctx, tok)
	assert.Equal(t, helperproto.CodeNotRegularFile, helperCode(t, err))
	assert.Equal(t, "/etc/shadow", strings.TrimSpace(h.sh("readlink "+helperproto.ACMEChallengePath(tok))))
	assert.Equal(t, shadow, h.fileSHA("/etc/shadow"))
	h.sh("rm " + helperproto.ACMEChallengePath(tok))

	// Directory refusals: each is undone before the next.
	for _, c := range []struct {
		name, breakIt, undo, code string
	}{
		{"linked challenge directory", "mv /var/www/alice-acme/.well-known/acme-challenge /var/www/alice-acme/.well-known/real && ln -s real /var/www/alice-acme/.well-known/acme-challenge",
			"rm /var/www/alice-acme/.well-known/acme-challenge && mv /var/www/alice-acme/.well-known/real /var/www/alice-acme/.well-known/acme-challenge", helperproto.CodePathNotAllowed},
		{"linked webroot", "mv /var/www/alice-acme /var/www/alice-acme-real && ln -s /var/www/alice-acme-real /var/www/alice-acme",
			"rm /var/www/alice-acme && mv /var/www/alice-acme-real /var/www/alice-acme", helperproto.CodePathNotAllowed},
		{"world-writable challenge directory", "chmod 0777 " + helperproto.ACMEChallengeDir, "chmod 0755 " + helperproto.ACMEChallengeDir, helperproto.CodeInsecurePermissions},
		{"challenge directory owned by another user", "chown " + linuxssh.ServiceUser + " " + helperproto.ACMEChallengeDir,
			"chown root " + helperproto.ACMEChallengeDir, helperproto.CodeInsecurePermissions},
		{"group-writable .well-known", "chmod 0775 /var/www/alice-acme/.well-known", "chmod 0755 /var/www/alice-acme/.well-known", helperproto.CodeInsecurePermissions},
	} {
		h.sh(c.breakIt)
		err = conn.PublishHTTP01Token(ctx, tok, rnKeyAuth(tok))
		assert.Equal(t, c.code, helperCode(t, err), "put: %s", c.name)
		_, err = conn.RemoveHTTP01Token(ctx, tok)
		assert.Equal(t, c.code, helperCode(t, err), "rm: %s", c.name)
		h.sh(c.undo)
		assert.Empty(t, strings.TrimSpace(h.sh("ls -A "+helperproto.ACMEChallengeDir)), c.name)
	}

	// Raw lines through the real sudo (Alice's constructors refuse these values): the exit codes.
	asSvc := []tcexec.ProcessOption{tcexec.WithUser(linuxssh.ServiceUser)}
	raw := func(stdin, args string) (int, string) {
		return h.execAs(asSvc, "sh", "-c", stdin+"sudo -n "+helperproto.HelperPath+" "+args)
	}
	for _, c := range []struct {
		stdin, args string
		exit        int
		code        string
	}{
		{"", "acme-challenge-put --token ../../../../../../etc/cron.d/x </dev/null", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"", "acme-challenge-rm --token " + strings.Repeat("a", 22) + "/../../../../../etc/passwd", helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"", "acme-challenge-rm --token " + strings.Repeat("a", 129), helperproto.ExitRefused, helperproto.CodeInvalidArgument},
		{"head -c 600 /dev/zero | tr '\\0' a | ", "acme-challenge-put --token " + tok, helperproto.ExitRefused, helperproto.CodeTooLarge},
		{"printf '%s' 'x.y' | ", "acme-challenge-put --token " + tok, helperproto.ExitRefused, helperproto.CodeBadContent},
		{"", "acme-challenge-rm --token " + tok + " --token " + tok, helperproto.ExitRefused, helperproto.CodeUsage},
	} {
		exit, out := raw(c.stdin, c.args)
		assert.Equal(t, c.exit, exit, "%s: %s", c.args, out)
		assert.Contains(t, out, `"code":"`+c.code+`"`, c.args)
	}
	code, _ = h.exec("sh", "-c", "test -e /etc/cron.d/x || test -e '/var/www/alice-acme/.well-known/acme-challenge/"+strings.Repeat("a", 129)+"'")
	assert.NotZero(t, code)
	assert.Empty(t, strings.TrimSpace(h.sh("ls -A "+helperproto.ACMEChallengeDir)), "no refusal left a file")

	// Leave the host as found: the test's configuration and directory go, Nginx reloads.
	h.sh("rm -f " + rnACMEConf + " && rm -rf /var/www/alice-acme")
	h.reloadNginx()
}
