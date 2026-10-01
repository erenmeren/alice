package linuxssh

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

const goldenSudoersHead = `# Managed by Alice. Do not edit. Validate with: visudo -cf /etc/sudoers.d/alice
Defaults:alice-svc !requiretty
Defaults:alice-svc !lecture
Defaults:alice-svc env_reset
Defaults:alice-svc secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:alice-svc log_output

Cmnd_Alias ALICE_COMMON = \
    /usr/local/libexec/alice-helper sshd-dump, \
    /usr/local/libexec/alice-helper hostkeys, \
    /usr/local/libexec/alice-helper cleanup --op *, \
    /usr/local/libexec/alice-helper authkeys-list, \
    /usr/local/libexec/alice-helper authkeys-read /*, \
    /usr/local/libexec/alice-helper authkeys-write /* --expect-sha256 * --op *
`

const goldenSudoersLinux = goldenSudoersHead + `
alice-svc ALL=(root) NOPASSWD: ALICE_COMMON
`

const goldenSudoersNginx = goldenSudoersHead + `
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-reload, \
    /usr/local/libexec/alice-helper stat *, \
    /usr/local/libexec/alice-helper read-cert *, \
    /usr/local/libexec/alice-helper install-cert *, \
    /usr/local/libexec/alice-helper backup *, \
    /usr/local/libexec/alice-helper restore *

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_NGINX_ONLY
`

func TestSudoersProfilesMatchTheSpec(t *testing.T) {
	linux, err := Sudoers("linux")
	require.NoError(t, err)
	assert.Equal(t, goldenSudoersLinux, linux)
	nginx, err := Sudoers("nginx")
	require.NoError(t, err)
	assert.Equal(t, goldenSudoersNginx, nginx)
	assert.NotContains(t, linux, "nginx", "a generic Linux target never gains nginx subcommands")
	_, err = Sudoers("root")
	assert.Error(t, err)
}

func TestAuthorizedKeysLine(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform"
	assert.Equal(t, "no-agent-forwarding,no-port-forwarding,no-X11-forwarding "+key, AuthorizedKeysLine(key, ""))
	assert.Equal(t, `from="10.0.0.5",no-agent-forwarding,no-port-forwarding,no-X11-forwarding `+key,
		AuthorizedKeysLine(key, "10.0.0.5"))
	assert.Equal(t, `from="10.0.0.0/8,2001:db8::/32",no-agent-forwarding,no-port-forwarding,no-X11-forwarding `+key,
		AuthorizedKeysLine(key, "10.0.0.0/8,2001:db8::/32"))
	// A from value that could break out of the quotes is dropped, never embedded.
	assert.Equal(t, "no-agent-forwarding,no-port-forwarding,no-X11-forwarding "+key,
		AuthorizedKeysLine(key, `1.2.3.4",command="sh`))
}

func TestSetupScriptLinux(t *testing.T) {
	line := `from="10.0.0.5",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform`
	script, err := SetupScript("linux", line)
	require.NoError(t, err)
	want := `#!/bin/sh
# Prepares this server for Alice (profile: linux). Run it as root in the directory that
# holds alice-helper from the Alice bundle. Running it again is safe.
set -eu
umask 077
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script as root." >&2
    exit 1
fi
if [ ! -f ./alice-helper ]; then
    echo "Copy alice-helper from the Alice bundle into this directory first." >&2
    exit 1
fi
install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root ./alice-helper /usr/local/libexec/alice-helper
if ! id alice-svc >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/alice-svc --shell /bin/bash alice-svc
fi
usermod -p '*' alice-svc
install -d -m 0700 -o alice-svc -g alice-svc /var/lib/alice-svc/.ssh
printf '%s\n' '` + line + `' > /var/lib/alice-svc/.ssh/authorized_keys
chown alice-svc:alice-svc /var/lib/alice-svc/.ssh/authorized_keys
chmod 0600 /var/lib/alice-svc/.ssh/authorized_keys
cat > /etc/sudoers.d/.alice.tmp <<'ALICE_SUDOERS'
` + goldenSudoersLinux + `ALICE_SUDOERS
chmod 0440 /etc/sudoers.d/.alice.tmp
visudo -cf /etc/sudoers.d/.alice.tmp
mv /etc/sudoers.d/.alice.tmp /etc/sudoers.d/alice
install -d -m 0700 -o root -g root /var/lib/alice-helper /var/lib/alice-helper/backups
echo "This server is ready for Alice."
`
	assert.Equal(t, want, script)

	nginx, err := SetupScript("nginx", line)
	require.NoError(t, err)
	assert.Contains(t, nginx, "(profile: nginx)")
	assert.Contains(t, nginx, goldenSudoersNginx)
}

func TestSetupScriptRefusesLinesThatCouldBreakTheScript(t *testing.T) {
	for _, bad := range []string{"", "ssh-ed25519 AAAA x'; rm -rf / #", "ssh-ed25519 AAAA\nrm -rf /", "ssh-ed25519 AAAA \x00"} {
		_, err := SetupScript("linux", bad)
		assert.Error(t, err, "%q", bad)
	}
	_, err := SetupScript("windows", "ssh-ed25519 AAAA x")
	assert.Error(t, err)
	assert.False(t, strings.Contains(goldenSudoersLinux, "ALICE_SUDOERS"), "the here-document marker never appears in sudoers")
}

// sudoGlob is sudo's argument match (fnmatch without FNM_PATHNAME): '*' matches any run of
// characters, slashes and spaces included; everything else is literal. The sudoers lines use no
// other wildcard.
func sudoGlob(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if sudoGlob(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	return s != "" && s[0] == pattern[0] && sudoGlob(pattern[1:], s[1:])
}

// sudoersPatterns returns the argument patterns of the helper lines of a sudoers profile.
func sudoersPatterns(t *testing.T, profile string) []string {
	t.Helper()
	text, err := Sudoers(profile)
	require.NoError(t, err)
	var out []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(l), `\`), " ")
		l = strings.TrimSuffix(l, ",")
		if args, ok := strings.CutPrefix(l, "/usr/local/libexec/alice-helper "); ok {
			out = append(out, args)
		}
	}
	return out
}

// sudoArgs is what sudo matches for a command line: the helper arguments after the remote shell
// removed the single quotes.
func sudoArgs(t *testing.T, cmd HelperCommand) string {
	t.Helper()
	line, ok := strings.CutPrefix(cmd.Line(), "sudo -n /usr/local/libexec/alice-helper ")
	require.True(t, ok, "%q runs through sudo", cmd.Line())
	return strings.ReplaceAll(line, "'", "")
}

// D12: every privileged command line the builders emit matches exactly one sudoers line of the
// linux profile, and nothing else (more arguments, other shapes) does.
func TestSudoersMatchesEveryBuiltCommand(t *testing.T) {
	op := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000ff")
	read, err := CmdAuthKeysRead("/home/deploy/.ssh/authorized_keys")
	require.NoError(t, err)
	write, err := CmdAuthKeysWrite("/home/deploy/.ssh/authorized_keys", helperproto.AbsentSHA256, op, []byte("x\n"))
	require.NoError(t, err)
	write2, err := CmdAuthKeysWrite("/root/.ssh/authorized_keys", strings.Repeat("ab", 32), op, nil)
	require.NoError(t, err)
	cleanup, err := CmdCleanup(op)
	require.NoError(t, err)
	patterns := sudoersPatterns(t, "linux")
	require.Len(t, patterns, 6)
	for _, cmd := range []HelperCommand{CmdSSHDDump(), CmdHostKeys(), CmdAuthKeysList(), read, write, write2, cleanup} {
		args := sudoArgs(t, cmd)
		n := 0
		for _, p := range patterns {
			if sudoGlob(p, args) {
				n++
			}
		}
		assert.Equal(t, 1, n, "%q matches exactly one sudoers line", args)
	}
	assert.False(t, strings.HasPrefix(CmdVersion().Line(), "sudo"), "version runs without sudo and is not in sudoers")
	for _, bad := range []string{
		"authkeys-list --all", "sshd-dump -f /tmp/x", "hostkeys x", "authkeys-read relative/path",
		"cleanup /var/lib/alice-helper", "authkeys-write /x --op y", "version", "",
	} {
		for _, p := range patterns {
			assert.False(t, sudoGlob(p, bad), "%q must not match %q", bad, p)
		}
	}
}
