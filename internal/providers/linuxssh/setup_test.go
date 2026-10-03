package linuxssh

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
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
    /usr/local/libexec/alice-helper authkeys-write /* --expect-sha256 * --content-sha256 * --op *
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

// wantOptions is SEC-082 plus no-pty and no-user-rc.
const wantOptions = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc"

func TestAuthorizedKeysLine(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform"
	assert.Equal(t, wantOptions+" "+key, AuthorizedKeysLine(key, ""))
	assert.Equal(t, `from="10.0.0.5",`+wantOptions+" "+key, AuthorizedKeysLine(key, "10.0.0.5"))
	assert.Equal(t, `from="10.0.0.0/8,2001:db8::/32",`+wantOptions+" "+key,
		AuthorizedKeysLine(key, "10.0.0.0/8,2001:db8::/32"))
	// A from value that could break out of the quotes is refused: no line at all, never a line
	// without the restriction the administrator asked for.
	for _, bad := range []string{`1.2.3.4",command="sh`, "alice.example.com", "10.0.0.1 ", strings.Repeat("1", 513)} {
		assert.Error(t, ValidateFrom(bad), "%q", bad)
		assert.Empty(t, AuthorizedKeysLine(key, bad), "%q", bad)
	}
	assert.NoError(t, ValidateFrom(""))
	assert.NoError(t, ValidateFrom("!10.0.0.9,10.0.0.*"))
	_, err := SetupScript("linux", AuthorizedKeysLine(key, "bad host"), true)
	assert.Error(t, err, "the script refuses the empty line of a refused from=")
}

// goldenUnverified is the helper check of a build without checksums (tests, go build without make).
const goldenUnverified = `# This Alice build has no alice-helper checksums (it was built without "make helper"),
# so the helper below is installed without checking it.
echo "Warning: this Alice build cannot verify alice-helper (development build without checksums)." >&2
`

func TestSetupScriptLinux(t *testing.T) {
	line := `from="10.0.0.5",` + wantOptions + ` ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform`
	script, err := SetupScript("linux", line, true)
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
` + goldenUnverified + `install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root ./alice-helper /usr/local/libexec/alice-helper
if ! id alice-svc >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/alice-svc --shell /bin/bash alice-svc
fi
if [ "$(getent passwd alice-svc | cut -d: -f6)" != /var/lib/alice-svc ]; then
    echo "The user alice-svc exists with a home directory other than /var/lib/alice-svc. Fix or remove it first." >&2
    exit 1
fi
usermod -p '*' alice-svc
chown -h root:root /var/lib/alice-svc
chmod 0755 /var/lib/alice-svc
rm -rf /var/lib/alice-svc/.ssh
install -d -m 0755 -o root -g root /var/lib/alice-svc/.ssh
t=$(mktemp /var/lib/alice-svc/.ssh/.ak.XXXXXX)
printf '%s\n' '` + line + `' >"$t"
chmod 0644 "$t"
mv -f "$t" /var/lib/alice-svc/.ssh/authorized_keys
cat > /etc/sudoers.d/.alice.tmp <<'ALICE_SUDOERS'
` + goldenSudoersLinux + `ALICE_SUDOERS
chmod 0440 /etc/sudoers.d/.alice.tmp
visudo -cf /etc/sudoers.d/.alice.tmp
mv /etc/sudoers.d/.alice.tmp /etc/sudoers.d/alice
install -d -m 0700 -o root -g root /var/lib/alice-helper /var/lib/alice-helper/backups
echo "This server is ready for Alice."
`
	assert.Equal(t, want, script)

	nginx, err := SetupScript("nginx", line, true)
	require.NoError(t, err)
	assert.Contains(t, nginx, "(profile: nginx)")
	assert.Contains(t, nginx, goldenSudoersNginx)
}

func TestSetupScriptRefusesLinesThatCouldBreakTheScript(t *testing.T) {
	for _, bad := range []string{"", "ssh-ed25519 AAAA x'; rm -rf / #", "ssh-ed25519 AAAA\nrm -rf /", "ssh-ed25519 AAAA \x00"} {
		_, err := SetupScript("linux", bad, true)
		assert.Error(t, err, "%q", bad)
	}
	_, err := SetupScript("windows", "ssh-ed25519 AAAA x", true)
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

// A re-run must not let alice-svc redirect root's writes (a symlink planted in its own home): the
// home and .ssh become root's, .ssh is recreated rather than reused (rm never follows links), the
// key is written to a fresh mktemp file and renamed into place, and nothing is ever handed to
// alice-svc with chown.
func TestSetupScriptNeverWritesThroughTheServiceUser(t *testing.T) {
	for _, profile := range []string{"linux", "nginx"} {
		script, err := SetupScript(profile, wantOptions+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", true)
		require.NoError(t, err)
		assert.NotContains(t, script, "chown alice-svc")
		assert.NotContains(t, script, "-o alice-svc")
		assert.NotContains(t, script, "> /var/lib/alice-svc", "no redirection onto a path alice-svc controlled")
		order := []string{
			"chown -h root:root /var/lib/alice-svc\n",
			"chmod 0755 /var/lib/alice-svc\n",
			"rm -rf /var/lib/alice-svc/.ssh\n",
			"install -d -m 0755 -o root -g root /var/lib/alice-svc/.ssh\n",
			"t=$(mktemp /var/lib/alice-svc/.ssh/.ak.XXXXXX)\n",
			`>"$t"` + "\n",
			"mv -f \"$t\" /var/lib/alice-svc/.ssh/authorized_keys\n",
		}
		last := -1
		for _, step := range order {
			i := strings.Index(script, step)
			require.GreaterOrEqual(t, i, 0, "%q missing", step)
			assert.Greater(t, i, last, "%q out of order", step)
			last = i
		}
		assert.Contains(t, script, "getent passwd alice-svc | cut -d: -f6")
	}
}

// withHelperSums sets the link-time helper checksums for one test.
func withHelperSums(t *testing.T, amd64, arm64 string) {
	t.Helper()
	oldAMD64, oldARM64 := helperSHA256LinuxAMD64, helperSHA256LinuxARM64
	helperSHA256LinuxAMD64, helperSHA256LinuxARM64 = amd64, arm64
	t.Cleanup(func() { helperSHA256LinuxAMD64, helperSHA256LinuxARM64 = oldAMD64, oldARM64 })
}

// R37 item 2: a build that knows the checksums of its helpers (make build after make helper)
// makes the setup script refuse a helper that is not the one of this Alice version, before it
// installs anything.
func TestSetupScriptVerifiesTheHelperChecksum(t *testing.T) {
	amd64, arm64 := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	withHelperSums(t, amd64, arm64)
	script, err := SetupScript("linux", wantOptions+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", false)
	require.NoError(t, err, "a build with checksums needs no permission to skip the check")
	assert.NotContains(t, script, "cannot verify")
	assert.Contains(t, script, `command -v sha256sum >/dev/null || { echo "sha256sum (coreutils) is required." >&2; exit 1; }`+"\n")
	assert.Contains(t, script, "    x86_64) helper_sha256="+amd64+" ;;\n")
	assert.Contains(t, script, "    aarch64) helper_sha256="+arm64+" ;;\n")
	assert.Contains(t, script, `printf '%s  ./alice-helper\n' "$helper_sha256" | sha256sum -c - >/dev/null 2>&1`)
	check, install := strings.Index(script, "sha256sum -c"), strings.Index(script, "install -m 0755 -o root -g root ./alice-helper")
	require.GreaterOrEqual(t, check, 0)
	assert.Less(t, check, install, "the helper is checked before it is installed")
}

// A checksum that is not 64 lower-case hex digits (a broken build) is never embedded in a
// root script. A release build then has no script at all; only a development build gets one
// that says it cannot verify the helper.
func TestSetupScriptIgnoresMalformedChecksums(t *testing.T) {
	for _, bad := range [][2]string{
		{"", strings.Repeat("b2", 32)},
		{strings.Repeat("a1", 32), ""},
		{strings.Repeat("A1", 32), strings.Repeat("b2", 32)},
		{strings.Repeat("a1", 32) + "; rm -rf /", strings.Repeat("b2", 32)},
	} {
		withHelperSums(t, bad[0], bad[1])
		_, err := SetupScript("linux", wantOptions+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", false)
		assert.ErrorIs(t, err, ErrHelperUnverified, "%q: only a development build may skip the check", bad)
		script, err := SetupScript("linux", wantOptions+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform", true)
		require.NoError(t, err)
		assert.Contains(t, script, goldenUnverified, "%q", bad)
		assert.NotContains(t, script, "rm -rf /;")
		assert.NotContains(t, script, "sha256sum -c")
	}
}

// The check runs in a real shell: the right helper passes, any other file stops the script.
func TestHelperCheckRunsInAShell(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	dir := t.TempDir()
	helper := []byte("#!/bin/sh\necho helper\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alice-helper"), helper, 0o600))
	sum := sha256.Sum256(helper)
	good := hex.EncodeToString(sum[:])
	run := func(amd64, arm64 string) error {
		block := helperCheck(amd64, arm64)
		cmd := exec.Command("sh", "-c", "set -eu\n"+block+"echo checked\n")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err == nil {
			assert.Contains(t, string(out), "checked")
		}
		return err
	}
	assert.NoError(t, run(good, good))
	assert.Error(t, run(strings.Repeat("0", 64), strings.Repeat("0", 64)), "a different helper is refused")
}
