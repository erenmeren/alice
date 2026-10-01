package linuxssh

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The sudoers file of spec §12.3. Profile "linux" allows only ALICE_COMMON (SSH-key work);
// profile "nginx" also allows the certificate subcommands (implemented by the helper from Phase 4).
const sudoersHead = `# Managed by Alice. Do not edit. Validate with: visudo -cf /etc/sudoers.d/alice
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

const sudoersNginxOnly = `
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-reload, \
    /usr/local/libexec/alice-helper stat *, \
    /usr/local/libexec/alice-helper read-cert *, \
    /usr/local/libexec/alice-helper install-cert *, \
    /usr/local/libexec/alice-helper backup *, \
    /usr/local/libexec/alice-helper restore *
`

var errUnknownProfile = errors.New(`linuxssh: unknown sudoers profile (want "linux" or "nginx")`)

// Sudoers returns /etc/sudoers.d/alice for a profile.
func Sudoers(profile string) (string, error) {
	switch profile {
	case "linux":
		return sudoersHead + "\nalice-svc ALL=(root) NOPASSWD: ALICE_COMMON\n", nil
	case "nginx":
		return sudoersHead + sudoersNginxOnly + "\nalice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_NGINX_ONLY\n", nil
	default:
		return "", errUnknownProfile
	}
}

// fromPattern is the address-list vocabulary of the from= option (addresses, CIDR, wildcards,
// negation). Nothing outside it is ever embedded in the quotes.
var fromPattern = regexp.MustCompile(`^[0-9A-Fa-f.:/,*?!]{1,512}$`)

// ErrInvalidFrom means a from= value is outside the address-list vocabulary.
var ErrInvalidFrom = errors.New("linuxssh: from= accepts only IP addresses, CIDR ranges, * ? wildcards and ! negation, comma separated")

// ValidateFrom checks a from= value for AuthorizedKeysLine; "" (no restriction) is valid.
func ValidateFrom(from string) error {
	if from == "" || fromPattern.MatchString(from) {
		return nil
	}
	return ErrInvalidFrom
}

// keyOptions restrict the platform key (SEC-082). Alice only opens exec channels, so it needs no
// agent, port or X11 forwarding, no pty and no ~/.ssh/rc. "restrict" is not used: it would also
// need explicit re-enabling and is not in SEC-082's list.
const keyOptions = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc"

// AuthorizedKeysLine is the line that authorizes Alice's key for alice-svc (SEC-082). from limits
// the source addresses and is optional (NAT, HA). An invalid from (see ValidateFrom) gives "":
// the caller asked for a restriction, so a line without it is never produced (SetupScript refuses
// the empty line).
func AuthorizedKeysLine(publicKey, from string) string {
	if ValidateFrom(from) != nil {
		return ""
	}
	opts := keyOptions
	if from != "" {
		opts = `from="` + from + `",` + opts
	}
	return opts + " " + publicKey
}

const scriptTemplate = `#!/bin/sh
# Prepares this server for Alice (profile: __PROFILE__). Run it as root in the directory that
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
printf '%s\n' '__LINE__' >"$t"
chmod 0644 "$t"
mv -f "$t" /var/lib/alice-svc/.ssh/authorized_keys
cat > /etc/sudoers.d/.alice.tmp <<'ALICE_SUDOERS'
__SUDOERS__ALICE_SUDOERS
chmod 0440 /etc/sudoers.d/.alice.tmp
visudo -cf /etc/sudoers.d/.alice.tmp
mv /etc/sudoers.d/.alice.tmp /etc/sudoers.d/alice
install -d -m 0700 -o root -g root /var/lib/alice-helper /var/lib/alice-helper/backups
echo "This server is ready for Alice."
`

var errBadKeyLine = errors.New("linuxssh: the authorized_keys line cannot be embedded in the setup script")

// SetupScript is the root script of spec §12.2 for a profile. "usermod -p '*'" leaves alice-svc
// without a password but not locked, so sshd also accepts its key with UsePAM no. The sudoers file
// is installed only after visudo accepted it (a file name with a dot is ignored by sudo).
//
// Running it again must be safe even if alice-svc is compromised: root never writes, chowns or
// chmods a path inside a directory alice-svc can change (it could plant a symlink to
// /etc/ld.so.preload there). The home and .ssh become root's (0755; sshd's StrictModes accepts
// root-owned key files), .ssh is removed and recreated (rm never follows links), and the key is
// written to a fresh mktemp file in the root-owned .ssh and renamed into place. A pre-existing
// alice-svc with another home is refused rather than reconfigured.
func SetupScript(profile, authorizedKeysLine string) (string, error) {
	sudoers, err := Sudoers(profile)
	if err != nil {
		return "", err
	}
	if authorizedKeysLine == "" || !utf8.ValidString(authorizedKeysLine) || strings.ContainsRune(authorizedKeysLine, '\'') ||
		strings.ContainsFunc(authorizedKeysLine, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errBadKeyLine
	}
	return strings.NewReplacer("__PROFILE__", profile, "__LINE__", authorizedKeysLine, "__SUDOERS__", sudoers).
		Replace(scriptTemplate), nil
}
