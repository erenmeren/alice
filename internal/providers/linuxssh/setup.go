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
    /usr/local/libexec/alice-helper authkeys-write /* --expect-sha256 * --content-sha256 * --op *
`

// The Nginx lines (profile "nginx", spec §12.3 / A-12). sudo matches arguments with fnmatch and
// no FNM_PATHNAME, so '*' also matches spaces and further words: the helper's own argument check is
// the real gate. Each line is still as narrow as sudo's grammar allows: flags are literal and in the
// helper's order, a command that takes no arguments ends right after its subcommand (the
// real-OpenSSH container matrix on ubuntu22, debian12 and rocky9 shows sudo itself refusing a
// further word, with its own text; TestRealOpenSSH asserts it), and the operation id and the two
// hashes are fixed-length '?' runs, so nothing
// can follow them. Only the two certificate paths are open-ended. tls-probe is unprivileged and has
// no line.
const (
	sudoersOpID = "????????-????-????-????-????????????"                             // 8-4-4-4-12, like helperproto.ValidOpID
	sudoersSHA  = "????????????????????????????????????????????????????????????????" // 64 characters
)

const sudoersNginxOnly = `
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-deploy --op ` + sudoersOpID + ` --cert /* --key /* --expect-cert-sha256 ` + sudoersSHA + ` --content-sha256 ` + sudoersSHA + `, \
    /usr/local/libexec/alice-helper nginx-restore --op ` + sudoersOpID + `, \
    /usr/local/libexec/alice-helper nginx-status --op ` + sudoersOpID + `, \
    /usr/local/libexec/alice-helper nginx-fence --op ` + sudoersOpID + `
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
install -d -m 0700 -o root -g root /var/lib/alice-helper
helper_dir=$(mktemp -d /var/lib/alice-helper/install.XXXXXX)
trap 'rm -rf "$helper_dir"' EXIT
cp ./alice-helper "$helper_dir/alice-helper"
__HELPER_CHECK__install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root "$helper_dir/alice-helper" /usr/local/libexec/alice-helper
if ! id alice-svc >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /var/lib/alice-svc --shell /bin/bash alice-svc
fi
if [ "$(getent passwd alice-svc | cut -d: -f6)" != /var/lib/alice-svc ]; then
    echo "The user alice-svc exists with a home directory other than /var/lib/alice-svc. Fix or remove it first." >&2
    exit 1
fi
usermod -p '*' alice-svc
mkdir -p /var/lib/alice-svc
chown -h root:root /var/lib/alice-svc
chmod 0755 /var/lib/alice-svc
for f in /var/lib/alice-svc/* /var/lib/alice-svc/.[!.]* /var/lib/alice-svc/..?*; do
    if [ -e "$f" ] || [ -L "$f" ]; then rm -rf -- "$f"; fi
done
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

// The SHA-256 checksums of the alice-helper binaries that belong to this Alice build: the lines
// of bin/alice-helper.sha256 that "make helper" writes, set at link time by "make build" and the
// image build (-X alice/internal/providers/linuxssh.helperSHA256LinuxAMD64=...). Empty in a build
// without them (go build, go test): the setup script then says that it cannot verify the helper.
var (
	helperSHA256LinuxAMD64 string
	helperSHA256LinuxARM64 string
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

const helperUnverified = `# This Alice build has no alice-helper checksums (it was built without "make helper"),
# so the helper below is installed without checking it.
echo "Warning: this Alice build cannot verify alice-helper (development build without checksums)." >&2
`

const helperVerify = `command -v sha256sum >/dev/null || { echo "sha256sum (coreutils) is required." >&2; exit 1; }
case "$(uname -m)" in
    x86_64) helper_sha256=__AMD64__ ;;
    aarch64) helper_sha256=__ARM64__ ;;
    *) echo "alice-helper is built for x86_64 and aarch64 only." >&2; exit 1 ;;
esac
if ! printf '%s  %s\n' "$helper_sha256" "$helper_dir/alice-helper" | sha256sum -c - >/dev/null 2>&1; then
    echo "./alice-helper is not the alice-helper of this Alice version (its SHA-256 checksum differs)." >&2
    echo "Copy alice-helper-linux-amd64 or alice-helper-linux-arm64 from the bundle of this Alice version as ./alice-helper." >&2
    exit 1
fi
`

// ErrHelperUnverified means this build has no alice-helper checksums and is not a development
// build: it offers no setup script rather than one that installs an unchecked helper as root.
var ErrHelperUnverified = errors.New("linuxssh: this Alice build has no alice-helper checksums; build it with make build or the image build")

// HelperChecksumsKnown reports whether this build embeds both alice-helper checksums (make build
// and the image build do). cmd/alice warns at startup when a non-development build lacks them.
func HelperChecksumsKnown() bool { return helperSumsKnown() }

func helperSumsKnown() bool {
	return sha256Hex.MatchString(helperSHA256LinuxAMD64) && sha256Hex.MatchString(helperSHA256LinuxARM64)
}

// helperCheck is the part of the setup script that checks the root-private copy of ./alice-helper
// ("$helper_dir/alice-helper") against the checksum of this Alice version for the server's
// architecture (R37 item 2). Unless both checksums are well formed it embeds neither and warns
// instead: a value that is not plain hex never reaches a root script.
func helperCheck(amd64, arm64 string) string {
	if !sha256Hex.MatchString(amd64) || !sha256Hex.MatchString(arm64) {
		return helperUnverified
	}
	return strings.NewReplacer("__AMD64__", amd64, "__ARM64__", arm64).Replace(helperVerify)
}

var errBadKeyLine = errors.New("linuxssh: the authorized_keys line cannot be embedded in the setup script")

// SetupScript is the root script of spec §12.2 for a profile. "usermod -p '*'" leaves alice-svc
// without a password but not locked, so sshd also accepts its key with UsePAM no. The sudoers file
// is installed only after visudo accepted it (a file name with a dot is ignored by sudo). The helper
// is checked against the checksum of this Alice version before it is installed (helperCheck).
//
// The helper is first copied into a fresh root-only directory below /var/lib/alice-helper; that
// copy is checked and installed, so whoever can write the directory the administrator ran the
// script in cannot swap the file between the check and the install (A-3 of the final review).
//
// Running it again must be safe even if alice-svc is compromised: root never writes, chowns or
// chmods a path inside a directory alice-svc can change (it could plant a symlink to
// /etc/ld.so.preload there). The home and .ssh become root's (0755; sshd's StrictModes accepts
// root-owned key files). The account is created without /etc/skel files, and everything in the
// home is removed on every run (rm never follows links), so no file alice-svc owns (a .bashrc
// that bash sources for every command sshd runs) survives; .ssh is recreated and the key is
// written to a fresh mktemp file in the root-owned .ssh and renamed into place. A pre-existing
// alice-svc with another home is refused rather than reconfigured.
//
// Without the helper checksums only a development build (allowUnverified) gets a script, and it
// says that it cannot verify the helper; any other build gets ErrHelperUnverified.
func SetupScript(profile, authorizedKeysLine string, allowUnverified bool) (string, error) {
	sudoers, err := Sudoers(profile)
	if err != nil {
		return "", err
	}
	if !allowUnverified && !helperSumsKnown() {
		return "", ErrHelperUnverified
	}
	if authorizedKeysLine == "" || !utf8.ValidString(authorizedKeysLine) || strings.ContainsRune(authorizedKeysLine, '\'') ||
		strings.ContainsFunc(authorizedKeysLine, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errBadKeyLine
	}
	return strings.NewReplacer("__PROFILE__", profile, "__LINE__", authorizedKeysLine, "__SUDOERS__", sudoers,
		"__HELPER_CHECK__", helperCheck(helperSHA256LinuxAMD64, helperSHA256LinuxARM64)).
		Replace(scriptTemplate), nil
}
