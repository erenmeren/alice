// Package helperproto is the protocol between Alice and alice-helper (spec §12.3, §13.1, R21):
// subcommand names, exit codes, error codes, the JSON answers and the argument vocabulary that
// both sides enforce (SEC-063). It uses only the standard library because the static helper
// binary imports it too.
package helperproto

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Protocol and file locations.
const (
	Protocol   = 1
	Version    = "1.0.0"
	HelperPath = "/usr/local/libexec/alice-helper"
	BackupRoot = "/var/lib/alice-helper/backups"
)

// Subcommands of protocol 1 (R37 item 3).
const (
	SubVersion       = "version"
	SubSSHDDump      = "sshd-dump"
	SubHostKeys      = "hostkeys"
	SubAuthKeysList  = "authkeys-list"
	SubAuthKeysRead  = "authkeys-read"
	SubAuthKeysWrite = "authkeys-write"
	SubCleanup       = "cleanup"
)

// Exit codes (spec §12.3).
const (
	ExitOK           = 0
	ExitRefused      = 2 // validation refused
	ExitPrecondition = 3 // hash mismatch, missing file
	ExitFailed       = 4 // command failed
)

// Error codes printed in ErrorResponse.Code. They are internal: Alice maps them to ALC codes.
const (
	CodeUsage               = "USAGE"
	CodeUnknownSubcommand   = "UNKNOWN_SUBCOMMAND"
	CodeNotRoot             = "NOT_ROOT"
	CodeInvalidArgument     = "INVALID_ARGUMENT"
	CodePathNotAllowed      = "PATH_NOT_ALLOWED"
	CodeNotRegularFile      = "NOT_REGULAR_FILE"
	CodeInsecurePermissions = "INSECURE_PERMISSIONS"
	CodeTooLarge            = "TOO_LARGE"
	CodeHashMismatch        = "HASH_MISMATCH"
	CodeNotFound            = "NOT_FOUND"
	CodeSSHDFailed          = "SSHD_FAILED"
	CodeIOError             = "IO_ERROR"
)

// Warning codes in AuthKeysListResponse.Warnings; they equal the web catalog keys warnings.<code>.
const (
	WarnSSHDUnreadable  = "sshd_unreadable"
	WarnDirectoryUsers  = "directory_users_not_listed"
	WarnUnsupportedPath = "unsupported_path"
)

// Size limits and markers.
const (
	MaxAuthorizedKeysSize = 1 << 20  // authkeys-read output and authkeys-write stdin
	AbsentSHA256          = "absent" // --expect-sha256 for a file that does not exist yet
	maxArgLen             = 4096
)

// ErrorResponse is the one JSON line printed on every failure.
type ErrorResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VersionResponse answers "version" (runs without sudo).
type VersionResponse struct {
	OK       bool   `json:"ok"`
	Helper   string `json:"helper"`
	Protocol int    `json:"protocol"`
}

// SSHDDumpResponse answers "sshd-dump".
type SSHDDumpResponse struct {
	OK       bool   `json:"ok"`
	Config   string `json:"config"`   // sshd -T output
	Fallback bool   `json:"fallback"` // sshd -T failed: Config is empty, defaults apply
}

// HostKeyInfo is one host key of the server.
type HostKeyInfo struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
}

// HostKeysResponse answers "hostkeys".
type HostKeysResponse struct {
	OK   bool          `json:"ok"`
	Keys []HostKeyInfo `json:"keys"`
}

// FileInfo describes one candidate authorized_keys file.
type FileInfo struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"` // "" when absent or too large
	Mode          string `json:"mode"`   // "0600"
	Owner         string `json:"owner"`
	StrictModesOK bool   `json:"strict_modes_ok"`
	TooLarge      bool   `json:"too_large"`
}

// UserFiles is one account and its candidate files.
type UserFiles struct {
	User  string     `json:"user"`
	UID   int        `json:"uid"`
	Home  string     `json:"home"`
	Files []FileInfo `json:"files"`
}

// AuthKeysListResponse answers "authkeys-list".
type AuthKeysListResponse struct {
	OK                    bool        `json:"ok"`
	Users                 []UserFiles `json:"users"`
	AuthorizedKeysCommand string      `json:"authorized_keys_command"`
	Warnings              []string    `json:"warnings"`
}

// AuthKeysReadResponse answers "authkeys-read".
type AuthKeysReadResponse struct {
	OK         bool   `json:"ok"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	ContentB64 string `json:"content_b64"`
}

// AuthKeysWriteResponse answers "authkeys-write".
type AuthKeysWriteResponse struct {
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256"`
	Backup string `json:"backup"`
}

// CleanupResponse answers "cleanup".
type CleanupResponse struct {
	OK      bool `json:"ok"`
	Removed int  `json:"removed"`
}

var (
	argRE  = regexp.MustCompile(`^[A-Za-z0-9._/@:+-]+$`)
	userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// ValidArg reports whether s may appear as a helper argument: 1 to 4096 characters from
// [A-Za-z0-9._/@:+-], no ".." path element and no leading "-" (it would read as an option).
// Everything else (spaces, quotes, shell metacharacters, control characters, non-ASCII) is refused.
func ValidArg(s string) bool {
	if len(s) == 0 || len(s) > maxArgLen || !argRE.MatchString(s) || strings.HasPrefix(s, "-") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// ValidPath reports whether s is a valid argument that is also an absolute, already clean path.
func ValidPath(s string) bool {
	return ValidArg(s) && strings.HasPrefix(s, "/") && filepath.Clean(s) == s
}

// ValidUser reports whether s is an acceptable Linux user name (SEC-062).
func ValidUser(s string) bool { return userRE.MatchString(s) }

// ValidOpID reports whether s is a lowercase UUID in 8-4-4-4-12 form (the backup directory name).
func ValidOpID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isLowerHex(c) {
				return false
			}
		}
	}
	return true
}

// ValidSHA256 reports whether s is 64 lowercase hex digits or AbsentSHA256.
func ValidSHA256(s string) bool {
	if s == AbsentSHA256 {
		return true
	}
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLowerHex(s[i]) {
			return false
		}
	}
	return true
}

func isLowerHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }
