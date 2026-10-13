// Package helperproto is the protocol between Alice and alice-helper (spec §12.3, §13.1, R21):
// subcommand names, exit codes, error codes, the JSON answers and the argument vocabulary that
// both sides enforce (SEC-063). It uses only the standard library because the static helper
// binary imports it too.
package helperproto

import (
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Protocol and file locations.
const (
	// Protocol 2: authkeys-read and authkeys-write answer with the resolved owner. Protocol 3:
	// authkeys-write takes --content-sha256 and refuses incomplete content (CONTENT_MISMATCH).
	// Protocol 4: the Nginx subcommands, tls-probe, and the accounts list of authkeys-list.
	// Protocol 5: nginx-fence (AUD-05), the fenced phase, RECOVERY_PENDING, NGINX_NOT_RUNNING,
	// OUTCOME_UNKNOWN, the name_not_allowed file problem, and nginx-restore answering a partial
	// restore as its outcome (exit 0) instead of HASH_MISMATCH.
	// Protocol 6 (AUD-03, AUD-22): authkeys-list lists account names of ValidAccount (not only
	// ValidUser), reports the /etc/passwd entries it cannot list (unlisted), returns the content of
	// the files it read (inline) so a discovery needs no authkeys-read for them, and keeps its whole
	// answer within MaxListOutput (truncated).
	// Protocol 7 (ACME, Task 7): acme-challenge-put and acme-challenge-rm write and remove one
	// HTTP-01 token file in ACMEChallengeDir. Nothing else changed: a protocol 6 helper serves every
	// other operation (MinProtocol); only an HTTP-01 challenge needs 7 (HTTP01MinProtocol).
	Protocol   = 7
	Version    = "1.6.0"
	HelperPath = "/usr/local/libexec/alice-helper"
	BackupRoot = "/var/lib/alice-helper/backups"
)

// MinProtocol is the oldest helper protocol Alice opens a session with (linuxssh.Open answers
// ssh.helper_outdated below it). It stays 6 when the helper moves to 7 (A1 of the ACME plan): a
// server that was not reinstalled keeps working for everything it did before.
const MinProtocol = 6

// HTTP01MinProtocol is the helper protocol an HTTP-01 challenge needs (acme-challenge-put and
// acme-challenge-rm). Only that operation checks it.
const HTTP01MinProtocol = 7

// HelperBudget bounds one helper call on the server (R37 item 17): the helper gives up before
// Alice's longest command budget (60 s) ends, with a 10 s margin, and never replaces a file after
// it. So a write normally ends before Alice gives up, but not always: the helper's budget starts
// when its process starts, Alice's when Conn.Run starts (a slow sudo or PAM eats the margin), and a
// cancelled job reports ssh.timeout at any moment. Alice therefore treats a timeout of a write as
// an uncertain outcome.
const HelperBudget = 50 * time.Second

// Subcommands of protocol 3 (R37 item 3).
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
	// CodeContentMismatch refuses a write whose stdin does not have the --content-sha256 hash: the
	// content arrived incomplete (the connection dropped while it was sent). Exit 3, nothing written.
	CodeContentMismatch = "CONTENT_MISMATCH"
	CodeNotFound        = "NOT_FOUND"
	CodeSSHDFailed      = "SSHD_FAILED"
	CodeIOError         = "IO_ERROR"
	CodeUnsafeFile      = "UNSAFE_FILE" // hard-linked, or owned by neither its user nor root
	// CodeHomeNotWritable refuses a write that needs a new <home>/.ssh the user may not create
	// (the home is not writable for its user). Exit 3, nothing written.
	CodeHomeNotWritable = "HOME_NOT_WRITABLE"
	// CodeAuthorizedKeysCommand refuses a write for a user whose keys sshd takes from an
	// AuthorizedKeysCommand: the files are not the whole truth, keys are managed elsewhere.
	CodeAuthorizedKeysCommand = "AUTHORIZED_KEYS_COMMAND"
)

// Warning codes in AuthKeysListResponse.Warnings; they equal the web catalog keys warnings.<code>.
const (
	WarnSSHDUnreadable  = "sshd_unreadable"
	WarnDirectoryUsers  = "directory_users_not_listed"
	WarnUnsupportedPath = "unsupported_path"
	WarnTooManyUsers    = "too_many_users" // more accounts than the helper lists
	// Alice's warnings for AuthKeysListResponse.Unlisted (parameter uid); the helper never sends
	// them in Warnings.
	WarnAccountNameUnsupported = "account_name_unsupported"
	WarnAccountHomeUnsupported = "account_home_unsupported"
	WarnAccountIDUnsupported   = "account_id_unsupported"
	// WarnAccountsNUL: /etc/passwd holds a NUL byte. glibc reads each line only up to it (the helper
	// does the same), but no legitimate file has one, so the account list is not complete (C1).
	WarnAccountsNUL = "accounts_nul_byte"
)

// Phase 4 warnings of nginx-dump. WarnStreamTLS and WarnMailTLS are also the codes of
// nginxconf.Config.Warnings, which takes its values from here.
const (
	WarnStreamTLS          = "stream_tls"           // TLS in stream {} is listed but not supported (F-21, R23)
	WarnMailTLS            = "mail_tls"             // TLS in mail {} is listed but not supported
	WarnConfigFileWritable = "config_file_writable" // a configuration file can be changed by users other than root
	WarnTooManyFiles       = "too_many_files"       // more referenced files than MaxNginxFiles
	// WarnCertificateBlockDropped: a block labelled CERTIFICATE in a certificate file is not an
	// X.509 certificate (or carries PEM headers); the helper dropped it and returned the others.
	WarnCertificateBlockDropped = "certificate_block_dropped"
	// WarnKeyGroupOpen: a key file is owned by a user other than root, or readable by a group other
	// than root's or by others (S10). A deployment keeps the owner and group (and 0640), so a new
	// key would be as exposed as the old one.
	WarnKeyGroupOpen = "key_group_open"
)

// Phase 4 subcommands (spec §12.3, R38 item 1). tls-probe runs without sudo (like version).
const (
	SubNginxDump    = "nginx-dump"
	SubNginxTest    = "nginx-test"
	SubNginxDeploy  = "nginx-deploy"
	SubNginxRestore = "nginx-restore"
	SubNginxStatus  = "nginx-status"
	SubTLSProbe     = "tls-probe"
	// SubNginxFence (protocol 5, AUD-05): under the Nginx lock, an operation without a journal (or
	// with a prepared one, which replaced nothing) gets a tombstone journal (PhaseFenced), after
	// which nginx-deploy of that operation refuses (FENCED) without writing anything. Idempotent;
	// an operation with any other journal is answered as nginx-status would, unchanged. The answer
	// is a NginxStatusResponse (Active false: the fence holds the lock).
	SubNginxFence = "nginx-fence"
)

// Phase 4 error codes.
const (
	CodeNginxNotFound = "NGINX_NOT_FOUND" // /usr/sbin/nginx does not exist (F-20)
	CodeConfigInvalid = "CONFIG_INVALID"  // nginx -T/-t fails before anything changed (F-02)
	CodeConfigChanged = "CONFIG_CHANGED"  // the paths are not a supported pair of the current configuration
	CodeNoSpace       = "NO_SPACE"        // less free space than the new files plus MinFreeBytes (F-10, F-11)
	CodeBadContent    = "BAD_CONTENT"     // stdin is not one certificate file and one unencrypted private key
	CodeBusy          = "BUSY"            // another nginx-deploy or nginx-restore holds the lock
	CodeUnknownOp     = "UNKNOWN_OP"      // nginx-restore: no journal for this operation
	CodeProbeFailed   = "PROBE_FAILED"    // tls-probe could not connect or complete the handshake
	// CodeOutputTooLarge: nginx-dump's answer would exceed NginxDumpOutput (exit 4); the helper
	// never sends a truncated answer.
	CodeOutputTooLarge = "OUTPUT_TOO_LARGE"
	// CodeSuperseded: nginx-restore (or a re-sent interrupted nginx-deploy) of an operation that a
	// later operation for the same certificate and key files replaced (exit 3, nothing changed):
	// only the latest operation of a pair can be rolled back.
	CodeSuperseded = "SUPERSEDED"
	// CodeRecoveryPending: nginx-deploy for a pair whose latest operation was interrupted (its
	// journal says writing or restoring, or cannot be read): a new operation would supersede it and
	// make its rollback impossible. Exit 3, nothing changed; ErrorResponse.PendingOp names that
	// operation, and nginx-restore of it comes first.
	CodeRecoveryPending = "RECOVERY_PENDING"
	// CodeNginxNotRunning: nginx-deploy found /usr/bin/systemctl missing or "systemctl is-active
	// nginx" failing before anything was written: a reload could not work. Exit 3, nothing changed.
	CodeNginxNotRunning = "NGINX_NOT_RUNNING"
	// CodeOutcomeUnknown: nginx-deploy or nginx-restore met an unexpected error after it had
	// renamed a file: the answer is not a refusal (Alice treats it as uncertain and reads
	// nginx-status). Exit 4. No refusal table holds it.
	CodeOutcomeUnknown = "OUTCOME_UNKNOWN"
	// CodeFenced: nginx-deploy of an operation that nginx-fence fenced (exit 3, nothing written):
	// Alice's recovery already recorded that this operation wrote nothing.
	CodeFenced = "FENCED"
)

// MaxAccountNames bounds AuthKeysListResponse.Accounts (R38 item 20).
const MaxAccountNames = 5000

// Protocol 6 limits and reasons (AUD-03, AUD-22).
const (
	MaxUnlistedAccounts = 100     // entries of AuthKeysListResponse.Unlisted
	MaxListInline       = 4 << 20 // total raw bytes of inline file content in one authkeys-list answer
	// MaxListOutput bounds the whole authkeys-list answer, its newline included (S8): below Alice's
	// 8 MiB read limit, so a server never turns a listing into a failed discovery. Over it the helper
	// first returns fewer files inline (Alice reads them with authkeys-read), then lists fewer users
	// and says Truncated.
	MaxListOutput = 7 << 20
	UnlistedName  = "name" // the name is not a ValidAccount
	UnlistedHome  = "home" // the account would be scanned, but its home is not a path the helper accepts (CleanHome)
	// UnlistedID: the uid or gid field is not a plain decimal number below 4294967295 (a sign, a
	// "+", 32-bit overflow or (uid_t)-1): glibc reads it, but as a clamped value nobody wrote.
	UnlistedID = "id"
)

// UnlistedAccount is an /etc/passwd entry authkeys-list did not list. Only the uid leaves the
// server: the name may hold any byte.
type UnlistedAccount struct {
	UID    int    `json:"uid"`
	Reason string `json:"reason"` // UnlistedName, UnlistedHome or UnlistedID
}

// Phase 4 limits.
const (
	MaxNginxConfig  = 20 << 20  // nginx -T output the helper reads
	MaxCertFileSize = 256 << 10 // a certificate or key file
	MaxDeployInput  = 512 << 10 // nginx-deploy stdin
	MaxNginxFiles   = 1000      // referenced certificate and key files nginx-dump describes
	MinFreeBytes    = 10 << 20  // free space kept after a write (spec §12.6 step 1)
	NginxDumpOutput = 16 << 20  // nginx-dump's answer: certificates are public and small
	NginxBackupKeep = 7 * 24 * time.Hour
)

// Configuration error classes of nginx -t (never the raw text).
const (
	ConfigErrKeyMismatch = "key_mismatch"
	ConfigErrFileMissing = "file_missing"
	ConfigErrCertLoad    = "cert_load"
	ConfigErrKeyLoad     = "key_load"
	ConfigErrSyntax      = "syntax"
	// ConfigErrUntrusted: nginx -T's output cannot be trusted: a section does not match its file,
	// or a configuration file cannot be read through the root-controlled walk (nginx-dump only).
	ConfigErrUntrusted = "untrusted"
	// ConfigErrUnsupported: a configuration Alice cannot read safely: no or a relative
	// --conf-path, the size cap, the parser's limits, a file name the vocabulary cannot carry.
	ConfigErrUnsupported = "unsupported"
)

// Reasons of an untrusted or unsupported configuration (NginxDumpResponse.ConfigErrorReason), a
// closed set; ConfigErrorFile names the file when it can be carried.
const (
	ConfigReasonNotRootControlled = "not_root_controlled" // a directory or link on the file's path is not root's alone
	ConfigReasonSpecialFS         = "special_filesystem"  // the file is on procfs, sysfs, FUSE or another pseudo file system
	ConfigReasonMissing           = "missing"             // the file named by the dump does not exist
	ConfigReasonNotRegular        = "not_regular"         // not a regular file
	ConfigReasonChanged           = "changed"             // the file's content is not what nginx -T printed
	ConfigReasonNameNotAllowed    = "name_not_allowed"    // the file name is not a path the helper accepts
	ConfigReasonUnexpectedText    = "unexpected_text"     // text before the first file of the dump
	ConfigReasonWrongFirstFile    = "wrong_first_file"    // the dump does not start with the configuration file
	ConfigReasonDuplicateFile     = "duplicate_file"      // the dump names one file twice
	ConfigReasonNoConfPath        = "no_conf_path"        // nginx -V names no absolute --conf-path
	ConfigReasonTooLarge          = "too_large"           // the dump, a line or a token is over its limit
	ConfigReasonTooComplex        = "too_complex"         // too many tokens, files, directives, arguments or nesting levels
	ConfigReasonIncludeLoop       = "include_loop"        // files include each other in a loop
	ConfigReasonNULByte           = "nul_byte"            // the dump contains a NUL byte
)

// File problems of nginx-dump (also providers.CertProblem*).
const (
	FileMissing           = "missing"
	FileNotRootControlled = "not_root_controlled"
	FileNotRegular        = "not_regular"
	FileHardLinked        = "hard_linked"
	FileTooLarge          = "too_large"
	FileNotACertificate   = "not_a_certificate"
	FileUnreadable        = "unreadable"
	FileBadName           = "bad_name" // the resolved name has no certificate or key extension
	// FileSpecialFS: the file or a directory on its path is on FUSE or a pseudo file system
	// (procfs, sysfs, ...), whose owners, modes and contents a daemon or the kernel reports.
	FileSpecialFS = "special_filesystem"
	// FileNameNotAllowed: the file's resolved path (after root's links, e.g. an acme.sh directory
	// "*.example.com") has a character outside the helper's argument vocabulary. The helper never
	// reads, replaces or journals such a file (a journal naming it could not be read back).
	FileNameNotAllowed = "name_not_allowed"
)

// Deployment journal phases (nginx-status, nginx-deploy outcome).
const (
	PhaseNone          = "none"           // no journal: nothing happened for this operation
	PhasePrepared      = "prepared"       // backups written; nothing renamed
	PhaseWriting       = "writing"        // between the first rename and the end of the reload: interrupted when not active
	PhaseCommitted     = "committed"      // both files written, nginx -t passed, reload and is-active passed
	PhaseUnchanged     = "unchanged"      // the files already held the new content; nothing written, no reload
	PhaseRestoring     = "restoring"      // a rollback is under way: interrupted when not active
	PhaseRestored      = "restored"       // the backups are back and Nginx reloaded
	PhaseRestoreFailed = "restore_failed" // the rollback could not finish
	PhaseFenced        = "fenced"         // nginx-fence's tombstone: nothing was written and nothing will be
)

// Deploy step names (nginx-deploy and nginx-restore report them in order).
const (
	StepBackup             = "backup"
	StepWriteKey           = "write_key"
	StepWriteCert          = "write_cert"
	StepConfigTest         = "config_test"
	StepReload             = "reload"
	StepRestore            = "restore"
	StepRollbackConfigTest = "rollback_config_test"
	StepRollbackReload     = "rollback_reload"
	// StepJournal: the journal could not record the commit after the files were replaced, so the
	// deployment was rolled back (the journal is what nginx-status reports; it must not disagree).
	StepJournal = "journal"
)

// RestoreErrFileChanged is the Error of PhaseRestoreFailed when a certificate or key file holds
// neither the deployed nor the backed-up content (someone else changed it): nothing is restored.
const RestoreErrFileChanged = "file_changed"

// KeyTypes of tls-probe.
const (
	ProbeAny   = "any"
	ProbeRSA   = "rsa"
	ProbeECDSA = "ecdsa"
)

// NoSNI is the --sni value of tls-probe that sends no server name (ValidArg accepts it,
// ValidSNI does not, so it can never be a real name).
const NoSNI = "_"

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
	// PendingOp is set with CodeRecoveryPending only: the interrupted operation (a ValidOpID) that
	// blocks the pair, so Alice can restore it (final review fix round 1, Important 1).
	PendingOp string `json:"pending_op,omitempty"`
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
	Unsupported   bool   `json:"unsupported"` // a candidate the helper refuses to read or write (escapes its directory, hard link, foreign owner)
	// Inline is true when ContentB64 holds the file's content (protocol 6): the helper read the
	// file for SHA256 from the same descriptor and returns it while the answer's inline total stays
	// within MaxListInline (and the answer within MaxListOutput). SHA256 is the hash of exactly this
	// content. Files without it are read with authkeys-read. Only discovery uses it: a change always
	// reads the file again with authkeys-read (its owner and hash guard the write).
	Inline     bool   `json:"inline"`
	ContentB64 string `json:"content_b64,omitempty"`
}

// UserFiles is one account and its candidate files.
type UserFiles struct {
	User  string     `json:"user"`
	UID   int        `json:"uid"`
	Home  string     `json:"home"`
	Files []FileInfo `json:"files"`
	// SSHDUnreadable is true when "sshd -T -C user=…" failed for this user: Files then come from the
	// global configuration and may be wrong, so write operations must refuse.
	SSHDUnreadable bool `json:"sshd_unreadable"`
	// AuthorizedKeysCommand is this user's effective AuthorizedKeysCommand ("none" when unset).
	AuthorizedKeysCommand string `json:"authorized_keys_command"`
}

// AuthKeysListResponse answers "authkeys-list".
type AuthKeysListResponse struct {
	OK                    bool        `json:"ok"`
	Users                 []UserFiles `json:"users"`
	AuthorizedKeysCommand string      `json:"authorized_keys_command"`
	Warnings              []string    `json:"warnings"`
	// Accounts is every ValidAccount /etc/passwd name, sorted and deduplicated (at most
	// MaxAccountNames); AccountsComplete is false when the list was cut or could not be read
	// completely (R38 item 20), when Unlisted is not empty, or when the answer is Truncated.
	Accounts         []string `json:"accounts"`
	AccountsComplete bool     `json:"accounts_complete"`
	// Unlisted names every entry the helper could not list (at most MaxUnlistedAccounts, never
	// null); AccountsComplete is false when it is not empty (AUD-03).
	Unlisted []UnlistedAccount `json:"unlisted"`
	// Truncated is true when the helper left users out to keep the answer within MaxListOutput (S8);
	// TruncatedFromUID is then the uid of the first user left out (absent when only account names
	// were cut).
	Truncated        bool `json:"truncated"`
	TruncatedFromUID *int `json:"truncated_from_uid,omitempty"`
}

// AuthKeysReadResponse answers "authkeys-read".
type AuthKeysReadResponse struct {
	OK         bool   `json:"ok"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	ContentB64 string `json:"content_b64"`
	// Owner is the account the helper resolved the file to; Alice refuses a change whose request
	// names another user (it would defeat the last-key guards).
	Owner string `json:"owner"`
	// UID is Owner's uid (protocol 6, I1): Alice's last-root-key guard decides from it at the time
	// of the change, for every uid-0 account, not only the one named root.
	UID int `json:"uid"`
}

// AuthKeysWriteResponse answers "authkeys-write".
type AuthKeysWriteResponse struct {
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256"`
	Backup string `json:"backup"`
	// Owner is the account the helper resolved the file to (since protocol 2).
	Owner string `json:"owner"`
}

// CleanupResponse answers "cleanup".
type CleanupResponse struct {
	OK      bool `json:"ok"`
	Removed int  `json:"removed"`
}

// NginxListen is one SSL listen of a server block.
type NginxListen struct {
	Addr          string `json:"addr"` // "" = any address
	Port          int    `json:"port"`
	DefaultServer bool   `json:"default_server"`
}

// NginxPair is one ssl_certificate / ssl_certificate_key pair of a server block.
type NginxPair struct {
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	Inherited   bool   `json:"inherited"`
	Unsupported string `json:"unsupported"` // "" or an nginxconf.Reason*
	Raw         string `json:"raw"`         // the directive's argument when unsupported (cleaned, at most 200 runes)
}

// NginxServer is one server block of the parsed configuration.
type NginxServer struct {
	File    string        `json:"file"`
	Line    int           `json:"line"`
	Names   []string      `json:"names"`
	Listens []NginxListen `json:"listens"` // SSL listens only
	Pairs   []NginxPair   `json:"pairs"`
	Stream  bool          `json:"stream"`
}

// NginxFile describes one certificate or key file a supported pair references. Key files are
// only stat'ed: their content is never read or returned.
type NginxFile struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"` // "cert" | "key"
	Exists    bool   `json:"exists"`
	Resolved  string `json:"resolved"`
	Symlinked bool   `json:"symlinked"`
	Mode      string `json:"mode"`  // "0644"
	Owner     string `json:"owner"` // account name or uid
	Group     string `json:"group"` // group name or gid
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"` // certificate files only
	PEM       string `json:"pem"`    // certificate files only: CERTIFICATE blocks, nothing else
	Problem   string `json:"problem"`
	FreeBytes int64  `json:"free_bytes"`
}

// NginxDumpResponse answers "nginx-dump".
type NginxDumpResponse struct {
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	ConfPath    string `json:"conf_path"`
	ConfigValid bool   `json:"config_valid"`
	ConfigError string `json:"config_error"` // a ConfigErr* class when !ConfigValid
	// ConfigErrorReason (a ConfigReason*) and ConfigErrorFile (a cleaned absolute path, or "") say
	// why and where for ConfigErrUntrusted and ConfigErrUnsupported.
	ConfigErrorReason string        `json:"config_error_reason"`
	ConfigErrorFile   string        `json:"config_error_file"`
	Servers           []NginxServer `json:"servers"`
	Files             []NginxFile   `json:"files"`
	Warnings          []string      `json:"warnings"`
	Writable          []string      `json:"writable"` // configuration files others than root can change
}

// NginxTestResponse answers "nginx-test".
type NginxTestResponse struct {
	OK    bool   `json:"ok"`
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

// NginxStep is one step of a deployment or restore.
type NginxStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok" | "failed"
	Error  string `json:"error"`  // a ConfigErr* class or "" (never raw text)
}

// NginxDeployInput is the JSON on nginx-deploy's stdin. It carries a private key: its String,
// GoString and LogValue redact the values so %v, %+v, %#v, %s and slog never print them. The type
// must still never be put into a log or an error: %d and json.Marshal print the fields (the wire
// form requires marshaling).
type NginxDeployInput struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// String redacts the key material so %v and %+v never print it.
func (NginxDeployInput) String() string { return "helperproto.NginxDeployInput{redacted}" }

// GoString redacts the key material so %#v never prints it.
func (NginxDeployInput) GoString() string { return "helperproto.NginxDeployInput{redacted}" }

// LogValue redacts the key material for log/slog handlers.
func (NginxDeployInput) LogValue() slog.Value { return slog.StringValue("redacted") }

// NginxDeployResponse answers "nginx-deploy".
type NginxDeployResponse struct {
	OK    bool   `json:"ok"`
	Phase string `json:"phase"` // PhaseCommitted, PhaseUnchanged, PhaseRestored, PhaseRestoreFailed
	// FailedStep is the step that decided the outcome: for PhaseRestored the step that failed and
	// started the rollback; for PhaseRestoreFailed the step that failed last (StepRestore,
	// StepRollbackConfigTest, StepRollbackReload), or the starting step when the rollback left a
	// file someone else changed (Error RestoreErrFileChanged).
	FailedStep string `json:"failed_step"`
	// CauseStep is the step whose failure started the rollback ("" when there was none).
	CauseStep string      `json:"cause_step"`
	Error     string      `json:"error"`
	Steps     []NginxStep `json:"steps"`
	BackupDir string      `json:"backup_dir"`
}

// NginxRestoreResponse answers "nginx-restore".
type NginxRestoreResponse struct {
	OK         bool        `json:"ok"`
	Phase      string      `json:"phase"` // PhaseRestored, PhaseRestoreFailed, or PhasePrepared/PhaseUnchanged (nothing to restore)
	FailedStep string      `json:"failed_step"`
	CauseStep  string      `json:"cause_step"`
	Error      string      `json:"error"`
	Steps      []NginxStep `json:"steps"`
}

// NginxStatusResponse answers "nginx-status".
type NginxStatusResponse struct {
	OK                bool   `json:"ok"`
	Phase             string `json:"phase"`
	Active            bool   `json:"active"` // a helper process holds the Nginx lock now
	FailedStep        string `json:"failed_step"`
	CauseStep         string `json:"cause_step"`
	Error             string `json:"error"`
	NewCertSHA256     string `json:"new_cert_sha256"`
	CurrentCertSHA256 string `json:"current_cert_sha256"`
	BackupDir         string `json:"backup_dir"`
}

// TLSProbeResponse answers "tls-probe".
type TLSProbeResponse struct {
	OK          bool   `json:"ok"`
	LeafSHA256  string `json:"leaf_sha256"` // hex SHA-256 of the served leaf's DER
	ChainLength int    `json:"chain_length"`
	NotAfter    string `json:"not_after"` // RFC 3339 UTC
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

// ValidUser reports whether s is an acceptable Linux user name (SEC-062): the names Alice itself
// configures (the SSH login user, the sudo user).
func ValidUser(s string) bool { return userRE.MatchString(s) }

// ValidAccount reports whether s is an account name the helper lists from /etc/passwd and Alice
// stores and shows (protocol 6, AUD-03, R39): 1 to 32 bytes of ASCII letters of either case,
// digits, "_", "." and "-", not starting with "." or "-", an optional final "$" (Samba machine
// accounts), and not all digits (it would read as a uid). That is what shadow-utils' useradd
// accepts on Debian and RHEL within 32 bytes. It never holds a comma, "/", a space, a quote, "="
// or a control character, so it is safe in "sshd -T -C user=<name>,…"; a "$" that reaches an
// expanded path is refused there by ValidPath. Case is significant: "John" and "john" are two
// accounts. Names Alice itself configures keep ValidUser (SEC-062).
func ValidAccount(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	body := strings.TrimSuffix(s, "$")
	if body == "" {
		return false
	}
	digits := true
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			digits = false
		case (c == '.' || c == '-') && i > 0:
			digits = false
		default:
			return false
		}
	}
	return !digits
}

// CleanHome returns an /etc/passwd home directory as the helper names paths: absolute, without
// repeated or trailing "/" and "." elements (the kernel and sshd read them the same way), and a
// ValidPath. A ".." element is refused, never cleaned: through a symbolic link it names another
// directory than the lexical result (AUD-03).
func CleanHome(h string) (string, bool) {
	if !strings.HasPrefix(h, "/") || slices.Contains(strings.Split(h, "/"), "..") {
		return "", false
	}
	c := filepath.Clean(h)
	if !ValidPath(c) {
		return "", false
	}
	return c, true
}

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

// ValidPort reports whether s is a decimal TCP port 1..65535 without leading zeros.
func ValidPort(s string) bool {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// ValidSNI reports whether s is a lower-case DNS name Alice may send as SNI: 1..253 bytes of
// [a-z0-9.-], no empty label, no leading or trailing hyphen in a label. IP literals are refused
// (RFC 6066 forbids them in server_name).
func ValidSNI(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ValidIP reports whether s is an IPv4 or IPv6 literal without a zone in its canonical form.
func ValidIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.String() == s
}

// ProbeTLSConfig is the client configuration of both verification probes (Alice's and the
// helper's tls-probe): no certificate verification (the served leaf's fingerprint is compared,
// spec §12.8 item 3), TLS 1.2 or later. With keyType ProbeAny the maximum version is left open,
// so a TLS 1.3-only site can be probed. ProbeRSA or ProbeECDSA limits the probe to TLS 1.2 with
// ECDHE_RSA or ECDHE_ECDSA suites so a dual-certificate server shows the one of that type
// (spec §12.8 item 4); callers use them only for that purpose. An unknown keyType behaves like
// ProbeAny, so callers validate the value. sni "" or NoSNI sends no name.
func ProbeTLSConfig(sni, keyType string) *tls.Config {
	c := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the probe only compares the served leaf's SHA-256 with the expected certificate (spec §12.8 item 3); it never trusts the connection or sends data
		MinVersion:         tls.VersionTLS12,
	}
	if sni != "" && sni != NoSNI {
		c.ServerName = sni
	}
	switch keyType {
	case ProbeRSA:
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	case ProbeECDSA:
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
	}
	return c
}

// marshal is json.Marshal (tests replace it to reach FitList's encoding failure).
var marshal = json.Marshal

// FitList keeps a whole authkeys-list answer, its newline included, within MaxListOutput (S8), so
// a large but legal configuration never makes Alice's read fail: first files give up their inline
// content, the last listed first (Alice reads them with authkeys-read; their hash stays); then
// users are left out from the end (the highest uids; TruncatedFromUID names the first of them),
// and finally the account names; the answer then says Truncated and the account list is not
// complete. Every round gives something up or returns, so it ends. The helper and Alice's emulator
// both use it.
func FitList(resp AuthKeysListResponse) AuthKeysListResponse {
	for {
		b, err := marshal(resp)
		if err != nil {
			return resp
		}
		excess := len(b) + 1 - MaxListOutput
		if excess <= 0 {
			return resp
		}
		if dropInline(&resp, excess) {
			continue
		}
		resp.Truncated, resp.AccountsComplete = true, false
		if n := len(resp.Users); n > 0 {
			freed := 0
			for n > 0 && freed < excess {
				u, _ := marshal(resp.Users[n-1])
				freed += len(u) + 1
				n--
			}
			uid := resp.Users[n].UID
			resp.Users, resp.TruncatedFromUID = resp.Users[:n], &uid
			continue
		}
		if len(resp.Accounts) == 0 {
			return resp
		}
		resp.Accounts = []string{}
	}
}

// dropInline removes the inline content of the last listed files until at least excess bytes of
// the encoded answer are freed (or none is left); it reports whether it removed any.
func dropInline(resp *AuthKeysListResponse, excess int) bool {
	freed, dropped := 0, false
	for i := len(resp.Users) - 1; i >= 0 && freed < excess; i-- {
		files := resp.Users[i].Files
		for j := len(files) - 1; j >= 0 && freed < excess; j-- {
			if !files[j].Inline {
				continue
			}
			// `,"content_b64":"…"` goes; `"inline":true` becomes `"inline":false` (one byte more).
			freed += len(files[j].ContentB64) + len(`,"content_b64":""`) - 1
			files[j].Inline, files[j].ContentB64 = false, ""
			dropped = true
		}
	}
	return dropped
}

// Protocol 7 subcommands (ACME HTTP-01, Task 7). Alice never edits the Nginx configuration: the
// administrator publishes ACMEWebroot on port 80 with a location block of their own, and the helper
// only writes and removes one token file in ACMEChallengeDir.
const (
	// SubACMEChallengePut: "acme-challenge-put --token T", the key authorization on stdin. The
	// file ACMEChallengeDir/T is created (or replaced atomically), root's, mode 0644.
	SubACMEChallengePut = "acme-challenge-put"
	// SubACMEChallengeRm: "acme-challenge-rm --token T" removes ACMEChallengeDir/T; a missing file
	// (or a missing directory) is success with Removed false.
	SubACMEChallengeRm = "acme-challenge-rm"
)

// HTTP-01 webroot (fixed: no argument names a path).
const (
	// ACMEWebroot is the directory the administrator publishes on port 80 for
	// /.well-known/acme-challenge/ ("root /var/www/alice-acme;").
	ACMEWebroot = "/var/www/alice-acme"
	// ACMEChallengeDir holds the token files. The administrator creates it (root's, 0755); the
	// helper never creates a directory and refuses a path with a link, a directory that is not
	// root's or that group or others can write, or one on a pseudo or FUSE file system.
	ACMEChallengeDir = ACMEWebroot + "/.well-known/acme-challenge"
	// MaxACMEBody bounds acme-challenge-put's stdin.
	MaxACMEBody = 512
	// MinACMEToken and MaxACMEToken bound a token (RFC 8555 §8.3: at least 128 bits of entropy,
	// base64url without padding, so at least 22 characters).
	MinACMEToken = 22
	MaxACMEToken = 128
	// acmeThumbprintLen is the base64url length (no padding) of a SHA-256 JWK thumbprint.
	acmeThumbprintLen = 43
)

// ACMEChallengeDirElems are the path elements of ACMEChallengeDir below "/", in walk order.
func ACMEChallengeDirElems() []string {
	return strings.Split(strings.TrimPrefix(ACMEChallengeDir, "/"), "/")
}

// ACMEChallengePath is the token file of a valid token on the server.
func ACMEChallengePath(token string) string { return ACMEChallengeDir + "/" + token }

// ACMEChallengeURLPath is the URL path the CA (and Alice's own check) fetches for a token.
func ACMEChallengeURLPath(token string) string { return "/.well-known/acme-challenge/" + token }

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// ValidACMEToken reports whether s is an HTTP-01 token the helper accepts as a file name:
// MinACMEToken to MaxACMEToken characters of [A-Za-z0-9_-]. No ".", "/", NUL, space or non-ASCII
// byte can pass, so a token is always one plain name in ACMEChallengeDir. A token may start with
// "-" (base64url); the helper reads it as the value of --token, never as an option.
func ValidACMEToken(s string) bool {
	if len(s) < MinACMEToken || len(s) > MaxACMEToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBase64URL(s[i]) {
			return false
		}
	}
	return true
}

// ValidKeyAuthorization reports whether body is the key authorization of token (RFC 8555 §8.1):
// the token, ".", and the 43-character base64url SHA-256 thumbprint of the account key, with
// nothing before or after (no newline). Its length is fixed by the token, so a body cut short in
// transit is refused rather than published.
func ValidKeyAuthorization(token string, body []byte) bool {
	if !ValidACMEToken(token) || len(body) != len(token)+1+acmeThumbprintLen || string(body[:len(token)]) != token || body[len(token)] != '.' {
		return false
	}
	for _, c := range body[len(token)+1:] {
		if !isBase64URL(c) {
			return false
		}
	}
	return true
}

// ACMEChallengePutResponse answers acme-challenge-put.
type ACMEChallengePutResponse struct {
	OK       bool   `json:"ok"`
	Path     string `json:"path"`     // the token file (ACMEChallengePath)
	Replaced bool   `json:"replaced"` // a token file of that name existed and was replaced
}

// ACMEChallengeRmResponse answers acme-challenge-rm.
type ACMEChallengeRmResponse struct {
	OK      bool   `json:"ok"`
	Path    string `json:"path"`
	Removed bool   `json:"removed"` // false: there was no such file (success)
}
