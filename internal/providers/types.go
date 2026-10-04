package providers

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"alice/internal/secrets"
)

// OSRelease is the part of /etc/os-release Alice shows.
type OSRelease struct{ ID, VersionID, PrettyName string }

// ConnectionReport is the result of TestConnection.
type ConnectionReport struct {
	HostKey        HostKey
	HelperVersion  string
	HelperProtocol int
	OS             OSRelease
	Warnings       []Warning
	Nginx          *NginxFacts // what the Nginx provider found on the server; nil for linuxssh
	Azure          *AzureFacts // the vault's access check; nil for other providers
}

// DiscoverRequest selects what Discover reads. SSHKeys and Certificates are Phase 3/4's; for a
// Key Vault, Certificates lists the vault's certificates and the KV fields select the rest
// (spec §11.6; R40 rows 15-17).
type DiscoverRequest struct {
	SSHKeys, Certificates bool
	KVKeys, KVSecrets     bool                 // also list keys / secrets (every fourth poll, §11.6 item 4)
	KVKnown               map[string]KVKnown   // certificate name -> what Alice stored; details are fetched when the listing differs
	KVKnownKeys           map[string]time.Time // key name -> attributes.updated whose details Alice read
}

// DiscoveryResult is read-only data; inventory reconciles it.
type DiscoveryResult struct {
	SSHKeys          []DiscoveredSSHKey
	HostKeys         []DiscoveredHostKey
	SSHD             SSHDSummary
	UnreadableLines  []UnreadableLine
	Warnings         []Warning
	Partial          bool     // some source failed (a file could not be read); reported, it does not stop missing marking
	UID0Users        []string // listed accounts with uid 0 (root and any other); their last key is guarded like root's
	Accounts         []string // every account name of /etc/passwd the helper reported (carry 1)
	AccountsComplete bool     // Accounts is the whole list; only then may inventory mark vanished users' keys missing
	ReadFiles        []string // files read completely: missing marking is limited to these, also in a partial scan (R37 #23)
	Certificates     []DiscoveredCertificate
	Nginx            *NginxFacts  // nil when certificates were not read
	KV               *KVInventory // the Key Vault half; nil for other providers
}

// DiscoveredSSHKey is one authorized_keys entry.
type DiscoveredSSHKey struct {
	OSUser      string
	FilePath    string
	LineNo      int
	PublicKey   string // "ssh-ed25519 AAAA…" (type and base64 blob, no options, no comment)
	Fingerprint string // "SHA256:…"
	KeyType     string
	Bits        int
	Comment     string
	Options     string   // verbatim option text, "" when none
	Flags       []string // Flag* values
}

// Flags of discovered keys (spec §13.3 item 5).
const (
	FlagWeak            = "weak"              // RSA < 2048, DSA
	FlagCommand         = "command"           // command= present (shown, never touched)
	FlagRootWithoutFrom = "root_without_from" // root key without from=
	FlagDuplicate       = "duplicate"         // same key more than once in the file
	FlagCertAuthority   = "cert_authority"    // cert-authority line: inventory only, never managed
	FlagSecurityKey     = "security_key"      // sk-* (FIDO) key
)

// DiscoveredHostKey is one server host key from the host key inventory (informational).
type DiscoveredHostKey struct {
	KeyType     string
	Bits        int
	Fingerprint string
	Weak        bool // DSA, RSA < 2048
}

// SSHDSummary is what Alice shows from sshd's effective configuration (spec §13.2).
type SSHDSummary struct {
	Read                   bool // false: sshd -T failed, defaults were assumed
	PubkeyAuthentication   string
	PasswordAuthentication string
	PermitRootLogin        string
	AuthorizedKeysFile     []string
	AuthorizedKeysCommand  string // "none" or the program
	KeysManagedElsewhere   bool   // AuthorizedKeysCommand is set (F-35)
	CertificatesInUse      bool   // TrustedUserCAKeys or AuthorizedPrincipalsFile set
}

// UnreadableLine is an authorized_keys line that does not parse (kept verbatim, never changed).
type UnreadableLine struct {
	OSUser, FilePath string
	LineNo           int
}

// Warning is a stable code (i18n key "warnings.<code>") and its parameters.
type Warning struct {
	Code   string
	Params map[string]string
}

// AuthKeyChange asks for one authorized_keys change.
type AuthKeyChange struct {
	OperationID           uuid.UUID
	OSUser                string
	FilePath              string
	Fingerprint           string   // remove: the key to remove
	Line                  string   // add: the authorized_keys line to add
	ProtectedFingerprints []string // keys that must never be removed (the platform key)
	AllowLastRootKey      bool
}

// AuthKeyResult is the outcome of a change.
type AuthKeyResult struct {
	Changed   bool
	Removed   int
	OldSHA256 string
	NewSHA256 string
	Verified  bool
	Backup    string // the helper's backup of the previous file (for restoring), when a write happened
}

// StepStatus is the state of one externally visible step.
type StepStatus string

// Step states.
const (
	StepStarted StepStatus = "started"
	StepOK      StepStatus = "ok"
	StepFailed  StepStatus = "failed"
	StepSkipped StepStatus = "skipped"
)

// StepLogger records the steps of a mutating operation (params are redacted, never secrets).
type StepLogger interface {
	Step(name string, status StepStatus, params map[string]string)
}

// Descriptor is what GET /providers shows.
type Descriptor struct {
	Kind             Kind
	DisplayNameKey   string
	Capabilities     []Capability
	ConfigSchema     ConfigSchema
	CredentialSchema CredentialSchema
}

// NginxFacts is what Alice shows about Nginx on a server.
type NginxFacts struct {
	Version     string `json:"version"`
	ConfPath    string `json:"conf_path"`
	ConfigValid bool   `json:"config_valid"`
	// ConfigError is a ConfigErr* class when !ConfigValid, never raw nginx output.
	ConfigError string `json:"config_error"`
	// ConfigErrorReason (a ConfigReason* value) and ConfigErrorFile (a cleaned absolute path, or
	// "") say why and where for ConfigErrUntrusted and ConfigErrUnsupported.
	ConfigErrorReason string `json:"config_error_reason"`
	ConfigErrorFile   string `json:"config_error_file"`
	Found             bool   `json:"found"`
}

// Configuration error classes of NginxFacts.ConfigError and of a deployment step's Error. They
// equal helperproto.ConfigErr* (a test compares them).
const (
	ConfigErrKeyMismatch = "key_mismatch"
	ConfigErrFileMissing = "file_missing"
	ConfigErrCertLoad    = "cert_load"
	ConfigErrKeyLoad     = "key_load"
	ConfigErrSyntax      = "syntax"
	ConfigErrUntrusted   = "untrusted"   // nginx -T's output cannot be trusted
	ConfigErrUnsupported = "unsupported" // a configuration Alice cannot read safely
)

// Reasons of NginxFacts.ConfigErrorReason (a closed set); they equal helperproto.ConfigReason*.
const (
	ConfigReasonNotRootControlled = "not_root_controlled"
	ConfigReasonSpecialFS         = "special_filesystem"
	ConfigReasonMissing           = "missing"
	ConfigReasonNotRegular        = "not_regular"
	ConfigReasonChanged           = "changed"
	ConfigReasonNameNotAllowed    = "name_not_allowed"
	ConfigReasonUnexpectedText    = "unexpected_text"
	ConfigReasonWrongFirstFile    = "wrong_first_file"
	ConfigReasonDuplicateFile     = "duplicate_file"
	ConfigReasonNoConfPath        = "no_conf_path"
	ConfigReasonTooLarge          = "too_large"
	ConfigReasonTooComplex        = "too_complex"
	ConfigReasonIncludeLoop       = "include_loop"
	ConfigReasonNULByte           = "nul_byte"
)

// DiscoveredCertificate is one certificate file Nginx uses.
type DiscoveredCertificate struct {
	Location CertLocation
	// PEMChain is the file's CERTIFICATE blocks that parse as X.509, re-encoded in file order (not
	// the file's bytes: text around the blocks is gone); empty when Location.Problem != "".
	PEMChain []byte
	// FileSHA256 is the SHA-256 of the file's bytes on disk as the helper read them. It is NOT the
	// hash of PEMChain (the two differ whenever the file holds anything but canonical blocks), and
	// it is the value a deployment sends as the compare-and-swap expectation. Never compare it with
	// a hash of PEMChain.
	FileSHA256 string
}

// CertLocation is a certificate/key file pair of an Nginx server and the server blocks using it.
type CertLocation struct {
	CertPath         string
	KeyPath          string
	ResolvedCertPath string
	Servers          []CertServer
	Inherited        bool
	Symlinked        bool
	CustomLocation   bool // resolved outside /etc/ssl, /etc/nginx, /etc/pki, /etc/letsencrypt
	Supported        bool
	Unsupported      string // Unsupported* reason when !Supported
	Problem          string // CertProblem* code of the certificate file
	KeyExists        bool
	KeyMode          string
	KeyOwner         string
	KeyGroup         string // account group name or gid of the key file
	KeyProblem       string // CertProblem* code of the key file
	Warnings         []string
	FreeBytes        int64
}

// CertServer is one server block using a location (only its SSL listens).
type CertServer struct {
	Names   []string     `json:"names"`
	Listens []CertListen `json:"listens"`
	File    string       `json:"file"`
	Line    int          `json:"line"`
}

// CertListen is one SSL listen of a server block.
type CertListen struct {
	Addr          string `json:"addr"`
	Port          int    `json:"port"`
	DefaultServer bool   `json:"default_server"`
}

// Unsupported reasons of CertLocation.Unsupported (nginxconf's plus the ones the provider and
// inventory add); the nginxconf ones equal nginxconf.Reason* (a test compares them).
const (
	UnsupportedVariable           = "variable"
	UnsupportedDataValue          = "data_value"
	UnsupportedEngineKey          = "engine_key"
	UnsupportedKeyMissing         = "key_missing"
	UnsupportedPasswordFile       = "password_file"
	UnsupportedPathNotAllowed     = "path_not_allowed"
	UnsupportedStream             = "stream"
	UnsupportedCombinedFile       = "combined_file"
	UnsupportedConfigFileWritable = "config_file_writable" // a configuration file can be changed by users other than root
	UnsupportedKeyConflict        = "key_conflict"         // one certificate file used with different key files
	UnsupportedFile               = "file_problem"         // see Problem / KeyProblem
	UnsupportedKeyType            = "unsupported_key"      // the certificate is not RSA or ECDSA (set by inventory)
	// UnsupportedUnknown: the helper gave a reason Alice does not know (a newer helper, or a broken
	// one). The location is unsupported; the UI shows a generic text.
	UnsupportedUnknown = "unknown"
)

// Certificate and key file problems of CertLocation.Problem / KeyProblem (helperproto.File*).
const (
	CertProblemMissing           = "missing"
	CertProblemNotRootControlled = "not_root_controlled"
	CertProblemNotRegular        = "not_regular"
	CertProblemHardLinked        = "hard_linked"
	CertProblemTooLarge          = "too_large"
	CertProblemNotACertificate   = "not_a_certificate"
	CertProblemUnreadable        = "unreadable"
	CertProblemBadName           = "bad_name"
	CertProblemSpecialFS         = "special_filesystem" // on FUSE or a pseudo file system
	// CertProblemNameNotAllowed: the file resolves (through root's links) to a path outside the
	// helper's argument vocabulary (a space, "*", "~", ",", non-ASCII; an acme.sh "*.example.com"
	// directory). The helper never deploys to it.
	CertProblemNameNotAllowed = "name_not_allowed"
	// CertProblemUnknown: the helper gave a problem Alice does not know; the file is not used.
	CertProblemUnknown = "unknown"
)

// Warnings of CertLocation.Warnings (location level) and of Warning.Code in a discovery (server
// level). The helper-sourced ones equal helperproto.Warn*.
const (
	WarnKeyModeOpen    = "key_mode_open" // key file mode allows more than 0640
	WarnSymlinked      = "symlinked"     // another tool (certbot) may replace the file
	WarnCustomLocation = "custom_location"
	// WarnKeyGroupOpen: the key file is owned by a user other than root, or readable by a group
	// other than root's or by others; a deployment keeps owner, group and 0640.
	WarnKeyGroupOpen = "key_group_open"
	// WarnCertificateBlockDropped: a CERTIFICATE block of the file is not an X.509 certificate;
	// the others were returned.
	WarnCertificateBlockDropped = "certificate_block_dropped"
	WarnStreamTLS               = "stream_tls"           // TLS in stream {} is listed, not supported
	WarnMailTLS                 = "mail_tls"             // TLS in mail {} is listed, not supported
	WarnConfigFileWritable      = "config_file_writable" // a configuration file can be changed by users other than root
	WarnTooManyFiles            = "too_many_files"       // more referenced files than the helper describes
	// WarnListTruncated: Alice cut a list of the dump at its bound (server names, listens or
	// servers of a location, writable files); what is shown is incomplete.
	WarnListTruncated = "list_truncated"
	// WarnLocationsDropped: Alice left certificate locations of the dump out (more than
	// helperproto.MaxNginxFiles): the list is not every location of the server, so inventory marks
	// none missing. Only the provider emits it (too_many_files is the helper's own warning).
	WarnLocationsDropped = "locations_dropped"
)

// VerifyOptions are a location's verification settings (Administrator, R38 item 6).
type VerifyOptions struct {
	Port int    // 0 = the ports of the SSL listens
	SNI  string // "" = derived from server_name and the certificate (spec §12.8 item 1)
	Skip bool
}

// Requests are validated by the provider, not by the framework: operation ids, paths, SNI, ports
// and hashes pass through the provider's helperproto validators when it builds helper commands.

// DeployRequest asks for one deployment of a certificate file pair (spec §6.3). It carries a
// private key: Format and LogValue print nothing but the operation id, so no fmt verb and no slog
// handler shows the key, and the key has no JSON form (the wire form is helperproto's).
type DeployRequest struct {
	OperationID      uuid.UUID // = deployment id = the helper's operation id
	Location         CertLocation
	ExpectCertSHA256 string            // the certificate file's SHA-256 from the last discovery
	CertificatePEM   []byte            // leaf first, then the chain (public)
	PrivateKeyPEM    secrets.Plaintext `json:"-"` // the caller zeroes it after the call
	Fingerprint      string            // hex SHA-256 of the new leaf
	SANs             []string
	KeyType          string // "rsa" | "ecdsa"
	OldFingerprint   string // served before the change ("" when verification is skipped)
	OldSANs          []string
	Verify           VerifyOptions
	// ChainLength is the number of certificates in CertificatePEM (>= 1), set by the caller that
	// parsed the chain; the provider compares the served chain length with it (spec §12.8 item 5).
	ChainLength int
}

func (r DeployRequest) redacted() string {
	return fmt.Sprintf("providers.DeployRequest{operation:%s, key:[redacted]}", r.OperationID)
}

// Format prints the operation id only, for every verb and flag; the value receiver covers
// pointers too.
func (r DeployRequest) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, r.redacted()) }

// LogValue keeps the key out of slog output.
func (r DeployRequest) LogValue() slog.Value { return slog.StringValue(r.redacted()) }

// DeployResult is how an operation ended on the server. Only DeployNoChange, a refusal by a
// well-formed helper answer, means that nothing changed. DeployUncertain means Alice does not
// know: a timeout, a lost connection, a malformed answer, an unexpected exit status.
type DeployResult string

// Deploy results.
const (
	// DeployCommitted: the new files are live and verified.
	DeployCommitted DeployResult = "committed"
	// DeployUnchanged: the files already held this certificate.
	DeployUnchanged DeployResult = "unchanged"
	// DeployNoChange: nothing was changed by this operation. A provider reports it only for a
	// well-formed refusal (the provider's own before contacting the helper, the helper's, or
	// sudo's before the helper started), never for a transport failure, a timeout or an answer it
	// cannot parse. The one other case: the helper answered "unchanged" and the verification then
	// failed (Phase unchanged, FailedStep verify; see outcome.go).
	DeployNoChange DeployResult = "no_change"
	// DeployRolledBack: changed, failed, previous files restored and verified.
	DeployRolledBack DeployResult = "rolled_back"
	// DeployRollbackFailed: changed, failed, and the restore did not finish.
	DeployRollbackFailed DeployResult = "rollback_failed"
	// DeployUncertain: the outcome is unknown (the request may have reached the helper); read it
	// with DeploymentStatus. The error returned with it says why.
	DeployUncertain DeployResult = "uncertain"
)

// Deployment step names, in the order a deployment reports them to the StepLogger: the helper's
// (equal to helperproto.Step*), then the provider's. Step params are allowlisted primitives
// (error, port, mode, served).
const (
	StepNameBackup             = "backup"
	StepNameWriteKey           = "write_key"
	StepNameWriteCert          = "write_cert"
	StepNameConfigTest         = "config_test"
	StepNameReload             = "reload"
	StepNameJournal            = "journal" // the journal could not record the commit: the helper rolled back
	StepNameRestore            = "restore"
	StepNameRollbackConfigTest = "rollback_config_test"
	StepNameRollbackReload     = "rollback_reload"
	// StepNameVerify and StepNameVerifyOld are provider-side steps with no helperproto
	// counterpart: the helper never reports them.
	StepNameVerify    = "verify"     // the served certificate after the change
	StepNameVerifyOld = "verify_old" // the old certificate after a rollback
)

// DeployErrFileChanged is DeployOutcome.Error when a certificate or key file holds neither the
// deployed nor the backed-up content (someone else changed it): nothing was restored.
const DeployErrFileChanged = "file_changed"

// DeployStep is one step a completed operation reported.
type DeployStep struct {
	Name   string // StepName*
	Status StepStatus
	// Error is a ConfigErr* class, DeployErrFileChanged or "" (also "" for a failed step whose
	// cause is not a configuration error, such as a killed Nginx); never raw text.
	Error string
}

// DeployOutcome is the result of DeployCertificate. Exactly three situations exist: an explicit
// refusal (Result DeployNoChange: nothing changed, no Steps, returned with a *Error), a completed
// operation (committed, unchanged, rolled back or rollback failed, with its Steps, returned with a
// nil error) and an uncertain one (DeployUncertain, returned together with the error that made it
// uncertain). Validate and CheckDeployReturn enforce this (see outcome.go for every rule). A
// blank or unknown Result, an outcome that fails Validate and any error that is not one of the
// above are uncertain: read the truth with DeploymentStatus.
type DeployOutcome struct {
	Result DeployResult
	// Phase is the helper journal phase of a completed operation (Phase*), "" otherwise.
	Phase string
	// FailedStep is the step that decided the outcome; CauseStep the step whose failure started
	// the rollback ("" when none). Both are StepName* values.
	FailedStep string
	CauseStep  string
	// Error is the helper's error class of a completed, failed operation (ConfigErr*,
	// DeployErrFileChanged or "").
	Error  string
	Steps  []DeployStep
	Reason string // stable reason (ALC code) when Result is not committed/unchanged
	Params map[string]string
	// Verified is "remote" | "local" | "skipped" | "".
	Verified string
	Backup   BackupRef
}

// BackupRef is persisted in deployments.rollback_info before the first change (spec §6.3 item 3).
type BackupRef struct {
	OperationID uuid.UUID `json:"operation_id"`
	Dir         string    `json:"dir,omitempty"`
}

// RollbackRequest restores the files an operation replaced and checks the old certificate.
type RollbackRequest struct {
	OperationID    uuid.UUID
	Location       CertLocation
	OldFingerprint string
	OldChainLength int // certificates in the old chain, compared with the served chain; 0 = not compared
	OldSANs        []string
	KeyType        string
	Verify         VerifyOptions
}

// RollbackOutcome is the result of RollbackDeployment. Result is DeployRolledBack,
// DeployRollbackFailed, DeployNoChange or DeployUncertain (returned with the error); see
// RollbackOutcome.Validate and CheckRollbackReturn for the rules. DeployNoChange means "nothing was
// restored" (the helper answered phase prepared or unchanged, or refused with SUPERSEDED because a
// later operation replaced the files). It does NOT mean the files are unchanged since the
// deployment: the engine must not read it that way. A blank or unknown Result, or an outcome that
// fails Validate, is uncertain: read the truth with DeploymentStatus.
type RollbackOutcome struct {
	Result     DeployResult
	Phase      string // Phase* of the helper's answer, "" when none
	FailedStep string
	CauseStep  string
	Error      string // as DeployOutcome.Error
	Steps      []DeployStep
	Reason     string
	Params     map[string]string
	Verified   string
}

// VerifyRequest (validated by the provider, like every request) checks which certificate the location's websites serve.
type VerifyRequest struct {
	Location            CertLocation
	Fingerprint         string // expected leaf; "" = report what is served
	ChainLength         int    // certificates in the expected chain, compared with the served one (spec §12.8 item 5); 0 = not compared
	PreviousFingerprint string // the leaf served before the change: a mismatch equal to it is verify_failed (F-05), another is verify_other (F-06)
	SANs                []string
	KeyType             string
	Verify              VerifyOptions
}

// VerifyResult is the result of VerifyDeployment.
type VerifyResult struct {
	OK                bool
	Mode              string // "remote" | "local" | "skipped"
	Served            string // the fingerprint served (first mismatching endpoint, or the first endpoint when Fingerprint == "")
	ServedChainLength int    // certificates the endpoint served (the helper's chain_length); 0 when nothing was probed
	Reason            string // "deployment.verify_failed" | "deployment.verify_other" | "deployment.verify_unreachable"
	Params            map[string]string
}

// Deployment phases of DeploymentState (the nginx provider reports the helper journal's phases,
// whose names are the same: a test compares them with helperproto.Phase*). jobs may not import
// helperproto (archtest), so the engine uses these.
const (
	PhaseNone          = "none"
	PhasePrepared      = "prepared"
	PhaseWriting       = "writing"
	PhaseCommitted     = "committed"
	PhaseUnchanged     = "unchanged"
	PhaseRestoring     = "restoring"
	PhaseRestored      = "restored"
	PhaseRestoreFailed = "restore_failed"
	// PhaseFenced: Session.FenceDeployment made sure the operation never runs on the server
	// (AUD-05); nothing was written by it. DeploymentStatus reports it too.
	PhaseFenced = "fenced"
)

// DeploymentState is what the server knows about an operation (helper journal).
type DeploymentState struct {
	Phase             string // Phase*
	Active            bool
	FailedStep        string // as DeployOutcome.FailedStep
	CauseStep         string
	Error             string // as DeployOutcome.Error
	NewCertSHA256     string
	CurrentCertSHA256 string
	BackupDir         string
}
