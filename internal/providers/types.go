package providers

import "github.com/google/uuid"

// OSRelease is the part of /etc/os-release Alice shows.
type OSRelease struct{ ID, VersionID, PrettyName string }

// ConnectionReport is the result of TestConnection.
type ConnectionReport struct {
	HostKey        HostKey
	HelperVersion  string
	HelperProtocol int
	OS             OSRelease
	Warnings       []Warning
}

// DiscoverRequest selects what Discover reads.
type DiscoverRequest struct{ SSHKeys bool }

// DiscoveryResult is read-only data; inventory reconciles it.
type DiscoveryResult struct {
	SSHKeys         []DiscoveredSSHKey
	HostKeys        []DiscoveredHostKey
	SSHD            SSHDSummary
	UnreadableLines []UnreadableLine
	Warnings        []Warning
	Partial         bool     // some source failed (a file could not be read); reported, it does not stop missing marking
	UID0Users       []string // listed accounts with uid 0 (root and any other); their last key is guarded like root's
	ReadFiles       []string // files read completely: missing marking is limited to these, also in a partial scan (R37 #23)
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
