// Package providers defines the compile-time provider framework (spec §6): the Provider and
// Session interfaces, capabilities, declarative config schemas, the frozen registry and the one
// error type providers return. Providers are pure adapters: no database access (archtest), no
// runtime code loading.
package providers

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
)

// Kind names a provider.
type Kind string

// Provider kinds of v1.
const (
	KindLinuxSSH Kind = "linuxssh"
	KindNginx    Kind = "nginx"
	KindAzureKV  Kind = "azurekv"
)

// The reasons every web-server provider shares (internal/providers/webserver). The error code is
// the provider kind, a dot and the reason (Kind.Reason): "nginx.not_found".
const (
	ReasonNotFound       = "not_found"       // the web server is not installed
	ReasonProfileMissing = "profile_missing" // sudo refused a subcommand of the provider's sudoers profile
	ReasonConfigInvalid  = "config_invalid"  // the web server's configuration test fails
	ReasonHelperTooOld   = "helper_too_old"  // the helper's protocol is below what the provider's dump needs
)

// Reason is the error code of reason r for this provider kind: "<kind>.<r>".
func (k Kind) Reason(r string) string { return string(k) + "." + r }

// KindForTargetType maps targets.type to the provider kind (spec §6.4).
func KindForTargetType(t string) (Kind, bool) {
	switch t {
	case "linux":
		return KindLinuxSSH, true
	case "nginx":
		return KindNginx, true
	case "azure_key_vault":
		return KindAzureKV, true
	default:
		return "", false
	}
}

// TargetConfig is the non-secret target configuration (targets.config).
type TargetConfig map[string]any

// TargetRef identifies the target a session works on.
type TargetRef struct {
	ID     uuid.UUID
	Name   string
	Kind   Kind
	Config TargetConfig
}

// HostKey is an SSH server key in wire form plus its SHA-256 fingerprint ("SHA256:…").
type HostKey struct {
	Type        string // ssh.PublicKey.Type(), e.g. "ssh-ed25519"
	PublicKey   []byte // ssh.PublicKey.Marshal()
	Fingerprint string // ssh.FingerprintSHA256
}

// ErrNoPinnedKey is returned by HostKeyStore.Pinned when no key is pinned for the target.
var ErrNoPinnedKey = errors.New("providers: no pinned host key")

// HostKeyStore is implemented by inventory. Pinned returns ErrNoPinnedKey when nothing is pinned.
// Observed records a presented key that is not pinned. changed is the caller's view (another key
// was pinned when it compared) and is advisory only: the store decides from its own pinned key
// whether the sighting is a change that blocks the target, so a stale or wrong flag never unblocks
// or skips a block. Observed must honour ctx, may complete after Dial has returned (Dial stops
// waiting at its handshake budget), and must be idempotent per (target, key).
type HostKeyStore interface {
	Pinned(ctx context.Context, target uuid.UUID) (HostKey, error)
	Observed(ctx context.Context, target uuid.UUID, key HostKey, changed bool) error
}

// CredentialSource hands a provider the secret of one session. release zeroes what was decrypted.
type CredentialSource interface {
	SSHSigner(ctx context.Context) (signer ssh.Signer, release func(), err error)
}

// Env carries injected dependencies so providers stay pure.
type Env struct {
	Clock    clock.Clock
	HostKeys HostKeyStore
	Log      *slog.Logger // already redacting
	// FreshConnection asks for a new connection instead of a reused one: an explicit connection
	// test must see the host key the server presents now (R37 item 21). The connection may be
	// kept for reuse afterwards.
	FreshConnection bool
}

// Provider is one kind of managed system.
type Provider interface {
	Kind() Kind
	DisplayNameKey() string
	Capabilities() CapabilitySet
	ConfigSchema() ConfigSchema
	CredentialSchema() CredentialSchema
	ValidateConfig(cfg TargetConfig) []validate.FieldError
	Open(ctx context.Context, t TargetRef, cred CredentialSource, env Env) (Session, error)
}

// Session is one connection scope. Methods of capabilities a provider does not advertise return
// ErrUnsupported (embed UnsupportedSession). A provider advertises a capability only when its
// methods are implemented: the conformance suite fails otherwise.
type Session interface {
	Close() error
	TestConnection(ctx context.Context) (ConnectionReport, error)
	Discover(ctx context.Context, req DiscoverRequest) (DiscoveryResult, error)
	// ListAuthorizedKeys returns the keys a full discovery finds and nothing about what it read: a key
	// missing from it proves nothing. Code that must conclude "not in the file" uses ListKeys.
	ListAuthorizedKeys(ctx context.Context) ([]DiscoveredSSHKey, error)
	// ListKeys (CapAuthorizedKeys) is ListAuthorizedKeys with the coverage of every candidate file it
	// names (KeyListing): a key is absent only where KeyListing.Absent says so.
	ListKeys(ctx context.Context) (KeyListing, error)
	AddAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)
	RemoveAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)
	// VerifyKeyLogin (CapKeyLogin) tries one login (KeyLoginRequest). A refused or unprovable login
	// is an outcome with a nil error; a connection that fails (unreachable, timeout, host key changed
	// or unconfirmed, address refused) is an error. It changes no target state itself, except that
	// the dial records an observed changed host key, as every dial does. An empty request is refused
	// with a *Error (ssh.helper_refused, param field os_user) before anything is sent.
	VerifyKeyLogin(ctx context.Context, req KeyLoginRequest) (KeyLoginResult, error)
	// DeployCertificate (CapDeployCertificate) never returns a non-nil error together with a
	// change it knows about: a known change is an outcome with a nil error. A well-formed helper
	// refusal is DeployNoChange with a non-nil *Error; a transport failure after the request was
	// sent, a timeout, an unparsable answer or an unexpected exit is DeployUncertain with the
	// error (CheckDeployReturn lists every rule). A caller treats an outcome that fails
	// DeployOutcome.Validate, a blank or unknown Result or an unmapped error as uncertain and reads
	// the truth with DeploymentStatus.
	DeployCertificate(ctx context.Context, req DeployRequest, log StepLogger) (DeployOutcome, error)
	// RollbackDeployment (CapDeployCertificate) restores the files an operation replaced. The same
	// rules apply (CheckRollbackReturn): an outcome that fails RollbackOutcome.Validate, a blank or
	// unknown Result or an unmapped error is uncertain; read the truth with DeploymentStatus.
	RollbackDeployment(ctx context.Context, req RollbackRequest, log StepLogger) (RollbackOutcome, error)
	// DeploymentStatus (CapDeployCertificate) reads what the server knows about an operation. A
	// state that fails DeploymentState.Validate must not be acted on.
	DeploymentStatus(ctx context.Context, op uuid.UUID) (DeploymentState, error)
	// FenceDeployment (CapDeployCertificate; AUD-05) makes sure an operation that left no journal
	// can never be carried out afterwards (a send that reaches the server late): it answers
	// PhaseFenced when the operation now never runs and wrote nothing, or the state of the
	// journal it found after all (any other phase; nothing changed then). Only PhaseFenced with a
	// nil error proves "nothing was written"; an error, or an answer that fails
	// DeploymentState.Validate, proves nothing (uncertain).
	FenceDeployment(ctx context.Context, op uuid.UUID) (DeploymentState, error)
	// ReadCertificateSecret (CapReadCertificateSecret) reads the secret that backs one version of a
	// vault certificate: its content type and value (a PFX or PEM with the private key). The caller
	// zeroes the value. It never reads "latest": Version is required. A request that names no valid
	// certificate or version is refused with a *Error before anything is sent.
	ReadCertificateSecret(ctx context.Context, req SecretRequest) (CertificateSecret, error)
	// ImportCertificate (CapImportCertificate) adds a version to a vault certificate (creating it
	// when the name is new). The outcome rules are ImportResult.Validate and CheckImportReturn: a
	// request that may have reached the vault is never answered "refused". The caller zeroes
	// req.PFX.
	ImportCertificate(ctx context.Context, req ImportRequest, log StepLogger) (ImportResult, error)
	// VerifyDeployment (CapVerifyDeployment) checks which certificate the location serves.
	VerifyDeployment(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// ConnectionCache is implemented by providers that keep connections to targets between sessions
// (linuxssh's pool). ForgetTarget closes the idle connections of a deleted target and drops what
// the provider keeps for it; a connection still in use is closed when its session ends.
type ConnectionCache interface {
	ForgetTarget(target uuid.UUID)
}

// SetupGuide is implemented by providers that need host preparation (linuxssh).
type SetupGuide interface {
	SetupSnippets(authorizedKeysLine string) map[string]SetupSnippet // key: profile "linux" | "nginx" | "apache"
	HelperInfo() (path string, protocol int)                         // "/usr/local/libexec/alice-helper", helperproto.Protocol
}

// SetupSnippet is the host preparation for one sudoers profile.
type SetupSnippet struct {
	Profile string // "linux" | "nginx" | "apache"
	Sudoers string // content of /etc/sudoers.d/alice
	Script  string // shell script to run as root on the target
}
